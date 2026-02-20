//! # Accelerated FHE Operations via MANA/UNHAL
//!
//! This module integrates NINE65's FHE operations with MANA's parallel
//! stream processing and UNHAL's hardware abstraction.
//!
//! ## Performance Gains
//!
//! - RNS operations: Parallel across primes (Rayon)
//! - Coefficient operations: SIMD vectorized (wide)
//! - NTT: Parallel butterflies + SIMD
//!
//! ## Usage
//!
//! ```ignore
//! use nine65::accelerated::AcceleratedFHE;
//!
//! let fhe = AcceleratedFHE::new(&config);
//! let ct_sum = fhe.add_ciphertexts(&ct_a, &ct_b);
//! ```

#[cfg(feature = "accelerated")]
use mana::anchor::AnchorContext;
#[cfg(feature = "accelerated")]
use mana::stream::ManaStream;
#[cfg(feature = "accelerated")]
use unhal::accelerator::{Accelerator, AcceleratorConfig};

use crate::arithmetic::rns::{RNSContext, RNSPolynomial};
use crate::ops::Ciphertext;
use crate::params::FHEConfig;
use crate::ring::RingPolynomial;

/// Accelerated FHE context using MANA/UNHAL
#[cfg(feature = "accelerated")]
pub struct AcceleratedFHE {
    /// FHE configuration
    config: FHEConfig,
    /// UNHAL accelerator
    accel: Accelerator,
    /// K-Elimination anchor context
    anchor_ctx: AnchorContext,
    /// RNS primes
    primes: Vec<u64>,
}

#[cfg(feature = "accelerated")]
impl AcceleratedFHE {
    /// Create accelerated FHE context
    pub fn new(config: &FHEConfig) -> Self {
        let accel = Accelerator::new(AcceleratorConfig::auto_detect());
        let anchor_ctx = AnchorContext::for_fhe();

        // Use config primes if available, otherwise default
        let primes = if config.primes.len() > 1 {
            config.primes.clone()
        } else {
            vec![config.q]
        };

        Self {
            config: config.clone(),
            accel,
            anchor_ctx,
            primes,
        }
    }

    /// Convert RNS polynomial to MANA stream for parallel processing
    pub fn rns_to_stream(&self, rns: &RNSPolynomial) -> ManaStream {
        // Each RNS limb becomes a MANA lane
        let lanes: Vec<mana::lane::Lane> = rns
            .limbs
            .iter()
            .zip(self.primes.iter())
            .map(|(limb, &prime)| mana::lane::Lane::from_coeffs(limb.clone(), prime))
            .collect();

        use std::sync::Arc;
        let product_cache = self.primes.iter().fold(1u128, |acc, &p| acc * p as u128);
        ManaStream {
            lanes,
            primes: Arc::new(self.primes.clone()),
            n: rns.n,
            product_cache,
        }
    }

    /// Convert MANA stream back to RNS polynomial
    pub fn stream_to_rns(&self, stream: &ManaStream) -> RNSPolynomial {
        let limbs: Vec<Vec<u64>> = stream
            .lanes
            .iter()
            .map(|lane| lane.coeffs.clone())
            .collect();

        RNSPolynomial { limbs, n: stream.n }
    }

    /// Accelerated ciphertext addition
    ///
    /// Uses SIMD + Rayon for parallel coefficient-wise addition
    pub fn add_ciphertexts(&self, ct_a: &Ciphertext, ct_b: &Ciphertext) -> Ciphertext {
        // Note: This is a simplified version - full implementation would
        // convert both c0 and c1 polynomials to streams and add them

        // For now, use standard addition (the acceleration happens in
        // the underlying RNS operations when using AcceleratedRNS below)
        let c0_coeffs = self.add_polynomials(&ct_a.c0.coeffs, &ct_b.c0.coeffs);
        let c1_coeffs = self.add_polynomials(&ct_a.c1.coeffs, &ct_b.c1.coeffs);

        Ciphertext {
            c0: RingPolynomial::from_coeffs(c0_coeffs, self.config.q),
            c1: RingPolynomial::from_coeffs(c1_coeffs, self.config.q),
        }
    }

    /// Accelerated polynomial addition (coefficients only)
    fn add_polynomials(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        let q = self.config.q;
        a.iter()
            .zip(b.iter())
            .map(|(&ai, &bi)| {
                let sum = ai as u128 + bi as u128;
                if sum >= q as u128 {
                    (sum - q as u128) as u64
                } else {
                    sum as u64
                }
            })
            .collect()
    }

    /// Accelerated RNS polynomial addition using MANA streams
    pub fn add_rns_accelerated(
        &self,
        a: &RNSPolynomial,
        b: &RNSPolynomial,
        _ctx: &RNSContext,
    ) -> RNSPolynomial {
        let stream_a = self.rns_to_stream(a);
        let stream_b = self.rns_to_stream(b);

        let result_stream = self.accel.add_streams(&stream_a, &stream_b);

        self.stream_to_rns(&result_stream)
    }

    /// Accelerated RNS polynomial subtraction
    pub fn sub_rns_accelerated(
        &self,
        a: &RNSPolynomial,
        b: &RNSPolynomial,
        _ctx: &RNSContext,
    ) -> RNSPolynomial {
        let stream_a = self.rns_to_stream(a);
        let stream_b = self.rns_to_stream(b);

        let result_stream = self.accel.sub_streams(&stream_a, &stream_b);

        self.stream_to_rns(&result_stream)
    }

    /// Accelerated coefficient-wise multiplication (Hadamard product)
    pub fn mul_rns_coeffwise(
        &self,
        a: &RNSPolynomial,
        b: &RNSPolynomial,
        _ctx: &RNSContext,
    ) -> RNSPolynomial {
        let stream_a = self.rns_to_stream(a);
        let stream_b = self.rns_to_stream(b);

        let result_stream = self.accel.mul_streams(&stream_a, &stream_b);

        self.stream_to_rns(&result_stream)
    }

    /// Exact division using K-Elimination anchor
    ///
    /// This is critical for FHE rescaling operations
    pub fn exact_divide_rns(&self, poly: &RNSPolynomial, divisor: u64) -> Vec<u128> {
        let stream = self.rns_to_stream(poly);
        self.anchor_ctx.exact_divide_stream(&stream, divisor)
    }

    /// Get underlying accelerator for custom operations
    pub fn accelerator(&self) -> &Accelerator {
        &self.accel
    }

    /// Get anchor context for exact division
    pub fn anchor(&self) -> &AnchorContext {
        &self.anchor_ctx
    }
}

/// Accelerated RNS Context - drop-in replacement with SIMD/Rayon
#[cfg(feature = "accelerated")]
pub struct AcceleratedRNS {
    /// Base RNS context
    base: RNSContext,
    /// UNHAL accelerator
    accel: Accelerator,
}

#[cfg(feature = "accelerated")]
impl AcceleratedRNS {
    /// Create from existing RNS context
    pub fn new(base: RNSContext) -> Self {
        Self {
            base,
            accel: Accelerator::auto(),
        }
    }

    /// Get underlying RNS context
    pub fn base(&self) -> &RNSContext {
        &self.base
    }

    /// Accelerated RNS number addition
    pub fn add(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        // For small vectors, SIMD overhead may not help
        // Use threshold to decide
        if a.len() < 4 {
            self.base.add(a, b)
        } else {
            // Convert to streams and use accelerator
            let stream_a = ManaStream::from_ints(a, &self.base.primes);
            let stream_b = ManaStream::from_ints(b, &self.base.primes);
            let result = self.accel.add_streams(&stream_a, &stream_b);

            // Extract first coefficient from each lane
            result.lanes.iter().map(|lane| lane.coeffs[0]).collect()
        }
    }

    /// Accelerated RNS number multiplication
    pub fn mul(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        if a.len() < 4 {
            self.base.mul(a, b)
        } else {
            let stream_a = ManaStream::from_ints(a, &self.base.primes);
            let stream_b = ManaStream::from_ints(b, &self.base.primes);
            let result = self.accel.mul_streams(&stream_a, &stream_b);

            result.lanes.iter().map(|lane| lane.coeffs[0]).collect()
        }
    }
}

#[cfg(all(test, feature = "accelerated"))]
mod tests {
    use super::*;
    use crate::params::SecureConfig;

    #[test]
    fn test_rns_stream_roundtrip() {
        let config = SecureConfig::secure_128().into_config();
        let accel_fhe = AcceleratedFHE::new(&config);

        // Create a simple RNS polynomial
        let rns_ctx = RNSContext::new(vec![998244353, 985661441], 8);
        let values: Vec<u64> = (0..8).collect();
        let rns_poly = RNSPolynomial::from_poly(&values, &rns_ctx);

        // Convert to stream and back
        let stream = accel_fhe.rns_to_stream(&rns_poly);
        let recovered = accel_fhe.stream_to_rns(&stream);

        // Verify
        for (orig, rec) in rns_poly.limbs.iter().zip(recovered.limbs.iter()) {
            assert_eq!(orig, rec);
        }
    }

    #[test]
    fn test_accelerated_add() {
        // Use light config which has n=512 (minimum for security)
        let config = SecureConfig::secure_128().into_config();
        let primes = config.primes.clone();
        let n = config.n;

        let rns_ctx = RNSContext::new(primes.clone(), n);
        let accel_fhe = AcceleratedFHE::new(&config);

        let a: Vec<u64> = (0..n).map(|i| i as u64).collect();
        let b: Vec<u64> = (0..n).map(|i| (i + 10) as u64).collect();

        let rns_a = RNSPolynomial::from_poly(&a, &rns_ctx);
        let rns_b = RNSPolynomial::from_poly(&b, &rns_ctx);

        // Accelerated add
        let result = accel_fhe.add_rns_accelerated(&rns_a, &rns_b, &rns_ctx);

        // Sequential add
        let expected = rns_a.add(&rns_b, &rns_ctx);

        // Compare
        for (res, exp) in result.limbs.iter().zip(expected.limbs.iter()) {
            assert_eq!(res, exp);
        }
    }
}
