//! # Anchor - K-Elimination Exact Division
//!
//! Provides exact RNS division with zero approximation.
//!
//! ## The K-Elimination Theorem
//!
//! Given value V represented in dual codex (α, β):
//! - V ≡ vα (mod αcap)
//! - V ≡ vβ (mod βcap)
//!
//! We can recover V exactly:
//! - k = (vβ - vα) × αcap⁻¹ (mod βcap)
//! - V = vα + k × αcap
//!
//! Then exact division: V / d = (vα + k × αcap) / d when d | V
//!
//! ## Why This Matters
//!
//! FHE rescaling requires dividing ciphertext coefficients by primes.
//! Traditional RNS division needs full O(k²) reconstruction.
//! K-Elimination: O(k) anchor-first division.

use crate::stream::ManaStream;

/// K-Elimination anchor for exact division
#[derive(Clone, Debug)]
pub struct KAnchor {
    /// Alpha primes (computational codex)
    pub alpha_primes: Vec<u64>,
    /// Beta primes (anchor codex)
    pub beta_primes: Vec<u64>,
    /// Product of alpha primes
    pub alpha_cap: u128,
    /// Product of beta primes
    pub beta_cap: u128,
    /// αcap⁻¹ mod βcap (precomputed)
    pub alpha_inv_beta: u128,
}

impl KAnchor {
    /// Create K-Elimination anchor
    ///
    /// All primes must be coprime across both sets.
    pub fn new(alpha_primes: &[u64], beta_primes: &[u64]) -> Self {
        let alpha_cap: u128 = alpha_primes.iter().map(|&p| p as u128).product();
        let beta_cap: u128 = beta_primes.iter().map(|&p| p as u128).product();

        let alpha_inv_beta =
            mod_inverse_u128(alpha_cap % beta_cap, beta_cap).expect("Primes must be coprime");

        Self {
            alpha_primes: alpha_primes.to_vec(),
            beta_primes: beta_primes.to_vec(),
            alpha_cap,
            beta_cap,
            alpha_inv_beta,
        }
    }

    /// Create anchor optimized for FHE operations
    ///
    /// Uses 62-bit anchor primes for ~112-bit total capacity.
    /// Safe for N=1024 tensor products (~70-bit intermediate values).
    pub fn for_fhe() -> Self {
        // Alpha: ~48 bits (3 × 16-bit primes)
        let alpha_primes = vec![65537, 65521, 65519];

        // Beta: ~62 bits (single large prime)
        // This gives ~110-bit total capacity
        let beta_primes = vec![4611686018427387847u64];

        Self::new(&alpha_primes, &beta_primes)
    }

    /// Extract k value for exact reconstruction
    ///
    /// k = (vβ - vα) × αcap⁻¹ mod βcap
    #[inline]
    pub fn extract_k(&self, v_alpha: u128, v_beta: u128) -> u128 {
        let diff = if v_beta >= v_alpha {
            v_beta - v_alpha
        } else {
            self.beta_cap - ((v_alpha - v_beta) % self.beta_cap)
        };

        mul_mod_u128(diff, self.alpha_inv_beta, self.beta_cap)
    }

    /// Exact division: V / divisor where divisor | V
    ///
    /// This is the KEY operation for FHE rescaling.
    #[inline]
    pub fn exact_divide(&self, v_alpha: u128, v_beta: u128, divisor: u64) -> u128 {
        let k = self.extract_k(v_alpha, v_beta);
        let v_full = v_alpha + k * self.alpha_cap;
        v_full / (divisor as u128)
    }

    /// Exact division with verification
    pub fn exact_divide_checked(&self, v_alpha: u128, v_beta: u128, divisor: u64) -> Option<u128> {
        let k = self.extract_k(v_alpha, v_beta);
        let v_full = v_alpha + k * self.alpha_cap;

        if v_full.is_multiple_of(divisor as u128) {
            Some(v_full / (divisor as u128))
        } else {
            None
        }
    }

    /// Scale value by t/q with exact rounding
    ///
    /// Computes: round(value × t / q) = floor((value × t + q/2) / q)
    pub fn scale_and_round(&self, value: u64, t: u64, q: u64) -> u64 {
        let value = value as u128;
        let t = t as u128;
        let q = q as u128;

        // Add q/2 for rounding
        let numerator = value * t + q / 2;

        let v_alpha = numerator % self.alpha_cap;
        let v_beta = numerator % self.beta_cap;

        let k = self.extract_k(v_alpha, v_beta);
        let full_numerator = v_alpha + k * self.alpha_cap;

        ((full_numerator / q) % q) as u64
    }
}

/// Full anchor context with both computational and anchor streams
#[derive(Clone, Debug)]
pub struct AnchorContext {
    /// K-Elimination anchor
    pub anchor: KAnchor,
    /// All primes (alpha + beta)
    all_primes: Vec<u64>,
}

impl AnchorContext {
    /// Create anchor context from K-Elimination anchor
    pub fn new(anchor: KAnchor) -> Self {
        let mut all_primes = anchor.alpha_primes.clone();
        all_primes.extend(&anchor.beta_primes);

        Self { anchor, all_primes }
    }

    /// Create FHE-optimized context
    pub fn for_fhe() -> Self {
        Self::new(KAnchor::for_fhe())
    }

    /// Get all primes for stream creation
    pub fn primes(&self) -> &[u64] {
        &self.all_primes
    }

    /// Create a stream in this anchor context
    pub fn stream(&self, values: &[u64]) -> ManaStream {
        ManaStream::from_ints(values, &self.all_primes)
    }

    /// Exact divide a stream by a scalar divisor (coefficient-wise)
    pub fn exact_divide_stream(&self, stream: &ManaStream, divisor: u64) -> Vec<u128> {
        let alpha_count = self.anchor.alpha_primes.len();

        (0..stream.n)
            .map(|i| {
                // Get alpha residue (product of alpha lanes at position i)
                let v_alpha = self.compute_partial_crt(stream, i, 0, alpha_count);

                // Get beta residue (product of beta lanes at position i)
                let v_beta =
                    self.compute_partial_crt(stream, i, alpha_count, self.all_primes.len());

                self.anchor.exact_divide(v_alpha, v_beta, divisor)
            })
            .collect()
    }

    /// Compute partial CRT for a range of lanes
    fn compute_partial_crt(
        &self,
        stream: &ManaStream,
        coeff_idx: usize,
        lane_start: usize,
        lane_end: usize,
    ) -> u128 {
        let primes = &self.all_primes[lane_start..lane_end];
        let product: u128 = primes.iter().map(|&p| p as u128).product();

        let mut result = 0u128;
        for (lane_offset, &p) in primes.iter().enumerate() {
            let lane_idx = lane_start + lane_offset;
            let mi = product / p as u128;
            let mi_inv = mod_inverse_u128(mi % p as u128, p as u128).unwrap();
            let coeff = stream.lanes[lane_idx].coeffs[coeff_idx] as u128;
            let term = (coeff * mi_inv) % p as u128;
            let contribution = (term * mi) % product;
            result = (result + contribution) % product;
        }

        result
    }
}

/// Modular multiplication for u128
fn mul_mod_u128(a: u128, b: u128, m: u128) -> u128 {
    if a < (1u128 << 64) && b < (1u128 << 64) {
        (a * b) % m
    } else {
        // Binary multiplication for large values
        let mut result = 0u128;
        let mut a = a % m;
        let mut b = b;

        while b > 0 {
            if b & 1 == 1 {
                result = (result + a) % m;
            }
            a = (a << 1) % m;
            b >>= 1;
        }

        result
    }
}

/// Modular inverse for u128
fn mod_inverse_u128(a: u128, m: u128) -> Option<u128> {
    let (g, x, _) = extended_gcd_i128(a as i128, m as i128);

    if g != 1 {
        return None;
    }

    Some(if x < 0 {
        (x + m as i128) as u128
    } else {
        x as u128
    })
}

fn extended_gcd_i128(a: i128, b: i128) -> (i128, i128, i128) {
    if a == 0 {
        return (b, 0, 1);
    }
    let (g, x1, y1) = extended_gcd_i128(b % a, a);
    let x = y1 - (b / a) * x1;
    let y = x1;
    (g, x, y)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_k_anchor_basic() {
        let anchor = KAnchor::new(&[17, 19], &[23, 29]);

        assert_eq!(anchor.alpha_cap, 323);
        assert_eq!(anchor.beta_cap, 667);

        // Test reconstruction
        let v: u128 = 1000;
        let v_alpha = v % anchor.alpha_cap;
        let v_beta = v % anchor.beta_cap;

        let k = anchor.extract_k(v_alpha, v_beta);
        let reconstructed = v_alpha + k * anchor.alpha_cap;

        assert_eq!(reconstructed, v);
    }

    #[test]
    fn test_exact_division() {
        let anchor = KAnchor::new(&[65537, 65521], &[65519, 65497]);

        // 12345 / 5 = 2469
        let v: u128 = 12345;
        let v_alpha = v % anchor.alpha_cap;
        let v_beta = v % anchor.beta_cap;

        let result = anchor.exact_divide(v_alpha, v_beta, 5);
        assert_eq!(result, 2469);
    }

    #[test]
    fn test_fhe_anchor() {
        let anchor = KAnchor::for_fhe();

        // Verify capacity is sufficient
        assert!(anchor.alpha_cap > 1u128 << 47); // ~48 bits
        assert!(anchor.beta_cap > 1u128 << 61); // ~62 bits

        // Test large value
        let v: u128 = 1_000_000_000_000_000u128;
        let v_alpha = v % anchor.alpha_cap;
        let v_beta = v % anchor.beta_cap;

        let k = anchor.extract_k(v_alpha, v_beta);
        let reconstructed = v_alpha + k * anchor.alpha_cap;
        assert_eq!(reconstructed, v);
    }

    #[test]
    fn test_scale_and_round() {
        let anchor = KAnchor::for_fhe();
        let q: u64 = 65537;
        let t: u64 = 257;

        for &coeff in &[0u64, 1, 100, 1000, 10000, 32768, 65536] {
            let scaled = anchor.scale_and_round(coeff, t, q);
            let expected = (((coeff as u128) * (t as u128) + (q as u128) / 2) / (q as u128)) as u64;
            assert_eq!(scaled, expected % q, "Scale failed for coeff={}", coeff);
        }
    }
}
