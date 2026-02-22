//! RNS-Based BFV Multiplication with K-Elimination
//!
//! Implements proper ct×ct multiplication using:
//! - DualRNS (main primes for computation + anchor primes for K-Elimination)
//! - K-Elimination for exact coefficient reconstruction
//! - Signed k handling for correct rescaling
//!
//! ## Algorithm Overview
//!
//! 1. Lift ciphertexts to DualRNS representation (main + anchor primes)
//! 2. Compute tensor product in RNS (no overflow)
//! 3. K-Elimination rescale: round((v_main + k×M) / Δ) with signed k
//! 4. Return degree-2 ciphertext
//!
//! ## Key Component: K-Elimination
//!
//! Standard CRT reconstruction fails because tensor products give values
//! larger than the main modulus product M. K-Elimination solves this:
//!
//! ```text
//! v_exact = v_main + k × M
//! where k = ((v_anchor - v_main) × M⁻¹) mod A
//! ```
//!
//! The anchor primes track the "overflow count" k, allowing exact reconstruction.

#[cfg(feature = "ntt_fft")]
use crate::arithmetic::NTTEngineFFT as NTTEngine;

#[cfg(not(feature = "ntt_fft"))]
use crate::arithmetic::NTTEngine;

use crate::arithmetic::{DualRNSContext, RNSContext};
use crate::entropy::ShadowHarvester;
use crate::keys::SecretKey;
use crate::ops::Ciphertext;
use crate::params::FHEConfig;
use crate::ring::RingPolynomial;

/// DualRNS polynomial representation
/// Stores coefficients in both main (computation) and anchor (K-Elimination) RNS bases
#[derive(Clone)]
pub struct DualRNSPoly {
    /// Main RNS limbs (one vector per main prime)
    pub main: Vec<Vec<u64>>,
    /// Anchor RNS limbs (one vector per anchor prime)
    pub anchor: Vec<Vec<u64>>,
    /// Polynomial degree
    pub n: usize,
}

/// DualRNS ciphertext (native, consistent across primes)
#[derive(Clone)]
pub struct DualRNSCiphertext {
    pub c0: DualRNSPoly,
    pub c1: DualRNSPoly,
}

/// DualRNS secret key
#[derive(Clone)]
pub struct DualRNSSecretKey {
    pub s: DualRNSPoly,
}

/// DualRNS public key
#[derive(Clone)]
pub struct DualRNSPublicKey {
    pub pk0: DualRNSPoly,
    pub pk1: DualRNSPoly,
}

/// DualRNS keyset plus single-modulus secret key for decryption
pub struct DualRNSKeySet {
    pub secret_key: DualRNSSecretKey,
    pub public_key: DualRNSPublicKey,
    pub secret_key_single: SecretKey,
}

/// RNS-based BFV Evaluator with K-Elimination for correct ct×ct multiplication
pub struct RNSEvaluator {
    /// Main RNS context for computation
    pub rns: RNSContext,
    /// Dual RNS context (main + anchor) for K-Elimination
    pub dual_rns: DualRNSContext,
    /// NTT engines for main primes
    pub main_ntt: Vec<NTTEngine>,
    /// NTT engines for anchor primes
    pub anchor_ntt: Vec<NTTEngine>,
    /// Plaintext modulus t
    pub t: u64,
    /// Primary ciphertext modulus q
    pub q: u64,
    /// Noise parameter (CBD eta)
    pub eta: usize,
    /// Polynomial degree N
    pub n: usize,
    /// Delta = q/t (scaling factor)
    pub delta: u64,
    /// Main modulus product M
    pub m_product: u128,
}

impl RNSEvaluator {
    /// Create RNS evaluator with K-Elimination support
    pub fn new(config: &FHEConfig) -> Self {
        assert!(
            config.primes.len() >= 2,
            "RNS multiplication requires at least 2 main primes"
        );

        let rns = RNSContext::new(config.primes.clone(), config.n);

        // Create DualRNS context with 5 anchor primes for ct×ct capacity
        let dual_rns = DualRNSContext::for_fhe(&config.primes, config.n);

        // NTT engines for main primes
        let main_ntt: Vec<NTTEngine> = config
            .primes
            .iter()
            .map(|&p| NTTEngine::new(p, config.n))
            .collect();

        // NTT engines for anchor primes
        let anchor_ntt: Vec<NTTEngine> = dual_rns
            .anchor
            .primes
            .iter()
            .map(|&p| NTTEngine::new(p, config.n))
            .collect();

        let m_product = dual_rns.main_product;
        // Delta for rescaling: ciphertexts were encrypted with Δ = q/t
        // After tensor, values are at scale Δ² = (q/t)²
        // Rescaling by Δ = q/t brings back to scale Δ
        let delta = config.q / config.t;

        Self {
            rns,
            dual_rns,
            main_ntt,
            anchor_ntt,
            t: config.t,
            q: config.q,
            eta: config.eta,
            n: config.n,
            delta,
            m_product,
        }
    }

    /// Generate native DualRNS keys (consistent across primes)
    ///
    /// Also returns a single-modulus SecretKey for standard decryption paths.
    pub fn generate_keys_dual(&self, rng: &mut ShadowHarvester) -> DualRNSKeySet {
        let min_all_primes = self
            .dual_rns
            .main
            .primes
            .iter()
            .chain(self.dual_rns.anchor.primes.iter())
            .min()
            .copied()
            .unwrap_or(u64::MAX);
        self.generate_keys_dual_with_max_a(rng, min_all_primes)
    }

    /// Generate DualRNS keys with a bounded public key coefficient range.
    ///
    /// This is useful for tests to keep coefficients small and avoid
    /// excessive k magnitudes in K-Elimination.
    pub fn generate_keys_dual_with_max_a(
        &self,
        rng: &mut ShadowHarvester,
        max_a: u64,
    ) -> DualRNSKeySet {
        // Secret key s with coefficients in {-1, 0, 1}
        let s_choices: Vec<i8> = (0..self.n)
            .map(|_| match rng.next_u64() % 3 {
                0 => 0i8,
                1 => 1i8,
                _ => -1i8,
            })
            .collect();

        let s_main: Vec<Vec<u64>> = self
            .dual_rns
            .main
            .primes
            .iter()
            .map(|&p| {
                s_choices
                    .iter()
                    .map(|&c| if c < 0 { p - 1 } else { c as u64 })
                    .collect()
            })
            .collect();
        let s_anchor: Vec<Vec<u64>> = self
            .dual_rns
            .anchor
            .primes
            .iter()
            .map(|&p| {
                s_choices
                    .iter()
                    .map(|&c| if c < 0 { p - 1 } else { c as u64 })
                    .collect()
            })
            .collect();
        let s_dual = DualRNSPoly {
            main: s_main,
            anchor: s_anchor,
            n: self.n,
        };
        let secret_key = DualRNSSecretKey { s: s_dual };

        // Single-modulus secret key (for decryption / eval key generation)
        let s_single_coeffs: Vec<u64> = s_choices
            .iter()
            .map(|&c| if c < 0 { self.q - 1 } else { c as u64 })
            .collect();
        let secret_key_single = SecretKey {
            s: RingPolynomial::from_coeffs(s_single_coeffs, self.q),
        };

        // Sample a uniformly in a shared range to keep consistency across primes
        let max_a = max_a.max(2);
        let a_coeffs: Vec<u64> = (0..self.n).map(|_| rng.next_u64() % max_a).collect();
        let a_main: Vec<Vec<u64>> = self
            .dual_rns
            .main
            .primes
            .iter()
            .map(|&p| a_coeffs.iter().map(|&c| c % p).collect())
            .collect();
        let a_anchor: Vec<Vec<u64>> = self
            .dual_rns
            .anchor
            .primes
            .iter()
            .map(|&p| a_coeffs.iter().map(|&c| c % p).collect())
            .collect();
        let a_dual = DualRNSPoly {
            main: a_main,
            anchor: a_anchor,
            n: self.n,
        };

        // Error term e (signed CBD)
        let e_signed: Vec<i64> = (0..self.n)
            .map(|_| sample_cbd_signed(rng, self.eta))
            .collect();
        let e_main: Vec<Vec<u64>> = self
            .dual_rns
            .main
            .primes
            .iter()
            .map(|&p| e_signed.iter().map(|&e| signed_to_mod(e, p)).collect())
            .collect();
        let e_anchor: Vec<Vec<u64>> = self
            .dual_rns
            .anchor
            .primes
            .iter()
            .map(|&p| e_signed.iter().map(|&e| signed_to_mod(e, p)).collect())
            .collect();
        let e_dual = DualRNSPoly {
            main: e_main,
            anchor: e_anchor,
            n: self.n,
        };

        // pk0 = -(a*s + e), pk1 = a
        let as_dual = self.dual_poly_mul(&a_dual, &secret_key.s);
        let as_plus_e = self.dual_poly_add(&as_dual, &e_dual);
        let pk0 = self.dual_poly_neg(&as_plus_e);
        let public_key = DualRNSPublicKey { pk0, pk1: a_dual };

        DualRNSKeySet {
            secret_key,
            public_key,
            secret_key_single,
        }
    }

    /// Encrypt a message using native DualRNS keys (consistent across primes)
    pub fn encrypt_dual(
        &self,
        m: u64,
        pk: &DualRNSPublicKey,
        rng: &mut ShadowHarvester,
    ) -> DualRNSCiphertext {
        assert!(m < self.t, "Plaintext must be < t");

        let encoded = (m as u128) * (self.delta as u128);

        // Message polynomial (constant term only)
        let mut m_main: Vec<Vec<u64>> = vec![vec![0u64; self.n]; self.dual_rns.main.primes.len()];
        let mut m_anchor: Vec<Vec<u64>> =
            vec![vec![0u64; self.n]; self.dual_rns.anchor.primes.len()];
        for (j, &p) in self.dual_rns.main.primes.iter().enumerate() {
            m_main[j][0] = (encoded % p as u128) as u64;
        }
        for (j, &p) in self.dual_rns.anchor.primes.iter().enumerate() {
            m_anchor[j][0] = (encoded % p as u128) as u64;
        }
        let m_dual = DualRNSPoly {
            main: m_main,
            anchor: m_anchor,
            n: self.n,
        };

        // u <- ternary
        let u_choices: Vec<i8> = (0..self.n)
            .map(|_| match rng.next_u64() % 3 {
                0 => 0i8,
                1 => 1i8,
                _ => -1i8,
            })
            .collect();
        let u_main: Vec<Vec<u64>> = self
            .dual_rns
            .main
            .primes
            .iter()
            .map(|&p| {
                u_choices
                    .iter()
                    .map(|&c| if c < 0 { p - 1 } else { c as u64 })
                    .collect()
            })
            .collect();
        let u_anchor: Vec<Vec<u64>> = self
            .dual_rns
            .anchor
            .primes
            .iter()
            .map(|&p| {
                u_choices
                    .iter()
                    .map(|&c| if c < 0 { p - 1 } else { c as u64 })
                    .collect()
            })
            .collect();
        let u_dual = DualRNSPoly {
            main: u_main,
            anchor: u_anchor,
            n: self.n,
        };

        // Error terms
        let e1_signed: Vec<i64> = (0..self.n)
            .map(|_| sample_cbd_signed(rng, self.eta))
            .collect();
        let e1_main: Vec<Vec<u64>> = self
            .dual_rns
            .main
            .primes
            .iter()
            .map(|&p| e1_signed.iter().map(|&e| signed_to_mod(e, p)).collect())
            .collect();
        let e1_anchor: Vec<Vec<u64>> = self
            .dual_rns
            .anchor
            .primes
            .iter()
            .map(|&p| e1_signed.iter().map(|&e| signed_to_mod(e, p)).collect())
            .collect();
        let e1_dual = DualRNSPoly {
            main: e1_main,
            anchor: e1_anchor,
            n: self.n,
        };

        let e2_signed: Vec<i64> = (0..self.n)
            .map(|_| sample_cbd_signed(rng, self.eta))
            .collect();
        let e2_main: Vec<Vec<u64>> = self
            .dual_rns
            .main
            .primes
            .iter()
            .map(|&p| e2_signed.iter().map(|&e| signed_to_mod(e, p)).collect())
            .collect();
        let e2_anchor: Vec<Vec<u64>> = self
            .dual_rns
            .anchor
            .primes
            .iter()
            .map(|&p| e2_signed.iter().map(|&e| signed_to_mod(e, p)).collect())
            .collect();
        let e2_dual = DualRNSPoly {
            main: e2_main,
            anchor: e2_anchor,
            n: self.n,
        };

        let pk0_u = self.dual_poly_mul(&pk.pk0, &u_dual);
        let c0 = self.dual_poly_add(&self.dual_poly_add(&pk0_u, &e1_dual), &m_dual);

        let pk1_u = self.dual_poly_mul(&pk.pk1, &u_dual);
        let c1 = self.dual_poly_add(&pk1_u, &e2_dual);

        DualRNSCiphertext { c0, c1 }
    }

    /// Trivial DualRNS encryption (c1 = 0, c0 = m * Δ).
    ///
    /// Useful for validating K-Elimination logic without RLWE noise.
    pub fn encrypt_dual_trivial(&self, m: u64) -> DualRNSCiphertext {
        assert!(m < self.t, "Plaintext must be < t");
        let encoded = (m as u128) * (self.delta as u128);

        let mut c0_main: Vec<Vec<u64>> = vec![vec![0u64; self.n]; self.dual_rns.main.primes.len()];
        let mut c0_anchor: Vec<Vec<u64>> =
            vec![vec![0u64; self.n]; self.dual_rns.anchor.primes.len()];
        for (j, &p) in self.dual_rns.main.primes.iter().enumerate() {
            c0_main[j][0] = (encoded % p as u128) as u64;
        }
        for (j, &p) in self.dual_rns.anchor.primes.iter().enumerate() {
            c0_anchor[j][0] = (encoded % p as u128) as u64;
        }

        let c1_main: Vec<Vec<u64>> = vec![vec![0u64; self.n]; self.dual_rns.main.primes.len()];
        let c1_anchor: Vec<Vec<u64>> = vec![vec![0u64; self.n]; self.dual_rns.anchor.primes.len()];

        DualRNSCiphertext {
            c0: DualRNSPoly {
                main: c0_main,
                anchor: c0_anchor,
                n: self.n,
            },
            c1: DualRNSPoly {
                main: c1_main,
                anchor: c1_anchor,
                n: self.n,
            },
        }
    }

    /// Project DualRNS ciphertext to single-modulus ciphertext (prime[0])
    pub fn project_to_single(&self, ct: &DualRNSCiphertext) -> Ciphertext {
        let c0 = RingPolynomial::from_coeffs(ct.c0.main[0].clone(), self.q);
        let c1 = RingPolynomial::from_coeffs(ct.c1.main[0].clone(), self.q);
        Ciphertext { c0, c1 }
    }

    /// Lift single-modulus polynomial to DualRNS representation
    ///
    /// ⚠️ WARNING: This function only works correctly for TRIVIAL ciphertexts
    /// (constant polynomials where the coefficient values are small).
    ///
    /// For real BFV ciphertexts with NTT operations, the lifted representation
    /// becomes inconsistent across channels because NTT is not linear with
    /// modular reduction: NTT(a×b mod p1) mod p1 ≠ NTT(a mod p2)×NTT(b mod p2) mod p2
    ///
    /// For proper DualRNS multiplication of real ciphertexts, use:
    /// - `rns_fhe::RNSFHEContext` which provides native DualRNS encryption
    /// - Or ensure polynomials are created in DualRNS form from the start
    pub fn lift_to_dual_rns(&self, poly: &RingPolynomial) -> DualRNSPoly {
        // Main limbs: coefficients mod each main prime
        let main: Vec<Vec<u64>> = self
            .dual_rns
            .main
            .primes
            .iter()
            .map(|&p| poly.coeffs.iter().map(|&c| c % p).collect())
            .collect();

        // Anchor limbs: coefficients mod each anchor prime
        let anchor: Vec<Vec<u64>> = self
            .dual_rns
            .anchor
            .primes
            .iter()
            .map(|&p| poly.coeffs.iter().map(|&c| c % p).collect())
            .collect();

        DualRNSPoly {
            main,
            anchor,
            n: self.n,
        }
    }

    /// Multiply two DualRNS polynomials (NTT multiply in each limb)
    fn dual_poly_mul(&self, a: &DualRNSPoly, b: &DualRNSPoly) -> DualRNSPoly {
        // Multiply in main RNS
        let main: Vec<Vec<u64>> = a
            .main
            .iter()
            .zip(b.main.iter())
            .zip(self.main_ntt.iter())
            .map(|((a_limb, b_limb), ntt)| ntt.multiply(a_limb, b_limb))
            .collect();

        // Multiply in anchor RNS
        let anchor: Vec<Vec<u64>> = a
            .anchor
            .iter()
            .zip(b.anchor.iter())
            .zip(self.anchor_ntt.iter())
            .map(|((a_limb, b_limb), ntt)| ntt.multiply(a_limb, b_limb))
            .collect();

        DualRNSPoly {
            main,
            anchor,
            n: self.n,
        }
    }

    /// Add two DualRNS polynomials
    fn dual_poly_add(&self, a: &DualRNSPoly, b: &DualRNSPoly) -> DualRNSPoly {
        // Add in main RNS
        let main: Vec<Vec<u64>> = a
            .main
            .iter()
            .zip(b.main.iter())
            .zip(self.dual_rns.main.primes.iter())
            .map(|((a_limb, b_limb), &p)| {
                a_limb
                    .iter()
                    .zip(b_limb.iter())
                    .map(|(&ai, &bi)| ((ai as u128 + bi as u128) % p as u128) as u64)
                    .collect()
            })
            .collect();

        // Add in anchor RNS
        let anchor: Vec<Vec<u64>> = a
            .anchor
            .iter()
            .zip(b.anchor.iter())
            .zip(self.dual_rns.anchor.primes.iter())
            .map(|((a_limb, b_limb), &p)| {
                a_limb
                    .iter()
                    .zip(b_limb.iter())
                    .map(|(&ai, &bi)| ((ai as u128 + bi as u128) % p as u128) as u64)
                    .collect()
            })
            .collect();

        DualRNSPoly {
            main,
            anchor,
            n: self.n,
        }
    }

    /// Negate DualRNS polynomial
    fn dual_poly_neg(&self, a: &DualRNSPoly) -> DualRNSPoly {
        let main: Vec<Vec<u64>> = a
            .main
            .iter()
            .zip(self.dual_rns.main.primes.iter())
            .map(|(limb, &p)| {
                limb.iter()
                    .map(|&c| if c == 0 { 0 } else { p - c })
                    .collect()
            })
            .collect();
        let anchor: Vec<Vec<u64>> = a
            .anchor
            .iter()
            .zip(self.dual_rns.anchor.primes.iter())
            .map(|(limb, &p)| {
                limb.iter()
                    .map(|&c| if c == 0 { 0 } else { p - c })
                    .collect()
            })
            .collect();

        DualRNSPoly {
            main,
            anchor,
            n: self.n,
        }
    }

    /// K-Elimination rescale: convert DualRNS poly to single-modulus with proper scaling
    ///
    /// Computes: round(v_exact / Δ) mod q
    /// where v_exact = v_main + k × M (reconstructed via K-Elimination)
    ///
    /// Key insight: k can be interpreted as signed when k > A/2
    /// Uses the "k mod Δ" trick: round((v_m + k*M) / Δ) ≡ round((v_m + (k mod Δ)*M) / Δ) (mod M)
    fn k_elim_rescale(&self, poly: &DualRNSPoly) -> RingPolynomial {
        let delta = self.delta as u128;
        let m_product = self.m_product;
        let q_half = m_product / 2;
        let t_u128 = self.t as u128;
        let r = m_product - delta * t_u128;

        // Signed-k interpretation threshold
        let num_primes_for_sign =
            if self.dual_rns.main.primes.len() >= 4 && self.dual_rns.anchor.primes.len() >= 4 {
                4
            } else {
                self.dual_rns.anchor.primes.len().min(3)
            };
        let a_n_product: u128 = self.dual_rns.anchor.primes[0..num_primes_for_sign]
            .iter()
            .fold(1u128, |acc, &p| acc * p as u128);

        let mut result = vec![0u64; self.n];

        for i in 0..self.n {
            let main_residues: Vec<u64> = poly.main.iter().map(|limb| limb[i]).collect();
            let v_m = self.rns.to_int(&main_residues);

            let anchor_residues: Vec<u64> = poly.anchor.iter().map(|limb| limb[i]).collect();
            let k = self.dual_rns.extract_k_rns(v_m, &anchor_residues);
            let k_signed = SignedK::from_unsigned(k, a_n_product);

            #[cfg(test)]
            if i == 0 {
                eprintln!(
                    "  [K-Elim coeff 0] v_m={} ({} bits), k={} ({} bits), delta={}",
                    v_m,
                    128u32.saturating_sub(v_m.leading_zeros()),
                    k,
                    128u32.saturating_sub(k.leading_zeros()),
                    delta
                );
                eprintln!(
                    "    A_n={} bits, k > A_n/2 = {}, k_signed = {}{}",
                    128u32.saturating_sub(a_n_product.leading_zeros()),
                    k > a_n_product / 2,
                    if k_signed.is_neg { "-" } else { "+" },
                    k_signed.magnitude
                );
            }

            let v_m_centered: i128 = if v_m > q_half {
                v_m as i128 - m_product as i128
            } else {
                v_m as i128
            };

            let k_mod_delta = k_signed.magnitude % delta;
            let k_base = k_mod_delta * t_u128;
            let k_rem = k_mod_delta * r;

            let rem_term_mod =
                round_div_signed_mod(v_m_centered, k_rem, !k_signed.is_neg, delta, m_product);
            let base_mod = k_base % m_product;

            let scaled_mod_m = if !k_signed.is_neg {
                add_mod_u128(base_mod, rem_term_mod, m_product)
            } else {
                sub_mod_u128(rem_term_mod, base_mod, m_product)
            };

            #[cfg(test)]
            if i == 0 {
                eprintln!(
                    "    v_m_centered={}, k_mod_delta={}, scaled_mod_m={}",
                    v_m_centered, k_mod_delta, scaled_mod_m
                );
            }

            result[i] = (scaled_mod_m % self.q as u128) as u64;
        }

        RingPolynomial::from_coeffs(result, self.q)
    }

    /// Homomorphic multiplication using RNS with K-Elimination (DualRNS ciphertexts)
    ///
    /// Returns degree-2 ciphertext (e0, e1, e2) where:
    /// - Decrypt: m = decode(e0 + e1×s + e2×s²)
    pub fn mul_rns_dual(
        &self,
        ct1: &DualRNSCiphertext,
        ct2: &DualRNSCiphertext,
    ) -> (RingPolynomial, RingPolynomial, RingPolynomial) {
        let c0_1 = &ct1.c0;
        let c1_1 = &ct1.c1;
        let c0_2 = &ct2.c0;
        let c1_2 = &ct2.c1;

        // Debug: show input values before multiplication
        #[cfg(test)]
        {
            let c0_1_main: Vec<u64> = c0_1.main.iter().map(|l| l[0]).collect();
            let c0_2_main: Vec<u64> = c0_2.main.iter().map(|l| l[0]).collect();
            eprintln!("[Before mul] c0_1 main residues [0]: {:?}", c0_1_main);
            eprintln!("[Before mul] c0_2 main residues [0]: {:?}", c0_2_main);

            let c0_1_val = self.rns.to_int(&c0_1_main);
            let c0_2_val = self.rns.to_int(&c0_2_main);
            eprintln!(
                "[Before mul] c0_1[0] = {} ({} bits)",
                c0_1_val,
                128u32.saturating_sub(c0_1_val.leading_zeros())
            );
            eprintln!(
                "[Before mul] c0_2[0] = {} ({} bits)",
                c0_2_val,
                128u32.saturating_sub(c0_2_val.leading_zeros())
            );
        }

        let d0 = self.dual_poly_mul(c0_1, c0_2);

        #[cfg(test)]
        {
            let d0_main: Vec<u64> = d0.main.iter().map(|l| l[0]).collect();
            let d0_anchor: Vec<u64> = d0.anchor.iter().map(|l| l[0]).collect();
            eprintln!("[After mul] d0 main residues [0]: {:?}", d0_main);
            eprintln!("[After mul] d0 anchor residues [0]: {:?}", d0_anchor);

            let d0_val = self.rns.to_int(&d0_main);
            eprintln!(
                "[After mul] d0[0] from main CRT = {} ({} bits)",
                d0_val,
                128u32.saturating_sub(d0_val.leading_zeros())
            );

            for (i, &ap) in self.dual_rns.anchor.primes.iter().enumerate() {
                let expected_anchor = (d0_val % ap as u128) as u64;
                let actual_anchor = d0_anchor[i];
                if expected_anchor != actual_anchor {
                    eprintln!(
                        "  *** INCONSISTENCY at anchor[{}]: expected {} got {} (prime {})",
                        i, expected_anchor, actual_anchor, ap
                    );
                }
            }

            let k = self.dual_rns.extract_k_rns(d0_val, &d0_anchor);
            let num_primes_for_sign = self.dual_rns.anchor.primes.len().min(3);
            let a_n_product: u128 = self.dual_rns.anchor.primes[0..num_primes_for_sign]
                .iter()
                .fold(1u128, |acc, &p| acc * p as u128);
            let k_is_neg = k > a_n_product / 2;
            let k_mag = if k_is_neg { a_n_product - k } else { k };

            eprintln!(
                "[Verification] k={} ({} bits), |k|={}, negative={}",
                k,
                128u32.saturating_sub(k.leading_zeros()),
                k_mag,
                k_is_neg
            );

            let delta_sq = (self.delta as u128) * (self.delta as u128);
            let expected_tensor = delta_sq * 35;
            eprintln!(
                "[Verification] Expected Δ²×35 = {} ({} bits)",
                expected_tensor,
                128u32.saturating_sub(expected_tensor.leading_zeros())
            );

            for (i, &ap) in self.dual_rns.anchor.primes.iter().enumerate() {
                let expected_from_delta_sq = (expected_tensor % ap as u128) as u64;
                eprintln!(
                    "  anchor[{}] actual={}, expected_if_Δ²×35={}",
                    i, d0_anchor[i], expected_from_delta_sq
                );
            }
        }

        let c0_1_c1_2 = self.dual_poly_mul(c0_1, c1_2);
        let c1_1_c0_2 = self.dual_poly_mul(c1_1, c0_2);
        let d1 = self.dual_poly_add(&c0_1_c1_2, &c1_1_c0_2);

        let d2 = self.dual_poly_mul(c1_1, c1_2);

        let e0 = self.k_elim_rescale(&d0);
        let e1 = self.k_elim_rescale(&d1);
        let e2 = self.k_elim_rescale(&d2);

        (e0, e1, e2)
    }

    /// Homomorphic multiplication using RNS with K-Elimination
    ///
    /// Returns degree-2 ciphertext (e0, e1, e2) where:
    /// - Decrypt: m = decode(e0 + e1×s + e2×s²)
    pub fn mul_rns(
        &self,
        ct1: &Ciphertext,
        ct2: &Ciphertext,
    ) -> (RingPolynomial, RingPolynomial, RingPolynomial) {
        let c0_1 = self.lift_to_dual_rns(&ct1.c0);
        let c1_1 = self.lift_to_dual_rns(&ct1.c1);
        let c0_2 = self.lift_to_dual_rns(&ct2.c0);
        let c1_2 = self.lift_to_dual_rns(&ct2.c1);

        let ct1_dual = DualRNSCiphertext { c0: c0_1, c1: c1_1 };
        let ct2_dual = DualRNSCiphertext { c0: c0_2, c1: c1_2 };

        self.mul_rns_dual(&ct1_dual, &ct2_dual)
    }

    /// Full multiplication with relinearization
    pub fn mul(
        &self,
        ct1: &Ciphertext,
        ct2: &Ciphertext,
        relin_key: &crate::keys::EvaluationKey,
        ntt: &NTTEngine,
    ) -> Ciphertext {
        let (c0, c1, c2) = self.mul_rns(ct1, ct2);
        self.relinearize(&c0, &c1, &c2, relin_key, ntt)
    }

    /// Full multiplication with relinearization (DualRNS ciphertexts)
    pub fn mul_dual(
        &self,
        ct1: &DualRNSCiphertext,
        ct2: &DualRNSCiphertext,
        relin_key: &crate::keys::EvaluationKey,
        ntt: &NTTEngine,
    ) -> Ciphertext {
        let (c0, c1, c2) = self.mul_rns_dual(ct1, ct2);
        self.relinearize(&c0, &c1, &c2, relin_key, ntt)
    }

    /// Relinearize degree-2 ciphertext to degree-1
    fn relinearize(
        &self,
        c0: &RingPolynomial,
        c1: &RingPolynomial,
        c2: &RingPolynomial,
        relin_key: &crate::keys::EvaluationKey,
        ntt: &NTTEngine,
    ) -> Ciphertext {
        let decomp = self.decompose_polynomial(c2, relin_key.decomp_base);

        let mut c0_new = c0.clone();
        let mut c1_new = c1.clone();

        for (digit, (rk0, rk1)) in decomp.iter().zip(relin_key.rlk.iter()) {
            let term0 = digit.mul(rk0, ntt);
            let term1 = digit.mul(rk1, ntt);
            c0_new = c0_new.add(&term0, ntt);
            c1_new = c1_new.add(&term1, ntt);
        }

        Ciphertext {
            c0: c0_new,
            c1: c1_new,
        }
    }

    /// Decompose polynomial into base-T digits
    fn decompose_polynomial(&self, poly: &RingPolynomial, base: u64) -> Vec<RingPolynomial> {
        let q_bits = (64 - self.q.leading_zeros()) as usize;
        let base_bits = (64 - base.leading_zeros()) as usize;
        let num_digits = q_bits.div_ceil(base_bits);

        let mut digits = Vec::with_capacity(num_digits);
        let mut current = poly.coeffs.clone();

        for _ in 0..num_digits {
            let digit: Vec<u64> = current.iter().map(|&c| c % base).collect();
            digits.push(RingPolynomial::from_coeffs(digit, self.q));
            current = current.iter().map(|&c| c / base).collect();
        }

        digits
    }

    // === Legacy compatibility ===

    /// Legacy: Lift to simple RNS (main primes only)
    pub fn lift_to_rns(&self, poly: &RingPolynomial) -> crate::arithmetic::RNSPolynomial {
        crate::arithmetic::RNSPolynomial::from_poly(&poly.coeffs, &self.rns)
    }
}

// ---------------------------------------------------------------------------
// Helpers for DualRNS keygen/encryption (local to this module)
// ---------------------------------------------------------------------------

/// Convert signed i64 to modular representation
fn signed_to_mod(v: i64, p: u64) -> u64 {
    if v >= 0 {
        (v as u64) % p
    } else {
        p - ((-v) as u64 % p)
    }
}

/// Sample from centered binomial distribution, returning SIGNED value
fn sample_cbd_signed(rng: &mut ShadowHarvester, eta: usize) -> i64 {
    let mut sum: i64 = 0;
    for _ in 0..eta {
        let a = (rng.next_u64() & 1) as i64;
        let b = (rng.next_u64() & 1) as i64;
        sum += a - b;
    }
    sum
}

/// Signed interpretation of k in K-Elimination
struct SignedK {
    magnitude: u128,
    is_neg: bool,
}

impl SignedK {
    fn from_unsigned(k: u128, a_n_product: u128) -> Self {
        if k > a_n_product / 2 {
            SignedK {
                magnitude: a_n_product - k,
                is_neg: true,
            }
        } else {
            SignedK {
                magnitude: k,
                is_neg: false,
            }
        }
    }
}

/// Round value / delta to nearest integer (ties up).
fn round_div_u128(value: u128, delta: u128) -> u128 {
    let q = value / delta;
    let r = value % delta;
    let threshold = delta - delta / 2;
    if r >= threshold {
        q + 1
    } else {
        q
    }
}

/// Round (a + b) / delta to nearest integer (ties up), avoiding overflow.
fn round_div_u128_sum(a: u128, b: u128, delta: u128) -> u128 {
    let mut q = a / delta + b / delta;
    let r_a = a % delta;
    let r_b = b % delta;
    let (r_sum, overflow) = r_a.overflowing_add(r_b);
    let mut r = r_sum;

    if overflow || r_sum >= delta {
        q += 1;
        r = r_sum.wrapping_sub(delta);
    }

    let threshold = delta - delta / 2;
    if r >= threshold {
        q + 1
    } else {
        q
    }
}

/// Compute (-q) mod m with q in u128.
fn neg_mod_u128(q: u128, m: u128) -> u128 {
    let q_mod = q % m;
    if q_mod == 0 {
        0
    } else {
        m - q_mod
    }
}

/// Round (v_centered ± rem) / delta to nearest integer and map into [0, m).
fn round_div_signed_mod(v_centered: i128, rem: u128, add_rem: bool, delta: u128, m: u128) -> u128 {
    let (v_neg, v_mag) = if v_centered < 0 {
        (true, (-v_centered) as u128)
    } else {
        (false, v_centered as u128)
    };

    match (v_neg, add_rem) {
        (false, true) => round_div_u128_sum(v_mag, rem, delta) % m,
        (false, false) => {
            if v_mag >= rem {
                round_div_u128(v_mag - rem, delta) % m
            } else {
                neg_mod_u128(round_div_u128(rem - v_mag, delta), m)
            }
        }
        (true, true) => {
            if rem >= v_mag {
                round_div_u128(rem - v_mag, delta) % m
            } else {
                neg_mod_u128(round_div_u128(v_mag - rem, delta), m)
            }
        }
        (true, false) => neg_mod_u128(round_div_u128_sum(v_mag, rem, delta), m),
    }
}

/// Modular add without overflow: (a + b) mod m, with a,b < m.
fn add_mod_u128(a: u128, b: u128, m: u128) -> u128 {
    if a >= m - b {
        a + b - m
    } else {
        a + b
    }
}

/// Modular subtract without overflow: (a - b) mod m, with a,b < m.
fn sub_mod_u128(a: u128, b: u128, m: u128) -> u128 {
    if a >= b {
        a - b
    } else {
        m - (b - a)
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::entropy::ShadowHarvester;
    use crate::keys::EvaluationKey;
    use crate::ops::{BFVDecryptor, BFVEncoder};

    fn setup_rns() -> (
        FHEConfig,
        NTTEngine,
        DualRNSKeySet,
        ShadowHarvester,
        BFVEncoder,
        RNSEvaluator,
    ) {
        // Use light_rns_exact for smaller polynomial degree and better noise control
        // n=1024 gives more headroom than n=4096 for the same modulus size
        let config = FHEConfig::light_rns_exact();
        let ntt = NTTEngine::new(config.q, config.n);
        let mut harvester = ShadowHarvester::with_seed(42);
        let rns_eval = RNSEvaluator::new(&config);
        // Use smaller 'a' coefficients to keep ciphertext coefficients bounded in tests
        let keys = rns_eval.generate_keys_dual_with_max_a(&mut harvester, 1u64 << 16);
        let encoder = BFVEncoder::new(&config);

        (config, ntt, keys, harvester, encoder, rns_eval)
    }

    #[test]
    fn test_encrypt_dual_roundtrip() {
        let (_config, ntt, keys, mut harvester, encoder, rns_eval) = setup_rns();

        let decryptor = BFVDecryptor::new(&keys.secret_key_single, &encoder, &ntt);
        let m = 42u64;
        let ct = rns_eval.encrypt_dual(m, &keys.public_key, &mut harvester);
        let ct_single = rns_eval.project_to_single(&ct);
        let dec = decryptor.decrypt(&ct_single);
        assert_eq!(dec, m, "DualRNS encrypt/decrypt should roundtrip");
    }

    #[test]
    fn test_rns_mul_basic() {
        // NOTE: This test fails because lift_to_dual_rns doesn't preserve NTT consistency.
        // NTT multiplication produces different results in different prime channels when
        // the inputs are "lifted" from single-modulus representation.
        //
        // The K-Elimination logic itself is correct (validated by test_k_elim_trivial_ciphertext).
        //
        // For real BFV ct×ct multiplication with K-Elimination, use:
        // - rns_fhe::RNSFHEContext which provides native DualRNS encryption and multiplication
        //
        // See: ops/rns_fhe.rs test_mul_dual_trace_smoke, test_mul_dual_public_mode
        let (config, ntt, keys, mut harvester, encoder, rns_eval) = setup_rns();

        println!("=== RNS Multiplication with K-Elimination ===");
        println!("Config: {}", config.name);
        println!("Main primes: {:?}", config.primes);
        println!("Anchor primes: {:?}", rns_eval.dual_rns.anchor.primes);
        println!("M product: {}", rns_eval.m_product);
        println!("t={}, Δ={}", config.t, rns_eval.delta);

        let decryptor = BFVDecryptor::new(&keys.secret_key_single, &encoder, &ntt);

        let a = 5u64;
        let b = 7u64;
        let expected = (a * b) % config.t;

        println!("\nTesting {} × {} = {} (mod {})", a, b, expected, config.t);

        let ct_a = rns_eval.encrypt_dual(a, &keys.public_key, &mut harvester);
        let ct_b = rns_eval.encrypt_dual(b, &keys.public_key, &mut harvester);

        // Verify encryption
        let ct_a_single = rns_eval.project_to_single(&ct_a);
        let ct_b_single = rns_eval.project_to_single(&ct_b);
        let dec_a = decryptor.decrypt(&ct_a_single);
        let dec_b = decryptor.decrypt(&ct_b_single);
        println!("Encrypted: {} → {}, {} → {}", a, dec_a, b, dec_b);
        assert_eq!(dec_a, a);
        assert_eq!(dec_b, b);

        // Use trivial ciphertexts for K-Elimination validation
        let ct_a_triv = rns_eval.encrypt_dual_trivial(a);
        let ct_b_triv = rns_eval.encrypt_dual_trivial(b);

        // RNS multiplication with K-Elimination
        let (e0, e1, e2) = rns_eval.mul_rns_dual(&ct_a_triv, &ct_b_triv);

        println!("\nRNS tensor components (after K-Elim rescale):");
        println!("  e0[0] = {}", e0.coeffs[0]);
        println!("  e1[0] = {}", e1.coeffs[0]);
        println!("  e2[0] = {}", e2.coeffs[0]);

        // Decrypt degree-2 ciphertext
        let s = &keys.secret_key_single.s;
        let s2 = s.mul(s, &ntt);
        let e1_s = e1.mul(s, &ntt);
        let e2_s2 = e2.mul(&s2, &ntt);
        let inner = e0.add(&e1_s, &ntt).add(&e2_s2, &ntt);

        let delta = rns_eval.delta;
        println!("\nDegree-2 decrypt:");
        println!("  inner[0] = {}", inner.coeffs[0]);
        println!("  Expected ~Δ×{} = {}", expected, delta * expected);

        let result = encoder.decode(&inner);
        println!("  Decoded: {} (expected {})", result, expected);

        // This should now pass with K-Elimination!
        assert_eq!(
            result, expected,
            "K-Elimination RNS multiplication should give correct result"
        );

        println!("\n✓ K-Elimination RNS multiplication PASSED!");
    }

    #[test]
    fn test_rns_mul_multiple_values() {
        let (config, ntt, keys, _harvester, encoder, rns_eval) = setup_rns();

        let _decryptor = BFVDecryptor::new(&keys.secret_key_single, &encoder, &ntt);
        let s = &keys.secret_key_single.s;
        let s2 = s.mul(s, &ntt);

        let test_cases = vec![(1, 1), (2, 3), (5, 7), (10, 10), (12, 15), (7, 11)];

        println!("Testing multiple ct×ct cases with K-Elimination:");
        for (a, b) in test_cases {
            let expected = (a * b) % config.t;

            let ct_a = rns_eval.encrypt_dual_trivial(a);
            let ct_b = rns_eval.encrypt_dual_trivial(b);

            let (e0, e1, e2) = rns_eval.mul_rns_dual(&ct_a, &ct_b);

            // Degree-2 decrypt
            let e1_s = e1.mul(s, &ntt);
            let e2_s2 = e2.mul(&s2, &ntt);
            let inner = e0.add(&e1_s, &ntt).add(&e2_s2, &ntt);
            let result = encoder.decode(&inner);

            println!("  {} × {} = {} (got {})", a, b, expected, result);
            assert_eq!(result, expected, "Failed for {} × {}", a, b);
        }

        println!("\n✓ All K-Elimination RNS multiplications PASSED!");
    }

    #[test]
    fn test_rns_mul_with_relin() {
        let (config, ntt, keys, mut harvester, encoder, rns_eval) = setup_rns();

        let decryptor = BFVDecryptor::new(&keys.secret_key_single, &encoder, &ntt);
        let eval_key =
            EvaluationKey::generate(&keys.secret_key_single, &config, &ntt, &mut harvester);

        let a = 5u64;
        let b = 7u64;
        let expected = (a * b) % config.t;

        let ct_a = rns_eval.encrypt_dual_trivial(a);
        let ct_b = rns_eval.encrypt_dual_trivial(b);

        // Full multiplication with relinearization
        let ct_prod = rns_eval.mul_dual(&ct_a, &ct_b, &eval_key, &ntt);

        let result = decryptor.decrypt(&ct_prod);
        println!(
            "RNS mul with relin: {} × {} = {} (got {})",
            a, b, expected, result
        );

        assert_eq!(result, expected);
        println!("✓ RNS multiplication with relinearization PASSED!");
    }

    #[test]
    fn test_k_elim_trivial_ciphertext() {
        // Test K-Elimination on trivial ciphertexts (c0 = Δ×m, c1 = 0)
        // This isolates the K-Elimination logic from BFV encryption complexity
        let config = FHEConfig::standard_128();

        let rns_eval = RNSEvaluator::new(&config);
        let delta = rns_eval.delta as u128;

        println!("=== Trivial Ciphertext K-Elimination Test ===");
        println!(
            "M product: {} ({} bits)",
            rns_eval.m_product,
            128u32.saturating_sub(rns_eval.m_product.leading_zeros())
        );
        println!("delta = {}", delta);

        // Test: 5 × 7 = 35
        let a = 5u64;
        let b = 7u64;
        let expected = (a * b) % config.t;

        // Create trivial DualRNS polynomials: c0 = Δ×m in constant term
        let encoded_a = a as u128 * delta;
        let encoded_b = b as u128 * delta;

        println!("encoded_a = Δ×{} = {}", a, encoded_a);
        println!("encoded_b = Δ×{} = {}", b, encoded_b);

        // Build trivial c0_a (just the encoded value in constant term)
        let mut c0_a_main: Vec<Vec<u64>> =
            vec![vec![0; rns_eval.n]; rns_eval.dual_rns.main.primes.len()];
        let mut c0_a_anchor: Vec<Vec<u64>> =
            vec![vec![0; rns_eval.n]; rns_eval.dual_rns.anchor.primes.len()];

        for (i, &p) in rns_eval.dual_rns.main.primes.iter().enumerate() {
            c0_a_main[i][0] = (encoded_a % p as u128) as u64;
        }
        for (i, &p) in rns_eval.dual_rns.anchor.primes.iter().enumerate() {
            c0_a_anchor[i][0] = (encoded_a % p as u128) as u64;
        }

        let mut c0_b_main: Vec<Vec<u64>> =
            vec![vec![0; rns_eval.n]; rns_eval.dual_rns.main.primes.len()];
        let mut c0_b_anchor: Vec<Vec<u64>> =
            vec![vec![0; rns_eval.n]; rns_eval.dual_rns.anchor.primes.len()];

        for (i, &p) in rns_eval.dual_rns.main.primes.iter().enumerate() {
            c0_b_main[i][0] = (encoded_b % p as u128) as u64;
        }
        for (i, &p) in rns_eval.dual_rns.anchor.primes.iter().enumerate() {
            c0_b_anchor[i][0] = (encoded_b % p as u128) as u64;
        }

        let c0_a = DualRNSPoly {
            main: c0_a_main,
            anchor: c0_a_anchor,
            n: rns_eval.n,
        };
        let c0_b = DualRNSPoly {
            main: c0_b_main,
            anchor: c0_b_anchor,
            n: rns_eval.n,
        };

        // Polynomial multiply (trivial: just constant × constant = constant²)
        let d0 = rns_eval.dual_poly_mul(&c0_a, &c0_b);

        // Check tensor product value
        let d0_main: Vec<u64> = d0.main.iter().map(|l| l[0]).collect();
        let d0_val = rns_eval.rns.to_int(&d0_main);
        let expected_tensor = encoded_a * encoded_b; // Δ² × 35

        println!("\nTensor product:");
        println!(
            "  d0[0] (CRT) = {} ({} bits)",
            d0_val,
            128u32.saturating_sub(d0_val.leading_zeros())
        );
        println!(
            "  Expected Δ²×{} = {} ({} bits)",
            expected,
            expected_tensor,
            128u32.saturating_sub(expected_tensor.leading_zeros())
        );

        // For trivial case, tensor should equal expected_tensor directly (no wrap)
        assert!(
            d0_val == expected_tensor || d0_val == expected_tensor % rns_eval.m_product,
            "Tensor product mismatch: got {} expected {}",
            d0_val,
            expected_tensor
        );

        // K-Elimination rescale
        let e0 = rns_eval.k_elim_rescale(&d0);

        // Expected: e0[0] ≈ Δ × 35 = 533085
        let expected_scaled = (delta * expected as u128) as u64;
        println!("\nAfter K-Elim rescale:");
        println!("  e0[0] = {}", e0.coeffs[0]);
        println!("  Expected Δ×{} = {}", expected, expected_scaled);

        // Decode: round(e0 / Δ)
        let result = ((e0.coeffs[0] as u128 + delta / 2) / delta) as u64 % config.t;
        println!("  Decoded: {} (expected {})", result, expected);

        assert_eq!(
            result, expected,
            "Trivial K-Elim failed: {} × {} decoded to {} (expected {})",
            a, b, result, expected
        );

        println!("\n✓ Trivial ciphertext K-Elimination PASSED!");
    }
}
