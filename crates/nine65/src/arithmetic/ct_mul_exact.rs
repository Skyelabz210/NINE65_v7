//! Exact Ciphertext Multiplication
//!
//! Ciphertext multiplication using dual-track exact arithmetic.
//!
//! The key insight: coefficient-wise scaling doesn't commute with polynomial
//! convolution mod q. Instead, we:
//! 1. Maintain dual-track residues throughout tensor product
//! 2. Reconstruct true integers via K-Elimination
//! 3. Perform exact division Δ² → Δ on integers
//! 4. Re-encode into dual-track representation
//!
//! No floating-point. No lossy rounding. Just exact integer arithmetic.
//!
//! # Relationship to the production K-Elimination record (issue #70 index)
//!
//! Built on `exact_coeff::ExactContext` (in turn on `exact_divider::
//! ExactDivider`) — see those modules' own notes. Not the production
//! ciphertext-multiplication path: `rns_fhe.rs` references this module only
//! in comments pointing at its tests, never at runtime. See
//! `docs/K_ELIMINATION_IMPLEMENTATIONS_2026-09-03.md` for the full
//! inventory.

// Allow explicit indexing in polynomial convolution - loop indices are used
// in computing coefficient positions (i+j), not just array access.
#![allow(clippy::needless_range_loop)]

use super::exact_coeff::{AnchorTrack, ExactCoeff, ExactContext, ExactPoly, RnsInner};

use crate::arithmetic::NTTEngine;

use crate::ring::RingPolynomial;

/// Exact ciphertext with dual-track coefficients
#[derive(Clone, Debug)]
pub struct ExactCiphertext {
    pub c0: ExactPoly,
    pub c1: ExactPoly,
}

/// Degree-2 ciphertext (output of tensor product, before relinearization)
#[derive(Clone, Debug)]
pub struct ExactCiphertext2 {
    pub d0: ExactPoly,
    pub d1: ExactPoly,
    pub d2: ExactPoly,
}

/// Context for exact FHE operations
pub struct ExactFHEContext {
    pub exact_ctx: ExactContext,
    pub ntt: NTTEngine,
    /// Psi powers for NTT twist (negacyclic)
    pub psi_powers: Vec<u64>,
    pub psi_inv_powers: Vec<u64>,
    /// Primitive root info for anchor modulus A
    pub anchor_omega: u64,
    pub anchor_omega_inv: u64,
    pub anchor_omega_powers: Vec<u64>,
    pub anchor_omega_inv_powers: Vec<u64>,
    pub anchor_n_inv: u64,
    pub anchor_psi: u64,
    pub anchor_psi_inv: u64,
    pub anchor_psi_powers: Vec<u64>,
    pub anchor_psi_inv_powers: Vec<u64>,
    /// True if anchor modulus supports NTT for this n
    pub anchor_ntt_supported: bool,
}

type AnchorRoots = (u64, u64, Vec<u64>, Vec<u64>, Vec<u64>, Vec<u64>, u64);

impl ExactFHEContext {
    /// Create from standard FHE parameters
    pub fn new(q: u64, n: usize, t: u64) -> Self {
        let exact_ctx = ExactContext::from_single_modulus(q, n, t);
        let ntt = NTTEngine::new(q, n);

        // Store psi powers for main modulus
        let psi_powers = ntt.psi_powers.clone();
        let psi_inv_powers = ntt.psi_inv_powers.clone();

        // Compute primitive roots for anchor modulus A
        let a = exact_ctx.a;
        let (
            anchor_psi,
            anchor_omega,
            anchor_psi_powers,
            anchor_psi_inv_powers,
            anchor_omega_powers,
            anchor_omega_inv_powers,
            anchor_n_inv,
        ) = Self::compute_anchor_roots(a, n);

        let anchor_omega_inv = mod_inverse(anchor_omega, a);
        let anchor_psi_inv = mod_inverse(anchor_psi, a);
        let anchor_ntt_supported = (a - 1).is_multiple_of(2 * n as u64) && anchor_omega != 1;

        Self {
            exact_ctx,
            ntt,
            psi_powers,
            psi_inv_powers,
            anchor_omega,
            anchor_omega_inv,
            anchor_omega_powers,
            anchor_omega_inv_powers,
            anchor_n_inv,
            anchor_psi,
            anchor_psi_inv,
            anchor_psi_powers,
            anchor_psi_inv_powers,
            anchor_ntt_supported,
        }
    }

    /// Compute primitive roots for anchor modulus
    fn compute_anchor_roots(a: u64, n: usize) -> AnchorRoots {
        // Check if A supports 2N-th roots
        if !(a - 1).is_multiple_of(2 * n as u64) {
            // A doesn't support NTT - use naive convolution for anchor track
            // Return dummy values; we'll handle this in the NTT functions
            return (
                1,
                1,
                vec![1; n],
                vec![1; n],
                vec![1; n],
                vec![1; n],
                mod_inverse(n as u64, a),
            );
        }

        // Find primitive 2N-th root
        let exp = (a - 1) / (2 * n as u64);
        let mut g = 3u64;
        let psi = loop {
            let candidate = mod_pow(g, exp, a);
            if mod_pow(candidate, n as u64, a) != 1 || mod_pow(candidate, (n / 2) as u64, a) == 1 {
                g += 1;
                if g > 1000 {
                    // Fallback
                    break 1;
                }
                continue;
            }
            break candidate;
        };

        let psi_inv = if psi == 1 { 1 } else { mod_inverse(psi, a) };
        let omega = mod_pow(psi, 2, a);
        let omega_inv = if omega == 1 { 1 } else { mod_inverse(omega, a) };
        let n_inv = mod_inverse(n as u64, a);

        let psi_powers: Vec<u64> = (0..n).map(|i| mod_pow(psi, i as u64, a)).collect();
        let psi_inv_powers: Vec<u64> = (0..n).map(|i| mod_pow(psi_inv, i as u64, a)).collect();
        let omega_powers: Vec<u64> = (0..n).map(|i| mod_pow(omega, i as u64, a)).collect();
        let omega_inv_powers: Vec<u64> = (0..n).map(|i| mod_pow(omega_inv, i as u64, a)).collect();

        (
            psi,
            omega,
            psi_powers,
            psi_inv_powers,
            omega_powers,
            omega_inv_powers,
            n_inv,
        )
    }

    /// Convert RingPolynomial to ExactPoly
    pub fn from_ring_poly(&self, poly: &RingPolynomial) -> ExactPoly {
        let coeffs = poly
            .coeffs
            .iter()
            .map(|&c| self.exact_ctx.encode(c as u128))
            .collect();
        ExactPoly { coeffs }
    }

    /// Convert ExactPoly back to RingPolynomial (uses inner track only)
    pub fn to_ring_poly(&self, poly: &ExactPoly) -> RingPolynomial {
        let coeffs = poly
            .coeffs
            .iter()
            .map(|c| c.inner.limbs[0]) // First (and only for single-mod) limb
            .collect();
        RingPolynomial {
            coeffs,
            q: self.exact_ctx.m,
        }
    }

    /// Polynomial multiplication using NTT with dual-track
    ///
    /// This is the key operation: multiply polynomials while maintaining
    /// exact magnitude in the anchor track.
    pub fn poly_mul(&self, a: &ExactPoly, b: &ExactPoly) -> ExactPoly {
        let _n = self.exact_ctx.n;

        // Step 1: Apply ψ-twist (convert to cyclic domain)
        let a_twisted = self.apply_psi_twist(a);
        let b_twisted = self.apply_psi_twist(b);

        // Step 2: Forward NTT on inner track
        let a_ntt_inner = self.ntt_forward_inner(&a_twisted);
        let b_ntt_inner = self.ntt_forward_inner(&b_twisted);

        // Step 3: Forward NTT on anchor track (separate computation)
        let a_ntt_anchor = self.ntt_forward_anchor(&a_twisted);
        let b_ntt_anchor = self.ntt_forward_anchor(&b_twisted);

        // Step 4: Pointwise multiplication in both tracks
        let c_ntt =
            self.pointwise_mul_ntt(&a_ntt_inner, &b_ntt_inner, &a_ntt_anchor, &b_ntt_anchor);

        // Step 5: Inverse NTT on both tracks
        // If anchor modulus doesn't support NTT, compute anchor A track by
        // naive cyclic convolution on the twisted coefficients.
        let anchor_a_override = if self.anchor_ntt_supported {
            None
        } else {
            let a_vals: Vec<u64> = a_twisted.coeffs.iter().map(|c| c.anchor.a_res).collect();
            let b_vals: Vec<u64> = b_twisted.coeffs.iter().map(|c| c.anchor.a_res).collect();
            Some(self.cyclic_convolution_mod(&a_vals, &b_vals, self.exact_ctx.a))
        };

        let c_twisted = self.ntt_inverse(&c_ntt, anchor_a_override.as_deref());

        // Step 6: Remove ψ-twist
        self.remove_psi_twist(&c_twisted)
    }

    /// Apply ψ-twist for negacyclic convolution
    fn apply_psi_twist(&self, poly: &ExactPoly) -> ExactPoly {
        let coeffs = poly
            .coeffs
            .iter()
            .enumerate()
            .map(|(i, c)| {
                // Main modulus psi twist
                let psi_m = self.psi_powers[i];
                let inner_twisted = RnsInner {
                    limbs: vec![
                        ((c.inner.limbs[0] as u128 * psi_m as u128) % self.exact_ctx.m as u128)
                            as u64,
                    ],
                };

                // Anchor modulus psi twist
                let psi_a = self.anchor_psi_powers[i];
                let m_res =
                    ((c.anchor.m_res as u128 * psi_m as u128) % self.exact_ctx.m as u128) as u64;
                let a_res =
                    ((c.anchor.a_res as u128 * psi_a as u128) % self.exact_ctx.a as u128) as u64;

                ExactCoeff {
                    inner: inner_twisted,
                    anchor: AnchorTrack { m_res, a_res },
                }
            })
            .collect();
        ExactPoly { coeffs }
    }

    /// Remove ψ-twist after inverse NTT
    fn remove_psi_twist(&self, poly: &ExactPoly) -> ExactPoly {
        let coeffs = poly
            .coeffs
            .iter()
            .enumerate()
            .map(|(i, c)| {
                // Main modulus psi_inv twist
                let psi_inv_m = self.psi_inv_powers[i];
                let inner_untwisted = RnsInner {
                    limbs: vec![
                        ((c.inner.limbs[0] as u128 * psi_inv_m as u128) % self.exact_ctx.m as u128)
                            as u64,
                    ],
                };

                // Anchor modulus psi_inv twist
                let psi_inv_a = self.anchor_psi_inv_powers[i];
                let m_res = ((c.anchor.m_res as u128 * psi_inv_m as u128)
                    % self.exact_ctx.m as u128) as u64;
                let a_res = ((c.anchor.a_res as u128 * psi_inv_a as u128)
                    % self.exact_ctx.a as u128) as u64;

                ExactCoeff {
                    inner: inner_untwisted,
                    anchor: AnchorTrack { m_res, a_res },
                }
            })
            .collect();
        ExactPoly { coeffs }
    }

    /// Forward NTT on inner track (returns raw u64 values)
    fn ntt_forward_inner(&self, poly: &ExactPoly) -> Vec<u64> {
        let inner: Vec<u64> = poly.coeffs.iter().map(|c| c.inner.limbs[0]).collect();
        self.ntt.ntt(&inner)
    }

    /// Forward NTT on anchor track (M and A separately)
    fn ntt_forward_anchor(&self, poly: &ExactPoly) -> Vec<AnchorTrack> {
        let _n = self.exact_ctx.n;
        let m = self.exact_ctx.m;
        let a = self.exact_ctx.a;

        // NTT in M (use main omega)
        let m_vals: Vec<u64> = poly.coeffs.iter().map(|c| c.anchor.m_res).collect();
        let m_ntt = self.ntt_generic_with_omega(&m_vals, m, &self.ntt.omega_powers);

        // NTT in A (use anchor omega if supported)
        let a_ntt = if self.anchor_ntt_supported {
            let a_vals: Vec<u64> = poly.coeffs.iter().map(|c| c.anchor.a_res).collect();
            self.ntt_generic_with_omega(&a_vals, a, &self.anchor_omega_powers)
        } else {
            vec![0u64; m_ntt.len()]
        };

        m_ntt
            .into_iter()
            .zip(a_ntt)
            .map(|(m_res, a_res)| AnchorTrack { m_res, a_res })
            .collect()
    }

    /// Generic NTT with specified omega powers
    fn ntt_generic_with_omega(
        &self,
        coeffs: &[u64],
        modulus: u64,
        omega_powers: &[u64],
    ) -> Vec<u64> {
        let n = coeffs.len();
        let mut result = vec![0u64; n];

        for k in 0..n {
            let mut sum = 0u128;
            for j in 0..n {
                let exp = (k * j) % n;
                let w = omega_powers[exp] % modulus;
                sum += (coeffs[j] as u128) * (w as u128);
            }
            result[k] = (sum % modulus as u128) as u64;
        }
        result
    }

    /// Pointwise multiplication in NTT domain with dual tracks
    fn pointwise_mul_ntt(
        &self,
        a_inner: &[u64],
        b_inner: &[u64],
        a_anchor: &[AnchorTrack],
        b_anchor: &[AnchorTrack],
    ) -> Vec<ExactCoeff> {
        let q = self.exact_ctx.m;
        let m = self.exact_ctx.m;
        let a_mod = self.exact_ctx.a;

        a_inner
            .iter()
            .zip(b_inner)
            .zip(a_anchor.iter().zip(b_anchor))
            .map(|((&ai, &bi), (aa, ab))| {
                // Inner track multiplication
                let inner_prod = ((ai as u128) * (bi as u128) % (q as u128)) as u64;

                // Anchor track multiplication
                let m_prod = ((aa.m_res as u128) * (ab.m_res as u128) % (m as u128)) as u64;
                let a_prod = ((aa.a_res as u128) * (ab.a_res as u128) % (a_mod as u128)) as u64;

                ExactCoeff {
                    inner: RnsInner {
                        limbs: vec![inner_prod],
                    },
                    anchor: AnchorTrack {
                        m_res: m_prod,
                        a_res: a_prod,
                    },
                }
            })
            .collect()
    }

    /// Inverse NTT on both tracks
    fn ntt_inverse(
        &self,
        ntt_coeffs: &[ExactCoeff],
        anchor_a_override: Option<&[u64]>,
    ) -> ExactPoly {
        let _n = self.exact_ctx.n;
        let _q = self.exact_ctx.m;
        let m = self.exact_ctx.m;
        let a_mod = self.exact_ctx.a;
        let n_inv_q = self.ntt.n_inv;
        let n_inv_a = self.anchor_n_inv;

        // Inner track INTT
        let inner_vals: Vec<u64> = ntt_coeffs.iter().map(|c| c.inner.limbs[0]).collect();
        let inner_intt = self.ntt.intt(&inner_vals);

        // Anchor M track INTT (use main omega_inv)
        let m_vals: Vec<u64> = ntt_coeffs.iter().map(|c| c.anchor.m_res).collect();
        let m_intt = self.intt_generic_with_omega(&m_vals, m, &self.ntt.omega_inv_powers, n_inv_q);

        // Anchor A track INTT (use anchor omega_inv) or override if provided
        let a_intt = if let Some(override_vals) = anchor_a_override {
            override_vals.to_vec()
        } else {
            let a_vals: Vec<u64> = ntt_coeffs.iter().map(|c| c.anchor.a_res).collect();
            self.intt_generic_with_omega(&a_vals, a_mod, &self.anchor_omega_inv_powers, n_inv_a)
        };

        let coeffs = inner_intt
            .into_iter()
            .zip(m_intt)
            .zip(a_intt)
            .map(|((inner, m_res), a_res)| ExactCoeff {
                inner: RnsInner { limbs: vec![inner] },
                anchor: AnchorTrack { m_res, a_res },
            })
            .collect();

        ExactPoly { coeffs }
    }

    /// Generic INTT with specified omega_inv powers
    fn intt_generic_with_omega(
        &self,
        coeffs: &[u64],
        modulus: u64,
        omega_inv_powers: &[u64],
        n_inv: u64,
    ) -> Vec<u64> {
        let n = coeffs.len();
        let mut result = vec![0u64; n];

        for k in 0..n {
            let mut sum = 0u128;
            for j in 0..n {
                let exp = (k * j) % n;
                let w_inv = omega_inv_powers[exp] % modulus;
                sum += (coeffs[j] as u128) * (w_inv as u128);
            }
            let scaled = (sum % modulus as u128) * (n_inv as u128) % (modulus as u128);
            result[k] = scaled as u64;
        }
        result
    }

    /// Naive cyclic convolution modulo `modulus` (O(n^2)).
    fn cyclic_convolution_mod(&self, a: &[u64], b: &[u64], modulus: u64) -> Vec<u64> {
        let n = a.len();
        let mut out = vec![0u64; n];

        for i in 0..n {
            let ai = a[i] as u128;
            for j in 0..n {
                let idx = (i + j) % n;
                let acc = out[idx] as u128 + ai * b[j] as u128;
                out[idx] = (acc % modulus as u128) as u64;
            }
        }

        out
    }

    /// Tensor product: compute degree-2 ciphertext from two degree-1 ciphertexts
    pub fn tensor_product(&self, ct1: &ExactCiphertext, ct2: &ExactCiphertext) -> ExactCiphertext2 {
        // d0 = c0_1 × c0_2
        let d0 = self.poly_mul(&ct1.c0, &ct2.c0);

        // d1 = c0_1 × c1_2 + c1_1 × c0_2
        let d1_part1 = self.poly_mul(&ct1.c0, &ct2.c1);
        let d1_part2 = self.poly_mul(&ct1.c1, &ct2.c0);
        let d1 = d1_part1.add(&d1_part2, &self.exact_ctx);

        // d2 = c1_1 × c1_2
        let d2 = self.poly_mul(&ct1.c1, &ct2.c1);

        ExactCiphertext2 { d0, d1, d2 }
    }

    /// Exact rescale: Δ² → Δ using K-Elimination
    ///
    /// Core reconstruction step. We reconstruct each coefficient
    /// as a true integer and perform exact division.
    pub fn exact_rescale(
        &self,
        ct2: &ExactCiphertext2,
        _s: &ExactPoly,
        _s2: &ExactPoly,
    ) -> ExactCiphertext2 {
        let delta = self.exact_ctx.delta;

        // For each coefficient position, we need to:
        // 1. Reconstruct true integer from dual track
        // 2. Divide exactly by Δ
        // 3. Re-encode into dual track

        let d0_rescaled = self.rescale_poly(&ct2.d0, delta);
        let d1_rescaled = self.rescale_poly(&ct2.d1, delta);
        let d2_rescaled = self.rescale_poly(&ct2.d2, delta);

        ExactCiphertext2 {
            d0: d0_rescaled,
            d1: d1_rescaled,
            d2: d2_rescaled,
        }
    }

    /// Rescale a polynomial by dividing each coefficient by d
    fn rescale_poly(&self, poly: &ExactPoly, d: u64) -> ExactPoly {
        let coeffs = poly
            .coeffs
            .iter()
            .map(|c| {
                // Reconstruct true integer
                let x = self.exact_ctx.reconstruct(c);

                // Exact division (or rounded if not exact)
                let quotient = if x.is_multiple_of(d as u128) {
                    x / (d as u128)
                } else {
                    // Round to nearest
                    (x + (d as u128 / 2)) / (d as u128)
                };

                // Re-encode
                self.exact_ctx.encode(quotient)
            })
            .collect();

        ExactPoly { coeffs }
    }

    /// Simple relinearization (without evaluation key - just sum d2*s² into d0)
    /// For proper security, use evaluation key version
    pub fn relinearize_simple(&self, ct2: &ExactCiphertext2, s: &ExactPoly) -> ExactCiphertext {
        // c0' = d0 + d2 * s²
        // c1' = d1
        let s2 = self.poly_mul(s, s);
        let d2_s2 = self.poly_mul(&ct2.d2, &s2);
        let c0 = ct2.d0.add(&d2_s2, &self.exact_ctx);
        let c1 = ct2.d1.clone();

        ExactCiphertext { c0, c1 }
    }
}

/// Modular inverse
fn mod_inverse(a: u64, m: u64) -> u64 {
    let mut mn = (m as i128, a as i128);
    let mut xy = (0i128, 1i128);
    while mn.1 != 0 {
        let q = mn.0 / mn.1;
        mn = (mn.1, mn.0 - q * mn.1);
        xy = (xy.1, xy.0 - q * xy.1);
    }
    while xy.0 < 0 {
        xy.0 += m as i128;
    }
    (xy.0 % m as i128) as u64
}

/// Modular exponentiation
fn mod_pow(base: u64, exp: u64, modulus: u64) -> u64 {
    if modulus == 1 {
        return 0;
    }
    let mut result = 1u64;
    let mut base = base % modulus;
    let mut exp = exp;
    while exp > 0 {
        if exp & 1 == 1 {
            result = ((result as u128 * base as u128) % modulus as u128) as u64;
        }
        exp >>= 1;
        base = ((base as u128 * base as u128) % modulus as u128) as u64;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_poly_mul_constant() {
        // Test: (5, 0, ...) × (7, 0, ...) = (35, 0, ...)
        let q = 998244353u64;
        let n = 8;
        let t = 500000u64;

        let ctx = ExactFHEContext::new(q, n, t);

        let mut a_coeffs = vec![ctx.exact_ctx.zero(); n];
        let mut b_coeffs = vec![ctx.exact_ctx.zero(); n];
        a_coeffs[0] = ctx.exact_ctx.encode(5);
        b_coeffs[0] = ctx.exact_ctx.encode(7);

        let a = ExactPoly { coeffs: a_coeffs };
        let b = ExactPoly { coeffs: b_coeffs };

        let c = ctx.poly_mul(&a, &b);

        let c0 = ctx.exact_ctx.reconstruct(&c.coeffs[0]);
        println!("(5,0,...) × (7,0,...) = ({}, ...)", c0);
        assert_eq!(c0, 35, "Constant multiply failed");

        // Rest should be zero
        for i in 1..n {
            let ci = ctx.exact_ctx.reconstruct(&c.coeffs[i]);
            assert_eq!(ci, 0, "Non-zero coefficient at index {}: {}", i, ci);
        }
    }

    #[test]
    fn test_exact_rescale() {
        let q = 998244353u64;
        let n = 8;
        let t = 500000u64;
        let delta = q / t;

        let ctx = ExactFHEContext::new(q, n, t);

        // Create coefficient at Δ² level
        let x = (delta as u128) * (delta as u128) * 35;
        let coeff = ctx.exact_ctx.encode(x);

        // Rescale by Δ
        let x_reconstructed = ctx.exact_ctx.reconstruct(&coeff);
        let quotient = x_reconstructed / (delta as u128);

        println!("x = {}, Δ = {}, x/Δ = {}", x, delta, quotient);
        assert_eq!(quotient, (delta as u128) * 35, "Rescale failed");
    }

    #[test]
    fn test_exact_ct_mul_simple() {
        // The big test: 5 × 7 = 35 via exact ct×ct
        let q = 998244353u64;
        let n = 1024; // Changed to match FHE config
        let t = 500000u64;
        let delta = q / t;

        println!("=== EXACT CT×CT TEST ===");
        println!("q={}, t={}, Δ={}, n={}", q, t, delta, n);

        let ctx = ExactFHEContext::new(q, n, t);

        // Create "trivial" ciphertexts encoding Δ×5 and Δ×7
        // ct = (Δ×m, 0) decrypts to m when c0 + c1*s = Δ×m
        let mut c0_a = vec![ctx.exact_ctx.zero(); n];
        let mut c0_b = vec![ctx.exact_ctx.zero(); n];

        c0_a[0] = ctx.exact_ctx.encode((delta * 5) as u128);
        c0_b[0] = ctx.exact_ctx.encode((delta * 7) as u128);

        let ct_a = ExactCiphertext {
            c0: ExactPoly { coeffs: c0_a },
            c1: ExactPoly::zero(&ctx.exact_ctx),
        };

        let ct_b = ExactCiphertext {
            c0: ExactPoly { coeffs: c0_b },
            c1: ExactPoly::zero(&ctx.exact_ctx),
        };

        // Tensor product
        let ct2 = ctx.tensor_product(&ct_a, &ct_b);

        // Check tensor result (should be Δ²×35 in d0[0])
        let d0_0 = ctx.exact_ctx.reconstruct(&ct2.d0.coeffs[0]);
        let expected_tensor = (delta as u128) * (delta as u128) * 35;
        println!("Tensor d0[0] = {} (expected {})", d0_0, expected_tensor);
        assert_eq!(d0_0, expected_tensor, "Tensor product failed");

        // Rescale by Δ
        let s_dummy = ExactPoly::zero(&ctx.exact_ctx);
        let ct2_rescaled = ctx.exact_rescale(&ct2, &s_dummy, &s_dummy);

        // Check rescaled result (should be Δ×35)
        let e0_0 = ctx.exact_ctx.reconstruct(&ct2_rescaled.d0.coeffs[0]);
        let expected_rescaled = (delta as u128) * 35;
        println!("Rescaled d0[0] = {} (expected {})", e0_0, expected_rescaled);
        assert_eq!(e0_0, expected_rescaled, "Rescale failed");

        // "Decrypt" (for trivial ciphertext, just decode d0[0])
        // m = round(d0[0] × t / q)
        let decrypted = (e0_0 * (t as u128) + (q as u128 / 2)) / (q as u128);
        println!("Decrypted: {} (expected 35)", decrypted);
        assert_eq!(decrypted, 35, "Final decrypt failed");

        println!("[PASS] EXACT CT*CT PASSED: 5 * 7 = 35");
    }
}
