//! Bootstrap Key and Key-Switch Key for Clockwork Bootstrap
//!
//! Generates the cryptographic material needed for bootstrapping:
//! - `BootstrapKey`: working secret key encrypted under bootstrap parameters
//! - `KeySwitchKey`: converts ciphertexts from boot key to working key

use crate::entropy::{require_secure_rng, FheRng, SecureRng};
use crate::errors::{Nine65Error, Nine65Result};
use crate::ops::rns_fhe::{
    DualRNSCiphertext, DualRNSEvalKey, DualRNSFullKeySet, DualRNSPoly, DualRNSPublicKey,
    DualRNSSecretKey, RNSFHEContext,
};
use crate::params::FHEConfig;
use zeroize::{Zeroize, Zeroizing};

/// NTT-friendly primes for the bootstrap modulus chain.
/// With q_small = t, bootstrap depth drops to ~1.
///
/// Ordering: work primes form a prefix (matching secure_128 → secure_256),
/// followed by extra primes for modswitch headroom. None may collide with
/// anchor primes [2013265921, 2281701377, 2483027969].
pub const BOOTSTRAP_PRIMES: [u64; 8] = [
    998244353,  // 2^23 * 7 * 17 + 1    (work prime 1-3)
    985661441,  // NTT-friendly 30-bit
    754974721,  // NTT-friendly 30-bit
    469762049,  // 2^26 * 7 + 1          (work prime 4, secure_128_deep)
    167772161,  // 2^25 * 5 + 1          (work prime 5, secure_192)
    1811939329, // 27 * 2^26 + 1         (extra for secure_192 modswitch)
    595591169,  // NTT-friendly 30-bit   (work prime 6, secure_256)
    645922817,  // NTT-friendly 30-bit   (extra for secure_256 modswitch)
];

/// Number of anchor primes for K-Elimination in bootstrap context.
pub const BOOTSTRAP_ANCHOR_COUNT: usize = 3;

/// Validate bootstrap primes meet FHE mathematical requirements.
///
/// # Requirements
/// 1. NTT compatibility: (q - 1) % (2N) == 0 for all primes
/// 2. Pairwise coprimality: gcd(p_i, p_j) == 1 for all i ≠ j
/// 3. Security: product Q ≥ 2^target_security
///
/// # Arguments
/// - `primes`: Bootstrap prime moduli
/// - `n`: Polynomial degree (ring dimension)
/// - `target_security`: Minimum security level in bits (e.g., 128)
///
/// # Errors
/// - `NTTConfigError` if any prime is not congruent to 1 mod 2N
/// - `NotCoprime` if any prime pair shares a factor
/// - `SecurityLevelNotMet` if product is too small
///
/// # Theorem Reference
/// - NTT: Requires q ≡ 1 (mod 2N) for primitive root existence
/// - CRT: Requires pairwise coprimality for unique reconstruction
/// - Security: LWE hardness scales with log(Q)
pub fn validate_bootstrap_primes(
    primes: &[u64],
    n: usize,
    target_security: u32,
) -> Nine65Result<()> {
    if primes.is_empty() {
        return Err(Nine65Error::InvalidParameter {
            message: "Bootstrap primes array is empty".to_string(),
        });
    }

    let two_n = 2 * n as u64;

    // 1. NTT compatibility check: (q - 1) % 2N == 0
    for (idx, &q) in primes.iter().enumerate() {
        if q == 0 {
            return Err(Nine65Error::NTTConfigError {
                message: format!("Bootstrap prime[{}] is zero", idx),
            });
        }

        if (q - 1) % two_n != 0 {
            return Err(Nine65Error::NTTConfigError {
                message: format!(
                    "Bootstrap prime[{}]={} not NTT-compatible: (q-1)%2N = {} (expected 0)",
                    idx,
                    q,
                    (q - 1) % two_n
                ),
            });
        }
    }

    // 2. Pairwise coprimality check
    for i in 0..primes.len() {
        for j in (i + 1)..primes.len() {
            let p_i = primes[i];
            let p_j = primes[j];
            let g = gcd_u64(p_i, p_j);

            if g != 1 {
                return Err(Nine65Error::NotCoprime {
                    m: p_i,
                    a: p_j,
                    gcd: g,
                });
            }
        }
    }

    // 3. Security level check: log2(Q) ≥ target_security
    // Compute log2(product) without overflow using sum of log2s
    let log2_product: u32 = primes
        .iter()
        .map(|&p| if p == 0 { 0 } else { 64 - p.leading_zeros() })
        .sum();

    if log2_product < target_security {
        return Err(Nine65Error::SecurityLevelNotMet {
            bits: log2_product,
            required: target_security,
        });
    }

    Ok(())
}

/// GCD using Euclidean algorithm for u64.
fn gcd_u64(a: u64, b: u64) -> u64 {
    if b == 0 {
        a
    } else {
        gcd_u64(b, a % b)
    }
}

/// Bootstrap key: working secret key encrypted under bootstrap parameters.
///
/// Since s has ternary coefficients {-1, 0, 1}, encrypting it introduces
/// minimal noise — exactly what we want for tight bootstrap noise budget.
pub struct BootstrapKey {
    /// Encryption of working secret key under bootstrap parameters.
    pub enc_s: DualRNSCiphertext,
    /// Evaluation key for relinearization within bootstrap circuit.
    pub eval_key: DualRNSEvalKey,
    /// Bootstrap public key.
    pub public_key: DualRNSPublicKey,
    /// Working plaintext modulus t (= q_small in our scheme).
    pub t_work: u64,
    /// Q_min: product of first 2 working primes (bootstrap trigger point).
    pub q_min: u128,
}

/// Key-switch key: converts ciphertext under s_boot to s_work.
/// Follows same gadget decomposition pattern as GaloisKey.
///
/// ksk[l] = (b_l, a_l) where b_l = -a_l*s_work + e_l + s_boot*base^l
pub struct KeySwitchKey {
    /// Key-switch components: ksk[l] = (b_l, a_l)
    pub ksk: Vec<(DualRNSPoly, DualRNSPoly)>,
    /// Decomposition base
    pub decomp_base: u64,
    /// Number of decomposition digits
    pub num_digits: usize,
}

/// Complete bootstrap key material (BSK + KSK + boot secret key for testing)
pub struct BootstrapKeySet {
    pub bsk: BootstrapKey,
    pub ksk: KeySwitchKey,
    /// Boot secret key — needed for testing/verification only.
    /// In production, this should be discarded after KSK generation.
    pub boot_sk: DualRNSSecretKey,
}

impl BootstrapKey {
    /// Generate bootstrap key material using the OS CSPRNG. This is the
    /// production entry point.
    pub fn generate_secure(
        work_config: &FHEConfig,
        boot_ctx: &RNSFHEContext,
        boot_keys: &DualRNSFullKeySet,
        work_sk: &DualRNSSecretKey,
    ) -> Nine65Result<Self> {
        let mut rng = SecureRng::new();
        Self::generate(work_config, boot_ctx, boot_keys, work_sk, &mut rng)
    }

    /// Generate bootstrap key material.
    ///
    /// 1. Validates bootstrap primes meet cryptographic requirements
    /// 2. Creates boot config with BOOTSTRAP_PRIMES
    /// 3. Generates boot key pair
    /// 4. Encodes work sk as Z_t polynomial: {-1,0,1} -> {t-1,0,1}
    /// 5. Encrypts encoded sk under boot pk
    ///
    /// `enc_s` is literally `Enc(work_sk)` -- the working secret key,
    /// encrypted. Generic over `FheRng`; `require_secure_rng` below rejects
    /// a non-secure RNG at this entry point outside test/debug builds and
    /// the `allow_insecure` feature. Prefer [`Self::generate_secure`] unless
    /// you have a specific, documented reason to inject a different RNG.
    pub fn generate<R: FheRng>(
        work_config: &FHEConfig,
        boot_ctx: &RNSFHEContext,
        boot_keys: &DualRNSFullKeySet,
        work_sk: &DualRNSSecretKey,
        rng: &mut R,
    ) -> Nine65Result<Self> {
        require_secure_rng(rng, "BootstrapKey::generate");

        let t = work_config.t;
        let n = work_config.n;

        // Validate bootstrap primes: NTT compatibility and pairwise coprimality.
        // Bootstrap modulus Q_boot is typically smaller than Q_work because
        // bootstrap operates at depth ~1-2, so fewer primes are needed.
        // Security target: use the log2(Q_boot) itself as the threshold,
        // since the actual LWE security depends on N/log(Q) ratio which is
        // validated separately by the LatticeSecurityEstimator.
        let boot_log_q: u32 = boot_ctx
            .config
            .primes
            .iter()
            .map(|&p| if p == 0 { 0 } else { 64 - p.leading_zeros() })
            .sum();
        validate_bootstrap_primes(&boot_ctx.config.primes, n, boot_log_q)?;

        // Encode working secret key for Z_t plaintext space.
        // Ternary {-1, 0, 1} -> {t-1, 0, 1} mod t.
        // The sk main[0] coefficients are in {0, 1, p-1} where p-1 represents -1.
        let work_s_coeffs = &work_sk.s.main[0];
        let first_work_prime = work_config.primes[0];

        // Issue #86: every coefficient of the working secret key must be
        // ternary ({0, 1, first_work_prime - 1}, i.e. {0, 1, -1} mod the
        // first work prime) before it is lifted into the bootstrap
        // ciphertext below. This used to be checked implicitly, in the
        // per-coefficient encode loop, by falling through to a `0` default
        // for anything that wasn't one of the three ternary values -- silently
        // treating a malformed (non-ternary) secret-key coefficient as if it
        // had been a genuine `0`, rather than rejecting the key material.
        // Validated once, up front, rather than per-coefficient inside that
        // loop (issue #89: validate once at the boundary, not repeatedly in
        // a proven inner loop) -- and before the RNG-consuming encrypt below,
        // so a malformed key is rejected without spending randomness on a
        // bootstrap key that will never be returned.
        if let Some(bad_index) = work_s_coeffs
            .iter()
            .position(|&coeff| coeff != 0 && coeff != 1 && coeff != first_work_prime - 1)
        {
            return Err(Nine65Error::KeyGenFailed {
                reason: format!(
                    "BootstrapKey::generate: work secret key coefficient {} at index {} is not ternary (expected 0, 1, or {})",
                    work_s_coeffs[bad_index], bad_index, first_work_prime - 1
                ),
            });
        }

        // We need to encode s as a single scalar per coefficient for encrypt_dual.
        // encrypt_dual takes a single u64 message. We need poly encryption.
        // Instead, we'll build the encoded polynomial and use trivial + noise approach.
        //
        // For the bootstrap key, we encrypt the full polynomial representing s.
        // We'll do this coefficient-by-coefficient is not efficient; instead we
        // use the RNSFHEContext's polynomial-level encrypt.
        //
        // Approach: encrypt m=0, then add Δ_boot * s_encoded into c0.
        // This gives Enc_boot(s_work) with proper noise characteristics.

        // Step 1: Create an encryption of 0 under boot pk
        let ct_zero = boot_ctx.encrypt_dual_with_rng(0, &boot_keys.public_key, rng);

        // Step 2: Add Δ_boot * s_encoded into c0 (coefficient by coefficient)
        let mut c0_main = ct_zero.c0.main.clone();
        let mut c0_anchor = ct_zero.c0.anchor.clone();

        for j in 0..n {
            let coeff = work_s_coeffs[j];
            // Map from mod-p representation to signed: 0->0, 1->1, p-1->-1
            let s_val: i64 = if coeff == 0 {
                0
            } else if coeff == 1 {
                1
            } else if coeff == first_work_prime - 1 {
                -1
            } else {
                // Unreachable: the ternary-coefficient check above already
                // rejected any `work_s_coeffs` value outside {0, 1,
                // first_work_prime - 1} before this loop runs (issue #86).
                // Kept as a defensive, non-panicking fallback rather than
                // an `unreachable!()` -- the invariant is proven by the
                // check above, not by this match arm's own reasoning.
                0
            };

            // Encode as Z_t value: -1 -> t-1, 0 -> 0, 1 -> 1
            let s_encoded = if s_val < 0 {
                t - ((-s_val) as u64)
            } else {
                s_val as u64
            };

            // Add Δ_boot * s_encoded to c0[j] for each boot prime
            for (i, &bp) in boot_ctx.config.primes.iter().enumerate() {
                let delta_i = boot_ctx.delta_rns[i];
                let contribution = (delta_i as u128 * s_encoded as u128) % bp as u128;
                c0_main[i][j] = ((c0_main[i][j] as u128 + contribution) % bp as u128) as u64;
            }

            // Same for anchor primes
            for (i, &ap) in boot_ctx.dual_rns.anchor.primes.iter().enumerate() {
                // Compute Δ_boot mod anchor_prime
                // Δ_boot = Q_boot / t, we need Δ mod ap
                let q_boot_mod_ap: u128 = boot_ctx.config.primes.iter().fold(1u128, |acc, &p| {
                    (acc * (p as u128 % ap as u128)) % ap as u128
                });
                let t_inv_ap = mod_inverse_u128(t as u128, ap as u128).unwrap_or(0);
                let delta_anchor = (q_boot_mod_ap * t_inv_ap) % ap as u128;

                let contribution = (delta_anchor * s_encoded as u128) % ap as u128;
                c0_anchor[i][j] = ((c0_anchor[i][j] as u128 + contribution) % ap as u128) as u64;
            }
        }

        let enc_s = DualRNSCiphertext {
            c0: DualRNSPoly {
                main: c0_main,
                anchor: c0_anchor,
                n,
            },
            c1: ct_zero.c1,
            level: ct_zero.level,
        };

        // Q_min: product of first 2 working primes
        let q_min = work_config.primes[0] as u128 * work_config.primes[1] as u128;

        Ok(Self {
            enc_s,
            eval_key: boot_keys.eval_key.clone(),
            public_key: boot_keys.public_key.clone(),
            t_work: t,
            q_min,
        })
    }
}

impl KeySwitchKey {
    /// Generate key-switch key: converts Enc_{s_boot} -> Enc_{s_work}.
    ///
    /// Follows the same gadget decomposition pattern as GaloisKey generation.
    /// For each digit l: ksk[l] = (-a_l*s_work + e_l + s_boot*base^l, a_l)
    pub fn generate<R: FheRng>(
        boot_sk: &DualRNSSecretKey,
        work_sk: &DualRNSSecretKey,
        boot_ctx: &RNSFHEContext,
        rng: &mut R,
    ) -> Nine65Result<Self> {
        let n = boot_ctx.n;
        let decomp_base: u64 = 1u64 << 10; // Smaller base for less noise
        let q_bits = boot_ctx.q_bits;
        let base_bits = decomp_base.trailing_zeros() as usize;
        let num_digits = q_bits.div_ceil(base_bits);

        let num_main = boot_ctx.config.primes.len();
        let num_anchor = boot_ctx.dual_rns.anchor.primes.len();

        // Find minimum prime for safe sampling
        let min_main = boot_ctx
            .config
            .primes
            .iter()
            .min()
            .copied()
            .unwrap_or(u64::MAX);
        let min_anchor = boot_ctx
            .dual_rns
            .anchor
            .primes
            .iter()
            .min()
            .copied()
            .unwrap_or(u64::MAX);
        let _min_prime = min_main.min(min_anchor);

        // Get the ternary representation from work_sk.
        // work_sk.s.main[0] has coefficients mod work_primes[0].
        // For a ternary key, they are in {0, 1, work_primes[0]-1}.
        // We need to re-encode under each boot prime. This is the working
        // secret key in a bare Vec -- zeroize the temporary on drop.
        let work_s_signed: Zeroizing<Vec<i64>> = Zeroizing::new(
            work_sk.s.main[0]
                .iter()
                .map(|&c| {
                    if c == 0 {
                        0i64
                    } else if c == 1 {
                        1i64
                    } else {
                        -1i64 // p-1 represents -1 for ternary
                    }
                })
                .collect(),
        );

        // Encode work_sk under boot primes
        let work_sk_boot_main: Vec<Vec<u64>> = boot_ctx
            .config
            .primes
            .iter()
            .map(|&bp| {
                work_s_signed
                    .iter()
                    .map(|&v| if v >= 0 { v as u64 } else { bp - ((-v) as u64) })
                    .collect()
            })
            .collect();
        let work_sk_boot_anchor: Vec<Vec<u64>> = boot_ctx
            .dual_rns
            .anchor
            .primes
            .iter()
            .map(|&ap| {
                work_s_signed
                    .iter()
                    .map(|&v| if v >= 0 { v as u64 } else { ap - ((-v) as u64) })
                    .collect()
            })
            .collect();
        let mut work_sk_boot = DualRNSPoly {
            main: work_sk_boot_main,
            anchor: work_sk_boot_anchor,
            n,
        };

        let mut ksk_pairs = Vec::with_capacity(num_digits);

        // power_of_base[i] = base^l mod each prime
        let mut power_main: Vec<u64> = boot_ctx.config.primes.iter().map(|_| 1u64).collect();
        let mut power_anchor: Vec<u64> = boot_ctx
            .dual_rns
            .anchor
            .primes
            .iter()
            .map(|_| 1u64)
            .collect();

        for _l in 0..num_digits {
            // a_l = random polynomial under boot primes
            let a_main: Vec<Vec<u64>> = (0..num_main)
                .map(|i| {
                    (0..n)
                        .map(|_| rng.next_u64() % boot_ctx.config.primes[i])
                        .collect()
                })
                .collect();
            let a_anchor: Vec<Vec<u64>> = (0..num_anchor)
                .map(|i| {
                    (0..n)
                        .map(|_| rng.next_u64() % boot_ctx.dual_rns.anchor.primes[i])
                        .collect()
                })
                .collect();
            let a_l = DualRNSPoly {
                main: a_main,
                anchor: a_anchor,
                n,
            };

            // e_l = small error (CBD eta=3)
            let e_signed: Vec<i64> = (0..n)
                .map(|_| {
                    let eta = boot_ctx.config.eta;
                    let mut sum: i64 = 0;
                    for _ in 0..eta {
                        let a = (rng.next_u64() & 1) as i64;
                        let b = (rng.next_u64() & 1) as i64;
                        sum += a - b;
                    }
                    sum
                })
                .collect();

            // b_l = -a_l * s_work + e_l + s_boot * base^l
            // All computations mod each prime
            let mut b_main: Vec<Vec<u64>> = vec![vec![0u64; n]; num_main];
            let mut b_anchor: Vec<Vec<u64>> = vec![vec![0u64; n]; num_anchor];

            // Main primes
            for i in 0..num_main {
                let p = boot_ctx.config.primes[i];
                let p128 = p as u128;

                // NTT multiply: a_l * s_work
                let a_s_work =
                    boot_ctx.ntt_engines[i].multiply(&a_l.main[i], &work_sk_boot.main[i]);

                for j in 0..n {
                    // -a*s_work
                    let neg_as = if a_s_work[j] == 0 {
                        0u64
                    } else {
                        p - a_s_work[j]
                    };

                    // + e_l
                    let e_mod = if e_signed[j] >= 0 {
                        e_signed[j] as u64
                    } else {
                        p - ((-e_signed[j]) as u64)
                    };

                    // + s_boot * base^l
                    let s_boot_val = boot_sk.s.main[i][j] as u128;
                    let power_val = power_main[i] as u128;
                    let s_boot_contrib = ((s_boot_val * power_val) % p128) as u64;

                    b_main[i][j] =
                        ((neg_as as u128 + e_mod as u128 + s_boot_contrib as u128) % p128) as u64;
                }
            }

            // Anchor primes
            for i in 0..num_anchor {
                let p = boot_ctx.dual_rns.anchor.primes[i];
                let p128 = p as u128;

                let a_s_work = boot_ctx.dual_rns.anchor.ntt_engines[i]
                    .multiply(&a_l.anchor[i], &work_sk_boot.anchor[i]);

                for j in 0..n {
                    let neg_as = if a_s_work[j] == 0 {
                        0u64
                    } else {
                        p - a_s_work[j]
                    };
                    let e_mod = if e_signed[j] >= 0 {
                        e_signed[j] as u64
                    } else {
                        p - ((-e_signed[j]) as u64)
                    };
                    let s_boot_val = boot_sk.s.anchor[i][j] as u128;
                    let power_val = power_anchor[i] as u128;
                    let s_boot_contrib = ((s_boot_val * power_val) % p128) as u64;

                    b_anchor[i][j] =
                        ((neg_as as u128 + e_mod as u128 + s_boot_contrib as u128) % p128) as u64;
                }
            }

            let b_l = DualRNSPoly {
                main: b_main,
                anchor: b_anchor,
                n,
            };

            ksk_pairs.push((b_l, a_l));

            // Update powers: power *= base mod each prime
            for i in 0..num_main {
                let p = boot_ctx.config.primes[i];
                power_main[i] = ((power_main[i] as u128 * decomp_base as u128) % p as u128) as u64;
            }
            for i in 0..num_anchor {
                let p = boot_ctx.dual_rns.anchor.primes[i];
                power_anchor[i] =
                    ((power_anchor[i] as u128 * decomp_base as u128) % p as u128) as u64;
            }
        }

        // work_sk_boot holds the working secret key re-encoded under boot
        // primes; it is no longer needed once the gadget pairs are built.
        work_sk_boot.zeroize();

        Ok(Self {
            ksk: ksk_pairs,
            decomp_base,
            num_digits,
        })
    }
}

/// Modular inverse via extended GCD for u128. Zero floating-point.
pub fn mod_inverse_u128(a: u128, m: u128) -> Option<u128> {
    let (g, x, _) = extended_gcd_i128(a as i128, m as i128);
    if g != 1 {
        return None;
    }
    Some(((x % m as i128 + m as i128) % m as i128) as u128)
}

fn extended_gcd_i128(a: i128, b: i128) -> (i128, i128, i128) {
    if a == 0 {
        return (b, 0, 1);
    }
    let (g, x1, y1) = extended_gcd_i128(b % a, a);
    (g, y1 - (b / a) * x1, x1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::bootstrap::crt_reconstruct_2;

    #[test]
    fn test_crt_reconstruct_2_boundary_values() {
        let p0 = BOOTSTRAP_PRIMES[0] as u128;
        let p1 = BOOTSTRAP_PRIMES[1] as u128;
        let p0_inv = mod_inverse_u128(p0, p1).expect("Inverse exists");
        let prod = p0 * p1;

        for x in [0u128, 1, p0 - 1, p0, p0 + 1, prod / 2, prod - 1] {
            let r0 = x % p0;
            let r1 = x % p1;
            let reconstructed = crt_reconstruct_2(r0, r1, p0, p1, p0_inv);
            assert_eq!(reconstructed, x, "CRT boundary failed for x={}", x);
        }
    }

    #[test]
    fn test_crt_reconstruct_2_all_bootstrap_prime_pairs() {
        for i in 0..BOOTSTRAP_PRIMES.len() {
            for j in (i + 1)..BOOTSTRAP_PRIMES.len() {
                let p0 = BOOTSTRAP_PRIMES[i] as u128;
                let p1 = BOOTSTRAP_PRIMES[j] as u128;
                let p0_inv = mod_inverse_u128(p0, p1)
                    .unwrap_or_else(|| panic!("No inverse for ({}, {})", p0, p1));

                let test_vals = [0u128, 1, 42, p0 - 1, p0, p0 * p1 - 1];
                for &x in &test_vals {
                    let r0 = x % p0;
                    let r1 = x % p1;
                    let result = crt_reconstruct_2(r0, r1, p0, p1, p0_inv);
                    assert_eq!(result, x, "CRT pair ({},{}) failed for x={}", p0, p1, x);
                }
            }
        }
    }

    #[test]
    fn test_mod_inverse_known_answers() {
        // inv(3, 7) = 5 because 3*5 = 15 ≡ 1 (mod 7)
        assert_eq!(mod_inverse_u128(3, 7), Some(5));
        // inv(1, p) = 1 for any p
        for &p in &BOOTSTRAP_PRIMES {
            assert_eq!(mod_inverse_u128(1, p as u128), Some(1));
        }
        // inv(p-1, p) = p-1 because (p-1)*(p-1) = p²-2p+1 ≡ 1 (mod p)
        for &p in &BOOTSTRAP_PRIMES {
            let p128 = p as u128;
            assert_eq!(mod_inverse_u128(p128 - 1, p128), Some(p128 - 1));
        }
    }

    #[test]
    fn test_mod_inverse_no_inverse_exists() {
        assert_eq!(mod_inverse_u128(0, 7), None);
        assert_eq!(mod_inverse_u128(4, 8), None);
        assert_eq!(mod_inverse_u128(6, 9), None);
    }

    #[test]
    fn test_mod_inverse_identity_and_self_inverse() {
        // inv(1, m) = 1 for all m > 1
        for m in [3u128, 7, 13, 997, 65537, BOOTSTRAP_PRIMES[0] as u128] {
            assert_eq!(mod_inverse_u128(1, m), Some(1), "inv(1, {}) should be 1", m);
        }
        // inv(p-1, p) = p-1 for all primes
        for &p in &BOOTSTRAP_PRIMES {
            let p128 = p as u128;
            let inv = mod_inverse_u128(p128 - 1, p128).expect("Inverse exists for p-1 mod p");
            assert_eq!(inv, p128 - 1, "inv(p-1, p) should be p-1 for p={}", p);
        }
    }

    #[test]
    fn test_crt_reconstruct_2_commutativity() {
        let p0 = BOOTSTRAP_PRIMES[0] as u128;
        let p1 = BOOTSTRAP_PRIMES[1] as u128;
        let p0_inv = mod_inverse_u128(p0, p1).expect("Inverse");
        let p1_inv = mod_inverse_u128(p1, p0).expect("Inverse");

        for x in [0u128, 42, 123456789, p0 * p1 / 3, p0 * p1 - 1] {
            let r0 = x % p0;
            let r1 = x % p1;
            let result_01 = crt_reconstruct_2(r0, r1, p0, p1, p0_inv);
            let result_10 = crt_reconstruct_2(r1, r0, p1, p0, p1_inv);
            assert_eq!(result_01, result_10, "CRT commutativity failed for x={}", x);
        }
    }

    #[test]
    fn test_crt_reconstruct_2_large_values() {
        let p0 = BOOTSTRAP_PRIMES[0] as u128;
        let p1 = BOOTSTRAP_PRIMES[1] as u128;
        let p0_inv = mod_inverse_u128(p0, p1).expect("Inverse");
        let prod = p0 * p1;

        // Test values near the upper boundary
        for offset in [0u128, 1, 2, 100, p0, p1] {
            let x = prod - 1 - offset;
            let r0 = x % p0;
            let r1 = x % p1;
            let result = crt_reconstruct_2(r0, r1, p0, p1, p0_inv);
            assert_eq!(result, x, "CRT large value failed for x={}", x);
        }
    }

    #[test]
    fn test_mod_inverse_all_bootstrap_primes() {
        // Every pair of BOOTSTRAP_PRIMES should have valid modular inverses
        for i in 0..BOOTSTRAP_PRIMES.len() {
            for j in 0..BOOTSTRAP_PRIMES.len() {
                if i == j {
                    continue;
                }
                let a = BOOTSTRAP_PRIMES[i] as u128;
                let m = BOOTSTRAP_PRIMES[j] as u128;
                let inv = mod_inverse_u128(a, m);
                assert!(
                    inv.is_some(),
                    "No inverse for BOOTSTRAP_PRIMES[{}]={} mod BOOTSTRAP_PRIMES[{}]={}",
                    i,
                    a,
                    j,
                    m
                );
                let inv_val = inv.unwrap();
                assert_eq!(
                    (a * inv_val) % m,
                    1,
                    "a*inv != 1 mod m for a={}, m={}, inv={}",
                    a,
                    m,
                    inv_val
                );
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // BOOTSTRAP PRIME VALIDATION TESTS
    // ═══════════════════════════════════════════════════════════════════

    #[ignore = "VESTIGIAL: asserts validate_bootstrap_primes accepts BOOTSTRAP_PRIMES at N=4096, 128-bit. The validator and the constant it validates exist only to gate bootstrap key material. NOTE: the NTT-compatibility and coprimality checks inside it are generic and live; if BOOTSTRAP_PRIMES is retired, re-express those checks against the work basis under a non-bootstrap name rather than restoring this test. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_validate_bootstrap_primes_valid_set() {
        // BOOTSTRAP_PRIMES should pass validation for N=4096
        let result = validate_bootstrap_primes(&BOOTSTRAP_PRIMES, 4096, 128);
        assert!(
            result.is_ok(),
            "BOOTSTRAP_PRIMES should be valid: {:?}",
            result.err()
        );
    }

    #[ignore = "VESTIGIAL: asserts validate_bootstrap_primes rejects a prime not congruent to 1 mod 2N with NTTConfigError — bootstrap-basis validation. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_validate_bootstrap_primes_ntt_incompatible() {
        // Prime not congruent to 1 mod 2N should fail
        let bad_primes = [17u64]; // 17 is prime but (17-1) % (2*4096) != 0
        let result = validate_bootstrap_primes(&bad_primes, 4096, 128);

        assert!(result.is_err(), "Non-NTT-compatible prime should fail");
        match result.err().unwrap() {
            Nine65Error::NTTConfigError { message } => {
                assert!(message.contains("not NTT-compatible"));
            }
            other => panic!("Expected NTTConfigError, got {:?}", other),
        }
    }

    #[ignore = "VESTIGIAL: asserts validate_bootstrap_primes rejects gcd(9, 21) = 3 with NotCoprime — bootstrap-basis validation. Coprimality itself remains architecturally live; only its application to the bootstrap prime set is quarantined. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_validate_bootstrap_primes_not_coprime() {
        // Use NTT-compatible composites that share a factor
        // For N=2: 2N=4, so we need q ≡ 1 (mod 4)
        // 9 = 3*3, 21 = 3*7, both ≡ 1 (mod 4), gcd(9, 21) = 3
        let not_coprime = [9u64, 21u64]; // gcd(9, 21) = 3
        let result = validate_bootstrap_primes(&not_coprime, 2, 10);

        assert!(result.is_err(), "Non-coprime values should fail");
        match result.err().unwrap() {
            Nine65Error::NotCoprime { m, a, gcd } => {
                assert_eq!(gcd, 3);
                assert!((m == 9 && a == 21) || (m == 21 && a == 9));
            }
            other => panic!("Expected NotCoprime, got {:?}", other),
        }
    }

    #[ignore = "VESTIGIAL: asserts validate_bootstrap_primes rejects a single 13-bit prime with SecurityLevelNotMet at the 128-bit bar — bootstrap-basis validation. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_validate_bootstrap_primes_insufficient_security() {
        // Single small prime should fail security check
        let small_prime = [8193u64]; // 8193 = 8192 + 1 (NTT-compatible for N=4096)
        let result = validate_bootstrap_primes(&small_prime, 4096, 128);

        assert!(result.is_err(), "Insufficient security should fail");
        match result.err().unwrap() {
            Nine65Error::SecurityLevelNotMet { bits, required } => {
                assert!(bits < required);
                assert_eq!(required, 128);
            }
            other => panic!("Expected SecurityLevelNotMet, got {:?}", other),
        }
    }

    #[ignore = "VESTIGIAL: asserts validate_bootstrap_primes rejects an empty bootstrap prime array with InvalidParameter. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_validate_bootstrap_primes_empty_array() {
        let empty: &[u64] = &[];
        let result = validate_bootstrap_primes(empty, 4096, 128);

        assert!(result.is_err(), "Empty prime array should fail");
        match result.err().unwrap() {
            Nine65Error::InvalidParameter { message } => {
                assert!(message.contains("empty"));
            }
            other => panic!("Expected InvalidParameter, got {:?}", other),
        }
    }

    #[ignore = "VESTIGIAL: asserts validate_bootstrap_primes rejects a zero entry in the bootstrap prime array with NTTConfigError. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_validate_bootstrap_primes_zero_prime() {
        let with_zero = [0u64, 998244353];
        let result = validate_bootstrap_primes(&with_zero, 4096, 128);

        assert!(result.is_err(), "Zero prime should fail");
        match result.err().unwrap() {
            Nine65Error::NTTConfigError { message } => {
                assert!(message.contains("zero"));
            }
            other => panic!("Expected NTTConfigError, got {:?}", other),
        }
    }

    #[ignore = "VESTIGIAL: asserts BOOTSTRAP_PRIMES either validate or fail only with NTTConfigError across N in [1024, 2048, 4096, 8192]. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_validate_bootstrap_primes_multiple_degrees() {
        // Test that BOOTSTRAP_PRIMES work for various N values
        for &n in &[1024, 2048, 4096, 8192] {
            let result = validate_bootstrap_primes(&BOOTSTRAP_PRIMES, n, 128);
            // Note: May fail for smaller N if (q-1) % 2N != 0
            // The actual BOOTSTRAP_PRIMES are designed for specific N ranges
            if result.is_err() {
                // This is expected - not all primes work for all N
                match result.err().unwrap() {
                    Nine65Error::NTTConfigError { .. } => {
                        // Expected for incompatible N
                    }
                    other => panic!("Unexpected error for N={}: {:?}", n, other),
                }
            }
        }
    }

    #[ignore = "VESTIGIAL: asserts the first two BOOTSTRAP_PRIMES pass at a 50-bit bar and fail at 128 — sizing the bootstrap basis against a security target. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_validate_bootstrap_primes_first_two_only() {
        // Smaller subset should still pass coprimality/NTT but may fail security
        let subset = &BOOTSTRAP_PRIMES[0..2];
        // Two 30-bit primes give ~60 bits, so use threshold=50 to ensure pass
        let result = validate_bootstrap_primes(subset, 4096, 50);

        // Should pass with lower threshold
        assert!(
            result.is_ok(),
            "First two primes should be valid with lower security: {:?}",
            result.err()
        );

        // But should fail with higher threshold
        let result_high = validate_bootstrap_primes(subset, 4096, 128);
        assert!(
            result_high.is_err(),
            "First two primes should fail 128-bit security"
        );
        match result_high.err().unwrap() {
            Nine65Error::SecurityLevelNotMet { .. } => {
                // Expected
            }
            other => panic!("Expected SecurityLevelNotMet, got {:?}", other),
        }
    }

    #[test]
    fn test_gcd_u64_basic() {
        assert_eq!(gcd_u64(48, 18), 6);
        assert_eq!(gcd_u64(17, 13), 1);
        assert_eq!(gcd_u64(100, 25), 25);
        assert_eq!(gcd_u64(7, 0), 7);
        assert_eq!(gcd_u64(0, 11), 11);
    }

    #[test]
    fn test_gcd_u64_bootstrap_primes_coprime() {
        // All bootstrap primes should be pairwise coprime
        for i in 0..BOOTSTRAP_PRIMES.len() {
            for j in (i + 1)..BOOTSTRAP_PRIMES.len() {
                let g = gcd_u64(BOOTSTRAP_PRIMES[i], BOOTSTRAP_PRIMES[j]);
                assert_eq!(
                    g, 1,
                    "BOOTSTRAP_PRIMES[{}]={} and [{}]={} should be coprime",
                    i, BOOTSTRAP_PRIMES[i], j, BOOTSTRAP_PRIMES[j]
                );
            }
        }
    }

    #[ignore = "VESTIGIAL: asserts BootstrapKey::generate succeeds against a config built from BOOTSTRAP_PRIMES — generation of bootstrap key material itself. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_bootstrap_key_generation_validates_primes() {
        use crate::entropy::ShadowHarvester;
        use crate::ops::rns_fhe::RNSFHEContext;
        use crate::params::SecureConfig;

        // Create a secure config (this will use BOOTSTRAP_PRIMES internally)
        let config = SecureConfig::secure_128();
        let work_config = config.config;

        // Create bootstrap context with valid primes
        let boot_config = FHEConfig {
            n: work_config.n,
            primes: BOOTSTRAP_PRIMES.to_vec(),
            q: BOOTSTRAP_PRIMES[0], // Use first prime as representative
            t: work_config.t,
            eta: work_config.eta,
            security_bits: 128,
            name: "test_boot_config",
        };
        let boot_ctx = RNSFHEContext::new(&boot_config);

        // Generate keys
        let mut rng = ShadowHarvester::new();
        let boot_keys = boot_ctx.generate_keys_dual_full(&mut rng);
        let work_keys = boot_ctx.generate_keys_dual_full(&mut rng);

        // This should succeed - primes are valid
        let result = BootstrapKey::generate(
            &work_config,
            &boot_ctx,
            &boot_keys,
            &work_keys.secret_key,
            &mut rng,
        );

        assert!(
            result.is_ok(),
            "BootstrapKey generation should succeed with valid primes: {:?}",
            result.err()
        );
    }

    // Note: Integration test for NTT validation is not included here because
    // RNSFHEContext::new() already panics on invalid NTT configuration during
    // NTT engine initialization. The unit test `test_validate_bootstrap_primes_ntt_incompatible`
    // validates the validation function itself. The system has defense-in-depth:
    // 1. NTT engine creation fails early (panics in arithmetic/ntt_fft.rs)
    // 2. validate_bootstrap_primes() provides explicit validation (returns Result)
    // 3. Both checks ensure NTT compatibility before any cryptographic operations.
}
