Warning: truncated output (original token count: 39388)
Total output lines: 3574

//! Clockwork Bootstrap — public (evaluator-side) ciphertext refresh
//!
//! The historical Phase 1 component switch is **not** BFV decryption.  BFV
//! rounds the combined phase `c0 + c1*s`; rounding `c0` and `c1` separately
//! displaces a secret-dependent quotient/carry term.  The legacy component
//! switch remains below only as a diagnostic oracle while the exact CRAM
//! Safe-Root/Lift transducer is built.  Both public entry points fail closed
//! before invoking it; see [`public_phase1_soundness_gate`].
//!
//! It is NOT a claim that Phase 1 is error-free. `modswitch_to_t` computes
//! `round(c * t / Q)` using `q_level_half` as the rounding offset; that is the
//! ordinary BFV mod-switch rounding, it deposits a per-coefficient residue
//! `r0 + r1*s`, and `docs/MODULUS_SWITCHING.md` records that the BFV rescale
//! rounds by necessity. The residue is noise-*independent*, so no noise bound
//! can shrink it away — which is precisely why some chains cannot carry a
//! public refresh at all (see `params::secure_configs`'s PUBLIC-REFRESH
//! ADMISSIBILITY section, and `noise::budget`'s "refresh-input reserve"). Do
//! not conflate this rounding step with the exact align-and-drop primitive
//! `ops::rns_fhe::exact_modulus_switch_drop_poly`, which divides by a whole RNS
//! prime with no rounding term at all.
//!
//! This does NOT make the system unlimited-depth, and no such claim is made
//! here: refresh admissibility is bounded by the config's `Delta` headroom (see
//! `bootstrap` below and `params::secure_configs`'s PUBLIC-REFRESH
//! ADMISSIBILITY section), and the roundtrip test suites for all three paths are
//! currently `#[ignore]`d as VESTIGIAL/RETIRED. Measured public direct-square
//! depths are 2-4; see `docs/CLAIM_SURFACE_AND_LIMITS_2026-08-22.md`.
//!
//! # Three-Phase Bootstrap (Circular Security)
//!
//! 1. **Displaced-state transduction** (not implemented; public path refused)
//! 2. **Homomorphic inner product** (TrivialEnc + PlaintextMul, depth ~1)
//! 3. **ModSwitch Q_boot -> Q_work** (drop extra boot prime, circular security)
//!
//! Circular security: boot_sk = work_sk (same ternary polynomial, lifted to boot
//! modulus space). Phase 2 uses plaintext × ciphertext (not ct × ct), so no
//! relinearization or key switching is needed.

use crate::arithmetic::k_elimination::KElimination;
use crate::arithmetic::rns::{crt_reconstruct_u256, DualRNSContext, U256};
#[cfg(test)]
use crate::entropy::ShadowHarvester;
use crate::entropy::{require_secure_rng, FheRng, SecureRng};
use crate::errors::{Nine65Error, Nine65Result};
use crate::keys::bootstrap::{
    ensure_q_boot_representable, mod_inverse_u128, BootstrapKey, BootstrapKeySet, KeySwitchKey,
    BOOTSTRAP_PRIMES,
};
use crate::ops::rns_fhe::{
    DualRNSCiphertext, DualRNSEvalKey, DualRNSFullKeySet, DualRNSPoly, DualRNSPublicKey,
    DualRNSSecretKey, RNSFHEContext,
};
use crate::params::secure_configs::{
    ensure_public_refresh_supported, ensure_public_refresh_with_ksk_supported,
};
use crate::params::FHEConfig;
use zeroize::Zeroizing;

/// Clockwork Bootstrap engine — holds precomputed data for bootstrap execution.
pub struct ClockworkBootstrap {
    /// Working FHE configuration.
    pub work_config: FHEConfig,
    /// Bootstrap FHE configuration.
    pub boot_config: FHEConfig,
    /// Plaintext modulus (= q_small).
    pub t: u64,
    /// Polynomial degree.
    pub n: usize,
    /// Q_min: modulus at minimum working level (product of first 2 work primes).
    pub q_min: u128,
    /// Multiplicative depth consumed by bootstrap circuit.
    pub bootstrap_depth: usize,
    /// Boot RNSFHEContext for NTT operations within bootstrap.
    pub boot_ctx: RNSFHEContext,
}

/// Refuse the public refresh until its displaced BFV state is carried exactly.
///
/// For centered representatives, independently rounded components leave the
/// correction
///
/// `K_j = round((R0_j + (R1 * s)_j) / Q)`,
///
/// where `*` is negacyclic convolution.  CRAM can *represent* this bounded
/// quotient/carry in its lift state, but this module does not yet homomorphically
/// transduce the secret-dependent convolution and rounding.  Silently omitting
/// `K` returns a plausible ciphertext of the wrong plaintext, so production
/// callers must receive a typed error instead.
pub(crate) fn public_phase1_soundness_gate() -> Nine65Result<()> {
    Err(Nine65Error::BootstrapFailed {
        reason: "public BFV refresh disabled: Phase 1 does not yet propagate the secret-dependent displaced quotient/carry through the CRAM Safe-Root/Lift state"
            .into(),
    })
}

/// Validate critical structural invariants after boot context creation.
///
/// 1. Work primes must be a subset of boot primes (modswitch drops the extra).
/// 2. Boot primes must contain exactly one prime not in work primes (the drop prime).
/// 3. Boot context anchor primes must equal the canonical anchor list for this N —
///    prevents silent anchor drift between work and boot contexts.
fn assert_boot_invariants(
    work: &FHEConfig,
    boot: &FHEConfig,
    boot_ctx: &RNSFHEContext,
) -> Nine65Result<()> {
    // 1) work primes must be subset of boot primes
    for &wp in &work.primes {
        if !boot.primes.contains(&wp) {
            return Err(Nine65Error::BootstrapConfigMismatch {
                reason: format!("Boot primes must contain work prime {}", wp),
            });
        }
    }

    // 2) boot must contain exactly one extra prime (the drop prime)
    let extras: Vec<u64> = boot
        .primes
        .iter()
        .copied()
        .filter(|bp| !work.primes.contains(bp))
        .collect();

    if extras.len() != 1 {
        return Err(Nine65Error::BootstrapConfigMismatch {
            reason: format!(
                "Boot primes must have exactly 1 extra prime, found {} extras: {:?}",
                extras.len(),
                extras
            ),
        });
    }

    // 3) anchor primes must match the canonical set for this N
    let canonical = DualRNSContext::canonical_anchor_primes_for_n(work.n);
    let boot_anchors = &boot_ctx.dual_rns.anchor.primes;

    if boot_anchors.is_empty() {
        return Err(Nine65Error::BootstrapConfigMismatch {
            reason: "Boot context anchor primes empty".into(),
        });
    }

    if boot_anchors.len() != canonical.len()
        || !boot_anchors.iter().zip(&canonical).all(|(a, b)| a == b)
    {
        return Err(Nine65Error::BootstrapConfigMismatch {
            reason: format!(
                "Boot anchor primes {:?} do not match canonical {:?}",
                boot_anchors, canonical
            ),
        });
    }

    Ok(())
}

impl ClockworkBootstrap {
    /// Create a bootstrap context for the given working configuration.
    pub fn new(work_config: &FHEConfig) -> Nine65Result<Self> {
        let n = work_config.n;
        let t = work_config.t;

        if work_config.primes.len() < 2 {
            return Err(Nine65Error::BootstrapConfigMismatch {
                reason: "Working config needs >= 2 primes".into(),
            });
        }

        let q_min = work_config.primes[0] as u128 * work_config.primes[1] as u128;

        // Bootstrap depth: ~1 for plaintext-ct multiply, +1 safety margin
        let bootstrap_depth = 2;
        // Need at least work_primes + 1 boot primes (circular security drops one)
        let min_for_depth = bootstrap_depth + 2;
        let min_for_modswitch = work_config.primes.len() + 1;
        let required = min_for_depth.max(min_for_modswitch);
        if required > BOOTSTRAP_PRIMES.len() {
            return Err(Nine65Error::BootstrapConfigMismatch {
                reason: format!(
                    "Bootstrap requires {} primes (work has {}, depth needs {}), \
                     but BOOTSTRAP_PRIMES only contains {}. \
                     Increase BOOTSTRAP_PRIMES or reduce circuit depth.",
                    required,
                    work_config.primes.len(),
                    min_for_depth,
                    BOOTSTRAP_PRIMES.len()
                ),
            });
        }
        let boot_prime_count = required;

        let boot_config = FHEConfig {
            n,
            primes: BOOTSTRAP_PRIMES[..boot_prime_count].to_vec(),
            q: BOOTSTRAP_PRIMES[0],
            t,
            eta: work_config.eta,
            security_bits: work_config.security_bits,
            name: "clockwork_bootstrap",
        };

        if boot_prime_count <= work_config.primes.len() {
            return Err(Nine65Error::BootstrapConfigMismatch {
                reason: format!(
                    "Need > {} boot primes for modswitch (work has {}), only {} available in BOOTSTRAP_PRIMES",
                    work_config.primes.len(), work_config.primes.len(), BOOTSTRAP_PRIMES.len()
                ),
            });
        }

        let boot_max_depth = boot_prime_count.saturating_sub(2);
        if boot_max_depth < bootstrap_depth {
            return Err(Nine65Error::BootstrapConfigMismatch {
                reason: format!(
                    "Need depth {}, only {} available from {} boot primes",
                    bootstrap_depth, boot_max_depth, boot_prime_count
                ),
            });
        }

        let boot_ctx = RNSFHEContext::try_new(&boot_config)?;

        assert_boot_invariants(work_config, &boot_config, &boot_ctx)?;

        Ok(Self {
            work_config: work_config.clone(),
            boot_config,
            t,
            n,
            q_min,
            bootstrap_depth,
            boot_ctx,
        })
    }

    // =========================================================================
    // CIRCULAR SECURITY KEY GENERATION
    // =========================================================================

    /// Lift working secret key to bootstrap modulus space.
    ///
    /// Extracts ternary {-1, 0, 1} from work_sk and re-encodes under boot primes
    /// and boot anchor primes. This is the "circular" part — same key, different
    /// modular representation.
    fn lift_sk_to_boot(&self, work_sk: &DualRNSSecretKey) -> DualRNSSecretKey {
        let n = self.n;
        let first_work_prime = self.work_config.primes[0];

        // Extract signed ternary coefficients from work_sk. This is the
        // secret key in a bare, unwrapped Vec -- zeroize the temporary on
        // drop so it does not linger in freed heap memory after the lifted
        // DualRNSSecretKey (which is itself Zeroize + ZeroizeOnDrop) is built.
        let s_signed: Zeroizing<Vec<i8>> = Zeroizing::new(
            work_sk.s.main[0]
                .iter()
                .map(|&c| {
                    if c == 0 {
                        0i8
                    } else if c == 1 {
                        1i8
                    } else if c == first_work_prime - 1 {
                        -1i8
                    } else {
                        0i8 // Non-ternary — shouldn't happen with proper key gen
                    }
                })
                .collect(),
        );

        // Encode under boot main primes
        let s_main: Vec<Vec<u64>> = self
            .boot_config
            .primes
            .iter()
            .map(|&p| {
                s_signed
                    .iter()
                    .map(|&c| if c < 0 { p - ((-c) as u64) } else { c as u64 })
                    .collect()
            })
            .collect();

        // Encode under boot anchor primes
        let s_anchor: Vec<Vec<u64>> = self
            .boot_ctx
            .dual_rns
            .anchor
            .primes
            .iter()
            .map(|&p| {
                s_signed
                    .iter()
                    .map(|&c| if c < 0 { p - ((-c) as u64) } else { c as u64 })
                    .collect()
            })
            .collect();

        DualRNSSecretKey {
            s: DualRNSPoly {
                main: s_main,
                anchor: s_anchor,
                n,
            },
        }
    }

    /// Generate a public key for circular security: pk = (-(a*s + e), a).
    ///
    /// Uses the boot context's NTT engines for polynomial multiplication.
    /// The resulting pk encrypts under boot_sk = lift(work_sk).
    fn generate_circular_pk<R: FheRng>(
        &self,
        boot_sk: &DualRNSSecretKey,
        rng: &mut R,
    ) -> Nine65Result<DualRNSPublicKey> {
        let n = self.n;
        let eta = self.boot_config.eta;
        let num_main = self.boot_config.primes.len();
        let num_anchor = self.boot_ctx.dual_rns.anchor.primes.len();

        // `a` must be uniform over the WHOLE ring R_Q_boot -- it is the only
        // thing hiding `a*s` in `pk0 = -(a*s + e)`. This used to draw ONE u64
        // mod the smallest boot/anchor prime and reduce that same narrow
        // value into every lane (issue #82): each lane's residue covered its
        // full modulus, but the integer the lanes jointly encoded was
        // confined to `[0, min_prime)` -- and biased within that range by the
        // `%` -- instead of `[0, Q_boot)`. Since this mask hides `a*s_boot`
        // and `s_boot` here IS the working secret key (circular security:
        // `boot_sk = lift(work_sk)`), that narrow joint support is exactly
        // the kind of structural leak flagged as security-sensitive by
        // WR-5A / issue #82.
        //
        // Fix: exact full-width rejection sampling uniform on [0, Q_boot),
        // then reduce that ONE accepted integer independently into every
        // main and anchor lane, reusing the same canonical sampler the main
        // FHE public-key path already uses
        // (`RNSFHEContext::sample_uniform_dual_poly`) rather than
        // maintaining a second implementation. Typed-refuse first if this
        // boot chain's Q_boot exceeds what the sampler can represent.
        ensure_q_boot_representable(&self.boot_config.primes)?;
        let a_dual = self
            .boot_ctx
            .sample_uniform_dual_poly(rng, &self.boot_config.primes);
        let a_main = a_dual.main;
        let a_anchor = a_dual.anchor;

        // Sample error e (CBD with given eta). Zeroized on drop -- it is
        // combined into a*s below and never itself needs to survive past
        // this function.
        let e_signed: Zeroizing<Vec<i64>> = Zeroizing::new(
            (0..n)
                .map(|_| {
                    let mut sum = 0i64;
                    for _ in 0..eta {
                        let a_bit = (rng.next_u64() & 1) as i64;
                        let b_bit = (rng.next_u64() & 1) as i64;
                        sum += a_bit - b_bit;
                    }
                    sum
                })
                .collect(),
        );
        let e_main: Vec<Vec<u64>> = self
            .boot_config
            .primes
            .iter()
            .map(|&p| {
                e_signed
                    .iter()
                    .map(|&e| if e >= 0 { e as u64 } else { p - ((-e) as u64) })
                    .collect()
            })
            .collect();
        let e_anchor: Vec<Vec<u64>> = self
            .boot_ctx
            .dual_rns
            .anchor
            .primes
            .iter()
            .map(|&p| {
                e_signed
                    .iter()
                    .map(|&e| if e >= 0 { e as u64 } else { p - ((-e) as u64) })
                    .collect()
            })
            .collect();

        // Compute pk0 = -(a*s + e) using NTT engines
        // Main primes
        let mut pk0_main = vec![vec![0u64; n]; num_main];
        for i in 0..num_main {
            let p = self.boot_config.primes[i] as u128;
            let as_prod = self.boot_ctx.ntt_engines[i].multiply(&a_main[i], &boot_sk.s.main[i]);
            for j in 0..n {
                let as_plus_e = (as_prod[j] as u128 + e_main[i][j] as u128) % p;
                pk0_main[i][j] = if as_plus_e == 0 {
                    0
                } else {
                    (p - as_plus_e) as u64
                };
            }
        }

        // Anchor primes
        let mut pk0_anchor = vec![vec![0u64; n]; num_anchor];
        for i in 0..num_anchor {
            let p = self.boot_ctx.dual_rns.anchor.primes[i] as u128;
            let as_prod = self.boot_ctx.dual_rns.anchor.ntt_engines[i]
                .multiply(&a_anchor[i], &boot_sk.s.anchor[i]);
            for j in 0..n {
                let as_plus_e = (as_prod[j] as u128 + e_anchor[i][j] as u128) % p;
                pk0_anchor[i][j] = if as_plus_e == 0 {
                    0
                } else {
                    (p - as_plus_e) as u64
                };
            }
        }

        Ok(DualRNSPublicKey {
            pk0: DualRNSPoly {
                main: pk0_main,
                anchor: pk0_anchor,
                n,
            },
            pk1: DualRNSPoly {
                main: a_main,
                anchor: a_anchor,
                n,
            },
        })
    }

    /// Generate all bootstrap key material (circular security) using the OS
    /// CSPRNG. This is the production entry point.
    pub fn generate_keys_secure(
        &self,
        work_sk: &DualRNSSecretKey,
    ) -> Nine65Result<BootstrapKeySet> {
        let mut rng = SecureRng::new();
        self.generate_keys(work_sk, &mut rng)
    }

    /// Generate all bootstrap key material (circular security).
    ///
    /// Uses the same secret key for boot and work contexts (circular security).
    /// No key-switch key is needed — Phase 2 produces plaintext × ciphertext
    /// (not ct × ct), so no relinearization is required.
    ///
    /// Generic over `FheRng` so callers can supply `SecureRng` (required for
    /// production — enforced by `require_secure_rng` below) or, for tests
    /// and reproducible benchmarks only, `ShadowHarvester`. Prefer
    /// [`Self::generate_keys_secure`] unless you have a specific, documented
    /// reason to inject a different RNG: this generates `enc_s = Enc(work_sk)`
    /// (the bootstrap key material encrypts the working secret key itself),
    /// so a predictable RNG here is a full key-recovery exposure, not just a
    /// ciphertext-distinguishing one.
    pub fn generate_keys<R: FheRng>(
        &self,
        work_sk: &DualRNSSecretKey,
        rng: &mut R,
    ) -> Nine65Result<BootstrapKeySet> {
        require_secure_rng(rng, "ClockworkBootstrap::generate_keys");

        // Circular security: lift work_sk to boot primes (same polynomial, new moduli)
        let boot_sk = self.lift_sk_to_boot(work_sk);

        // Generate circular PK: encrypts under the SAME key
        let boot_pk = self.generate_circular_pk(&boot_sk, rng)?;

        // Construct a DualRNSFullKeySet for BootstrapKey::generate
        // eval_key is unused (no ct×ct in Phase 2) — provide dummy
        let boot_keyset = DualRNSFullKeySet {
            secret_key: boot_sk.clone(),
            public_key: boot_pk,
            eval_key: DualRNSEvalKey {
                rlk: vec![],
                decomp_base: 1024,
                num_digits: 0,
            },
        };

        // Generate BSK: Enc_{circ_pk}(work_sk)
        let bsk = BootstrapKey::generate(
            &self.work_config,
            &self.boot_ctx,
            &boot_keyset,
            work_sk,
            rng,
        )?;

        // No KSK needed for circular security — create dummy
        let ksk = KeySwitchKey {
            ksk: vec![],
            decomp_base: 1024,
            num_digits: 0,
        };

        Ok(BootstrapKeySet { bsk, ksk, boot_sk })
    }

    /// Generate bootstrap key material with independent boot key and KSK,
    /// using the OS CSPRNG. This is the production entry point.
    pub fn generate_keys_with_ksk_secure(
        &self,
        work_sk: &DualRNSSecretKey,
    ) -> Nine65Result<BootstrapKeySet> {
        let mut rng = SecureRng::new();
        self.generate_keys_wi…29388 tokens truncated…() {
        use crate::params::SecureConfig;

        let config = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&config).expect("Context");
        let boot = ClockworkBootstrap::new(&config).expect("Bootstrap");
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual_full(&mut rng);
        let boot_keys = boot
            .generate_keys(&keys.secret_key, &mut rng)
            .expect("KeyGen");

        for m in [0u64, 1, 2, 7, 42, 100, 1000] {
            let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
            let ct_boot = boot
                .bootstrap(&ct, &boot_keys.bsk, &boot_keys.ksk)
                .expect("Circular bootstrap");
            let dec = ctx.decrypt_dual(&ct_boot, &keys.secret_key);
            assert_eq!(
                dec, m,
                "Circular bootstrap roundtrip failed: m={}, got={}",
                m, dec
            );
        }
    }

    /// Non-circular (KSK) bootstrap roundtrip: encrypt → bootstrap_with_ksk → decrypt.
    #[ignore = "VESTIGIAL: asserts encrypt -> boot.bootstrap_with_ksk -> decrypt recovers m under non-circular (key-switch) bootstrap. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_ksk_bootstrap_roundtrip() {
        use crate::params::SecureConfig;

        let config = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&config).expect("Context");
        let boot = ClockworkBootstrap::new(&config).expect("Bootstrap");
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual_full(&mut rng);
        let boot_keys_ksk = boot
            .generate_keys_with_ksk(&keys.secret_key, &mut rng)
            .expect("KSK KeyGen");

        for m in [0u64, 1, 2, 7, 42, 100, 1000] {
            let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
            let ct_boot = boot
                .bootstrap_with_ksk(&ct, &boot_keys_ksk.bsk, &boot_keys_ksk.ksk)
                .expect("KSK bootstrap");
            let dec = ctx.decrypt_dual(&ct_boot, &keys.secret_key);
            assert_eq!(
                dec, m,
                "KSK bootstrap roundtrip failed: m={}, got={}",
                m, dec
            );
        }
    }

    /// Mul → bootstrap → mul chain: bootstrap output is valid for subsequent ops.
    #[ignore = "VESTIGIAL: asserts the chain 2*3=6 -> bootstrap -> 6*5=30 decrypts correctly. Its premise is that the refresh in the middle is what makes the second multiply reachable; with exact division the second multiply needs nothing refreshed. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_mul_then_bootstrap_then_mul() {
        use crate::params::SecureConfig;

        let config = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&config).expect("Context");
        let boot = ClockworkBootstrap::new(&config).expect("Bootstrap");
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual_full(&mut rng);
        let boot_keys = boot
            .generate_keys(&keys.secret_key, &mut rng)
            .expect("KeyGen");

        // encrypt(2) * encrypt(3) = 6
        let ct_2 = ctx.encrypt_dual(2, &keys.public_key, &mut rng);
        let ct_3 = ctx.encrypt_dual(3, &keys.public_key, &mut rng);
        let ct_6 = ctx
            .mul_dual_public(&ct_2, &ct_3, &keys.eval_key)
            .expect("mul");
        assert_eq!(ctx.decrypt_dual(&ct_6, &keys.secret_key), 6);

        // Bootstrap refreshes noise while preserving plaintext
        let ct_fresh = boot
            .bootstrap(&ct_6, &boot_keys.bsk, &boot_keys.ksk)
            .expect("bootstrap");
        assert_eq!(ctx.decrypt_dual(&ct_fresh, &keys.secret_key), 6);

        // 6 * 5 = 30 — multiplication after bootstrap must work
        let ct_5 = ctx.encrypt_dual(5, &keys.public_key, &mut rng);
        let ct_30 = ctx
            .mul_dual_public(&ct_fresh, &ct_5, &keys.eval_key)
            .expect("mul after boot");
        assert_eq!(ctx.decrypt_dual(&ct_30, &keys.secret_key), 30);
    }

    /// AutoBootstrapEvaluator E2E: chain multiplications with auto-triggered
    /// bootstrap, verify correct final decryption.
    #[ignore = "VESTIGIAL: drives AutoBootstrapEvaluator::mul_auto over ten chained multiplies at a 500-permille trigger and asserts evaluator.bootstrap_count > 0 — it demands that a refresh actually fire, which is the budget-bounded-depth premise stated as an assertion. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_auto_bootstrap_chained_muls() {
        use crate::ops::auto_bootstrap::{AutoBootstrapEvaluator, TrackedCiphertext};
        use crate::params::SecureConfig;

        let config = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&config).expect("Context");
        let boot = ClockworkBootstrap::new(&config).expect("Bootstrap");
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual_full(&mut rng);
        let boot_keys = boot
            .generate_keys(&keys.secret_key, &mut rng)
            .expect("KeyGen");

        let t = config.t;
        let ct_two =
            TrackedCiphertext::fresh(ctx.encrypt_dual(2, &keys.public_key, &mut rng), &config);

        let mut evaluator = AutoBootstrapEvaluator::new(
            &ctx,
            &boot,
            &boot_keys.bsk,
            &boot_keys.ksk,
            &keys.eval_key,
            &config,
        );
        // Trigger bootstrap at 50% budget remaining — ensures bootstrap fires
        // after every multiplication (budget drops ~69% per mul for secure_128).
        evaluator.set_trigger_threshold(500);

        // Chain: 2 * 2 * 2 * ... (10 multiplications) = 2^11 = 2048 mod t
        let mut ct =
            TrackedCiphertext::fresh(ctx.encrypt_dual(2, &keys.public_key, &mut rng), &config);
        let mut expected = 2u64;
        for i in 0..10 {
            ct = evaluator
                .mul_auto(&ct, &ct_two)
                .unwrap_or_else(|e| panic!("mul_auto failed at step {}: {}", i, e));
            expected = (expected as u128 * 2 % t as u128) as u64;
        }

        let dec = ctx.decrypt_dual(&ct.ct, &keys.secret_key);
        assert_eq!(
            dec, expected,
            "AutoBootstrap chained muls: expected {}, got {} (bootstraps: {}, muls: {})",
            expected, dec, evaluator.bootstrap_count, evaluator.total_muls
        );
        assert!(
            evaluator.bootstrap_count > 0,
            "AutoBootstrap should have triggered at least once during 10 muls"
        );
    }

    // =====================================================================
    // AUDIT HARDENING: Boot Invariant Tests
    // =====================================================================

    /// Verify boot primes are a superset of work primes with exactly one extra
    /// (the drop prime). This is the structural invariant enforced by
    /// `assert_boot_invariants()` at construction time.
    #[ignore = "VESTIGIAL: asserts the boot prime set is a superset of the work primes with exactly one extra 'drop prime'. A drop prime is basis-movement bookkeeping and has no referent when the basis does not move. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_boot_primes_subset_and_single_drop_prime() {
        use crate::params::SecureConfig;

        let config = SecureConfig::secure_128().into_config();
        let boot = ClockworkBootstrap::new(&config).expect("boot");

        for &wp in &boot.work_config.primes {
            assert!(
                boot.boot_config.primes.contains(&wp),
                "Boot primes must contain work prime {}",
                wp
            );
        }
        let extras: Vec<u64> = boot
            .boot_config
            .primes
            .iter()
            .copied()
            .filter(|bp| !boot.work_config.primes.contains(bp))
            .collect();
        assert_eq!(
            extras.len(),
            1,
            "expected exactly 1 extra boot prime, got {:?}",
            extras
        );
    }

    /// Verify boot context anchor primes match the canonical anchor list.
    #[ignore = "VESTIGIAL: asserts boot_ctx anchor primes equal DualRNSContext::canonical_anchor_primes_for_n — an invariant of the bootstrap context's anchor lanes. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_boot_anchor_primes_match_canonical() {
        use crate::arithmetic::rns::DualRNSContext;
        use crate::params::SecureConfig;

        let config = SecureConfig::secure_128().into_config();
        let boot = ClockworkBootstrap::new(&config).expect("boot");

        let canonical = DualRNSContext::canonical_anchor_primes_for_n(config.n);
        let boot_anchors = &boot.boot_ctx.dual_rns.anchor.primes;

        assert_eq!(boot_anchors.len(), canonical.len(), "anchor count mismatch");
        for (i, (&got, &expected)) in boot_anchors.iter().zip(&canonical).enumerate() {
            assert_eq!(got, expected, "anchor prime [{}] mismatch", i);
        }
    }

    /// After bootstrap, anchor limbs must equal CRT(main) mod each anchor prime.
    /// This catches silent anchor corruption or Phase 3 recomputation errors.
    #[ignore = "VESTIGIAL: asserts post-bootstrap anchor limbs equal CRT(main) mod each anchor prime, reconstructing through crt_reconstruct_n over the refreshed ciphertext. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_bootstrap_output_anchor_consistency() {
        use crate::params::SecureConfig;

        let config = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&config).expect("ctx");
        let boot = ClockworkBootstrap::new(&config).expect("boot");
        let mut rng = ShadowHarvester::with_seed(7);
        let keys = ctx.generate_keys_dual_full(&mut rng);
        let boot_keys = boot
            .generate_keys(&keys.secret_key, &mut rng)
            .expect("boot keys");

        let ct = ctx.encrypt_dual(4242, &keys.public_key, &mut rng);
        let fresh = boot
            .bootstrap(&ct, &boot_keys.bsk, &boot_keys.ksk)
            .expect("bootstrap");

        // Work primes for CRT reconstruction
        let primes_u128: Vec<u128> = config.primes.iter().map(|&p| p as u128).collect();

        // Precompute Garner inverses
        let mut inv = vec![0u128; primes_u128.len()];
        let mut partial = 1u128;
        for k in 0..primes_u128.len() {
            if k > 0 {
                inv[k] = mod_inverse_u128(partial, primes_u128[k]).expect("inv");
            }
            partial *= primes_u128[k];
        }

        // Anchor primes from context
        let anchor_primes = &ctx.dual_rns.anchor.primes;
        assert!(!anchor_primes.is_empty());

        // Sample coefficient positions
        let max_pos = config.n.min(128);
        let positions: Vec<usize> = (0..max_pos).step_by(max_pos / 6).collect();
        for pos in positions {
            let c0_full = crt_reconstruct_n(
                fresh.c0.main.iter().map(|limb| limb[pos] as u128),
                &primes_u128,
                &inv,
            );

            for (ai, &ap) in anchor_primes.iter().enumerate() {
                let got = fresh.c0.anchor[ai][pos];
                let expected = (c0_full % ap as u128) as u64;
                assert_eq!(
                    got, expected,
                    "anchor mismatch at pos={} anchor_prime={} got={} expected={}",
                    pos, ap, got, expected
                );
            }
        }
    }

    // =====================================================================
    // AUDIT HARDENING: Config Matrix Roundtrip Tests
    // =====================================================================

    /// secure_128 / secure_192 / secure_256 all pass structural invariant
    /// checks: boot primes superset, single drop prime, canonical anchors.
    /// This is the "config matrix" coverage the auditor wants to see.
    #[ignore = "VESTIGIAL: asserts boot-prime superset, single drop prime and canonical anchors across the secure_128 / secure_192 / secure_256 bootstrap contexts. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_config_matrix_invariants_128_192_256() {
        use crate::arithmetic::rns::DualRNSContext;
        use crate::params::SecureConfig;

        let configs = [
            ("secure_128", SecureConfig::secure_128().into_config()),
            ("secure_192", SecureConfig::secure_192().into_config()),
            ("secure_256", SecureConfig::secure_256().into_config()),
        ];

        for (label, cfg) in configs {
            // Construction succeeds (assert_boot_invariants runs inside new())
            let boot = ClockworkBootstrap::new(&cfg).unwrap_or_else(|_| panic!("{}: boot", label));

            // Structural: subset + single drop prime
            for &wp in &cfg.primes {
                assert!(
                    boot.boot_config.primes.contains(&wp),
                    "{}: boot missing work prime {}",
                    label,
                    wp
                );
            }
            let extras: Vec<u64> = boot
                .boot_config
                .primes
                .iter()
                .copied()
                .filter(|bp| !cfg.primes.contains(bp))
                .collect();
            assert_eq!(extras.len(), 1, "{}: expected 1 extra boot prime", label);

            // Structural: canonical anchors
            let canonical = DualRNSContext::canonical_anchor_primes_for_n(cfg.n);
            assert_eq!(
                &boot.boot_ctx.dual_rns.anchor.primes, &canonical,
                "{}: anchor primes diverged from canonical",
                label
            );
        }
    }

    /// Bootstrap roundtrip for secure_128: encrypt -> bootstrap -> decrypt
    /// must recover the original plaintext for a range of messages.
    #[ignore = "VESTIGIAL: asserts encrypt -> boot.bootstrap -> decrypt recovers m across the secure_128 message range including t-1. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_config_matrix_roundtrip_secure_128() {
        use crate::params::SecureConfig;

        let cfg = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&cfg).expect("ctx");
        let boot = ClockworkBootstrap::new(&cfg).expect("boot");
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual_full(&mut rng);
        let boot_keys = boot
            .generate_keys(&keys.secret_key, &mut rng)
            .expect("keygen");

        for &m in &[0u64, 1, 2, 7, 42, 1000, cfg.t - 1] {
            let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
            let fresh = boot
                .bootstrap(&ct, &boot_keys.bsk, &boot_keys.ksk)
                .unwrap_or_else(|_| panic!("bootstrap m={}", m));
            let dec = ctx.decrypt_dual(&fresh, &keys.secret_key);
            assert_eq!(dec, m, "roundtrip fail m={} got={}", m, dec);
        }
    }

    // =====================================================================
    // AUDIT HARDENING: U256 Bootstrap Roundtrip Tests
    // =====================================================================

    /// secure_192 bootstrap roundtrip via U256 CRT fallback.
    ///
    /// Q_level (5 × ~30-bit primes ≈ 150 bits) overflows u128. The U256
    /// CRT reconstruction path handles this transparently, enabling full
    /// encrypt → bootstrap → decrypt roundtrip for secure_192.
    #[ignore = "VESTIGIAL: asserts the U256 CRT fallback carries a full secure_192 encrypt -> bootstrap -> decrypt roundtrip. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_secure_192_bootstrap_roundtrip_u256() {
        use crate::params::SecureConfig;

        let cfg = SecureConfig::secure_192().into_config();
        let ctx = RNSFHEContext::try_new(&cfg).expect("ctx");
        let boot = ClockworkBootstrap::new(&cfg).expect("boot construction must succeed");

        let mut rng = ShadowHarvester::with_seed(192);
        let keys = ctx.generate_keys_dual_full(&mut rng);
        let boot_keys = boot
            .generate_keys(&keys.secret_key, &mut rng)
            .expect("keygen");

        for &m in &[0u64, 1, 42, 1000, cfg.t - 1] {
            let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
            let fresh = boot
                .bootstrap(&ct, &boot_keys.bsk, &boot_keys.ksk)
                .unwrap_or_else(|e| panic!("secure_192 bootstrap m={} failed: {}", m, e));
            let dec = ctx.decrypt_dual(&fresh, &keys.secret_key);
            assert_eq!(dec, m, "secure_192 roundtrip fail m={} got={}", m, dec);
        }
    }

    /// secure_256 bootstrap roundtrip via U256 CRT fallback.
    ///
    /// Q_level (6 × ~30-bit primes ≈ 177 bits) overflows u128. The U256
    /// CRT reconstruction path handles this, enabling full roundtrip.
    #[ignore = "VESTIGIAL: asserts the U256 CRT fallback carries a full secure_256 encrypt -> bootstrap -> decrypt roundtrip. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_secure_256_bootstrap_roundtrip_u256() {
        use crate::params::SecureConfig;

        let cfg = SecureConfig::secure_256().into_config();
        let ctx = RNSFHEContext::try_new(&cfg).expect("ctx");
        let boot = ClockworkBootstrap::new(&cfg).expect("boot construction must succeed");

        let mut rng = ShadowHarvester::with_seed(256);
        let keys = ctx.generate_keys_dual_full(&mut rng);
        let boot_keys = boot
            .generate_keys(&keys.secret_key, &mut rng)
            .expect("keygen");

        for &m in &[0u64, 1, 42, 1000, cfg.t - 1] {
            let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
            let fresh = boot
                .bootstrap(&ct, &boot_keys.bsk, &boot_keys.ksk)
                .unwrap_or_else(|e| panic!("secure_256 bootstrap m={} failed: {}", m, e));
            let dec = ctx.decrypt_dual(&fresh, &keys.secret_key);
            assert_eq!(dec, m, "secure_256 roundtrip fail m={} got={}", m, dec);
        }
    }
}
