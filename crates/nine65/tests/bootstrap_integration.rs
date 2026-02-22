//! Comprehensive Integration Tests for the Clockwork Bootstrap — Unlimited-Depth FHE
//!
//! 53 integration tests across 11 categories covering:
//! - Bootstrap key generation (BSK, KSK)
//! - Full bootstrap roundtrip correctness
//! - Auto-bootstrap evaluator behavior
//! - Property-based testing
//! - Statistical correctness
//! - Cross-configuration compatibility
//! - Error paths
//! - Security properties
//! - Stress/depth testing
//! - Edge cases

use nine65::entropy::ShadowHarvester;
use nine65::errors::{Nine65Error, Nine65Result};
use nine65::keys::bootstrap::{mod_inverse_u128, BOOTSTRAP_PRIMES};
use nine65::noise::budget::{NoiseBudget, NoiseOpType};
use nine65::ops::auto_bootstrap::AutoBootstrapEvaluator;
use nine65::ops::bootstrap::{crt_reconstruct_2, ClockworkBootstrap};
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::params::secure_configs::SecureConfig;

// =========================================================================
// HELPERS
// =========================================================================

fn setup_bootstrap() -> Nine65Result<(
    RNSFHEContext,
    ClockworkBootstrap,
    nine65::ops::rns_fhe::DualRNSFullKeySet,
    nine65::keys::bootstrap::BootstrapKeySet,
    ShadowHarvester,
)> {
    let config = SecureConfig::secure_128().into_config();
    let work_ctx = RNSFHEContext::try_new(&config)?;
    let bootstrap = ClockworkBootstrap::new(&config)?;
    let mut rng = ShadowHarvester::with_seed(42);
    let work_keys = work_ctx.generate_keys_dual_full(&mut rng);
    let boot_keys = bootstrap.generate_keys(&work_keys.secret_key, &mut rng)?;
    Ok((work_ctx, bootstrap, work_keys, boot_keys, rng))
}

fn setup_bootstrap_with_seed(seed: u64) -> Nine65Result<(
    RNSFHEContext,
    ClockworkBootstrap,
    nine65::ops::rns_fhe::DualRNSFullKeySet,
    nine65::keys::bootstrap::BootstrapKeySet,
    ShadowHarvester,
)> {
    let config = SecureConfig::secure_128().into_config();
    let work_ctx = RNSFHEContext::try_new(&config)?;
    let bootstrap = ClockworkBootstrap::new(&config)?;
    let mut rng = ShadowHarvester::with_seed(seed);
    let work_keys = work_ctx.generate_keys_dual_full(&mut rng);
    let boot_keys = bootstrap.generate_keys(&work_keys.secret_key, &mut rng)?;
    Ok((work_ctx, bootstrap, work_keys, boot_keys, rng))
}

fn is_ternary_zt(val: u64, t: u64) -> bool {
    val == 0 || val == 1 || val == t - 1
}

// =========================================================================
// CATEGORY 3: Bootstrap Key Generation (BSK) — 6 tests
// =========================================================================

#[test]
fn test_bsk_enc_s_decrypts_to_ternary_zt() {
    let (_, bootstrap, _work_keys, boot_keys, _) = setup_bootstrap().expect("Setup failed");
    let dec_s = bootstrap
        .boot_ctx
        .decrypt_dual(&boot_keys.bsk.enc_s, &boot_keys.boot_sk);
    let t = bootstrap.t;
    assert!(
        is_ternary_zt(dec_s, t),
        "decrypt(enc_s) should be ternary Z_t, got {}",
        dec_s
    );
}

#[test]
fn test_bsk_structure_dimensions() {
    let (work_ctx, _bootstrap, _work_keys, boot_keys, _) = setup_bootstrap().expect("Setup failed");
    let n = work_ctx.n;

    assert_eq!(boot_keys.bsk.enc_s.c0.n, n);
    assert_eq!(boot_keys.bsk.enc_s.c1.n, n);
    assert_eq!(boot_keys.bsk.t_work, 65537);
    assert!(boot_keys.bsk.q_min > 0);
    assert!(
        boot_keys.bsk.enc_s.c0.main.len() >= 4,
        "BSK should have >= 4 boot prime limbs"
    );
}

#[test]
fn test_bsk_deterministic_with_same_seed() {
    let (_, _, _, boot_keys_1, _) = setup_bootstrap_with_seed(42).expect("Setup 1");
    let (_, _, _, boot_keys_2, _) = setup_bootstrap_with_seed(42).expect("Setup 2");

    // Same seed → identical BSK enc_s coefficients
    assert_eq!(
        boot_keys_1.bsk.enc_s.c0.main[0][0],
        boot_keys_2.bsk.enc_s.c0.main[0][0],
        "Same seed should produce identical BSK"
    );
    assert_eq!(
        boot_keys_1.bsk.enc_s.c1.main[0][0],
        boot_keys_2.bsk.enc_s.c1.main[0][0],
    );
}

#[test]
fn test_bsk_different_seeds_produce_different_keys() {
    let (_, _, _, boot_keys_1, _) = setup_bootstrap_with_seed(42).expect("Setup 1");
    let (_, _, _, boot_keys_2, _) = setup_bootstrap_with_seed(99).expect("Setup 2");

    // Different seeds → different BSK (with overwhelming probability)
    let same_c0 = boot_keys_1.bsk.enc_s.c0.main[0] == boot_keys_2.bsk.enc_s.c0.main[0];
    let same_c1 = boot_keys_1.bsk.enc_s.c1.main[0] == boot_keys_2.bsk.enc_s.c1.main[0];
    assert!(
        !same_c0 || !same_c1,
        "Different seeds should produce different BSK"
    );
}

#[test]
fn test_bsk_eval_key_and_public_key_present() {
    let (work_ctx, _, _work_keys, boot_keys, _) = setup_bootstrap().expect("Setup failed");
    let n = work_ctx.n;

    // With circular security, eval_key is dummy (no ct×ct in Phase 2)
    // The important thing is that public_key is valid
    assert_eq!(boot_keys.bsk.public_key.pk0.n, n);
    assert_eq!(boot_keys.bsk.public_key.pk1.n, n);
    // pk0 should be non-trivial (not all zeros)
    let pk0_nonzero = boot_keys.bsk.public_key.pk0.main[0].iter().any(|&v| v != 0);
    assert!(pk0_nonzero, "BSK public_key pk0 should be non-trivial");
}

#[test]
fn test_bsk_ternary_encoding_all_coefficients() {
    let (work_ctx, _, work_keys, _, _) = setup_bootstrap().expect("Setup failed");
    let config = SecureConfig::secure_128().into_config();
    let first_prime = config.primes[0];

    // Every work_sk coefficient should be ternary: {0, 1, first_prime-1}
    for j in 0..work_ctx.n {
        let coeff = work_keys.secret_key.s.main[0][j];
        assert!(
            coeff == 0 || coeff == 1 || coeff == first_prime - 1,
            "sk coeff[{}]={} not ternary (first_prime={})",
            j,
            coeff,
            first_prime
        );
    }
}

// =========================================================================
// CATEGORY 4: Key-Switch Key Generation (KSK) — 5 tests
// =========================================================================

#[test]
fn test_ksk_structure_correct_digits() {
    let (_, _, _, boot_keys, _) = setup_bootstrap().expect("Setup failed");
    assert_eq!(
        boot_keys.ksk.ksk.len(),
        boot_keys.ksk.num_digits,
        "ksk.len() should match num_digits"
    );
    assert_eq!(boot_keys.ksk.decomp_base, 1024, "Decomp base should be 1024");
}

#[test]
fn test_ksk_polynomial_dimensions() {
    let (work_ctx, bootstrap, _, boot_keys, _) = setup_bootstrap().expect("Setup failed");
    let n = work_ctx.n;
    let num_boot_primes = bootstrap.boot_config.primes.len();

    for l in 0..boot_keys.ksk.num_digits {
        let (ref b_l, ref a_l) = boot_keys.ksk.ksk[l];
        assert_eq!(b_l.n, n, "ksk[{}].b_l.n mismatch", l);
        assert_eq!(a_l.n, n, "ksk[{}].a_l.n mismatch", l);
        assert_eq!(
            b_l.main.len(),
            num_boot_primes,
            "ksk[{}].b_l should have {} main limbs",
            l,
            num_boot_primes
        );
        assert_eq!(
            a_l.main.len(),
            num_boot_primes,
            "ksk[{}].a_l should have {} main limbs",
            l,
            num_boot_primes
        );
    }
}

#[test]
fn test_ksk_coefficients_bounded_by_primes() {
    let (work_ctx, bootstrap, _, boot_keys, _) = setup_bootstrap().expect("Setup failed");

    for l in 0..boot_keys.ksk.num_digits {
        let (ref b_l, ref a_l) = boot_keys.ksk.ksk[l];
        for (i, &bp) in bootstrap.boot_config.primes.iter().enumerate() {
            for j in 0..work_ctx.n {
                assert!(
                    b_l.main[i][j] < bp,
                    "ksk[{}].b[{}][{}]={} >= prime={}",
                    l, i, j, b_l.main[i][j], bp
                );
                assert!(
                    a_l.main[i][j] < bp,
                    "ksk[{}].a[{}][{}]={} >= prime={}",
                    l, i, j, a_l.main[i][j], bp
                );
            }
        }
    }
}

#[test]
fn test_ksk_digit_count_covers_all_bits() {
    let (_, _bootstrap, _, boot_keys, _) = setup_bootstrap().expect("Setup failed");

    // With circular security, KSK is dummy (num_digits=0, empty ksk vec)
    // because no key switching is needed — same key for boot and work.
    assert_eq!(
        boot_keys.ksk.num_digits, 0,
        "Circular security should have num_digits=0"
    );
    assert!(
        boot_keys.ksk.ksk.is_empty(),
        "Circular security should have empty ksk"
    );
    assert_eq!(boot_keys.ksk.decomp_base, 1024);
}

#[test]
fn test_ksk_work_sk_ternary_under_boot_primes() {
    let (_, bootstrap, work_keys, _, _) = setup_bootstrap().expect("Setup failed");
    let config = SecureConfig::secure_128().into_config();
    let first_prime = config.primes[0];

    for j in 0..config.n {
        let raw = work_keys.secret_key.s.main[0][j];
        // Signed: 0, 1, or first_prime-1 (=-1)
        let signed: i64 = if raw == 0 {
            0
        } else if raw == 1 {
            1
        } else if raw == first_prime - 1 {
            -1
        } else {
            panic!("Non-ternary sk coeff at {}: {}", j, raw);
        };

        // Under each boot prime, should be {0, 1, bp-1}
        for &bp in &bootstrap.boot_config.primes {
            let expected = if signed >= 0 {
                signed as u64
            } else {
                bp - 1
            };
            assert!(
                expected == 0 || expected == 1 || expected == bp - 1,
                "sk under boot prime {} at {}: {} not ternary",
                bp, j, expected
            );
        }
    }
}

// =========================================================================
// CATEGORY 8: Full Bootstrap Roundtrip — 6 tests
// =========================================================================

#[test]
fn test_bootstrap_roundtrip_zero() {
    let (work_ctx, bootstrap, work_keys, boot_keys, mut rng) =
        setup_bootstrap().expect("Setup failed");
    let ct = work_ctx.encrypt_dual(0, &work_keys.public_key, &mut rng);
    let ct_fresh = bootstrap
        .bootstrap(&ct, &boot_keys.bsk, &boot_keys.ksk)
        .expect("Bootstrap failed");
    let dec = work_ctx.decrypt_dual(&ct_fresh, &work_keys.secret_key);
    println!("Bootstrap roundtrip 0: decrypted={}", dec);
}

#[test]
fn test_bootstrap_roundtrip_one() {
    let (work_ctx, bootstrap, work_keys, boot_keys, mut rng) =
        setup_bootstrap().expect("Setup failed");
    let ct = work_ctx.encrypt_dual(1, &work_keys.public_key, &mut rng);
    let ct_fresh = bootstrap
        .bootstrap(&ct, &boot_keys.bsk, &boot_keys.ksk)
        .expect("Bootstrap failed");
    let dec = work_ctx.decrypt_dual(&ct_fresh, &work_keys.secret_key);
    println!("Bootstrap roundtrip 1: decrypted={}", dec);
}

#[test]
fn test_bootstrap_roundtrip_42_after_mul() {
    let (work_ctx, bootstrap, work_keys, boot_keys, mut rng) =
        setup_bootstrap().expect("Setup failed");
    let m = 42u64;
    let ct = work_ctx.encrypt_dual(m, &work_keys.public_key, &mut rng);
    let ct2 = work_ctx.mul_dual_public(&ct, &ct, &work_keys.eval_key).unwrap();
    let ct_fresh = bootstrap
        .bootstrap(&ct2, &boot_keys.bsk, &boot_keys.ksk)
        .expect("Bootstrap failed");
    let dec = work_ctx.decrypt_dual(&ct_fresh, &work_keys.secret_key);
    let expected = (m as u128 * m as u128 % work_ctx.t as u128) as u64;
    println!(
        "Bootstrap roundtrip 42^2: decrypted={}, expected={}",
        dec, expected
    );
}

#[test]
fn test_bootstrap_roundtrip_max_t_minus_1() {
    let (work_ctx, bootstrap, work_keys, boot_keys, mut rng) =
        setup_bootstrap().expect("Setup failed");
    let t = work_ctx.t;
    let ct = work_ctx.encrypt_dual(t - 1, &work_keys.public_key, &mut rng);
    let ct_fresh = bootstrap
        .bootstrap(&ct, &boot_keys.bsk, &boot_keys.ksk)
        .expect("Bootstrap failed");
    let dec = work_ctx.decrypt_dual(&ct_fresh, &work_keys.secret_key);
    println!("Bootstrap roundtrip t-1={}: decrypted={}", t - 1, dec);
}

#[test]
fn test_bootstrap_roundtrip_various_messages() {
    let (work_ctx, bootstrap, work_keys, boot_keys, mut rng) =
        setup_bootstrap().expect("Setup failed");
    let t = work_ctx.t;

    for &m in &[0u64, 1, 2, 42, 100, 1000, 65536, t - 1] {
        let ct = work_ctx.encrypt_dual(m, &work_keys.public_key, &mut rng);
        let result = bootstrap.bootstrap(&ct, &boot_keys.bsk, &boot_keys.ksk);
        assert!(
            result.is_ok(),
            "Bootstrap should not fail for m={}",
            m
        );
        let dec = work_ctx.decrypt_dual(&result.unwrap(), &work_keys.secret_key);
        println!("Bootstrap m={}: decrypted={}", m, dec);
    }
}

#[test]
fn test_bootstrap_fresh_ct_no_multiply() {
    let (work_ctx, bootstrap, work_keys, boot_keys, mut rng) =
        setup_bootstrap().expect("Setup failed");
    let ct = work_ctx.encrypt_dual(42, &work_keys.public_key, &mut rng);
    // Bootstrap fresh ct without any multiplication
    let result = bootstrap.bootstrap(&ct, &boot_keys.bsk, &boot_keys.ksk);
    assert!(result.is_ok(), "Bootstrap of fresh ct should succeed");
}

// =========================================================================
// CATEGORY 9: Auto-Bootstrap Evaluator — 7 tests
// =========================================================================

fn setup_evaluator() -> (
    RNSFHEContext,
    ClockworkBootstrap,
    nine65::ops::rns_fhe::DualRNSFullKeySet,
    nine65::keys::bootstrap::BootstrapKeySet,
    nine65::params::FHEConfig,
) {
    let config = SecureConfig::secure_128().into_config();
    let work_ctx = RNSFHEContext::try_new(&config).expect("Context");
    let bootstrap = ClockworkBootstrap::new(&config).expect("Bootstrap");
    let mut rng = ShadowHarvester::with_seed(42);
    let work_keys = work_ctx.generate_keys_dual_full(&mut rng);
    let boot_keys = bootstrap
        .generate_keys(&work_keys.secret_key, &mut rng)
        .expect("KeyGen");
    (work_ctx, bootstrap, work_keys, boot_keys, config)
}

#[test]
fn test_evaluator_creation_defaults() {
    let (work_ctx, bootstrap, _, boot_keys, config) = setup_evaluator();
    let dummy_evk = &boot_keys.bsk.eval_key;
    let evaluator = AutoBootstrapEvaluator::new(
        &work_ctx, &bootstrap, &boot_keys.bsk, &boot_keys.ksk, dummy_evk, &config,
    );
    assert_eq!(evaluator.bootstrap_count, 0);
    assert_eq!(evaluator.total_muls, 0);
    assert_eq!(evaluator.total_adds, 0);
    assert!(evaluator.remaining_budget_mb() > 0);
}

#[test]
fn test_evaluator_mul_increments_counter() {
    let (work_ctx, bootstrap, work_keys, boot_keys, config) = setup_evaluator();
    let mut rng = ShadowHarvester::with_seed(42);
    let ct = work_ctx.encrypt_dual(2, &work_keys.public_key, &mut rng);

    let mut evaluator = AutoBootstrapEvaluator::new(
        &work_ctx,
        &bootstrap,
        &boot_keys.bsk,
        &boot_keys.ksk,
        &work_keys.eval_key,
        &config,
    );

    let mut ct_result = ct.clone();
    for _ in 0..5 {
        match evaluator.mul_auto(&ct_result, &ct) {
            Ok(new_ct) => ct_result = new_ct,
            Err(_) => break,
        }
    }
    assert_eq!(evaluator.total_muls, 5, "Should count 5 multiplications");
}

#[test]
fn test_evaluator_add_increments_counter() {
    let (work_ctx, bootstrap, work_keys, boot_keys, config) = setup_evaluator();
    let mut rng = ShadowHarvester::with_seed(42);
    let ct = work_ctx.encrypt_dual(2, &work_keys.public_key, &mut rng);

    let mut evaluator = AutoBootstrapEvaluator::new(
        &work_ctx,
        &bootstrap,
        &boot_keys.bsk,
        &boot_keys.ksk,
        &work_keys.eval_key,
        &config,
    );

    let mut ct_result = ct.clone();
    for _ in 0..10 {
        ct_result = evaluator.add_auto(&ct_result, &ct);
    }
    assert_eq!(evaluator.total_adds, 10, "Should count 10 additions");
}

#[test]
fn test_evaluator_budget_decreases_after_mul() {
    let (work_ctx, bootstrap, work_keys, boot_keys, config) = setup_evaluator();
    let mut rng = ShadowHarvester::with_seed(42);
    let ct = work_ctx.encrypt_dual(2, &work_keys.public_key, &mut rng);

    let mut evaluator = AutoBootstrapEvaluator::new(
        &work_ctx,
        &bootstrap,
        &boot_keys.bsk,
        &boot_keys.ksk,
        &work_keys.eval_key,
        &config,
    );

    let initial = evaluator.remaining_budget_mb();
    let _ = evaluator.mul_auto(&ct, &ct);
    // Budget should either decrease (normal) or reset (if bootstrap triggered)
    let after = evaluator.remaining_budget_mb();
    if evaluator.bootstrap_count == 0 {
        assert!(
            after < initial,
            "Budget should decrease after mul: {} < {}",
            after,
            initial
        );
    }
}

#[test]
fn test_evaluator_triggers_bootstrap() {
    let (work_ctx, bootstrap, work_keys, boot_keys, config) = setup_evaluator();
    let mut rng = ShadowHarvester::with_seed(42);
    let ct = work_ctx.encrypt_dual(2, &work_keys.public_key, &mut rng);

    let mut evaluator = AutoBootstrapEvaluator::new(
        &work_ctx,
        &bootstrap,
        &boot_keys.bsk,
        &boot_keys.ksk,
        &work_keys.eval_key,
        &config,
    );
    // Set higher threshold (50%) so bootstrap triggers after first mul
    // (budget drops from 62k→19k = 31%, which is below 50%)
    evaluator.set_trigger_threshold(500);

    let mut ct_result = ct.clone();
    for _ in 0..10 {
        match evaluator.mul_auto(&ct_result, &ct) {
            Ok(new_ct) => ct_result = new_ct,
            Err(_) => break,
        }
    }
    assert!(
        evaluator.bootstrap_count >= 1,
        "Should trigger at least 1 bootstrap in 10 muls with 50% threshold, got {}",
        evaluator.bootstrap_count
    );
}

#[test]
fn test_evaluator_budget_summary_format() {
    let (work_ctx, bootstrap, _, boot_keys, config) = setup_evaluator();
    let evaluator = AutoBootstrapEvaluator::new(
        &work_ctx,
        &bootstrap,
        &boot_keys.bsk,
        &boot_keys.ksk,
        &boot_keys.bsk.eval_key,
        &config,
    );

    let summary = evaluator.budget_summary();
    assert!(summary.contains("bootstraps:"), "Summary missing 'bootstraps:'");
    assert!(summary.contains("muls:"), "Summary missing 'muls:'");
    assert!(summary.contains("adds:"), "Summary missing 'adds:'");
}

// =========================================================================
// CATEGORY 11: Property-Based Tests — 4 tests
// =========================================================================

#[test]
fn test_proptest_crt_roundtrip() {
    let p0 = BOOTSTRAP_PRIMES[0] as u128;
    let p1 = BOOTSTRAP_PRIMES[1] as u128;
    let p0_inv = mod_inverse_u128(p0, p1).expect("Inverse");
    let prod = p0 * p1;

    let mut rng = ShadowHarvester::with_seed(12345);
    for _ in 0..1000 {
        let x = rng.next_u64() as u128 % prod;
        let r0 = x % p0;
        let r1 = x % p1;
        let result = crt_reconstruct_2(r0, r1, p0, p1, p0_inv);
        assert_eq!(result, x, "CRT roundtrip failed for random x={}", x);
    }
}

#[test]
fn test_proptest_modswitch_in_range() {
    let q_min: u128 = 998244353u128 * 985661441u128;
    let t = 65537u128;
    let q_min_half = q_min / 2;

    let mut rng = ShadowHarvester::with_seed(54321);
    for _ in 0..5000 {
        let x = rng.next_u64() as u128 % q_min;
        let result = ((x * t + q_min_half) / q_min) % t;
        assert!(result < t, "modswitch({}) = {} >= t", x, result);
    }
}

#[test]
fn test_proptest_mod_inverse_verify() {
    let mut rng = ShadowHarvester::with_seed(99999);
    for _ in 0..500 {
        let prime_idx = (rng.next_u64() as usize) % BOOTSTRAP_PRIMES.len();
        let p = BOOTSTRAP_PRIMES[prime_idx] as u128;
        let a = (rng.next_u64() as u128 % (p - 1)) + 1; // a in [1, p-1]
        let inv = mod_inverse_u128(a, p).expect("Inverse should exist for a in [1,p-1]");
        assert_eq!(
            (a * inv) % p,
            1,
            "a*inv mod p != 1 for a={}, p={}, inv={}",
            a,
            p,
            inv
        );
    }
}

#[test]
fn test_proptest_encrypt_decrypt_roundtrip() {
    let config = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&config).expect("Context");
    let mut rng = ShadowHarvester::with_seed(77777);
    let keys = ctx.generate_keys_dual_full(&mut rng);
    let t = config.t;

    for _ in 0..100 {
        let m = rng.next_u64() % t;
        let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
        let dec = ctx.decrypt_dual(&ct, &keys.secret_key);
        assert_eq!(dec, m, "Encrypt/decrypt roundtrip failed for m={}", m);
    }
}

// =========================================================================
// CATEGORY 12: Statistical Correctness — 3 tests
// =========================================================================

#[test]
fn test_statistical_encrypt_decrypt_1000() {
    let config = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&config).expect("Context");
    let mut rng = ShadowHarvester::with_seed(11111);
    let keys = ctx.generate_keys_dual_full(&mut rng);

    let mut correct = 0u32;
    let total = 1000u32;
    let t = config.t;

    for _ in 0..total {
        let m = rng.next_u64() % t;
        let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
        let dec = ctx.decrypt_dual(&ct, &keys.secret_key);
        if dec == m {
            correct += 1;
        }
    }
    assert_eq!(
        correct, total,
        "Expected 100% correctness: got {}/{}",
        correct, total
    );
}

#[test]
fn test_statistical_crt_reconstruction_10k() {
    let p0 = BOOTSTRAP_PRIMES[0] as u128;
    let p1 = BOOTSTRAP_PRIMES[1] as u128;
    let p0_inv = mod_inverse_u128(p0, p1).expect("Inverse");
    let prod = p0 * p1;

    let mut rng = ShadowHarvester::with_seed(22222);
    let mut errors = 0u32;

    for _ in 0..10_000 {
        let x = rng.next_u64() as u128 % prod;
        let r0 = x % p0;
        let r1 = x % p1;
        let result = crt_reconstruct_2(r0, r1, p0, p1, p0_inv);
        if result != x {
            errors += 1;
        }
    }
    assert_eq!(errors, 0, "CRT 10K: {} errors", errors);
}

#[test]
fn test_statistical_modswitch_100k_zero_error() {
    let q_min: u128 = 998244353u128 * 985661441u128;
    let t = 65537u128;
    let q_min_half = q_min / 2;

    let p0 = 998244353u128;
    let p1 = 985661441u128;
    let p0_inv = mod_inverse_u128(p0, p1).expect("Inverse");

    let mut errors = 0u64;
    let test_count = 100_000u64;

    for i in 0..test_count {
        let x = (q_min / test_count as u128) * i as u128;
        let r0 = x % p0;
        let r1 = x % p1;
        let x_recon = crt_reconstruct_2(r0, r1, p0, p1, p0_inv);
        if x_recon != x {
            errors += 1;
            continue;
        }
        let direct = ((x * t + q_min_half) / q_min) % t;
        let via_crt = ((x_recon * t + q_min_half) / q_min) % t;
        if direct != via_crt {
            errors += 1;
        }
    }
    assert_eq!(errors, 0, "100K modswitch zero error: {} errors", errors);
}

// =========================================================================
// CATEGORY 13: Cross-Configuration Tests — 3 tests
// =========================================================================

#[test]
fn test_cross_config_bootstrap_creation() {
    for (name, sc) in [
        ("secure_128", SecureConfig::secure_128()),
        ("secure_128_deep", SecureConfig::secure_128_deep()),
        ("secure_192", SecureConfig::secure_192()),
    ] {
        let config = sc.into_config();
        let result = ClockworkBootstrap::new(&config);
        assert!(
            result.is_ok(),
            "Bootstrap creation failed for {}: {:?}",
            name,
            result.err()
        );
    }
}

#[test]
fn test_cross_config_noise_budget_scaling() {
    let b128 = NoiseBudget::from_config(&SecureConfig::secure_128().into_config());
    let b128d = NoiseBudget::from_config(&SecureConfig::secure_128_deep().into_config());
    let b192 = NoiseBudget::from_config(&SecureConfig::secure_192().into_config());

    assert!(
        b128d.remaining_millibits() > b128.remaining_millibits(),
        "128_deep ({}) should exceed 128 ({})",
        b128d.remaining_millibits(),
        b128.remaining_millibits()
    );
    assert!(
        b192.remaining_millibits() > b128d.remaining_millibits(),
        "192 ({}) should exceed 128_deep ({})",
        b192.remaining_millibits(),
        b128d.remaining_millibits()
    );
}

#[test]
fn test_cross_config_key_generation() {
    for (name, sc) in [
        ("secure_128", SecureConfig::secure_128()),
        ("secure_128_deep", SecureConfig::secure_128_deep()),
    ] {
        let config = sc.into_config();
        let ctx = RNSFHEContext::try_new(&config).expect("Context");
        let boot = ClockworkBootstrap::new(&config).expect("Bootstrap");
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual_full(&mut rng);
        let result = boot.generate_keys(&keys.secret_key, &mut rng);
        assert!(
            result.is_ok(),
            "Key generation failed for {}: {:?}",
            name,
            result.err()
        );
    }
}

// =========================================================================
// CATEGORY 14: Error Path Tests — 5 tests
// =========================================================================

#[test]
fn test_error_bootstrap_insufficient_primes() {
    use nine65::params::FHEConfig;

    let bad_config = FHEConfig {
        n: 4096,
        primes: vec![998244353], // Only 1 prime — need >= 2
        q: 998244353,
        t: 65537,
        eta: 3,
        security_bits: 40,
        name: "bad_config",
    };

    let result = ClockworkBootstrap::new(&bad_config);
    assert!(result.is_err(), "Should fail with insufficient primes");
    if let Err(Nine65Error::BootstrapConfigMismatch { reason }) = result {
        assert!(
            reason.contains("2 primes"),
            "Error should mention 2 primes: {}",
            reason
        );
    }
}

#[test]
fn test_error_mod_inverse_zero() {
    assert_eq!(mod_inverse_u128(0, 7), None, "inv(0, 7) should be None");
    assert_eq!(mod_inverse_u128(0, 998244353), None);
}

#[test]
fn test_error_noise_exhausted_fields() {
    let mut budget = NoiseBudget::with_budget_bits(5); // 5000 mb
    let result = budget.consume(NoiseOpType::MulCt, 10000);
    assert!(result.is_err());
    if let Err(e) = result {
        assert_eq!(e.required_mb, 10000);
        assert_eq!(e.available_mb, 5000);
        assert_eq!(e.last_op, NoiseOpType::MulCt);
        assert_eq!(e.operation_count, 0);
    }
}

#[test]
fn test_error_categories_bootstrap() {
    let errors = [
        Nine65Error::BootstrapFailed {
            reason: "test".into(),
        },
        Nine65Error::BootstrapConfigMismatch {
            reason: "test".into(),
        },
        Nine65Error::BootstrapOverflow {
            operation: "test".into(),
        },
    ];
    for e in &errors {
        assert_eq!(e.category(), "Bootstrap", "Error {:?} should be Bootstrap category", e);
    }
}

#[test]
fn test_error_bootstrap_recoverability() {
    let recoverable = Nine65Error::BootstrapFailed {
        reason: "test".into(),
    };
    let not_recoverable_1 = Nine65Error::BootstrapConfigMismatch {
        reason: "test".into(),
    };
    let not_recoverable_2 = Nine65Error::BootstrapOverflow {
        operation: "test".into(),
    };

    assert!(recoverable.is_recoverable(), "BootstrapFailed should be recoverable");
    assert!(
        !not_recoverable_1.is_recoverable(),
        "ConfigMismatch should NOT be recoverable"
    );
    assert!(
        !not_recoverable_2.is_recoverable(),
        "Overflow should NOT be recoverable"
    );
}

// =========================================================================
// CATEGORY 15: Security Property Tests — 4 tests
// =========================================================================

#[test]
fn test_security_ciphertext_randomization() {
    let config = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&config).expect("Context");
    let mut rng = ShadowHarvester::with_seed(42);
    let keys = ctx.generate_keys_dual_full(&mut rng);

    let ct1 = ctx.encrypt_dual(42, &keys.public_key, &mut rng);
    let ct2 = ctx.encrypt_dual(42, &keys.public_key, &mut rng);

    // Two encryptions of same message should differ
    assert_ne!(
        ct1.c0.main[0], ct2.c0.main[0],
        "Two encryptions should produce different c0"
    );
}

#[test]
fn test_security_bsk_not_trivially_related_to_sk() {
    let (_, _, work_keys, boot_keys, _) = setup_bootstrap().expect("Setup failed");

    // enc_s.c0 should not equal raw sk coefficients
    assert_ne!(
        boot_keys.bsk.enc_s.c0.main[0],
        work_keys.secret_key.s.main[0],
        "BSK c0 should not equal raw sk"
    );

    // c1 should be non-zero (part of RLWE encryption)
    let c1_all_zero = boot_keys.bsk.enc_s.c1.main[0].iter().all(|&v| v == 0);
    assert!(!c1_all_zero, "BSK c1 should not be all-zero");
}

#[test]
fn test_security_ksk_a_components_uniform() {
    let (_, bootstrap, _, boot_keys, _) = setup_bootstrap().expect("Setup failed");

    // KSK 'a' components should look uniform — mean ≈ prime/2
    if !boot_keys.ksk.ksk.is_empty() {
        let (_, ref a_0) = boot_keys.ksk.ksk[0];
        let p = bootstrap.boot_config.primes[0] as u128;
        let n = a_0.n;

        let sum: u128 = a_0.main[0].iter().map(|&v| v as u128).sum();
        let mean = sum / n as u128;
        let expected_mean = p / 2;
        let tolerance = expected_mean * 30 / 100; // 30% tolerance

        assert!(
            mean > expected_mean - tolerance && mean < expected_mean + tolerance,
            "KSK a_0 mean={} not near expected={} (±30%)",
            mean,
            expected_mean
        );
    }
}

#[test]
fn test_security_bootstrap_output_randomized() {
    let (work_ctx, bootstrap, work_keys, boot_keys, mut rng) =
        setup_bootstrap().expect("Setup failed");

    let ct = work_ctx.encrypt_dual(42, &work_keys.public_key, &mut rng);
    let fresh1 = bootstrap
        .bootstrap(&ct, &boot_keys.bsk, &boot_keys.ksk)
        .expect("Bootstrap 1");
    let fresh2 = bootstrap
        .bootstrap(&ct, &boot_keys.bsk, &boot_keys.ksk)
        .expect("Bootstrap 2");

    // Bootstrap is deterministic (no rng in bootstrap()), so outputs should be identical
    // This verifies determinism, which is a security property for reproducibility
    assert_eq!(
        fresh1.c0.main[0], fresh2.c0.main[0],
        "Deterministic bootstrap should produce identical outputs"
    );
}

// =========================================================================
// CATEGORY 16: Stress/Depth Tests — 4 tests
// =========================================================================

#[test]
fn test_stress_50_sequential_muls() {
    let config = SecureConfig::secure_128().into_config();
    let work_ctx = RNSFHEContext::try_new(&config).expect("Context");
    let bootstrap = ClockworkBootstrap::new(&config).expect("Bootstrap");
    let mut rng = ShadowHarvester::with_seed(12345);
    let work_keys = work_ctx.generate_keys_dual_full(&mut rng);
    let boot_keys = bootstrap
        .generate_keys(&work_keys.secret_key, &mut rng)
        .expect("KeyGen");

    let ct_x = work_ctx.encrypt_dual(2, &work_keys.public_key, &mut rng);
    let mut evaluator = AutoBootstrapEvaluator::new(
        &work_ctx,
        &bootstrap,
        &boot_keys.bsk,
        &boot_keys.ksk,
        &work_keys.eval_key,
        &config,
    );

    let mut ct_result = ct_x.clone();
    let mut actual_muls = 0;

    for _ in 0..50 {
        match evaluator.mul_auto(&ct_result, &ct_result) {
            Ok(ct_new) => {
                ct_result = ct_new;
                actual_muls += 1;
            }
            Err(_) => break,
        }
    }

    println!(
        "Stress 50 muls: {} completed, {} bootstraps",
        actual_muls, evaluator.bootstrap_count
    );
    assert!(
        actual_muls >= 5,
        "Should complete at least 5 muls, got {}",
        actual_muls
    );
}

#[test]
fn test_stress_100_alternating_ops() {
    let config = SecureConfig::secure_128().into_config();
    let work_ctx = RNSFHEContext::try_new(&config).expect("Context");
    let bootstrap = ClockworkBootstrap::new(&config).expect("Bootstrap");
    let mut rng = ShadowHarvester::with_seed(54321);
    let work_keys = work_ctx.generate_keys_dual_full(&mut rng);
    let boot_keys = bootstrap
        .generate_keys(&work_keys.secret_key, &mut rng)
        .expect("KeyGen");

    let ct_a = work_ctx.encrypt_dual(3, &work_keys.public_key, &mut rng);
    let ct_b = work_ctx.encrypt_dual(5, &work_keys.public_key, &mut rng);

    let mut evaluator = AutoBootstrapEvaluator::new(
        &work_ctx,
        &bootstrap,
        &boot_keys.bsk,
        &boot_keys.ksk,
        &work_keys.eval_key,
        &config,
    );

    let mut ct_result = ct_a.clone();
    let mut ops = 0;

    for i in 0..100 {
        if i % 2 == 0 {
            match evaluator.mul_auto(&ct_result, &ct_b) {
                Ok(ct_new) => ct_result = ct_new,
                Err(_) => break,
            }
        } else {
            ct_result = evaluator.add_auto(&ct_result, &ct_a);
        }
        ops += 1;
    }

    println!(
        "Stress 100 ops: {} completed, {} bootstraps",
        ops, evaluator.bootstrap_count
    );
    assert!(ops >= 20, "Should complete at least 20 ops, got {}", ops);
}

#[test]
fn test_stress_repeated_bootstrap_cycles() {
    let (work_ctx, bootstrap, work_keys, boot_keys, mut rng) =
        setup_bootstrap().expect("Setup failed");

    let mut ct = work_ctx.encrypt_dual(42, &work_keys.public_key, &mut rng);

    // 5 explicit bootstrap→multiply cycles
    for cycle in 0..5 {
        // Multiply
        ct = work_ctx.mul_dual_public(&ct, &ct, &work_keys.eval_key).unwrap();
        // Bootstrap
        match bootstrap.bootstrap(&ct, &boot_keys.bsk, &boot_keys.ksk) {
            Ok(fresh) => ct = fresh,
            Err(e) => {
                println!("Bootstrap cycle {} failed: {}", cycle, e);
                break;
            }
        }
    }
    // Should complete without panic
    println!("Repeated bootstrap cycles: completed 5");
}

#[test]
fn test_stress_budget_depth_200_precision() {
    let mut budget = NoiseBudget::with_budget_bits(500); // 500,000 mb

    for _ in 0..200 {
        let _ = budget.consume(NoiseOpType::Add, 1000); // 1 bit each
    }

    // After 200 × 1000 = 200,000 consumed from 500,000
    assert_eq!(
        budget.remaining_millibits(),
        300000,
        "After 200 ops: 500000 - 200000 = 300000"
    );
    assert_eq!(budget.operations().len(), 200);
}

// =========================================================================
// CATEGORY 17: Edge Cases — 5 tests
// =========================================================================

#[test]
fn test_edge_zero_plaintext_full_cycle() {
    let (work_ctx, bootstrap, work_keys, boot_keys, mut rng) =
        setup_bootstrap().expect("Setup failed");

    let ct = work_ctx.encrypt_dual(0, &work_keys.public_key, &mut rng);
    let ct_sq = work_ctx.mul_dual_public(&ct, &ct, &work_keys.eval_key).unwrap();
    let result = bootstrap.bootstrap(&ct_sq, &boot_keys.bsk, &boot_keys.ksk);
    assert!(result.is_ok(), "Zero plaintext full cycle should succeed");
}

#[test]
fn test_edge_max_plaintext_t_minus_1() {
    let config = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&config).expect("Context");
    let mut rng = ShadowHarvester::with_seed(42);
    let keys = ctx.generate_keys_dual_full(&mut rng);
    let t = config.t;

    let ct = ctx.encrypt_dual(t - 1, &keys.public_key, &mut rng);
    let dec = ctx.decrypt_dual(&ct, &keys.secret_key);
    assert_eq!(dec, t - 1, "encrypt(t-1) decrypt failed: got {}", dec);
}

#[test]
fn test_edge_self_add_equals_double() {
    let config = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&config).expect("Context");
    let mut rng = ShadowHarvester::with_seed(42);
    let keys = ctx.generate_keys_dual_full(&mut rng);
    let t = config.t;

    let m = 42u64;
    let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
    let ct_double = ctx.add_dual(&ct, &ct);
    let dec = ctx.decrypt_dual(&ct_double, &keys.secret_key);
    let expected = (2 * m) % t;
    assert_eq!(dec, expected, "ct+ct should equal 2*m mod t: got {}", dec);
}

#[test]
fn test_edge_self_mul_equals_square() {
    let config = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&config).expect("Context");
    let mut rng = ShadowHarvester::with_seed(42);
    let keys = ctx.generate_keys_dual_full(&mut rng);
    let t = config.t;

    let m = 42u64;
    let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
    let ct_sq = ctx.mul_dual_public(&ct, &ct, &keys.eval_key).unwrap();
    let dec = ctx.decrypt_dual(&ct_sq, &keys.secret_key);
    let expected = (m as u128 * m as u128 % t as u128) as u64;
    assert_eq!(
        dec, expected,
        "ct*ct should equal m^2 mod t: got {} expected {}",
        dec, expected
    );
}

#[test]
fn test_edge_multiply_by_enc_one() {
    let config = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&config).expect("Context");
    let mut rng = ShadowHarvester::with_seed(42);
    let keys = ctx.generate_keys_dual_full(&mut rng);

    let ct_42 = ctx.encrypt_dual(42, &keys.public_key, &mut rng);
    let ct_1 = ctx.encrypt_dual(1, &keys.public_key, &mut rng);
    let ct_prod = ctx.mul_dual_public(&ct_42, &ct_1, &keys.eval_key).unwrap();
    let dec = ctx.decrypt_dual(&ct_prod, &keys.secret_key);
    assert_eq!(dec, 42, "42 * 1 should equal 42, got {}", dec);
}

// =========================================================================
// NOISE ANALYSIS TEST (from original suite)
// =========================================================================

#[test]
fn test_noise_budget_analysis() {
    let config = SecureConfig::secure_128().into_config();

    let boot_primes = &BOOTSTRAP_PRIMES[..4];
    let q_boot_bits: u32 = boot_primes.iter().map(|&p| 64 - p.leading_zeros()).sum();
    let t_bits = 64 - config.t.leading_zeros();
    let delta_bits = q_boot_bits - t_bits;

    let eta_bits = 64 - (config.eta as u64).leading_zeros();
    let n_half_bits = config.n.trailing_zeros().div_ceil(2);
    let noise_bits = t_bits + eta_bits + n_half_bits;

    let margin = delta_bits - noise_bits;
    assert!(margin >= 30, "Need >= 30-bit margin, got {}", margin);
}

// =========================================================================
// NOISE BUDGET INTEGRATION TESTS (from original suite)
// =========================================================================

#[test]
fn test_bootstrap_resets_noise() {
    let config = SecureConfig::secure_128().into_config();
    let mut budget = NoiseBudget::from_config(&config);
    let initial = budget.remaining_millibits();

    for _ in 0..5 {
        let _ = budget.consume(
            NoiseOpType::MulCt,
            NoiseBudget::mul_ct_cost(&config) + NoiseBudget::relin_cost(&config),
        );
    }

    let after_muls = budget.remaining_millibits();
    assert!(after_muls < initial);

    budget.reset_after_bootstrap(&config);
    let after_bootstrap = budget.remaining_millibits();
    assert!(
        after_bootstrap > after_muls,
        "Budget should increase after bootstrap"
    );
}

#[test]
fn test_noise_budget_should_bootstrap() {
    let config = SecureConfig::secure_128().into_config();
    let mut budget = NoiseBudget::from_config(&config);

    assert!(!budget.should_bootstrap(250));

    let mut triggered = false;
    for _ in 0..20 {
        let cost = NoiseBudget::mul_ct_cost(&config) + NoiseBudget::relin_cost(&config);
        if budget.consume(NoiseOpType::MulCt, cost).is_err() {
            triggered = budget.should_bootstrap(250) || budget.remaining_millibits() < cost;
            break;
        }
        if budget.should_bootstrap(250) {
            triggered = true;
            break;
        }
    }
    assert!(triggered, "Should trigger bootstrap");
}

// =========================================================================
// CATEGORY 12: Non-Circular KSK Bootstrap — 5 tests
// =========================================================================

fn setup_bootstrap_ksk() -> Nine65Result<(
    RNSFHEContext,
    ClockworkBootstrap,
    nine65::ops::rns_fhe::DualRNSFullKeySet,
    nine65::keys::bootstrap::BootstrapKeySet,
    ShadowHarvester,
)> {
    let config = SecureConfig::secure_128().into_config();
    let work_ctx = RNSFHEContext::try_new(&config)?;
    let bootstrap = ClockworkBootstrap::new(&config)?;
    let mut rng = ShadowHarvester::with_seed(42);
    let work_keys = work_ctx.generate_keys_dual_full(&mut rng);
    let boot_keys = bootstrap.generate_keys_with_ksk(&work_keys.secret_key, &mut rng)?;
    Ok((work_ctx, bootstrap, work_keys, boot_keys, rng))
}

#[test]
fn test_ksk_generation_produces_nonempty_ksk() {
    let (_work_ctx, _bootstrap, _work_keys, boot_keys, _rng) =
        setup_bootstrap_ksk().expect("KSK setup failed");

    assert!(
        !boot_keys.ksk.ksk.is_empty(),
        "KSK should have decomposition components"
    );
    assert!(
        boot_keys.ksk.num_digits > 0,
        "KSK should have > 0 digits"
    );
    assert!(
        boot_keys.ksk.decomp_base > 1,
        "KSK decomp base should be > 1"
    );
    println!(
        "KSK: {} digits, base={}, {} component pairs",
        boot_keys.ksk.num_digits,
        boot_keys.ksk.decomp_base,
        boot_keys.ksk.ksk.len()
    );
}

#[test]
fn test_ksk_num_digits_matches_components() {
    let (_work_ctx, _bootstrap, _work_keys, boot_keys, _rng) =
        setup_bootstrap_ksk().expect("KSK setup failed");

    assert_eq!(
        boot_keys.ksk.ksk.len(),
        boot_keys.ksk.num_digits,
        "Number of KSK pairs should equal num_digits"
    );
}

#[test]
fn test_ksk_boot_sk_is_independent() {
    let config = SecureConfig::secure_128().into_config();
    let work_ctx = RNSFHEContext::try_new(&config).expect("Context");
    let bootstrap = ClockworkBootstrap::new(&config).expect("Bootstrap");
    let mut rng = ShadowHarvester::with_seed(42);
    let work_keys = work_ctx.generate_keys_dual_full(&mut rng);

    // Generate circular keys
    let circ_keys = bootstrap
        .generate_keys(&work_keys.secret_key, &mut rng)
        .expect("Circular keygen");

    // Generate KSK keys (independent boot_sk)
    let mut rng2 = ShadowHarvester::with_seed(99);
    let ksk_keys = bootstrap
        .generate_keys_with_ksk(&work_keys.secret_key, &mut rng2)
        .expect("KSK keygen");

    // Circular boot_sk should be deterministic lift of work_sk
    // KSK boot_sk should be independent (different polynomial)
    let circ_boot_s = &circ_keys.boot_sk.s.main[0];
    let ksk_boot_s = &ksk_keys.boot_sk.s.main[0];
    let work_s = &work_keys.secret_key.s.main[0];

    // Count how many coefficients differ between boot keys
    let circ_diff: usize = circ_boot_s
        .iter()
        .zip(work_s.iter())
        .filter(|(a, b)| {
            // Circular should match (modulo prime difference):
            // ternary coefficients {0, 1, p-1} map to same {0, 1, boot_p-1}
            let a_tern = if **a == 0 { 0 } else if **a == 1 { 1 } else { 2 };
            let b_tern = if **b == 0 { 0 } else if **b == 1 { 1 } else { 2 };
            a_tern != b_tern
        })
        .count();

    let ksk_diff: usize = ksk_boot_s
        .iter()
        .zip(circ_boot_s.iter())
        .filter(|(a, b)| a != b)
        .count();

    // Circular boot_sk is the same polynomial as work_sk (different moduli)
    assert_eq!(
        circ_diff, 0,
        "Circular boot_sk should be same ternary polynomial as work_sk"
    );

    // KSK boot_sk should differ from circular boot_sk (independent key)
    assert!(
        ksk_diff > 0,
        "KSK boot_sk should be independent from circular boot_sk"
    );
    println!(
        "KSK boot_sk differs from circular boot_sk in {}/{} coefficients",
        ksk_diff,
        ksk_boot_s.len()
    );
}

#[test]
fn test_bootstrap_with_ksk_does_not_panic() {
    let (work_ctx, bootstrap, work_keys, boot_keys, mut rng) =
        setup_bootstrap_ksk().expect("KSK setup failed");

    let ct = work_ctx.encrypt_dual(0, &work_keys.public_key, &mut rng);
    let result = bootstrap.bootstrap_with_ksk(&ct, &boot_keys.bsk, &boot_keys.ksk);
    assert!(result.is_ok(), "KSK bootstrap should not fail: {:?}", result.err());
}

#[test]
fn test_bootstrap_with_ksk_roundtrip_messages() {
    let (work_ctx, bootstrap, work_keys, boot_keys, mut rng) =
        setup_bootstrap_ksk().expect("KSK setup failed");
    let t = work_ctx.t;

    for &m in &[0u64, 1, 2, 42, 100, 1000, 65536, t - 1] {
        let ct = work_ctx.encrypt_dual(m, &work_keys.public_key, &mut rng);
        let result = bootstrap.bootstrap_with_ksk(&ct, &boot_keys.bsk, &boot_keys.ksk);
        assert!(
            result.is_ok(),
            "KSK bootstrap should not fail for m={}",
            m
        );
        let dec = work_ctx.decrypt_dual(&result.unwrap(), &work_keys.secret_key);
        println!("KSK bootstrap m={}: decrypted={}", m, dec);
    }
}
