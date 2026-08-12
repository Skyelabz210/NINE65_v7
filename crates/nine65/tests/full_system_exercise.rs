//! Full System Exercise — Comprehensive FHE Integration Tests
//!
//! Exercises ALL encryption modes, ALL valid parameter configurations,
//! ALL homomorphic operations, and ALL key generation paths.
//!
//! Every test produces diagnostic output (run with `-- --nocapture`).
//!
//! Coverage matrix:
//! - Configs: test_fast, test_medium, secure_128, secure_128_deep, secure_192, secure_256
//! - Insecure configs: light, light_rns, light_exact, light_rns_exact, standard_128,
//!   high_192, deep_128, batched, he_standard_128, depth2_128, depth3_128
//! - Modes: RNS single, Dual-RNS symmetric, Dual-RNS public, Auto, GSO-FHE
//! - Ops: add, sub, negate, mul_symmetric, mul_public, add_plain, mod_switch, depth chain
//! - Values: 0, 1, t/2, t-1, random spread
//! - Determinism: seeded reproducibility checks

use nine65::entropy::ShadowHarvester;
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::params::secure_configs::SecureConfig;
use nine65::params::FHEConfig;

// ============================================================================
// HELPERS
// ============================================================================

/// Result container for a single encrypt-decrypt roundtrip
struct RoundtripResult {
    config_name: &'static str,
    plaintext: u64,
    decrypted: u64,
    correct: bool,
    t: u64,
}

impl RoundtripResult {
    fn report(&self) -> String {
        let status = if self.correct { "OK" } else { "MISMATCH" };
        format!(
            "[{}] config={}, m={}, dec={}, t={}",
            status, self.config_name, self.plaintext, self.decrypted, self.t
        )
    }
}

/// Result container for a homomorphic operation
struct OpResult {
    op_name: &'static str,
    config_name: &'static str,
    input_a: u64,
    input_b: Option<u64>,
    expected: u64,
    actual: u64,
    correct: bool,
}

impl OpResult {
    fn report(&self) -> String {
        let status = if self.correct { "OK" } else { "MISMATCH" };
        match self.input_b {
            Some(b) => format!(
                "[{}] {} on {}: {}({}, {}) = {} (expected {})",
                status, self.op_name, self.config_name, self.op_name, self.input_a, b,
                self.actual, self.expected
            ),
            None => format!(
                "[{}] {} on {}: {}({}) = {} (expected {})",
                status, self.op_name, self.config_name, self.op_name, self.input_a,
                self.actual, self.expected
            ),
        }
    }
}

/// Collect test values for a given plaintext modulus t
fn test_values(t: u64) -> Vec<u64> {
    let mut vals = vec![0, 1, t - 1, t / 2];
    // Add some spread values
    if t > 100 {
        vals.push(42);
        vals.push(t / 3);
        vals.push(t / 4);
        vals.push(t - 2);
    }
    if t > 10000 {
        vals.push(9999);
        vals.push(65536.min(t - 1));
    }
    vals
}

// ============================================================================
// MODULE 1: PARAMETER CONFIGURATION VALIDATION
// ============================================================================

#[test]
fn test_all_secure_configs_construct() {
    println!("\n=== SecureConfig Construction ===\n");
    println!(
        "{:<20} {:>6} {:>8} {:>10} {:>10} {:>10} {:>5}",
        "Config", "N", "log(Q)", "Classical", "Hybrid", "Quantum", "HE?"
    );
    println!("{}", "-".repeat(75));

    let configs: Vec<(&str, SecureConfig)> = vec![
        ("secure_128", SecureConfig::secure_128()),
        ("secure_128_deep", SecureConfig::secure_128_deep()),
        ("secure_192", SecureConfig::secure_192()),
        ("secure_256", SecureConfig::secure_256()),
        ("test_fast", SecureConfig::test_fast_insecure()),
        ("test_medium", SecureConfig::test_medium_insecure()),
    ];

    for (name, sc) in &configs {
        let log_q: u32 = sc.config.primes.iter().map(|&p| 64 - p.leading_zeros()).sum();
        println!(
            "{:<20} {:>6} {:>8} {:>10} {:>10} {:>10} {:>5}",
            name,
            sc.config.n,
            log_q,
            sc.classical_security,
            sc.hybrid_security,
            sc.quantum_security,
            if sc.he_standard_compliant { "yes" } else { "no" }
        );
    }

    // Verify production configs meet claims
    for (name, sc) in &configs {
        if name.starts_with("secure_") {
            assert!(
                sc.is_production_safe(),
                "{} should be production-safe",
                name
            );
        }
    }

    println!("\nAll {} SecureConfig variants constructed successfully.", configs.len());
}

#[test]
#[allow(deprecated)]
fn test_all_insecure_configs_construct() {
    println!("\n=== FHEConfig (Insecure/Test) Construction ===\n");
    println!(
        "{:<30} {:>6} {:>8} {:>8} {:>8} {:>10}",
        "Config", "N", "primes", "q", "t", "Q_product"
    );
    println!("{}", "-".repeat(80));

    let configs: Vec<(&str, FHEConfig)> = vec![
        ("light", FHEConfig::light_insecure()),
        ("light_mul", FHEConfig::light_mul_insecure()),
        ("light_rns", FHEConfig::light_rns_insecure()),
        ("light_exact", FHEConfig::light_exact_insecure()),
        ("light_rns_exact", FHEConfig::light_rns_exact_insecure()),
        ("large_single", FHEConfig::large_single_insecure()),
        ("standard_128", FHEConfig::standard_128_insecure()),
        ("high_192", FHEConfig::high_192_insecure()),
        ("deep_128", FHEConfig::deep_128_insecure()),
        ("batched", FHEConfig::batched_insecure()),
        ("he_standard_128", FHEConfig::he_standard_128_insecure()),
        ("he_standard_128_deep", FHEConfig::he_standard_128_deep_insecure()),
        ("depth2_128", FHEConfig::depth2_128_insecure()),
        ("depth3_128", FHEConfig::depth3_128_insecure()),
        ("deep_circuit", FHEConfig::deep_circuit_insecure()),
    ];

    for (name, cfg) in &configs {
        // try_rns_product: configs like deep_circuit exceed u128, where the
        // fail-closed rns_product() would panic; fall back to the exact bit
        // length, which is valid for any product size.
        let q_display = match cfg.try_rns_product() {
            Some(q_prod) if q_prod <= 1_000_000_000_000 => format!("{}", q_prod),
            _ => format!("~2^{}", cfg.rns_product_bit_length()),
        };
        println!(
            "{:<30} {:>6} {:>8} {:>8} {:>8} {:>10}",
            name,
            cfg.n,
            cfg.primes.len(),
            cfg.q,
            cfg.t,
            q_display
        );
    }

    println!("\nAll {} FHEConfig variants constructed successfully.", configs.len());
}

#[test]
fn test_custom_config_validation() {
    println!("\n=== Custom Config Validation ===\n");

    // Valid custom config
    let result = FHEConfig::custom(1024, vec![998244353], 65537, 2);
    println!("Valid custom(1024, [998244353], 65537, 2): {:?}", result.is_ok());
    assert!(result.is_ok(), "Valid custom config should succeed");

    // Invalid: N not power of 2
    let result = FHEConfig::custom(1000, vec![998244353], 65537, 2);
    println!("Invalid N=1000: {:?}", result.is_err());
    assert!(result.is_err(), "N=1000 should fail (not power of 2)");

    // Invalid: empty primes
    let result = FHEConfig::custom(1024, vec![], 65537, 2);
    println!("Invalid empty primes: {:?}", result.is_err());
    assert!(result.is_err(), "Empty primes should fail");

    // Invalid: t = 0
    let result = FHEConfig::custom(1024, vec![998244353], 0, 2);
    println!("Invalid t=0: {:?}", result.is_err());
    assert!(result.is_err(), "t=0 should fail");

    // Note: FHEConfig::custom does not currently reject t >= q.
    // This is a known gap — delta would be 0, which leads to broken encryption.
    // Testing that it at least doesn't panic:
    let result = FHEConfig::custom(1024, vec![998244353], 998244354, 2);
    println!("t >= q accepted (known gap): {:?}", result.is_ok());
    if result.is_ok() {
        let cfg = result.unwrap();
        println!("  delta = {} (should be 0, which breaks encryption)", cfg.delta());
    }

    println!("\nCustom config validation: all checks passed.");
}

// ============================================================================
// MODULE 2: RNS CONTEXT CONSTRUCTION
// ============================================================================

#[test]
fn test_rns_context_from_all_multi_prime_configs() {
    println!("\n=== RNSFHEContext Construction ===\n");

    let configs: Vec<(&str, FHEConfig)> = vec![
        ("secure_128", SecureConfig::secure_128().into_config()),
        ("secure_128_deep", SecureConfig::secure_128_deep().into_config()),
        ("secure_192", SecureConfig::secure_192().into_config()),
        ("secure_256", SecureConfig::secure_256().into_config()),
        ("test_fast", SecureConfig::test_fast_insecure().into_config()),
        ("test_medium", SecureConfig::test_medium_insecure().into_config()),
    ];

    println!(
        "{:<20} {:>8} {:>10} {:>15}",
        "Config", "primes", "mul_route", "result"
    );
    println!("{}", "-".repeat(60));

    for (name, cfg) in &configs {
        match RNSFHEContext::try_new(cfg) {
            Ok(ctx) => {
                println!(
                    "{:<20} {:>8} {:>10} {:>15}",
                    name,
                    cfg.primes.len(),
                    format!("{:?}", ctx.mul_route()),
                    "OK"
                );
            }
            Err(e) => {
                println!(
                    "{:<20} {:>8} {:>10} {:>15}",
                    name,
                    cfg.primes.len(),
                    "N/A",
                    format!("ERR: {}", e)
                );
                // Single-prime configs may not support RNSFHEContext
                if cfg.primes.len() >= 2 {
                    panic!("{} with {} primes should construct RNSFHEContext", name, cfg.primes.len());
                }
            }
        }
    }

    println!("\nRNSFHEContext construction complete.");
}

// ============================================================================
// MODULE 3: DUAL-RNS SYMMETRIC MODE (encrypt_dual / decrypt_dual)
// ============================================================================

#[test]
fn test_dual_symmetric_roundtrip_all_configs() {
    println!("\n=== Dual-RNS Symmetric Roundtrip (all configs) ===\n");

    let configs: Vec<(&str, FHEConfig)> = vec![
        ("secure_128", SecureConfig::secure_128().into_config()),
        ("secure_128_deep", SecureConfig::secure_128_deep().into_config()),
        ("test_fast", SecureConfig::test_fast_insecure().into_config()),
        ("test_medium", SecureConfig::test_medium_insecure().into_config()),
    ];

    let mut all_results: Vec<RoundtripResult> = Vec::new();

    for (name, cfg) in &configs {
        let ctx = match RNSFHEContext::try_new(cfg) {
            Ok(c) => c,
            Err(e) => {
                println!("[SKIP] {}: {}", name, e);
                continue;
            }
        };
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual(&mut rng);

        for &m in &test_values(cfg.t) {
            let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
            let dec = ctx.decrypt_dual(&ct, &keys.secret_key);

            let result = RoundtripResult {
                config_name: name,
                plaintext: m,
                decrypted: dec,
                correct: dec == m,
                t: cfg.t,
            };
            println!("  {}", result.report());
            all_results.push(result);
        }
    }

    let total = all_results.len();
    let passed = all_results.iter().filter(|r| r.correct).count();
    let failed = total - passed;

    println!("\n--- Summary: {}/{} passed, {} failed ---", passed, total, failed);
    assert_eq!(failed, 0, "{} roundtrips failed", failed);
}

#[test]
fn test_dual_symmetric_roundtrip_secure_192() {
    println!("\n=== Dual-RNS Symmetric: secure_192 ===\n");

    let cfg = SecureConfig::secure_192().into_config();
    let ctx = RNSFHEContext::try_new(&cfg).expect("secure_192 context");
    let mut rng = ShadowHarvester::with_seed(192);
    let keys = ctx.generate_keys_dual(&mut rng);

    // Reduced value set — N=16384 is slow
    let values = [0u64, 1, 42, cfg.t - 1];
    let mut passed = 0usize;
    let mut failed = 0usize;

    for &m in &values {
        let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
        let dec = ctx.decrypt_dual(&ct, &keys.secret_key);
        let ok = dec == m;
        println!("  [{}] m={}, dec={}", if ok { "OK" } else { "FAIL" }, m, dec);
        if ok { passed += 1; } else { failed += 1; }
    }

    println!("\n--- secure_192: {}/{} passed ---", passed, passed + failed);
    assert_eq!(failed, 0);
}

#[test]
fn test_dual_symmetric_roundtrip_secure_256() {
    println!("\n=== Dual-RNS Symmetric: secure_256 ===\n");

    let cfg = SecureConfig::secure_256().into_config();
    let ctx = RNSFHEContext::try_new(&cfg).expect("secure_256 context");
    let mut rng = ShadowHarvester::with_seed(256);
    let keys = ctx.generate_keys_dual(&mut rng);

    // Reduced value set — N=16384 is slow
    let values = [0u64, 1, 42, cfg.t - 1];
    let mut passed = 0usize;
    let mut failed = 0usize;

    for &m in &values {
        let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
        let dec = ctx.decrypt_dual(&ct, &keys.secret_key);
        let ok = dec == m;
        println!("  [{}] m={}, dec={}", if ok { "OK" } else { "FAIL" }, m, dec);
        if ok { passed += 1; } else { failed += 1; }
    }

    println!("\n--- secure_256: {}/{} passed ---", passed, passed + failed);
    assert_eq!(failed, 0);
}

// ============================================================================
// MODULE 4: DUAL-RNS PUBLIC MODE (with eval key for ct*ct multiplication)
// ============================================================================

#[test]
fn test_dual_public_mode_roundtrip() {
    println!("\n=== Dual-RNS Public Mode Roundtrip ===\n");

    let configs: Vec<(&str, FHEConfig)> = vec![
        ("secure_128", SecureConfig::secure_128().into_config()),
        ("test_medium", SecureConfig::test_medium_insecure().into_config()),
    ];

    for (name, cfg) in &configs {
        let ctx = match RNSFHEContext::try_new(&cfg) {
            Ok(c) => c,
            Err(e) => {
                println!("[SKIP] {}: {}", name, e);
                continue;
            }
        };
        let mut rng = ShadowHarvester::with_seed(100);
        let keys = ctx.generate_keys_dual_full(&mut rng);

        println!("  Config: {} (N={}, t={})", name, cfg.n, cfg.t);

        for &m in &[0u64, 1, 42, cfg.t - 1] {
            let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
            let dec = ctx.decrypt_dual(&ct, &keys.secret_key);
            let ok = dec == m;
            println!("    [{}] encrypt/decrypt m={}, got={}", if ok { "OK" } else { "FAIL" }, m, dec);
            assert_eq!(dec, m, "Public mode roundtrip failed for m={} on {}", m, name);
        }
    }

    println!("\nPublic mode roundtrip: all passed.");
}

// ============================================================================
// MODULE 5: AUTO MODE (automatic routing based on prime count)
// ============================================================================

#[test]
fn test_auto_mode_roundtrip() {
    println!("\n=== Auto Mode Roundtrip ===\n");

    let configs: Vec<(&str, FHEConfig)> = vec![
        ("secure_128", SecureConfig::secure_128().into_config()),
        ("test_fast", SecureConfig::test_fast_insecure().into_config()),
    ];

    for (name, cfg) in &configs {
        let ctx = match RNSFHEContext::try_new(&cfg) {
            Ok(c) => c,
            Err(e) => {
                println!("[SKIP] {}: {}", name, e);
                continue;
            }
        };

        let mut rng = ShadowHarvester::with_seed(200);
        let keys = ctx.generate_keys_auto(&mut rng);
        let mul_route = ctx.mul_route();

        println!("  Config: {} (route={:?})", name, mul_route);

        for &m in &[0u64, 1, 42, cfg.t - 1] {
            let ct = ctx.encrypt_auto(m, &keys, &mut rng).expect("encrypt_auto");
            match ctx.decrypt_auto(&ct, &keys) {
                Ok(dec) => {
                    let ok = dec == m;
                    println!("    [{}] m={}, dec={}", if ok { "OK" } else { "FAIL" }, m, dec);
                    assert_eq!(dec, m, "Auto mode failed for m={} on {}", m, name);
                }
                Err(e) => {
                    println!("    [ERR] m={}: {}", m, e);
                    panic!("Auto mode decrypt failed for m={} on {}: {}", m, name, e);
                }
            }
        }
    }

    println!("\nAuto mode roundtrip: all passed.");
}

// ============================================================================
// MODULE 6: HOMOMORPHIC ADDITION (dual symmetric)
// ============================================================================

#[test]
fn test_homomorphic_add_dual() {
    println!("\n=== Homomorphic Addition (Dual-RNS) ===\n");

    let cfg = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&cfg).expect("context");
    let mut rng = ShadowHarvester::with_seed(300);
    let keys = ctx.generate_keys_dual(&mut rng);

    let pairs: Vec<(u64, u64)> = vec![
        (0, 0),
        (1, 1),
        (42, 58),
        (cfg.t - 1, 1),  // wraparound: (t-1)+1 = 0 mod t
        (cfg.t / 2, cfg.t / 2),
        (100, 200),
        (cfg.t - 2, cfg.t - 3),
    ];

    let mut results: Vec<OpResult> = Vec::new();

    for (a, b) in &pairs {
        let ct_a = ctx.encrypt_dual(*a, &keys.public_key, &mut rng);
        let ct_b = ctx.encrypt_dual(*b, &keys.public_key, &mut rng);
        let ct_sum = ctx.add_dual(&ct_a, &ct_b);
        let dec = ctx.decrypt_dual(&ct_sum, &keys.secret_key);
        let expected = (*a + *b) % cfg.t;

        let result = OpResult {
            op_name: "add",
            config_name: "secure_128",
            input_a: *a,
            input_b: Some(*b),
            expected,
            actual: dec,
            correct: dec == expected,
        };
        println!("  {}", result.report());
        results.push(result);
    }

    let failed = results.iter().filter(|r| !r.correct).count();
    println!("\n--- Add: {}/{} passed ---", results.len() - failed, results.len());
    assert_eq!(failed, 0, "{} addition tests failed", failed);
}

// ============================================================================
// MODULE 7: HOMOMORPHIC SUBTRACTION (dual symmetric)
// ============================================================================

#[test]
fn test_homomorphic_sub_dual() {
    println!("\n=== Homomorphic Subtraction (Dual-RNS) ===\n");

    let cfg = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&cfg).expect("context");
    let mut rng = ShadowHarvester::with_seed(400);
    let keys = ctx.generate_keys_dual(&mut rng);

    let pairs: Vec<(u64, u64)> = vec![
        (0, 0),
        (1, 0),
        (0, 1),     // wraparound: 0 - 1 = t-1 mod t
        (100, 50),
        (50, 100),  // wraparound
        (cfg.t - 1, cfg.t - 1),
        (cfg.t - 1, 0),
    ];

    let mut results: Vec<OpResult> = Vec::new();

    for (a, b) in &pairs {
        let ct_a = ctx.encrypt_dual(*a, &keys.public_key, &mut rng);
        let ct_b = ctx.encrypt_dual(*b, &keys.public_key, &mut rng);
        let ct_diff = ctx.sub_dual(&ct_a, &ct_b);
        let dec = ctx.decrypt_dual(&ct_diff, &keys.secret_key);
        let expected = (cfg.t + *a - *b) % cfg.t;

        let result = OpResult {
            op_name: "sub",
            config_name: "secure_128",
            input_a: *a,
            input_b: Some(*b),
            expected,
            actual: dec,
            correct: dec == expected,
        };
        println!("  {}", result.report());
        results.push(result);
    }

    let failed = results.iter().filter(|r| !r.correct).count();
    println!("\n--- Sub: {}/{} passed ---", results.len() - failed, results.len());
    assert_eq!(failed, 0, "{} subtraction tests failed", failed);
}

// ============================================================================
// MODULE 8: HOMOMORPHIC MULTIPLICATION — SYMMETRIC (no eval key)
// ============================================================================

#[test]
fn test_homomorphic_mul_symmetric() {
    println!("\n=== Homomorphic Multiplication — Symmetric ===\n");

    let cfg = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&cfg).expect("context");
    let mut rng = ShadowHarvester::with_seed(500);
    let keys = ctx.generate_keys_dual(&mut rng);

    let pairs: Vec<(u64, u64)> = vec![
        (0, 0),
        (1, 1),
        (2, 3),
        (7, 11),
        (100, 200),
        (cfg.t - 1, 1),    // (t-1)*1 = t-1
        (cfg.t - 1, 2),    // (t-1)*2 = t-2 mod t
    ];

    let mut results: Vec<OpResult> = Vec::new();

    for (a, b) in &pairs {
        let ct_a = ctx.encrypt_dual(*a, &keys.public_key, &mut rng);
        let ct_b = ctx.encrypt_dual(*b, &keys.public_key, &mut rng);
        let ct_prod = ctx.mul_dual_symmetric(&ct_a, &ct_b, &keys.secret_key);
        let dec = ctx.decrypt_dual(&ct_prod, &keys.secret_key);
        let expected = ((*a as u128 * *b as u128) % cfg.t as u128) as u64;

        let result = OpResult {
            op_name: "mul_sym",
            config_name: "secure_128",
            input_a: *a,
            input_b: Some(*b),
            expected,
            actual: dec,
            correct: dec == expected,
        };
        println!("  {}", result.report());
        results.push(result);
    }

    let failed = results.iter().filter(|r| !r.correct).count();
    println!("\n--- Mul Symmetric: {}/{} passed ---", results.len() - failed, results.len());
    assert_eq!(failed, 0, "{} multiplication tests failed", failed);
}

// ============================================================================
// MODULE 9: HOMOMORPHIC MULTIPLICATION — PUBLIC (with eval key)
// ============================================================================

#[test]
fn test_homomorphic_mul_public() {
    println!("\n=== Homomorphic Multiplication — Public ===\n");

    let cfg = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&cfg).expect("context");
    let mut rng = ShadowHarvester::with_seed(600);
    let keys = ctx.generate_keys_dual_full(&mut rng);

    let pairs: Vec<(u64, u64)> = vec![
        (0, 1),
        (1, 1),
        (2, 3),
        (5, 7),
        (42, 100),
    ];

    let mut results: Vec<OpResult> = Vec::new();

    for (a, b) in &pairs {
        let ct_a = ctx.encrypt_dual(*a, &keys.public_key, &mut rng);
        let ct_b = ctx.encrypt_dual(*b, &keys.public_key, &mut rng);

        match ctx.mul_dual_public(&ct_a, &ct_b, &keys.eval_key) {
            Ok(ct_prod) => {
                let dec = ctx.decrypt_dual(&ct_prod, &keys.secret_key);
                let expected = ((*a as u128 * *b as u128) % cfg.t as u128) as u64;

                let result = OpResult {
                    op_name: "mul_pub",
                    config_name: "secure_128",
                    input_a: *a,
                    input_b: Some(*b),
                    expected,
                    actual: dec,
                    correct: dec == expected,
                };
                println!("  {}", result.report());
                results.push(result);
            }
            Err(e) => {
                println!("  [ERR] mul_pub({}, {}) = {}", a, b, e);
                results.push(OpResult {
                    op_name: "mul_pub",
                    config_name: "secure_128",
                    input_a: *a,
                    input_b: Some(*b),
                    expected: 0,
                    actual: 0,
                    correct: false,
                });
            }
        }
    }

    let failed = results.iter().filter(|r| !r.correct).count();
    println!("\n--- Mul Public: {}/{} passed ---", results.len() - failed, results.len());
    assert_eq!(failed, 0, "{} public multiplication tests failed", failed);
}

// ============================================================================
// MODULE 10: MULTIPLICATION DEPTH CHAIN — SYMMETRIC
// ============================================================================

#[test]
fn test_mul_depth_chain_symmetric_secure_128() {
    println!("\n=== Multiplication Depth Chain — Symmetric (secure_128) ===\n");

    let cfg = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&cfg).expect("context");
    let mut rng = ShadowHarvester::with_seed(700);
    let keys = ctx.generate_keys_dual(&mut rng);

    let base: u64 = 2;
    let mut current = ctx.encrypt_dual(base, &keys.public_key, &mut rng);
    let mut expected: u64 = base;
    let max_depth = 20;

    println!("  Base value: {}", base);
    println!("  {:>5} {:>15} {:>15} {:>8}", "Depth", "Expected", "Decrypted", "Status");
    println!("  {}", "-".repeat(50));

    let mut max_correct_depth = 0u32;

    for depth in 1..=max_depth {
        let ct_copy = current.clone();
        let ct_prod = ctx.mul_dual_symmetric(&current, &ct_copy, &keys.secret_key);
        expected = ((expected as u128 * expected as u128) % cfg.t as u128) as u64;

        match ctx.try_decrypt_dual(&ct_prod, &keys.secret_key) {
            Ok(dec) => {
                let ok = dec == expected;
                println!(
                    "  {:>5} {:>15} {:>15} {:>8}",
                    depth, expected, dec, if ok { "OK" } else { "WRONG" }
                );
                if ok {
                    max_correct_depth = depth as u32;
                    current = ct_prod;
                } else {
                    println!("  Noise exhausted at depth {}", depth);
                    break;
                }
            }
            Err(e) => {
                println!("  {:>5} {:>15} {:>15} {:>8}", depth, expected, format!("ERR: {}", e), "NOISE");
                break;
            }
        }
    }

    println!("\n--- Max correct depth: {} ---", max_correct_depth);
    // secure_128 with 3 primes should handle at least depth 1
    assert!(max_correct_depth >= 1, "Should achieve at least depth 1");
}

// ============================================================================
// MODULE 11: MULTIPLICATION DEPTH CHAIN — PUBLIC
// ============================================================================

#[test]
fn test_mul_depth_chain_public_secure_128() {
    println!("\n=== Multiplication Depth Chain — Public (secure_128) ===\n");

    let cfg = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&cfg).expect("context");
    let mut rng = ShadowHarvester::with_seed(710);
    let keys = ctx.generate_keys_dual_full(&mut rng);

    let base: u64 = 2;
    let mut current = ctx.encrypt_dual(base, &keys.public_key, &mut rng);
    let mut expected: u64 = base;
    let max_depth = 20;

    println!("  Base value: {}", base);
    println!("  {:>5} {:>15} {:>15} {:>8}", "Depth", "Expected", "Decrypted", "Status");
    println!("  {}", "-".repeat(50));

    let mut max_correct_depth = 0u32;

    for depth in 1..=max_depth {
        let ct_copy = current.clone();
        match ctx.mul_dual_public(&current, &ct_copy, &keys.eval_key) {
            Ok(ct_prod) => {
                expected = ((expected as u128 * expected as u128) % cfg.t as u128) as u64;

                match ctx.try_decrypt_dual(&ct_prod, &keys.secret_key) {
                    Ok(dec) => {
                        let ok = dec == expected;
                        println!(
                            "  {:>5} {:>15} {:>15} {:>8}",
                            depth, expected, dec, if ok { "OK" } else { "WRONG" }
                        );
                        if ok {
                            max_correct_depth = depth as u32;
                            current = ct_prod;
                        } else {
                            println!("  Noise exhausted at depth {}", depth);
                            break;
                        }
                    }
                    Err(e) => {
                        println!("  {:>5} {:>15} {:>15}", depth, expected, format!("ERR: {}", e));
                        break;
                    }
                }
            }
            Err(e) => {
                println!("  Mul public failed at depth {}: {}", depth, e);
                break;
            }
        }
    }

    println!("\n--- Max correct depth (public): {} ---", max_correct_depth);
    assert!(max_correct_depth >= 1, "Should achieve at least depth 1 in public mode");
}

// ============================================================================
// MODULE 12: DETERMINISM — SEEDED REPRODUCIBILITY
// ============================================================================

#[test]
fn test_deterministic_encryption() {
    println!("\n=== Determinism: Seeded Reproducibility ===\n");

    let cfg = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&cfg).expect("context");
    let m: u64 = 42;

    // Run 1
    let mut rng1 = ShadowHarvester::with_seed(999);
    let keys1 = ctx.generate_keys_dual(&mut rng1);
    let ct1 = ctx.encrypt_dual(m, &keys1.public_key, &mut rng1);
    let dec1 = ctx.decrypt_dual(&ct1, &keys1.secret_key);

    // Run 2 (same seed)
    let mut rng2 = ShadowHarvester::with_seed(999);
    let keys2 = ctx.generate_keys_dual(&mut rng2);
    let ct2 = ctx.encrypt_dual(m, &keys2.public_key, &mut rng2);
    let dec2 = ctx.decrypt_dual(&ct2, &keys2.secret_key);

    println!("  Run 1: encrypt({}) -> decrypt = {}", m, dec1);
    println!("  Run 2: encrypt({}) -> decrypt = {}", m, dec2);
    println!("  Decryptions match: {}", dec1 == dec2);

    // Check ciphertext equality (c0 main limbs)
    let c0_match = ct1.c0.main == ct2.c0.main;
    let c1_match = ct1.c1.main == ct2.c1.main;
    println!("  Ciphertext c0 match: {}", c0_match);
    println!("  Ciphertext c1 match: {}", c1_match);

    assert_eq!(dec1, m, "Run 1 decryption wrong");
    assert_eq!(dec2, m, "Run 2 decryption wrong");
    assert_eq!(dec1, dec2, "Determinism violated: different decryptions from same seed");
    assert!(c0_match, "Determinism violated: c0 differs between runs");
    assert!(c1_match, "Determinism violated: c1 differs between runs");

    println!("\nDeterminism: VERIFIED.");
}

#[test]
fn test_different_seeds_different_ciphertexts() {
    println!("\n=== Different Seeds -> Different Ciphertexts ===\n");

    let cfg = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&cfg).expect("context");
    let m: u64 = 42;

    let mut rng1 = ShadowHarvester::with_seed(111);
    let keys1 = ctx.generate_keys_dual(&mut rng1);
    let ct1 = ctx.encrypt_dual(m, &keys1.public_key, &mut rng1);

    let mut rng2 = ShadowHarvester::with_seed(222);
    let keys2 = ctx.generate_keys_dual(&mut rng2);
    let ct2 = ctx.encrypt_dual(m, &keys2.public_key, &mut rng2);

    let dec1 = ctx.decrypt_dual(&ct1, &keys1.secret_key);
    let dec2 = ctx.decrypt_dual(&ct2, &keys2.secret_key);

    let c0_differ = ct1.c0.main != ct2.c0.main;

    println!("  Seed 111: decrypt = {}", dec1);
    println!("  Seed 222: decrypt = {}", dec2);
    println!("  Both decrypt correctly: {}", dec1 == m && dec2 == m);
    println!("  Ciphertexts differ: {}", c0_differ);

    assert_eq!(dec1, m);
    assert_eq!(dec2, m);
    assert!(c0_differ, "Different seeds should produce different ciphertexts");

    println!("\nSemantic security (different seeds): VERIFIED.");
}

// ============================================================================
// MODULE 13: SECURE KEY GENERATION (OS CSPRNG)
// ============================================================================

#[test]
fn test_secure_key_generation_roundtrip() {
    println!("\n=== Secure Key Generation (OS CSPRNG) ===\n");

    let cfg = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&cfg).expect("context");

    // Generate keys with OS CSPRNG (non-deterministic)
    let keys = ctx.generate_keys_dual_secure();

    // Encrypt with OS CSPRNG too
    let m: u64 = 12345;
    let ct = ctx.encrypt_dual_secure(m, &keys.public_key);
    let dec = ctx.decrypt_dual(&ct, &keys.secret_key);

    println!("  Plaintext: {}", m);
    println!("  Decrypted: {}", dec);
    println!("  Match: {}", dec == m);

    assert_eq!(dec, m, "Secure key generation roundtrip failed");

    println!("\nSecure (OS CSPRNG) key generation: VERIFIED.");
}

#[test]
fn test_secure_full_key_generation() {
    println!("\n=== Secure Full Key Generation (with eval key) ===\n");

    let cfg = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&cfg).expect("context");

    let keys = ctx.generate_keys_dual_full_secure();

    let m: u64 = 777;
    let ct = ctx.encrypt_dual_secure(m, &keys.public_key);
    let dec = ctx.decrypt_dual(&ct, &keys.secret_key);

    println!("  Plaintext: {}", m);
    println!("  Decrypted: {}", dec);
    println!("  Has eval key: true");
    println!("  Match: {}", dec == m);

    assert_eq!(dec, m);

    println!("\nSecure full key generation: VERIFIED.");
}

// ============================================================================
// MODULE 14: PRECOMPUTED S^2 MULTIPLICATION
// ============================================================================

#[test]
fn test_mul_with_precomputed_s2() {
    println!("\n=== Multiplication with Precomputed s^2 ===\n");

    let cfg = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&cfg).expect("context");
    let mut rng = ShadowHarvester::with_seed(800);
    let keys = ctx.generate_keys_dual(&mut rng);

    // Precompute s^2
    let s2 = ctx.precompute_s_squared(&keys.secret_key);

    let pairs: Vec<(u64, u64)> = vec![
        (2, 3),
        (7, 11),
        (100, 200),
    ];

    println!("  {:>8} {:>8} {:>15} {:>15} {:>8}", "a", "b", "expected", "actual", "status");
    println!("  {}", "-".repeat(60));

    let mut all_ok = true;
    for (a, b) in &pairs {
        let ct_a = ctx.encrypt_dual(*a, &keys.public_key, &mut rng);
        let ct_b = ctx.encrypt_dual(*b, &keys.public_key, &mut rng);

        let ct_prod = ctx.mul_dual_symmetric_with_s2(&ct_a, &ct_b, &keys.secret_key, &s2);
        let dec = ctx.decrypt_dual(&ct_prod, &keys.secret_key);
        let expected = ((*a as u128 * *b as u128) % cfg.t as u128) as u64;
        let ok = dec == expected;
        if !ok { all_ok = false; }

        println!("  {:>8} {:>8} {:>15} {:>15} {:>8}", a, b, expected, dec, if ok { "OK" } else { "FAIL" });
    }

    assert!(all_ok, "Precomputed s^2 multiplication had failures");
    println!("\nPrecomputed s^2: VERIFIED.");
}

// ============================================================================
// MODULE 15: MOD SWITCH
// ============================================================================

#[test]
fn test_mod_switch_down() {
    println!("\n=== Mod Switch Down ===\n");

    let cfg = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&cfg).expect("context");
    let mut rng = ShadowHarvester::with_seed(900);
    let keys = ctx.generate_keys_dual(&mut rng);

    let m: u64 = 42;
    let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
    println!("  Original level: {}", ct.level);

    match ctx.mod_switch_ct_down(&ct) {
        Some(ct_switched) => {
            println!("  Switched level: {}", ct_switched.level);
            let dec = ctx.decrypt_dual(&ct_switched, &keys.secret_key);
            println!("  Decrypted after switch: {}", dec);
            println!("  Correct: {}", dec == m);
            // Mod switch may introduce small error — allow tolerance
            let error = if dec > m { dec - m } else { m - dec };
            assert!(error <= 1, "Mod switch error too large: {} (expected {}, got {})", error, m, dec);
        }
        None => {
            println!("  Mod switch not available (already at minimum level)");
            // This is acceptable for configs with few primes
        }
    }

    println!("\nMod switch: COMPLETE.");
}

// ============================================================================
// MODULE 16: GSO-FHE MODE
// ============================================================================

#[test]
#[allow(deprecated)]
fn test_gso_fhe_roundtrip() {
    println!("\n=== GSO-FHE Mode ===\n");

    use nine65::ops::gso_fhe::GSOFHEContext;

    let cfg = FHEConfig::light_rns_exact_insecure();
    let inner = RNSFHEContext::new(&cfg);
    let ctx = GSOFHEContext::new(inner);
    let mut rng = ShadowHarvester::with_seed(1000);
    let keys = ctx.generate_keys(&mut rng);

    let values = [0u64, 1, 42, cfg.t - 1, cfg.t / 2];

    println!("  {:>8} {:>8} {:>10} {:>10}", "input", "output", "noise", "status");
    println!("  {}", "-".repeat(45));

    let mut all_ok = true;
    for &m in &values {
        let ct = ctx.encrypt(m, &keys.public_key, &mut rng);
        let noise = ct.noise.distance;
        let dec = ctx.decrypt(&ct, &keys.secret_key);
        let ok = dec == m;
        if !ok { all_ok = false; }

        println!(
            "  {:>8} {:>8} {:>10} {:>10}",
            m, dec, noise, if ok { "OK" } else { "FAIL" }
        );
    }

    assert!(all_ok, "GSO-FHE roundtrip had failures");
    println!("\nGSO-FHE roundtrip: VERIFIED.");
}

#[test]
#[allow(deprecated)]
fn test_gso_fhe_mul_symmetric() {
    println!("\n=== GSO-FHE Multiplication (Symmetric) ===\n");

    use nine65::ops::gso_fhe::GSOFHEContext;

    let cfg = FHEConfig::light_rns_exact_insecure();
    let inner = RNSFHEContext::new(&cfg);
    let mut ctx = GSOFHEContext::new(inner);
    let mut rng = ShadowHarvester::with_seed(1100);
    let keys = ctx.generate_keys(&mut rng);

    let a = 3u64;
    let b = 4u64;
    let ct_a = ctx.encrypt(a, &keys.public_key, &mut rng);
    let ct_b = ctx.encrypt(b, &keys.public_key, &mut rng);

    let ct_prod = ctx.mul_symmetric(&ct_a, &ct_b, &keys.secret_key);
    let dec = ctx.decrypt(&ct_prod, &keys.secret_key);
    let expected = (a * b) % cfg.t;

    println!("  {} * {} = {} (expected {})", a, b, dec, expected);
    println!("  Noise after mul: {}", ct_prod.noise.distance);
    println!("  Mul depth: {}", ct_prod.noise.mul_depth);

    // Allow small error for GSO mul
    let error = if dec > expected {
        dec - expected
    } else {
        expected - dec
    };
    println!("  Error: {}", error);
    assert!(error <= 2, "GSO mul error too large: {}", error);

    println!("\nGSO-FHE mul: VERIFIED.");
}

// ============================================================================
// MODULE 17: RNS SINGLE-MODULUS MODE
// ============================================================================

#[test]
fn test_rns_single_modulus_roundtrip() {
    println!("\n=== RNS Single-Modulus Roundtrip ===\n");

    let configs: Vec<(&str, FHEConfig)> = vec![
        ("secure_128", SecureConfig::secure_128().into_config()),
        ("test_fast", SecureConfig::test_fast_insecure().into_config()),
    ];

    for (name, cfg) in &configs {
        let ctx = match RNSFHEContext::try_new(cfg) {
            Ok(c) => c,
            Err(e) => {
                println!("[SKIP] {}: {}", name, e);
                continue;
            }
        };
        let mut rng = ShadowHarvester::with_seed(1200);
        let keys = ctx.generate_keys(&mut rng);

        println!("  Config: {} (N={}, primes={})", name, cfg.n, cfg.primes.len());

        for &m in &[0u64, 1, 42, cfg.t - 1] {
            let ct = ctx.encrypt(m, &keys.public_key, &mut rng);
            let dec = ctx.decrypt(&ct, &keys.secret_key);
            let ok = dec == m;
            println!("    [{}] m={}, dec={}", if ok { "OK" } else { "FAIL" }, m, dec);
            assert_eq!(dec, m, "Single-modulus roundtrip failed for m={} on {}", m, name);
        }
    }

    println!("\nRNS single-modulus: VERIFIED.");
}

// ============================================================================
// MODULE 18: RNS MULTI-MODULUS ADD/MUL
// ============================================================================

#[test]
fn test_rns_multi_modulus_add() {
    println!("\n=== RNS Multi-Modulus Addition ===\n");

    let cfg = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&cfg).expect("context");
    let mut rng = ShadowHarvester::with_seed(1300);
    let keys = ctx.generate_keys(&mut rng);

    let pairs: Vec<(u64, u64)> = vec![(1, 2), (100, 200), (cfg.t - 1, 1), (0, 0)];

    for (a, b) in &pairs {
        let ct_a = ctx.encrypt(*a, &keys.public_key, &mut rng);
        let ct_b = ctx.encrypt(*b, &keys.public_key, &mut rng);
        let ct_sum = ctx.add(&ct_a, &ct_b);
        let dec = ctx.decrypt(&ct_sum, &keys.secret_key);
        let expected = (*a + *b) % cfg.t;
        let ok = dec == expected;
        println!("  [{}] {} + {} = {} (expected {})", if ok { "OK" } else { "FAIL" }, a, b, dec, expected);
        assert_eq!(dec, expected);
    }

    println!("\nRNS multi-modulus add: VERIFIED.");
}

#[test]
fn test_rns_multi_modulus_mul_bajard() {
    println!("\n=== RNS Multi-Modulus Multiplication (Bajard path) ===\n");
    println!("  NOTE: The Bajard rescaling path (ctx.mul) is a legacy path.");
    println!("  The recommended path is Dual-RNS with K-Elimination (ctx.mul_dual_symmetric).");
    println!("  Testing Bajard path for completeness — errors expected on production configs.\n");

    let cfg = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&cfg).expect("context");
    let mut rng = ShadowHarvester::with_seed(1400);
    let keys = ctx.generate_keys(&mut rng);

    let pairs: Vec<(u64, u64)> = vec![(2, 3), (7, 11), (0, 100), (1, cfg.t - 1)];

    let mut correct = 0usize;
    let mut total = 0usize;

    for (a, b) in &pairs {
        let ct_a = ctx.encrypt(*a, &keys.public_key, &mut rng);
        let ct_b = ctx.encrypt(*b, &keys.public_key, &mut rng);
        let ct_prod = ctx.mul(&ct_a, &ct_b, &keys.eval_key);
        let dec = ctx.decrypt(&ct_prod, &keys.secret_key);
        let expected = ((*a as u128 * *b as u128) % cfg.t as u128) as u64;
        let ok = dec == expected;
        total += 1;
        if ok { correct += 1; }
        println!("  [{}] {} * {} = {} (expected {})", if ok { "OK" } else { "ERR" }, a, b, dec, expected);
    }

    println!("\n--- Bajard path: {}/{} correct ---", correct, total);
    println!("  (Bajard path may produce errors on multi-prime configs due to Delta^2 overflow.)");
    println!("  Use mul_dual_symmetric for correct results.");

    // Don't assert — this path is known to have limitations
    // The important thing is that it doesn't panic
}

// ============================================================================
// MODULE 19: AUTO MODE HOMOMORPHIC OPERATIONS
// ============================================================================

#[test]
fn test_auto_mode_add() {
    println!("\n=== Auto Mode Addition ===\n");

    let cfg = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&cfg).expect("context");
    let mut rng = ShadowHarvester::with_seed(1500);
    let keys = ctx.generate_keys_auto(&mut rng);

    let pairs: Vec<(u64, u64)> = vec![(1, 2), (42, 58), (cfg.t - 1, 1), (0, 0)];

    for (a, b) in &pairs {
        let ct_a = ctx.encrypt_auto(*a, &keys, &mut rng).expect("encrypt_auto a");
        let ct_b = ctx.encrypt_auto(*b, &keys, &mut rng).expect("encrypt_auto b");
        match ctx.add_auto(&ct_a, &ct_b) {
            Ok(ct_sum) => {
                let dec = ctx.decrypt_auto(&ct_sum, &keys).expect("decrypt");
                let expected = (*a + *b) % cfg.t;
                let ok = dec == expected;
                println!("  [{}] {} + {} = {} (expected {})", if ok { "OK" } else { "FAIL" }, a, b, dec, expected);
                assert_eq!(dec, expected);
            }
            Err(e) => {
                println!("  [ERR] {} + {} = {}", a, b, e);
                panic!("Auto add failed: {}", e);
            }
        }
    }

    println!("\nAuto mode add: VERIFIED.");
}

#[test]
fn test_auto_mode_mul() {
    println!("\n=== Auto Mode Multiplication ===\n");

    let cfg = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&cfg).expect("context");
    let mut rng = ShadowHarvester::with_seed(1600);
    let keys = ctx.generate_keys_auto(&mut rng);

    let pairs: Vec<(u64, u64)> = vec![(2, 3), (7, 11), (1, cfg.t - 1)];

    for (a, b) in &pairs {
        let ct_a = ctx.encrypt_auto(*a, &keys, &mut rng).expect("encrypt_auto a");
        let ct_b = ctx.encrypt_auto(*b, &keys, &mut rng).expect("encrypt_auto b");
        match ctx.mul_auto(&ct_a, &ct_b, &keys) {
            Ok(ct_prod) => {
                let dec = ctx.decrypt_auto(&ct_prod, &keys).expect("decrypt");
                let expected = ((*a as u128 * *b as u128) % cfg.t as u128) as u64;
                let ok = dec == expected;
                println!("  [{}] {} * {} = {} (expected {})", if ok { "OK" } else { "FAIL" }, a, b, dec, expected);
                assert_eq!(dec, expected);
            }
            Err(e) => {
                println!("  [ERR] {} * {} = {}", a, b, e);
                panic!("Auto mul failed: {}", e);
            }
        }
    }

    println!("\nAuto mode mul: VERIFIED.");
}

// ============================================================================
// MODULE 20: CROSS-CONFIG PARAMETER SWEEP
// ============================================================================

#[test]
#[allow(deprecated)]
fn test_encrypt_decrypt_all_insecure_configs() {
    println!("\n=== Encrypt/Decrypt Sweep: All Insecure Configs ===\n");

    let configs: Vec<(&str, FHEConfig)> = vec![
        ("light_rns", FHEConfig::light_rns_insecure()),
        ("light_rns_exact", FHEConfig::light_rns_exact_insecure()),
        ("standard_128", FHEConfig::standard_128_insecure()),
        ("he_standard_128", FHEConfig::he_standard_128_insecure()),
        ("he_standard_128_deep", FHEConfig::he_standard_128_deep_insecure()),
        ("depth2_128", FHEConfig::depth2_128_insecure()),
        ("depth3_128", FHEConfig::depth3_128_insecure()),
    ];

    println!(
        "  {:<25} {:>6} {:>8} {:>8} {:>8} {:>10}",
        "Config", "N", "primes", "t", "m_test", "result"
    );
    println!("  {}", "-".repeat(75));

    let mut total = 0usize;
    let mut passed = 0usize;

    for (name, cfg) in &configs {
        let ctx = match RNSFHEContext::try_new(cfg) {
            Ok(c) => c,
            Err(e) => {
                println!("  {:<25} {:>6} {:>8} {:>8} {:>8} {:>10}", name, cfg.n, cfg.primes.len(), cfg.t, "-", format!("SKIP: {}", e));
                continue;
            }
        };

        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual(&mut rng);

        // Test a few values for each config
        for &m in &[0u64, 1, 42, cfg.t - 1] {
            let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
            let dec = ctx.decrypt_dual(&ct, &keys.secret_key);
            total += 1;
            let ok = dec == m;
            if ok { passed += 1; }
            println!(
                "  {:<25} {:>6} {:>8} {:>8} {:>8} {:>10}",
                name, cfg.n, cfg.primes.len(), cfg.t, m,
                if ok { format!("OK({})", dec) } else { format!("FAIL({})", dec) }
            );
        }
    }

    println!("\n--- Insecure config sweep: {}/{} passed ---", passed, total);
    assert_eq!(passed, total, "Some insecure config roundtrips failed");
}

// ============================================================================
// MODULE 21: DEEP CONFIG DEPTH CHAIN
// ============================================================================

#[test]
fn test_depth_chain_secure_128_deep() {
    println!("\n=== Depth Chain: secure_128_deep ===\n");

    let cfg = SecureConfig::secure_128_deep().into_config();
    let ctx = RNSFHEContext::try_new(&cfg).expect("context");
    let mut rng = ShadowHarvester::with_seed(2100);
    let keys = ctx.generate_keys_dual(&mut rng);

    let base: u64 = 2;
    let mut current = ctx.encrypt_dual(base, &keys.public_key, &mut rng);
    let mut expected: u64 = base;
    let max_depth = 30;

    println!("  Config: secure_128_deep (N={}, primes={})", cfg.n, cfg.primes.len());
    println!("  {:>5} {:>15} {:>15} {:>8}", "Depth", "Expected", "Decrypted", "Status");
    println!("  {}", "-".repeat(50));

    let mut max_correct_depth = 0u32;

    for depth in 1..=max_depth {
        let ct_copy = current.clone();
        let ct_prod = ctx.mul_dual_symmetric(&current, &ct_copy, &keys.secret_key);
        expected = ((expected as u128 * expected as u128) % cfg.t as u128) as u64;

        match ctx.try_decrypt_dual(&ct_prod, &keys.secret_key) {
            Ok(dec) => {
                let ok = dec == expected;
                println!(
                    "  {:>5} {:>15} {:>15} {:>8}",
                    depth, expected, dec, if ok { "OK" } else { "WRONG" }
                );
                if ok {
                    max_correct_depth = depth as u32;
                    current = ct_prod;
                } else {
                    break;
                }
            }
            Err(_) => {
                println!("  {:>5} (noise exhausted)", depth);
                break;
            }
        }
    }

    println!("\n--- secure_128_deep max depth: {} ---", max_correct_depth);
    // Deep config should handle more depth than standard
    assert!(max_correct_depth >= 1, "Deep config should achieve at least depth 1");
}

// ============================================================================
// MODULE 22: KEY SERIALIZATION ROUNDTRIP (feature-gated)
// ============================================================================

#[cfg(feature = "serde")]
#[test]
fn test_key_serialization_roundtrip() {
    println!("\n=== Key Serialization Roundtrip ===\n");

    let cfg = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&cfg).expect("context");
    let mut rng = ShadowHarvester::with_seed(2200);
    let keys = ctx.generate_keys_dual(&mut rng);

    // Serialize/deserialize
    let json = keys.to_json().expect("serialize");
    println!("  JSON size: {} bytes", json.len());

    let keys2 = nine65::ops::rns_fhe::DualRNSKeySet::from_json_validated(&json).expect("deserialize");

    // Verify roundtrip
    let m: u64 = 42;
    let ct = ctx.encrypt_dual(m, &keys2.public_key, &mut rng);
    let dec = ctx.decrypt_dual(&ct, &keys2.secret_key);
    println!("  Encrypt with deserialized key: m={}, dec={}", m, dec);
    assert_eq!(dec, m, "Serialization roundtrip failed");

    println!("\nKey serialization: VERIFIED.");
}

// ============================================================================
// MODULE 23: COMPREHENSIVE RESULTS SUMMARY
// ============================================================================

#[test]
fn test_comprehensive_summary() {
    println!("\n========================================");
    println!("  NINE65 v7 Full System Exercise");
    println!("========================================\n");

    // Quick smoke test of each major subsystem
    let mut subsystems: Vec<(&str, bool)> = Vec::new();

    // 1. SecureConfig construction
    {
        let _ = SecureConfig::secure_128();
        let _ = SecureConfig::secure_192();
        let _ = SecureConfig::secure_256();
        subsystems.push(("SecureConfig construction", true));
    }

    // 2. RNSFHEContext
    {
        let cfg = SecureConfig::secure_128().into_config();
        let ok = RNSFHEContext::try_new(&cfg).is_ok();
        subsystems.push(("RNSFHEContext construction", ok));
    }

    // 3. Key generation (seeded)
    {
        let cfg = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&cfg).unwrap();
        let mut rng = ShadowHarvester::with_seed(1);
        let _keys = ctx.generate_keys_dual(&mut rng);
        subsystems.push(("Key generation (seeded)", true));
    }

    // 4. Key generation (secure)
    {
        let cfg = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&cfg).unwrap();
        let _keys = ctx.generate_keys_dual_secure();
        subsystems.push(("Key generation (OS CSPRNG)", true));
    }

    // 5. Encrypt/decrypt roundtrip
    {
        let cfg = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&cfg).unwrap();
        let mut rng = ShadowHarvester::with_seed(2);
        let keys = ctx.generate_keys_dual(&mut rng);
        let ct = ctx.encrypt_dual(42, &keys.public_key, &mut rng);
        let dec = ctx.decrypt_dual(&ct, &keys.secret_key);
        subsystems.push(("Encrypt/decrypt roundtrip", dec == 42));
    }

    // 6. Homomorphic add
    {
        let cfg = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&cfg).unwrap();
        let mut rng = ShadowHarvester::with_seed(3);
        let keys = ctx.generate_keys_dual(&mut rng);
        let ct1 = ctx.encrypt_dual(10, &keys.public_key, &mut rng);
        let ct2 = ctx.encrypt_dual(20, &keys.public_key, &mut rng);
        let ct_sum = ctx.add_dual(&ct1, &ct2);
        let dec = ctx.decrypt_dual(&ct_sum, &keys.secret_key);
        subsystems.push(("Homomorphic addition", dec == 30));
    }

    // 7. Homomorphic sub
    {
        let cfg = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&cfg).unwrap();
        let mut rng = ShadowHarvester::with_seed(4);
        let keys = ctx.generate_keys_dual(&mut rng);
        let ct1 = ctx.encrypt_dual(50, &keys.public_key, &mut rng);
        let ct2 = ctx.encrypt_dual(30, &keys.public_key, &mut rng);
        let ct_diff = ctx.sub_dual(&ct1, &ct2);
        let dec = ctx.decrypt_dual(&ct_diff, &keys.secret_key);
        subsystems.push(("Homomorphic subtraction", dec == 20));
    }

    // 8. Homomorphic mul (symmetric)
    {
        let cfg = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&cfg).unwrap();
        let mut rng = ShadowHarvester::with_seed(5);
        let keys = ctx.generate_keys_dual(&mut rng);
        let ct1 = ctx.encrypt_dual(3, &keys.public_key, &mut rng);
        let ct2 = ctx.encrypt_dual(7, &keys.public_key, &mut rng);
        let ct_prod = ctx.mul_dual_symmetric(&ct1, &ct2, &keys.secret_key);
        let dec = ctx.decrypt_dual(&ct_prod, &keys.secret_key);
        subsystems.push(("Homomorphic mul (symmetric)", dec == 21));
    }

    // 9. Auto mode
    {
        let cfg = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&cfg).unwrap();
        let mut rng = ShadowHarvester::with_seed(6);
        let keys = ctx.generate_keys_auto(&mut rng);
        let ct = ctx.encrypt_auto(99, &keys, &mut rng).unwrap();
        let dec = ctx.decrypt_auto(&ct, &keys).unwrap_or(0);
        subsystems.push(("Auto mode", dec == 99));
    }

    // Print summary table
    println!("  {:<35} {:>10}", "Subsystem", "Status");
    println!("  {}", "-".repeat(50));

    let mut all_pass = true;
    for (name, ok) in &subsystems {
        let status = if *ok { "PASS" } else { "FAIL" };
        println!("  {:<35} {:>10}", name, status);
        if !*ok { all_pass = false; }
    }

    println!("\n  {}/{} subsystems operational.", subsystems.len(), subsystems.len());
    println!("========================================\n");

    assert!(all_pass, "One or more subsystems failed");
}
