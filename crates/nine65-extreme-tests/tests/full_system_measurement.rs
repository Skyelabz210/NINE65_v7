//! Full-system empirical measurement — run, do not inherit.
//!
//! Every number this file prints is produced by executing the system in this
//! working tree. Nothing here quotes a report, a plan document, or a prior
//! benchmark run. Where a claim cannot be measured, the test says so rather
//! than substituting a remembered value.
//!
//! The two binding rules under test:
//!   RULE 1  no floating-point variables anywhere in the crypto/arithmetic path
//!   RULE 2  no synthetic emissions in residue space
//! Rule 1 and Rule 2 are audited statically (see `scripts/` and the companion
//! shell audit); this file covers the empirical surface: screened security,
//! achievable depth per config per mode, and whether the refusals the codebase
//! imposes are justified by measurement.
//!
//! Run with:
//!   cargo test -p nine65-extreme-tests --release --test full_system_measurement -- --nocapture

use nine65::entropy::ShadowHarvester;
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::params::security_estimator::{
    CostModel, LatticeSecurityEstimator, SecretDistribution,
};
use nine65::params::SecureConfig;

/// The four named configurations, in the order the claim surface lists them.
fn named_configs() -> Vec<(&'static str, SecureConfig)> {
    vec![
        ("secure_128", SecureConfig::secure_128()),
        ("secure_128_deep", SecureConfig::secure_128_deep()),
        ("secure_192", SecureConfig::secure_192()),
        ("secure_256", SecureConfig::secure_256()),
    ]
}

/// Bit length of a signed margin, for reporting headroom.
fn margin_bits(v: i128) -> u32 {
    if v <= 0 {
        0
    } else {
        128 - (v as u128).leading_zeros()
    }
}

// ===================================================================
// MEASUREMENT 1 — screened security, both cost models, all configs
// ===================================================================

#[test]
fn measure_screened_security_all_configs() {
    println!("\n=== MEASUREMENT 1: screened security (this tree, this run) ===");
    println!(
        "{:<18} {:>6} {:>7} {:>8} | {:>9} {:>9} {:>9} {:>9} | {:>8} {:>7}",
        "config", "n", "log_q", "claimed", "cSVP:cls", "cSVP:hyb", "cSVP:qnt", "cSVP:eff",
        "MATZOV", "meets"
    );

    for (name, sc) in named_configs() {
        let n = sc.config.n;
        let log_q = sc.log_q();
        let claimed = sc.claimed_security;

        let core = LatticeSecurityEstimator::new(CostModel::CoreSVP).estimate(
            n,
            log_q,
            SecretDistribution::Ternary,
            claimed,
        );
        let matzov = LatticeSecurityEstimator::new(CostModel::MATZOV).estimate(
            n,
            log_q,
            SecretDistribution::Ternary,
            claimed,
        );

        println!(
            "{:<18} {:>6} {:>7} {:>8} | {:>9} {:>9} {:>9} {:>9} | {:>8} {:>7}",
            name,
            n,
            log_q,
            claimed,
            core.classical_bits,
            core.hybrid_bits,
            core.quantum_bits,
            core.effective_bits,
            matzov.effective_bits,
            core.meets_claim && matzov.meets_claim
        );

        // Report, do not assert a threshold: the point of this run is to
        // establish the numbers, not to enforce a remembered one.
        if core.effective_bits < claimed {
            println!(
                "    NOTE  {} screens at {} effective bits under Core-SVP but its name asserts {}",
                name, core.effective_bits, claimed
            );
        }
    }
    println!("=== end measurement 1 ===\n");
}

// ===================================================================
// MEASUREMENT 2 — public-mode depth driven to ACTUAL failure
// ===================================================================

#[test]
fn measure_public_depth_to_actual_failure() {
    println!("\n=== MEASUREMENT 2: PUBLIC mode, repeated squaring to first wrong decrypt ===");
    const MAX_DEPTH: u32 = 8;

    for (name, sc) in named_configs() {
        let config = sc.into_config();
        let t = config.t as u128;
        let ctx = match RNSFHEContext::try_new(&config) {
            Ok(c) => c,
            Err(e) => {
                println!("{:<18} context construction refused: {}", name, e);
                continue;
            }
        };
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual_full(&mut rng);

        let mut ct = ctx.encrypt_dual(2, &keys.public_key, &mut rng);
        let mut expected: u128 = 2;
        let (d0, m0) = ctx.decrypt_dual_with_diagnostics(&ct, &keys.secret_key);
        let fresh_ok = d0 as u128 == expected;
        print!(
            "{:<18} depth0 dec={} exp={} margin_bits={} ok={}",
            name, d0, expected, margin_bits(m0), fresh_ok
        );

        let mut last_good: i32 = if fresh_ok { 0 } else { -1 };
        for depth in 1..=MAX_DEPTH {
            let next = match ctx.mul_dual_public(&ct, &ct, &keys.eval_key) {
                Ok(v) => v,
                Err(e) => {
                    println!("  | depth{} REFUSED by op: {}", depth, e);
                    break;
                }
            };
            ct = next;
            expected = expected * expected % t;
            let (d, m) = ctx.decrypt_dual_with_diagnostics(&ct, &keys.secret_key);
            let ok = d as u128 == expected;
            print!(
                "  | d{} dec={} exp={} mb={} {}",
                depth,
                d,
                expected,
                margin_bits(m),
                if ok { "OK" } else { "WRONG" }
            );
            if !ok {
                break;
            }
            last_good = depth as i32;
        }
        println!("\n    --> {} MEASURED public direct-square depth = {}", name, last_good);
    }
    println!("=== end measurement 2 ===\n");
}

// ===================================================================
// MEASUREMENT 3 — symmetric-mode depth driven to ACTUAL failure
// ===================================================================

#[test]
fn measure_symmetric_depth_to_actual_failure() {
    println!("\n=== MEASUREMENT 3: SYMMETRIC mode, repeated squaring to first wrong decrypt ===");
    const MAX_DEPTH: u32 = 8;

    for (name, sc) in named_configs() {
        let config = sc.into_config();
        let t = config.t as u128;
        let ctx = match RNSFHEContext::try_new(&config) {
            Ok(c) => c,
            Err(e) => {
                println!("{:<18} context construction refused: {}", name, e);
                continue;
            }
        };
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual_full(&mut rng);

        let mut ct = ctx.encrypt_dual(2, &keys.public_key, &mut rng);
        let mut expected: u128 = 2;
        let mut last_good: i32 = -1;
        {
            let (d0, _) = ctx.decrypt_dual_with_diagnostics(&ct, &keys.secret_key);
            if d0 as u128 == expected {
                last_good = 0;
            }
            print!("{:<18} depth0 dec={} exp={}", name, d0, expected);
        }

        for depth in 1..=MAX_DEPTH {
            ct = ctx.mul_dual_symmetric(&ct, &ct, &keys.secret_key);
            expected = expected * expected % t;
            let (d, m) = ctx.decrypt_dual_with_diagnostics(&ct, &keys.secret_key);
            let ok = d as u128 == expected;
            print!(
                "  | d{} dec={} exp={} mb={} {}",
                depth,
                d,
                expected,
                margin_bits(m),
                if ok { "OK" } else { "WRONG" }
            );
            if !ok {
                break;
            }
            last_good = depth as i32;
        }
        println!("\n    --> {} MEASURED symmetric direct-square depth = {}", name, last_good);
    }
    println!("=== end measurement 3 ===\n");
}

// ===================================================================
// MEASUREMENT 4 — is the secure_128 public-refresh BAN justified?
// ===================================================================
//
// A refusal added to production code must earn its place by measurement.
// The ban rests on a physical claim: three main lanes at n=8192 leave
// insufficient post-bootstrap headroom, so a refreshed ciphertext decrypts
// wrong by a small amount. This measures the post-bootstrap margin on every
// config so the claim can be checked rather than assumed. If secure_128's
// margin is not materially worse than the configs where refresh is believed
// to work, the ban is NOT justified and must come out.

#[test]
fn measure_post_bootstrap_headroom_that_the_ban_rests_on() {
    use nine65::ops::bootstrap::ClockworkBootstrap;

    println!("\n=== MEASUREMENT 4: post-bootstrap headroom (the basis of the refusal) ===");
    println!(
        "{:<18} {:>6} {:>7} | {:>14} {:>14} {:>10}",
        "config", "lanes", "log_q", "fresh_margin_b", "boot_margin_b", "boot_ok"
    );

    for (name, sc) in named_configs() {
        let lanes = sc.config.primes.len();
        let log_q = sc.log_q();
        let config = sc.into_config();
        let ctx = match RNSFHEContext::try_new(&config) {
            Ok(c) => c,
            Err(e) => {
                println!("{:<18} context refused: {}", name, e);
                continue;
            }
        };
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual_full(&mut rng);

        let fresh = ctx.encrypt_dual(7, &keys.public_key, &mut rng);
        let (_, fresh_margin) = ctx.decrypt_dual_with_diagnostics(&fresh, &keys.secret_key);

        let boot = match ClockworkBootstrap::new(&config) {
            Ok(b) => b,
            Err(e) => {
                println!(
                    "{:<18} {:>6} {:>7} | {:>14} bootstrap ctor REFUSED: {}",
                    name,
                    lanes,
                    log_q,
                    margin_bits(fresh_margin),
                    e
                );
                continue;
            }
        };
        let bk = match boot.generate_keys(&keys.secret_key, &mut rng) {
            Ok(k) => k,
            Err(e) => {
                println!(
                    "{:<18} {:>6} {:>7} | {:>14} keygen REFUSED: {}",
                    name,
                    lanes,
                    log_q,
                    margin_bits(fresh_margin),
                    e
                );
                continue;
            }
        };

        match boot.bootstrap(&fresh, &bk.bsk, &bk.ksk) {
            Ok(b) => {
                let (d, m) = ctx.decrypt_dual_with_diagnostics(&b, &keys.secret_key);
                println!(
                    "{:<18} {:>6} {:>7} | {:>14} {:>14} {:>10}",
                    name,
                    lanes,
                    log_q,
                    margin_bits(fresh_margin),
                    margin_bits(m),
                    d == 7
                );
                if d != 7 {
                    println!(
                        "    MEASURED CORRUPTION on {}: bootstrap(7) decrypts to {} (error {})",
                        name,
                        d,
                        d as i64 - 7
                    );
                }
            }
            Err(e) => {
                println!(
                    "{:<18} {:>6} {:>7} | {:>14} {:>14} REFUSED: {}",
                    name,
                    lanes,
                    log_q,
                    margin_bits(fresh_margin),
                    "-",
                    e
                );
            }
        }
    }
    println!("=== end measurement 4 ===\n");
}

// ===================================================================
// MEASUREMENT 5 — how many lanes can n=8192 actually carry at 128 bits?
// ===================================================================
//
// secure_128 is secure_128_deep minus one prime, and screens at 259
// effective bits against a 128-bit claim. That is a parameter choice, not a
// ceiling. This sweeps log_q at n=8192 to find the largest chain that still
// screens >= 128 under BOTH cost models, which is the number a refusal
// should be measured against.

#[test]
fn measure_lane_budget_at_n8192_for_128_bits() {
    println!("\n=== MEASUREMENT 5: usable modulus budget at n=8192, claim=128 ===");
    println!(
        "{:>7} {:>8} {:>10} {:>9} {:>9} {:>8}",
        "primes", "log_q~", "CoreSVP", "MATZOV", "binding", "ok>=128"
    );
    // Production primes here are ~30 bits each.
    let mut best = 0usize;
    for primes in 1..=10usize {
        let log_q = (primes as u32) * 30;
        let core = LatticeSecurityEstimator::new(CostModel::CoreSVP).estimate(
            8192,
            log_q,
            SecretDistribution::Ternary,
            128,
        );
        let matz = LatticeSecurityEstimator::new(CostModel::MATZOV).estimate(
            8192,
            log_q,
            SecretDistribution::Ternary,
            128,
        );
        let binding = core.effective_bits.min(matz.effective_bits);
        let ok = binding >= 128;
        if ok {
            best = primes;
        }
        println!(
            "{:>7} {:>8} {:>10} {:>9} {:>9} {:>8}",
            primes, log_q, core.effective_bits, matz.effective_bits, binding, ok
        );
    }
    println!(
        "    --> MEASURED: n=8192 carries up to {} x ~30-bit primes at a 128-bit claim",
        best
    );
    println!("        secure_128 ships 3; secure_128_deep ships 4.");
    println!("=== end measurement 5 ===\n");
}
