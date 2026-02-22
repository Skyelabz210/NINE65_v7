//! Bootstrap Parameter Exploration Harness
//!
//! Empirical investigation of Clockwork Bootstrap correctness across parameter space.
//!
//! ## Background
//!
//! Finding F-1: Bootstrap roundtrip at `secure_128` does not recover non-zero
//! plaintexts. m=0 recovers exactly; m=1 decrypts to 45,590 after bootstrap.
//!
//! ## Hypotheses Under Test
//!
//! H1: Bootstrap noise exceeds decryption threshold at compact parameters.
//!     Test: vary Q_boot (num boot primes) while holding N, t, eta constant.
//!
//! H2: Modswitch rounding error accumulates through polynomial multiplication.
//!     Test: vary N (polynomial degree) — smaller N = fewer rounding error terms.
//!
//! H3: Plaintext modulus t is too large relative to bootstrap noise floor.
//!     Test: vary t — smaller t means larger Δ_boot = Q_boot/t, more noise room.
//!
//! H4: Noise parameter eta dominates bootstrap noise.
//!     Test: vary eta from 1..5 while holding other params constant.
//!
//! H5: The phase computation (c0_small + c1_small * s) mod t introduces
//!     distributed rounding error from modswitch-before-multiply.
//!     Test: compare decrypt(bootstrap(encrypt(m))) vs direct decrypt, measuring
//!     the error magnitude to distinguish noise from algorithmic issues.
//!
//! H6: NINE65's modswitch omits the Δ⁻¹ correction found in QMNF_System.
//!     QMNF's `rescale_bfv_delta_rns()` applies 3 extra steps after rounding:
//!       sr = round(a * t / Q)           ← both systems do this
//!       m_hat = sr * Δ⁻¹ (mod t)       ← QMNF does this, NINE65 skips
//!       v = m_hat * Δ (mod Q_i)         ← QMNF does this, NINE65 skips
//!     The Δ⁻¹ correction extracts the raw message from the Δ-scaled value.
//!     Without it, the modswitch output still has Δ encoding baked in, which
//!     interacts incorrectly with the polynomial multiply in Phase 2.
//!     Test: simulate bootstrap with and without Δ⁻¹ correction, compare results.
//!
//! ## Architecture Note
//!
//! GSO-FHE (Innovation #6) handles depth-50+ without bootstrapping via
//! K-Elimination exact rescaling. The Clockwork Bootstrap is the safety net
//! for budget exhaustion. Correctness here means the safety net actually works.

use nine65::entropy::ShadowHarvester;
use nine65::errors::Nine65Result;
use nine65::keys::bootstrap::mod_inverse_u128;
use nine65::ops::bootstrap::{crt_reconstruct_2, ClockworkBootstrap};
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::params::FHEConfig;

// =========================================================================
// TEST INFRASTRUCTURE
// =========================================================================

/// Result of a single bootstrap correctness trial.
#[derive(Debug, Clone)]
struct BootstrapTrial {
    message: u64,
    decrypted_fresh: u64,
    decrypted_after_bootstrap: u64,
    fresh_correct: bool,
    bootstrap_correct: bool,
    error_magnitude: u64,
}

/// Aggregate results for a parameter configuration.
#[derive(Debug)]
struct ConfigResult {
    config_name: String,
    n: usize,
    num_work_primes: usize,
    num_boot_primes: usize,
    t: u64,
    eta: usize,
    log_q_work: u32,
    log_q_boot: u32,
    delta_boot_bits: u32,
    trials: Vec<BootstrapTrial>,
    fresh_success_rate: f64,    // for reporting only — not used in computation
    bootstrap_success_rate: f64, // for reporting only
    mean_error: f64,             // for reporting only
    max_error: u64,
}

/// Standard test messages spanning the plaintext space.
fn test_messages(t: u64) -> Vec<u64> {
    let mut msgs = vec![0, 1, 2, 42, 100, 1000];
    if t > 256 {
        msgs.push(t / 4);
        msgs.push(t / 2);
        msgs.push(t - 1);
    }
    if t > 65536 {
        msgs.push(65536);
    }
    msgs.retain(|&m| m < t);
    msgs
}

/// Run bootstrap correctness trials for a given config.
fn run_trials(
    config: &FHEConfig,
    seed: u64,
) -> Nine65Result<ConfigResult> {
    let ctx = RNSFHEContext::try_new(config)?;
    let boot = ClockworkBootstrap::new(config)?;
    let mut rng = ShadowHarvester::with_seed(seed);
    let keys = ctx.generate_keys_dual_full(&mut rng);
    let boot_keys = boot.generate_keys(&keys.secret_key, &mut rng)?;

    let messages = test_messages(config.t);
    let mut trials = Vec::with_capacity(messages.len());

    for &m in &messages {
        let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
        let decrypted_fresh = ctx.decrypt_dual(&ct, &keys.secret_key);

        let ct_boot = boot.bootstrap(&ct, &boot_keys.bsk, &boot_keys.ksk)?;
        let decrypted_boot = ctx.decrypt_dual(&ct_boot, &keys.secret_key);

        let error = decrypted_boot.abs_diff(m);
        // Also check wraparound error (mod t)
        let wrap_error = if decrypted_boot > m {
            config.t - decrypted_boot + m
        } else {
            config.t - m + decrypted_boot
        };
        let min_error = error.min(wrap_error);

        trials.push(BootstrapTrial {
            message: m,
            decrypted_fresh,
            decrypted_after_bootstrap: decrypted_boot,
            fresh_correct: decrypted_fresh == m,
            bootstrap_correct: decrypted_boot == m,
            error_magnitude: min_error,
        });
    }

    let total = trials.len() as f64;
    let fresh_ok = trials.iter().filter(|t| t.fresh_correct).count() as f64;
    let boot_ok = trials.iter().filter(|t| t.bootstrap_correct).count() as f64;
    let mean_err = trials.iter().map(|t| t.error_magnitude as f64).sum::<f64>() / total;
    let max_err = trials.iter().map(|t| t.error_magnitude).max().unwrap_or(0);

    let log_q_work: u32 = config.primes.iter().map(|&p| 64 - p.leading_zeros()).sum();
    let boot_primes = &boot.boot_config.primes;
    let log_q_boot: u32 = boot_primes.iter().map(|&p| 64 - p.leading_zeros()).sum();

    // Δ_boot = Q_boot / t (approximate via log2)
    let q_boot_product: u128 = boot_primes.iter().fold(1u128, |acc, &p| {
        acc.saturating_mul(p as u128)
    });
    let delta_boot = q_boot_product / config.t as u128;
    let delta_boot_bits = if delta_boot > 0 { 128 - delta_boot.leading_zeros() } else { 0 };

    Ok(ConfigResult {
        config_name: config.name.to_string(),
        n: config.n,
        num_work_primes: config.primes.len(),
        num_boot_primes: boot_primes.len(),
        t: config.t,
        eta: config.eta,
        log_q_work,
        log_q_boot,
        delta_boot_bits,
        trials,
        fresh_success_rate: fresh_ok / total,
        bootstrap_success_rate: boot_ok / total,
        mean_error: mean_err,
        max_error: max_err,
    })
}

/// Print a ConfigResult in tabular form.
fn print_result(r: &ConfigResult) {
    println!("\n{}", "=".repeat(70));
    println!("Config: {} | N={} | t={} | eta={}", r.config_name, r.n, r.t, r.eta);
    println!(
        "Work: {} primes (log Q = {} bits) | Boot: {} primes (log Q = {} bits)",
        r.num_work_primes, r.log_q_work, r.num_boot_primes, r.log_q_boot
    );
    println!("Δ_boot ≈ 2^{} bits", r.delta_boot_bits);
    println!("Fresh decrypt: {:.0}% correct", r.fresh_success_rate * 100.0);
    println!(
        "Bootstrap decrypt: {:.0}% correct | mean_error={:.1} | max_error={}",
        r.bootstrap_success_rate * 100.0,
        r.mean_error,
        r.max_error
    );
    println!("{:-<70}", "");
    println!(
        "{:<10} {:>12} {:>12} {:>8} {:>10}",
        "Message", "Fresh", "Bootstrap", "Match?", "Error"
    );
    for t in &r.trials {
        println!(
            "{:<10} {:>12} {:>12} {:>8} {:>10}",
            t.message,
            t.decrypted_fresh,
            t.decrypted_after_bootstrap,
            if t.bootstrap_correct { "YES" } else { "NO" },
            t.error_magnitude,
        );
    }
}

// =========================================================================
// H1: VARY BOOT PRIME COUNT (noise floor ∝ num_boot_primes)
// =========================================================================

/// Test bootstrap correctness with 2, 3, 4, 5, 6 boot primes.
/// More primes = larger Q_boot (more noise room) but also more noise sources.
#[test]
fn explore_h1_boot_prime_count() {
    println!("\n\n========== H1: BOOT PRIME COUNT ==========");
    println!("Hypothesis: fewer boot primes reduce noise but also reduce Q_boot.");
    println!("We test the net effect on correctness.\n");

    let base_config = FHEConfig {
        n: 4096,
        primes: vec![998244353, 985661441, 754974721],
        q: 998244353,
        t: 65537,
        eta: 3,
        security_bits: 128,
        name: "h1_base",
    };

    // ClockworkBootstrap::new computes boot_prime_count internally as
    // (bootstrap_depth + 2).min(BOOTSTRAP_PRIMES.len()) = 4.
    // To test different counts, we'd need to modify ClockworkBootstrap.
    // Instead, we observe the current behavior and vary what we can.
    match run_trials(&base_config, 42) {
        Ok(r) => {
            print_result(&r);
            println!(
                "\nH1 FINDING: With {} boot primes, bootstrap correctness = {:.0}%",
                r.num_boot_primes,
                r.bootstrap_success_rate * 100.0
            );
        }
        Err(e) => println!("H1 base config failed: {:?}", e),
    }
}

// =========================================================================
// H2: VARY POLYNOMIAL DEGREE N
// =========================================================================

/// Smaller N means fewer terms in polynomial product, less rounding error
/// accumulation from modswitch-before-multiply.
#[test]
fn explore_h2_polynomial_degree() {
    println!("\n\n========== H2: POLYNOMIAL DEGREE ==========");
    println!("Hypothesis: smaller N reduces accumulated rounding error in c1*s.\n");

    // N=1024 with 2 primes (minimum for bootstrap)
    let configs = [
        FHEConfig {
            n: 1024,
            primes: vec![998244353, 985661441],
            q: 998244353,
            t: 65537,
            eta: 2,
            security_bits: 40,
            name: "h2_n1024",
        },
        FHEConfig {
            n: 2048,
            primes: vec![998244353, 985661441],
            q: 998244353,
            t: 65537,
            eta: 2,
            security_bits: 80,
            name: "h2_n2048",
        },
        FHEConfig {
            n: 4096,
            primes: vec![998244353, 985661441, 754974721],
            q: 998244353,
            t: 65537,
            eta: 3,
            security_bits: 128,
            name: "h2_n4096",
        },
    ];

    let mut results = Vec::new();
    for config in &configs {
        match run_trials(config, 42) {
            Ok(r) => {
                print_result(&r);
                results.push(r);
            }
            Err(e) => println!("Config {} failed: {:?}", config.name, e),
        }
    }

    println!("\n--- H2 SUMMARY ---");
    println!(
        "{:<15} {:>6} {:>8} {:>12} {:>10}",
        "Config", "N", "Boot %", "Mean Error", "Max Error"
    );
    for r in &results {
        println!(
            "{:<15} {:>6} {:>7.0}% {:>12.1} {:>10}",
            r.config_name, r.n, r.bootstrap_success_rate * 100.0, r.mean_error, r.max_error
        );
    }
}

// =========================================================================
// H3: VARY PLAINTEXT MODULUS t
// =========================================================================

/// Smaller t means larger Δ_boot = Q_boot/t, giving more noise headroom.
/// Trade-off: smaller plaintext space.
#[test]
fn explore_h3_plaintext_modulus() {
    println!("\n\n========== H3: PLAINTEXT MODULUS ==========");
    println!("Hypothesis: smaller t increases Δ_boot, improving correctness.\n");

    let t_values: Vec<u64> = vec![
        17,    // tiny — Δ_boot huge
        257,   // small prime
        1021,  // ~10-bit prime
        4093,  // ~12-bit prime
        8209,  // ~13-bit prime
        65537, // standard (Fermat F4)
    ];

    let mut results = Vec::new();
    for &t in &t_values {
        let config = FHEConfig {
            n: 4096,
            primes: vec![998244353, 985661441, 754974721],
            q: 998244353,
            t,
            eta: 3,
            security_bits: 128,
            name: "h3_custom",
        };

        match run_trials(&config, 42) {
            Ok(r) => {
                print_result(&r);
                results.push(r);
            }
            Err(e) => println!("t={} failed: {:?}", t, e),
        }
    }

    println!("\n--- H3 SUMMARY ---");
    println!(
        "{:>8} {:>10} {:>8} {:>12} {:>10}",
        "t", "Δ_boot", "Boot %", "Mean Error", "Max Error"
    );
    for r in &results {
        println!(
            "{:>8} {:>10} {:>7.0}% {:>12.1} {:>10}",
            r.t,
            format!("2^{}", r.delta_boot_bits),
            r.bootstrap_success_rate * 100.0,
            r.mean_error,
            r.max_error
        );
    }
}

// =========================================================================
// H4: VARY NOISE PARAMETER eta
// =========================================================================

/// eta controls CBD noise width. Smaller eta = less initial noise in BSK
/// and KSK, but potentially less security.
#[test]
fn explore_h4_noise_parameter() {
    println!("\n\n========== H4: NOISE PARAMETER eta ==========");
    println!("Hypothesis: smaller eta reduces bootstrap noise floor.\n");

    let mut results = Vec::new();
    for eta in 1..=5 {
        let config = FHEConfig {
            n: 4096,
            primes: vec![998244353, 985661441, 754974721],
            q: 998244353,
            t: 65537,
            eta,
            security_bits: 128,
            name: "h4_custom",
        };

        match run_trials(&config, 42) {
            Ok(r) => {
                print_result(&r);
                results.push(r);
            }
            Err(e) => println!("eta={} failed: {:?}", eta, e),
        }
    }

    println!("\n--- H4 SUMMARY ---");
    println!(
        "{:>5} {:>8} {:>12} {:>10}",
        "eta", "Boot %", "Mean Error", "Max Error"
    );
    for r in &results {
        println!(
            "{:>5} {:>7.0}% {:>12.1} {:>10}",
            r.eta, r.bootstrap_success_rate * 100.0, r.mean_error, r.max_error
        );
    }
}

// =========================================================================
// H5: DISTRIBUTED ROUNDING ERROR ANALYSIS
// =========================================================================

/// Directly measure the error from modswitch-before-multiply vs the
/// correct decrypt-then-round approach. This isolates whether the issue
/// is noise or algorithmic (rounding doesn't distribute over poly mul).
#[test]
#[allow(clippy::needless_range_loop)] // k used for both indexing and arithmetic (j-k negacyclic)
fn explore_h5_modswitch_distribution_error() {
    println!("\n\n========== H5: MODSWITCH DISTRIBUTION ERROR ==========");
    println!("Hypothesis: rounding before poly-mul introduces systematic error.\n");
    println!("Compare: round(c0+c1*s) vs round(c0) + round(c1)*s\n");

    use nine65::params::SecureConfig;

    let config = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&config).expect("Context");
    let _boot = ClockworkBootstrap::new(&config).expect("Bootstrap");
    let mut rng = ShadowHarvester::with_seed(42);
    let keys = ctx.generate_keys_dual_full(&mut rng);

    let t = config.t as u128;
    let p0 = config.primes[0] as u128;
    let p1 = config.primes[1] as u128;
    let q_min = p0 * p1;
    let q_min_half = q_min / 2;
    let p0_inv = mod_inverse_u128(p0, p1).expect("Inverse");

    let n = config.n;

    // Get ternary secret key coefficients
    let sk_signed: Vec<i64> = keys.secret_key.s.main[0]
        .iter()
        .map(|&c| {
            if c == 0 { 0i64 }
            else if c == 1 { 1i64 }
            else { -1i64 }
        })
        .collect();

    let sk_weight: usize = sk_signed.iter().filter(|&&v| v != 0).count();
    println!("Secret key Hamming weight: {} / {} ({:.1}%)",
        sk_weight, n, sk_weight as f64 / n as f64 * 100.0);

    for m in [0u64, 1, 42, 100, 65536] {
        let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);

        // Method A: Correct BFV decrypt (reference)
        let decrypted_correct = ctx.decrypt_dual(&ct, &keys.secret_key);

        // Method B: What bootstrap Phase 1+2 effectively computes
        // Step 1: CRT reconstruct c0, c1 from RNS limbs
        let mut c0_full = vec![0u128; n];
        let mut c1_full = vec![0u128; n];
        for j in 0..n {
            c0_full[j] = crt_reconstruct_2(
                ct.c0.main[0][j] as u128, ct.c0.main[1][j] as u128,
                p0, p1, p0_inv,
            );
            c1_full[j] = crt_reconstruct_2(
                ct.c1.main[0][j] as u128, ct.c1.main[1][j] as u128,
                p0, p1, p0_inv,
            );
        }

        // Step 2a: Correct approach — compute phase first, THEN round
        // phase[j] = c0[j] + (c1*s)[j] mod q_min (negacyclic convolution)
        let mut phase = vec![0i128; n];
        for j in 0..n {
            phase[j] = c0_full[j] as i128;
            for k in 0..n {
                let s_k = sk_signed[k];
                if s_k == 0 { continue; }
                // Negacyclic: index j-k, with sign flip if wrap
                let idx = (j as i128 - k as i128).rem_euclid(n as i128) as usize;
                let sign = if j >= k { 1i128 } else { -1i128 };
                phase[j] += sign * s_k as i128 * c1_full[idx] as i128;
            }
            phase[j] = phase[j].rem_euclid(q_min as i128);
        }
        let m_correct = ((phase[0] as u128 * t + q_min_half) / q_min % t) as u64;

        // Step 2b: Bootstrap approach — round c0 and c1 individually, THEN poly-mul
        let c0_small: Vec<u64> = (0..n)
            .map(|j| ((c0_full[j] * t + q_min_half) / q_min % t) as u64)
            .collect();
        let c1_small: Vec<u64> = (0..n)
            .map(|j| ((c1_full[j] * t + q_min_half) / q_min % t) as u64)
            .collect();

        // Compute c0_small + c1_small * s in Z_t (negacyclic)
        let mut result_bootstrap = vec![0i128; n];
        for j in 0..n {
            result_bootstrap[j] = c0_small[j] as i128;
            for k in 0..n {
                let s_k = sk_signed[k];
                if s_k == 0 { continue; }
                let idx = (j as i128 - k as i128).rem_euclid(n as i128) as usize;
                let sign = if j >= k { 1i128 } else { -1i128 };
                result_bootstrap[j] += sign * s_k as i128 * c1_small[idx] as i128;
            }
            result_bootstrap[j] = result_bootstrap[j].rem_euclid(t as i128);
        }
        let m_bootstrap_sim = result_bootstrap[0] as u64;

        // Step 2c: Measure the distributed rounding error
        let error_correct = m_correct.abs_diff(m);
        let error_bootstrap = m_bootstrap_sim.abs_diff(m);

        println!(
            "m={:>6}: decrypt={:>6} | phase_round={:>6} (err={}) | bootstrap_sim={:>6} (err={}) | actual_boot=TBD",
            m, decrypted_correct, m_correct, error_correct,
            m_bootstrap_sim, error_bootstrap,
        );
    }

    println!("\nIf 'phase_round' matches decrypt but 'bootstrap_sim' doesn't,");
    println!("then the error is from modswitch-before-multiply (distributed rounding).");
    println!("If both match, the error is from Phase 2/3 noise injection.");
}

// =========================================================================
// COMBINED SWEEP: Find the correctness boundary
// =========================================================================

/// Sweep the parameter space to find configurations where bootstrap
/// achieves >90% correctness. This identifies the boundary.
#[test]
fn explore_combined_sweep() {
    println!("\n\n========== COMBINED PARAMETER SWEEP ==========");
    println!("Finding the correctness boundary across (N, t, eta) space.\n");

    // Parameter grid
    let n_values = [1024usize, 2048, 4096];
    let t_values: Vec<u64> = vec![17, 257, 1021, 4093, 65537];
    let eta_values = [1usize, 2, 3];

    println!(
        "{:<12} {:>6} {:>8} {:>5} {:>10} {:>8} {:>10} {:>10}",
        "Config", "N", "t", "eta", "Δ_boot", "Boot %", "Mean Err", "Max Err"
    );
    println!("{}", "=".repeat(80));

    for &n in &n_values {
        for &t in &t_values {
            for &eta in &eta_values {
                // Select primes compatible with N
                let primes: Vec<u64> = match n {
                    1024 => vec![998244353, 985661441],
                    2048 => vec![998244353, 985661441],
                    4096 => vec![998244353, 985661441, 754974721],
                    _ => continue,
                };

                // Skip if t > smallest prime (invalid config)
                if t >= primes[0] {
                    continue;
                }

                let config = FHEConfig {
                    n,
                    primes: primes.clone(),
                    q: primes[0],
                    t,
                    eta,
                    security_bits: 80, // exploratory, not production
                    name: "sweep",
                };

                match run_trials(&config, 42) {
                    Ok(r) => {
                        let marker = if r.bootstrap_success_rate >= 0.9 {
                            " <<< CORRECT"
                        } else if r.bootstrap_success_rate > 0.0 {
                            " << PARTIAL"
                        } else {
                            ""
                        };
                        println!(
                            "N={:<5} t={:<7} η={:<3} {:>10} {:>7.0}% {:>10.1} {:>10}{}",
                            n,
                            t,
                            eta,
                            format!("2^{}", r.delta_boot_bits),
                            r.bootstrap_success_rate * 100.0,
                            r.mean_error,
                            r.max_error,
                            marker,
                        );
                    }
                    Err(e) => {
                        println!(
                            "N={:<5} t={:<7} η={:<3} FAILED: {}",
                            n, t, eta,
                            format!("{:?}", e).chars().take(40).collect::<String>()
                        );
                    }
                }
            }
        }
    }
}

// =========================================================================
// PHASE-BY-PHASE DIAGNOSTIC
// =========================================================================

/// Run each bootstrap phase independently and measure intermediate values.
/// This pinpoints exactly where correctness breaks down.
#[test]
fn explore_phase_by_phase_diagnostic() {
    println!("\n\n========== PHASE-BY-PHASE DIAGNOSTIC ==========");
    println!("Isolating which bootstrap phase introduces the error.\n");

    use nine65::params::SecureConfig;

    let config = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&config).expect("Context");
    let boot = ClockworkBootstrap::new(&config).expect("Bootstrap");
    let mut rng = ShadowHarvester::with_seed(42);
    let keys = ctx.generate_keys_dual_full(&mut rng);
    let boot_keys = boot.generate_keys(&keys.secret_key, &mut rng).expect("KeyGen");

    let n = config.n;
    let t = config.t;

    for m in [0u64, 1, 42] {
        println!("\n--- Message m={} ---", m);

        let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
        let dec_fresh = ctx.decrypt_dual(&ct, &keys.secret_key);
        println!("  Fresh decrypt: {} (correct={})", dec_fresh, dec_fresh == m);

        // Phase 1: ModSwitch
        // We can't call modswitch_to_t directly (it's private), but we can
        // observe the full bootstrap and compare with a manual modswitch.
        let p0 = config.primes[0] as u128;
        let p1 = config.primes[1] as u128;
        let q_min = p0 * p1;
        let q_min_half = q_min / 2;
        let t128 = t as u128;
        let p0_inv = mod_inverse_u128(p0, p1).expect("Inverse");

        // Manual modswitch
        let mut c0_small = vec![0u64; n];
        let mut c1_small = vec![0u64; n];
        for j in 0..n {
            let c0_val = crt_reconstruct_2(
                ct.c0.main[0][j] as u128, ct.c0.main[1][j] as u128,
                p0, p1, p0_inv,
            );
            c0_small[j] = ((c0_val * t128 + q_min_half) / q_min % t128) as u64;

            let c1_val = crt_reconstruct_2(
                ct.c1.main[0][j] as u128, ct.c1.main[1][j] as u128,
                p0, p1, p0_inv,
            );
            c1_small[j] = ((c1_val * t128 + q_min_half) / q_min % t128) as u64;
        }

        // Statistics on modswitch output
        let c0_max = c0_small.iter().max().unwrap();
        let c1_max = c1_small.iter().max().unwrap();
        let c0_nonzero = c0_small.iter().filter(|&&v| v != 0).count();
        let c1_nonzero = c1_small.iter().filter(|&&v| v != 0).count();
        println!("  Phase 1 (ModSwitch Q->{}):", t);
        println!("    c0_small: max={}, nonzero={}/{}, [0]={}", c0_max, c0_nonzero, n, c0_small[0]);
        println!("    c1_small: max={}, nonzero={}/{}, [0]={}", c1_max, c1_nonzero, n, c1_small[0]);

        // Full bootstrap result
        let ct_boot = boot.bootstrap(&ct, &boot_keys.bsk, &boot_keys.ksk).expect("Bootstrap");
        let dec_boot = ctx.decrypt_dual(&ct_boot, &keys.secret_key);
        println!("  Full bootstrap decrypt: {} (correct={})", dec_boot, dec_boot == m);

        // Analyze the bootstrap output ciphertext
        let c0_boot_max: u64 = ct_boot.c0.main[0].iter().max().copied().unwrap_or(0);
        let c1_boot_max: u64 = ct_boot.c1.main[0].iter().max().copied().unwrap_or(0);
        println!("  Bootstrap output: c0_max={}, c1_max={}, level={}",
            c0_boot_max, c1_boot_max, ct_boot.level);

        // Compare output structure with fresh encrypt
        let ct_fresh_m = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
        let c0_fresh_max: u64 = ct_fresh_m.c0.main[0].iter().max().copied().unwrap_or(0);
        let c1_fresh_max: u64 = ct_fresh_m.c1.main[0].iter().max().copied().unwrap_or(0);
        println!("  Fresh encrypt:    c0_max={}, c1_max={}, level={}",
            c0_fresh_max, c1_fresh_max, ct_fresh_m.level);
    }
}

// =========================================================================
// NOISE FLOOR ESTIMATION
// =========================================================================

/// Empirically estimate the noise introduced by each bootstrap phase
/// by encrypting zero and observing the output.
#[test]
fn explore_noise_floor_estimation() {
    println!("\n\n========== NOISE FLOOR ESTIMATION ==========");
    println!("Encrypt(0) through bootstrap — any non-zero output IS the noise.\n");

    use nine65::params::SecureConfig;

    let config = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&config).expect("Context");
    let boot = ClockworkBootstrap::new(&config).expect("Bootstrap");
    let mut rng = ShadowHarvester::with_seed(42);
    let keys = ctx.generate_keys_dual_full(&mut rng);
    let boot_keys = boot.generate_keys(&keys.secret_key, &mut rng).expect("KeyGen");

    let _n = config.n;

    // Multiple seeds to get noise statistics
    let num_samples = 10;
    let mut noise_magnitudes = Vec::new();

    for seed in 0..num_samples {
        let mut sample_rng = ShadowHarvester::with_seed(100 + seed);
        let ct_zero = ctx.encrypt_dual(0, &keys.public_key, &mut sample_rng);
        let dec_fresh = ctx.decrypt_dual(&ct_zero, &keys.secret_key);

        let ct_boot = boot.bootstrap(&ct_zero, &boot_keys.bsk, &boot_keys.ksk)
            .expect("Bootstrap");
        let dec_boot = ctx.decrypt_dual(&ct_boot, &keys.secret_key);

        noise_magnitudes.push(dec_boot);
        println!(
            "  Sample {}: fresh_dec={}, boot_dec={} (noise={})",
            seed, dec_fresh, dec_boot, dec_boot
        );
    }

    let all_zero = noise_magnitudes.iter().all(|&v| v == 0);
    let max_noise = noise_magnitudes.iter().max().unwrap();
    println!("\nNoise floor for m=0: all_zero={}, max={}", all_zero, max_noise);
    println!("If max > 0, even m=0 has noise (just happens to round correctly).");

    // Now do the same for m=1 to see the noise magnitude
    println!("\nNoise measurement for m=1:");
    for seed in 0..num_samples {
        let mut sample_rng = ShadowHarvester::with_seed(200 + seed);
        let ct_one = ctx.encrypt_dual(1, &keys.public_key, &mut sample_rng);
        let ct_boot = boot.bootstrap(&ct_one, &boot_keys.bsk, &boot_keys.ksk)
            .expect("Bootstrap");
        let dec_boot = ctx.decrypt_dual(&ct_boot, &keys.secret_key);
        let error = if dec_boot > 1 {
            (dec_boot - 1).min(config.t - dec_boot + 1)
        } else {
            1 - dec_boot
        };
        println!("  Sample {}: dec={}, error={}", seed, dec_boot, error);
    }
}

// =========================================================================
// SEED SENSITIVITY
// =========================================================================

/// Test whether bootstrap correctness varies with RNG seed.
/// If correctness is seed-dependent, the noise is marginal.
/// If consistently wrong, it's a structural issue.
#[test]
fn explore_seed_sensitivity() {
    println!("\n\n========== SEED SENSITIVITY ==========");
    println!("Does bootstrap correctness depend on the random seed?\n");

    use nine65::params::SecureConfig;
    let config = SecureConfig::secure_128().into_config();

    let mut correct_per_seed = Vec::new();

    for seed in [1u64, 7, 42, 100, 999, 12345, 65536, 999999] {
        match run_trials(&config, seed) {
            Ok(r) => {
                let correct = r.trials.iter().filter(|t| t.bootstrap_correct).count();
                let total = r.trials.len();
                let m0_ok = r.trials.iter()
                    .find(|t| t.message == 0)
                    .map(|t| t.bootstrap_correct)
                    .unwrap_or(false);
                println!(
                    "  seed={:>8}: {}/{} correct, m=0 correct={}, boot_rate={:.0}%",
                    seed, correct, total, m0_ok, r.bootstrap_success_rate * 100.0
                );
                correct_per_seed.push((seed, correct, total));
            }
            Err(e) => println!("  seed={}: FAILED: {:?}", seed, e),
        }
    }

    let all_same = correct_per_seed.windows(2).all(|w| w[0].1 == w[1].1);
    println!(
        "\nSeed sensitivity: {} (all seeds give same correctness count)",
        if all_same { "STRUCTURAL (seed-independent)" } else { "MARGINAL (seed-dependent)" }
    );
}

// =========================================================================
// ANCHOR LIMB ANALYSIS
// =========================================================================

/// The key_switch output zeros out anchor limbs. Investigate whether
/// this causes issues for subsequent decrypt_dual.
#[test]
fn explore_anchor_limb_impact() {
    println!("\n\n========== ANCHOR LIMB ANALYSIS ==========");
    println!("Bootstrap zeros anchor limbs. Does this break decrypt?\n");

    use nine65::params::SecureConfig;

    let config = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&config).expect("Context");
    let boot = ClockworkBootstrap::new(&config).expect("Bootstrap");
    let mut rng = ShadowHarvester::with_seed(42);
    let keys = ctx.generate_keys_dual_full(&mut rng);
    let boot_keys = boot.generate_keys(&keys.secret_key, &mut rng).expect("KeyGen");

    let ct = ctx.encrypt_dual(42, &keys.public_key, &mut rng);

    // Check anchor limbs before bootstrap
    let anchor_nonzero_before: usize = ct.c0.anchor.iter()
        .flat_map(|limb| limb.iter())
        .filter(|&&v| v != 0)
        .count();

    let ct_boot = boot.bootstrap(&ct, &boot_keys.bsk, &boot_keys.ksk).expect("Bootstrap");

    // Check anchor limbs after bootstrap
    let anchor_nonzero_after: usize = ct_boot.c0.anchor.iter()
        .flat_map(|limb| limb.iter())
        .filter(|&&v| v != 0)
        .count();

    println!("  Before bootstrap: {} non-zero anchor coefficients", anchor_nonzero_before);
    println!("  After bootstrap:  {} non-zero anchor coefficients", anchor_nonzero_after);
    println!("  Anchor limbs zeroed: {}", anchor_nonzero_after == 0);

    // Check if decrypt_dual uses anchor limbs
    let dec_main_only = ctx.decrypt_dual(&ct_boot, &keys.secret_key);
    println!("  Decrypt with zero anchors: {}", dec_main_only);
    println!("  (If decrypt uses only main limbs, zero anchors are fine)");
}

// =========================================================================
// H6: Δ⁻¹ CORRECTION (from QMNF_System's rescale_bfv_delta_rns)
// =========================================================================

/// QMNF_System's `rescale_bfv_delta_rns()` applies a critical Δ⁻¹ correction
/// after the modswitch rounding that NINE65's Clockwork Bootstrap omits.
///
/// The full QMNF rescale pipeline:
///   1. CRT reconstruct a ∈ [0, Q)
///   2. sr = round(a * t / Q)            ← BOTH systems do this
///   3. m_hat = sr * Δ⁻¹ (mod t)         ← NINE65 SKIPS THIS
///   4. v = m_hat * Δ (mod Q_i)           ← NINE65 SKIPS THIS
///
/// Without step 3, the modswitch output `sr` still encodes `Δ * m mod t`,
/// not the raw message `m`. When Phase 2 then computes:
///   TrivialEnc(Δ_boot * sr) + sr_c1 * BSK
/// it's effectively computing:
///   Enc_boot(Δ_boot * (Δ_work * m mod t) + ...)
/// instead of:
///   Enc_boot(Δ_boot * m + ...)
///
/// This test simulates the full bootstrap cleartext path with and without
/// the Δ⁻¹ correction to determine if this is the root cause of F-1.
#[test]
fn explore_h6_delta_inverse_correction() {
    println!("\n\n========== H6: Δ⁻¹ CORRECTION ANALYSIS ==========");
    println!("QMNF_System applies sr × Δ⁻¹ (mod t) after modswitch rounding.");
    println!("NINE65 skips this. Testing whether this is the root cause of F-1.\n");

    use nine65::params::SecureConfig;

    let config = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&config).expect("Context");
    let mut rng = ShadowHarvester::with_seed(42);
    let keys = ctx.generate_keys_dual_full(&mut rng);

    let n = config.n;
    let t = config.t;
    let t128 = t as u128;
    let p0 = config.primes[0] as u128;
    let p1 = config.primes[1] as u128;
    let q_min = p0 * p1;
    let q_min_half = q_min / 2;
    let p0_inv = mod_inverse_u128(p0, p1).expect("Inverse");

    // Compute Δ_work = round(Q_min / t)
    let delta_work = (q_min + t128 / 2) / t128;
    let delta_work_mod_t = (delta_work % t128) as u64;

    // Compute Δ⁻¹ mod t (the QMNF correction factor)
    let delta_inv_mod_t = mod_inverse_u128(delta_work_mod_t as u128, t128);

    println!("Parameters:");
    println!("  Q_min = p0 * p1 = {} ({} bits)", q_min, 128 - q_min.leading_zeros());
    println!("  t = {}", t);
    println!("  Δ_work = round(Q_min/t) = {} ({} bits)", delta_work, 128 - delta_work.leading_zeros());
    println!("  Δ_work mod t = {}", delta_work_mod_t);
    match delta_inv_mod_t {
        Some(inv) => println!("  Δ⁻¹ mod t = {} (verify: {} * {} mod {} = {})",
            inv, delta_work_mod_t, inv, t, (delta_work_mod_t as u128 * inv) % t128),
        None => println!("  Δ⁻¹ mod t = DOES NOT EXIST (gcd(Δ,t) ≠ 1) ← THIS IS THE PROBLEM"),
    }
    println!();

    // Get ternary secret key
    let sk_signed: Vec<i64> = keys.secret_key.s.main[0]
        .iter()
        .map(|&c| {
            if c == 0 { 0i64 }
            else if c == 1 { 1i64 }
            else { -1i64 }
        })
        .collect();

    println!(
        "{:<8} {:>8} {:>12} {:>12} {:>12} {:>12}",
        "Message", "Decrypt", "No Δ⁻¹", "With Δ⁻¹", "Err(no)", "Err(with)"
    );
    println!("{}", "=".repeat(70));

    for m in [0u64, 1, 2, 7, 42, 100, 1000, 65536] {
        let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
        let dec_fresh = ctx.decrypt_dual(&ct, &keys.secret_key);

        // CRT reconstruct c0, c1 from RNS limbs
        let mut c0_full = vec![0u128; n];
        let mut c1_full = vec![0u128; n];
        for j in 0..n {
            c0_full[j] = crt_reconstruct_2(
                ct.c0.main[0][j] as u128, ct.c0.main[1][j] as u128,
                p0, p1, p0_inv,
            );
            c1_full[j] = crt_reconstruct_2(
                ct.c1.main[0][j] as u128, ct.c1.main[1][j] as u128,
                p0, p1, p0_inv,
            );
        }

        // === METHOD A: Current NINE65 (no Δ⁻¹ correction) ===
        // sr = round(a * t / Q_min) — this is what modswitch_to_t returns
        let c0_no_correction: Vec<u64> = (0..n)
            .map(|j| ((c0_full[j] * t128 + q_min_half) / q_min % t128) as u64)
            .collect();
        let c1_no_correction: Vec<u64> = (0..n)
            .map(|j| ((c1_full[j] * t128 + q_min_half) / q_min % t128) as u64)
            .collect();

        // Compute c0 + c1*s in Z_t (negacyclic convolution)
        let m_no_correction = cleartext_phase_eval(
            &c0_no_correction, &c1_no_correction, &sk_signed, n, t,
        );

        // === METHOD B: With QMNF Δ⁻¹ correction ===
        let (c0_with_correction, c1_with_correction) = if let Some(inv) = delta_inv_mod_t {
            let c0_corrected: Vec<u64> = c0_no_correction.iter()
                .map(|&sr| ((sr as u128 * inv) % t128) as u64)
                .collect();
            let c1_corrected: Vec<u64> = c1_no_correction.iter()
                .map(|&sr| ((sr as u128 * inv) % t128) as u64)
                .collect();
            (c0_corrected, c1_corrected)
        } else {
            // Δ⁻¹ doesn't exist — correction impossible
            (c0_no_correction.clone(), c1_no_correction.clone())
        };

        let m_with_correction = cleartext_phase_eval(
            &c0_with_correction, &c1_with_correction, &sk_signed, n, t,
        );

        // Error computation (mod t distance)
        let err_no = mod_distance(m_no_correction, m, t);
        let err_with = mod_distance(m_with_correction, m, t);

        println!(
            "m={:<6} {:>8} {:>12} {:>12} {:>12} {:>12}{}",
            m, dec_fresh, m_no_correction, m_with_correction,
            err_no, err_with,
            if err_with == 0 && err_no != 0 { "  ← Δ⁻¹ FIXES IT" }
            else if err_with == 0 && err_no == 0 { "  (both correct)" }
            else if err_with < err_no { "  ← Δ⁻¹ helps" }
            else { "" }
        );
    }

    println!("\n--- INTERPRETATION ---");
    println!("If 'With Δ⁻¹' column shows 0 error for all messages:");
    println!("  → The Δ⁻¹ correction IS the fix. Port QMNF's rescale_bfv_delta_rns steps 3-4.");
    println!("If 'With Δ⁻¹' still has errors:");
    println!("  → The issue is deeper (Phase 2 noise, polynomial convolution error, etc.).");
    if delta_inv_mod_t.is_none() {
        println!("\nCRITICAL: Δ⁻¹ mod t DOES NOT EXIST.");
        println!("  gcd(Δ_work, t) ≠ 1, meaning Δ and t share a factor.");
        println!("  This makes QMNF-style correction impossible for this (Q_min, t) pair.");
        println!("  Possible fixes: change t to an odd prime, or adjust Q_min.");
    }
}

/// Simulate the BFV phase evaluation in cleartext:
/// result[0] = (c0[0] + (c1 * s)[0]) mod t
/// where * is negacyclic polynomial multiplication in Z_t[X]/(X^N+1).
fn cleartext_phase_eval(
    c0: &[u64],
    c1: &[u64],
    sk_signed: &[i64],
    n: usize,
    t: u64,
) -> u64 {
    // For coefficient 0 of the negacyclic convolution c1 * s:
    // (c1*s)[0] = sum_{k=0}^{N-1} c1[k] * s[N-k] * (-1)  for k>0
    //           = c1[0]*s[0] - c1[1]*s[N-1] - c1[2]*s[N-2] - ... - c1[N-1]*s[1]
    //
    // More generally, for all j:
    // (c1*s)[j] = sum_{k=0}^{N-1} c1[k] * s[(j-k) mod N] * sign
    // where sign = -1 if (j-k) wrapped around (j < k), +1 otherwise.
    //
    // We only need coefficient 0 for scalar message recovery.
    let mut phase_0 = c0[0] as i128;
    for k in 0..n {
        let s_k = sk_signed[k];
        if s_k == 0 { continue; }

        // Index: (0 - k) mod N = N - k for k > 0, or 0 for k = 0
        // Sign: -1 for k > 0 (wrapped), +1 for k = 0
        if k == 0 {
            phase_0 += s_k as i128 * c1[0] as i128;
        } else {
            // Negacyclic: X^N = -1, so X^{-k} = -X^{N-k}
            phase_0 -= s_k as i128 * c1[n - k] as i128;
        }
    }
    phase_0.rem_euclid(t as i128) as u64
}

/// Distance in Z_t (circular): min(|a-b|, t-|a-b|)
fn mod_distance(a: u64, b: u64, t: u64) -> u64 {
    let diff = a.abs_diff(b);
    diff.min(t - diff)
}

// =========================================================================
// H6b: Δ⁻¹ CORRECTION — FULL POLYNOMIAL EVALUATION
// =========================================================================

/// Same as H6 but evaluates ALL N coefficients (not just [0]) to check
/// whether the correction works across the entire polynomial, and whether
/// the Δ encoding corrupts the negacyclic convolution structure.
#[test]
fn explore_h6b_full_polynomial_correction() {
    println!("\n\n========== H6b: FULL POLYNOMIAL Δ⁻¹ ANALYSIS ==========");
    println!("Evaluating all N coefficients with/without Δ⁻¹ correction.\n");

    use nine65::params::SecureConfig;

    let config = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&config).expect("Context");
    let mut rng = ShadowHarvester::with_seed(42);
    let keys = ctx.generate_keys_dual_full(&mut rng);

    let n = config.n;
    let t = config.t;
    let t128 = t as u128;
    let p0 = config.primes[0] as u128;
    let p1 = config.primes[1] as u128;
    let q_min = p0 * p1;
    let q_min_half = q_min / 2;
    let p0_inv = mod_inverse_u128(p0, p1).expect("Inverse");

    let delta_work = (q_min + t128 / 2) / t128;
    let delta_work_mod_t = (delta_work % t128) as u64;
    let delta_inv_mod_t = mod_inverse_u128(delta_work_mod_t as u128, t128);

    let sk_signed: Vec<i64> = keys.secret_key.s.main[0]
        .iter()
        .map(|&c| {
            if c == 0 { 0i64 }
            else if c == 1 { 1i64 }
            else { -1i64 }
        })
        .collect();

    for m in [0u64, 1, 42] {
        println!("\n--- m={} ---", m);

        let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);

        // CRT reconstruct
        let mut c0_full = vec![0u128; n];
        let mut c1_full = vec![0u128; n];
        for j in 0..n {
            c0_full[j] = crt_reconstruct_2(
                ct.c0.main[0][j] as u128, ct.c0.main[1][j] as u128,
                p0, p1, p0_inv,
            );
            c1_full[j] = crt_reconstruct_2(
                ct.c1.main[0][j] as u128, ct.c1.main[1][j] as u128,
                p0, p1, p0_inv,
            );
        }

        // Modswitch (no correction)
        let c0_raw: Vec<u64> = (0..n)
            .map(|j| ((c0_full[j] * t128 + q_min_half) / q_min % t128) as u64)
            .collect();
        let c1_raw: Vec<u64> = (0..n)
            .map(|j| ((c1_full[j] * t128 + q_min_half) / q_min % t128) as u64)
            .collect();

        // Full negacyclic convolution for ALL coefficients — no correction
        let phase_no_corr = full_negacyclic_phase(&c0_raw, &c1_raw, &sk_signed, n, t);

        // With Δ⁻¹ correction
        let phase_with_corr = if let Some(inv) = delta_inv_mod_t {
            let c0_corr: Vec<u64> = c0_raw.iter()
                .map(|&sr| ((sr as u128 * inv) % t128) as u64)
                .collect();
            let c1_corr: Vec<u64> = c1_raw.iter()
                .map(|&sr| ((sr as u128 * inv) % t128) as u64)
                .collect();
            full_negacyclic_phase(&c0_corr, &c1_corr, &sk_signed, n, t)
        } else {
            phase_no_corr.clone()
        };

        // Reference: compute phase in Q_min, THEN round (correct BFV decrypt)
        let phase_correct = {
            let mut ph = vec![0i128; n];
            for j in 0..n {
                ph[j] = c0_full[j] as i128;
                for k in 0..n {
                    let s_k = sk_signed[k];
                    if s_k == 0 { continue; }
                    if k == 0 {
                        ph[j] += s_k as i128 * c1_full[j] as i128;
                    } else if j >= k {
                        ph[j] += s_k as i128 * c1_full[j - k] as i128;
                    } else {
                        // Negacyclic wrap: X^N = -1
                        ph[j] -= s_k as i128 * c1_full[n + j - k] as i128;
                    }
                }
                ph[j] = ph[j].rem_euclid(q_min as i128);
            }
            let result: Vec<u64> = ph.iter()
                .map(|&v| ((v as u128 * t128 + q_min_half) / q_min % t128) as u64)
                .collect();
            result
        };

        // For scalar encoding, message is in coefficient 0. Others should be ~0 (noise).
        println!("  Coeff[0] — message coefficient:");
        println!("    Correct BFV:    {}", phase_correct[0]);
        println!("    No Δ⁻¹:         {} (err={})", phase_no_corr[0], mod_distance(phase_no_corr[0], m, t));
        println!("    With Δ⁻¹:       {} (err={})", phase_with_corr[0], mod_distance(phase_with_corr[0], m, t));

        // Check how many noise coefficients differ between methods
        let mut diff_no_corr = 0u32;
        let mut diff_with_corr = 0u32;
        for j in 1..n {
            if phase_no_corr[j] != phase_correct[j] { diff_no_corr += 1; }
            if phase_with_corr[j] != phase_correct[j] { diff_with_corr += 1; }
        }
        println!("  Noise coefficients [1..N) differing from correct BFV:");
        println!("    No Δ⁻¹:   {}/{}", diff_no_corr, n - 1);
        println!("    With Δ⁻¹: {}/{}", diff_with_corr, n - 1);
    }
}

/// Full negacyclic polynomial phase evaluation: c0 + c1*s mod (X^N+1) in Z_t.
/// Returns all N coefficients.
fn full_negacyclic_phase(
    c0: &[u64],
    c1: &[u64],
    sk: &[i64],
    n: usize,
    t: u64,
) -> Vec<u64> {
    let mut result = vec![0i128; n];
    for j in 0..n {
        result[j] = c0[j] as i128;
        for k in 0..n {
            let s_k = sk[k];
            if s_k == 0 { continue; }
            if k == 0 {
                result[j] += s_k as i128 * c1[j] as i128;
            } else if j >= k {
                result[j] += s_k as i128 * c1[j - k] as i128;
            } else {
                result[j] -= s_k as i128 * c1[n + j - k] as i128;
            }
        }
        result[j] = result[j].rem_euclid(t as i128);
    }
    result.iter().map(|&v| v as u64).collect()
}

// =========================================================================
// H6c: GCD(Δ, t) ANALYSIS — Can Δ⁻¹ Even Exist?
// =========================================================================

/// For the Δ⁻¹ correction to work, we need gcd(Δ, t) = 1.
/// BFV typically uses t = 65537 (Fermat prime F4). Since Δ = round(Q/t),
/// Δ mod t can be anything. If gcd(Δ mod t, t) ≠ 1, the correction
/// is impossible and a different approach is needed.
///
/// This test checks all parameter configs to determine where Δ⁻¹ exists.
#[test]
fn explore_h6c_gcd_delta_t() {
    println!("\n\n========== H6c: GCD(Δ, t) EXISTENCE CHECK ==========");
    println!("Δ⁻¹ mod t exists iff gcd(Δ mod t, t) = 1.\n");

    let configs: Vec<(&str, Vec<u64>, u64)> = vec![
        ("secure_128", vec![998244353, 985661441, 754974721], 65537),
        ("secure_128_deep", vec![998244353, 985661441, 754974721, 469762049], 65537),
        ("2-prime", vec![998244353, 985661441], 65537),
        ("t=17", vec![998244353, 985661441], 17),
        ("t=257", vec![998244353, 985661441], 257),
        ("t=1021", vec![998244353, 985661441], 1021),
        ("t=4093", vec![998244353, 985661441], 4093),
        ("t=2053", vec![998244353, 985661441], 2053),
        ("batched t=257", vec![998244353, 985661441, 754974721], 257),
    ];

    println!(
        "{:<20} {:>12} {:>12} {:>12} {:>8} {:>10}",
        "Config", "Q_min", "Δ_work", "Δ mod t", "gcd", "Δ⁻¹ exists?"
    );
    println!("{}", "=".repeat(80));

    for (name, primes, t) in &configs {
        let q_min: u128 = primes[0] as u128 * primes[1] as u128;
        let t128 = *t as u128;
        let delta = (q_min + t128 / 2) / t128;
        let delta_mod_t = (delta % t128) as u64;
        let g = gcd_u64(delta_mod_t, *t);
        let inv_exists = g == 1;
        let inv_str = if inv_exists {
            let inv = mod_inverse_u128(delta_mod_t as u128, t128).unwrap();
            format!("YES ({})", inv)
        } else {
            format!("NO (gcd={})", g)
        };

        println!(
            "{:<20} {:>12} {:>12} {:>12} {:>8} {:>10}",
            name,
            format!("2^{}", 128 - q_min.leading_zeros()),
            format!("2^{}", 128 - delta.leading_zeros()),
            delta_mod_t,
            g,
            inv_str,
        );
    }

    println!("\nFor t=65537 (Fermat prime): Δ⁻¹ exists iff Δ mod 65537 ≠ 0.");
    println!("Since 65537 is prime, gcd(Δ,t)=1 unless 65537 | Δ (astronomically unlikely).");
}

fn gcd_u64(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let temp = b;
        b = a % b;
        a = temp;
    }
    a
}

// =========================================================================
// REGRESSION TEST: Bootstrap roundtrip correctness after Δ⁻¹ fix (F-1)
// =========================================================================

/// Regression test for Finding F-1: verify that bootstrap roundtrip
/// recovers the original plaintext for a range of messages.
///
/// Tests both circular security (`bootstrap()`) and non-circular
/// (`bootstrap_with_ksk()`) paths.
#[test]
fn test_bootstrap_roundtrip_correctness() {
    use nine65::params::SecureConfig;

    let config = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&config).expect("Context");
    let boot = ClockworkBootstrap::new(&config).expect("Bootstrap context");
    let mut rng = ShadowHarvester::with_seed(42);
    let keys = ctx.generate_keys_dual_full(&mut rng);

    // --- Circular security path ---
    let boot_keys_circ = boot
        .generate_keys(&keys.secret_key, &mut rng)
        .expect("Circular key generation");

    let test_messages = [0u64, 1, 2, 7, 42, 100, 1000];

    for &m in &test_messages {
        let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);

        // Sanity: fresh decrypt must be exact
        let dec_fresh = ctx.decrypt_dual(&ct, &keys.secret_key);
        assert_eq!(dec_fresh, m, "Fresh decrypt failed for m={}", m);

        // Bootstrap roundtrip (circular)
        let ct_boot = boot
            .bootstrap(&ct, &boot_keys_circ.bsk, &boot_keys_circ.ksk)
            .expect("Bootstrap failed");
        let dec_boot = ctx.decrypt_dual(&ct_boot, &keys.secret_key);
        assert_eq!(
            dec_boot, m,
            "Circular bootstrap roundtrip failed: m={}, got={}",
            m, dec_boot
        );
    }

    // --- Non-circular (KSK) path ---
    let boot_keys_ksk = boot
        .generate_keys_with_ksk(&keys.secret_key, &mut rng)
        .expect("KSK key generation");

    for &m in &test_messages {
        let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
        let ct_boot = boot
            .bootstrap_with_ksk(&ct, &boot_keys_ksk.bsk, &boot_keys_ksk.ksk)
            .expect("Bootstrap with KSK failed");
        let dec_boot = ctx.decrypt_dual(&ct_boot, &keys.secret_key);
        assert_eq!(
            dec_boot, m,
            "KSK bootstrap roundtrip failed: m={}, got={}",
            m, dec_boot
        );
    }
}
