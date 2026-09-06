//! Measured cost of the core FHE operations, per config.
//!
//! Exists because the numbers in `README.md` and `CLAUDE.md` were inherited
//! rather than re-measured, and because a constant-time change landed inside
//! `BarrettContext::reduce_ct`, which `NTTEngine` calls in its pointwise
//! multiply — the innermost loop of every ciphertext multiply. A perf claim
//! that nobody re-runs is the same class of problem as a CI claim that nobody
//! checks.
//!
//! Run:
//!   cargo test -p nine65 --test op_timings --release --features allow_insecure \
//!     -- --ignored --nocapture
//!
//! ## Machine-readable output (issue #19)
//!
//! Alongside the human-readable markdown table this test prints, it also
//! writes an integer-nanosecond JSON capture — every raw sample plus its
//! median, per operation, per config, plus the full config TUPLE (n, primes,
//! t), never just the config NAME (CLAUDE.md documents `secure_128` being
//! silently redefined once already; a name-keyed comparison across that
//! redefinition is meaningless). `scripts/check_benchmark_regression.py`
//! consumes this file to flag a median regression against a committed
//! baseline. No floating-point value appears anywhere in the JSON path —
//! only u128/u64 nanoseconds and integer arithmetic, per CLAUDE.md's
//! "Important Coding Rules".
//!
//! Output path: `$NINE65_BENCH_JSON_OUT` if set, else
//! `<repo_root>/bench-results/op_timings.json` (resolved from the
//! compile-time `CARGO_MANIFEST_DIR`, so it does not depend on the test
//! process's current directory or on `$CARGO_TARGET_DIR`).

use nine65::arithmetic::integer_math::format_ratio;
use nine65::entropy::ShadowHarvester;
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::params::secure_configs::SecureConfig;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

/// Integer-only median: sorts a copy of `values` and returns the middle
/// element (odd sample counts only in this file — no interpolation, so no
/// division by two is ever needed to produce the result itself). Takes a
/// slice rather than consuming the samples: `time_config` needs the raw
/// per-round nanosecond vectors again afterward to build the JSON capture's
/// per-operation medians.
fn median_ns(values: &[u128]) -> u128 {
    let mut v = values.to_vec();
    v.sort_unstable();
    v[v.len() / 2]
}

/// Median duration in milliseconds, formatted to `decimals` fractional
/// digits via the shared integer-only [`format_ratio`] helper — the
/// integer-only replacement for `median(..) as f64 / 1e6` followed by
/// `{:.N}`.
fn median_ms(v: &[u128], decimals: u32) -> String {
    format_ratio(median_ns(v), 1_000_000, decimals)
}

/// One operation's raw samples plus its integer median, ready to serialize.
struct OpSamples {
    key: &'static str,
    samples_ns: Vec<u128>,
    median_ns: u128,
}

/// One config's full measured tuple: identity (n, primes, t — never just a
/// name) plus every timed operation.
struct ConfigResult {
    name: &'static str,
    n: usize,
    primes: Vec<u64>,
    t: u64,
    rounds: usize,
    ops: Vec<OpSamples>,
}

fn time_config(name: &'static str, secure: SecureConfig, rounds: usize) -> ConfigResult {
    let config = secure.config.clone();
    let ctx = RNSFHEContext::new(&config);
    let mut rng = ShadowHarvester::with_seed(4242);
    let keys = ctx.generate_keys_dual_full(&mut rng);

    let (mut enc, mut add, mut mul, mut dec, mut smul) = (vec![], vec![], vec![], vec![], vec![]);
    let s2 = ctx.precompute_s_squared(&keys.secret_key);

    for i in 0..rounds {
        let a = (i as u64 % 17) + 2;
        let b = (i as u64 % 13) + 3;

        let t0 = Instant::now();
        let ct_a = ctx.encrypt_dual(a, &keys.public_key, &mut rng);
        enc.push(t0.elapsed().as_nanos());

        let ct_b = ctx.encrypt_dual(b, &keys.public_key, &mut rng);

        let t1 = Instant::now();
        let sum = ctx.add_dual(&ct_a, &ct_b);
        add.push(t1.elapsed().as_nanos());

        let t2 = Instant::now();
        let prod = ctx
            .mul_dual_public(&ct_a, &ct_b, &keys.eval_key)
            .expect("mul_dual_public returned Err");
        mul.push(t2.elapsed().as_nanos());

        let t3 = Instant::now();
        let got = ctx.decrypt_dual(&sum, &keys.secret_key);
        dec.push(t3.elapsed().as_nanos());

        let t4 = Instant::now();
        let sprod = ctx.mul_dual_symmetric_with_s2(&ct_a, &ct_b, &keys.secret_key, &s2);
        smul.push(t4.elapsed().as_nanos());
        assert_eq!(
            ctx.decrypt_dual(&sprod, &keys.secret_key),
            (a * b) % config.t,
            "{name}: symmetric mul must stay exact"
        );

        assert_eq!(got, (a + b) % config.t, "{name}: add must stay exact");
        assert_eq!(
            ctx.decrypt_dual(&prod, &keys.secret_key),
            (a * b) % config.t,
            "{name}: mul must stay exact"
        );
    }

    println!(
        "| `{name}` | {} | {} | {} | {} | {} | {} | {} |",
        config.n,
        config.primes.len(),
        median_ms(&enc, 2),
        median_ms(&add, 3),
        median_ms(&mul, 2),
        median_ms(&smul, 2),
        median_ms(&dec, 2),
    );

    let ops = [
        ("encrypt", enc),
        ("add", add),
        ("public_mul", mul),
        ("symmetric_mul", smul),
        ("decrypt", dec),
    ]
    .into_iter()
    .map(|(key, samples_ns)| OpSamples {
        key,
        median_ns: median_ns(&samples_ns),
        samples_ns,
    })
    .collect();

    ConfigResult {
        name,
        n: config.n,
        primes: config.primes.clone(),
        t: config.t,
        rounds,
        ops,
    }
}

fn json_u128_array(values: &[u128]) -> String {
    let mut s = String::from("[");
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&v.to_string());
    }
    s.push(']');
    s
}

fn json_u64_array(values: &[u64]) -> String {
    let mut s = String::from("[");
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&v.to_string());
    }
    s.push(']');
    s
}

/// Hand-rolled, not a `serde_json::to_string` call: this test target's only
/// required feature is `allow_insecure` (see `crates/nine65/Cargo.toml`'s
/// `[[test]] name = "op_timings"` stanza) and the documented reproduce
/// command in CLAUDE.md/README.md does not pass `--features serde`. Every
/// value below is a plain integer or a known-safe identifier string (config
/// names, op keys), so no escaping beyond this is needed.
fn results_to_json(results: &[ConfigResult]) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"schema\": \"nine65-op-timings-v1\",\n");
    out.push_str("  \"source\": \"crates/nine65/tests/op_timings.rs\",\n");
    out.push_str("  \"unit\": \"nanoseconds\",\n");
    out.push_str("  \"configs\": [\n");
    for (ci, cfg) in results.iter().enumerate() {
        out.push_str("    {\n");
        out.push_str(&format!("      \"config\": \"{}\",\n", cfg.name));
        out.push_str(&format!("      \"n\": {},\n", cfg.n));
        out.push_str(&format!(
            "      \"primes\": {},\n",
            json_u64_array(&cfg.primes)
        ));
        out.push_str(&format!("      \"t\": {},\n", cfg.t));
        out.push_str(&format!("      \"rounds\": {},\n", cfg.rounds));
        out.push_str("      \"operations\": {\n");
        for (oi, op) in cfg.ops.iter().enumerate() {
            out.push_str(&format!("        \"{}\": {{\n", op.key));
            out.push_str(&format!(
                "          \"samples_ns\": {},\n",
                json_u128_array(&op.samples_ns)
            ));
            out.push_str(&format!("          \"median_ns\": {}\n", op.median_ns));
            out.push_str(if oi + 1 < cfg.ops.len() {
                "        },\n"
            } else {
                "        }\n"
            });
        }
        out.push_str("      }\n");
        out.push_str(if ci + 1 < results.len() {
            "    },\n"
        } else {
            "    }\n"
        });
    }
    out.push_str("  ]\n");
    out.push_str("}\n");
    out
}

fn json_output_path() -> PathBuf {
    if let Ok(p) = std::env::var("NINE65_BENCH_JSON_OUT") {
        return PathBuf::from(p);
    }
    // CARGO_MANIFEST_DIR is crates/nine65 (absolute, resolved at compile
    // time) — two levels up is the repo root, independent of the test
    // process's working directory or any CARGO_TARGET_DIR override.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../bench-results/op_timings.json")
}

#[test]
#[ignore = "timing measurement — run explicitly with --ignored --nocapture"]
fn measure_core_op_timings() {
    println!("\n=== NINE65 core operation timings (this build, this machine) ===");
    println!("| Config | N | main lanes | Encrypt ms | Add ms | Public mul ms | Symmetric mul ms | Decrypt ms |");
    println!("|---|---|---|---|---|---|---|---|");
    let results = vec![
        time_config("secure_128", SecureConfig::secure_128(), 5),
        time_config("secure_128_deep", SecureConfig::secure_128_deep(), 5),
        time_config("secure_192", SecureConfig::secure_192(), 3),
        time_config("secure_256", SecureConfig::secure_256(), 3),
    ];
    println!();

    let json = results_to_json(&results);
    let out_path = json_output_path();
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).expect("failed to create JSON output directory");
    }
    fs::write(&out_path, json).expect("failed to write op_timings JSON capture");
    println!("JSON capture written to: {}", out_path.display());
    println!("Compare against a baseline with:");
    println!(
        "  python3 scripts/check_benchmark_regression.py --current {}",
        out_path.display()
    );
}

/// WR-7 (issues #87/#88) performance evidence: the factorization-aware
/// structural screen (`dual_estimate_with_factorization`) now runs inside
/// every named `SecureConfig` constructor, in addition to the pre-existing
/// width-only estimate. This is one-time, construction-time cost -- it never
/// touches a ciphertext coefficient -- but issues #87/#88 both explicitly ask
/// for measured before/after evidence rather than an assertion that it is
/// cheap. Integer nanoseconds only, per the project's zero-float rule for
/// anything past the display line.
///
/// Run:
///   cargo test -p nine65 --test op_timings --release --features allow_insecure \
///     -- --ignored --nocapture measure_secure_config_construction_timing
#[test]
#[ignore = "timing measurement — run explicitly with --ignored --nocapture"]
fn measure_secure_config_construction_timing() {
    fn median_nanos(mut v: Vec<u128>) -> u128 {
        v.sort_unstable();
        v[v.len() / 2]
    }

    fn time_construction(name: &str, rounds: usize, build: impl Fn() -> SecureConfig) {
        let mut samples = Vec::with_capacity(rounds);
        for _ in 0..rounds {
            let t0 = Instant::now();
            let config = build();
            samples.push(t0.elapsed().as_nanos());
            std::hint::black_box(&config);
        }
        println!(
            "| `{name}` | {} ns (median of {rounds}) |",
            median_nanos(samples)
        );
    }

    println!("\n=== NINE65 SecureConfig construction timing (WR-7, this build, this machine) ===");
    println!("| Config | construction time |");
    println!("|---|---|");
    time_construction("secure_128", 50, SecureConfig::secure_128);
    time_construction("secure_128_deep", 50, SecureConfig::secure_128_deep);
    time_construction("secure_192", 50, SecureConfig::secure_192);
    time_construction("secure_256", 50, SecureConfig::secure_256);
    println!();
}
