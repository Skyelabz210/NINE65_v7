//! Multiplicative-depth chain benchmark.
//!
//! # Why this file exists
//!
//! The two regression floors for this substrate are (a) end-to-end ciphertext-op
//! latency and (b) **multiplicative depth >= 200**. Before this file, nothing in
//! `benches/` chained ciphertext multiplies at all: the only ct x ct multiply in
//! the whole bench suite (`nine65_vs_seal_comparison`, group
//! `FHE_DualRNS_K-Elimination`) re-multiplies the *same two fixed ciphertexts*
//! every iteration, which is depth 1 repeated, not depth N. The depth floor was
//! therefore unmeasurable from any benchmark.
//!
//! # What is measured, and what "depth" means here
//!
//! Depth is only meaningful when it is **correctness-gated**: a chain has reached
//! depth `k` only if the ciphertext at step `k` still decrypts to the expected
//! plaintext. Every depth counted below is verified with `decrypt_dual` against a
//! plaintext tracked in the clear. A chain stops at the first wrong decryption.
//!
//! # Provenance: this is modelled on KNOWN-GOOD PASSING tests
//!
//! The encrypt / multiply / decrypt shape is taken from two tests that were run
//! green before this bench was written:
//!
//! * `crates/nine65/src/ops/rns_fhe.rs`, `tests::test_secure_128_mul_dual_symmetric`
//!   — the canonical `secure_128` shape:
//!   `generate_keys_dual` -> `encrypt_dual` -> `mul_dual_symmetric` ->
//!   `decrypt_dual`, asserting `(a*b) % t`. Verified passing.
//! * `crates/nine65/tests/depth_and_noise.rs`, `depth_and_noise_curve_deep_chain`
//!   — the chain driver and the `generate_keys_dual_full` / `precompute_s_squared`
//!   / `mul_dual_symmetric_with_s2` shape. Verified passing (reached depth 256).
//!
//! This bench deliberately uses only `decrypt_dual`, never
//! `decrypt_dual_with_diagnostics`: the latter is `pub` only under
//! `cfg(any(test, debug_assertions))`, so depending on it would force
//! `RUSTFLAGS="-C debug-assertions=on"` on every bench invocation. Correctness of
//! the decrypted plaintext is the gate here, not the noise magnitude; the noise
//! curve itself is already measured in `tests/depth_and_noise.rs`.
//!
//! # THREE chain shapes, because "depth" is not one number
//!
//! Depth is a property of *the chain shape*, not of the scheme alone. Reporting a
//! single number invites exactly the misreading this file is meant to prevent:
//!
//! 1. `symmetric_seq`  — `ct <- ct x Enc(1)`, symmetric mode (evaluator holds the
//!    secret key). One operand is always fresh and low-noise.
//! 2. `symmetric_square` — `ct <- ct x ct`, symmetric mode. Both operands carry
//!    accumulated noise. Worst case.
//! 3. `public_seq` — `ct <- ct x Enc(1)` through `mul_dual_public`, i.e. the
//!    actual FHE threat model, where the evaluator does NOT hold the secret key
//!    and relinearization goes through the evaluation key.
//!
//! Shape 3 is the one that corresponds to "homomorphic evaluation" as the term is
//! normally used. Shape 1 requires the secret key at the evaluator, which
//! `mul_dual_symmetric` itself documents as "NOT SECURE for multi-party".
//!
//! # The anti-ladder invariant is asserted, not assumed
//!
//! This substrate does not switch moduli. K-Elimination divides the value exactly
//! and the basis does not move, so `main.len()`, `anchor.len()` and `ct.level`
//! must be **constant** across an arbitrarily long chain. Every chain below
//! asserts that. A moving lane count means the retired auto modulus-switch is
//! back, and it would silently invalidate the depth number.
//!
//! Note that "levels remaining" / "budget consumed" are NOT reported: they
//! measure a retired mechanism. See `docs/RETIRED_MECHANISMS.md`.
//!
//! # Running
//!
//! ```text
//! cargo bench -p nine65 --bench depth_chain
//! ```
//!
//! Knobs:
//! * `NINE65_DEPTH_CHAIN_MAX`  — chain ceiling (default 256; the floor to clear is 200)
//! * `NINE65_DEPTH_CHAIN_SECS` — wall-clock cap per chain (default 900)
//! * `NINE65_DEPTH_CHAIN_SURVEY=0` — skip the depth survey, time the links only

use std::time::{Duration, Instant};

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use nine65::entropy::ShadowHarvester;
use nine65::ops::rns_fhe::{
    DualRNSCiphertext, DualRNSFullKeySet, DualRNSSecretKey, RNSFHEContext,
};
use nine65::params::secure_configs::SecureConfig;

// ============================================================================
// KNOBS
// ============================================================================

/// The regression floor this bench exists to check. Stated in the project docs
/// as "multiplicative depth >= 200, achieved before CRAM".
const DEPTH_FLOOR: usize = 200;

/// Chain ceiling. Default clears the floor with margin so a chain that stops at
/// the ceiling can be reported as "ceiling, not noise".
const DEFAULT_MAX_DEPTH: usize = 256;

/// Wall-clock cap per chain.
const DEFAULT_WALL_SECS: u64 = 900;

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn max_depth() -> usize {
    env_usize("NINE65_DEPTH_CHAIN_MAX", DEFAULT_MAX_DEPTH)
}

fn wall_cap() -> Duration {
    Duration::from_secs(env_usize("NINE65_DEPTH_CHAIN_SECS", DEFAULT_WALL_SECS as usize) as u64)
}

fn survey_enabled() -> bool {
    std::env::var("NINE65_DEPTH_CHAIN_SURVEY").as_deref() != Ok("0")
}

// ============================================================================
// SETUP — shape taken from test_secure_128_mul_dual_symmetric
// ============================================================================

/// `secure_128`: N=8192, three 30-bit main lanes, five anchor lanes, t=65537.
///
/// `generate_keys_dual_full` (not `generate_keys_dual`) because the public-mode
/// chain needs `eval_key`. `mul_dual_symmetric` asserts `anchor_count >= 5`,
/// which this config satisfies.
fn ctx_and_keys() -> (RNSFHEContext, DualRNSFullKeySet) {
    let cfg = SecureConfig::secure_128();
    let ctx = RNSFHEContext::new(&cfg.config);
    let mut rng = ShadowHarvester::with_seed(42);
    let keys = ctx.generate_keys_dual_full(&mut rng);
    (ctx, keys)
}

// ============================================================================
// CHAIN DRIVER
// ============================================================================

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Stop {
    /// Decryption became incorrect — the real depth limit.
    Noise,
    /// Wall-clock cap hit while the chain was still healthy.
    Timeout,
    /// Hit the requested ceiling with the chain still healthy. The measured
    /// depth is a LOWER BOUND, not the limit.
    CeilingReached,
}

struct ChainResult {
    max_correct_depth: usize,
    stop: Stop,
    /// Wall time for the whole chain, for a per-link cost cross-check.
    elapsed: Duration,
    /// Lane shape observed at depth 0, for the anti-ladder assertion.
    lanes0: (usize, usize, usize),
}

/// Run one correctness-gated chain.
///
/// `step` advances the ciphertext one multiply and returns the new expected
/// plaintext. A depth counts as reached only if `decrypt_dual` agrees.
fn run_chain<F>(
    ctx: &RNSFHEContext,
    sk: &DualRNSSecretKey,
    title: &str,
    ct0: DualRNSCiphertext,
    m0: u64,
    mut step: F,
) -> ChainResult
where
    F: FnMut(&DualRNSCiphertext, u64) -> (DualRNSCiphertext, u64),
{
    println!("\n---- {title} ----");

    let mut ct = ct0;
    let mut expected = m0 % ctx.t;

    let lanes0 = (ct.c0.main.len(), ct.c0.anchor.len(), ct.level);
    assert_eq!(
        ctx.decrypt_dual(&ct, sk),
        expected,
        "{title}: the FRESH encryption did not decrypt — setup is broken, \
         no depth number from this chain is meaningful"
    );

    let start = Instant::now();
    let cap = wall_cap();
    let dmax = max_depth();

    let mut max_correct_depth = 0usize;
    let mut stop = Stop::CeilingReached;

    for depth in 1..=dmax {
        if start.elapsed() > cap {
            stop = Stop::Timeout;
            println!("  wall-clock cap {}s hit before depth {depth}", cap.as_secs());
            break;
        }

        let (next, next_expected) = step(&ct, expected);
        ct = next;
        expected = next_expected;

        // THE ANTI-LADDER INVARIANT. Exact division divides the value without
        // moving the basis, so the lane shape must not change. If this trips,
        // a modulus switch has come back and the depth number is meaningless.
        let lanes = (ct.c0.main.len(), ct.c0.anchor.len(), ct.level);
        assert_eq!(
            lanes, lanes0,
            "{title}: LANE SHAPE MOVED at depth {depth} \
             (main,anchor,level) {lanes0:?} -> {lanes:?}. \
             The basis must not move; a modulus switch has been reintroduced."
        );

        let got = ctx.decrypt_dual(&ct, sk);
        if got == expected {
            max_correct_depth = depth;
        } else {
            stop = Stop::Noise;
            println!("  first INCORRECT decryption at depth {depth}: got {got}, want {expected}");
            break;
        }
    }

    let elapsed = start.elapsed();
    let verdict = if max_correct_depth >= DEPTH_FLOOR {
        "MEETS floor >= 200"
    } else {
        "BELOW floor >= 200"
    };
    let bound = match stop {
        Stop::CeilingReached => " (LOWER BOUND — stopped at ceiling, not at noise)",
        Stop::Timeout => " (LOWER BOUND — stopped on wall clock, not at noise)",
        Stop::Noise => " (TRUE LIMIT — stopped at noise)",
    };
    println!(
        "  max correct depth = {max_correct_depth}  [{verdict}]{bound}\n  \
         lane shape (main,anchor,level) = {lanes0:?}, CONSTANT across chain\n  \
         wall = {:.1}s over {max_correct_depth} links",
        elapsed.as_secs_f64()
    );

    ChainResult {
        max_correct_depth,
        stop,
        elapsed,
        lanes0,
    }
}

// ============================================================================
// THE SURVEY — this is the deliverable, not the criterion timings
// ============================================================================

fn depth_survey(ctx: &RNSFHEContext, keys: &DualRNSFullKeySet) {
    let sk = &keys.secret_key;
    let s2 = ctx.precompute_s_squared(sk);
    let t = ctx.t as u128;

    println!("\n================================================================");
    println!("MULTIPLICATIVE DEPTH SURVEY — correctness-gated, secure_128");
    println!("================================================================");
    println!(
        "N={} t={} main_lanes={} anchor_lanes={} ceiling={} floor={DEPTH_FLOOR}",
        ctx.n,
        ctx.t,
        ctx.config.primes.len(),
        ctx.dual_rns.anchor.primes.len(),
        max_depth()
    );
    println!(
        "NOTE: no 'levels remaining' or 'budget consumed' is reported — those \n\
         measure the retired modulus-switching mechanism. The lane shape is \n\
         asserted CONSTANT instead; that is the anti-ladder observable."
    );

    // ---- Shape 1: symmetric, ct x Enc(1) ----
    let mut rng = ShadowHarvester::with_seed(9001);
    let ct_one = ctx.encrypt_dual(1, &keys.public_key, &mut rng);
    assert_eq!(ctx.decrypt_dual(&ct_one, sk), 1, "Enc(1) is not Enc(1)");
    let m0 = 5u64;
    let ct0 = ctx.encrypt_dual(m0, &keys.public_key, &mut rng);
    let r_sym_seq = run_chain(
        ctx,
        sk,
        "SHAPE 1  symmetric  ct <- ct x Enc(1)   [needs secret key at evaluator]",
        ct0,
        m0,
        |ct, expected| {
            (
                ctx.mul_dual_symmetric_with_s2(ct, &ct_one, sk, &s2),
                expected,
            )
        },
    );

    // ---- Shape 2: symmetric squaring, ct x ct ----
    let mut rng = ShadowHarvester::with_seed(9001);
    let m0 = 3u64;
    let ct0 = ctx.encrypt_dual(m0, &keys.public_key, &mut rng);
    let r_sym_sq = run_chain(
        ctx,
        sk,
        "SHAPE 2  symmetric  ct <- ct x ct        [worst case: both operands noisy]",
        ct0,
        m0,
        |ct, expected| {
            let next = ctx.mul_dual_symmetric_with_s2(ct, ct, sk, &s2);
            (next, ((expected as u128 * expected as u128) % t) as u64)
        },
    );

    // ---- Shape 3: public mode, ct x Enc(1) — THE ACTUAL FHE MODEL ----
    let mut rng = ShadowHarvester::with_seed(9001);
    let ct_one = ctx.encrypt_dual(1, &keys.public_key, &mut rng);
    let m0 = 5u64;
    let ct0 = ctx.encrypt_dual(m0, &keys.public_key, &mut rng);
    let r_pub_seq = run_chain(
        ctx,
        sk,
        "SHAPE 3  PUBLIC     ct <- ct x Enc(1)    [real FHE model: no secret key at evaluator]",
        ct0,
        m0,
        |ct, expected| {
            (
                ctx.mul_dual_public(ct, &ct_one, &keys.eval_key)
                    .expect("mul_dual_public returned Err"),
                expected,
            )
        },
    );

    // ---- Verdict table ----
    println!("\n================================================================");
    println!("DEPTH FLOOR VERDICT  (floor: multiplicative depth >= {DEPTH_FLOOR})");
    println!("================================================================");
    let row = |name: &str, r: &ChainResult| {
        let v = if r.max_correct_depth >= DEPTH_FLOOR {
            "MEETS"
        } else {
            "BELOW"
        };
        let per_link = if r.max_correct_depth > 0 {
            format!(
                "{:.1} ms/link",
                r.elapsed.as_secs_f64() * 1000.0 / r.max_correct_depth as f64
            )
        } else {
            "n/a".to_string()
        };
        println!(
            "  {name:<40} depth={:<5} {v:<6} stopped_by={:?}  ({per_link}, incl. decrypt gate)",
            r.max_correct_depth, r.stop
        );
    };
    row("SHAPE 1 symmetric ct x Enc(1)", &r_sym_seq);
    row("SHAPE 2 symmetric squaring ct x ct", &r_sym_sq);
    row("SHAPE 3 PUBLIC ct x Enc(1)  <- FHE model", &r_pub_seq);

    println!(
        "\n  Lane shape constant in all three chains: {:?} / {:?} / {:?}",
        r_sym_seq.lanes0, r_sym_sq.lanes0, r_pub_seq.lanes0
    );
    println!(
        "\n  READ THIS BEFORE QUOTING A DEPTH NUMBER:\n\
         \x20   Depth is a property of the CHAIN SHAPE, not of the scheme alone.\n\
         \x20   Quoting SHAPE 1 as 'the' depth of the system overstates it by the\n\
         \x20   distance between SHAPE 1 and SHAPE 3. SHAPE 3 is the configuration\n\
         \x20   that corresponds to homomorphic evaluation in the normal sense.\n\
         \x20   This bench REPORTS; it does not assert. Enforcement of the floor\n\
         \x20   belongs in the test suite, gated on the shape actually claimed."
    );
    println!("================================================================\n");
}

// ============================================================================
// CRITERION — per-link cost. The survey above is the depth deliverable.
// ============================================================================

fn bench_depth_chain(c: &mut Criterion) {
    let (ctx, keys) = ctx_and_keys();
    let sk = &keys.secret_key;
    let s2 = ctx.precompute_s_squared(sk);

    if survey_enabled() {
        depth_survey(&ctx, &keys);
    }

    let mut rng = ShadowHarvester::with_seed(9001);
    let ct_one = ctx.encrypt_dual(1, &keys.public_key, &mut rng);
    let ct_a = ctx.encrypt_dual(5, &keys.public_key, &mut rng);

    // ---- Cost of ONE link in each shape ----
    // Full-ciphertext, N=8192. MILLISECONDS. Never compare these to the
    // nanosecond lane-level ids in `timing`.
    let mut group = c.benchmark_group("depth_chain_link");
    group.sample_size(10);

    group.bench_function("symmetric_with_s2", |b| {
        b.iter(|| black_box(ctx.mul_dual_symmetric_with_s2(black_box(&ct_a), &ct_one, sk, &s2)));
    });
    group.bench_function("symmetric_plain", |b| {
        b.iter(|| black_box(ctx.mul_dual_symmetric(black_box(&ct_a), &ct_one, sk)));
    });
    group.bench_function("public", |b| {
        b.iter(|| {
            black_box(
                ctx.mul_dual_public(black_box(&ct_a), &ct_one, &keys.eval_key)
                    .expect("mul_dual_public"),
            )
        });
    });
    // The correctness gate itself, so chain wall-time can be decomposed.
    group.bench_function("decrypt_gate", |b| {
        b.iter(|| black_box(ctx.decrypt_dual(black_box(&ct_a), sk)));
    });
    group.finish();

    // ---- Chain cost vs depth: confirms per-link cost is FLAT in depth ----
    // If the basis moved, later links would get cheaper. Flatness here is the
    // timing-side echo of the lane-shape assertion.
    let mut group = c.benchmark_group("depth_chain_scaling");
    group.sample_size(10);
    for len in [1usize, 4, 16] {
        group.bench_with_input(BenchmarkId::from_parameter(len), &len, |b, &len| {
            b.iter(|| {
                let mut ct = ct_a.clone();
                for _ in 0..len {
                    ct = ctx.mul_dual_symmetric_with_s2(&ct, &ct_one, sk, &s2);
                }
                black_box(ct)
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_depth_chain);
criterion_main!(benches);
