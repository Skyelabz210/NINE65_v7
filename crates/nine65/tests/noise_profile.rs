//! # Noise profile — what noise are we actually looking at?
//!
//! An empirical measurement, not an argument. Everything below is a number
//! read off a real ciphertext with a real secret key.
//!
//! ## Which measure, and why that one
//!
//! Four things in this workspace answer to the name "noise". Only one of them
//! is a *measurement*:
//!
//! | thing | what it is | usable here |
//! |---|---|---|
//! | `FHEConfig::noise_budget()` (`params/mod.rs:410`) | closed-form estimate from `Δ`, `η`, `N`. Never looks at a ciphertext. | no — a prediction |
//! | `FHEConfig::rns_noise_budget_millibits()` (`params/mod.rs:232`) | same, in millibits | no — a prediction |
//! | `noise::budget::NoiseBudget` (`noise/mod.rs`) | an accounting model propagated *alongside* the ciphertext | no — bookkeeping |
//! | `GSOFHEContext::noise_stats()` (`ops/gso_fhe.rs:497`) | a real readout, but of `GSOCiphertext` | no — wrong ciphertext type |
//! | **`RNSFHEContext::decrypt_dual_with_diagnostics()`** (`ops/rns_fhe.rs:2529`) | **reconstructs `c0 + c1·s` off the actual limbs and returns `(decoded, margin)`** | **yes** |
//!
//! `decrypt_dual_with_diagnostics` is the one the codebase itself treats as
//! authoritative: `try_decrypt_dual` (`rns_fhe.rs:2390`) turns `margin < 0`
//! into `NoiseExhausted`. Its contract is
//!
//! ```text
//!     margin = Δ/2 - |error|          =>      |error| = Δ/2 - margin
//! ```
//!
//! so `|error|` is the noise magnitude in the same units as `Δ`, and `Δ/2` is
//! the ceiling. Every "noise" number in this file is that `|error|`, reported
//! as `1000·log2(|error|)` millibits using integer arithmetic only (workspace
//! rule A1: no floats).
//!
//! ## Two limits of the measure, respected throughout
//!
//! 1. The number is only meaningful while decryption is CORRECT. Past that the
//!    decode has landed on a different lattice point and `|error|` is measured
//!    against the wrong reference. No depth is reported as reached unless
//!    `decrypt_dual` returned the expected plaintext there.
//! 2. It needs `Q·t < 2^128`; above that `decrypt_dual_with_diagnostics` takes
//!    its `decrypt_dual_u256` fallback and returns `margin = 0`, which is not a
//!    measurement. `secure_128` (`Q·t ≈ 2^105`) satisfies this;
//!    `secure_128_deep` and up do not. `measure()` asserts the condition rather
//!    than silently reporting zeros.
//!
//! ## Running it
//!
//! `decrypt_dual_with_diagnostics` is `pub` only under
//! `cfg(any(test, debug_assertions))`, so a plain `--release` run will not
//! compile against it. Use:
//!
//! ```text
//! RUSTFLAGS="-C debug-assertions=on -C overflow-checks=off" \
//!   cargo test --release -p nine65 --test noise_profile -- --nocapture --test-threads=1
//! ```
//!
//! Knobs: `NINE65_NOISE_DEPTH` (default 64), `NINE65_NOISE_SECS` (default 600).

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::{Duration, Instant};

use exact_transcendentals::k_elim;

use nine65::entropy::ShadowHarvester;
use nine65::ops::rns_fhe::{
    DualRNSCiphertext, DualRNSFullKeySet, DualRNSPoly, DualRNSSecretKey, RNSFHEContext,
};
use nine65::params::secure_configs::SecureConfig;

// ===========================================================================
// KNOBS
// ===========================================================================

const DEFAULT_MAX_DEPTH: usize = 64;
const DEFAULT_WALL_SECS: u64 = 600;

fn max_depth() -> usize {
    std::env::var("NINE65_NOISE_DEPTH")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_DEPTH)
}

fn wall_cap() -> Duration {
    Duration::from_secs(
        std::env::var("NINE65_NOISE_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_WALL_SECS),
    )
}

// ===========================================================================
// INTEGER LOG2 IN MILLIBITS  (A1: no floats anywhere in this file)
// ===========================================================================

/// `1000·log2(x)`, integer-only. `log2_mb(0) == 0`.
fn log2_mb(x: u128) -> i64 {
    if x == 0 {
        return 0;
    }
    let b = (127 - x.leading_zeros()) as i64;
    let shift = 60i64 - b;
    let mut m: u128 = if shift >= 0 {
        x << (shift as u32)
    } else {
        x >> ((-shift) as u32)
    };
    let one: u128 = 1u128 << 60;
    let mut out = b * 1000;
    let mut w = 500i64;
    while w > 0 {
        m = (m * m) >> 60;
        if m >= (one << 1) {
            m >>= 1;
            out += w;
        }
        w /= 2;
    }
    out
}

/// Render millibits as `bits.millibits`.
fn mb(x: i64) -> String {
    let sign = if x < 0 { "-" } else { "" };
    let a = x.abs();
    format!("{sign}{}.{:03}", a / 1000, a % 1000)
}

// ===========================================================================
// THE SAMPLE
// ===========================================================================

#[derive(Clone, Debug)]
struct Sample {
    depth: usize,
    /// `poly.main.len()` — the lane count. The anti-ladder observable.
    main_lanes: usize,
    anchor_lanes: usize,
    level: usize,
    decoded: u64,
    expected: u64,
    correct: bool,
    /// `Δ/2 - margin`, the measured noise magnitude, in the units of `Δ`.
    noise_abs: u128,
    noise_mb: i64,
    /// Raw `margin`. `< 0` is the codebase's own noise-exhaustion condition.
    margin: i128,
}

fn q_at(ctx: &RNSFHEContext, lanes: usize) -> u128 {
    ctx.config.primes[..lanes]
        .iter()
        .fold(1u128, |acc, &p| acc * p as u128)
}

/// `Δ/2` — the ceiling the measure is quoted against.
fn delta_half(ctx: &RNSFHEContext, lanes: usize) -> u128 {
    (q_at(ctx, lanes) / ctx.t as u128) / 2
}

/// Read the existing diagnostic measure off a real ciphertext.
fn measure(
    ctx: &RNSFHEContext,
    ct: &DualRNSCiphertext,
    sk: &DualRNSSecretKey,
    depth: usize,
    expected: u64,
) -> Sample {
    let lanes = ct.c0.main.len();

    // Guard limit (2): above this the diagnostic returns margin = 0 from the
    // U256 fallback and there is no measurement to report.
    assert!(
        q_at(ctx, lanes)
            .checked_mul(ctx.t as u128)
            .is_some(),
        "Q*t >= 2^128 at {lanes} lanes: decrypt_dual_with_diagnostics would take \
         its U256 fallback and return margin = 0. That is not a measurement."
    );

    let dh = delta_half(ctx, lanes);
    let (decoded, margin) = ctx.decrypt_dual_with_diagnostics(ct, sk);
    let noise_abs = (dh as i128 - margin).max(0) as u128;

    Sample {
        depth,
        main_lanes: lanes,
        anchor_lanes: ct.c0.anchor.len(),
        level: ct.level,
        decoded,
        expected,
        correct: decoded == expected,
        noise_abs,
        noise_mb: log2_mb(noise_abs),
        margin,
    }
}

fn print_config(ctx: &RNSFHEContext) {
    let lanes = ctx.config.primes.len();
    println!(
        "  config     : N={} t={} main_lanes={} anchor_lanes={}",
        ctx.n,
        ctx.t,
        lanes,
        ctx.dual_rns.anchor.primes.len()
    );
    println!(
        "  log2(Q)    : {}    log2(delta/2) = CEILING = {} bits",
        mb(log2_mb(q_at(ctx, lanes))),
        mb(log2_mb(delta_half(ctx, lanes)))
    );
    println!(
        "  predicted  : FHEConfig::noise_budget() = {} bits, estimated_depth() = {}",
        ctx.config.noise_budget(),
        ctx.config.estimated_depth()
    );
}

fn header() {
    println!(
        "{:>6} | {:>5} {:>6} {:>5} | {:>11} | {:>9} | {:>11} | {}",
        "depth", "lanes", "anchor", "level", "noise bits", "d(noise)", "margin sign", "decrypt"
    );
    println!("-------+-------------------+-------------+-----------+-------------+---------------");
}

fn row(s: &Sample, prev: Option<&Sample>) {
    let d = match prev {
        Some(p) => mb(s.noise_mb - p.noise_mb),
        None => "-".to_string(),
    };
    println!(
        "{:>6} | {:>5} {:>6} {:>5} | {:>11} | {:>9} | {:>11} | {}",
        s.depth,
        s.main_lanes,
        s.anchor_lanes,
        s.level,
        mb(s.noise_mb),
        d,
        if s.margin < 0 { "NEGATIVE" } else { "positive" },
        if s.correct {
            "OK".to_string()
        } else {
            format!("WRONG got {} want {}", s.decoded, s.expected)
        },
    );
}

// ===========================================================================
// CURVE SHAPE — classified from the numbers, never rounded down
// ===========================================================================

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Shape {
    Flat,
    BoundedGrowth,
    UnboundedGrowth,
    NotMeasurable,
}

struct Curve {
    shape: Shape,
    text: String,
}

/// Classify over the depths that decrypted correctly.
///
/// The discriminator is growth of `log2(noise)` per DOUBLING of depth:
///
/// * `< 0.5` bits total over the whole run   -> FLAT
/// * `<= ~1.5` bits per doubling             -> BOUNDED GROWTH
///   (magnitude at most ~linear in depth; `log2` rises like `log2(depth)`,
///   so the ceiling is reached only at exponentially large depth)
/// * more                                     -> UNBOUNDED GROWTH
///   (magnitude super-linear; the ceiling arrives at finite, small depth)
fn classify(samples: &[Sample]) -> Curve {
    let good: Vec<&Sample> = samples.iter().filter(|s| s.correct && s.depth >= 1).collect();
    if good.len() < 4 {
        return Curve {
            shape: Shape::NotMeasurable,
            text: format!("not_measurable: only {} usable depths", good.len()),
        };
    }
    // Depth 1 is the fresh-ciphertext transient; the shape lives after it.
    let a = good[1];
    let z = good[good.len() - 1];
    let total = z.noise_mb - a.noise_mb;
    let doublings = log2_mb(z.depth as u128) - log2_mb(a.depth as u128);
    let per_doubling = if doublings > 0 {
        total * 1000 / doublings
    } else {
        0
    };
    let per_depth_step = total / ((z.depth - a.depth).max(1) as i64);

    let shape = if total.abs() < 500 {
        Shape::Flat
    } else if per_doubling <= 1500 {
        Shape::BoundedGrowth
    } else {
        Shape::UnboundedGrowth
    };

    let label = match shape {
        Shape::Flat => "FLAT",
        Shape::BoundedGrowth => "BOUNDED GROWTH (magnitude ~linear in depth)",
        Shape::UnboundedGrowth => "UNBOUNDED GROWTH (magnitude super-linear in depth)",
        Shape::NotMeasurable => "not_measurable",
    };

    Curve {
        shape,
        text: format!(
            "{label}\n      depth {} -> {}: noise {} -> {} bits \
             (total {} bits; {} bits/doubling; {} bits/depth-step)",
            a.depth,
            z.depth,
            mb(a.noise_mb),
            mb(z.noise_mb),
            mb(total),
            mb(per_doubling),
            mb(per_depth_step),
        ),
    }
}

// ===========================================================================
// EXACT DIVISION — residue-native, basis-preserving
// ===========================================================================
//
// There is no `div_plain_dual` on `RNSFHEContext`, so the per-lane exact
// division is assembled here from `exact_transcendentals::k_elim`, the same
// primitive `basis_invariance.rs` uses. Four lines, no reconstruction, no
// cross-lane carry, no lane dropped, `level` untouched.

fn lane_reciprocal(d: u64, prime: u64) -> u64 {
    let inv = k_elim::reciprocal_lanewise(&[d as i128], &[prime as i128])
        .unwrap_or_else(|| panic!("divisor {d} is not a unit on lane {prime}"));
    inv[0] as u64
}

fn divide_lane(limb: &[u64], prime: u64, d: u64) -> Vec<u64> {
    let inv = lane_reciprocal(d, prime) as u128;
    let p = prime as u128;
    limb.iter()
        .map(|&r| ((r as u128 * inv) % p) as u64)
        .collect()
}

fn exact_divide_poly(ctx: &RNSFHEContext, poly: &DualRNSPoly, d: u64) -> DualRNSPoly {
    DualRNSPoly {
        main: poly
            .main
            .iter()
            .enumerate()
            .map(|(i, limb)| divide_lane(limb, ctx.config.primes[i], d))
            .collect(),
        anchor: poly
            .anchor
            .iter()
            .enumerate()
            .map(|(j, limb)| divide_lane(limb, ctx.dual_rns.anchor.primes[j], d))
            .collect(),
        n: poly.n,
    }
}

fn exact_divide(ctx: &RNSFHEContext, ct: &DualRNSCiphertext, d: u64) -> DualRNSCiphertext {
    DualRNSCiphertext {
        c0: exact_divide_poly(ctx, &ct.c0, d),
        c1: exact_divide_poly(ctx, &ct.c1, d),
        // NOT `level - 1`. Nothing was consumed, so nothing is decremented.
        level: ct.level,
    }
}

// ===========================================================================
// CHAIN DRIVER
// ===========================================================================

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Stop {
    /// Decryption became incorrect. Noise won.
    Noise,
    /// A step panicked (this is the signature of the vestigial ladder /
    /// sbni out-of-bounds, if it is still live).
    Panic,
    /// Wall-clock cap hit with the chain still healthy.
    Timeout,
    /// Requested depth exhausted with the chain still healthy.
    DepthLimit,
}

struct ChainResult {
    samples: Vec<Sample>,
    max_correct_depth: usize,
    stop: Stop,
    panic_depth: Option<usize>,
    elapsed: Duration,
}

fn run_chain<F>(
    ctx: &RNSFHEContext,
    sk: &DualRNSSecretKey,
    title: &str,
    ct0: DualRNSCiphertext,
    m0: u64,
    dmax: usize,
    mut step: F,
) -> ChainResult
where
    F: FnMut(&DualRNSCiphertext, u64) -> (DualRNSCiphertext, u64),
{
    println!("\n----------------------------------------------------------------");
    println!("{title}");
    println!("----------------------------------------------------------------");
    print_config(ctx);
    header();

    let mut ct = ct0;
    let mut expected = m0 % ctx.t;

    let mut samples = vec![measure(ctx, &ct, sk, 0, expected)];
    row(&samples[0], None);
    assert!(samples[0].correct, "{title}: fresh encryption did not decrypt");

    let start = Instant::now();
    let cap = wall_cap();
    let mut max_correct_depth = 0usize;
    let mut stop = Stop::DepthLimit;
    let mut panic_depth = None;

    for depth in 1..=dmax {
        if start.elapsed() > cap {
            stop = Stop::Timeout;
            println!("--  wall-clock cap {}s hit before depth {depth}", cap.as_secs());
            break;
        }

        let stepped = catch_unwind(AssertUnwindSafe(|| step(&ct, expected)));
        let (next, next_expected) = match stepped {
            Ok(v) => v,
            Err(_) => {
                stop = Stop::Panic;
                panic_depth = Some(depth);
                println!("--  PANIC while computing depth {depth}");
                break;
            }
        };
        ct = next;
        expected = next_expected;

        let s = measure(ctx, &ct, sk, depth, expected);
        let correct = s.correct;
        if depth <= 20 || depth % 8 == 0 || depth == dmax || !correct {
            row(&s, samples.last());
        }
        samples.push(s);

        if correct {
            max_correct_depth = depth;
        } else {
            stop = Stop::Noise;
            println!("--  first INCORRECT decryption at depth {depth}");
            break;
        }
    }

    let elapsed = start.elapsed();
    let curve = classify(&samples);
    println!(
        "\n  max depth with CORRECT decryption : {max_correct_depth}\n  \
           stopped by                        : {stop:?}\n  \
           wall clock                        : {}s\n  \
           CURVE SHAPE                       : {}",
        elapsed.as_secs(),
        curve.text
    );

    ChainResult {
        samples,
        max_correct_depth,
        stop,
        panic_depth,
        elapsed,
    }
}

/// The anti-ladder observable: the lane set must not move anywhere in a chain.
fn assert_lanes_constant(samples: &[Sample], what: &str) {
    let (m0, a0, l0) = (
        samples[0].main_lanes,
        samples[0].anchor_lanes,
        samples[0].level,
    );
    for s in samples {
        assert_eq!(
            s.main_lanes, m0,
            "{what}: MAIN LANE COUNT MOVED at depth {} ({m0} -> {}) — the ladder is back",
            s.depth, s.main_lanes
        );
        assert_eq!(s.anchor_lanes, a0, "{what}: anchor lanes moved at depth {}", s.depth);
        assert_eq!(s.level, l0, "{what}: ct.level moved at depth {}", s.depth);
    }
    println!("  LANES CONSTANT over 0..={}: main={m0} anchor={a0} level={l0}", samples.last().unwrap().depth);
}

// ===========================================================================
// SETUP
// ===========================================================================

/// `secure_128`: N=8192, three ~30-bit main lanes, five anchor lanes, t=65537.
/// The deepest shipped parameter set for which the existing measure is
/// actually available (`Q·t ≈ 2^105.3 < 2^128`).
fn ctx_and_keys() -> (RNSFHEContext, DualRNSFullKeySet) {
    let cfg = SecureConfig::secure_128();
    let ctx = RNSFHEContext::new(&cfg.config);
    let mut rng = ShadowHarvester::with_seed(42);
    let keys = ctx.generate_keys_dual_full(&mut rng);
    (ctx, keys)
}

// ===========================================================================
// (1) BASELINE — the noise of a fresh encryption
// ===========================================================================

#[test]
fn noise_profile_1_fresh_encryption_baseline() {
    let (ctx, keys) = ctx_and_keys();
    let sk = &keys.secret_key;
    let mut rng = ShadowHarvester::with_seed(7);

    println!("\n================================================================");
    println!("(1) BASELINE — fresh Enc(m), measure = decrypt_dual_with_diagnostics");
    println!("================================================================");
    print_config(&ctx);
    println!();
    println!(
        "{:>8} | {:>12} | {:>14} | {:>10} | {}",
        "m", "noise bits", "noise/(delta/2)", "margin>0", "decrypt"
    );
    println!("---------+--------------+----------------+------------+---------");

    let lanes = ctx.config.primes.len();
    let dh = delta_half(&ctx, lanes);
    let ceiling_mb = log2_mb(dh);
    let mut fresh_mb = Vec::new();

    for m in [0u64, 1, 2, 5, 42, 1000, 30000] {
        let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
        let s = measure(&ctx, &ct, sk, 0, m);
        // ppm of the ceiling, integer-only.
        let ppm = if dh == 0 { 0 } else { (s.noise_abs * 1_000_000) / dh };
        println!(
            "{:>8} | {:>12} | {:>10}ppm | {:>10} | {}",
            m,
            mb(s.noise_mb),
            ppm,
            s.margin > 0,
            if s.correct { "OK" } else { "WRONG" }
        );
        assert!(s.correct, "fresh Enc({m}) did not decrypt");
        assert!(s.margin > 0, "fresh Enc({m}) has non-positive margin");
        fresh_mb.push(s.noise_mb);
    }

    let lo = *fresh_mb.iter().min().unwrap();
    let hi = *fresh_mb.iter().max().unwrap();
    println!(
        "\n  fresh-encryption noise : {} .. {} bits\n  \
           ceiling  log2(delta/2) : {} bits\n  \
           headroom at depth 0    : {} .. {} bits",
        mb(lo),
        mb(hi),
        mb(ceiling_mb),
        mb(ceiling_mb - hi),
        mb(ceiling_mb - lo),
    );
}

// ===========================================================================
// (2) THE CHAIN — multiplication depth, no division
// ===========================================================================

/// Public mode (`mul_dual_public`) — the real FHE model, and the exact call
/// site the vestigial Step-5 modulus switch used to sit in. If the ladder is
/// live this chain panics in `sbni::inject_dual_in_place` at depth 2-3 and
/// `Stop::Panic` records the depth.
#[test]
fn noise_profile_2_multiplication_chain_public() {
    let (ctx, keys) = ctx_and_keys();
    let sk = &keys.secret_key;
    let mut rng = ShadowHarvester::with_seed(9001);

    println!("\n================================================================");
    println!("(2) MULTIPLY CHAIN — public mode, no division");
    println!("================================================================");

    let ct_one = ctx.encrypt_dual(1, &keys.public_key, &mut rng);
    assert_eq!(ctx.decrypt_dual(&ct_one, sk), 1, "Enc(1) is not Enc(1)");

    let m0 = 5u64;
    let ct0 = ctx.encrypt_dual(m0, &keys.public_key, &mut rng);

    let r = run_chain(
        &ctx,
        sk,
        "ct x Enc(1) through mul_dual_public",
        ct0,
        m0,
        max_depth(),
        |ct, e| {
            (
                ctx.mul_dual_public(ct, &ct_one, &keys.eval_key)
                    .expect("mul_dual_public returned Err"),
                e,
            )
        },
    );

    assert_lanes_constant(&r.samples, "public chain");
    if let Some(d) = r.panic_depth {
        panic!("public chain PANICKED at depth {d} — the vestigial ladder is live");
    }
    assert!(r.max_correct_depth >= 1, "public mode died before one multiply");
}

/// Symmetric mode — same tensor+rescale core, cheaper relinearization, so the
/// chain reaches further per second of wall clock. Used for the deep push.
#[test]
fn noise_profile_3_multiplication_chain_symmetric() {
    let (ctx, keys) = ctx_and_keys();
    let sk = &keys.secret_key;
    let s2 = ctx.precompute_s_squared(sk);
    let mut rng = ShadowHarvester::with_seed(9001);

    println!("\n================================================================");
    println!("(3) MULTIPLY CHAIN — symmetric mode, no division");
    println!("================================================================");

    let ct_one = ctx.encrypt_dual(1, &keys.public_key, &mut rng);
    let m0 = 5u64;
    let ct0 = ctx.encrypt_dual(m0, &keys.public_key, &mut rng);

    let r = run_chain(
        &ctx,
        sk,
        "ct x Enc(1) through mul_dual_symmetric_with_s2",
        ct0,
        m0,
        max_depth(),
        |ct, e| (ctx.mul_dual_symmetric_with_s2(ct, &ct_one, sk, &s2), e),
    );

    assert_lanes_constant(&r.samples, "symmetric chain");
    assert!(r.max_correct_depth >= 1);
}

/// Repeated squaring — worst case. Both operands carry accumulated noise AND
/// the plaintext itself grows, so this bounds the chain from the other side.
#[test]
fn noise_profile_4_squaring_chain() {
    let (ctx, keys) = ctx_and_keys();
    let sk = &keys.secret_key;
    let s2 = ctx.precompute_s_squared(sk);
    let t = ctx.t as u128;
    let mut rng = ShadowHarvester::with_seed(9001);

    println!("\n================================================================");
    println!("(4) SQUARING CHAIN — worst case (both operands noisy, plaintext grows)");
    println!("================================================================");

    let m0 = 3u64;
    let ct0 = ctx.encrypt_dual(m0, &keys.public_key, &mut rng);

    let r = run_chain(
        &ctx,
        sk,
        "ct x ct repeated squaring",
        ct0,
        m0,
        max_depth().min(32),
        |ct, e| {
            (
                ctx.mul_dual_symmetric_with_s2(ct, ct, sk, &s2),
                ((e as u128 * e as u128) % t) as u64,
            )
        },
    );

    assert_lanes_constant(&r.samples, "squaring chain");
}

// ===========================================================================
// (5) THE LOSSLESS-RESCALE HYPOTHESIS, MEASURED DIRECTLY
// ===========================================================================

/// Does exact division reduce the MEASURED noise, and by how much relative to
/// the divisor?
///
/// Protocol per divisor `d`:
///   1. `Enc(m)`                  -> measure  (noise `e`)
///   2. `mul_plain_dual(., d)`    -> measure  (the underlying integer is now
///                                             exactly `d·(Δm + e)`, hence
///                                             exactly divisible by `d`)
///   3. `exact_divide(., d)`      -> measure
///
/// The hypothesis says step 3 is step 2 minus exactly `log2(d)` bits, with NO
/// rounding term — i.e. `noise_abs` returns to its step-1 value bit for bit.
/// Classical modulus switching cannot do this: its rounding adds
/// `~||s||·sqrt(N)` regardless of `d`.
#[test]
fn noise_profile_5_exact_division_vs_divisor() {
    let (ctx, keys) = ctx_and_keys();
    let sk = &keys.secret_key;
    let mut rng = ShadowHarvester::with_seed(31337);

    // Units on every lane, and `d·m < t/2` so the diagnostic's positive branch
    // is the one exercised.
    const DIVISORS: &[u64] = &[2, 3, 5, 7, 11, 23, 97, 1009, 4093, 16381];

    println!("\n================================================================");
    println!("(5) EXACT DIVISION vs MEASURED NOISE — the lossless-rescale hypothesis");
    println!("================================================================");
    print_config(&ctx);
    println!();
    println!(
        "{:>7} | {:>11} | {:>11} | {:>11} | {:>10} | {:>10} | {:>8} | {}",
        "d", "noise e", "after x d", "after / d", "d(x d)", "d(/ d)", "log2 d", "bit-exact"
    );
    println!(
        "--------+-------------+-------------+-------------+------------+------------+----------+-----------"
    );

    let mut worst_dev_mb = 0i64;
    let mut all_bit_exact = true;

    for &d in DIVISORS {
        let m = 1u64;
        let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
        let before = measure(&ctx, &ct, sk, 0, m);
        assert!(before.correct, "d={d}: fresh ciphertext did not decrypt");

        let scaled = ctx.mul_plain_dual(&ct, d);
        let after_mul = measure(&ctx, &scaled, sk, 0, d * m);
        assert!(
            after_mul.correct,
            "d={d}: mul_plain_dual(Enc({m}), {d}) decoded {} not {}",
            after_mul.decoded,
            d * m
        );

        let divided = exact_divide(&ctx, &scaled, d);
        let after_div = measure(&ctx, &divided, sk, 0, m);

        // The basis did not move.
        assert_eq!(divided.c0.main.len(), ct.c0.main.len(), "d={d}: lane dropped");
        assert_eq!(divided.c0.anchor.len(), ct.c0.anchor.len(), "d={d}: anchor dropped");
        assert_eq!(divided.level, ct.level, "d={d}: level decremented");
        assert!(
            after_div.correct,
            "d={d}: exact division did not return Enc({m}); got {}",
            after_div.decoded
        );

        let log2d = log2_mb(d as u128);
        let mul_delta = after_mul.noise_mb - before.noise_mb;
        let div_delta = after_div.noise_mb - after_mul.noise_mb;
        let bit_exact = after_div.noise_abs == before.noise_abs;
        all_bit_exact &= bit_exact;
        worst_dev_mb = worst_dev_mb.max((div_delta + log2d).abs());

        println!(
            "{:>7} | {:>11} | {:>11} | {:>11} | {:>10} | {:>10} | {:>8} | {}",
            d,
            mb(before.noise_mb),
            mb(after_mul.noise_mb),
            mb(after_div.noise_mb),
            mb(mul_delta),
            mb(div_delta),
            mb(log2d),
            bit_exact
        );
    }

    println!(
        "\n  worst |d(/d) + log2(d)| : {} bits\n  \
           bit-exact round trip     : {all_bit_exact}",
        mb(worst_dev_mb)
    );
    println!(
        "  => division by d reduces the measured noise by EXACTLY log2(d) bits,\n     \
        with no rounding term at all. This is the lossless-rescale mechanism."
    );

    assert!(
        worst_dev_mb <= 5,
        "division did NOT reduce noise by log2(d): worst deviation {} bits",
        mb(worst_dev_mb)
    );
    assert!(all_bit_exact, "division added a rounding term somewhere");
}

/// The precondition, stated numerically: the divisor must divide the WHOLE
/// underlying integer `Δm + e`, not just the plaintext. This is the boundary
/// of the mechanism and it is why (5) cannot simply be applied to a noisy
/// ciphertext to shrink its noise.
#[test]
fn noise_profile_6_division_requires_the_noise_to_be_divisible() {
    let (ctx, keys) = ctx_and_keys();
    let sk = &keys.secret_key;
    let mut rng = ShadowHarvester::with_seed(4242);

    println!("\n================================================================");
    println!("(6) PRECONDITION — divide when only the PLAINTEXT is divisible by d");
    println!("================================================================");

    let d = 4u64;
    let m = 12u64; // d | m, but d does not divide e
    let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
    let before = measure(&ctx, &ct, sk, 0, m);
    assert!(before.correct);

    let divided = exact_divide(&ctx, &ct, d);
    let after = measure(&ctx, &divided, sk, 0, m / d);

    println!(
        "  Enc({m}) / {d}: noise {} -> {} bits; decoded {} (wanted {}); correct={}",
        mb(before.noise_mb),
        mb(after.noise_mb),
        after.decoded,
        m / d,
        after.correct
    );
    println!(
        "  lanes untouched: main {} -> {}, anchor {} -> {}, level {} -> {}",
        ct.c0.main.len(),
        divided.c0.main.len(),
        ct.c0.anchor.len(),
        divided.c0.anchor.len(),
        ct.level,
        divided.level
    );
    println!(
        "  => the basis never moves, but the VALUE is destroyed unless d divides\n     \
        the full integer. Noise is not of that form, so exact division cannot be\n     \
        pointed at accumulated noise directly."
    );

    // Unconditional part: the basis does not move either way.
    assert_eq!(divided.c0.main.len(), ct.c0.main.len());
    assert_eq!(divided.c0.anchor.len(), ct.c0.anchor.len());
    assert_eq!(divided.level, ct.level);
}

// ===========================================================================
// (7) TWO CURVES — with and without exact division after every multiply
// ===========================================================================

/// The comparison the depth argument turns on.
///
/// Chain A: multiply only.
/// Chain B: multiply, then `x d` then exact-divide by `d`. That scale-then-
///          divide pair is the only shape in which exact division applies to a
///          chain step, because (6) shows the underlying integer has to be
///          divisible and this is what makes it so. The plaintext is preserved
///          at every step, so the two chains are comparable depth for depth.
///
/// If exact division buys depth, B's curve sits below A's and B reaches deeper.
#[test]
fn noise_profile_7_two_curves_compared() {
    let (ctx, keys) = ctx_and_keys();
    let sk = &keys.secret_key;
    let s2 = ctx.precompute_s_squared(sk);
    let d = 97u64;
    let dmax = max_depth();

    println!("\n================================================================");
    println!("(7) TWO CURVES — multiply-only vs multiply-then-exact-divide");
    println!("================================================================");

    let mut rng_a = ShadowHarvester::with_seed(9001);
    let ct_one_a = ctx.encrypt_dual(1, &keys.public_key, &mut rng_a);
    let m0 = 5u64;
    let ct_a = ctx.encrypt_dual(m0, &keys.public_key, &mut rng_a);
    let a = run_chain(&ctx, sk, "CHAIN A — multiply only", ct_a, m0, dmax, |ct, e| {
        (ctx.mul_dual_symmetric_with_s2(ct, &ct_one_a, sk, &s2), e)
    });

    // Identical RNG stream so the two chains start from the same ciphertext.
    let mut rng_b = ShadowHarvester::with_seed(9001);
    let ct_one_b = ctx.encrypt_dual(1, &keys.public_key, &mut rng_b);
    let ct_b = ctx.encrypt_dual(m0, &keys.public_key, &mut rng_b);
    let b = run_chain(
        &ctx,
        sk,
        &format!("CHAIN B — multiply, then x {d} and exact-divide by {d}"),
        ct_b,
        m0,
        dmax,
        |ct, e| {
            let mul = ctx.mul_dual_symmetric_with_s2(ct, &ct_one_b, sk, &s2);
            let scaled = ctx.mul_plain_dual(&mul, d);
            (exact_divide(&ctx, &scaled, d), e)
        },
    );

    assert_lanes_constant(&a.samples, "CHAIN A");
    assert_lanes_constant(&b.samples, "CHAIN B");

    println!("\n  SIDE BY SIDE (measured noise, bits)");
    println!("{:>6} | {:>12} | {:>12} | {:>12}", "depth", "A mul", "B mul+/d", "B - A");
    println!("-------+--------------+--------------+-------------");
    let n = a.samples.len().min(b.samples.len());
    let mut identical = true;
    for i in 0..n {
        let (x, y) = (&a.samples[i], &b.samples[i]);
        if x.correct && y.correct && x.noise_abs != y.noise_abs {
            identical = false;
        }
        if i <= 12 || i % 8 == 0 || !x.correct || !y.correct {
            println!(
                "{:>6} | {:>12} | {:>12} | {:>12}",
                i,
                mb(x.noise_mb),
                mb(y.noise_mb),
                mb(y.noise_mb - x.noise_mb)
            );
        }
    }

    println!(
        "\n  CHAIN A: max correct depth {} ({:?}) in {}s\n  \
           CHAIN B: max correct depth {} ({:?}) in {}s\n  \
           curves identical at every shared depth: {identical}",
        a.max_correct_depth,
        a.stop,
        a.elapsed.as_secs(),
        b.max_correct_depth,
        b.stop,
        b.elapsed.as_secs(),
    );

    if b.max_correct_depth > a.max_correct_depth {
        println!("  => exact division BOUGHT {} extra depth", b.max_correct_depth - a.max_correct_depth);
    } else if b.max_correct_depth == a.max_correct_depth {
        println!(
            "  => exact division bought NO extra depth. The x d / / d pair is a\n     \
            bit-exact round trip: it removes exactly the log2({d}) bits it added\n     \
            and leaves the multiplication's own noise untouched."
        );
    } else {
        println!("  => exact division COST {} depth", a.max_correct_depth - b.max_correct_depth);
    }
}

// ===========================================================================
// (8) THE VERDICT — one place that prints the answer
// ===========================================================================

/// Push the cheapest chain as far as the knobs allow and print the shape,
/// the max correct depth, and what stopped it.
#[test]
fn noise_profile_8_verdict() {
    let (ctx, keys) = ctx_and_keys();
    let sk = &keys.secret_key;
    let s2 = ctx.precompute_s_squared(sk);
    let mut rng = ShadowHarvester::with_seed(9001);

    println!("\n================================================================");
    println!("(8) VERDICT — deepest push");
    println!("================================================================");

    let ct_one = ctx.encrypt_dual(1, &keys.public_key, &mut rng);
    let m0 = 5u64;
    let ct0 = ctx.encrypt_dual(m0, &keys.public_key, &mut rng);

    let r = run_chain(
        &ctx,
        sk,
        "deepest reachable chain",
        ct0,
        m0,
        max_depth(),
        |ct, e| (ctx.mul_dual_symmetric_with_s2(ct, &ct_one, sk, &s2), e),
    );

    assert_lanes_constant(&r.samples, "verdict chain");

    let curve = classify(&r.samples);
    let ceiling_mb = log2_mb(delta_half(&ctx, ctx.config.primes.len()));
    let last = r
        .samples
        .iter()
        .filter(|s| s.correct)
        .last()
        .expect("no correct sample");

    println!("\n  ============================================================");
    println!("  MAX DEPTH WITH CORRECT DECRYPTION : {}", r.max_correct_depth);
    println!("  STOPPED BY                        : {:?}", r.stop);
    println!("  CURVE SHAPE                       : {:?}", curve.shape);
    println!("  NOISE AT MAX DEPTH                : {} bits", mb(last.noise_mb));
    println!("  CEILING log2(delta/2)             : {} bits", mb(ceiling_mb));
    println!("  HEADROOM REMAINING                : {} bits", mb(ceiling_mb - last.noise_mb));
    println!("  ============================================================");

    // Never report a depth as reached unless it decrypted.
    for s in r.samples.iter().take(r.max_correct_depth + 1) {
        assert!(s.correct, "depth {} counted but decrypted wrong", s.depth);
    }
    assert_ne!(
        curve.shape,
        Shape::NotMeasurable,
        "not enough usable depths to classify the curve"
    );
}

// ===========================================================================
// (9) WHAT IS THE NOISE, MECHANICALLY? — additive term or multiplicative factor
// ===========================================================================

/// A log-scale curve cannot distinguish "each multiply ADDS a fixed quantity"
/// from "each multiply MULTIPLIES by a fixed factor" by eye, and the two have
/// completely different consequences for depth:
///
/// * additive `e_k = k·c`      -> `log2` rises like `log2(depth)`, ceiling at
///                                depth `~ (Δ/2)/c`  — huge but finite
/// * multiplicative `e_k = f^k` -> `log2` rises LINEARLY in depth, ceiling at
///                                depth `~ log2(Δ/2)/log2(f)` — small
///
/// So this measures the increment in RAW units. If `e_{k+1} - e_k` is constant
/// the term is additive; if `e_{k+1} / e_k` is constant it is multiplicative.
#[test]
fn noise_profile_9_per_multiply_increment() {
    let (ctx, keys) = ctx_and_keys();
    let sk = &keys.secret_key;
    let s2 = ctx.precompute_s_squared(sk);
    let mut rng = ShadowHarvester::with_seed(9001);

    println!("\n================================================================");
    println!("(9) IS THE PER-MULTIPLY NOISE ADDITIVE OR MULTIPLICATIVE?");
    println!("================================================================");
    print_config(&ctx);

    let ct_one = ctx.encrypt_dual(1, &keys.public_key, &mut rng);
    let m0 = 5u64;
    let mut ct = ctx.encrypt_dual(m0, &keys.public_key, &mut rng);

    let depth = max_depth().min(64);
    let mut prev = measure(&ctx, &ct, sk, 0, m0);
    let mut samples = vec![prev.clone()];

    println!(
        "\n{:>6} | {:>11} | {:>16} | {:>16} | {}",
        "depth", "log2 e_k", "log2(e_k - e_k-1)", "log2(e_k / e_k-1)", "decrypt"
    );
    println!("-------+-------------+------------------+------------------+---------");

    for k in 1..=depth {
        ct = ctx.mul_dual_symmetric_with_s2(&ct, &ct_one, sk, &s2);
        let s = measure(&ctx, &ct, sk, k, m0);
        let raw_diff = s.noise_abs.saturating_sub(prev.noise_abs);
        let ratio_mb = s.noise_mb - prev.noise_mb;
        if k <= 12 || k % 8 == 0 || k == depth || !s.correct {
            println!(
                "{:>6} | {:>11} | {:>16} | {:>16} | {}",
                k,
                mb(s.noise_mb),
                mb(log2_mb(raw_diff)),
                mb(ratio_mb),
                if s.correct { "OK" } else { "WRONG" }
            );
        }
        samples.push(s.clone());
        prev = s;
        if !prev.correct {
            break;
        }
    }

    // Spread of the raw increment over the settled part of the chain.
    let settled: Vec<i64> = samples
        .windows(2)
        .skip(3)
        .filter(|w| w[1].correct)
        .map(|w| log2_mb(w[1].noise_abs.saturating_sub(w[0].noise_abs)))
        .collect();
    assert!(!settled.is_empty(), "no settled increments recorded");
    let lo = *settled.iter().min().unwrap();
    let hi = *settled.iter().max().unwrap();

    println!(
        "\n  raw per-multiply increment over depths 4..{}: log2 in [{}, {}] bits\n  \
           spread = {} bits",
        settled.len() + 3,
        mb(lo),
        mb(hi),
        mb(hi - lo)
    );

    let ceiling_mb = log2_mb(delta_half(&ctx, ctx.config.primes.len()));
    if hi - lo < 2000 {
        // Constant additive term c. Ceiling reached at depth (Δ/2)/c.
        let depth_mb = ceiling_mb - hi;
        println!(
            "  => ADDITIVE. Each multiply adds a FIXED ~2^{} of noise; the noise\n     \
            magnitude is LINEAR in depth. Ceiling {} bits is reached at depth\n     \
            ~2^{} = the noise curve is BOUNDED GROWTH, not flat and not exponential.",
            mb(hi),
            mb(ceiling_mb),
            mb(depth_mb)
        );
    } else {
        println!("  => NOT a constant additive term; see the ratio column.");
    }
}

// ===========================================================================
// (10) PUBLIC MODE, MORE DATA POINTS — sweep t to widen the measurable window
// ===========================================================================

/// At `t = 65537` the public chain only affords two measurable depths before
/// the ceiling, which is not enough points to classify a shape. `t` sits on
/// both sides of the problem — it divides `Q` to set the ceiling `Δ/2 = Q/2t`,
/// and it multiplies the per-level noise — so lowering it widens the window
/// from both ends. Same `N`, same primes, same lane count; only `t` moves.
#[test]
fn noise_profile_10_public_mode_t_sweep() {
    use nine65::params::FHEConfig;

    println!("\n================================================================");
    println!("(10) PUBLIC MODE — per-level noise increment across t");
    println!("================================================================");
    println!(
        "\n{:>7} | {:>10} | {:>8} | {:>36} | {:>7} | {:>9} | {}",
        "t", "ceiling", "max depth", "first 6 d(log2 noise)", "last d", "end noise", "stop"
    );
    println!(
        "--------+------------+----------+--------------------------------------+---------+-----------+-------"
    );

    let primes = vec![998244353u64, 985661441, 754974721];
    let mut increments_by_t: Vec<(u64, Vec<i64>, usize)> = Vec::new();

    for t in [3u64, 17, 257, 4099, 65537] {
        let cfg = FHEConfig::custom(8192, primes.clone(), t, 3).expect("custom config rejected");
        let ctx = RNSFHEContext::new(&cfg);
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual_full(&mut rng);
        let sk = &keys.secret_key;

        let mut rng = ShadowHarvester::with_seed(9001);
        let ct_one = ctx.encrypt_dual(1, &keys.public_key, &mut rng);
        let mut ct = ctx.encrypt_dual(1, &keys.public_key, &mut rng);

        let ceiling_mb = log2_mb(delta_half(&ctx, ctx.config.primes.len()));
        let mut prev = measure(&ctx, &ct, sk, 0, 1);
        assert!(prev.correct, "t={t}: fresh encryption did not decrypt");

        let mut incs = Vec::new();
        let mut max_correct = 0usize;
        let mut stop = "DepthLimit";

        for k in 1..=max_depth() {
            let stepped = catch_unwind(AssertUnwindSafe(|| {
                ctx.mul_dual_public(&ct, &ct_one, &keys.eval_key)
            }));
            let next = match stepped {
                Ok(Ok(v)) => v,
                Ok(Err(_)) => {
                    stop = "Err";
                    break;
                }
                Err(_) => {
                    stop = "PANIC";
                    break;
                }
            };
            ct = next;
            let s = measure(&ctx, &ct, sk, k, 1);
            if !s.correct {
                stop = "Noise";
                break;
            }
            max_correct = k;
            incs.push(s.noise_mb - prev.noise_mb);
            prev = s;
        }

        // First six increments (the transient) then the last one (the tail).
        let shown: Vec<String> = incs.iter().take(6).map(|&i| mb(i)).collect();
        let tail = incs.last().map(|&i| mb(i)).unwrap_or_else(|| "-".into());
        println!(
            "{:>7} | {:>10} | {:>8} | {:>36} | {:>7} | {:>9} | {}",
            t,
            mb(ceiling_mb),
            max_correct,
            format!("{} ...", shown.join(" ")),
            tail,
            mb(prev.noise_mb),
            stop
        );
        increments_by_t.push((t, incs, max_correct));
    }

    println!(
        "\n  Read the increment column: a CONSTANT per-level increment in log2\n  \
        means the noise MAGNITUDE is multiplied by a fixed factor at every\n  \
        level, i.e. it grows EXPONENTIALLY in depth. A shrinking increment\n  \
        means additive accumulation."
    );

    for (t, incs, maxd) in &increments_by_t {
        if incs.len() >= 2 {
            let lo = *incs.iter().min().unwrap();
            let hi = *incs.iter().max().unwrap();
            println!(
                "    t={t:>6}: {} levels, increment in [{}, {}] bits, spread {} bits -> {}",
                maxd,
                mb(lo),
                mb(hi),
                mb(hi - lo),
                if hi - lo < 3000 {
                    "CONSTANT factor per level => EXPONENTIAL magnitude growth"
                } else {
                    "non-constant"
                }
            );
        } else {
            println!("    t={t:>6}: {maxd} levels — too few points to classify");
        }
    }
}

// ===========================================================================
// (11) PUBLIC MODE — the same increment question, in raw units
// ===========================================================================

/// (10) shows the public-mode log-increment collapsing to `0.000` bits, which
/// on its own is ambiguous: it is what you see both when the noise has stopped
/// growing AND when it is still growing additively from a much higher plateau
/// (a `2^43` increment on a `2^70` value is `6e-7` bits). Raw units settle it.
///
/// `t = 257` because at `t = 65537` public mode affords one measurable level.
#[test]
fn noise_profile_11_public_mode_raw_increment() {
    use nine65::params::FHEConfig;

    let t = 257u64;
    let cfg = FHEConfig::custom(8192, vec![998244353u64, 985661441, 754974721], t, 3)
        .expect("custom config rejected");
    let ctx = RNSFHEContext::new(&cfg);
    let mut rng = ShadowHarvester::with_seed(42);
    let keys = ctx.generate_keys_dual_full(&mut rng);
    let sk = &keys.secret_key;

    println!("\n================================================================");
    println!("(11) PUBLIC MODE — raw per-multiply increment (t={t})");
    println!("================================================================");
    print_config(&ctx);

    let mut rng = ShadowHarvester::with_seed(9001);
    let ct_one = ctx.encrypt_dual(1, &keys.public_key, &mut rng);
    let mut ct = ctx.encrypt_dual(1, &keys.public_key, &mut rng);

    let mut prev = measure(&ctx, &ct, sk, 0, 1);
    assert!(prev.correct);

    println!(
        "\n{:>6} | {:>11} | {:>18} | {:>18} | {}",
        "depth", "log2 e_k", "log2(e_k - e_k-1)", "log2(e_k / e_k-1)", "decrypt"
    );
    println!("-------+-------------+--------------------+--------------------+---------");

    let depth = max_depth();
    let mut settled: Vec<i64> = Vec::new();
    let mut max_correct = 0usize;

    for k in 1..=depth {
        ct = ctx
            .mul_dual_public(&ct, &ct_one, &keys.eval_key)
            .expect("mul_dual_public returned Err");
        let s = measure(&ctx, &ct, sk, k, 1);
        let raw = s.noise_abs.saturating_sub(prev.noise_abs);
        if k <= 10 || k % 32 == 0 || k == depth || !s.correct {
            println!(
                "{:>6} | {:>11} | {:>18} | {:>18} | {}",
                k,
                mb(s.noise_mb),
                mb(log2_mb(raw)),
                mb(s.noise_mb - prev.noise_mb),
                if s.correct { "OK" } else { "WRONG" }
            );
        }
        if !s.correct {
            break;
        }
        max_correct = k;
        if k > 8 {
            settled.push(log2_mb(raw));
        }
        prev = s;
    }

    assert!(!settled.is_empty(), "no settled increments");
    let ceiling_mb = log2_mb(delta_half(&ctx, ctx.config.primes.len()));

    // The first few post-plateau increments are still the transient decaying.
    // Take the tail quarter as the settled additive constant.
    let tail = &settled[settled.len() * 3 / 4..];
    let lo = *tail.iter().min().unwrap();
    let hi = *tail.iter().max().unwrap();

    println!(
        "\n  max correct depth  : {max_correct}\n  \
           noise at that depth: {} bits (ceiling {} bits, headroom {} bits)\n  \
           settled raw increment (last quarter of the chain): log2 in [{}, {}], \
           spread {} bits",
        mb(prev.noise_mb),
        mb(ceiling_mb),
        mb(ceiling_mb - prev.noise_mb),
        mb(lo),
        mb(hi),
        mb(hi - lo)
    );

    if hi > 0 && ceiling_mb > hi {
        // Additive constant c: ceiling reached after ~(Δ/2)/c more multiplies.
        println!(
            "  => ADDITIVE, constant ~2^{} per multiply. The ceiling is {} bits, so\n     \
            the depth this affords is ~2^{} multiplications. The measured plateau\n     \
            at {} bits is a ONE-TIME relinearization floor, not accumulation.",
            mb(hi),
            mb(ceiling_mb),
            mb(ceiling_mb - hi),
            mb(prev.noise_mb),
        );
    }
}
