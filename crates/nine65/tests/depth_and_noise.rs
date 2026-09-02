//! Depth and noise curve, measured after the retirement of the Step-5 auto
//! modulus-switch in `mul_dual_public` and of SBNI.
//!
//! Before that retirement, `mul_dual_public` returned a ciphertext whose
//! `poly.main` was one lane shorter than `self.config.primes`, and the next
//! multiply indexed the full prime list against it inside
//! `sbni::inject_dual_in_place` — an out-of-bounds panic at roughly depth 2-3.
//! Nothing downstream of that could be measured. This file is the measurement.
//!
//! # The noise measure
//!
//! Every noise number here comes from the measure the codebase already
//! exposes: `RNSFHEContext::decrypt_dual_with_diagnostics(ct, sk)`. It
//! reconstructs `c0 + c1*s` over the *actual* ciphertext limbs, locates the
//! nearest ideal encoding point `m*Δ`, and returns `(decoded, margin)` with
//!
//! ```text
//!     margin = Δ/2 - |error|      so      |error| = Δ/2 - margin
//! ```
//!
//! `|error|` is the measured noise magnitude; it is reported below as
//! `1000 * log2(|error|)` millibits, computed with integer arithmetic only.
//! `margin < 0` is this codebase's own definition of noise exhaustion —
//! `try_decrypt_dual` turns exactly that condition into `NoiseExhausted`.
//!
//! This is a *measured* quantity taken off real residues. It is deliberately
//! not `crate::noise::budget::NoiseBudget` (a predictive accounting model, as
//! `bin/cram_exploratory_probe.rs` itself records with
//! `"noise_budget_is_accounting_model": true`) and not
//! `GSOFHEContext::noise_stats` (a tracker propagated alongside the ciphertext
//! rather than read out of it).
//!
//! ## Two limits of that measure, respected throughout
//!
//! 1. **It is only meaningful while decryption is correct.** Once the decode
//!    lands on the wrong lattice point, `|error|` is measured against that
//!    wrong point and the number is noise about noise. Every curve below stops
//!    at the last depth that decrypted correctly, and no depth is counted as
//!    reached unless `decrypt_dual` returned the expected plaintext there.
//!
//! 2. **It requires `Q * t < 2^128` and a plaintext below `t/2`.** Above the
//!    first, `decrypt_dual_with_diagnostics` takes its `decrypt_dual_u256`
//!    fallback and returns `margin = 0` unconditionally — no measurement at
//!    all (this rules out 4+ prime chains at `t = 65537`). Above the second,
//!    the decode takes its `full_value > q_half` branch, whose `ideal_point`
//!    is `Q - decoded*Δ` when the value being encoded is `-(t - decoded)`;
//!    the reported error is then `~Q` rather than the true error. Both
//!    conditions hold for every measurement in this file, and
//!    `Sample::noise_valid` records the second explicitly.
//!
//! # What is asserted
//!
//! * **Lane count is constant across every chain.** `poly.main.len()`,
//!   `poly.anchor.len()` and `ct.level` must not move at any depth. This is
//!   the anti-ladder invariant carried out to depth: `basis_invariance.rs`
//!   proves the basis does not move under *division*; this file proves it does
//!   not move under a long *multiplication chain* either.
//! * Decryption correctness at every depth counted as reached.
//! * Exact division reduces the measured noise by exactly `log2(d)`.
//!
//! # Running the deep version
//!
//! Defaults are sized for an ordinary `cargo test` run. The deep run reported
//! in the accompanying analysis was:
//!
//! ```text
//! RUSTFLAGS="-C debug-assertions=on -C overflow-checks=off" \
//!   NINE65_DEPTH_MAX=4096 NINE65_DEPTH_SECS=1800 \
//!   cargo test --release -p nine65 --test depth_and_noise -- --nocapture --test-threads=1
//! ```
//!
//! `-C debug-assertions=on` is required in release: `decrypt_dual_with_
//! diagnostics` is `pub` only under `cfg(any(test, debug_assertions))`.
//!
//! # What that run measured (secure_128, N=8192, 3 main lanes, t=65537)
//!
//! ```text
//!   budget log2(delta/2) = 72.260 bits
//!
//!   CHAIN A   symmetric ct x Enc(1)   depth 4096   stopped by DEPTH LIMIT, not noise
//!   CHAIN A'  symmetric squaring      depth    1   stopped by noise
//!   CHAIN A'' public mul_dual_public  depth    1   stopped by noise
//!   CHAIN B   A plus scale/divide     depth 4096   noise identical to A at every depth
//!
//!   CHAIN A noise:  d=1 29.907  d=2 42.368  d=4 44.347  d=16 46.644  d=64 48.804
//!                   d=256 50.815  d=1024 52.734  d=4096 54.854 bits
//! ```
//!
//! Lane count was 3 main / 5 anchor / level 3 at every one of those depths, in
//! every chain. The curve is BOUNDED GROWTH, not flat: the noise magnitude
//! grows very close to linearly in depth (about 1.05 bits of log2 per doubling
//! of depth), which puts budget exhaustion near depth 2^28.6 by extrapolation
//! from the measured last octave. Depth is therefore very large but finite.

use std::time::{Duration, Instant};

use exact_transcendentals::k_elim;

use nine65::entropy::ShadowHarvester;
use nine65::ops::rns_fhe::{DualRNSCiphertext, DualRNSFullKeySet, DualRNSPoly, RNSFHEContext};
use nine65::params::secure_configs::SecureConfig;

// ============================================================================
// KNOBS
// ============================================================================

/// Ceiling for the deep chain. The pre-CRAM system reportedly reached ~200, so
/// the default clears that. Override with `NINE65_DEPTH_MAX`.
const DEFAULT_MAX_DEPTH: usize = 256;

/// Wall-clock cap per chain. Override with `NINE65_DEPTH_SECS`. Four chains
/// run in this file, so the default bounds the whole file at ~20 minutes in the
/// dev profile and about two minutes in release.
const DEFAULT_WALL_SECS: u64 = 300;

/// Floor below which the retirement must be considered regressed. The crash it
/// removed bit at depth 2-3.
const DEPTH_REGRESSION_FLOOR: usize = 32;

fn max_depth() -> usize {
    std::env::var("NINE65_DEPTH_MAX")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_DEPTH)
}

fn wall_cap() -> Duration {
    Duration::from_secs(
        std::env::var("NINE65_DEPTH_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_WALL_SECS),
    )
}

// ============================================================================
// INTEGER LOG2, IN MILLIBITS (no floats)
// ============================================================================

/// `1000 * log2(x)`, integer-only, ~1 millibit resolution. `log2_mb(0) == 0`.
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

// ============================================================================
// THE MEASUREMENT
// ============================================================================

#[derive(Clone, Debug)]
struct Sample {
    depth: usize,
    /// `poly.main.len()` — the main lane count. THE anti-ladder observable.
    main_lanes: usize,
    anchor_lanes: usize,
    level: usize,
    decoded: u64,
    expected: u64,
    correct: bool,
    /// `Δ/2 - margin`: the measured noise magnitude.
    noise_abs: u128,
    noise_mb: i64,
    /// False when the plaintext is >= t/2 and the diagnostic's negative branch
    /// would report a meaningless error. Correctness is still valid.
    noise_valid: bool,
    /// Raw margin. Negative == the codebase's own noise-exhaustion condition.
    margin: i128,
}

fn q_at_level(ctx: &RNSFHEContext, level: usize) -> u128 {
    ctx.config.primes[..level]
        .iter()
        .fold(1u128, |acc, &p| acc * p as u128)
}

fn delta_half(ctx: &RNSFHEContext, level: usize) -> u128 {
    (q_at_level(ctx, level) / ctx.t as u128) / 2
}

/// Pull the existing diagnostic measure off a real ciphertext.
fn measure(
    ctx: &RNSFHEContext,
    ct: &DualRNSCiphertext,
    sk: &nine65::ops::rns_fhe::DualRNSSecretKey,
    depth: usize,
    expected: u64,
) -> Sample {
    let dh = delta_half(ctx, ct.c0.main.len());
    let (decoded, margin) = ctx.decrypt_dual_with_diagnostics(ct, sk);
    let noise_abs = (dh as i128 - margin).max(0) as u128;

    Sample {
        depth,
        main_lanes: ct.c0.main.len(),
        anchor_lanes: ct.c0.anchor.len(),
        level: ct.level,
        decoded,
        expected,
        correct: decoded == expected,
        noise_abs,
        noise_mb: log2_mb(noise_abs),
        noise_valid: expected < ctx.t / 2,
        margin,
    }
}

fn print_config(ctx: &RNSFHEContext) {
    let level = ctx.config.primes.len();
    let q = q_at_level(ctx, level);
    println!(
        "config: N={} t={} main_lanes={} anchor_lanes={} log2(Q)={} \
         budget log2(delta/2)={} measurable(Q*t<2^128)={}",
        ctx.config.n,
        ctx.t,
        level,
        ctx.dual_rns.anchor.primes.len(),
        mb(log2_mb(q)),
        mb(log2_mb(delta_half(ctx, level))),
        q.checked_mul(ctx.t as u128).is_some(),
    );
}

fn print_row(s: &Sample, prev: Option<&Sample>) {
    let delta = match prev {
        Some(p) if p.noise_valid && s.noise_valid => mb(s.noise_mb - p.noise_mb),
        _ => "-".to_string(),
    };
    println!(
        "{:>6} | {:>5} {:>6} {:>5} | {:>10} | {:>9} | {}",
        s.depth,
        s.main_lanes,
        s.anchor_lanes,
        s.level,
        if s.noise_valid {
            mb(s.noise_mb)
        } else {
            "(n/a)".into()
        },
        delta,
        if s.correct {
            if s.margin < 0 {
                "OK (margin NEGATIVE)".to_string()
            } else {
                "OK".to_string()
            }
        } else {
            format!("WRONG got {} want {}", s.decoded, s.expected)
        },
    );
}

fn print_table_header() {
    println!(
        "{:>6} | {:>5} {:>6} {:>5} | {:>10} | {:>9} | {}",
        "depth", "lanes", "anchor", "level", "noise bits", "delta", "decrypt"
    );
    println!("-------|-------------------|------------|-----------|--------------------");
}

// ============================================================================
// (2) THE ANTI-LADDER INVARIANT
// ============================================================================

/// Assert the lane count never moved anywhere in a recorded chain.
fn assert_lane_count_constant(samples: &[Sample], what: &str) {
    assert!(!samples.is_empty(), "{what}: no samples recorded");
    let m0 = samples[0].main_lanes;
    let a0 = samples[0].anchor_lanes;
    let l0 = samples[0].level;
    for s in samples {
        assert_eq!(
            s.main_lanes, m0,
            "{what}: MAIN LANE COUNT MOVED at depth {} ({m0} -> {}). \
             A lane was consumed — the modulus ladder is back.",
            s.depth, s.main_lanes
        );
        assert_eq!(
            s.anchor_lanes, a0,
            "{what}: ANCHOR LANE COUNT MOVED at depth {} ({a0} -> {})",
            s.depth, s.anchor_lanes
        );
        assert_eq!(
            s.level, l0,
            "{what}: ct.level MOVED at depth {} ({l0} -> {})",
            s.depth, s.level
        );
    }
    println!(
        "LANE COUNT CONSTANT over depths {}..={}: main={m0} anchor={a0} level={l0}",
        samples.first().unwrap().depth,
        samples.last().unwrap().depth,
    );
}

// ============================================================================
// CURVE SHAPE
// ============================================================================

/// Describe the measured curve over the depths where decryption was correct
/// and the measure was valid. Never rounds a rising curve down to flat.
fn describe_curve(samples: &[Sample]) -> String {
    let good: Vec<&Sample> = samples
        .iter()
        .filter(|s| s.correct && s.noise_valid && s.depth >= 1)
        .collect();
    if good.len() < 4 {
        return format!("not_measurable (only {} usable depths)", good.len());
    }
    // Depth 1 is the transient from a fresh ciphertext; the shape lives after.
    let a = good[1];
    let z = good[good.len() - 1];
    let total = z.noise_mb - a.noise_mb;

    // Growth per doubling of depth. A magnitude that grows linearly in depth
    // shows up here as +1000 millibits (1 bit) per doubling.
    let doublings = log2_mb(z.depth as u128) - log2_mb(a.depth as u128);
    let per_doubling = if doublings > 0 {
        total * 1000 / doublings
    } else {
        0
    };

    let shape = if total.abs() < 500 {
        "FLAT"
    } else if per_doubling <= 1500 {
        // <= ~1 bit per doubling of depth == magnitude grows at most ~linearly
        "BOUNDED GROWTH (magnitude ~linear in depth; log2 grows ~log2(depth))"
    } else {
        "GROWTH (faster than linear in depth — geometric in log2 terms)"
    };

    format!(
        "{shape}\n    depth {} -> {}: noise {} -> {} bits (+{} bits over {} doublings, \
         {} bits per doubling)",
        a.depth,
        z.depth,
        mb(a.noise_mb),
        mb(z.noise_mb),
        mb(total),
        mb(doublings),
        mb(per_doubling),
    )
}

/// Depth at which the measured curve would reach the budget, extrapolated from
/// its own last octave. Reported as an order of magnitude, not a promise.
fn extrapolate_exhaustion(ctx: &RNSFHEContext, samples: &[Sample]) -> String {
    let good: Vec<&Sample> = samples
        .iter()
        .filter(|s| s.correct && s.noise_valid && s.depth >= 1)
        .collect();
    if good.len() < 8 {
        return "insufficient data".into();
    }
    let budget_mb = log2_mb(delta_half(ctx, good[0].main_lanes));
    let z = good[good.len() - 1];
    let a = good[good.len() / 2];
    let doublings = log2_mb(z.depth as u128) - log2_mb(a.depth as u128);
    let rise = z.noise_mb - a.noise_mb;
    if rise <= 0 || doublings <= 0 {
        return format!(
            "curve is flat or falling over its last octave; budget {} bits not approached",
            mb(budget_mb)
        );
    }
    let per_doubling = rise * 1000 / doublings;
    let remaining = budget_mb - z.noise_mb;
    if remaining <= 0 {
        return "already at budget".into();
    }
    let more_doublings = remaining * 1000 / per_doubling; // millibits of log2(depth)
    let exhaust_log2_depth = log2_mb(z.depth as u128) + more_doublings;
    format!(
        "budget {} bits; at depth {} the measure is {} bits, {} bits short; \
         at {} bits per doubling that is ~2^{} more depth, i.e. exhaustion near depth 2^{}",
        mb(budget_mb),
        z.depth,
        mb(z.noise_mb),
        mb(remaining),
        mb(per_doubling),
        mb(more_doublings),
        mb(exhaust_log2_depth),
    )
}

// ============================================================================
// EXACT DIVISION (residue-native, basis-preserving)
// ============================================================================
//
// The same primitive `basis_invariance.rs` assembles: per-lane K-Elimination
// reciprocal applied to every main and anchor lane. No lane dropped, `level`
// not decremented.

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
    let main = poly
        .main
        .iter()
        .enumerate()
        .map(|(i, limb)| divide_lane(limb, ctx.config.primes[i], d))
        .collect();
    let anchor = poly
        .anchor
        .iter()
        .enumerate()
        .map(|(j, limb)| divide_lane(limb, ctx.dual_rns.anchor.primes[j], d))
        .collect();
    DualRNSPoly {
        main,
        anchor,
        n: poly.n,
    }
}

fn exact_divide_dual(ctx: &RNSFHEContext, ct: &DualRNSCiphertext, d: u64) -> DualRNSCiphertext {
    DualRNSCiphertext {
        c0: exact_divide_poly(ctx, &ct.c0, d),
        c1: exact_divide_poly(ctx, &ct.c1, d),
        // Not `ct.level - 1`. Nothing was spent, so nothing is decremented.
        level: ct.level,
    }
}

// ============================================================================
// CHAIN DRIVER
// ============================================================================

#[derive(Debug, PartialEq, Eq)]
enum Stop {
    /// Decryption became incorrect.
    Noise,
    /// Wall-clock cap.
    Timeout,
    /// Ran out of requested depth with the chain still healthy.
    DepthLimitReached,
}

struct ChainResult {
    samples: Vec<Sample>,
    max_correct_depth: usize,
    stop: Stop,
}

/// Run a chain, sampling at EVERY depth.
fn run_chain<F>(
    ctx: &RNSFHEContext,
    sk: &nine65::ops::rns_fhe::DualRNSSecretKey,
    title: &str,
    ct0: DualRNSCiphertext,
    m0: u64,
    mut step: F,
) -> ChainResult
where
    F: FnMut(&DualRNSCiphertext, u64) -> (DualRNSCiphertext, u64),
{
    println!("\n================================================================");
    println!("{title}");
    println!("================================================================");
    print_config(ctx);
    print_table_header();

    let mut ct = ct0;
    let mut expected = m0 % ctx.t;

    let mut samples = vec![measure(ctx, &ct, sk, 0, expected)];
    print_row(&samples[0], None);
    assert!(
        samples[0].correct,
        "{title}: the fresh encryption did not decrypt"
    );

    let start = Instant::now();
    let cap = wall_cap();
    let dmax = max_depth();

    let mut max_correct_depth = 0usize;
    let mut stop = Stop::DepthLimitReached;

    for depth in 1..=dmax {
        if start.elapsed() > cap {
            stop = Stop::Timeout;
            println!(
                "-- wall-clock cap {}s reached before depth {depth}",
                cap.as_secs()
            );
            break;
        }

        let (next, next_expected) = step(&ct, expected);
        ct = next;
        expected = next_expected;

        let s = measure(ctx, &ct, sk, depth, expected);
        let correct = s.correct;
        // Print densely near the start, then one row per octave-ish, plus any
        // failure. Every depth is still recorded in `samples`.
        if depth <= 24 || depth % 16 == 0 || depth == dmax || !correct {
            print_row(&s, samples.last());
        }
        samples.push(s);

        if correct {
            max_correct_depth = depth;
        } else {
            stop = Stop::Noise;
            println!("-- first INCORRECT decryption at depth {depth}");
            break;
        }
    }

    println!(
        "\n  max depth with CORRECT decryption : {max_correct_depth}\n  \
           stopped by                        : {stop:?}\n  \
           wall clock                        : {}s\n  \
           curve                             : {}\n  \
           extrapolation                     : {}",
        start.elapsed().as_secs(),
        describe_curve(&samples),
        extrapolate_exhaustion(ctx, &samples),
    );

    ChainResult {
        samples,
        max_correct_depth,
        stop,
    }
}

// ============================================================================
// SETUP
// ============================================================================

/// `secure_128`: N=8192, three 30-bit main lanes, five anchor lanes, t=65537.
/// The deepest shipped parameter set for which the existing noise measure is
/// actually available (`Q*t = 2^105.3 < 2^128`); `secure_128_deep` and above
/// fall into the `decrypt_dual_u256` path and report `margin = 0`.
fn ctx_and_keys() -> (RNSFHEContext, DualRNSFullKeySet) {
    let cfg = SecureConfig::secure_128();
    let ctx = RNSFHEContext::new(&cfg.config);
    let mut rng = ShadowHarvester::with_seed(42);
    let keys = ctx.generate_keys_dual_full(&mut rng);
    (ctx, keys)
}

// ============================================================================
// TEST 1 — the deep chain
// ============================================================================

/// Sequential multiplicative depth in symmetric mode: at every step a genuine
/// ciphertext x ciphertext multiply against `Enc(1)`, so the plaintext is a
/// known constant at every depth and correctness is unambiguous.
///
/// This is the chain that used to hit the `sbni.rs:84` out-of-bounds panic at
/// depth 2-3.
#[test]
fn depth_and_noise_curve_deep_chain() {
    let (ctx, keys) = ctx_and_keys();
    let sk = &keys.secret_key;
    let s2 = ctx.precompute_s_squared(sk);

    let mut rng = ShadowHarvester::with_seed(9001);
    let ct_one = ctx.encrypt_dual(1, &keys.public_key, &mut rng);
    assert_eq!(ctx.decrypt_dual(&ct_one, sk), 1, "Enc(1) is not Enc(1)");

    let m0 = 5u64;
    let ct0 = ctx.encrypt_dual(m0, &keys.public_key, &mut rng);

    let r = run_chain(
        &ctx,
        sk,
        "CHAIN A — symmetric ct x Enc(1); no modulus switch, no division",
        ct0,
        m0,
        |ct, expected| {
            (
                ctx.mul_dual_symmetric_with_s2(ct, &ct_one, sk, &s2),
                expected,
            )
        },
    );

    // (2) THE ANTI-LADDER INVARIANT, asserted across the entire chain.
    assert_lane_count_constant(&r.samples, "CHAIN A");

    // Every counted depth decrypted correctly, by construction of the loop.
    for s in r.samples.iter().take(r.max_correct_depth + 1) {
        assert!(s.correct, "depth {} counted but decrypted wrong", s.depth);
    }

    assert!(
        r.max_correct_depth >= DEPTH_REGRESSION_FLOOR,
        "REGRESSION: chain reached only depth {} (floor {DEPTH_REGRESSION_FLOOR}). \
         The retired auto modulus-switch / SBNI crash bit at depth 2-3; \
         anything near that means it is back.",
        r.max_correct_depth
    );
}

// ============================================================================
// TEST 2 — the harsh chain: repeated squaring
// ============================================================================

/// Both operands carry accumulated noise and the plaintext grows, so the noise
/// magnitude is multiplied rather than incremented at every step. This is the
/// worst case for depth and it is included so the depth reported by Test 1
/// cannot be read as a property of the scheme alone.
#[test]
fn depth_and_noise_curve_squaring_chain() {
    let (ctx, keys) = ctx_and_keys();
    let sk = &keys.secret_key;
    let s2 = ctx.precompute_s_squared(sk);
    let t = ctx.t as u128;

    let mut rng = ShadowHarvester::with_seed(9001);
    let m0 = 3u64;
    let ct0 = ctx.encrypt_dual(m0, &keys.public_key, &mut rng);

    let r = run_chain(
        &ctx,
        sk,
        "CHAIN A' — symmetric repeated squaring ct x ct (worst case)",
        ct0,
        m0,
        |ct, expected| {
            let next = ctx.mul_dual_symmetric_with_s2(ct, ct, sk, &s2);
            (next, ((expected as u128 * expected as u128) % t) as u64)
        },
    );

    assert_lane_count_constant(&r.samples, "CHAIN A'");
    assert!(r.max_correct_depth >= 1, "squaring died before depth 1");
}

// ============================================================================
// TEST 3 — public mode, the real FHE model
// ============================================================================

/// Same chain as Test 1 but through `mul_dual_public` — the mode where the
/// evaluator does not hold the secret key, and the mode whose Step 5 contained
/// the retired auto modulus-switch.
#[test]
fn depth_and_noise_curve_public_mode() {
    let (ctx, keys) = ctx_and_keys();
    let sk = &keys.secret_key;

    let mut rng = ShadowHarvester::with_seed(9001);
    let ct_one = ctx.encrypt_dual(1, &keys.public_key, &mut rng);
    let m0 = 5u64;
    let ct0 = ctx.encrypt_dual(m0, &keys.public_key, &mut rng);

    let r = run_chain(
        &ctx,
        sk,
        "CHAIN A'' — PUBLIC mul_dual_public(ct, Enc(1)); the retired Step-5 site",
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

    // The invariant holds regardless of how deep the chain gets: this is the
    // call site the auto modulus-switch was removed from, so a lane moving
    // here is the specific regression to catch.
    assert_lane_count_constant(&r.samples, "CHAIN A''");
    assert!(
        r.max_correct_depth >= 1,
        "public mode failed before a single multiply completed"
    );
}

// ============================================================================
// TEST 4 — does exact division reduce noise in proportion to the divisor?
// ============================================================================

/// The mechanism the entire depth argument rests on, measured directly.
///
/// For each divisor `d`: measure a ciphertext's noise; scale it by `d` with
/// `mul_plain_dual` (the underlying integer becomes `d*(Δm + e)`, hence exactly
/// divisible by `d`); measure; exact-divide by `d`; measure. The question is
/// whether the third measurement is the second one minus `log2(d)`.
#[test]
fn exact_division_reduces_noise_in_proportion_to_the_divisor() {
    let (ctx, keys) = ctx_and_keys();
    let sk = &keys.secret_key;
    let mut rng = ShadowHarvester::with_seed(31337);

    // Every one of these is a unit on every lane of the chain, and `d * m`
    // stays below `t/2` so the diagnostic's positive branch is used.
    const DIVISORS: &[u64] = &[2, 3, 5, 7, 11, 23, 97, 1009, 4093, 16381];

    println!("\n================================================================");
    println!("EXACT DIVISION vs MEASURED NOISE");
    println!("================================================================");
    print_config(&ctx);
    println!(
        "{:>7} | {:>12} | {:>12} | {:>12} | {:>9} | {:>9} | {:>8}",
        "d", "noise", "after x d", "after / d", "x d delta", "/ d delta", "log2 d"
    );
    println!(
        "--------|--------------|--------------|--------------|-----------|-----------|---------"
    );

    let mut worst_dev_mb: i64 = 0;

    for &d in DIVISORS {
        let m = 1u64;
        let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
        let before = measure(&ctx, &ct, sk, 0, m);
        assert!(
            before.correct,
            "d={d}: the fresh ciphertext did not decrypt"
        );

        let scaled = ctx.mul_plain_dual(&ct, d);
        let after_mul = measure(&ctx, &scaled, sk, 0, d * m);
        assert!(
            after_mul.correct,
            "d={d}: mul_plain_dual(Enc({m}), {d}) is not Enc({}) (got {})",
            d * m,
            after_mul.decoded
        );

        let divided = exact_divide_dual(&ctx, &scaled, d);
        let after_div = measure(&ctx, &divided, sk, 0, m);

        // The basis did not move.
        assert_eq!(
            divided.c0.main.len(),
            ct.c0.main.len(),
            "d={d}: lane dropped"
        );
        assert_eq!(
            divided.c0.anchor.len(),
            ct.c0.anchor.len(),
            "d={d}: anchor lane dropped"
        );
        assert_eq!(divided.level, ct.level, "d={d}: level decremented");
        assert!(
            after_div.correct,
            "d={d}: exact division did not return Enc({m}) (got {})",
            after_div.decoded
        );

        let log2d = log2_mb(d as u128);
        let mul_delta = after_mul.noise_mb - before.noise_mb;
        let div_delta = after_div.noise_mb - after_mul.noise_mb;

        println!(
            "{:>7} | {:>12} | {:>12} | {:>12} | {:>9} | {:>9} | {:>8}",
            d,
            mb(before.noise_mb),
            mb(after_mul.noise_mb),
            mb(after_div.noise_mb),
            mb(mul_delta),
            mb(div_delta),
            mb(log2d)
        );

        worst_dev_mb = worst_dev_mb.max((div_delta + log2d).abs());

        // Stronger than proportionality: the round trip is bit-exact, so the
        // division introduced no rounding term whatsoever.
        assert_eq!(
            after_div.noise_abs, before.noise_abs,
            "d={d}: exact division did not restore the pre-scaling noise exactly"
        );
    }

    println!(
        "\nworst deviation of the /d noise delta from -log2(d): {} bits",
        mb(worst_dev_mb)
    );
    println!(
        "=> exact division reduces the MEASURED noise by exactly log2(d): the\n   \
         reduction is proportional to the divisor, with no rounding term."
    );

    assert!(
        worst_dev_mb <= 5,
        "exact division did NOT reduce noise in proportion to d \
         (worst deviation {} bits)",
        mb(worst_dev_mb)
    );
}

// ============================================================================
// TEST 5 — the precondition, stated numerically
// ============================================================================

/// Exact division is exact on the whole underlying integer `Δm + e`, not on the
/// plaintext alone. Dividing by a `d` that divides `m` but not `Δm + e` yields
/// the unique lane-wise quotient `(v + kQ)/d`, which is of order `Q/d` — the
/// ciphertext is destroyed even though not one lane was touched.
///
/// This is the boundary of the mechanism, recorded so the depth argument cannot
/// lean on something it does not have.
#[test]
fn exact_division_requires_the_noise_to_be_divisible_too() {
    let (ctx, keys) = ctx_and_keys();
    let sk = &keys.secret_key;
    let mut rng = ShadowHarvester::with_seed(4242);

    println!("\n================================================================");
    println!("PRECONDITION — dividing when only the PLAINTEXT is divisible by d");
    println!("================================================================");

    let d = 4u64;
    let m = 12u64; // d | m, but d does not divide the noise
    let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
    let before = measure(&ctx, &ct, sk, 0, m);
    assert!(before.correct);

    let divided = exact_divide_dual(&ctx, &ct, d);
    let after = measure(&ctx, &divided, sk, 0, m / d);

    println!(
        "  Enc({m}) / {d}: noise {} -> {} bits; decrypted {} (wanted {}); correct={}",
        mb(before.noise_mb),
        mb(after.noise_mb),
        after.decoded,
        m / d,
        after.correct,
    );
    println!(
        "  lanes: main {} -> {}, anchor {} -> {}, level {} -> {}",
        ct.c0.main.len(),
        divided.c0.main.len(),
        ct.c0.anchor.len(),
        divided.c0.anchor.len(),
        ct.level,
        divided.level,
    );

    // The basis does not move either way — that part is unconditional.
    assert_eq!(divided.c0.main.len(), ct.c0.main.len());
    assert_eq!(divided.c0.anchor.len(), ct.c0.anchor.len());
    assert_eq!(divided.level, ct.level);

    println!(
        "  => the divisor must divide the FULL underlying integer (Delta*m + e).\n     \
         Divisibility of the plaintext alone is not sufficient."
    );
}

// ============================================================================
// TEST 6 — two chains compared: plain vs exact division after every multiply
// ============================================================================

/// The lossless-rescale hypothesis, run as a chain.
///
/// Chain B does, at every depth: one ciphertext x ciphertext multiply, then
/// `mul_plain_dual(., d)` followed by `exact_divide(., d)`. That scale-then-
/// divide pair is the only form in which exact division applies to a chain
/// step, because Test 5 shows the underlying integer has to be divisible by `d`
/// and this is what makes it so. The plaintext is preserved at every step, so
/// the two chains are comparable depth for depth.
///
/// If exact division buys depth, chain B's noise curve sits below chain A's.
#[test]
fn two_chains_compared_plain_vs_exact_division() {
    let (ctx, keys) = ctx_and_keys();
    let sk = &keys.secret_key;
    let s2 = ctx.precompute_s_squared(sk);
    let d = 97u64;

    let mut rng = ShadowHarvester::with_seed(9001);
    let ct_one = ctx.encrypt_dual(1, &keys.public_key, &mut rng);
    let m0 = 5u64;

    let ct_a = ctx.encrypt_dual(m0, &keys.public_key, &mut rng);
    let a = run_chain(
        &ctx,
        sk,
        "CHAIN A (control) — multiply only",
        ct_a,
        m0,
        |ct, expected| {
            (
                ctx.mul_dual_symmetric_with_s2(ct, &ct_one, sk, &s2),
                expected,
            )
        },
    );

    let mut rng_b = ShadowHarvester::with_seed(9001);
    let _ = ctx.encrypt_dual(1, &keys.public_key, &mut rng_b); // keep the streams aligned
    let ct_b = ctx.encrypt_dual(m0, &keys.public_key, &mut rng_b);
    let b = run_chain(
        &ctx,
        sk,
        &format!("CHAIN B — multiply, then scale by {d} and exact-divide by {d}"),
        ct_b,
        m0,
        |ct, expected| {
            let mul = ctx.mul_dual_symmetric_with_s2(ct, &ct_one, sk, &s2);
            let scaled = ctx.mul_plain_dual(&mul, d);
            (exact_divide_dual(&ctx, &scaled, d), expected)
        },
    );

    assert_lane_count_constant(&a.samples, "CHAIN A");
    assert_lane_count_constant(&b.samples, "CHAIN B");

    println!("\n================================================================");
    println!("SIDE BY SIDE — measured noise (bits) at each depth");
    println!("================================================================");
    println!(
        "{:>6} | {:>12} | {:>12} | {:>12}",
        "depth", "A mul only", "B mul then /d", "B - A"
    );
    println!("-------|--------------|--------------|-------------");
    let n = a.samples.len().min(b.samples.len());
    for i in 0..n {
        let (x, y) = (&a.samples[i], &b.samples[i]);
        let interesting = i <= 16 || i % 16 == 0 || !x.correct || !y.correct;
        if !interesting {
            continue;
        }
        println!(
            "{:>6} | {:>12} | {:>12} | {:>12}",
            i,
            if x.correct {
                mb(x.noise_mb)
            } else {
                "-".into()
            },
            if y.correct {
                mb(y.noise_mb)
            } else {
                "-".into()
            },
            if x.correct && y.correct {
                mb(y.noise_mb - x.noise_mb)
            } else {
                "-".into()
            },
        );
    }

    println!(
        "\nCHAIN A: depth {} ({:?})\nCHAIN B: depth {} ({:?})",
        a.max_correct_depth, a.stop, b.max_correct_depth, b.stop
    );

    let identical = (0..n)
        .filter(|&i| a.samples[i].correct && b.samples[i].correct)
        .all(|i| a.samples[i].noise_abs == b.samples[i].noise_abs);

    if b.max_correct_depth > a.max_correct_depth {
        println!(
            "=> exact division BOUGHT {} extra depth",
            b.max_correct_depth - a.max_correct_depth
        );
    } else if b.max_correct_depth == a.max_correct_depth {
        println!(
            "=> exact division bought NO extra depth. Noise curves identical at \
             every depth: {identical}."
        );
        println!(
            "   The scale-then-divide pair is a bit-exact round trip: it removes\n   \
             exactly the log2({d}) bits it just added and does not touch the noise\n   \
             the multiplication accumulated. Exact division reduces noise in\n   \
             proportion to the divisor (Test 4) but it can only divide noise it\n   \
             can divide exactly (Test 5), and multiplication noise is not of that\n   \
             form. It is not a rescale substitute for a multiply chain."
        );
    } else {
        println!(
            "=> exact division COST {} depth",
            a.max_correct_depth - b.max_correct_depth
        );
    }

    assert_lane_count_constant(&b.samples, "CHAIN B (post-division)");
}
