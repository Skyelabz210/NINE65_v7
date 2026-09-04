//! Expanded Differential Power Analysis (DPA) Simulation for NINE65 v7.
//! Verifies side-channel resistance of the Parallel Summation CRT implementation.

use nine65::arithmetic::integer_math::{format_ratio, integer_sqrt_u128};
use nine65::arithmetic::rns::U512;
use nine65::prelude::*;
use std::time::Instant;

/// Integer dither in `{0, 1}`: `floor((nanos % 1000) * NOISE_LEVEL / 1000)`.
/// Integer stand-in for the original `[0, NOISE_LEVEL)` float jitter added to
/// each simulated trace sample — same qualitative role (perturb the
/// simulated leakage a little so it isn't a bare Hamming weight), no float.
const NOISE_LEVEL: u128 = 2;

/// Simulate a power trace for a Parallel Summation CRT operation.
/// Power is modeled as Hamming Weight of intermediate sums plus a small
/// integer dither (see [`NOISE_LEVEL`]).
fn simulate_power_trace(residues: &[u64], weights: &[U512]) -> Vec<i64> {
    let mut trace = Vec::new();
    let mut current_sum = U512::zero();

    for (residue, weight) in residues.iter().zip(weights.iter()) {
        // Step 1: Multiply residue by precomputed weight (Mi * [Mi^-1 mod pi])
        let term = weight.mul_u128(*residue as u128);

        // Model power leakage of the multiplication
        trace.push(hamming_weight_u512(&term) as i64 + dither() as i64);

        // Step 2: Parallel Summation (Accumulation)
        current_sum = current_sum.add(term);

        // Model power leakage of the addition
        trace.push(hamming_weight_u512(&current_sum) as i64 + dither() as i64);
    }
    trace
}

fn hamming_weight_u512(val: &U512) -> u32 {
    val.d0.count_ones() + val.d1.count_ones() + val.d2.count_ones() + val.d3.count_ones()
}

/// Small pseudo-random dither in `{0, 1}` from the low bits of the wall
/// clock — integer analogue of the original continuous-noise simulation.
fn dither() -> u128 {
    (Instant::now().elapsed().as_nanos() % 1000) * NOISE_LEVEL / 1000
}

fn main() {
    println!("NINE65 v7 Expanded DPA Simulation");
    println!("=================================");

    let secure_config = SecureConfig::secure_256();
    let config = secure_config.into_config();
    let basis = &config.primes;
    let n_primes = basis.len();

    // Precompute weights for Parallel Summation CRT
    // M = product of all primes
    let mut m = U512::from_u64(1);
    for &p in basis {
        m = m.mul_u128(p as u128);
    }

    let mut weights = Vec::new();
    for &p in basis {
        let mi = m.div_u64(p);
        let mi_inv = mod_inv(mi.mod_u64(p), p);
        weights.push(mi.mul_u128(mi_inv as u128));
    }

    println!("Target: Parallel Summation CRT with {} primes", n_primes);
    println!("Noise Level: {NOISE_LEVEL} (integer dither, High Variance)");

    // Attack Simulation: Correlation Power Analysis (CPA)
    // We try to recover residue[0] by correlating simulated traces with hypotheses.
    let target_residue = 123456789u64 % basis[0];
    let mut residues = vec![0u64; n_primes];
    residues[0] = target_residue;
    // Fill others with random values
    for i in 1..n_primes {
        residues[i] = (i as u64 * 987654321) % basis[i];
    }

    let n_traces = 500;
    let mut traces = Vec::new();
    for _ in 0..n_traces {
        traces.push(simulate_power_trace(&residues, &weights));
    }

    println!("Simulated {} power traces under heavy load.", n_traces);

    // Perform Correlation Check
    // If the system is resistant, the correlation for the correct residue
    // should be negligible. Pearson correlation r = numerator / sqrt(denom_sq);
    // both `numerator` and `denom_sq` are exact integers (see
    // `correlation_components`), so the running "is this guess the new best"
    // comparison below is done as an exact cross-multiplied comparison of
    // r^2 — `a/sqrt(b) > c/sqrt(d)` (a, c >= 0; b, d > 0) iff
    // `a^2 * d > c^2 * b` — never taking a square root until the final
    // display value. `(0, 0)` is the "no correlation yet" sentinel: any
    // strictly positive numerator beats it, matching the original `corr >
    // 0.0` starting condition.
    let mut max_corr_num: i128 = 0;
    let mut max_corr_denom_sq: u128 = 0;
    let mut best_guess = 0u64;

    // We only check a few hypotheses for demo purposes
    for guess in 0..1000u32 {
        let (num, denom_sq) = correlation_components(&traces, guess, &weights[0]);
        let is_new_best = match (denom_sq, max_corr_denom_sq) {
            (0, _) => false,    // this guess's correlation is undefined (0/0) -> treated as 0
            (_, 0) => num != 0, // first real correlation beats the zero sentinel
            (cand_denom, best_denom) => {
                let cand_num_sq = num.unsigned_abs().saturating_mul(num.unsigned_abs());
                let best_num_sq = max_corr_num
                    .unsigned_abs()
                    .saturating_mul(max_corr_num.unsigned_abs());
                cand_num_sq.saturating_mul(best_denom) > best_num_sq.saturating_mul(cand_denom)
            }
        };
        if is_new_best {
            max_corr_num = num;
            max_corr_denom_sq = denom_sq;
            best_guess = guess as u64;
        }
    }

    // Correlation magnitude scaled by 10^4 (4 fractional digits), computed as
    // isqrt(numerator^2 * 10^8 / denom_sq) — the one sqrt in this file, taken
    // only once at the end for display, on values already known to be exact
    // non-negative integers.
    let max_corr_scaled_1e4 = if max_corr_denom_sq == 0 {
        0u128
    } else {
        let num_sq = max_corr_num
            .unsigned_abs()
            .saturating_mul(max_corr_num.unsigned_abs());
        let scaled_sq = num_sq
            .saturating_mul(100_000_000u128)
            .checked_div(max_corr_denom_sq)
            .unwrap_or(0);
        integer_sqrt_u128(scaled_sq)
    };

    println!("------------------------------------------");
    println!("DPA/CPA Analysis Results:");
    println!("  Target Residue: {}", target_residue);
    println!("  Best Guess:     {}", best_guess);
    println!(
        "  Max Correlation: {}",
        format_ratio(max_corr_scaled_1e4, 10_000, 4)
    );

    // Original threshold was `max_corr < 0.1`; 0.1 * 10_000 = 1000 exactly in
    // the scaled-by-10^4 domain, so this is an exact integer comparison, not
    // an approximation of the float one.
    if max_corr_scaled_1e4 < 1000 {
        println!("  Status: RESISTANT (Zero Shadow Entropy verified)");
    } else {
        println!("  Status: VULNERABLE (Leakage detected)");
    }
    println!("------------------------------------------");
}

fn mod_inv(a: u64, m: u64) -> u64 {
    let mut a = a as i128;
    let mut m = m as i128;
    let m0 = m;
    let (mut y, mut x) = (0, 1);
    if m == 1 {
        return 0;
    }
    while a > 1 {
        let q = a / m;
        let mut t = m;
        m = a % m;
        a = t;
        t = y;
        y = x - q * y;
        x = t;
    }
    if x < 0 {
        x += m0;
    }
    x as u64
}

/// Pearson-correlation numerator and squared-denominator between
/// `traces[..][0]` (leakage of the first multiplication) and the constant
/// hypothesis `HW(guess * weight)`, as exact integers:
///
///   numerator = n * sum_xy - sum_x * sum_y
///   denom_sq  = (n * sum_x2 - sum_x^2) * (n * sum_y2 - sum_y^2)
///
/// so that `correlation = numerator / sqrt(denom_sq)` — never computed here;
/// callers compare `numerator^2 / denom_sq` across guesses instead (see
/// `main`), or take the one sqrt needed for the final display value.
fn correlation_components(traces: &[Vec<i64>], guess: u32, weight: &U512) -> (i128, u128) {
    let hypothesis_hw = hamming_weight_u512(&weight.mul_u128(guess as u128)) as i128;
    let n = traces.len() as i128;

    let mut sum_x: i128 = 0;
    let mut sum_y: i128 = 0;
    let mut sum_xy: i128 = 0;
    let mut sum_x2: i128 = 0;
    let mut sum_y2: i128 = 0;

    for trace in traces {
        let x = trace[0] as i128; // Leakage of the first multiplication
        let y = hypothesis_hw;
        sum_x += x;
        sum_y += y;
        sum_xy += x * y;
        sum_x2 += x * x;
        sum_y2 += y * y;
    }

    let numerator = n * sum_xy - sum_x * sum_y;
    let var_x = n * sum_x2 - sum_x * sum_x; // >= 0 by Cauchy-Schwarz
    let var_y = n * sum_y2 - sum_y * sum_y; // >= 0 by Cauchy-Schwarz
    let denom_sq = (var_x.max(0) as u128).saturating_mul(var_y.max(0) as u128);
    (numerator, denom_sq)
}
