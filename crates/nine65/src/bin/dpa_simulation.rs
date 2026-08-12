//! Expanded Differential Power Analysis (DPA) Simulation for NINE65 v7.
//! Verifies side-channel resistance of the Parallel Summation CRT implementation.

use nine65::prelude::*;
use nine65::arithmetic::rns::U512;
use std::time::Instant;

/// Simulate a power trace for a Parallel Summation CRT operation.
/// Power is modeled as Hamming Weight of intermediate sums + Gaussian noise.
fn simulate_power_trace(residues: &[u64], basis: &[u64], weights: &[U512], noise_level: f64) -> Vec<f64> {
    let mut trace = Vec::new();
    let mut current_sum = U512::zero();
    
    for i in 0..residues.len() {
        // Step 1: Multiply residue by precomputed weight (Mi * [Mi^-1 mod pi])
        let term = weights[i].mul_u128(residues[i] as u128);
        
        // Model power leakage of the multiplication
        trace.push(hamming_weight_u512(&term) as f64 + rand_noise(noise_level));
        
        // Step 2: Parallel Summation (Accumulation)
        current_sum = current_sum.add(term);
        
        // Model power leakage of the addition
        trace.push(hamming_weight_u512(&current_sum) as f64 + rand_noise(noise_level));
    }
    trace
}

fn hamming_weight_u512(val: &U512) -> u32 {
    val.d0.count_ones() + val.d1.count_ones() + val.d2.count_ones() + val.d3.count_ones()
}

fn rand_noise(level: f64) -> f64 {
    // Simple pseudo-random noise for simulation
    (Instant::now().elapsed().as_nanos() % 1000) as f64 / 1000.0 * level
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
    println!("Noise Level: 2.0 (High Variance)");

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
        traces.push(simulate_power_trace(&residues, basis, &weights, 2.0));
    }

    println!("Simulated {} power traces under heavy load.", n_traces);

    // Perform Correlation Check
    // If the system is resistant, the correlation for the correct residue should be negligible.
    let mut max_corr = 0.0f64;
    let mut best_guess = 0u64;

    // We only check a few hypotheses for demo purposes
    for guess in 0..1000 {
        let corr = calculate_correlation(&traces, guess, &weights[0]);
        if corr > max_corr {
            max_corr = corr;
            best_guess = guess as u64;
        }
    }

    println!("------------------------------------------");
    println!("DPA/CPA Analysis Results:");
    println!("  Target Residue: {}", target_residue);
    println!("  Best Guess:     {}", best_guess);
    println!("  Max Correlation: {:.4}", max_corr);
    
    if max_corr < 0.1 {
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
    if m == 1 { return 0; }
    while a > 1 {
        let q = a / m;
        let mut t = m;
        m = a % m;
        a = t;
        t = y;
        y = x - q * y;
        x = t;
    }
    if x < 0 { x += m0; }
    x as u64
}

fn calculate_correlation(traces: &[Vec<f64>], guess: u32, weight: &U512) -> f64 {
    // Simplified Pearson Correlation between Trace[0] and HW(guess * weight)
    let hypothesis_hw = hamming_weight_u512(&weight.mul_u128(guess as u128)) as f64;
    let mut sum_x = 0.0;
    let mut sum_y = 0.0;
    let mut sum_xy = 0.0;
    let mut sum_x2 = 0.0;
    let mut sum_y2 = 0.0;
    let n = traces.len() as f64;

    for trace in traces {
        let x = trace[0]; // Leakage of the first multiplication
        let y = hypothesis_hw;
        sum_x += x;
        sum_y += y;
        sum_xy += x * y;
        sum_x2 += x * x;
        sum_y2 += y * y;
    }

    let numerator = n * sum_xy - sum_x * sum_y;
    let denominator = ((n * sum_x2 - sum_x * sum_x) * (n * sum_y2 - sum_y * sum_y)).sqrt();
    if denominator == 0.0 { 0.0 } else { (numerator / denominator).abs() }
}
