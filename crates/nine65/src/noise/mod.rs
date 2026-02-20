//! FHE Noise Tracking System
//!
//! Based on CDHS (Comprehensive Diagnostic Health System) v2.0
//! Adapted for BFV ciphertext noise budget monitoring.
//!
//! All noise tracking uses integer-only arithmetic.
//! No floating point = perfect determinism across platforms.
//!
//! Noise in BFV:
//! - Fresh ciphertext has initial noise ~3.2σ
//! - Addition: noise_sum ≈ max(noise_a, noise_b) + 1 bit
//! - Multiplication: noise_prod ≈ noise_a + noise_b + log2(t) bits
//! - Rescaling: noise_new = noise - log2(q_i) bits
//!
//! This module tracks noise in "millibits" (1 bit = 1000 millibits)
//! for precise integer-only accounting.
//!
//! ## Submodules
//!
//! - `budget`: Config-aware noise budget tracking with cost estimation
//!
//! ## Re-exports
//!
//! The most commonly used types from the budget submodule are re-exported
//! for convenience:
//!
//! ```ignore
//! use nine65::noise::{NoiseBudget, NoiseExhausted, NoiseOpType};
//! ```

pub mod budget;

#[cfg(feature = "exact_rational")]
pub mod exact_noise;
#[cfg(feature = "exact_rational")]
pub use exact_noise::ExactNoiseTracker;

// Re-export commonly used types from budget module
pub use budget::{NoiseBudget, NoiseExhausted, NoiseOpType, NoiseOperation};

use std::collections::VecDeque;

// =============================================================================
// CONSTANTS - FixedQ representation for sub-bit precision
// =============================================================================

/// FixedQ scale factor (1,000,000 = 6 decimal places)
pub const FIXEDQ_SCALE: i64 = 1_000_000;

/// Millibits per bit (for sub-bit noise precision)
pub const MILLIBITS_PER_BIT: i64 = 1000;

/// Maximum noise budget in millibits (before decryption fails)
/// For typical parameters: ~438 bits = 438,000 millibits
pub const MAX_NOISE_BUDGET_MILLIBITS: i64 = 500_000;

/// Initial noise after encryption (~3.2 bits = 3200 millibits)
pub const INITIAL_NOISE_MILLIBITS: i64 = 3200;

// =============================================================================
// NOISE SNAPSHOT - Point-in-time measurement
// =============================================================================

/// NoiseSnapshot captures ciphertext noise at a specific operation
#[derive(Debug, Clone, Copy)]
pub struct NoiseSnapshot {
    /// Operation sequence number
    pub op_id: u64,

    /// Estimated noise in millibits
    pub noise_millibits: i64,

    /// Noise budget remaining in millibits
    pub budget_remaining: i64,

    /// Operation type (0=encrypt, 1=add, 2=mul, 3=rescale)
    pub op_type: u8,
}

impl NoiseSnapshot {
    pub fn new(op_id: u64, noise_millibits: i64, budget_total: i64, op_type: u8) -> Self {
        Self {
            op_id,
            noise_millibits,
            budget_remaining: budget_total - noise_millibits,
            op_type,
        }
    }

    /// Get noise in millibits (same as public field, for API compat)
    pub fn noise_bits_millibits(&self) -> i64 {
        self.noise_millibits
    }

    /// Get budget remaining in millibits (same as public field, for API compat)
    pub fn budget_remaining_millibits(&self) -> i64 {
        self.budget_remaining
    }
}

// =============================================================================
// EMA CALCULATOR - Exponential Moving Average (Integer-Only)
// =============================================================================

/// EMACalculator tracks noise trends without storing history
#[derive(Debug, Clone)]
pub struct EMACalculator {
    /// Current EMA value (FixedQ format)
    current_ema: i64,

    /// Alpha parameter in FixedQ (typical: 0.1 = 100,000)
    alpha: i64,

    /// Sample count
    samples: u64,
}

impl EMACalculator {
    /// Create with alpha = numerator/denominator
    pub fn new(alpha_numerator: i64, alpha_denominator: i64) -> Self {
        let alpha = (alpha_numerator * FIXEDQ_SCALE) / alpha_denominator;
        Self {
            current_ema: 0,
            alpha,
            samples: 0,
        }
    }

    /// Standard alpha=0.1 for noise tracking
    pub fn standard() -> Self {
        Self::new(1, 10)
    }

    /// Fast alpha=0.3 for quick response
    pub fn fast() -> Self {
        Self::new(3, 10)
    }

    /// Slow alpha=0.05 for stable baseline
    pub fn slow() -> Self {
        Self::new(1, 20)
    }

    /// Update EMA with new sample (millibits)
    #[inline]
    pub fn update(&mut self, new_value: i64) {
        let new_scaled = new_value * (FIXEDQ_SCALE / MILLIBITS_PER_BIT);

        if self.samples == 0 {
            self.current_ema = new_scaled;
        } else {
            // EMA = alpha * new + (1 - alpha) * old
            let delta = new_scaled.wrapping_sub(self.current_ema);
            let adjustment = delta.wrapping_mul(self.alpha) / FIXEDQ_SCALE;
            self.current_ema = self.current_ema.wrapping_add(adjustment);
        }

        self.samples += 1;
    }

    /// Get current EMA in millibits
    #[inline]
    pub fn value_millibits(&self) -> i64 {
        self.current_ema * MILLIBITS_PER_BIT / FIXEDQ_SCALE
    }

    /// Reset to initial state
    pub fn reset(&mut self) {
        self.current_ema = 0;
        self.samples = 0;
    }
}

// =============================================================================
// NOISE BUDGET TRACKER - Per-ciphertext noise accounting
// =============================================================================

/// NoiseBudgetTracker monitors a single ciphertext's noise evolution
#[derive(Debug, Clone)]
pub struct NoiseBudgetTracker {
    /// Total budget at encryption (millibits)
    initial_budget: i64,

    /// Current estimated noise (millibits)
    current_noise: i64,

    /// Operation count
    op_count: u64,

    /// Multiplication depth
    mul_depth: u32,

    /// Noise growth EMA
    growth_ema: EMACalculator,

    /// History of noise snapshots (limited size)
    history: VecDeque<NoiseSnapshot>,
}

impl NoiseBudgetTracker {
    /// Create tracker for given total budget (in bits)
    pub fn new(total_budget_bits: u32) -> Self {
        let initial_budget = (total_budget_bits as i64) * MILLIBITS_PER_BIT;

        Self {
            initial_budget,
            current_noise: INITIAL_NOISE_MILLIBITS,
            op_count: 0,
            mul_depth: 0,
            growth_ema: EMACalculator::standard(),
            history: VecDeque::with_capacity(64),
        }
    }

    /// Create tracker for standard 128-bit security (218-bit modulus budget)
    pub fn standard_128() -> Self {
        // Budget ≈ log2(Q) - log2(t) - safety = 218 - 16 - 50 = 152 bits
        Self::new(152)
    }

    /// Create tracker for deep circuits (438-bit modulus budget)
    pub fn deep_128() -> Self {
        // Budget ≈ 438 - 16 - 50 = 372 bits
        Self::new(372)
    }

    // =========================================================================
    // NOISE UPDATE OPERATIONS
    // =========================================================================

    /// Record encryption (initial noise)
    pub fn on_encrypt(&mut self) {
        self.current_noise = INITIAL_NOISE_MILLIBITS;
        self.record_snapshot(0);
    }

    /// Record addition operation
    /// Noise grows by ~1 bit
    pub fn on_add(&mut self) {
        let growth = MILLIBITS_PER_BIT; // 1 bit
        self.current_noise += growth;
        self.growth_ema.update(growth);
        self.record_snapshot(1);
    }

    /// Record multiplication operation
    /// Noise approximately doubles plus log2(t) overhead
    pub fn on_mul(&mut self, other_noise_millibits: i64, log2_t: u32) {
        // noise_prod ≈ noise_a + noise_b + log2(t)
        let log2_t_millibits = (log2_t as i64) * MILLIBITS_PER_BIT;
        let new_noise = self.current_noise + other_noise_millibits + log2_t_millibits;

        let growth = new_noise - self.current_noise;
        self.current_noise = new_noise;
        self.mul_depth += 1;
        self.growth_ema.update(growth);
        self.record_snapshot(2);
    }

    /// Record rescaling operation (noise reduction)
    /// Noise decreases by log2(q_i) bits
    pub fn on_rescale(&mut self, log2_prime: u32) {
        let reduction = (log2_prime as i64) * MILLIBITS_PER_BIT;
        self.current_noise = (self.current_noise - reduction).max(INITIAL_NOISE_MILLIBITS);
        self.record_snapshot(3);
    }

    /// Record plain multiplication (noise grows by ~log2(scalar))
    pub fn on_mul_plain(&mut self, log2_scalar: u32) {
        let growth = (log2_scalar as i64) * MILLIBITS_PER_BIT;
        self.current_noise += growth;
        self.growth_ema.update(growth);
        self.record_snapshot(4);
    }

    // =========================================================================
    // QUERY METHODS
    // =========================================================================

    /// Get current noise in millibits
    #[inline]
    pub fn noise_millibits(&self) -> i64 {
        self.current_noise
    }

    /// Get remaining budget in millibits
    #[inline]
    pub fn budget_remaining_millibits(&self) -> i64 {
        self.initial_budget - self.current_noise
    }

    /// Get budget utilization as percentage (0-100)
    pub fn utilization_percent(&self) -> i64 {
        if self.initial_budget == 0 {
            return 100;
        }
        (self.current_noise * 100) / self.initial_budget
    }

    /// Check if budget is exhausted (decryption will fail)
    #[inline]
    pub fn is_exhausted(&self) -> bool {
        self.current_noise >= self.initial_budget
    }

    /// Check if budget is critical (<10% remaining)
    #[inline]
    pub fn is_critical(&self) -> bool {
        self.budget_remaining_millibits() < self.initial_budget / 10
    }

    /// Get estimated remaining multiplications
    pub fn remaining_muls_estimate(&self, log2_t: u32) -> u32 {
        let remaining = self.budget_remaining_millibits();
        let avg_growth = self.growth_ema.value_millibits().max(1);
        let mul_cost = (log2_t as i64) * MILLIBITS_PER_BIT + avg_growth;

        if mul_cost <= 0 {
            return u32::MAX;
        }
        (remaining / mul_cost).max(0) as u32
    }

    /// Get multiplication depth
    pub fn mul_depth(&self) -> u32 {
        self.mul_depth
    }

    // =========================================================================
    // INTERNAL
    // =========================================================================

    fn record_snapshot(&mut self, op_type: u8) {
        self.op_count += 1;

        let snapshot = NoiseSnapshot::new(
            self.op_count,
            self.current_noise,
            self.initial_budget,
            op_type,
        );

        // Keep limited history
        if self.history.len() >= 64 {
            self.history.pop_front();
        }
        self.history.push_back(snapshot);
    }
}

// =============================================================================
// MULTI-WINDOW NOISE DETECTOR - Anomaly detection across time horizons
// =============================================================================

/// Window for computing running statistics
#[derive(Debug, Clone)]
pub struct NoiseWindow {
    values: VecDeque<i64>,
    capacity: usize,
    sum: i64,
    sum_squares: i64,
}

impl NoiseWindow {
    pub fn new(capacity: usize) -> Self {
        Self {
            values: VecDeque::with_capacity(capacity),
            capacity,
            sum: 0,
            sum_squares: 0,
        }
    }

    /// Add value to window
    pub fn push(&mut self, value: i64) {
        if self.values.len() == self.capacity {
            if let Some(old) = self.values.pop_front() {
                self.sum -= old;
                // Use smaller divisor (100) to preserve precision
                let old_scaled = old / 100;
                self.sum_squares -= old_scaled * old_scaled;
            }
        }

        self.sum += value;
        let value_scaled = value / 100;
        self.sum_squares += value_scaled * value_scaled;
        self.values.push_back(value);
    }

    /// Get mean value
    pub fn mean(&self) -> i64 {
        if self.values.is_empty() {
            0
        } else {
            self.sum / self.values.len() as i64
        }
    }

    /// Get standard deviation using integer sqrt
    pub fn std_dev(&self) -> i64 {
        if self.values.len() < 2 {
            return 0;
        }

        let n = self.values.len() as i64;
        let mean = self.mean();
        let mean_scaled = mean / 100;
        let mean_sq = mean_scaled * mean_scaled;
        let variance = (self.sum_squares / n).saturating_sub(mean_sq).max(0);

        // Scale back: sqrt(variance) * 100 to restore original scale
        integer_sqrt(variance) * 100
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

// =============================================================================
// P² QUANTILE ESTIMATOR - O(1) Memory Streaming Percentiles
// =============================================================================

/// Number of markers for P² algorithm
const P2_MARKERS: usize = 5;

/// P² Quantile Estimator - computes streaming percentiles without storing history
///
/// Based on: Jain & Chlamtac, "The P² Algorithm for Dynamic Calculation
/// of Quantiles and Histograms Without Storing Observations" (1985)
///
/// Memory: O(1) - only 5 markers regardless of sample count
/// Time: O(1) per update
///
/// INTEGER-ONLY IMPLEMENTATION: Uses Q32.32 fixed-point arithmetic.
/// No floating point = perfect determinism across platforms.
///
/// Fixed-point format: 1.0 = Q32_ONE = 2^32 = 4294967296
#[derive(Debug, Clone)]
pub struct P2QuantileEstimator {
    /// Target quantile in Q32.32 format (0 to Q32_ONE represents 0.0 to 1.0)
    p_q32: i64,

    /// Marker heights (sorted sample values in millibits)
    q: [i64; P2_MARKERS],

    /// Actual marker positions (1-indexed)
    n: [i64; P2_MARKERS],

    /// Desired marker positions in Q32.32 format
    n_prime_q32: [i64; P2_MARKERS],

    /// Increment for desired positions in Q32.32 format
    dn_q32: [i64; P2_MARKERS],

    /// Total observation count
    count: u64,
}

/// Q32.32 fixed-point representation of 1.0
const Q32_ONE: i64 = 1i64 << 32;

impl P2QuantileEstimator {
    /// Create estimator for given quantile in permille (0-1000, where 500 = 0.5)
    pub fn new(p_permille: i64) -> Self {
        assert!(
            (0..=1000).contains(&p_permille),
            "p_permille must be 0-1000"
        );

        // Convert permille to Q32.32: p_q32 = p_permille * Q32_ONE / 1000
        let p_q32 = (p_permille * Q32_ONE) / 1000;

        // Initial n_prime values in Q32.32:
        // [1.0, 1.0 + 2.0*p, 1.0 + 4.0*p, 3.0 + 2.0*p, 5.0]
        let n_prime_q32 = [
            Q32_ONE,                 // 1.0
            Q32_ONE + 2 * p_q32,     // 1.0 + 2.0*p
            Q32_ONE + 4 * p_q32,     // 1.0 + 4.0*p
            3 * Q32_ONE + 2 * p_q32, // 3.0 + 2.0*p
            5 * Q32_ONE,             // 5.0
        ];

        // dn values in Q32.32: [0.0, p/2, p, (1+p)/2, 1.0]
        let dn_q32 = [
            0,                     // 0.0
            p_q32 / 2,             // p/2
            p_q32,                 // p
            (Q32_ONE + p_q32) / 2, // (1+p)/2
            Q32_ONE,               // 1.0
        ];

        Self {
            p_q32,
            q: [0; P2_MARKERS],
            n: [1, 2, 3, 4, 5],
            n_prime_q32,
            dn_q32,
            count: 0,
        }
    }

    /// Median estimator (p = 0.5)
    pub fn median() -> Self {
        Self::new(500)
    }

    /// 90th percentile estimator
    pub fn p90() -> Self {
        Self::new(900)
    }

    /// 95th percentile estimator
    pub fn p95() -> Self {
        Self::new(950)
    }

    /// 99th percentile estimator
    pub fn p99() -> Self {
        Self::new(990)
    }

    /// Update estimator with new observation (in millibits)
    pub fn update(&mut self, x: i64) {
        self.count += 1;

        if self.count <= P2_MARKERS as u64 {
            // Initialization phase: collect first 5 samples
            self.q[(self.count - 1) as usize] = x;

            if self.count == P2_MARKERS as u64 {
                // Sort initial samples
                self.q.sort_unstable();
            }
            return;
        }

        // Find cell k where x falls
        let k: usize;
        if x < self.q[0] {
            self.q[0] = x;
            k = 0;
        } else if x < self.q[1] {
            k = 0;
        } else if x < self.q[2] {
            k = 1;
        } else if x < self.q[3] {
            k = 2;
        } else if x < self.q[4] {
            k = 3;
        } else {
            k = 3;
            if x > self.q[4] {
                self.q[4] = x;
            }
        }

        // Increment positions of markers > k
        for i in (k + 1)..P2_MARKERS {
            self.n[i] += 1;
        }

        // Update desired positions (Q32.32 arithmetic)
        for i in 0..P2_MARKERS {
            self.n_prime_q32[i] += self.dn_q32[i];
        }

        // Adjust heights of markers 1, 2, 3 if needed
        for i in 1..=3 {
            // d = n_prime[i] - n[i] in Q32.32
            let d_q32 = self.n_prime_q32[i] - (self.n[i] * Q32_ONE);

            // Check if |d| >= 1.0 and there's room to adjust
            if (d_q32 >= Q32_ONE && self.n[i + 1] - self.n[i] > 1)
                || (d_q32 <= -Q32_ONE && self.n[i - 1] - self.n[i] < -1)
            {
                let d_sign = if d_q32 >= 0 { 1i64 } else { -1i64 };

                // Try parabolic interpolation
                let q_new = self.parabolic_q32(i, d_sign);

                if self.q[i - 1] < q_new && q_new < self.q[i + 1] {
                    self.q[i] = q_new;
                } else {
                    // Use linear interpolation fallback
                    self.q[i] = self.linear_q32(i, d_sign);
                }

                self.n[i] += d_sign;
            }
        }
    }

    /// Parabolic interpolation (P² formula) - INTEGER ONLY
    /// Uses i128 for intermediate calculations to prevent overflow
    fn parabolic_q32(&self, i: usize, d: i64) -> i64 {
        let ni = self.n[i];
        let ni_prev = self.n[i - 1];
        let ni_next = self.n[i + 1];

        let qi = self.q[i];
        let qi_prev = self.q[i - 1];
        let qi_next = self.q[i + 1];

        // term1 = (ni - ni_prev + d) * (qi_next - qi) / (ni_next - ni)
        let num1 = (ni - ni_prev + d) as i128 * (qi_next - qi) as i128;
        let denom1 = (ni_next - ni) as i128;
        let term1 = if denom1 != 0 { num1 / denom1 } else { 0 };

        // term2 = (ni_next - ni - d) * (qi - qi_prev) / (ni - ni_prev)
        let num2 = (ni_next - ni - d) as i128 * (qi - qi_prev) as i128;
        let denom2 = (ni - ni_prev) as i128;
        let term2 = if denom2 != 0 { num2 / denom2 } else { 0 };

        // result = qi + d / (ni_next - ni_prev) * (term1 + term2)
        let denom_final = (ni_next - ni_prev) as i128;
        let adjustment = if denom_final != 0 {
            (d as i128 * (term1 + term2)) / denom_final
        } else {
            0
        };

        (qi as i128 + adjustment) as i64
    }

    /// Linear interpolation fallback - INTEGER ONLY
    fn linear_q32(&self, i: usize, d: i64) -> i64 {
        let qi = self.q[i];
        let (qi_neighbor, ni_neighbor) = if d > 0 {
            (self.q[i + 1], self.n[i + 1])
        } else {
            (self.q[i - 1], self.n[i - 1])
        };
        let ni = self.n[i];

        // result = qi + d * (qi_neighbor - qi) / (ni_neighbor - ni)
        let denom = (ni_neighbor - ni) as i128;
        if denom == 0 {
            return qi;
        }

        let adjustment = (d as i128 * (qi_neighbor - qi) as i128) / denom;
        (qi as i128 + adjustment) as i64
    }

    /// Get current quantile estimate (in millibits)
    pub fn value(&self) -> i64 {
        if self.count < P2_MARKERS as u64 {
            // Not enough samples - return best available
            if self.count == 0 {
                return 0;
            }
            // idx = (count - 1) * p_q32 / Q32_ONE
            let idx = (((self.count - 1) as i64 * self.p_q32) / Q32_ONE) as usize;
            return self.q[idx.min(self.count as usize - 1)];
        }

        // Middle marker (index 2) is the quantile estimate
        self.q[2]
    }

    /// Get value in millibits/1000 (for display - returns integer millibits)
    pub fn value_millibits(&self) -> i64 {
        self.value()
    }

    /// Get value as (integer_bits, milli_fraction) for display
    /// e.g., 3500 millibits -> (3, 500) meaning 3.500 bits
    pub fn value_bits_parts(&self) -> (i64, i64) {
        let v = self.value();
        (v / MILLIBITS_PER_BIT as i64, v % MILLIBITS_PER_BIT as i64)
    }

    /// Get observation count
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Get all marker heights (for debugging)
    pub fn markers(&self) -> [i64; P2_MARKERS] {
        self.q
    }
}

/// Noise distribution tracker using multiple P² estimators
#[derive(Debug, Clone)]
pub struct NoiseDistribution {
    /// Median (P50)
    pub median: P2QuantileEstimator,
    /// 90th percentile
    pub p90: P2QuantileEstimator,
    /// 95th percentile
    pub p95: P2QuantileEstimator,
    /// 99th percentile
    pub p99: P2QuantileEstimator,
    /// Running sum for mean calculation
    sum: i64,
    /// Sample count
    count: u64,
}

impl Default for NoiseDistribution {
    fn default() -> Self {
        Self {
            median: P2QuantileEstimator::median(),
            p90: P2QuantileEstimator::p90(),
            p95: P2QuantileEstimator::p95(),
            p99: P2QuantileEstimator::p99(),
            sum: 0,
            count: 0,
        }
    }
}

impl NoiseDistribution {
    pub fn new() -> Self {
        Self::default()
    }

    /// Update all estimators with new noise observation (millibits)
    pub fn update(&mut self, noise_millibits: i64) {
        self.median.update(noise_millibits);
        self.p90.update(noise_millibits);
        self.p95.update(noise_millibits);
        self.p99.update(noise_millibits);
        self.sum += noise_millibits;
        self.count += 1;
    }

    /// Get mean noise (millibits)
    pub fn mean(&self) -> i64 {
        if self.count == 0 {
            0
        } else {
            self.sum / self.count as i64
        }
    }

    /// Get mean in millibits
    pub fn mean_millibits(&self) -> i64 {
        self.mean()
    }

    /// Get median in millibits
    pub fn median_millibits(&self) -> i64 {
        self.median.value()
    }

    /// Get P90 in millibits
    pub fn p90_millibits(&self) -> i64 {
        self.p90.value()
    }

    /// Get P95 in millibits
    pub fn p95_millibits(&self) -> i64 {
        self.p95.value()
    }

    /// Get P99 in millibits
    pub fn p99_millibits(&self) -> i64 {
        self.p99.value()
    }

    /// Print distribution summary
    pub fn summary(&self) -> String {
        use crate::arithmetic::integer_math::format_millibits;
        format!(
            "Noise Distribution (n={}): mean={} median={} P90={} P95={} P99={} bits",
            self.count,
            format_millibits(self.mean_millibits() as u64),
            format_millibits(self.median_millibits() as u64),
            format_millibits(self.p90_millibits() as u64),
            format_millibits(self.p95_millibits() as u64),
            format_millibits(self.p99_millibits() as u64)
        )
    }
}

/// Integer square root using Newton's method
pub fn integer_sqrt(n: i64) -> i64 {
    if n <= 0 {
        return 0;
    }

    let mut x = n;
    let mut y = (x + 1) / 2;

    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }

    x
}

/// MultiWindowNoiseDetector detects anomalous noise growth
#[derive(Debug, Clone)]
pub struct MultiWindowNoiseDetector {
    /// Short window (16 operations)
    short: NoiseWindow,
    /// Medium window (64 operations)
    medium: NoiseWindow,
    /// Long window (256 operations)
    long: NoiseWindow,
    /// Alert threshold in standard deviations (FixedQ)
    threshold_sigma: i64,
}

impl Default for MultiWindowNoiseDetector {
    fn default() -> Self {
        Self {
            short: NoiseWindow::new(16),
            medium: NoiseWindow::new(64),
            long: NoiseWindow::new(256),
            threshold_sigma: 3 * FIXEDQ_SCALE, // 3σ threshold
        }
    }
}

impl MultiWindowNoiseDetector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Update with new noise measurement (millibits)
    pub fn update(&mut self, noise_millibits: i64) {
        self.short.push(noise_millibits);
        self.medium.push(noise_millibits);
        self.long.push(noise_millibits);
    }

    /// Detect anomalous noise growth
    pub fn detect_anomaly(&self, current_noise: i64) -> NoiseAnomaly {
        let short_z = self.z_score(&self.short, current_noise);
        let medium_z = self.z_score(&self.medium, current_noise);
        let long_z = self.z_score(&self.long, current_noise);

        NoiseAnomaly {
            short_anomaly: short_z.abs() > self.threshold_sigma,
            medium_anomaly: medium_z.abs() > self.threshold_sigma,
            long_anomaly: long_z.abs() > self.threshold_sigma,
            short_z,
            medium_z,
            long_z,
        }
    }

    fn z_score(&self, window: &NoiseWindow, value: i64) -> i64 {
        if window.len() < 2 {
            return 0;
        }

        let mean = window.mean();
        let std = window.std_dev();

        if std == 0 {
            return 0;
        }

        ((value - mean) * FIXEDQ_SCALE) / std
    }
}

/// Noise anomaly signal
#[derive(Debug, Clone)]
pub struct NoiseAnomaly {
    pub short_anomaly: bool,
    pub medium_anomaly: bool,
    pub long_anomaly: bool,
    pub short_z: i64,
    pub medium_z: i64,
    pub long_z: i64,
}

impl NoiseAnomaly {
    pub fn has_anomaly(&self) -> bool {
        self.short_anomaly || self.medium_anomaly || self.long_anomaly
    }

    pub fn severity(&self) -> u8 {
        (self.short_anomaly as u8) + (self.medium_anomaly as u8) + (self.long_anomaly as u8)
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ema_calculation() {
        let mut ema = EMACalculator::new(1, 10); // alpha = 0.1

        ema.update(1000); // 1 bit
        assert_eq!(ema.value_millibits(), 1000);

        ema.update(2000); // 2 bits
                          // EMA = 0.1 * 2000 + 0.9 * 1000 = 1100
        assert!((ema.value_millibits() - 1100).abs() < 50);
    }

    #[test]
    fn test_noise_budget_tracker() {
        let mut tracker = NoiseBudgetTracker::new(100); // 100-bit budget

        tracker.on_encrypt();
        assert!(tracker.noise_millibits() < 5000); // Initial noise ~3.2 bits = 3200 mb

        // Simulate 10 additions
        for _ in 0..10 {
            tracker.on_add();
        }

        assert!(tracker.noise_millibits() < 15000); // ~13 bits after 10 adds
        assert!(!tracker.is_exhausted());
    }

    #[test]
    fn test_noise_budget_exhaustion() {
        let mut tracker = NoiseBudgetTracker::new(20); // Small 20-bit budget

        tracker.on_encrypt();

        // Simulate multiplications until exhausted
        for _ in 0..10 {
            if tracker.is_exhausted() {
                break;
            }
            tracker.on_mul(tracker.noise_millibits(), 16); // log2(t)=16
        }

        println!("Final noise: {} millibits", tracker.noise_millibits());
        println!("Mul depth: {}", tracker.mul_depth());
        assert!(tracker.mul_depth() <= 3); // Should exhaust in ~2-3 muls
    }

    #[test]
    fn test_noise_window() {
        let mut window = NoiseWindow::new(10);

        for i in 1..=10 {
            window.push(i * 1000); // 1-10 bits
        }

        let mean = window.mean();
        assert_eq!(mean, 5500); // Average of 1000..10000 = 5500
    }

    #[test]
    fn test_integer_sqrt() {
        assert_eq!(integer_sqrt(0), 0);
        assert_eq!(integer_sqrt(1), 1);
        assert_eq!(integer_sqrt(4), 2);
        assert_eq!(integer_sqrt(100), 10);
        assert_eq!(integer_sqrt(1000000), 1000);
    }

    #[test]
    fn test_multi_window_detector() {
        let mut detector = MultiWindowNoiseDetector::new();

        // Add noise values with variance (using wider range)
        for i in 0..200 {
            // Add significant variation to establish measurable std dev
            let noise = 5000 + ((i as i64 % 20) - 10) * 100; // 4000-6000 millibits
            detector.update(noise);
        }

        // Check baseline statistics
        let short_mean = detector.short.mean();
        let short_std = detector.short.std_dev();
        println!("Short window: mean={}, std={}", short_mean, short_std);

        // With scale/100, values 4000-6000 give std_dev ~575
        assert!(short_std > 0, "Should have measurable std dev");

        // Normal value (within range) should not trigger
        let signal = detector.detect_anomaly(5000);
        println!(
            "Normal value z-scores: short={}, medium={}, long={}",
            signal.short_z, signal.medium_z, signal.long_z
        );
        assert!(
            !signal.short_anomaly,
            "Normal value should not trigger short anomaly"
        );

        // Large spike (50 bits = 10× baseline) should trigger
        let signal = detector.detect_anomaly(50000);
        println!(
            "Spike z-scores: short={}, medium={}, long={}",
            signal.short_z, signal.medium_z, signal.long_z
        );

        // With std_dev ~575, a spike of 45000 above mean should give z-score ~78
        // which is well above the 3.0 threshold
        assert!(signal.has_anomaly(), "10× spike should trigger anomaly");
    }

    #[test]
    fn test_p2_quantile_median() {
        let mut p2 = P2QuantileEstimator::median();

        // Add values 1-100 bits (1000-100000 millibits)
        for i in 1..=100 {
            p2.update(i * MILLIBITS_PER_BIT);
        }

        let median = p2.value();
        let expected = 50 * MILLIBITS_PER_BIT; // 50 bits

        println!("P² median estimate: {} millibits", median);
        println!("Expected: {} millibits", expected);

        // P² should be within 10% of true median for 100 samples
        let error = (median - expected).abs();
        let tolerance = expected / 10; // 10% tolerance
        assert!(
            error < tolerance,
            "Median error {} exceeds tolerance {}",
            error,
            tolerance
        );
    }

    #[test]
    fn test_p2_quantile_p95() {
        let mut p2 = P2QuantileEstimator::p95();

        // Add values 1-100 bits
        for i in 1..=100 {
            p2.update(i * MILLIBITS_PER_BIT);
        }

        let p95 = p2.value();
        let expected = 95 * MILLIBITS_PER_BIT; // 95 bits

        println!("P² P95 estimate: {} millibits", p95);
        println!("Expected: {} millibits", expected);

        // P95 should be within 15% for 100 samples
        let error = (p95 - expected).abs();
        let tolerance = expected / 7; // ~15% tolerance
        assert!(
            error < tolerance,
            "P95 error {} exceeds tolerance {}",
            error,
            tolerance
        );
    }

    #[test]
    fn test_p2_large_stream() {
        let mut p2 = P2QuantileEstimator::median();

        // Simulate 10,000 FHE operations with noise growing from 3-50 bits
        for i in 0..10_000 {
            // Noise grows logarithmically, typical for FHE
            let noise = 3000 + (i as i64 * 47) / 10; // 3 to ~50 bits
            p2.update(noise);
        }

        let median_mb = p2.value_millibits();
        println!(
            "Median over 10k ops: {} millibits (expected ~26500)",
            median_mb
        );

        // Median of 3-50 linear sequence should be ~26.5 bits = 26500 millibits
        assert!(
            median_mb > 20000 && median_mb < 35000,
            "Median {} outside expected range",
            median_mb
        );

        // Verify O(1) memory - only 5 markers stored
        assert_eq!(p2.markers().len(), 5);
        assert_eq!(p2.count(), 10_000);
    }

    #[test]
    fn test_noise_distribution() {
        let mut dist = NoiseDistribution::new();

        // Add 1000 noise samples with increasing trend
        for i in 0..1000 {
            // Noise: 5-25 bits with some variance
            let base = 5000 + (i as i64 * 20); // 5 to 25 bits
            let variance = ((i % 10) as i64 - 5) * 100; // ±500 millibits
            dist.update(base + variance);
        }

        println!("{}", dist.summary());

        // Verify ordering: median < P90 < P95 < P99
        assert!(
            dist.median_millibits() < dist.p90_millibits(),
            "Median should be less than P90"
        );
        assert!(
            dist.p90_millibits() < dist.p95_millibits(),
            "P90 should be less than P95"
        );
        assert!(
            dist.p95_millibits() <= dist.p99_millibits(),
            "P95 should be less than or equal to P99"
        );

        // Mean should be close to median for uniform-ish distribution
        let mean_median_diff = (dist.mean_millibits() - dist.median_millibits()).abs();
        assert!(
            mean_median_diff < 5000,
            "Mean-median difference {} too large",
            mean_median_diff
        );
    }

    #[test]
    fn test_p2_o1_memory() {
        let mut p2 = P2QuantileEstimator::median();

        // Add 100,000 samples with uniform distribution 10-90 bits
        for i in 0..100_000 {
            let noise = 10000 + (i % 80000); // 10 to 90 bits in millibits
            p2.update(noise);
        }

        // Memory is still O(1) - only 5 markers
        assert_eq!(p2.markers().len(), 5);
        assert_eq!(p2.count(), 100_000);

        // Median of 10-90 uniform should be ~50 bits
        let median_mb = p2.value_millibits();
        println!(
            "Median of 100k samples (10-90 bits): {} millibits",
            median_mb
        );

        // Allow reasonable tolerance for P² algorithm
        assert!(
            median_mb > 30000 && median_mb < 70000,
            "Median {} outside expected range 30000-70000",
            median_mb
        );
    }

    #[test]
    fn test_budget_utilization() {
        let mut tracker = NoiseBudgetTracker::new(100);
        tracker.on_encrypt();

        let initial_util = tracker.utilization_percent();
        assert!(initial_util < 10); // ~3% initially

        // Add noise
        for _ in 0..50 {
            tracker.on_add();
        }

        let final_util = tracker.utilization_percent();
        assert!(final_util > initial_util);
        println!("Utilization: {}%", final_util);
    }

    #[test]
    fn test_remaining_muls_estimate() {
        let mut tracker = NoiseBudgetTracker::new(100);
        tracker.on_encrypt();

        let estimate = tracker.remaining_muls_estimate(16);
        println!("Estimated remaining muls: {}", estimate);

        assert!(estimate > 0);
        assert!(estimate < 10); // Should be limited with 100-bit budget
    }
}
