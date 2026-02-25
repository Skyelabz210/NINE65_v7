//! Noise Budget Tracking Module
//!
//! Integer-based noise budget tracking for FHE operations.
//! Uses millibits (1000 millibits = 1 bit) for precision without floats.
//!
//! # Integer Noise Tracking
//!
//! Standard FHE libraries use floating-point for noise estimation:
//! ```ignore
//! noise_bits = log2(noise_magnitude)  // FLOAT!
//! ```
//!
//! QMNF uses exact integer arithmetic in millibits:
//! ```ignore
//! noise_millibits = integer_log2_scaled(noise_magnitude, 1000)
//! ```
//!
//! This prevents drift in noise estimates over deep circuits.
//!
//! # Precision Analysis
//!
//! Millibits precision (1000/bit) is sufficient for all practical circuits:
//! - Depth 20: max cumulative error = 20 × 0.5 = 10 millibits = 0.01 bits
//! - Depth 50: max cumulative error = 50 × 0.5 = 25 millibits = 0.025 bits
//! - Depth 100: max cumulative error = 100 × 0.5 = 50 millibits = 0.05 bits
//!
//! With typical 30-bit budgets, relative error is < 0.2% even for extreme depths.
//! Microbits (1M/bit) is unnecessary and would only add computational overhead.

use crate::params::FHEConfig;

/// Noise budget in millibits (1000 millibits = 1 bit)
///
/// Tracks remaining noise budget through FHE operations.
/// When budget reaches 0, decryption will fail.
#[derive(Clone, Debug)]
pub struct NoiseBudget {
    /// Remaining budget in millibits
    remaining_mb: i64,
    /// Initial budget in millibits
    initial_mb: i64,
    /// Operations log (for debugging)
    operations: Vec<NoiseOperation>,
}

/// Record of a noise-consuming operation
#[derive(Clone, Debug)]
pub struct NoiseOperation {
    /// Operation type
    pub op_type: NoiseOpType,
    /// Noise cost in millibits
    pub cost_mb: i64,
    /// Budget after operation
    pub remaining_mb: i64,
}

/// Types of FHE operations
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum NoiseOpType {
    /// Fresh encryption
    Encrypt,
    /// Homomorphic addition (ct + ct)
    Add,
    /// Addition with plaintext (ct + pt)
    AddPlain,
    /// Multiplication with plaintext (ct × pt)
    MulPlain,
    /// Ciphertext multiplication (ct × ct)
    MulCt,
    /// Relinearization after multiplication
    Relin,
    /// Modulus switching / rescaling
    Rescale,
    /// Bootstrap (noise refresh)
    Bootstrap,
}

/// Error when noise budget is exhausted
#[derive(Debug, Clone)]
pub struct NoiseExhausted {
    /// How much budget was needed
    pub required_mb: i64,
    /// How much was available
    pub available_mb: i64,
    /// Total operations performed
    pub operation_count: usize,
    /// Last operation attempted
    pub last_op: NoiseOpType,
}

impl std::fmt::Display for NoiseExhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Noise budget exhausted: needed {} millibits, had {} (after {} ops)",
            self.required_mb, self.available_mb, self.operation_count
        )
    }
}

impl std::error::Error for NoiseExhausted {}

impl NoiseBudget {
    /// Create noise budget from FHE parameters
    ///
    /// Budget is calculated as: log2(Δ) - log2(initial_noise)
    /// where Δ = q/t is the scaling factor and initial_noise depends on η
    pub fn from_config(config: &FHEConfig) -> Self {
        // Approximate log2(Q / t) where Q is the full RNS modulus product.
        // We sum per-prime bit widths to avoid underestimating budget by only
        // looking at `config.q` (which is a single prime representative).
        let log_q_bits: i64 = config
            .primes
            .iter()
            .map(|&p| (64 - p.leading_zeros()) as i64)
            .sum();
        let t_bits = (64 - config.t.leading_zeros()) as i64;
        let delta_bits = (log_q_bits - t_bits).max(0);
        let delta_mb = delta_bits * 1000;

        // Initial noise estimate: η × √N × constant
        // In millibits: approximately (log2(η) + log2(N)/2 + 3) × 1000
        let eta_bits = if config.eta > 0 {
            64 - (config.eta as u64).leading_zeros()
        } else {
            1
        };
        let n_bits = config.n.trailing_zeros(); // log2(N) since N is power of 2
        let initial_noise_mb = ((eta_bits as i64) + (n_bits as i64 / 2) + 3) * 1000;

        let budget_mb = delta_mb.saturating_sub(initial_noise_mb);

        Self {
            remaining_mb: budget_mb,
            initial_mb: budget_mb,
            operations: Vec::new(),
        }
    }

    /// Create with specific initial budget (for testing)
    pub fn with_budget_bits(bits: i64) -> Self {
        let mb = bits * 1000;
        Self {
            remaining_mb: mb,
            initial_mb: mb,
            operations: Vec::new(),
        }
    }

    /// Consume noise budget for an operation.
    ///
    /// Returns `Ok(remaining)` if budget sufficient, `Err(NoiseExhausted)` otherwise.
    ///
    /// # Overflow Protection (IBM BFV Attack Defense)
    ///
    /// Uses checked arithmetic to detect overflow. If the subtraction would
    /// overflow i64, the operation is rejected. This prevents silent wraparound
    /// which could mask noise budget exhaustion — exactly the condition
    /// exploited by IBM's 2025 BFV key recovery attack.
    pub fn consume(&mut self, op_type: NoiseOpType, cost_mb: i64) -> Result<i64, NoiseExhausted> {
        // Check budget sufficiency (positive costs only)
        if cost_mb > 0 && self.remaining_mb < cost_mb {
            return Err(NoiseExhausted {
                required_mb: cost_mb,
                available_mb: self.remaining_mb,
                operation_count: self.operations.len(),
                last_op: op_type,
            });
        }

        // Checked subtraction to prevent silent overflow
        let new_remaining = self.remaining_mb.checked_sub(cost_mb).ok_or(NoiseExhausted {
            required_mb: cost_mb,
            available_mb: self.remaining_mb,
            operation_count: self.operations.len(),
            last_op: op_type,
        })?;

        self.remaining_mb = new_remaining;

        self.operations.push(NoiseOperation {
            op_type,
            cost_mb,
            remaining_mb: self.remaining_mb,
        });

        Ok(self.remaining_mb)
    }

    /// Estimate cost of encryption
    pub fn encrypt_cost(config: &FHEConfig) -> i64 {
        // Encryption adds error e with distribution CBD(η)
        // Cost ≈ log2(η × √N) × 1000 millibits
        let eta_bits = 64 - (config.eta as u64).leading_zeros();
        let n_bits = config.n.trailing_zeros();
        ((eta_bits as i64) + (n_bits as i64 / 2)) * 1000
    }

    /// Estimate cost of homomorphic addition
    pub fn add_cost() -> i64 {
        // Addition roughly doubles noise, cost ≈ 1 bit = 1000 millibits
        1000
    }

    /// Estimate cost of plaintext addition
    pub fn add_plain_cost() -> i64 {
        // Minimal noise increase
        100
    }

    /// Estimate cost of plaintext multiplication
    pub fn mul_plain_cost(config: &FHEConfig) -> i64 {
        // Noise multiplied by plaintext coefficient bound
        // Cost ≈ log2(t) × 1000 millibits
        let t_bits = 64 - config.t.leading_zeros();
        (t_bits as i64) * 1000
    }

    /// Estimate cost of ciphertext multiplication
    pub fn mul_ct_cost(config: &FHEConfig) -> i64 {
        // Most expensive operation
        // Cost ≈ (log2(t) + log2(N) + log2(η)) × 1000
        let t_bits = 64 - config.t.leading_zeros();
        let n_bits = config.n.trailing_zeros();
        let eta_bits = 64 - (config.eta as u64).leading_zeros();
        ((t_bits as i64) + (n_bits as i64) + (eta_bits as i64)) * 1000
    }

    /// Estimate cost of relinearization
    pub fn relin_cost(config: &FHEConfig) -> i64 {
        // Depends on decomposition base
        // Typically adds log2(N) bits of noise
        let n_bits = config.n.trailing_zeros();
        (n_bits as i64) * 1000
    }

    /// Estimate cost of K-Elimination rescaling
    ///
    /// K-Elimination rescaling divides by the plaintext modulus t,
    /// which REDUCES noise instead of adding it. Returns negative cost.
    pub fn rescale_cost(config: &FHEConfig) -> i64 {
        // Rescaling divides by t, reducing noise by log2(t) bits
        // This is a GAIN (negative cost)
        let t_bits = 64 - config.t.leading_zeros();
        -((t_bits as i64) * 1000) // Negative = gives back budget
    }

    /// Estimate net cost of one multiplication cycle (mul + relin + rescale)
    ///
    /// This is the typical cost when doing depth-d circuits.
    pub fn multiplication_cycle_cost(config: &FHEConfig) -> i64 {
        let mul_cost = Self::mul_ct_cost(config);
        let relin_cost = Self::relin_cost(config);
        let rescale_gain = Self::rescale_cost(config); // Negative
        mul_cost + relin_cost + rescale_gain
    }

    /// Get remaining budget in millibits
    pub fn remaining_millibits(&self) -> i64 {
        self.remaining_mb
    }

    /// Get initial budget in millibits
    pub fn initial_millibits(&self) -> i64 {
        self.initial_mb
    }

    /// Check if operation can be performed
    ///
    /// For operations with a negative cost (e.g., rescaling, which refunds noise
    /// budget), this always returns true — budget-refunding operations are never
    /// blocked by an insufficient budget.
    pub fn can_perform(&self, cost_mb: i64) -> bool {
        if cost_mb < 0 {
            // Negative cost means the operation improves the noise budget (e.g.,
            // rescaling after a multiplication). Always allow it.
            return true;
        }
        self.remaining_mb >= cost_mb
    }

    /// Estimate how many more multiplications can be performed
    pub fn remaining_multiplications(&self, config: &FHEConfig) -> usize {
        let mul_cost = Self::mul_ct_cost(config) + Self::relin_cost(config);
        if mul_cost <= 0 {
            return usize::MAX;
        }
        (self.remaining_mb / mul_cost) as usize
    }

    /// Reset budget after successful bootstrap.
    ///
    /// Post-bootstrap noise is approximately `t × η × √N`, so the
    /// remaining budget is `log2(Q/t) − log2(t × η × √N)`, i.e.
    /// `log2(Q) − 2·log2(t) − log2(η) − log2(N)/2`.
    pub fn reset_after_bootstrap(&mut self, config: &FHEConfig) {
        let log_q_bits: i64 = config
            .primes
            .iter()
            .map(|&p| (64 - p.leading_zeros()) as i64)
            .sum();
        let t_bits = (64 - config.t.leading_zeros()) as i64;
        let eta_bits = if config.eta > 0 {
            (64 - (config.eta as u64).leading_zeros()) as i64
        } else {
            1
        };
        let n_half_bits = (config.n.trailing_zeros() / 2) as i64;

        // budget = delta_bits − bootstrap_noise_bits
        //        = (log_Q − log_t) − (log_t + log_η + log_√N)
        //        = log_Q − 2·log_t − log_η − log_√N
        let post_bootstrap_mb =
            (log_q_bits - 2 * t_bits - eta_bits - n_half_bits).max(0) * 1000;
        self.remaining_mb = post_bootstrap_mb;
        self.operations.push(NoiseOperation {
            op_type: NoiseOpType::Bootstrap,
            cost_mb: 0,
            remaining_mb: self.remaining_mb,
        });
    }

    /// Check if bootstrap should trigger (budget below threshold).
    /// threshold_permille: 250 means trigger at 25% remaining budget.
    pub fn should_bootstrap(&self, threshold_permille: u32) -> bool {
        let threshold_mb = (self.initial_mb * threshold_permille as i64) / 1000;
        self.remaining_mb <= threshold_mb
    }

    /// Get operation history
    pub fn operations(&self) -> &[NoiseOperation] {
        &self.operations
    }

    /// Get summary statistics
    pub fn summary(&self) -> String {
        use crate::arithmetic::integer_math::format_millibits;
        let used = self.initial_mb - self.remaining_mb;
        let used_percent = if self.initial_mb > 0 {
            (used * 100) / self.initial_mb
        } else {
            100
        };
        format!(
            "Noise Budget: {}/{} bits remaining ({}% used, {} ops)",
            format_millibits(self.remaining_mb.max(0) as u64),
            format_millibits(self.initial_mb as u64),
            used_percent,
            self.operations.len()
        )
    }
}

impl std::fmt::Display for NoiseBudget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.summary())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::SecureConfig;

    #[test]
    fn test_noise_budget_creation() {
        let config = SecureConfig::secure_128().into_config();
        let budget = NoiseBudget::from_config(&config);

        println!("Light config budget: {}", budget);
        assert!(
            budget.remaining_millibits() > 0,
            "Should have positive budget"
        );
    }

    #[test]
    fn test_noise_budget_consumption() {
        let config = SecureConfig::secure_128().into_config();
        let mut budget = NoiseBudget::from_config(&config);

        let initial = budget.remaining_millibits();

        // Perform addition
        budget
            .consume(NoiseOpType::Add, NoiseBudget::add_cost())
            .unwrap();

        assert!(
            budget.remaining_millibits() < initial,
            "Budget should decrease"
        );
        assert_eq!(budget.operations().len(), 1);
    }

    #[test]
    fn test_noise_budget_exhaustion() {
        let mut budget = NoiseBudget::with_budget_bits(5); // Only 5 bits

        // Try expensive operation
        let result = budget.consume(NoiseOpType::MulCt, 10000); // 10 bits needed

        assert!(result.is_err(), "Should fail when budget exhausted");
        if let Err(e) = result {
            assert_eq!(e.last_op, NoiseOpType::MulCt);
        }
    }

    #[test]
    fn test_noise_budget_tracking() {
        // Use explicit budget for predictable test behavior
        let mut budget = NoiseBudget::with_budget_bits(50); // 50 bits = plenty of room

        println!("Initial: {}", budget);

        // Simulate operations with fixed costs
        let r1 = budget.consume(NoiseOpType::Encrypt, 5000); // 5 bits
        println!("After encrypt: {} (result: {:?})", budget, r1.is_ok());
        assert!(r1.is_ok(), "Encrypt should succeed");

        let r2 = budget.consume(NoiseOpType::Add, 1000); // 1 bit
        println!("After add: {} (result: {:?})", budget, r2.is_ok());
        assert!(r2.is_ok(), "Add should succeed");

        let r3 = budget.consume(NoiseOpType::MulPlain, 10000); // 10 bits
        println!("After mul_plain: {} (result: {:?})", budget, r3.is_ok());
        assert!(r3.is_ok(), "MulPlain should succeed");

        // Check all operations were recorded
        assert_eq!(budget.operations().len(), 3);

        // Verify budget decreased correctly
        assert_eq!(budget.remaining_millibits(), 50000 - 5000 - 1000 - 10000);
    }

    #[test]
    fn test_remaining_multiplications() {
        let config = SecureConfig::secure_128().into_config();
        let budget = NoiseBudget::from_config(&config);

        let remaining_muls = budget.remaining_multiplications(&config);
        println!(
            "Remaining multiplications for light_mul: {}",
            remaining_muls
        );
    }

    #[test]
    fn test_he_standard_budget() {
        let config = SecureConfig::secure_128().into_config();
        let budget = NoiseBudget::from_config(&config);

        println!("HE Standard 128 budget: {}", budget);
        println!(
            "Remaining multiplications: {}",
            budget.remaining_multiplications(&config)
        );

        assert!(
            budget.remaining_millibits() > 0,
            "HE Standard should have positive budget"
        );
    }

    #[test]
    fn test_deep_circuit_precision() {
        // Verify millibits precision is sufficient for depth-100 circuits
        let mut budget = NoiseBudget::with_budget_bits(50); // 50,000 millibits

        // Simulate 100 operations with varying costs
        for i in 0..100 {
            let cost = 100 + (i % 10) * 10; // 100-190 millibits per op
            let _ = budget.consume(NoiseOpType::Add, cost);
        }

        let remaining = budget.remaining_millibits();
        assert!(remaining > 35000, "Should have ~35.5 bits remaining");
        assert!(remaining < 36000, "Should have ~35.5 bits remaining");
        assert_eq!(budget.operations().len(), 100);
    }

    // =====================================================================
    // CATEGORY 10: Noise Budget Extensions (8 tests)
    // =====================================================================

    #[test]
    fn test_budget_from_config_all_production() {
        for sc in [
            SecureConfig::secure_128(),
            SecureConfig::secure_128_deep(),
            SecureConfig::secure_192(),
        ] {
            let config = sc.into_config();
            let budget = NoiseBudget::from_config(&config);
            assert!(
                budget.remaining_millibits() > 0,
                "Config '{}' should have positive budget, got {}",
                config.name,
                budget.remaining_millibits()
            );
        }
    }

    #[test]
    fn test_budget_with_bits_exact() {
        let budget = NoiseBudget::with_budget_bits(50);
        assert_eq!(budget.remaining_millibits(), 50000);
        assert_eq!(budget.initial_millibits(), 50000);
    }

    #[test]
    fn test_budget_consume_exact_decrease() {
        let mut budget = NoiseBudget::with_budget_bits(50);
        budget.consume(NoiseOpType::Add, 5000).unwrap();
        assert_eq!(budget.remaining_millibits(), 45000);
    }

    #[test]
    fn test_budget_consume_rejects_overbudget() {
        let mut budget = NoiseBudget::with_budget_bits(5); // 5000 millibits
        let result = budget.consume(NoiseOpType::MulCt, 10000); // Need 10 bits
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.required_mb, 10000);
            assert_eq!(e.available_mb, 5000);
            assert_eq!(e.last_op, NoiseOpType::MulCt);
        }
    }

    #[test]
    fn test_budget_reset_after_bootstrap_restores() {
        let config = SecureConfig::secure_128().into_config();
        let mut budget = NoiseBudget::from_config(&config);

        // Deplete budget
        let cost = NoiseBudget::mul_ct_cost(&config) + NoiseBudget::relin_cost(&config);
        let _ = budget.consume(NoiseOpType::MulCt, cost);
        let pre_reset = budget.remaining_millibits();

        budget.reset_after_bootstrap(&config);
        let post_reset = budget.remaining_millibits();

        assert!(
            post_reset > pre_reset,
            "Post-bootstrap budget {} should exceed pre-reset {}",
            post_reset,
            pre_reset
        );
    }

    #[test]
    fn test_budget_should_bootstrap_threshold_boundary() {
        let mut budget = NoiseBudget::with_budget_bits(100); // 100,000 mb
        // threshold_permille=250 means trigger at 25% = 25,000 mb
        assert!(!budget.should_bootstrap(250), "100% should not trigger");

        // Consume to exactly 25,000 (75,000 consumed)
        budget.consume(NoiseOpType::MulCt, 75000).unwrap();
        assert!(budget.should_bootstrap(250), "At 25% should trigger");

        // One above threshold
        let mut budget2 = NoiseBudget::with_budget_bits(100);
        budget2.consume(NoiseOpType::MulCt, 74999).unwrap();
        assert!(
            !budget2.should_bootstrap(250),
            "Just above 25% should NOT trigger"
        );
    }

    #[test]
    fn test_budget_cost_functions_deterministic() {
        let config = SecureConfig::secure_128().into_config();

        let mul_cost = NoiseBudget::mul_ct_cost(&config);
        let add_cost = NoiseBudget::add_cost();
        let relin_cost = NoiseBudget::relin_cost(&config);
        let rescale_cost = NoiseBudget::rescale_cost(&config);

        assert!(mul_cost > add_cost, "mul should cost more than add");
        assert!(relin_cost > 0, "relin should have positive cost");
        assert!(rescale_cost < 0, "rescale should be negative (gain)");

        let cycle = NoiseBudget::multiplication_cycle_cost(&config);
        assert_eq!(
            cycle,
            mul_cost + relin_cost + rescale_cost,
            "Cycle should be mul+relin+rescale"
        );
    }

    #[test]
    fn test_budget_consume_checked_overflow_protection() {
        // Create budget near i64 boundaries to test checked arithmetic
        let mut budget = NoiseBudget {
            remaining_mb: i64::MAX,
            initial_mb: i64::MAX,
            operations: Vec::new(),
        };
        // Adding budget (negative cost) near i64::MAX should not overflow
        let result = budget.consume(NoiseOpType::Rescale, i64::MIN);
        // i64::MAX - i64::MIN would overflow, so checked_sub should catch it
        assert!(
            result.is_err(),
            "Should reject operation that would overflow i64"
        );
    }

    #[test]
    fn test_budget_consume_negative_cost_rescale() {
        // Rescaling should add back budget (negative cost)
        let mut budget = NoiseBudget::with_budget_bits(20); // 20,000 mb
        budget.consume(NoiseOpType::MulCt, 10000).unwrap(); // Down to 10,000
        assert_eq!(budget.remaining_millibits(), 10000);

        // Rescale gives back 5,000 (cost = -5000)
        budget.consume(NoiseOpType::Rescale, -5000).unwrap();
        assert_eq!(budget.remaining_millibits(), 15000);
    }

    #[test]
    fn test_budget_remaining_multiplications_monotonic() {
        let config = SecureConfig::secure_128().into_config();
        let mut budget = NoiseBudget::from_config(&config);

        let mut prev_remaining = budget.remaining_multiplications(&config);

        let cost = NoiseBudget::mul_ct_cost(&config) + NoiseBudget::relin_cost(&config);
        for _ in 0..5 {
            if budget.consume(NoiseOpType::MulCt, cost).is_err() {
                break;
            }
            let current = budget.remaining_multiplications(&config);
            assert!(
                current <= prev_remaining,
                "remaining_multiplications should be monotonically decreasing"
            );
            prev_remaining = current;
        }
    }
}
