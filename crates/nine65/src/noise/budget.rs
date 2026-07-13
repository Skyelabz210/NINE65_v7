//! Exact integer noise-budget tracking for NINE65.
//!
//! Budgets are represented in millibits. The full ciphertext modulus remains
//! canonical as its ordered RNS factor vector. Budget initialization and
//! post-bootstrap reset derive their size from the exact multi-limb quotient
//! `floor(Q / t)`; per-lane bit-width sums, saturated products, floating point,
//! Garner reconstruction, and mixed-radix conversion are not used.

use crate::params::FHEConfig;

/// Noise budget in millibits (`1000` millibits = one bit).
#[derive(Clone, Debug)]
pub struct NoiseBudget {
    remaining_mb: i64,
    initial_mb: i64,
    operations: Vec<NoiseOperation>,
}

/// One noise-budget transition.
#[derive(Clone, Debug)]
pub struct NoiseOperation {
    pub op_type: NoiseOpType,
    pub cost_mb: i64,
    pub remaining_mb: i64,
}

/// FHE operations represented in the noise ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NoiseOpType {
    Encrypt,
    Add,
    AddPlain,
    MulPlain,
    MulCt,
    Relin,
    Rescale,
    Bootstrap,
}

/// Error returned when an operation cannot be represented safely in the
/// current budget.
#[derive(Clone, Debug)]
pub struct NoiseExhausted {
    pub required_mb: i64,
    pub available_mb: i64,
    pub operation_count: usize,
    pub last_op: NoiseOpType,
}

impl std::fmt::Display for NoiseExhausted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "Noise budget exhausted: needed {} millibits, had {} (after {} ops)",
            self.required_mb, self.available_mb, self.operation_count
        )
    }
}

impl std::error::Error for NoiseExhausted {}

/// Multiply an ordered factor vector into exact little-endian `u64` limbs.
fn exact_product_limbs(factors: &[u64]) -> Vec<u64> {
    let mut limbs = vec![1u64];

    for &factor in factors {
        let mut carry = 0u128;
        for limb in &mut limbs {
            let product = (*limb as u128) * factor as u128 + carry;
            *limb = product as u64;
            carry = product >> 64;
        }
        if carry != 0 {
            limbs.push(carry as u64);
        }
    }

    trim_limbs(&mut limbs);
    limbs
}

/// Divide one exact little-endian multi-limb integer by a nonzero `u64`.
fn divide_limbs_by_u64(limbs: &[u64], divisor: u64) -> Vec<u64> {
    assert!(divisor != 0, "multi-limb divisor must be nonzero");

    let mut quotient = vec![0u64; limbs.len()];
    let mut remainder = 0u128;
    for index in (0..limbs.len()).rev() {
        let numerator = (remainder << 64) | limbs[index] as u128;
        quotient[index] = (numerator / divisor as u128) as u64;
        remainder = numerator % divisor as u128;
    }

    trim_limbs(&mut quotient);
    quotient
}

fn trim_limbs(limbs: &mut Vec<u64>) {
    while limbs.len() > 1 && limbs.last() == Some(&0) {
        limbs.pop();
    }
}

fn limbs_bit_length(limbs: &[u64]) -> i64 {
    for index in (0..limbs.len()).rev() {
        let limb = limbs[index];
        if limb != 0 {
            return index as i64 * 64 + (64 - limb.leading_zeros()) as i64;
        }
    }
    0
}

fn scalar_bit_length(value: u64) -> i64 {
    if value == 0 {
        0
    } else {
        (64 - value.leading_zeros()) as i64
    }
}

/// Exact bit length of `floor(Q / t)`, where `Q` is the full RNS product.
fn exact_delta_bit_length(config: &FHEConfig) -> i64 {
    assert!(!config.primes.is_empty(), "RNS factor vector must not be empty");
    assert!(config.t >= 2, "plaintext modulus must be at least two");
    assert!(
        config.primes.iter().all(|&prime| config.t < prime),
        "plaintext modulus must be smaller than every RNS prime"
    );

    let product = exact_product_limbs(&config.primes);
    let quotient = divide_limbs_by_u64(&product, config.t);
    limbs_bit_length(&quotient)
}

fn initial_noise_bit_bound(config: &FHEConfig) -> i64 {
    let eta_bits = scalar_bit_length(config.eta as u64).max(1);
    let root_n_bits = (config.n.trailing_zeros() / 2) as i64;
    eta_bits + root_n_bits + 3
}

fn bootstrap_noise_bit_bound(config: &FHEConfig) -> i64 {
    let t_bits = scalar_bit_length(config.t);
    let eta_bits = scalar_bit_length(config.eta as u64).max(1);
    let root_n_bits = (config.n.trailing_zeros() / 2) as i64;
    t_bits + eta_bits + root_n_bits
}

impl NoiseBudget {
    /// Construct a budget from exact RNS quotient size.
    pub fn from_config(config: &FHEConfig) -> Self {
        let delta_bits = exact_delta_bit_length(config);
        let budget_bits = (delta_bits - initial_noise_bit_bound(config)).max(0);
        let budget_mb = budget_bits
            .checked_mul(1000)
            .expect("initial noise budget exceeds i64 millibits");

        Self {
            remaining_mb: budget_mb,
            initial_mb: budget_mb,
            operations: Vec::new(),
        }
    }

    /// Construct an explicit test budget.
    pub fn with_budget_bits(bits: i64) -> Self {
        let millibits = bits
            .checked_mul(1000)
            .expect("explicit noise budget exceeds i64 millibits");
        Self {
            remaining_mb: millibits,
            initial_mb: millibits,
            operations: Vec::new(),
        }
    }

    /// Consume or refund budget using checked integer arithmetic.
    pub fn consume(
        &mut self,
        op_type: NoiseOpType,
        cost_mb: i64,
    ) -> Result<i64, NoiseExhausted> {
        if cost_mb > 0 && self.remaining_mb < cost_mb {
            return Err(self.exhausted(op_type, cost_mb));
        }

        let new_remaining = self
            .remaining_mb
            .checked_sub(cost_mb)
            .ok_or_else(|| self.exhausted(op_type, cost_mb))?;

        self.remaining_mb = new_remaining;
        self.operations.push(NoiseOperation {
            op_type,
            cost_mb,
            remaining_mb: new_remaining,
        });
        Ok(new_remaining)
    }

    fn exhausted(&self, last_op: NoiseOpType, required_mb: i64) -> NoiseExhausted {
        NoiseExhausted {
            required_mb,
            available_mb: self.remaining_mb,
            operation_count: self.operations.len(),
            last_op,
        }
    }

    pub fn encrypt_cost(config: &FHEConfig) -> i64 {
        let eta_bits = scalar_bit_length(config.eta as u64).max(1);
        let root_n_bits = (config.n.trailing_zeros() / 2) as i64;
        (eta_bits + root_n_bits) * 1000
    }

    pub fn add_cost() -> i64 {
        1000
    }

    pub fn add_plain_cost() -> i64 {
        100
    }

    pub fn mul_plain_cost(config: &FHEConfig) -> i64 {
        scalar_bit_length(config.t) * 1000
    }

    pub fn mul_ct_cost(config: &FHEConfig) -> i64 {
        let t_bits = scalar_bit_length(config.t);
        let n_bits = config.n.trailing_zeros() as i64;
        let eta_bits = scalar_bit_length(config.eta as u64).max(1);
        (t_bits + n_bits + eta_bits) * 1000
    }

    pub fn relin_cost(config: &FHEConfig) -> i64 {
        config.n.trailing_zeros() as i64 * 1000
    }

    /// K-Elimination rescaling returns the conservative bit-width of `t` to
    /// the ledger. This is an accounting transition only; the arithmetic path
    /// remains resident in DualRNS main and anchor lanes.
    pub fn rescale_cost(config: &FHEConfig) -> i64 {
        -(scalar_bit_length(config.t) * 1000)
    }

    pub fn multiplication_cycle_cost(config: &FHEConfig) -> i64 {
        Self::mul_ct_cost(config) + Self::relin_cost(config) + Self::rescale_cost(config)
    }

    pub fn remaining_millibits(&self) -> i64 {
        self.remaining_mb
    }

    pub fn initial_millibits(&self) -> i64 {
        self.initial_mb
    }

    pub fn can_perform(&self, cost_mb: i64) -> bool {
        cost_mb < 0 || self.remaining_mb >= cost_mb
    }

    pub fn remaining_multiplications(&self, config: &FHEConfig) -> usize {
        let cost = Self::mul_ct_cost(config) + Self::relin_cost(config);
        if cost <= 0 {
            return usize::MAX;
        }
        if self.remaining_mb <= 0 {
            return 0;
        }
        (self.remaining_mb / cost) as usize
    }

    /// Reset after a successful real bootstrap using exact `floor(Q / t)` size.
    pub fn reset_after_bootstrap(&mut self, config: &FHEConfig) {
        let delta_bits = exact_delta_bit_length(config);
        let budget_bits = (delta_bits - bootstrap_noise_bit_bound(config)).max(0);
        let budget_mb = budget_bits
            .checked_mul(1000)
            .expect("post-bootstrap noise budget exceeds i64 millibits");

        self.remaining_mb = budget_mb;
        self.operations.push(NoiseOperation {
            op_type: NoiseOpType::Bootstrap,
            cost_mb: 0,
            remaining_mb: budget_mb,
        });
    }

    /// Trigger when the remaining budget is at or below the configured
    /// permille fraction of the initial fresh budget.
    pub fn should_bootstrap(&self, threshold_permille: u32) -> bool {
        assert!(threshold_permille <= 1000, "threshold must be in 0..=1000");
        let threshold_mb = (self.initial_mb as i128 * threshold_permille as i128 / 1000) as i64;
        self.remaining_mb <= threshold_mb
    }

    pub fn operations(&self) -> &[NoiseOperation] {
        &self.operations
    }

    pub fn summary(&self) -> String {
        use crate::arithmetic::integer_math::format_millibits;

        let used = self.initial_mb.saturating_sub(self.remaining_mb);
        let used_percent = if self.initial_mb > 0 {
            ((used as i128 * 100) / self.initial_mb as i128) as i64
        } else {
            100
        };

        format!(
            "Noise Budget: {}/{} bits remaining ({}% used, {} ops)",
            format_millibits(self.remaining_mb.max(0) as u64),
            format_millibits(self.initial_mb.max(0) as u64),
            used_percent,
            self.operations.len()
        )
    }
}

impl std::fmt::Display for NoiseBudget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.summary())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::SecureConfig;

    fn raw_config(primes: Vec<u64>, t: u64, n: usize, eta: usize) -> FHEConfig {
        FHEConfig {
            n,
            q: primes[0],
            primes,
            t,
            eta,
            security_bits: 0,
            name: "noise_test",
        }
    }

    #[test]
    fn exact_delta_size_does_not_sum_lane_widths() {
        let config = raw_config(vec![5, 5], 2, 1, 1);
        assert_eq!(exact_delta_bit_length(&config), 4); // floor(25/2) = 12
        let summed_lane_widths = 6i64;
        let t_bits = scalar_bit_length(config.t);
        assert_ne!(exact_delta_bit_length(&config), summed_lane_widths - t_bits);
    }

    #[test]
    fn exact_delta_size_handles_products_above_u128() {
        let config = raw_config(
            vec![u64::MAX, 274177, 67280421310721, 2],
            3,
            1,
            1,
        );
        assert!(exact_delta_bit_length(&config) > 128);
    }

    #[test]
    fn production_budgets_are_positive() {
        for secure in [
            SecureConfig::secure_128(),
            SecureConfig::secure_128_deep(),
            SecureConfig::secure_192(),
            SecureConfig::secure_256(),
        ] {
            let config = secure.into_config();
            let budget = NoiseBudget::from_config(&config);
            assert!(
                budget.remaining_millibits() > 0,
                "{} produced a non-positive budget",
                config.name
            );
        }
    }

    #[test]
    fn consume_is_exact_and_fail_closed() {
        let mut budget = NoiseBudget::with_budget_bits(5);
        assert_eq!(budget.consume(NoiseOpType::Add, 1000), Ok(4000));
        let error = budget
            .consume(NoiseOpType::MulCt, 5000)
            .expect_err("over-budget operation must fail");
        assert_eq!(error.required_mb, 5000);
        assert_eq!(error.available_mb, 4000);
        assert_eq!(error.last_op, NoiseOpType::MulCt);
    }

    #[test]
    fn checked_refund_rejects_i64_overflow() {
        let mut budget = NoiseBudget {
            remaining_mb: i64::MAX,
            initial_mb: i64::MAX,
            operations: Vec::new(),
        };
        assert!(budget.consume(NoiseOpType::Rescale, i64::MIN).is_err());
    }

    #[test]
    fn bootstrap_reset_uses_exact_delta_size() {
        let config = SecureConfig::secure_128_deep().into_config();
        let mut budget = NoiseBudget::from_config(&config);
        let cost = NoiseBudget::mul_ct_cost(&config) + NoiseBudget::relin_cost(&config);
        let _ = budget.consume(NoiseOpType::MulCt, cost);
        let before = budget.remaining_millibits();
        budget.reset_after_bootstrap(&config);
        assert!(budget.remaining_millibits() > before);
        assert_eq!(budget.operations().last().unwrap().op_type, NoiseOpType::Bootstrap);
    }

    #[test]
    fn threshold_boundary_is_inclusive() {
        let mut budget = NoiseBudget::with_budget_bits(100);
        budget.consume(NoiseOpType::MulCt, 75000).unwrap();
        assert!(budget.should_bootstrap(250));

        let mut above = NoiseBudget::with_budget_bits(100);
        above.consume(NoiseOpType::MulCt, 74999).unwrap();
        assert!(!above.should_bootstrap(250));
    }

    #[test]
    #[should_panic(expected = "threshold must be in 0..=1000")]
    fn invalid_threshold_panics() {
        NoiseBudget::with_budget_bits(1).should_bootstrap(1001);
    }

    #[test]
    fn multiplication_cycle_includes_k_elimination_credit() {
        let config = SecureConfig::secure_128_deep().into_config();
        assert_eq!(
            NoiseBudget::multiplication_cycle_cost(&config),
            NoiseBudget::mul_ct_cost(&config)
                + NoiseBudget::relin_cost(&config)
                + NoiseBudget::rescale_cost(&config)
        );
        assert!(NoiseBudget::rescale_cost(&config) < 0);
    }
}