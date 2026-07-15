//! Auto-bootstrap evaluator for continued-depth public-key FHE.
//!
//! The evaluator keeps ciphertexts in DualRNS form, tracks an exact integer
//! noise budget, and invokes Clockwork bootstrap before an operation whenever
//! the tracked budget cannot fund that operation or crosses the configured
//! threshold. No reconstructed integer, mixed-radix value, or floating-point
//! quantity is used on this path.

use crate::errors::{Nine65Error, Nine65Result};
use crate::keys::bootstrap::{BootstrapKey, KeySwitchKey};
use crate::noise::budget::{NoiseBudget, NoiseOpType};
use crate::ops::bootstrap::ClockworkBootstrap;
use crate::ops::rns_fhe::{DualRNSCiphertext, DualRNSEvalKey, RNSFHEContext};
use crate::params::FHEConfig;

#[inline]
fn assert_valid_trigger_threshold(permille: u32) {
    assert!(
        permille <= 1000,
        "auto-bootstrap threshold must be in 0..=1000 permille"
    );
}

/// Evaluator that automatically bootstraps before a tracked operation would
/// cross the configured lower budget boundary.
pub struct AutoBootstrapEvaluator<'a> {
    work_ctx: &'a RNSFHEContext,
    bootstrap: &'a ClockworkBootstrap,
    bsk: &'a BootstrapKey,
    ksk: &'a KeySwitchKey,
    evk: &'a DualRNSEvalKey,
    budget: NoiseBudget,
    /// Trigger threshold in permille (`250` means 25 percent remaining).
    trigger_permille: u32,
    /// Number of real ciphertext bootstrap calls performed.
    pub bootstrap_count: usize,
    /// Total ciphertext-ciphertext multiplications performed.
    pub total_muls: usize,
    /// Total ciphertext-ciphertext additions performed.
    pub total_adds: usize,
}

impl<'a> AutoBootstrapEvaluator<'a> {
    pub fn new(
        work_ctx: &'a RNSFHEContext,
        bootstrap: &'a ClockworkBootstrap,
        bsk: &'a BootstrapKey,
        ksk: &'a KeySwitchKey,
        evk: &'a DualRNSEvalKey,
        config: &FHEConfig,
    ) -> Self {
        Self {
            work_ctx,
            bootstrap,
            bsk,
            ksk,
            evk,
            budget: NoiseBudget::from_config(config),
            trigger_permille: 250,
            bootstrap_count: 0,
            total_muls: 0,
            total_adds: 0,
        }
    }

    /// Set the bootstrap trigger threshold in permille.
    pub fn set_trigger_threshold(&mut self, permille: u32) {
        assert_valid_trigger_threshold(permille);
        self.trigger_permille = permille;
    }

    #[inline]
    fn requires_preflight_refresh(&self, operation_cost_mb: i64) -> bool {
        !self.budget.can_perform(operation_cost_mb)
            || self.budget.should_bootstrap(self.trigger_permille)
    }

    /// Prepare both operands for a binary operation.
    ///
    /// The evaluator does not carry per-ciphertext noise metadata, so when the
    /// chain budget requires refresh it refreshes both operands. This keeps the
    /// pair at a common fresh boundary and avoids performing an operation first
    /// and trying to repair an already over-budget result afterward.
    fn prepare_binary_operands(
        &mut self,
        ct1: &DualRNSCiphertext,
        ct2: &DualRNSCiphertext,
        operation_cost_mb: i64,
    ) -> Nine65Result<(DualRNSCiphertext, DualRNSCiphertext)> {
        if !self.requires_preflight_refresh(operation_cost_mb) {
            return Ok((ct1.clone(), ct2.clone()));
        }

        let left = self.bootstrap.bootstrap(ct1, self.bsk, self.ksk)?;
        let right = self.bootstrap.bootstrap(ct2, self.bsk, self.ksk)?;
        self.bootstrap_count += 2;
        self.budget.reset_after_bootstrap(&self.work_ctx.config);

        if !self.budget.can_perform(operation_cost_mb) {
            return Err(Nine65Error::ConfigError {
                message: format!(
                    "post-bootstrap budget {}mb cannot fund operation cost {}mb",
                    self.budget.remaining_millibits(),
                    operation_cost_mb
                ),
            });
        }

        Ok((left, right))
    }

    fn consume_preflighted(
        &mut self,
        op_type: NoiseOpType,
        operation_cost_mb: i64,
    ) -> Nine65Result<()> {
        self.budget
            .consume(op_type, operation_cost_mb)
            .map(|_| ())
            .map_err(|error| Nine65Error::ConfigError {
                message: format!("noise preflight invariant failed: {error}"),
            })
    }

    /// Multiply with automatic pre-operation bootstrap.
    pub fn mul_auto(
        &mut self,
        ct1: &DualRNSCiphertext,
        ct2: &DualRNSCiphertext,
    ) -> Nine65Result<DualRNSCiphertext> {
        let operation_cost = NoiseBudget::mul_ct_cost(&self.work_ctx.config)
            + NoiseBudget::relin_cost(&self.work_ctx.config);
        let (left, right) = self.prepare_binary_operands(ct1, ct2, operation_cost)?;
        let result = self.work_ctx.mul_dual_public(&left, &right, self.evk)?;
        self.consume_preflighted(NoiseOpType::MulCt, operation_cost)?;
        self.total_muls += 1;
        Ok(result)
    }

    /// Add with automatic pre-operation bootstrap and explicit error propagation.
    pub fn try_add_auto(
        &mut self,
        ct1: &DualRNSCiphertext,
        ct2: &DualRNSCiphertext,
    ) -> Nine65Result<DualRNSCiphertext> {
        let operation_cost = NoiseBudget::add_cost();
        let (left, right) = self.prepare_binary_operands(ct1, ct2, operation_cost)?;
        let result = self.work_ctx.add_dual(&left, &right);
        self.consume_preflighted(NoiseOpType::Add, operation_cost)?;
        self.total_adds += 1;
        Ok(result)
    }

    /// Compatibility wrapper for existing callers.
    ///
    /// New code should call [`Self::try_add_auto`] so bootstrap errors can be
    /// handled by the caller.
    pub fn add_auto(
        &mut self,
        ct1: &DualRNSCiphertext,
        ct2: &DualRNSCiphertext,
    ) -> DualRNSCiphertext {
        self.try_add_auto(ct1, ct2)
            .expect("auto-bootstrap addition preflight failed")
    }

    /// Current noise budget remaining in millibits.
    pub fn remaining_budget_mb(&self) -> i64 {
        self.budget.remaining_millibits()
    }

    /// Exact integer summary of evaluator activity.
    pub fn budget_summary(&self) -> String {
        format!(
            "{} | bootstrap calls: {}, muls: {}, adds: {}",
            self.budget.summary(),
            self.bootstrap_count,
            self.total_muls,
            self.total_adds,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "0..=1000")]
    fn trigger_threshold_rejects_values_above_one_hundred_percent() {
        assert_valid_trigger_threshold(1001);
    }

    #[test]
    fn trigger_threshold_accepts_closed_legal_interval() {
        assert_valid_trigger_threshold(0);
        assert_valid_trigger_threshold(250);
        assert_valid_trigger_threshold(1000);
    }
}
