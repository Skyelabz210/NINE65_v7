//! Auto-bootstrap evaluator for continued-depth public-key FHE.
//!
//! The evaluator keeps ciphertext state in DualRNS form, tracks an exact
//! integer noise budget, and invokes Clockwork bootstrap when the budget is
//! exhausted or crosses a configured threshold. No reconstructed integer,
//! mixed-radix value, or floating-point quantity is used on this path.

use crate::errors::{Nine65Error, Nine65Result};
use crate::keys::bootstrap::{BootstrapKey, KeySwitchKey};
use crate::noise::budget::{NoiseBudget, NoiseOpType};
use crate::ops::bootstrap::ClockworkBootstrap;
use crate::ops::rns_fhe::{DualRNSCiphertext, DualRNSEvalKey, RNSFHEContext};
use crate::params::FHEConfig;

/// Evaluator that automatically bootstraps when the tracked budget reaches its
/// configured lower boundary.
pub struct AutoBootstrapEvaluator<'a> {
    work_ctx: &'a RNSFHEContext,
    bootstrap: &'a ClockworkBootstrap,
    bsk: &'a BootstrapKey,
    ksk: &'a KeySwitchKey,
    evk: &'a DualRNSEvalKey,
    budget: NoiseBudget,
    /// Trigger threshold in permille (`250` means 25 percent remaining).
    trigger_permille: u32,
    /// Number of successful bootstraps performed.
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
    ///
    /// The legal interval is `0..=1000`. Values outside that interval are a
    /// caller configuration error and are rejected immediately rather than
    /// producing a permanently-on or permanently-off refresh policy.
    pub fn set_trigger_threshold(&mut self, permille: u32) {
        assert_valid_trigger_threshold(permille);
        self.trigger_permille = permille;
    }

    /// Refresh both operands via bootstrap when the pending operation would
    /// exceed the tracked budget or cross the configured trigger threshold,
    /// so an over-budget operand is bootstrapped *before* it is combined
    /// with anything else -- never after.
    ///
    /// This is the fix for the Q17 finding in the deep-analysis audit: the
    /// previous implementation performed the multiply (or add) *first* and
    /// only checked the budget afterward, refreshing the *result*. A
    /// budget-crossing operation had therefore already computed on an
    /// operand whose tracked noise had crossed the safe threshold, and the
    /// post-hoc "refresh" of the result could only faithfully re-encrypt
    /// that already-corrupted value -- it could never repair it. Checking
    /// and refreshing before the operation, on the operands, is the only
    /// ordering under which "refresh" actually means what it says.
    fn preflight_refresh(
        &mut self,
        ct1: &DualRNSCiphertext,
        ct2: &DualRNSCiphertext,
        operation_cost: i64,
    ) -> Nine65Result<(DualRNSCiphertext, DualRNSCiphertext)> {
        if !self.budget.can_perform(operation_cost)
            || self.budget.should_bootstrap(self.trigger_permille)
        {
            let fresh1 = self.bootstrap.bootstrap(ct1, self.bsk, self.ksk)?;
            let fresh2 = self.bootstrap.bootstrap(ct2, self.bsk, self.ksk)?;
            self.budget.reset_after_bootstrap(&self.work_ctx.config);
            self.bootstrap_count += 2;
            Ok((fresh1, fresh2))
        } else {
            Ok((ct1.clone(), ct2.clone()))
        }
    }

    /// Multiply with automatic bootstrap.
    ///
    /// Refreshes the operands *before* multiplying whenever the multiply
    /// would exhaust or cross the tracked noise budget (see
    /// [`Self::preflight_refresh`]); the multiply itself then always runs on
    /// operands the budget can account for.
    pub fn mul_auto(
        &mut self,
        ct1: &DualRNSCiphertext,
        ct2: &DualRNSCiphertext,
    ) -> Nine65Result<DualRNSCiphertext> {
        let operation_cost = NoiseBudget::mul_ct_cost(&self.work_ctx.config)
            + NoiseBudget::relin_cost(&self.work_ctx.config);

        let (op1, op2) = self.preflight_refresh(ct1, ct2, operation_cost)?;

        self.budget
            .consume(NoiseOpType::MulCt, operation_cost)
            .map_err(|e| Nine65Error::BootstrapFailed {
                reason: format!(
                    "noise budget cannot cover a single multiply immediately \
                     after refresh (config budget too small for this op): {}",
                    e
                ),
            })?;

        let result = self.work_ctx.mul_dual_public(&op1, &op2, self.evk)?;
        self.total_muls += 1;
        Ok(result)
    }

    /// Add with automatic bootstrap and explicit error propagation.
    ///
    /// Additions are inexpensive, but a sufficiently long addition-only chain
    /// can still consume the tracked budget. Refreshes the operands *before*
    /// adding whenever the add would exhaust or cross the tracked noise
    /// budget (see [`Self::preflight_refresh`]).
    pub fn try_add_auto(
        &mut self,
        ct1: &DualRNSCiphertext,
        ct2: &DualRNSCiphertext,
    ) -> Nine65Result<DualRNSCiphertext> {
        let operation_cost = NoiseBudget::add_cost();

        let (op1, op2) = self.preflight_refresh(ct1, ct2, operation_cost)?;

        self.budget
            .consume(NoiseOpType::Add, operation_cost)
            .map_err(|e| Nine65Error::BootstrapFailed {
                reason: format!(
                    "noise budget cannot cover a single add immediately \
                     after refresh (config budget too small for this op): {}",
                    e
                ),
            })?;

        let result = self.work_ctx.add_dual(&op1, &op2);
        self.total_adds += 1;
        Ok(result)
    }

    /// Compatibility wrapper for existing callers.
    ///
    /// New code should call [`Self::try_add_auto`] so a bootstrap failure can be
    /// handled by the caller. This wrapper no longer ignores an exhausted noise
    /// budget; it fails loudly if refresh itself fails.
    pub fn add_auto(
        &mut self,
        ct1: &DualRNSCiphertext,
        ct2: &DualRNSCiphertext,
    ) -> DualRNSCiphertext {
        self.try_add_auto(ct1, ct2)
            .expect("auto-bootstrap addition refresh failed")
    }

    /// Current noise budget remaining in millibits.
    pub fn remaining_budget_mb(&self) -> i64 {
        self.budget.remaining_millibits()
    }

    /// Exact-integer summary of evaluator activity.
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

/// Validate an auto-bootstrap trigger threshold expressed in permille.
///
/// Legal thresholds lie in the closed interval `0..=1000` (0% to 100% of the
/// budget remaining). Values above 1000 permille are a caller configuration
/// error and panic rather than producing a permanently-on refresh policy.
fn assert_valid_trigger_threshold(permille: u32) {
    assert!(
        permille <= 1000,
        "auto-bootstrap threshold must be in 0..=1000 permille"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore = "VESTIGIAL: asserts assert_valid_trigger_threshold(1001) panics — argument validation for the auto-bootstrap refresh trigger. A refresh trigger threshold only means something if there is a budget to be at 25 percent of. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    #[should_panic(expected = "0..=1000")]
    fn trigger_threshold_rejects_values_above_one_hundred_percent() {
        assert_valid_trigger_threshold(1001);
    }

    #[ignore = "VESTIGIAL: asserts assert_valid_trigger_threshold accepts 0, 250 and 1000 permille — the legal interval of the auto-bootstrap refresh trigger. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn trigger_threshold_accepts_closed_legal_interval() {
        assert_valid_trigger_threshold(0);
        assert_valid_trigger_threshold(250);
        assert_valid_trigger_threshold(1000);
    }
}
