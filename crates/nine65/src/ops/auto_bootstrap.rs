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
        assert!(
            permille <= 1000,
            "auto-bootstrap threshold must be in 0..=1000 permille"
        );
        self.trigger_permille = permille;
    }

    #[inline]
    fn refresh_if_required(
        &mut self,
        ciphertext: DualRNSCiphertext,
        budget_exhausted: bool,
    ) -> Nine65Result<DualRNSCiphertext> {
        if budget_exhausted || self.budget.should_bootstrap(self.trigger_permille) {
            let fresh = self
                .bootstrap
                .bootstrap(&ciphertext, self.bsk, self.ksk)?;
            self.budget.reset_after_bootstrap(&self.work_ctx.config);
            self.bootstrap_count += 1;
            Ok(fresh)
        } else {
            Ok(ciphertext)
        }
    }

    /// Multiply with automatic bootstrap.
    pub fn mul_auto(
        &mut self,
        ct1: &DualRNSCiphertext,
        ct2: &DualRNSCiphertext,
    ) -> Nine65Result<DualRNSCiphertext> {
        let operation_cost = NoiseBudget::mul_ct_cost(&self.work_ctx.config)
            + NoiseBudget::relin_cost(&self.work_ctx.config);
        let budget_exhausted = self
            .budget
            .consume(NoiseOpType::MulCt, mul_cost)
            .is_err();

        self.refresh_if_required(result, budget_exhausted)
    }

    /// Add with automatic bootstrap and explicit error propagation.
    ///
    /// Additions are inexpensive, but a sufficiently long addition-only chain
    /// can still consume the tracked budget. This checked entry point refreshes
    /// on either exhaustion or threshold crossing.
    pub fn try_add_auto(
        &mut self,
        ct1: &DualRNSCiphertext,
        ct2: &DualRNSCiphertext,
    ) -> Nine65Result<DualRNSCiphertext> {
        let result = self.work_ctx.add_dual(ct1, ct2);
        self.total_adds += 1;

        let budget_exhausted = self
            .budget
            .consume(NoiseOpType::Add, NoiseBudget::add_cost())
            .is_err();

        self.refresh_if_required(result, budget_exhausted)
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
