//! Auto-Bootstrap Evaluator — Truly Unlimited Depth FHE
//!
//! Wraps `RNSFHEContext` with automatic bootstrap triggering.
//! When noise budget drops below threshold, bootstrap fires automatically.

use crate::errors::Nine65Result;
use crate::keys::bootstrap::{BootstrapKey, KeySwitchKey};
use crate::noise::budget::{NoiseBudget, NoiseOpType};
use crate::ops::bootstrap::ClockworkBootstrap;
use crate::ops::rns_fhe::{DualRNSCiphertext, DualRNSEvalKey, RNSFHEContext};
use crate::params::FHEConfig;

/// Evaluator that automatically bootstraps when noise is low.
pub struct AutoBootstrapEvaluator<'a> {
    work_ctx: &'a RNSFHEContext,
    bootstrap: &'a ClockworkBootstrap,
    bsk: &'a BootstrapKey,
    ksk: &'a KeySwitchKey,
    evk: &'a DualRNSEvalKey,
    budget: NoiseBudget,
    /// Trigger threshold in permille (250 = trigger at 25% remaining)
    trigger_permille: u32,
    /// Number of bootstraps performed
    pub bootstrap_count: usize,
    /// Total multiplications performed
    pub total_muls: usize,
    /// Total additions performed
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
            trigger_permille: 250, // Bootstrap at 25% remaining
            bootstrap_count: 0,
            total_muls: 0,
            total_adds: 0,
        }
    }

    /// Set the bootstrap trigger threshold (in permille).
    pub fn set_trigger_threshold(&mut self, permille: u32) {
        self.trigger_permille = permille;
    }

    /// Multiply with automatic bootstrap — enables unlimited depth.
    pub fn mul_auto(
        &mut self,
        ct1: &DualRNSCiphertext,
        ct2: &DualRNSCiphertext,
    ) -> Nine65Result<DualRNSCiphertext> {
        let result = self.work_ctx.mul_dual_public(ct1, ct2, self.evk)?;
        self.total_muls += 1;

        let mul_cost = NoiseBudget::mul_ct_cost(&self.work_ctx.config)
            + NoiseBudget::relin_cost(&self.work_ctx.config);
        // Consume may fail if budget is exhausted, but we check should_bootstrap below
        let _ = self.budget.consume(NoiseOpType::MulCt, mul_cost);

        if self.budget.should_bootstrap(self.trigger_permille) {
            self.bootstrap_count += 1;
            let fresh = self.bootstrap.bootstrap(&result, self.bsk, self.ksk)?;
            self.budget.reset_after_bootstrap(&self.work_ctx.config);
            Ok(fresh)
        } else {
            Ok(result)
        }
    }

    /// Add (no bootstrap needed — additions are cheap).
    pub fn add_auto(
        &mut self,
        ct1: &DualRNSCiphertext,
        ct2: &DualRNSCiphertext,
    ) -> DualRNSCiphertext {
        self.total_adds += 1;
        let _ = self
            .budget
            .consume(NoiseOpType::Add, NoiseBudget::add_cost());
        self.work_ctx.add_dual(ct1, ct2)
    }

    /// Get current noise budget remaining in millibits.
    pub fn remaining_budget_mb(&self) -> i64 {
        self.budget.remaining_millibits()
    }

    /// Get budget summary string.
    pub fn budget_summary(&self) -> String {
        format!(
            "{} | bootstraps: {}, muls: {}, adds: {}",
            self.budget.summary(),
            self.bootstrap_count,
            self.total_muls,
            self.total_adds,
        )
    }
}
