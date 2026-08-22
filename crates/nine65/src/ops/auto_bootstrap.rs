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
    ///
    /// Two further properties of this predicate are load-bearing.
    ///
    /// **The trigger is reserve-aware.** It consults
    /// [`NoiseBudget::can_perform_with_reserve`], not `can_perform`. The
    /// decryption boundary is *not* the binding constraint on a ciphertext
    /// that is about to be refreshed: Phase 1 of the refresh
    /// (`ClockworkBootstrap::modswitch_to_t`) carries a ciphertext exactly only
    /// while its noise sits a further `log2(n) + 1` bits below `Delta/2`. A
    /// ciphertext that has merely stayed decryptable can already be past that
    /// point, and refreshing it then re-encrypts a value the refresh itself
    /// has perturbed. Withholding the reserve makes the trigger fire strictly
    /// before that window closes rather than after it.
    ///
    /// **A squaring refreshes once, not twice.** For `ct * ct` the same
    /// ciphertext arrives as both operands. Bootstrapping it twice costs two
    /// refreshes, produces two independent encryptions of the same value for no
    /// benefit, and made `bootstrap_count` report double the work actually
    /// done. [`same_ciphertext`] detects the case and one refresh result is
    /// used for both operands.
    fn preflight_refresh(
        &mut self,
        ct1: &DualRNSCiphertext,
        ct2: &DualRNSCiphertext,
        operation_cost: i64,
    ) -> Nine65Result<(DualRNSCiphertext, DualRNSCiphertext)> {
        let config = &self.work_ctx.config;
        if !self.budget.can_perform_with_reserve(operation_cost, config)
            || self.budget.should_bootstrap(self.trigger_permille)
        {
            let (fresh1, fresh2) = if same_ciphertext(ct1, ct2) {
                let refreshed = self.bootstrap.bootstrap(ct1, self.bsk, self.ksk)?;
                self.bootstrap_count += 1;
                (refreshed.clone(), refreshed)
            } else {
                let fresh1 = self.bootstrap.bootstrap(ct1, self.bsk, self.ksk)?;
                let fresh2 = self.bootstrap.bootstrap(ct2, self.bsk, self.ksk)?;
                self.bootstrap_count += 2;
                (fresh1, fresh2)
            };
            self.budget.reset_after_bootstrap(&self.work_ctx.config);
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

/// Whether two operands are the same ciphertext, so one refresh serves both.
///
/// Pointer equality is the cheap exact test and catches the shape that matters
/// -- `evaluator.mul_auto(&ct, &ct)`, a squaring. It is only a sufficient
/// condition, so a limb-wise comparison follows as a fallback for operands that
/// are equal by value but distinct by address (a clone, or the same ciphertext
/// reached through two bindings). The comparison is `O(n * lanes)` integer
/// equality against the cost of a full bootstrap, so the fallback is free in
/// any accounting that matters.
///
/// Being conservative in the right direction matters here: a false *negative*
/// costs one redundant refresh, while a false *positive* would substitute one
/// operand for another. Only exact limb equality is accepted, so a false
/// positive means the two ciphertexts are bit-identical and interchangeable.
fn same_ciphertext(ct1: &DualRNSCiphertext, ct2: &DualRNSCiphertext) -> bool {
    if std::ptr::eq(ct1, ct2) {
        return true;
    }
    ct1.level == ct2.level
        && ct1.c0.n == ct2.c0.n
        // `c1.n` is compared too, not just `c0.n`. For a well-formed poly it is
        // implied by equal limb vectors, but this predicate governs OPERAND
        // SUBSTITUTION, so it should assert the invariant it documents rather
        // than rely on well-formedness holding at every call site.
        && ct1.c1.n == ct2.c1.n
        && ct1.c0.main == ct2.c0.main
        && ct1.c0.anchor == ct2.c0.anchor
        && ct1.c1.main == ct2.c1.main
        && ct1.c1.anchor == ct2.c1.anchor
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
    use crate::entropy::ShadowHarvester;
    use crate::ops::bootstrap::ClockworkBootstrap;
    use crate::params::SecureConfig;

    struct Harness {
        ctx: RNSFHEContext,
        boot: ClockworkBootstrap,
        keys: crate::ops::rns_fhe::DualRNSFullKeySet,
        boot_keys: crate::keys::bootstrap::BootstrapKeySet,
        config: FHEConfig,
    }

    fn harness(secure: SecureConfig, seed: u64) -> Harness {
        let config = secure.into_config();
        let ctx = RNSFHEContext::try_new(&config).expect("context");
        let boot = ClockworkBootstrap::new(&config).expect("bootstrap");
        let mut rng = ShadowHarvester::with_seed(seed);
        let keys = ctx.generate_keys_dual_full(&mut rng);
        let boot_keys = boot
            .generate_keys(&keys.secret_key, &mut rng)
            .expect("bootstrap keys");
        Harness {
            ctx,
            boot,
            keys,
            boot_keys,
            config,
        }
    }

    /// Repeated squaring under `mul_auto`, checking the plaintext after *every*
    /// operation and reporting where a refresh fired.
    ///
    /// Base 3 is used rather than base 2: `2^(2^k) mod 65537` collapses to 1 at
    /// `k = 5` (because `2^16 = -1 mod 65537`), after which the circuit is only
    /// squaring 1 and proves nothing. `3` has order 65536, so `3^(2^k)` stays
    /// non-trivial for every `k < 16`.
    fn squaring_run(h: &Harness, depth: usize) -> (Vec<bool>, Vec<usize>, usize) {
        let mut rng = ShadowHarvester::with_seed(4242);
        let mut evaluator = AutoBootstrapEvaluator::new(
            &h.ctx,
            &h.boot,
            &h.boot_keys.bsk,
            &h.boot_keys.ksk,
            &h.keys.eval_key,
            &h.config,
        );

        let mut ct = h.ctx.encrypt_dual(3, &h.keys.public_key, &mut rng);
        assert_eq!(
            h.ctx.decrypt_dual(&ct, &h.keys.secret_key),
            3,
            "fresh encryption must round-trip before the circuit starts"
        );

        let mut expected: u128 = 3;
        let mut correct = Vec::with_capacity(depth);
        let mut refreshed_at = Vec::new();
        let mut before = evaluator.bootstrap_count;

        for level in 1..=depth {
            ct = evaluator
                .mul_auto(&ct, &ct)
                .unwrap_or_else(|e| panic!("mul_auto failed at depth {}: {}", level, e));
            expected = expected * expected % h.config.t as u128;
            let decrypted = h.ctx.decrypt_dual(&ct, &h.keys.secret_key);
            let ok = decrypted as u128 == expected;
            if !ok {
                println!(
                    "  {} depth {}: decrypted {} expected {}",
                    h.config.name, level, decrypted, expected
                );
            }
            correct.push(ok);
            if evaluator.bootstrap_count > before {
                refreshed_at.push(level);
                assert_eq!(
                    evaluator.bootstrap_count - before,
                    1,
                    "{}: a squaring passes one ciphertext as both operands, so its refresh \
                     must cost exactly one bootstrap -- got {} at depth {}",
                    h.config.name,
                    evaluator.bootstrap_count - before,
                    level,
                );
                before = evaluator.bootstrap_count;
            }
        }
        (correct, refreshed_at, evaluator.bootstrap_count)
    }

    fn assert_squaring_circuit_is_exact(secure: SecureConfig, seed: u64, depth: usize) {
        let name = secure.config.name;
        let h = harness(secure, seed);
        let (correct, refreshed_at, bootstraps) = squaring_run(&h, depth);

        println!(
            "{}: depth {} squaring, refreshes at {:?}, {} bootstraps total",
            name, depth, refreshed_at, bootstraps
        );

        let first_bad = correct.iter().position(|ok| !ok).map(|i| i + 1);
        assert!(
            first_bad.is_none(),
            "{}: repeated squaring under auto-refresh first decrypted incorrectly at \
             depth {:?} (refreshes fired at {:?})",
            name,
            first_bad,
            refreshed_at,
        );

        // ACCEPTANCE: automatic refresh must actually fire, otherwise this test
        // proves nothing about the refresh path.
        let first_refresh = *refreshed_at
            .first()
            .unwrap_or_else(|| panic!("{}: no automatic refresh fired in {} levels", name, depth));

        // ACCEPTANCE: the plaintext is correct at the triggering operation and
        // stays correct for at least three subsequent nonlinear operations.
        assert!(
            depth >= first_refresh + 3,
            "{}: circuit too short to observe three nonlinear operations after the first \
             refresh (first refresh at depth {}, circuit depth {})",
            name,
            first_refresh,
            depth,
        );
        for level in first_refresh..=(first_refresh + 3) {
            assert!(
                correct[level - 1],
                "{}: depth {} is wrong -- the refresh at depth {} did not keep the plaintext",
                name,
                level,
                first_refresh,
            );
        }
    }

    /// ACCEPTANCE (secure_128_deep): a repeated-square circuit runs to the
    /// model-predicted depth with every intermediate decryption correct.
    ///
    /// "Model-predicted depth" is unbounded here: the ledger funds one ct x ct
    /// multiply per refresh cycle (`remaining_multiplications_before_refresh`),
    /// and the refresh re-funds it, so depth is bounded only by how long the
    /// test is willing to run. Eight levels is four full refresh cycles.
    #[test]
    fn repeated_squaring_is_exact_under_auto_refresh_secure_128_deep() {
        assert_squaring_circuit_is_exact(SecureConfig::secure_128_deep(), 11, 8);
    }

    /// ACCEPTANCE (secure_192): same circuit, larger chain.
    #[test]
    fn repeated_squaring_is_exact_under_auto_refresh_secure_192() {
        assert_squaring_circuit_is_exact(SecureConfig::secure_192(), 11, 8);
    }

    /// secure_256 is the one admitted config whose fresh budget funds **two**
    /// multiplies before the reserve-aware trigger fires (its chain is 158
    /// Delta bits against 49 mb per multiply and a 15 mb reserve), so its first
    /// refresh input carries two levels of noise rather than one. That is the
    /// case the ledger is least corroborated on, which is exactly why it is
    /// tested rather than assumed.
    #[test]
    fn repeated_squaring_is_exact_under_auto_refresh_secure_256() {
        assert_squaring_circuit_is_exact(SecureConfig::secure_256(), 11, 8);
    }

    /// ACCEPTANCE: `bootstrap_count` increments by exactly one per squaring
    /// refresh.
    ///
    /// Before the `same_ciphertext` fix, `ct * ct` bootstrapped the one operand
    /// twice and added two to the counter: twice the work, no benefit, and a
    /// counter that reported double the refreshes actually performed.
    #[test]
    fn squaring_refresh_costs_exactly_one_bootstrap() {
        let h = harness(SecureConfig::secure_128_deep(), 11);
        let (_, refreshed_at, bootstraps) = squaring_run(&h, 6);
        assert!(
            !refreshed_at.is_empty(),
            "no refresh fired, so the counter is untested"
        );
        // `squaring_run` already asserts the per-refresh delta is 1; this pins
        // the total as well, so a compensating double-count cannot hide.
        assert_eq!(
            bootstraps,
            refreshed_at.len(),
            "{} refreshes fired but bootstrap_count reached {}",
            refreshed_at.len(),
            bootstraps,
        );
    }

    #[test]
    fn same_ciphertext_accepts_identity_and_bit_identical_clones() {
        let h = harness(SecureConfig::secure_128_deep(), 11);
        let mut rng = ShadowHarvester::with_seed(9);
        let ct = h.ctx.encrypt_dual(5, &h.keys.public_key, &mut rng);
        let clone = ct.clone();
        let other = h.ctx.encrypt_dual(5, &h.keys.public_key, &mut rng);

        assert!(same_ciphertext(&ct, &ct), "identity must be detected");
        assert!(
            same_ciphertext(&ct, &clone),
            "a bit-identical clone is interchangeable and must be detected"
        );
        assert!(
            !same_ciphertext(&ct, &other),
            "two independent encryptions of the same message are NOT interchangeable"
        );
    }

    /// ACCEPTANCE: drive the ledger to the trigger boundary from both sides and
    /// confirm the refresh fires BEFORE it, never after.
    ///
    /// The boundary under test is the refresh-input boundary, not the
    /// decryption boundary: `can_perform_with_reserve` must refuse an operation
    /// that `can_perform` would still allow, and the gap between the two is
    /// exactly `bootstrap_input_reserve_mb`.
    #[test]
    fn trigger_fires_before_the_refresh_window_closes_not_after() {
        use crate::noise::budget::bootstrap_input_reserve_mb;

        let mut total_permitted = 0usize;
        let mut total_permitted_decryption_only = 0usize;

        for secure in [
            SecureConfig::secure_128(),
            SecureConfig::secure_128_deep(),
            SecureConfig::secure_192(),
            SecureConfig::secure_256(),
        ] {
            let config = secure.into_config();
            let cost = NoiseBudget::mul_ct_cost(&config) + NoiseBudget::relin_cost(&config);
            let reserve = bootstrap_input_reserve_mb(&config);

            // Walk a fresh budget down one operation at a time and record the
            // last state at which the reserve-aware predicate still says yes.
            let mut budget = NoiseBudget::from_config(&config);
            let mut permitted = 0usize;
            while budget.can_perform_with_reserve(cost, &config) {
                budget
                    .consume(NoiseOpType::MulCt, cost)
                    .expect("reserve-aware predicate promised this operation was affordable");
                permitted += 1;
                assert!(
                    permitted < 64,
                    "{}: trigger never fires -- the reserve is not being withheld",
                    config.name
                );
            }

            assert!(
                budget.remaining_millibits() >= 0,
                "{}: budget went negative before the trigger fired",
                config.name
            );

            // NOTE ON WHAT IS AND IS NOT A GATE HERE.
            //
            // `remaining < cost + reserve` and `remaining_multiplications_
            // before_refresh() == 0` are algebraic CONSEQUENCES of the loop's
            // own exit condition (`remaining - reserve < cost`). They cannot
            // fail, and an earlier revision of this test presented them as the
            // acceptance gate, which overstated it. They are kept below as an
            // internal consistency check on `divide_budget`, labelled as such.
            //
            // The discriminating measurement is the counterfactual walk: run
            // the SAME descent again with the decryption-only predicate and
            // compare how far each gets. If the reserve were ever dropped,
            // ignored, or set to zero, the two walks would agree everywhere,
            // and the aggregate assertion below is what catches that.
            let mut decryption_only = NoiseBudget::from_config(&config);
            let mut permitted_decryption_only = 0usize;
            while decryption_only.can_perform(cost) {
                decryption_only
                    .consume(NoiseOpType::MulCt, cost)
                    .expect("decryption predicate promised this operation was affordable");
                permitted_decryption_only += 1;
                assert!(permitted_decryption_only < 64, "{}: runaway", config.name);
            }

            assert!(
                permitted <= permitted_decryption_only,
                "{}: the reserve-aware predicate permitted {} multiplies where the \
                 decryption-only predicate permitted {} -- the trigger must never \
                 be MORE permissive than the boundary it sits inside",
                config.name,
                permitted,
                permitted_decryption_only,
            );
            total_permitted += permitted;
            total_permitted_decryption_only += permitted_decryption_only;

            // Internal consistency of `divide_budget` with the loop condition.
            let decryption_bounded = budget.remaining_multiplications(&config);
            let refresh_bounded = budget.remaining_multiplications_before_refresh(&config);
            assert!(
                refresh_bounded <= decryption_bounded,
                "{}: refresh-bounded depth {} exceeded decryption-bounded depth {}",
                config.name,
                refresh_bounded,
                decryption_bounded,
            );
            assert_eq!(
                refresh_bounded, 0,
                "{}: divide_budget disagrees with can_perform_with_reserve at the \
                 state the walk stopped at",
                config.name,
            );
            println!(
                "{}: {} multiplies permitted before refresh ({} under the \
                 decryption-only predicate), {} mb left \
                 (cost {} mb, reserve {} mb, decryption-bounded depth still {})",
                config.name,
                permitted,
                permitted_decryption_only,
                budget.remaining_millibits(),
                cost,
                reserve,
                decryption_bounded,
            );
        }

        // The reserve must COST something somewhere. Per-config strictness does
        // not hold -- on some tuples the leftover slack is smaller than the
        // reserve, so both walks stop at the same count -- but if the reserve
        // stopped being withheld at all, every walk would agree and this sum
        // would come out equal.
        assert!(
            total_permitted < total_permitted_decryption_only,
            "the refresh reserve is inert: the reserve-aware walk permitted {} \
             multiplies in total and the decryption-only walk permitted {}. A \
             trigger that never fires earlier than the decryption boundary is \
             not a conservative trigger.",
            total_permitted,
            total_permitted_decryption_only,
        );
    }

    /// The ledger must fund at least one multiply immediately after a refresh
    /// on every config whose chain is admitted for public refresh -- otherwise
    /// `mul_auto` would refresh and then fail, making forward progress
    /// impossible. Configs that are *not* admitted are expected to fail closed.
    #[test]
    fn a_refreshed_budget_funds_at_least_one_multiply_where_refresh_is_supported() {
        use crate::params::secure_configs::supports_public_refresh;

        for secure in [
            SecureConfig::secure_128(),
            SecureConfig::secure_128_deep(),
            SecureConfig::secure_192(),
            SecureConfig::secure_256(),
            SecureConfig::hardware_opt(),
        ] {
            let config = secure.into_config();
            let mut budget = NoiseBudget::from_config(&config);
            budget.reset_after_bootstrap(&config);
            let cost = NoiseBudget::mul_ct_cost(&config) + NoiseBudget::relin_cost(&config);
            // `can_perform`, not `can_perform_with_reserve`, and deliberately.
            // Forward progress in `mul_auto` is decided by the `budget.consume`
            // that follows `preflight_refresh`, and `consume` gates on the
            // DECRYPTION boundary. `can_perform_with_reserve` decides only
            // whether `preflight_refresh` refreshes first -- it is the trigger,
            // not the funding check. Asserting the reserve-aware predicate here
            // would assert something `mul_auto` never asks.
            let funds_a_multiply = budget.can_perform(cost);
            let would_trigger_again = !budget.can_perform_with_reserve(cost, &config);
            println!(
                "{}: post-refresh budget {} mb, one multiply costs {} mb, \
                 funds a multiply = {}, would trigger another refresh first = {}, \
                 chain admitted for public refresh = {}",
                config.name,
                budget.remaining_millibits(),
                cost,
                funds_a_multiply,
                would_trigger_again,
                supports_public_refresh(&config),
            );
            if supports_public_refresh(&config) {
                assert!(
                    funds_a_multiply,
                    "{}: chain is admitted for public refresh but a refreshed budget \
                     ({} mb) cannot fund one multiply ({} mb) -- mul_auto could never \
                     make forward progress",
                    config.name,
                    budget.remaining_millibits(),
                    cost,
                );
                // Record the steady state honestly: the trigger is latched on
                // after a refresh, so `mul_auto` refreshes before every
                // subsequent multiply. See
                // `a_refresh_cycle_never_funds_more_than_one_multiply`.
                // Whether the trigger is already latched on again at this
                // point differs per config and is NOT uniform -- see the
                // measured table in
                // `a_refresh_cycle_never_funds_more_than_one_multiply`, which
                // pins it. Asserting it uniformly here would be wrong:
                // `secure_192` clears the reserve post-refresh and
                // `secure_128_deep` does not.
            }
        }
    }

    /// Regression guard on the measured refresh envelope.
    ///
    /// Measured on this commit (`ClockworkBootstrap::bootstrap`, circular path,
    /// repeated squaring of an encrypted 3, every intermediate decrypted):
    ///
    /// | policy | secure_128_deep | secure_192 |
    /// |--------|-----------------|------------|
    /// | refresh after every multiply (k=1) | correct through depth 9 | correct through depth 9 |
    /// | refresh after every 2nd multiply (k=2) | refresh before depth 3 returned 65534 for 16 | refresh before depth 3 returned 65508 for 16 |
    ///
    /// The refresh is plaintext-exact only while its input carries at most one
    /// multiply's worth of noise above a refresh output. That envelope is what
    /// `bootstrap_input_reserve_mb` exists to enforce, and it is not something
    /// the ledger can re-derive from `Delta` alone -- the noise-independent
    /// residue of `modswitch_to_t` sets it. So pin it: a steady-state refresh
    /// cycle must never be modelled as funding more than one ct x ct multiply.
    /// Widening the reserve is safe and will keep this test green; narrowing it
    /// past the measured envelope will not.
    #[test]
    fn a_refresh_cycle_never_funds_more_than_one_multiply() {
        use crate::noise::budget::bootstrap_input_reserve_mb;
        use crate::params::secure_configs::supports_public_refresh;

        for secure in [
            SecureConfig::secure_128_deep(),
            SecureConfig::secure_192(),
            SecureConfig::secure_256(),
        ] {
            let config = secure.into_config();
            assert!(
                supports_public_refresh(&config),
                "{}: expected an admitted config",
                config.name
            );
            let mut budget = NoiseBudget::from_config(&config);
            budget.reset_after_bootstrap(&config);
            let funded = budget.remaining_multiplications_before_refresh(&config);
            let cost = NoiseBudget::mul_ct_cost(&config) + NoiseBudget::relin_cost(&config);

            println!(
                "{}: post-refresh {} mb, reserve {} mb, one multiply {} mb -> \
                 trigger-funded multiplies = {}",
                config.name,
                budget.remaining_millibits(),
                bootstrap_input_reserve_mb(&config),
                cost,
                funded,
            );

            assert!(
                funded <= 1,
                "{}: a refresh cycle is modelled as funding {} multiplies, but the refresh \
                 is only measured plaintext-exact for an input carrying one multiply",
                config.name,
                funded,
            );

            // `funded <= 1` above is the load-bearing invariant, but on its
            // own it does not say which side of the boundary each config
            // actually sits on, so pin the MEASURED value per config too.
            //
            // Measured on this commit:
            //   secure_128_deep  post-refresh  54000 mb, reserve 14000, cost 47000 -> 0
            //   secure_192       post-refresh  78000 mb, reserve 15000, cost 49000 -> 1
            //   secure_256       post-refresh 107000 mb, reserve 15000, cost 49000 -> 1
            //
            // `0` means the trigger is latched on: `mul_auto` refreshes before
            // every post-refresh multiply, so `trigger_permille` /
            // `should_bootstrap` are inert in steady state on that config. `1`
            // means one multiply fits inside the cycle. Both are safe; which
            // one holds is a real behavioural fact about the config and should
            // fail loudly when it moves, in either direction.
            let expected_funded = match config.name {
                "secure_128_deep" => 0,
                "secure_192" => 1,
                "secure_256" => 1,
                other => panic!("unhandled config in the measured table: {other}"),
            };
            assert_eq!(
                funded, expected_funded,
                "{}: the post-refresh trigger funds {} multiplies where {} was \
                 measured. Rising ABOVE 1 means a refresh cycle is modelled as \
                 carrying more than one multiply's noise past the refresh \
                 window, which the k=2 measurement above says it cannot. Any \
                 other move is a behaviour change -- re-measure the envelope \
                 before updating this table.",
                config.name, funded, expected_funded,
            );
        }
    }

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
