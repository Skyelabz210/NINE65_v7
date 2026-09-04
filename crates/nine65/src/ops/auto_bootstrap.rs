//! Auto-bootstrap evaluator for continued-depth public-key FHE.
//!
//! The evaluator keeps ciphertext state in DualRNS form, tracks an exact
//! integer noise budget, and invokes Clockwork bootstrap when the budget is
//! exhausted or crosses a configured threshold. No reconstructed integer,
//! mixed-radix value, or floating-point quantity is used on this path.
//!
//! # Per-ciphertext noise tracking (issue #93)
//!
//! Noise/refresh state is tracked **per ciphertext**, not per evaluator
//! session. [`TrackedCiphertext`] pairs a [`DualRNSCiphertext`] with its own
//! [`NoiseBudget`]; [`AutoBootstrapEvaluator`] is a stateless-with-respect-
//! to-noise dispatcher over `TrackedCiphertext` values -- it still owns the
//! keys and activity counters, but it owns no shared ledger any operand's
//! history can leak into or be overwritten by.
//!
//! This replaces an earlier design in which the evaluator held one mutable
//! `NoiseBudget` consulted and mutated by every ciphertext it touched. That
//! was only a sound model for one strictly linear operation chain, where
//! each new operation consumes the immediately previous result. The public
//! API always accepted arbitrary ciphertext operands, so a caller could
//! branch a DAG -- encrypt two ciphertexts, operate on one, refresh, then
//! reuse the other -- and the session ledger would no longer describe the
//! operand actually entering the refresh decision: an unrelated branch's
//! activity could trigger (or suppress) a refresh on a ciphertext it never
//! touched. The mechanism now is:
//!
//! 1. Encryption creates an independent, fresh ledger per ciphertext
//!    ([`TrackedCiphertext::fresh`]).
//! 2. Binary operations ([`AutoBootstrapEvaluator::mul_auto`],
//!    [`AutoBootstrapEvaluator::try_add_auto`]) inspect **both operands'**
//!    own ledgers.
//! 3. Only the operand(s) whose own ledger requires it are refreshed
//!    ([`AutoBootstrapEvaluator::preflight_refresh`]) -- an operation on one
//!    ciphertext can never refresh, exhaust, or silently reset another's
//!    state, because there is no shared ledger for it to act through.
//! 4. The output ledger is derived from the actual operand states entering
//!    the operation (the worse of the two, matching the two-operand tensor
//!    bound `v1, v2 <= v` this module's noise algebra assumes), not from a
//!    global operation counter.
//! 5. Cloning a `TrackedCiphertext` clones its ledger exactly; the clone and
//!    the original then evolve completely independently.
//! 6. A ciphertext squared against itself (`mul_auto(&ct, &ct)`) still
//!    refreshes at most once and produces one output ledger -- see
//!    [`same_ciphertext`].

use crate::errors::{Nine65Error, Nine65Result};
use crate::keys::bootstrap::{BootstrapKey, KeySwitchKey};
use crate::noise::budget::{NoiseBudget, NoiseOpType};
use crate::ops::bootstrap::ClockworkBootstrap;
use crate::ops::rns_fhe::{DualRNSCiphertext, DualRNSEvalKey, RNSFHEContext};
use crate::params::FHEConfig;

/// A ciphertext paired with the exact per-ciphertext noise ledger that
/// governs its own refresh eligibility.
///
/// This is the unit of state issue #93 asks for: everything
/// [`AutoBootstrapEvaluator`] needs to decide whether *this* ciphertext
/// needs a refresh travels with the ciphertext itself, not with the
/// evaluator. Two `TrackedCiphertext` values are otherwise unrelated even if
/// they encrypt the same plaintext or originated from the same evaluator --
/// an operation performed on one can never observe or mutate the other's
/// ledger.
#[derive(Clone, Debug)]
pub struct TrackedCiphertext {
    /// The underlying ciphertext.
    pub ct: DualRNSCiphertext,
    /// This ciphertext's own noise ledger. Private so the only way to
    /// advance it is through the evaluator methods that also advance `ct`,
    /// keeping the two fields from drifting out of sync with each other.
    budget: NoiseBudget,
}

impl TrackedCiphertext {
    /// Wrap a ciphertext with a fresh ledger, seated at the noise level of a
    /// fresh encryption (see [`NoiseBudget::from_config`]).
    ///
    /// Every call produces an INDEPENDENT ledger. Encrypting two values does
    /// not halve either one's budget, and encrypting the same plaintext
    /// twice does not make the two results share state.
    pub fn fresh(ct: DualRNSCiphertext, config: &FHEConfig) -> Self {
        Self {
            ct,
            budget: NoiseBudget::from_config(config),
        }
    }

    /// Millibits remaining in this ciphertext's own ledger.
    pub fn remaining_budget_mb(&self) -> i64 {
        self.budget.remaining_millibits()
    }

    /// Exact-integer summary of this ciphertext's own ledger.
    pub fn budget_summary(&self) -> String {
        self.budget.summary()
    }

    /// Read-only access to the tracked ledger -- e.g. for a caller or test
    /// that wants to record the before/after state of a specific operand
    /// rather than only the evaluator-wide activity counters.
    pub fn budget(&self) -> &NoiseBudget {
        &self.budget
    }
}

/// Evaluator that automatically bootstraps a ciphertext operand when its OWN
/// tracked budget reaches its configured lower boundary.
///
/// Holds the keys and public evaluator activity counters
/// (`bootstrap_count`, `total_muls`, `total_adds`). It holds no noise ledger
/// of its own: every ledger decision is made against the
/// [`TrackedCiphertext`] operand(s) passed to the call, so evaluator
/// activity on one ciphertext cannot affect the tracked state of another.
pub struct AutoBootstrapEvaluator<'a> {
    work_ctx: &'a RNSFHEContext,
    bootstrap: &'a ClockworkBootstrap,
    bsk: &'a BootstrapKey,
    ksk: &'a KeySwitchKey,
    evk: &'a DualRNSEvalKey,
    config: &'a FHEConfig,
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
        config: &'a FHEConfig,
    ) -> Self {
        Self {
            work_ctx,
            bootstrap,
            bsk,
            ksk,
            evk,
            config,
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

    /// Wrap a ciphertext produced outside the evaluator (e.g. a fresh
    /// encryption) as a [`TrackedCiphertext`] against this evaluator's
    /// config. A convenience for `TrackedCiphertext::fresh(ct, self.config)`.
    pub fn track(&self, ct: DualRNSCiphertext) -> TrackedCiphertext {
        TrackedCiphertext::fresh(ct, self.config)
    }

    /// Whether `budget` requires a refresh before it enters an operation
    /// costing `operation_cost` -- the same predicate the old session ledger
    /// applied, now evaluated against one specific operand's own state.
    ///
    /// Reserve-aware ([`NoiseBudget::can_perform_with_reserve`], not
    /// `can_perform`): the decryption boundary is not the binding constraint
    /// on a ciphertext about to be refreshed. See the derivation on
    /// `can_perform_with_reserve` and `bootstrap_input_reserve_mb`.
    fn needs_refresh(&self, budget: &NoiseBudget, operation_cost: i64) -> bool {
        !budget.can_perform_with_reserve(operation_cost, self.config)
            || budget.should_bootstrap(self.trigger_permille)
    }

    /// Refresh one operand via bootstrap, producing a new `TrackedCiphertext`
    /// whose ledger is reset to the post-refresh level. The operand's OWN
    /// pre-refresh ledger is cloned and reset, not any other ciphertext's --
    /// bootstrap reset applies only to the ciphertext state being refreshed.
    fn refresh_operand(&mut self, operand: &TrackedCiphertext) -> Nine65Result<TrackedCiphertext> {
        let refreshed_ct = self.bootstrap.bootstrap(&operand.ct, self.bsk, self.ksk)?;
        self.bootstrap_count += 1;
        let mut budget = operand.budget.clone();
        budget.reset_after_bootstrap(self.config);
        Ok(TrackedCiphertext {
            ct: refreshed_ct,
            budget,
        })
    }

    /// Refresh whichever operand(s) need it -- and only those -- before a
    /// pending operation, so an over-budget operand is bootstrapped *before*
    /// it is combined with anything else -- never after.
    ///
    /// This is the fix for the Q17 finding in the deep-analysis audit: an
    /// earlier implementation performed the multiply (or add) *first* and
    /// only checked the budget afterward, refreshing the *result*. A
    /// budget-crossing operation had therefore already computed on an
    /// operand whose tracked noise had crossed the safe threshold, and the
    /// post-hoc "refresh" of the result could only faithfully re-encrypt
    /// that already-corrupted value -- it could never repair it. Checking
    /// and refreshing before the operation, on the operands, is the only
    /// ordering under which "refresh" actually means what it says.
    ///
    /// This is also the fix for issue #93: the check is against EACH
    /// operand's own ledger, not a ledger shared across every ciphertext the
    /// evaluator has ever touched. A clean operand paired with a noisy one
    /// is refreshed alone; a noisy operand paired with a clean one never
    /// borrows the clean one's headroom.
    ///
    /// **A squaring refreshes once, not twice.** For `ct * ct` the same
    /// ciphertext arrives as both operands. [`same_ciphertext`] detects the
    /// case and reuses operand 1's refresh outcome for operand 2 rather than
    /// deciding independently -- bit-identical ciphertexts only arise here
    /// from identity or a clone, and a clone shares its ledger with its
    /// origin at the moment of cloning, so the decision is provably the same
    /// either way. Deciding independently would risk two refreshes of one
    /// ciphertext: two bootstraps, two independent encryptions of the same
    /// value, and a `bootstrap_count` that reports double the work done.
    fn preflight_refresh(
        &mut self,
        ct1: &TrackedCiphertext,
        ct2: &TrackedCiphertext,
        operation_cost: i64,
    ) -> Nine65Result<(TrackedCiphertext, TrackedCiphertext)> {
        let same = same_ciphertext(&ct1.ct, &ct2.ct);

        let op1 = if self.needs_refresh(&ct1.budget, operation_cost) {
            self.refresh_operand(ct1)?
        } else {
            ct1.clone()
        };

        let op2 = if same {
            op1.clone()
        } else if self.needs_refresh(&ct2.budget, operation_cost) {
            self.refresh_operand(ct2)?
        } else {
            ct2.clone()
        };

        Ok((op1, op2))
    }

    /// Multiply with automatic bootstrap.
    ///
    /// Refreshes whichever operand(s) need it *before* multiplying (see
    /// [`Self::preflight_refresh`]); the multiply itself then always runs on
    /// operands their own ledgers can account for. The output's ledger is
    /// derived from whichever operand ledger is worse (less remaining
    /// budget) after preflight, matching the two-operand tensor bound
    /// `v1, v2 <= v` this module's noise algebra assumes -- not from a
    /// global operation counter.
    pub fn mul_auto(
        &mut self,
        ct1: &TrackedCiphertext,
        ct2: &TrackedCiphertext,
    ) -> Nine65Result<TrackedCiphertext> {
        let operation_cost =
            NoiseBudget::mul_ct_cost(self.config) + NoiseBudget::relin_cost(self.config);

        let (op1, op2) = self.preflight_refresh(ct1, ct2, operation_cost)?;

        let mut out_budget = combine_for_binary_op(&op1.budget, &op2.budget);
        out_budget
            .consume(NoiseOpType::MulCt, operation_cost)
            .map_err(|e| Nine65Error::BootstrapFailed {
                reason: format!(
                    "noise budget cannot cover a single multiply immediately \
                     after refresh (config budget too small for this op): {}",
                    e
                ),
            })?;

        let result = self.work_ctx.mul_dual_public(&op1.ct, &op2.ct, self.evk)?;
        self.total_muls += 1;
        Ok(TrackedCiphertext {
            ct: result,
            budget: out_budget,
        })
    }

    /// Add with automatic bootstrap and explicit error propagation.
    ///
    /// Additions are inexpensive, but a sufficiently long addition-only chain
    /// can still consume a ciphertext's own tracked budget. Refreshes
    /// whichever operand(s) need it *before* adding (see
    /// [`Self::preflight_refresh`]).
    pub fn try_add_auto(
        &mut self,
        ct1: &TrackedCiphertext,
        ct2: &TrackedCiphertext,
    ) -> Nine65Result<TrackedCiphertext> {
        let operation_cost = NoiseBudget::add_cost();

        let (op1, op2) = self.preflight_refresh(ct1, ct2, operation_cost)?;

        let mut out_budget = combine_for_binary_op(&op1.budget, &op2.budget);
        out_budget
            .consume(NoiseOpType::Add, operation_cost)
            .map_err(|e| Nine65Error::BootstrapFailed {
                reason: format!(
                    "noise budget cannot cover a single add immediately \
                     after refresh (config budget too small for this op): {}",
                    e
                ),
            })?;

        let result = self.work_ctx.add_dual(&op1.ct, &op2.ct);
        self.total_adds += 1;
        Ok(TrackedCiphertext {
            ct: result,
            budget: out_budget,
        })
    }

    /// Compatibility wrapper for existing callers.
    ///
    /// New code should call [`Self::try_add_auto`] so a bootstrap failure can
    /// be handled by the caller. This wrapper no longer ignores an exhausted
    /// noise budget; it fails loudly if refresh itself fails.
    pub fn add_auto(
        &mut self,
        ct1: &TrackedCiphertext,
        ct2: &TrackedCiphertext,
    ) -> TrackedCiphertext {
        self.try_add_auto(ct1, ct2)
            .expect("auto-bootstrap addition refresh failed")
    }
}

/// Derive the ledger a binary operation's OUTPUT should carry, from the
/// actual tracked state of its two operands.
///
/// The Fan-Vercauteren tensor bound this module's noise algebra is built on
/// assumes a single input level `v` with `v1, v2 <= v` -- i.e. the bound is
/// only valid once both operands are treated as being as noisy as the worse
/// of the two. `NoiseBudget::remaining_millibits` is a decreasing function of
/// noise (more noise, less remaining budget), so "worse" is "smaller
/// remaining budget": the output inherits that operand's ledger (its
/// `cycle_initial_mb` and operation history included) before the operation's
/// own cost is charged against it.
///
/// This -- not a global operation counter -- is what issue #93 calls for:
/// "Derive the output state from the actual noise bound for the operation."
fn combine_for_binary_op(op1: &NoiseBudget, op2: &NoiseBudget) -> NoiseBudget {
    if op1.remaining_millibits() <= op2.remaining_millibits() {
        op1.clone()
    } else {
        op2.clone()
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
pub fn same_ciphertext(ct1: &DualRNSCiphertext, ct2: &DualRNSCiphertext) -> bool {
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

    fn new_evaluator<'a>(h: &'a Harness) -> AutoBootstrapEvaluator<'a> {
        AutoBootstrapEvaluator::new(
            &h.ctx,
            &h.boot,
            &h.boot_keys.bsk,
            &h.boot_keys.ksk,
            &h.keys.eval_key,
            &h.config,
        )
    }

    fn fresh_tracked(h: &Harness, m: u64, rng: &mut ShadowHarvester) -> TrackedCiphertext {
        let ct = h.ctx.encrypt_dual(m, &h.keys.public_key, rng);
        TrackedCiphertext::fresh(ct, &h.config)
    }

    fn decrypt(h: &Harness, tc: &TrackedCiphertext) -> u64 {
        h.ctx.decrypt_dual(&tc.ct, &h.keys.secret_key)
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
        let mut evaluator = new_evaluator(h);

        let mut ct = fresh_tracked(h, 3, &mut rng);
        assert_eq!(
            decrypt(h, &ct),
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
            let decrypted = decrypt(h, &ct);
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
    ///
    /// KNOWN PRE-EXISTING FAILURE (issue #117, not this issue's problem): the
    /// real (non-bypassed) `ClockworkBootstrap::bootstrap` unconditionally
    /// fails `public_phase1_soundness_gate` for every config, so the first
    /// triggered refresh in this circuit panics via the `unwrap_or_else`
    /// above. This refactor deliberately preserves that -- it changes WHERE
    /// noise state lives, not what `bootstrap()` does when actually called.
    /// See `docs/PUBLIC_REFRESH_CORRUPTS_ADMITTED_CONFIGS_2026-09-03.md`.
    #[test]
    fn repeated_squaring_is_exact_under_auto_refresh_secure_128_deep() {
        assert_squaring_circuit_is_exact(SecureConfig::secure_128_deep(), 11, 8);
    }

    /// ACCEPTANCE (secure_192): same circuit, larger chain.
    ///
    /// KNOWN PRE-EXISTING FAILURE -- see the doc comment on the
    /// `secure_128_deep` variant above.
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
    ///
    /// KNOWN PRE-EXISTING FAILURE -- see the doc comment on the
    /// `secure_128_deep` variant above.
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
    ///
    /// KNOWN PRE-EXISTING FAILURE -- see the doc comment on
    /// `repeated_squaring_is_exact_under_auto_refresh_secure_128_deep` above.
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

    // =========================================================================
    // ADVERSARIAL DAG TESTS (issue #93)
    //
    // Every scenario below decrypts and compares to an exact plaintext oracle
    // at every node. None of them require a real bootstrap to succeed --
    // `ClockworkBootstrap::bootstrap` unconditionally fails
    // `public_phase1_soundness_gate` on this commit (issue #117, a separately
    // tracked, pre-existing defect this issue does not touch), so a scenario
    // that stays inside the operands' own fresh budgets is the only kind that
    // can observe end-to-end correctness right now. The one scenario that
    // deliberately crosses the refresh boundary
    // (`refresh_targets_only_the_operand_that_needs_it`) asserts on the
    // DECISION (which operand was targeted) rather than on bootstrap success,
    // and pins the failure to the already-known #117 reason so a regression
    // there is not silently absorbed by this refactor.
    // =========================================================================

    /// Scenario 1-3 from the issue: square one fresh ciphertext, run several
    /// operations on an unrelated one, then reuse the first. Under the old
    /// shared-session ledger, operating on `b` would consume/mutate the ONE
    /// evaluator-wide budget, so by the time `a` was reused the ledger no
    /// longer described `a` at all. Under per-ciphertext tracking, `a`'s own
    /// ledger must be bit-for-bit what a freshly squared ciphertext's ledger
    /// would be, regardless of everything that happened to `b` in between.
    #[test]
    fn branch_and_reuse_after_unrelated_branch_changes_evaluator_activity() {
        let h = harness(SecureConfig::secure_128_deep(), 501);
        let mut rng = ShadowHarvester::with_seed(1);
        let mut evaluator = new_evaluator(&h);

        // 1. a = square(fresh_a)
        let fresh_a = fresh_tracked(&h, 6, &mut rng);
        let a = evaluator.mul_auto(&fresh_a, &fresh_a).expect("square a");
        assert_eq!(decrypt(&h, &a), 36, "a must decrypt to 6*6");

        // Reference: what a fresh-then-squared ledger looks like in
        // isolation, computed via an INDEPENDENT evaluator instance so
        // nothing from step 2 below can reach it.
        let h_ref = harness(SecureConfig::secure_128_deep(), 501);
        let mut rng_ref = ShadowHarvester::with_seed(1);
        let mut ref_evaluator = new_evaluator(&h_ref);
        let ref_fresh = fresh_tracked(&h_ref, 6, &mut rng_ref);
        let a_reference = ref_evaluator
            .mul_auto(&ref_fresh, &ref_fresh)
            .expect("square reference");
        let a_budget_after_square = a.remaining_budget_mb();
        assert_eq!(
            a_budget_after_square,
            a_reference.remaining_budget_mb(),
            "a's ledger right after its own squaring must match an isolated \
             squaring exactly -- this is the baseline the next step must not move"
        );

        // 2. b = several operations on a completely unrelated fresh ciphertext,
        // run through the SAME evaluator that produced `a`. One multiply (the
        // most a fresh secure_128_deep ciphertext funds before its OWN ledger
        // would need a refresh -- see `trigger_fires_before_the_refresh_
        // window_closes_not_after`'s measured table) followed by several
        // cheap adds, so the chain is nontrivial without depending on the
        // separately-broken bootstrap path succeeding.
        let mut b = fresh_tracked(&h, 2, &mut rng);
        let mut expected_b: u64 = 2;
        let b_sq = evaluator.mul_auto(&b, &b).expect("square b");
        expected_b = (expected_b * expected_b) % h.config.t;
        assert_eq!(decrypt(&h, &b_sq), expected_b);
        b = b_sq;
        for step in 0..5 {
            let one = fresh_tracked(&h, 1, &mut rng);
            b = evaluator
                .try_add_auto(&b, &one)
                .unwrap_or_else(|e| panic!("try_add_auto on b failed at step {}: {}", step, e));
            expected_b = (expected_b + 1) % h.config.t;
            assert_eq!(
                decrypt(&h, &b),
                expected_b,
                "b must decrypt correctly at every step of its own chain"
            );
        }
        assert!(
            b.remaining_budget_mb() < a_budget_after_square,
            "b's chain must actually have consumed b's own budget, or this test \
             proves nothing about cross-contamination"
        );

        // 3. reuse `a` -- the SAME evaluator ran one multiply and five adds on
        // `b` in between, so under the old shared-ledger design `a`'s
        // "budget" would now reflect b's history, not a's. It must not have
        // moved at all.
        assert_eq!(
            a.remaining_budget_mb(),
            a_budget_after_square,
            "a's own ledger must be untouched by four unrelated operations on b \
             performed through the same evaluator -- evaluator activity on one \
             ciphertext must not silently overwrite another's tracked state"
        );
        assert_eq!(
            decrypt(&h, &a),
            36,
            "a's plaintext must also be untouched by b's chain"
        );

        // And `a` must still be usable exactly as if `b` never happened: add
        // it to a third fresh ciphertext and check the result.
        let c = fresh_tracked(&h, 1, &mut rng);
        let combined = evaluator.try_add_auto(&a, &c).expect("a + c");
        assert_eq!(decrypt(&h, &combined), 37, "a(36) + c(1) = 37");
    }

    /// Explicit form of the issue's "unrelated fresh operations cannot
    /// consume another ciphertext's remaining budget" requirement: encrypt
    /// two ciphertexts, drive one through several operations, and check the
    /// OTHER's ledger at every single step, not only at the end.
    #[test]
    fn unrelated_fresh_operations_cannot_consume_anothers_remaining_budget() {
        let h = harness(SecureConfig::secure_128_deep(), 502);
        let mut rng = ShadowHarvester::with_seed(2);
        let mut evaluator = new_evaluator(&h);

        let untouched = fresh_tracked(&h, 9, &mut rng);
        let untouched_budget = untouched.remaining_budget_mb();
        assert_eq!(
            untouched_budget,
            NoiseBudget::from_config(&h.config).remaining_millibits(),
            "a fresh TrackedCiphertext's budget must equal NoiseBudget::from_config \
             exactly -- it is what `TrackedCiphertext::fresh` is defined to produce"
        );

        // One multiply -- the most a fresh secure_128_deep ciphertext funds
        // before its OWN ledger needs a refresh -- followed by several cheap
        // adds, so `driven` accumulates a nontrivial history without
        // depending on the separately-broken bootstrap path.
        let mut driven = fresh_tracked(&h, 3, &mut rng);
        let mut expected: u64 = 3;
        driven = evaluator.mul_auto(&driven, &driven).expect("square driven");
        expected = (expected * expected) % h.config.t;
        assert_eq!(decrypt(&h, &driven), expected);
        assert_eq!(
            untouched.remaining_budget_mb(),
            untouched_budget,
            "untouched ciphertext's budget moved after squaring a completely \
             unrelated ciphertext, run through the same evaluator"
        );
        for step in 0..5 {
            let one = fresh_tracked(&h, 1, &mut rng);
            driven = evaluator.try_add_auto(&driven, &one).unwrap_or_else(|e| {
                panic!("try_add_auto on driven failed at step {}: {}", step, e)
            });
            expected = (expected + 1) % h.config.t;
            assert_eq!(decrypt(&h, &driven), expected);
            assert_eq!(
                untouched.remaining_budget_mb(),
                untouched_budget,
                "untouched ciphertext's budget moved after step {} on a completely \
                 unrelated ciphertext, run through the same evaluator",
                step,
            );
        }

        // Finally: operate on the untouched ciphertext together with a fresh
        // one and confirm the cost charged is exactly what a fresh+fresh
        // multiply costs -- unaffected by `driven`'s three-multiply history.
        let other_fresh = fresh_tracked(&h, 4, &mut rng);
        let result = evaluator
            .mul_auto(&untouched, &other_fresh)
            .expect("untouched * other_fresh");
        assert_eq!(decrypt(&h, &result), 36, "9 * 4 = 36");
        let mul_cost = NoiseBudget::mul_ct_cost(&h.config) + NoiseBudget::relin_cost(&h.config);
        assert_eq!(
            result.remaining_budget_mb(),
            untouched_budget - mul_cost,
            "cost charged must be exactly fresh_budget - mul_cost, with no residue \
             from driven's unrelated history leaking in"
        );
    }

    /// Scenario 5 from the issue: clone one branch, evolve only one clone,
    /// then check both. The un-evolved clone must be byte-for-byte as if it
    /// had never been cloned at all -- both its ciphertext and its ledger.
    #[test]
    fn clone_then_diverge_produces_independent_ledgers() {
        let h = harness(SecureConfig::secure_128_deep(), 503);
        let mut rng = ShadowHarvester::with_seed(3);
        let mut evaluator = new_evaluator(&h);

        let original = fresh_tracked(&h, 7, &mut rng);
        let clone_a = original.clone();
        let clone_b = original.clone();

        assert_eq!(clone_a.remaining_budget_mb(), clone_b.remaining_budget_mb());

        // Evolve only clone_b: one multiply -- the most a fresh
        // secure_128_deep ciphertext funds before its OWN ledger needs a
        // refresh -- followed by several cheap adds.
        let mut evolved_b = clone_b;
        let mut expected_b: u64 = 7;
        evolved_b = evaluator
            .mul_auto(&evolved_b, &evolved_b)
            .expect("evolve clone_b: square");
        expected_b = (expected_b * expected_b) % h.config.t;
        for _ in 0..5 {
            let one = fresh_tracked(&h, 1, &mut rng);
            evolved_b = evaluator
                .try_add_auto(&evolved_b, &one)
                .expect("evolve clone_b: add");
            expected_b = (expected_b + 1) % h.config.t;
        }

        // clone_a must be completely unaffected: same plaintext, same ledger.
        assert_eq!(
            decrypt(&h, &clone_a),
            7,
            "un-evolved clone must still decrypt to the original plaintext"
        );
        assert_eq!(
            clone_a.remaining_budget_mb(),
            original.remaining_budget_mb(),
            "un-evolved clone's ledger must be untouched by the other clone's evolution"
        );
        assert_eq!(decrypt(&h, &evolved_b), expected_b);
        assert!(
            evolved_b.remaining_budget_mb() < clone_a.remaining_budget_mb(),
            "the evolved clone's own ledger must actually have moved, or this test \
             proves nothing"
        );
    }

    /// Scenario 4 from the issue: combine two branches with genuinely
    /// different noise histories (different depth, different operation mix)
    /// and check that the combined result's ledger is derived from the
    /// operands actually entering the operation -- specifically, the WORSE
    /// (lower-remaining-budget) of the two -- not from some other counter.
    #[test]
    fn combining_branches_of_different_noise_histories_derives_output_from_the_worse_operand() {
        let h = harness(SecureConfig::secure_128_deep(), 504);
        let mut rng = ShadowHarvester::with_seed(4);
        let mut evaluator = new_evaluator(&h);

        // Shallow branch: one multiply.
        let shallow_base = fresh_tracked(&h, 2, &mut rng);
        let shallow = evaluator
            .mul_auto(&shallow_base, &shallow_base)
            .expect("shallow branch");
        assert_eq!(decrypt(&h, &shallow), 4);

        // Deep branch: one multiply (the most a fresh secure_128_deep
        // ciphertext funds before its OWN ledger needs a refresh) plus three
        // adds -- a different operation MIX and a strictly worse ledger than
        // `shallow`, not just "more of the same op".
        let deep_base = fresh_tracked(&h, 2, &mut rng);
        let mut deep = evaluator
            .mul_auto(&deep_base, &deep_base)
            .expect("deep step 1: square");
        let mut expected_deep = (2u64 * 2) % h.config.t;
        for step in 0..3 {
            let one = fresh_tracked(&h, 1, &mut rng);
            deep = evaluator
                .try_add_auto(&deep, &one)
                .unwrap_or_else(|e| panic!("deep step 2.{} (add) failed: {}", step, e));
            expected_deep = (expected_deep + 1) % h.config.t;
        }
        assert_eq!(decrypt(&h, &deep), expected_deep);

        assert!(
            deep.remaining_budget_mb() < shallow.remaining_budget_mb(),
            "the deeper/mixed branch must carry a strictly worse ledger than the \
             shallow one, or this test does not exercise the asymmetric case"
        );

        let add_cost = NoiseBudget::add_cost();
        let combined = evaluator
            .try_add_auto(&shallow, &deep)
            .expect("combine shallow + deep");
        let expected_combined = (4 + expected_deep) % h.config.t;
        assert_eq!(decrypt(&h, &combined), expected_combined);

        // THE ASSERTION: output ledger = worse operand's ledger - op cost.
        // `deep` is worse (checked above), so it -- not `shallow`, and not
        // some fresh/global counter -- must be what the combined ledger is
        // derived from.
        assert_eq!(
            combined.remaining_budget_mb(),
            deep.remaining_budget_mb() - add_cost,
            "combined ledger must be derived from the worse (deep) operand's \
             actual tracked state, exactly, not from the shallow operand or a \
             global operation counter"
        );
    }

    /// The refresh decision itself is per-operand: pairing a clean ciphertext
    /// with a noise-exhausted one must target ONLY the exhausted one.
    ///
    /// This cannot observe a successful end-to-end refresh -- see the module
    /// note above -- so it asserts on the decision (via the same private
    /// predicate `preflight_refresh` itself consults) and, when it drives the
    /// evaluator far enough to actually attempt a refresh, pins the failure
    /// to the ALREADY-KNOWN #117 reason (`public_phase1_soundness_gate`), so
    /// a different failure here would mean this refactor broke something new
    /// rather than merely inheriting the tracked, pre-existing defect.
    #[test]
    fn refresh_targets_only_the_operand_that_needs_it() {
        let h = harness(SecureConfig::secure_128_deep(), 505);
        let mut rng = ShadowHarvester::with_seed(5);
        let mut evaluator = new_evaluator(&h);

        let mul_cost = NoiseBudget::mul_ct_cost(&h.config) + NoiseBudget::relin_cost(&h.config);

        // Drive `dirty` right up to (but not past) the point where the next
        // multiply would require a refresh.
        let mut dirty = fresh_tracked(&h, 3, &mut rng);
        let mut expected_dirty: u64 = 3;
        let mut steps = 0;
        loop {
            if evaluator.needs_refresh(dirty.budget(), mul_cost) {
                break;
            }
            dirty = evaluator
                .mul_auto(&dirty, &dirty)
                .unwrap_or_else(|e| panic!("driving dirty failed at step {}: {}", steps, e));
            expected_dirty = (expected_dirty * expected_dirty) % h.config.t;
            assert_eq!(decrypt(&h, &dirty), expected_dirty);
            steps += 1;
            assert!(steps < 32, "dirty never reached the refresh boundary");
        }

        let clean = fresh_tracked(&h, 5, &mut rng);

        // Precondition the whole test rests on: at this exact moment, `dirty`
        // needs a refresh and `clean` does not.
        assert!(
            evaluator.needs_refresh(dirty.budget(), mul_cost),
            "setup failed to reach the refresh boundary on dirty"
        );
        assert!(
            !evaluator.needs_refresh(clean.budget(), mul_cost),
            "clean must not need a refresh -- it is fresh"
        );

        let dirty_budget_before = dirty.remaining_budget_mb();
        let clean_budget_before = clean.remaining_budget_mb();
        let bootstrap_count_before = evaluator.bootstrap_count;

        let result = evaluator.mul_auto(&clean, &dirty);

        println!(
            "refresh_targets_only_the_operand_that_needs_it: dirty before={} mb, \
             clean before={} mb, bootstrap_count before={}, result={:?}",
            dirty_budget_before,
            clean_budget_before,
            bootstrap_count_before,
            result.as_ref().map(|tc| tc.remaining_budget_mb())
        );

        match result {
            Ok(tc) => {
                // If the underlying #117 defect is ever fixed independently
                // of this issue, this branch becomes reachable: the refresh
                // succeeded, and the combined result must still be exact.
                assert_eq!(
                    decrypt(&h, &tc),
                    (expected_dirty * 5) % h.config.t,
                    "if refresh succeeds, the combined plaintext must still be exact"
                );
                assert_eq!(
                    evaluator.bootstrap_count,
                    bootstrap_count_before + 1,
                    "exactly one operand (dirty) needed a refresh -- clean must not \
                     have been refreshed too"
                );
            }
            Err(Nine65Error::BootstrapFailed { reason }) => {
                // The expected outcome on this commit: the evaluator correctly
                // decided `dirty` needed a refresh and attempted it, and that
                // attempt failed for the ALREADY-KNOWN #117 reason -- not
                // because `clean` was mistakenly targeted (clean needed no
                // refresh, so if it had been the one attempted, `dirty`'s
                // untouched, still-exhausted ledger would be the only
                // evidence, which the assertions above already established).
                assert!(
                    reason.contains("Phase 1 does not yet propagate"),
                    "refresh failed for an unexpected reason (not the known #117 \
                     Phase-1 gate): {}",
                    reason
                );
                assert_eq!(
                    evaluator.bootstrap_count, bootstrap_count_before,
                    "a failed refresh attempt must not have incremented bootstrap_count"
                );
            }
            Err(other) => panic!(
                "mul_auto(clean, dirty) failed with an unexpected error variant \
                 (expected BootstrapFailed with the known #117 reason): {:?}",
                other
            ),
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
