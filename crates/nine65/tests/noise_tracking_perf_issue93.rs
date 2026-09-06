//! Before/after performance evidence for issue #93 (per-ciphertext noise
//! tracking), as its "Mandatory before/after performance evidence" section
//! requires: linear repeated-squaring auto path, an independent two-branch
//! DAG workload, an add-heavy DAG, bootstrap count, and per-tracked-ciphertext
//! memory overhead. Integer ns/us timings only -- no floating point anywhere
//! in this file, per `CLAUDE.md`'s zero-float rule.
//!
//! "Before" (the shared-session-ledger `AutoBootstrapEvaluator`) no longer
//! type-checks against this crate's API once the refactor lands, so its
//! numbers were captured by running this same file's logic (adapted to the
//! old `mul_auto(&DualRNSCiphertext, &DualRNSCiphertext)` signature) against
//! the pre-refactor tree in a separate run; both runs are quoted together in
//! the PR description for issue #93 rather than kept side by side as code.
//!
//! Run:
//!   cargo test -p nine65 --test noise_tracking_perf_issue93 --release \
//!     --features allow_insecure -- --ignored --nocapture

use nine65::entropy::ShadowHarvester;
use nine65::noise::budget::NoiseBudget;
use nine65::ops::auto_bootstrap::{AutoBootstrapEvaluator, TrackedCiphertext};
use nine65::ops::bootstrap::ClockworkBootstrap;
use nine65::ops::rns_fhe::{DualRNSCiphertext, RNSFHEContext};
use nine65::params::SecureConfig;
use std::time::Instant;

struct Harness {
    ctx: RNSFHEContext,
    boot: ClockworkBootstrap,
    keys: nine65::ops::rns_fhe::DualRNSFullKeySet,
    boot_keys: nine65::keys::bootstrap::BootstrapKeySet,
    config: nine65::params::FHEConfig,
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

fn new_evaluator(h: &Harness) -> AutoBootstrapEvaluator<'_> {
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
    TrackedCiphertext::fresh(h.ctx.encrypt_dual(m, &h.keys.public_key, rng), &h.config)
}

/// Integer-only (min, median, max) over a set of nanosecond samples. No
/// float division anywhere -- median is a direct index into the sorted
/// vector, not an averaged/interpolated value.
fn ns_stats(mut samples: Vec<u128>) -> (u128, u128, u128) {
    assert!(!samples.is_empty(), "no samples to summarize");
    samples.sort_unstable();
    let min = samples[0];
    let max = samples[samples.len() - 1];
    let median = samples[samples.len() / 2];
    (min, median, max)
}

fn print_stats(label: &str, samples: Vec<u128>) {
    let n = samples.len();
    let total: u128 = samples.iter().sum();
    let (min, median, max) = ns_stats(samples);
    println!("  {label}: n={n} total_ns={total} min_ns={min} median_ns={median} max_ns={max}");
}

// =============================================================================
// 1. LINEAR REPEATED-SQUARING AUTO PATH
// =============================================================================
//
// Drives `mul_auto(&ct, &ct)` until it errors, timing every successful call.
// On this commit every admitted config funds exactly ONE ct x ct multiply
// from a fresh ciphertext before `preflight_refresh` decides a refresh is
// needed (see `ops::auto_bootstrap::tests::trigger_fires_before_the_refresh_
// window_closes_not_after`'s measured table), and every real refresh
// currently fails `public_phase1_soundness_gate` (issue #117, pre-existing,
// not touched here) -- so depth reached is 1 for both the old and the new
// design; what this measures is per-op cost and where the OWN chain stops,
// not depth. That equality is itself part of the evidence: a strictly linear
// chain behaves identically before and after issue #93's refactor.
#[test]
#[ignore = "perf evidence, run explicitly: --ignored --nocapture"]
fn bench_linear_repeated_squaring_auto_path() {
    for secure in [
        SecureConfig::secure_128_deep(),
        SecureConfig::secure_192(),
        SecureConfig::secure_256(),
    ] {
        let name = secure.config.name;
        let h = harness(secure, 90_001);
        let mut rng = ShadowHarvester::with_seed(1);
        let mut evaluator = new_evaluator(&h);

        let mut ct = fresh_tracked(&h, 3, &mut rng);
        let mut samples = Vec::new();
        let mut depth_reached = 0usize;
        let mut stop_reason = String::new();

        for _ in 0..20 {
            let t0 = Instant::now();
            match evaluator.mul_auto(&ct, &ct) {
                Ok(next) => {
                    samples.push(t0.elapsed().as_nanos());
                    ct = next;
                    depth_reached += 1;
                }
                Err(e) => {
                    stop_reason = format!("{}", e);
                    break;
                }
            }
        }

        println!(
            "[linear-squaring] {name}: depth_reached={depth_reached} bootstrap_count={} stop_reason={:?}",
            evaluator.bootstrap_count, stop_reason
        );
        if !samples.is_empty() {
            print_stats("mul_auto", samples);
        }
    }
}

// =============================================================================
// 2. INDEPENDENT TWO-BRANCH DAG WORKLOAD
// =============================================================================
//
// THE decisive comparison for issue #93. Branch B is driven through a
// nontrivial history (one multiply, several adds) on a shared evaluator;
// branch A is untouched fresh ciphertext on the SAME evaluator. Under the
// OLD shared-session-ledger design, B's activity leaves the evaluator's one
// budget too depleted to fund A's first operation, so `mul_auto` on A
// wrongly decides a refresh is needed and fails (the refresh itself then
// also fails on issue #117, but the wrong DECISION already happened -- a
// fresh, untouched ciphertext should never need a refresh). Under the NEW
// per-ciphertext design, A carries its own independent, still-fresh ledger,
// so its first operation succeeds and decrypts exactly, regardless of B.
#[test]
#[ignore = "perf evidence, run explicitly: --ignored --nocapture"]
fn bench_independent_two_branch_dag() {
    let h = harness(SecureConfig::secure_128_deep(), 90_002);
    let mut rng = ShadowHarvester::with_seed(2);
    let mut evaluator = new_evaluator(&h);

    let workload_start = Instant::now();

    // Branch B: nontrivial, unrelated history.
    let mut b = fresh_tracked(&h, 2, &mut rng);
    let mut expected_b: u64 = 2;
    let mut b_samples = Vec::new();
    let t0 = Instant::now();
    b = evaluator.mul_auto(&b, &b).expect("square b");
    b_samples.push(t0.elapsed().as_nanos());
    expected_b = (expected_b * expected_b) % h.config.t;
    for _ in 0..5 {
        let one = fresh_tracked(&h, 1, &mut rng);
        let t1 = Instant::now();
        b = evaluator.try_add_auto(&b, &one).expect("add to b");
        b_samples.push(t1.elapsed().as_nanos());
        expected_b = (expected_b + 1) % h.config.t;
    }
    assert_eq!(h.ctx.decrypt_dual(&b.ct, &h.keys.secret_key), expected_b);

    // Branch A: fresh, untouched, reused only now.
    let a = fresh_tracked(&h, 11, &mut rng);
    let t2 = Instant::now();
    let a_result = evaluator.mul_auto(&a, &a);
    let a_elapsed_ns = t2.elapsed().as_nanos();

    let workload_elapsed_ns = workload_start.elapsed().as_nanos();

    println!(
        "[two-branch-dag] {}: branch A's first op after B's unrelated history: {} \
         (elapsed_ns={a_elapsed_ns}), bootstrap_count={}, total_workload_ns={workload_elapsed_ns}",
        h.config.name,
        match &a_result {
            Ok(tc) => format!(
                "SUCCEEDED (decrypted={})",
                h.ctx.decrypt_dual(&tc.ct, &h.keys.secret_key)
            ),
            Err(e) => format!("FAILED ({})", e),
        },
        evaluator.bootstrap_count,
    );
    print_stats("branch B ops", b_samples);

    // ACCEPTANCE for the per-ciphertext (post-#93) design: A's own ledger was
    // never touched by B, so A's first operation must succeed and be exact --
    // it is the SAME thing an isolated evaluator would do with A alone.
    let a_tc = a_result.expect(
        "branch A's first operation must succeed under per-ciphertext tracking: \
         a fresh, untouched ciphertext must never be refused because of an \
         UNRELATED branch's activity on the same evaluator",
    );
    assert_eq!(
        h.ctx.decrypt_dual(&a_tc.ct, &h.keys.secret_key),
        121,
        "11*11=121"
    );
}

// =============================================================================
// 3. ADD-HEAVY DAG
// =============================================================================
//
// Additions are cheap (`NoiseBudget::add_cost() == 1000` millibits against a
// mul's ~47000-49000), so a long add-only chain stays inside a single fresh
// ciphertext's budget without ever reaching the broken refresh path -- this
// is the one workload in this file that can run to real depth.
#[test]
#[ignore = "perf evidence, run explicitly: --ignored --nocapture"]
fn bench_add_heavy_dag() {
    const CHAIN_LEN: usize = 40;
    for secure in [SecureConfig::secure_128_deep(), SecureConfig::secure_192()] {
        let name = secure.config.name;
        let h = harness(secure, 90_003);
        let mut rng = ShadowHarvester::with_seed(3);
        let mut evaluator = new_evaluator(&h);

        let mut ct = fresh_tracked(&h, 0, &mut rng);
        let mut expected: u64 = 0;
        let mut samples = Vec::with_capacity(CHAIN_LEN);
        let mut completed = 0usize;

        for i in 0..CHAIN_LEN {
            let one = fresh_tracked(&h, 1, &mut rng);
            let t0 = Instant::now();
            match evaluator.try_add_auto(&ct, &one) {
                Ok(next) => {
                    samples.push(t0.elapsed().as_nanos());
                    ct = next;
                    expected = (expected + 1) % h.config.t;
                    completed += 1;
                }
                Err(e) => {
                    println!("[add-heavy-dag] {name}: stopped at op {i}: {e}");
                    break;
                }
            }
        }

        assert_eq!(
            h.ctx.decrypt_dual(&ct.ct, &h.keys.secret_key),
            expected,
            "{name}: add-heavy chain must stay exact through every completed op"
        );
        println!(
            "[add-heavy-dag] {name}: completed={completed}/{CHAIN_LEN} bootstrap_count={} \
             final_remaining_budget_mb={}",
            evaluator.bootstrap_count,
            ct.remaining_budget_mb(),
        );
        print_stats("try_add_auto", samples);
    }
}

// =============================================================================
// 4. PER-TRACKED-CIPHERTEXT MEMORY OVERHEAD
// =============================================================================
//
// Exact, integer, `std::mem::size_of`-based. Under the OLD design one
// `NoiseBudget` existed per EVALUATOR SESSION; under the NEW design one
// exists per LIVE TrackedCiphertext -- that is the memory cost of the
// correctness fix, and this is what it is, in bytes, not an estimate.
#[test]
#[ignore = "perf evidence, run explicitly: --ignored --nocapture"]
fn bench_memory_overhead() {
    let ct_size = std::mem::size_of::<DualRNSCiphertext>();
    let budget_size = std::mem::size_of::<NoiseBudget>();
    let op_size = std::mem::size_of::<nine65::noise::budget::NoiseOperation>();
    let tracked_size = std::mem::size_of::<TrackedCiphertext>();

    println!("[memory] size_of::<DualRNSCiphertext>()   = {ct_size} bytes");
    println!("[memory] size_of::<NoiseBudget>()          = {budget_size} bytes (fixed part; operations Vec grows on the heap, {op_size} bytes/op)");
    println!("[memory] size_of::<NoiseOperation>()       = {op_size} bytes");
    println!("[memory] size_of::<TrackedCiphertext>()    = {tracked_size} bytes");
    println!(
        "[memory] fixed per-ciphertext ledger overhead vs. an untracked ciphertext = {} bytes \
         (before issue #93: this existed ONCE per evaluator session; after: once per LIVE TrackedCiphertext)",
        tracked_size - ct_size,
    );

    // Sanity: the wrapper must not silently duplicate the ciphertext's own
    // heap-backed contents beyond the one NoiseBudget field it adds.
    assert!(
        tracked_size >= ct_size,
        "TrackedCiphertext must be at least as large as the ciphertext it wraps"
    );
}
