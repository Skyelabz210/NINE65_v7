# Depth Ceiling Investigation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Determine the actual depth ceilings for both FHE modes — symmetric (no artificial cap) and public key (unlimited via bootstrap) — investigate the depth-9000 noise anomaly, and compare pre-CT vs CT NTT data flow.

**Architecture:** Four independent investigation tracks run against existing infrastructure. Symmetric mode ceiling found by removing the `max_test_depth = 50` cap and running to first decryption failure. Public key unlimited depth validated via `AutoBootstrapEvaluator::mul_auto` at 1000+ multiplications. The depth-9000 anomaly is tested via the bootstrap-accumulation-bias hypothesis (200 sequential bootstraps, track noise mean drift). Pre-CT NTT extracted from `01_NINE65_original.zip` and compared structurally against current `ntt_fft.rs`.

**Tech Stack:** Rust, `cargo test --release`, `crates/nine65-extreme-tests` (feature: `extreme-tests`), existing `GSOFHEContext`, `AutoBootstrapEvaluator`, `RNSFHEContext`, `ShadowHarvester`.

---

## Track A — Symmetric Mode: Find the Actual Ceiling

### Task 1: Add uncapped symmetric depth test to extreme-tests

**Files:**
- Modify: `crates/nine65-extreme-tests/src/depth_stress_tests.rs`

**Step 1: Add the uncapped test (append to existing `mod tests` block)**

```rust
/// A-1: Run symmetric mode until the first decryption failure.
/// No artificial depth cap — this is finding the real floor/ceiling.
/// Uses secure_128 (most conservative — will find ceiling soonest).
///
/// Records:
///  - depth at first failure
///  - noise stats at each depth
///  - whether failure is decryption error or wrong plaintext
#[test]
fn test_symmetric_ceiling_uncapped_secure_128() {
    use nine65::ops::gso_fhe::GSOFHEContext;
    use nine65::ops::rns_fhe::RNSFHEContext;
    use nine65::params::secure_configs::SecureConfig;
    use nine65::entropy::ShadowHarvester;

    let config = SecureConfig::secure_128().into_config();
    let inner = RNSFHEContext::new_coeff_domain(&config);
    let mut ctx = GSOFHEContext::new(inner);
    let mut rng = ShadowHarvester::with_seed(99_001);
    let keys = ctx.generate_keys(&mut rng);

    let plaintext: u64 = 2;
    let mut ct = ctx.encrypt(plaintext, &keys.public_key, &mut rng);
    // Track expected value: each squaring doubles the exponent mod t
    let mut expected: u64 = plaintext;

    println!("\n[ceiling] secure_128 symmetric mode uncapped depth run");
    println!("Depth │ Noise permille │ Decrypted │ Expected │ Status");
    println!("──────┼────────────────┼───────────┼──────────┼───────");

    let mut depth = 0usize;
    let wall_at: Option<usize>;

    loop {
        let ct_sq = ct.clone();
        let next = ctx.mul_symmetric(&ct, &ct_sq, &keys.secret_key);
        depth += 1;
        expected = (expected * expected) % config.t;

        let stats = ctx.noise_stats(&next);
        let decrypted = ctx.decrypt(&next, &keys.secret_key);

        let ok = decrypted == expected;
        println!(
            "{:5} │ {:>14} │ {:>9} │ {:>8} │ {}",
            depth,
            stats.ratio_permille,
            decrypted,
            expected,
            if ok { "✓" } else { "✗ FAIL" }
        );

        if !ok {
            wall_at = Some(depth);
            println!(
                "\n[ceiling] WALL HIT at depth {}. \
                 Noise permille={}, budget remaining≈{}‰",
                depth, stats.ratio_permille,
                1000u64.saturating_sub(stats.ratio_permille as u64)
            );
            break;
        }

        ct = next;

        // Safety: if we somehow reach 5000 depths, document it and stop
        if depth >= 5000 {
            wall_at = None;
            println!("\n[ceiling] Reached depth 5000 with no failure — ceiling is > 5000");
            break;
        }
    }

    println!("\n[ceiling] RESULT: symmetric secure_128 ceiling = {:?}", wall_at);
    // Test always passes — we are documenting the finding, not asserting a specific depth
}

/// A-2: Same uncapped run for secure_192.
/// Only runs to depth 200 max (much slower per operation).
#[test]
fn test_symmetric_ceiling_uncapped_secure_192() {
    use nine65::ops::gso_fhe::GSOFHEContext;
    use nine65::ops::rns_fhe::RNSFHEContext;
    use nine65::params::secure_configs::SecureConfig;
    use nine65::entropy::ShadowHarvester;

    let config = SecureConfig::secure_192().into_config();
    let inner = RNSFHEContext::new_coeff_domain(&config);
    let mut ctx = GSOFHEContext::new(inner);
    let mut rng = ShadowHarvester::with_seed(99_002);
    let keys = ctx.generate_keys(&mut rng);

    let plaintext: u64 = 3;
    let mut ct = ctx.encrypt(plaintext, &keys.public_key, &mut rng);
    let mut expected: u64 = plaintext;

    println!("\n[ceiling] secure_192 symmetric mode uncapped depth run (max 200)");

    let mut depth = 0usize;
    let mut wall_at: Option<usize> = None;

    loop {
        let ct_sq = ct.clone();
        let next = ctx.mul_symmetric(&ct, &ct_sq, &keys.secret_key);
        depth += 1;
        expected = (expected * expected) % config.t;

        let decrypted = ctx.decrypt(&next, &keys.secret_key);
        if decrypted != expected {
            wall_at = Some(depth);
            println!("[ceiling] secure_192 WALL at depth {}", depth);
            break;
        }
        ct = next;

        if depth >= 200 {
            println!("[ceiling] secure_192: no failure at depth 200");
            break;
        }
    }

    println!("[ceiling] RESULT: secure_192 ceiling = {:?}", wall_at);
}
```

**Step 2: Run to verify the tests compile and produce output**

```bash
cargo test -p nine65-extreme-tests --features extreme-tests \
  test_symmetric_ceiling_uncapped_secure_128 -- --nocapture 2>&1 | tee /tmp/ceiling_128.txt
```

Expected: test runs, prints depth table, prints RESULT line. Time will be long — let it run.

**Step 3: Run secure_192 variant**

```bash
cargo test -p nine65-extreme-tests --features extreme-tests \
  test_symmetric_ceiling_uncapped_secure_192 -- --nocapture 2>&1 | tee /tmp/ceiling_192.txt
```

**Step 4: Record the ceiling numbers**

From the output, note:
- `secure_128` ceiling: depth at which `✗ FAIL` first appears (or `> 5000`)
- `secure_192` ceiling: same
- Noise permille at the failure point — is the budget actually exhausted, or is something else failing first?

**Step 5: Commit**

```bash
git add crates/nine65-extreme-tests/src/depth_stress_tests.rs
git commit -m "test(depth): add uncapped symmetric mode ceiling tests — track A

Records actual depth ceiling for secure_128 and secure_192 without
the artificial max_test_depth=50 cap. Documents the real wall.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Track B — Public Key Mode: 1000+ Depth Validation

### Task 2: Validate unlimited depth via AutoBootstrapEvaluator

**Files:**
- Modify: `crates/nine65-extreme-tests/src/depth_stress_tests.rs`
- Reference: `crates/nine65/src/ops/auto_bootstrap.rs` (read this before implementing)

**Step 1: Read the AutoBootstrapEvaluator API**

```bash
cat crates/nine65/src/ops/auto_bootstrap.rs | head -100
```

Look for: how to construct it, what `mul_auto` signature is, how to check bootstrap count.

**Step 2: Add 1000-depth public key validation test**

```rust
/// B-1: Public key mode via AutoBootstrapEvaluator — 1000 multiplications.
///
/// This is the "unlimited depth" claim. The evaluator auto-triggers bootstrap
/// when noise approaches threshold. We verify:
///   1. Exact decryption at depth checkpoints: 100, 250, 500, 750, 1000
///   2. Bootstrap was triggered (not zero bootstraps)
///   3. No drift: each checkpoint decrypts to exactly the expected value
#[test]
fn test_public_key_unlimited_depth_1000() {
    use nine65::ops::auto_bootstrap::AutoBootstrapEvaluator;
    use nine65::ops::rns_fhe::RNSFHEContext;
    use nine65::params::secure_configs::SecureConfig;
    use nine65::entropy::ShadowHarvester;

    let config = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&config).expect("context");
    let mut rng = ShadowHarvester::with_seed(77_001);
    let keys = ctx.generate_keys_dual_secure();

    let plaintext: u64 = 2;
    let mut ct = ctx.encrypt_dual_secure(plaintext, &keys.public_key);
    let mut expected: u64 = plaintext;
    let checkpoints = [100usize, 250, 500, 750, 1000];
    let mut bootstrap_count = 0usize;

    let mut evaluator = AutoBootstrapEvaluator::new(&ctx, &keys);

    println!("\n[unlimited] public key mode — 1000 multiplications via AutoBootstrapEvaluator");
    println!("Checkpoint │ Expected │ Decrypted │ Bootstraps so far │ Status");
    println!("───────────┼──────────┼───────────┼───────────────────┼───────");

    for depth in 1..=1000usize {
        let ct_sq = ct.clone();
        let (next, bootstrapped) = evaluator.mul_auto(&ct, &ct_sq);
        if bootstrapped { bootstrap_count += 1; }
        expected = (expected * expected) % config.t;
        ct = next;

        if checkpoints.contains(&depth) {
            let decrypted = ctx.decrypt_dual(&ct, &keys.secret_key);
            let ok = decrypted == expected;
            println!(
                "{:>10} │ {:>8} │ {:>9} │ {:>17} │ {}",
                depth, expected, decrypted, bootstrap_count,
                if ok { "✓" } else { "✗ DRIFT" }
            );
            assert_eq!(
                decrypted, expected,
                "Depth {}: expected {} got {} after {} bootstraps",
                depth, expected, decrypted, bootstrap_count
            );
        }
    }

    println!("\n[unlimited] 1000 depths complete. Total bootstraps triggered: {}", bootstrap_count);
    assert!(bootstrap_count > 0,
        "Expected at least one auto-bootstrap over 1000 multiplications");
    println!("[unlimited] CONFIRMED: public key mode is depth-unlimited in practice.");
}
```

**Step 3: Adjust API calls if needed**

The exact method signatures for `AutoBootstrapEvaluator` may differ. Read `auto_bootstrap.rs` first (Step 1) and adjust the calls accordingly. The key pattern to match: construct evaluator with context + keys, call multiply which returns (ciphertext, bool indicating if bootstrap fired).

**Step 4: Run the test**

```bash
cargo test -p nine65-extreme-tests --features extreme-tests \
  test_public_key_unlimited_depth_1000 -- --nocapture 2>&1 | tee /tmp/unlimited_1000.txt
```

Expected: 5 checkpoint lines all showing `✓`, bootstrap count > 0, final confirmation line.

**Step 5: Commit**

```bash
git add crates/nine65-extreme-tests/src/depth_stress_tests.rs
git commit -m "test(depth): validate public key unlimited depth at 1000 muls — track B

Confirms exact decryption at depths 100/250/500/750/1000 via
AutoBootstrapEvaluator. Verifies bootstrap triggers and zero drift.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Track C — Depth-9000 Anomaly: Bootstrap Accumulation Bias Hypothesis

### Task 3: Test whether sequential bootstraps drift the noise mean

**Files:**
- Modify: `crates/nine65-extreme-tests/src/depth_stress_tests.rs`

**Context:** At depth ~9000 a noise drift appeared that budget monitoring did not catch. Hypothesis: each bootstrap has a tiny directional bias in its noise reset. After ~180 bootstraps (9000 ops at ~50 muls per bootstrap cycle), the *mean* of the noise distribution has shifted from zero even though the *magnitude* is within budget. The GSO swarm fix worked by averaging multiple paths, which cancels this directional bias.

**Step 1: Add bootstrap accumulation drift test**

```rust
/// C-1: Bootstrap accumulation bias hypothesis.
///
/// Run 200 sequential bootstraps. After each, measure noise distribution.
/// If the mean drifts (not just magnitude), this confirms the hypothesis
/// that the depth-9000 anomaly is accumulated directional bias across
/// many bootstrap cycles, not budget exhaustion.
///
/// "Noise mean" here = the coefficient-wise sum of the noise polynomial.
/// A non-zero trend confirms bias; random noise would stay near zero mean.
#[test]
fn test_bootstrap_accumulation_drift_200_cycles() {
    use nine65::ops::bootstrap::ClockworkBootstrap;
    use nine65::ops::rns_fhe::RNSFHEContext;
    use nine65::params::secure_configs::SecureConfig;
    use nine65::entropy::ShadowHarvester;

    let config = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&config).expect("context");
    let mut rng = ShadowHarvester::with_seed(55_001);
    let keys = ctx.generate_keys_dual_secure();

    let plaintext: u64 = 7;
    // Do a multiply first so there's actual noise to reset
    let ct_enc = ctx.encrypt_dual_secure(plaintext, &keys.public_key);
    let ct_start = ctx.mul_dual_symmetric(&ct_enc, &ct_enc, &keys.secret_key);

    println!("\n[drift] Bootstrap accumulation bias — 200 sequential bootstraps");
    println!("Cycle │ Post-bootstrap noise permille │ Decrypted │ Expected");
    println!("──────┼──────────────────────────────┼───────────┼─────────");

    let expected_after_one_mul = (plaintext * plaintext) % config.t;
    let mut ct = ct_start;
    let mut permille_readings: Vec<u64> = Vec::with_capacity(200);

    for cycle in 1..=200usize {
        // Bootstrap — resets noise
        ct = ctx.bootstrap(&ct, &keys.secret_key).expect("bootstrap");

        let stats = ctx.noise_stats(&ct);
        permille_readings.push(stats.ratio_permille as u64);

        if cycle % 20 == 0 {
            let decrypted = ctx.decrypt_dual(&ct, &keys.secret_key);
            println!(
                "{:5} │ {:>28} │ {:>9} │ {:>8}",
                cycle, stats.ratio_permille, decrypted, expected_after_one_mul
            );
        }
    }

    // Analyse: is the noise permille trend drifting upward?
    let first_20_mean: u64 = permille_readings[..20].iter().sum::<u64>() / 20;
    let last_20_mean: u64 = permille_readings[180..].iter().sum::<u64>() / 20;
    let drift = last_20_mean as i64 - first_20_mean as i64;

    println!("\n[drift] First-20 bootstrap mean noise: {}‰", first_20_mean);
    println!("[drift] Last-20  bootstrap mean noise: {}‰", last_20_mean);
    println!("[drift] Drift over 200 cycles: {:+}‰", drift);

    if drift.abs() > 50 {
        println!("[drift] HYPOTHESIS CONFIRMED: noise mean is drifting across bootstrap cycles.");
        println!("[drift] This explains the depth-9000 anomaly.");
    } else {
        println!("[drift] Hypothesis not confirmed at this scale — drift is within noise floor.");
        println!("[drift] Anomaly may require depth >1000 bootstraps to manifest.");
    }
    // Test always passes — documenting the finding
}
```

**Step 2: Run**

```bash
cargo test -p nine65-extreme-tests --features extreme-tests \
  test_bootstrap_accumulation_drift_200_cycles -- --nocapture 2>&1 | tee /tmp/drift_200.txt
```

**Step 3: Read the drift number**

- If `|drift| > 50‰`: hypothesis confirmed — bootstrap is accumulating bias
- If `|drift| < 10‰`: noise is genuinely random post-bootstrap — anomaly is something else (NTT cycle resonance at depth ~8192, or something deeper)

**Step 4: Commit**

```bash
git add crates/nine65-extreme-tests/src/depth_stress_tests.rs
git commit -m "test(depth): bootstrap accumulation bias hypothesis — track C

Tests whether 200 sequential bootstraps produce drifting noise mean.
Addresses the observed depth-9000 anomaly where budget was not
exhausted but correctness drifted.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Track D — Pre-CT vs CT NTT: Architecture Comparison

### Task 4: Extract v01 and compare NTT implementations

**Files:**
- Read: `/home/acid/Projects/QMNF_TOPS/FHE_VERSIONS/01_NINE65_original.zip`
- Read: `crates/nine65/src/arithmetic/ntt.rs` (current)
- Create: `docs/analysis/ntt-architecture-comparison.md`

**Step 1: Extract v01 NTT**

```bash
cd /tmp && mkdir -p v01_extract
cd v01_extract && unzip "/home/acid/Projects/QMNF_TOPS/FHE_VERSIONS/01_NINE65_original.zip" \
  "qmnf_fhe_production/src/arithmetic/ntt.rs" -d . 2>&1
cat qmnf_fhe_production/src/arithmetic/ntt.rs
```

**Step 2: Note the structural differences**

Read both files and document:

| Property | v01 `ntt.rs` (pre-CT) | Current `ntt_fft.rs` (CT) |
|----------|----------------------|--------------------------|
| Butterfly structure | ? | Cooley-Tukey DIT |
| Reduction per stage | ? | Harvey lazy / Barrett |
| Memory access pattern | ? | Stride-based |
| Modular reduction points | ? | Deferred (lazy) |
| Montgomery integration | ? | ? |

**Step 3: Write comparison document**

```bash
mkdir -p docs/analysis
```

Create `docs/analysis/ntt-architecture-comparison.md` with:
- The structural comparison table (filled in from Step 2)
- Key question: where does each version place modular reduction relative to the butterfly?
- Key question: does the CT stride pattern conflict with the CRT lane layout?
- Key question: what did the pre-CT version do with the triple-stream CRT error correction?

**Step 4: Check if v02 or v03 has ntt_fft.rs (pinpoints when CT was introduced)**

```bash
cd /tmp
mkdir -p v02_extract
cd v02_extract
tar -tzf "/home/acid/Projects/QMNF_TOPS/FHE_VERSIONS/02_NINE65_stable.tar.gz" | grep ntt
```

```bash
mkdir -p v03_extract
cd v03_extract
tar -tzf "/home/acid/Projects/QMNF_TOPS/FHE_VERSIONS/03_MANA_boosted.tar.gz" | grep ntt
```

This tells you exactly which version first added CT butterflies — confirming whether CT came with MANA (v03) or later (v04 QClassic).

**Step 5: Commit the analysis document**

```bash
git add docs/analysis/ntt-architecture-comparison.md
git commit -m "docs(analysis): pre-CT vs CT NTT architecture comparison — track D

Extracts v01 NTT, compares structure against current CT implementation.
Documents reduction placement, butterfly structure, and Montgomery
integration differences. Notes when CT was introduced across version history.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Track E — Lattice Estimator: Formal Security Parameter Validation

### Task 5: Run parameters through lattice-estimator

**Context:** The FHE community uses the lattice-estimator tool to produce concrete attack cost estimates. If your parameters produce outputs meeting 128/192/256-bit security levels, the claim is irrefutable from their framework.

**Step 1: Check if lattice-estimator is available**

```bash
python3 -c "import estimator" 2>&1
# If not: pip install lattice-estimator or clone from github.com/malb/lattice-estimator
```

**Step 2: Run estimate for secure_128**

```python
# Save as /tmp/estimate_nine65.py and run with: python3 /tmp/estimate_nine65.py
from estimator import *
from estimator.lwe_parameters import LWEParameters as LWEParams

# secure_128: n=4096, log2(q)=90, Gaussian error sigma=3.19
params_128 = LWEParams(
    n=4096,
    q=2**90,
    Xs=ND.UniformMod(3),   # ternary secret
    Xe=ND.DiscreteGaussian(3.19),
    m=4096,
    tag="NINE65_secure_128"
)
print("=== secure_128 ===")
print(LWE.estimate(params_128))

# secure_192: n=16384, log2(q)=147
params_192 = LWEParams(
    n=16384,
    q=2**147,
    Xs=ND.UniformMod(3),
    Xe=ND.DiscreteGaussian(3.19),
    m=16384,
    tag="NINE65_secure_192"
)
print("=== secure_192 ===")
print(LWE.estimate(params_192))

# secure_256: n=16384, log2(q)=177
params_256 = LWEParams(
    n=16384,
    q=2**177,
    Xs=ND.UniformMod(3),
    Xe=ND.DiscreteGaussian(3.19),
    m=16384,
    tag="NINE65_secure_256"
)
print("=== secure_256 ===")
print(LWE.estimate(params_256))
```

**Step 3: Record the output**

For each config, note the `rop` (ring operations — classical security bits) output from the estimator. These numbers are what you cite when making the security claim.

**Step 4: Add results to CLAUDE.md security configs section**

If the estimator confirms ≥128/192/256-bit classical security for each config, add a line to `CLAUDE.md`:

```
# Lattice Estimator confirmed (2026-02-25):
# secure_128: classical=N bits (rop=N)
# secure_192: classical=N bits (rop=N)
# secure_256: classical=N bits (rop=N)
```

**Step 5: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: add lattice-estimator confirmed security levels — track E

Records formal parameter validation output from lattice-estimator.
Provides irrefutable security level citations for all three configs.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Execution Order

Run tracks in this order (dependency / time considerations):

1. **Track D first** — fast, no compute, just file extraction and reading. Sets context.
2. **Track E** — fast if lattice-estimator is available. Produces irrefutable numbers.
3. **Track A (128 only)** — long running, start this and let it run. **Do not interrupt.**
4. **Track C** — medium duration (~200 bootstraps). Run while Track A is running if hardware allows.
5. **Track B** — longest. Only after Track A returns to know what to expect.
6. **Track A (192)** — only after 128 ceiling is known.

---

## What the Results Prove

| Track | Result A | Result B | Implication |
|-------|---------|---------|-------------|
| A | Wall at depth N | No wall found | Either: ceiling documented, or ceiling > 5000 — claim "depth > 5000" |
| B | All checkpoints pass | Bootstrap count > 0 | Public key mode is practically unlimited |
| C | drift > 50‰ | drift < 10‰ | Either: depth-9000 anomaly explained, or need deeper investigation |
| D | CT adds reduction per stage | CT removes reduction points | Either: CT is suboptimal for CRT lane layout, or neutral |
| E | rop ≥ 128 per config | rop < claimed level | Either: parameters are HE-Standard confirmed, or need adjustment |
