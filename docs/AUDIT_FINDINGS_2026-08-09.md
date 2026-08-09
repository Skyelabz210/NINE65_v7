# NINE65_v7 — Audit Findings, 2026-08-09

Index and record for the residue-native audit pass. Detail lives in the
companion documents; this file is the summary, the provenance, and the open
list. Every claim below is labelled **PROVEN** (measured or read off executable
code), **REPORTED** (from a doc or prior artifact, not re-verified here), or
**OPEN**.

| Companion | Covers |
|---|---|
| `LADDER_REMOVAL.md` | modulus-switch removal, noise curve, exact-division measurements |
| `RETIRED_MECHANISMS.md` | governing policy for retiring a mechanism (Part I ladder, Part II bootstrap) |
| `RESIDUE_SPACE_AUDIT.md` | residue-space exit map, MANA gap, bootstrap quarantine, GSO addendum (§8) |
| `PERFORMANCE_POSITION.md` | benchmark records, comparability contract, batching blockers |

---

## 1. Defects found and fixed

### 1.1 Silent anchor-capacity wraparound at depth 2 — **PROVEN, FIXED**

`DualRNSContext::extract_k_rns_level` (`arithmetic/rns.rs:~1319`) selected how
many anchor primes to CRT-reconstruct `k` from via a three-tier heuristic keyed
on `level_main_primes.len()`. That heuristic was calibrated for the retired
modulus-switching ladder, where a shrinking main-prime count tracked shrinking
remaining depth. With the ladder gone the main-prime count is **constant** for a
given config, so the selection never adapted while `k` grew.

At `secure_128_deep` the tensor value reached 271 bits against a 4-anchor
capacity of 125 bits; `crt_reconstruct_u256` silently returned `k mod A4` — a
deterministic wraparound, no error raised, wrong plaintext.

Fix: reconstruct from the full canonical 5-anchor set unconditionally.
`test_mul_dual_symmetric_depth2_secure_128_deep` passes (independently re-run).

### 1.2 `e2·s²` winding leak — **PROVEN, FIXED**

`mul_dual_symmetric` (`ops/rns_fhe.rs:2769`) plus five siblings
(`mul_dual_symmetric_with_s2`, `mul_ntt_domain{,_with_s2}`,
`mul_coeff_domain{,_with_s2}`) folded `e2·s²` into `c0` with no winding reset.

`e0`/`e1`/`e2` leave the rescale canonical (`k == 0`, measured 0 of 8192
coefficients nonzero). `e2·s²` does not: its true integer product overshoots
`M_level` by ~12 bits, and `dual_poly_mul` runs independent NTTs per main and
per anchor prime, so the main lanes come back wrapped and the anchor lanes do
not. The emitted pair encodes a nonzero winding, which the next rescale then
faithfully divides — putting the surplus into the noise term.

Nothing is wrong mod Q, which is why depth 1 and 2 still decrypted. Measured
c0 winding 12 → 13 → 13 → 14 bits at depths 1-4 (**steady state, not
compounding**). Depth 3 failed on noise (105 bits against Δ = 103), not on
capacity — 0 of 8192 coefficients were over capacity.

Fix: `canonicalize_dual_anchor` on the combined result at all six sites.
Depth 3 now decrypts correctly (6561). Tensor winding 152 → 130 bits; margin
under dual capacity 6 → 27 bits. `mul_dual_public` was never affected — it
relinearizes *before* the rescale, so its output is canonical by construction.

**Depth 4 still fails**, on ordinary BFV noise budget (Δ = 103 bits, saturated).
That is a parameter limit, not this defect. **OPEN**.

---

## 2. Mechanisms confirmed nominal

Four mechanisms were found to be non-functional. In **every case the test suite
was green**, which is the finding that matters more than any individual one.

| Mechanism | Verdict | Evidence |
|---|---|---|
| SBNI | retired | hardcoded-constant entropy source; ±20 perturbation vanishes into a >100-bit rescale |
| GSO-FHE basin collapse | nominal | `NoiseEstimate::collapse()` zeroes a counter; `GSOSwarm::collapse()` mixes its own `shadow` field; real ciphertext untouched. Delete the branch → byte-identical output. Two adversarial verifiers failed to refute. Present unchanged in 6 repo generations. |
| AHOP attractor reduction | nominal (ancestor of the above) | `apply_attractor_reduction()` multiplies a `noise_bits` counter by 0.8/0.9/0.95; never touches `c0`/`c1` |
| `div_div_div_chimera` | nominal | `noise_bound: 0` is a **literal** (`div_div_div_chimera.rs:166`); the "proof" checks it against itself. Reimplemented independently: `42 × 13` → 1,515,464,045 (want 546) |

**PROVEN.** Genealogy across nine prior repos found the pattern is *inherited*,
not independently re-derived — `fhe_ahop.rs` (tagged `G6-01`) states the seed
idea, and steps 1, 2 and 4 of it were carried forward faithfully while step 3
("Noise = distance from attractor") was never built. See `RESIDUE_SPACE_AUDIT.md`
§8.2.

---

## 3. The architectural gap: division is implemented and not called

**PROVEN.** This is the headline structural finding.

`CRAM_INTEGRATION_CONTRACT.md` §3 is normative:

> NTT lanes remain CLASS-F. **K-Elimination anchors**, integrity lanes, and
> compatible base-extension support **are CLASS-R.**

The FHE anchor is five CLASS-F NTT-friendly primes (`p ≡ 1 mod 2N`) and is fed
through `anchor.ntt_engines` — CLASS-F treatment for a CLASS-R job. Because
CLASS-F primes are scarce, capacity froze at five primes / 157 bits, which is
the proximate cause of §1.1. `canonical_anchor_primes_for_n` **ignores its `n`
argument**.

Meanwhile Fused Piggyback Division is already built and tested:

- `cram_rescale_by_scalar_fpd` — `exact_transcendentals/src/cram_ct.rs:1461`
- `fpd_one_coefficient` — `:1390`; `wrap_with_fpd_aux` — `:1443`
- `select_aux_for_fpd` — `chimera.rs:352`
- 10 FPD tests incl. divide-by-6, divide-by-30, negative divisors, 4 rejection cases
- `nine65` depends on it **by default**: `default = ["exact_transcendentals_backend"]`

And the FHE rescale never calls it: **zero** occurrences of
`piggyback|aux_lane|auxiliary` in `ops/rns_fhe.rs` or `arithmetic/rns.rs`, and
no `gcd` dispatcher. BFV rescale divides by Δ = Q/t, which shares factors with
the main basis, so by the documented rule (`gcd(b,M) > 1 → FPD`) it belongs on
the FPD path.

Critically, FPD **fails closed** where the hand-rolled anchor wraps silently:

> The fusion product over S8's good lanes plus the aux primes must exceed
> `2 * quotient_bound`; otherwise the lane reports `BoundInsufficient`.

Defect §1.1 is structurally impossible on that path.

Note also that FPD's auxiliary lane is **ephemeral** — "piggybacked for the
duration of the division operation… not a permanent basis extension" — which
removes the need for a permanent NTT'd parallel anchor entirely.

---

## 4. The formal layer already states the missing check

**PROVEN.** `Skyelabz210/k-elimination-lean4` (Lean 4.27.0-rc1 + Mathlib,
**zero `sorry`**, ~30 theorems, plus a Coq development):

```lean
theorem kElimination_core (X M A : ℕ) (_hM : 0 < M) (hRange : X < M * A) :
    let vM := X % M; let k := X / M
    k < A ∧ X % A = (vM + k * M) % A

def range_overflow (M A X : ℕ) : Prop := X ≥ M * A
```

`hRange` is a hypothesis. Defect §1.1 was precisely its violation:

| anchors | M·A | X (271 bits) | `hRange` |
|---|---|---|---|
| A4 (125 b) | 244 bits | 271 > 244 | **violated** |
| A5 (159 b) | 278 bits | 271 < 278 | satisfied |

The proof was never wrong; the implementation ran outside its stated domain and
did not check. The measured 6-bit pre-fix margin is exactly `278 − 271`.

**Scope caveat:** the Lean development is over ℕ for a single `(M, A)` pair. It
does not cover the multi-anchor CRT subset selection the FHE code performs, nor
the polynomial/negacyclic setting. It is a correct proof of the primitive, not
of `k_elim_rescale_dual`. Bridging them is where a runtime `X < M·A` assertion
belongs. **OPEN.**

---

## 5. Test suite state — **PROVEN** (measured 2026-08-09)

| suite | result |
|---|---|
| `cargo test -p nine65 --lib` | 648 passed / 3 failed / 103 ignored (128.5s) |
| `--test basis_invariance` | 12 / 12 |
| `--test depth_and_noise` | 6 / 6 (364s) |
| `cargo check -p nine65 --tests` | 3 targets fail to compile |

**All 3 failures are stale expectations, not defects:**

- `security::tests::test_lwe_params_from_config` (`security/mod.rs:315`) asserts
  `n == 4096`; `secure_configs.rs:178` has passed 8192 since `b63d5d1` (Jul 13).
- `noise::budget::tests::exact_delta_size_does_not_sum_lane_widths`
  (`budget.rs:350`) — fixture primes `[5,5]`, `t=2` make the wrong and right
  formulas both evaluate to 4, so `assert_ne!` fires against correct code.
- `noise::budget::tests::exact_delta_size_handles_products_above_u128`
  (`budget.rs:354`) — includes prime `2` with `t=3`, violating the documented
  precondition at `budget.rs:126`; panics before reaching its own assertion.

**Non-compiling targets:**

- `rns_context_metadata_regression.rs`, `dual_rns_context_metadata_regression.rs`
  — assert on fields (`q_product_checked`, `q_product_limbs`, six
  `*_product_{checked,limbs,bit_length}`) with **zero occurrences in `src`, at
  HEAD or in the worktree**. Added by `00ef97e` against an exact-limbs metadata
  refactor that never landed. These have never compiled and never run.
- `full_system_exercise.rs` — **two-line defect**. `light_insecure`
  (`params/mod.rs:102`,`:107`) and `he_standard_128_insecure` (`:311`,`:316`)
  each carry **two `#[cfg]` attributes, which AND together**. The narrower one
  omits `debug_assertions`. For an integration test the lib is a normal
  dependency so `cfg(test)` is false, the narrow cfg fails, and the function
  vanishes. Deleting the redundant narrow line fixes all three `E0599`s.

`ci.yml:187` runs `cargo test --workspace`, so these targets gate CI — **CI is
red today**, and has been. Only 4 soft gates exist repo-wide, all benign.

**Ignored census (103):** 84 `VESTIGIAL:` bootstrap quarantine, 9 `RETIRED:`,
8 statistical-timing (`security/ct_verification.rs`), 2 in `k_elimination.rs`.
`src` holds 884 `#[test]`; the ~130 beyond 648+3+103 are feature-gated
(`serde`, `clockwork`, `shadow-entropy`, `slow_tests`), not missing.
`exact_transcendentals`: 445 tests, zero ignored.

### 5.1 The green suite detected none of §2

Assertion strength, not count, is the problem:

- `depth_and_noise.rs` asserted only `max_correct_depth >= 1` — green while
  depth 2 was wrong.
- `gso_fhe.rs` `test_gso_mul_public_depth2` prints "WARN: Depth-2 public mode
  still failing" via `println!` with **no assertion**.
- `gso_fhe.rs:653` allows `error <= 2` on an exact-arithmetic claim.
- `cram_pde.rs:569` `dkam_subcriticality` asserts the precondition
  (`degree() < 3`) and never the conclusion — and `deep_winding` two tests
  below asserts 62-bit growth under a passing gate.

### 5.2 The depth-50 claim is backed by a loop counter — **PROVEN, RUN-CONFIRMED**

This is the most consequential test finding and it needs stating plainly.

`benchmark_symmetric_max_depth_secure_128` (`gso_fhe.rs:862`) and
`_secure_192` (`:890`) have **zero assertions**. They print:

```rust
println!("SECURE_128 MAX DEPTH: {} multiplicative levels", depth);
```

where `depth` is assigned `depth = d;` inside `for d in 1..=max_test_depth`
with `max_test_depth = 50`. It is **the loop variable**. Neither test ever
decrypts. Re-running `:890` reports "SECURE_192 MAX DEPTH: 50 multiplicative
levels" after 111s of multiplications whose results were never checked. This is
the provenance of `CLAUDE.md:141-142` ("Depth 50 in 6.29s / 10.10s").

`benchmark_symmetric_max_depth` (`:801`) does decrypt every 10 depths — but
only `println!`s the value with no comparison, and its lone assertion is
`assert!(depth >= 10)`, again on the loop variable.

The one test in that group that *does* compute values, `test_gso_deep_symmetric`
(`:728`), was run: on `light_rns_exact_insecure` (t=65537, base 2) the chain
must be `4, 16, 256, 65536, 1, 1, …`. Actual: `depth 1 = 4`, then `14172,
52203, 33391, 16925, … 10924`. **Every depth from 2 onward decrypts to
garbage, and the test passes** on `assert!(ct.depth() >= 10)`. It also prints
`noise=0/~2^41 (0.0%)` throughout — the GSO tracker reports zero noise on a
ciphertext that has lost its plaintext, consistent with §2.

**Scope, stated precisely:** these are the *GSO wrapper* path
(`GSOFHEContext::mul_symmetric`), and `test_gso_deep_symmetric` uses a toy
insecure config. This does **not** establish that production symmetric depth is
1 — `depth_and_noise.rs` holds `DEPTH_REGRESSION_FLOOR = 32` with real
per-sample correctness assertions and passes. What it does establish is that
**the depth-50 figure specifically has never been correctness-checked**, and the
number quoted in `CLAUDE.md` comes from a counter. The claim may well hold; it
needs a test that decrypts and compares. **OPEN.**

### 5.3 Other headline claims with non-gating tests — **PROVEN**

| claim | test | what it actually asserts |
|---|---|---|
| K-Elimination exactness | `formal_spec_linkage.rs:115` `test_k_elimination_exact_for_secure_128` | `anchor.primes.len() >= 5`. Counts primes; never calls `extract_k`, never reconstructs, never compares. |
| A1 zero-float | `security_estimator.rs:552` `test_no_floating_point` | three estimator outputs are `> 0`. Could not detect an `f64` added on the next line. **63 `f64`/`f32` occurrences under `crates/nine65/src`, 81 under `exact_transcendentals/src`**; `#![deny(clippy::float_arithmetic)]` is present in `cram-core`, `clockwork-core`, `math_utils`, `fhe-service`, `private-feedback-*` — **not** in `nine65` or `exact_transcendentals`. |
| constant-time | `security/ct_verification.rs:36` | `T_TEST_THRESHOLD = 100.0` while the same file's docstring states `t > 5` indicates a leak — 20× loose. All **8** timing tests carry `#[ignore]` (lines 208, 245, 308, 345, 382, 423, 463, 530), so none run by default. |
| exact transcendentals | `binary_splitting.rs:604+`, `agm.rs:492+`, `cordic.rs:726+`, `continued_fraction.rs:411` | float-epsilon tolerances (`< 0.1`, `< 0.01`) in a crate whose premise is exactness. An error of 0.09 passes. |
| K-Elim capacity near u128 max | `k_elimination_extremes.rs:12` | zero assertions; both `Ok` and `Err` explicitly accepted — and both test primes are **even**, so the constructor rejects on coprimality and the `beta_cap` overflow path under test is never reached. |

**Meta-finding:** every module in `crates/nine65-extreme-tests/` sits behind
`#[cfg(all(test, feature = "extreme-tests"))]` with the feature off by default.
`cargo test -p nine65-extreme-tests --lib` reports **`running 0 tests`**. That
78-test harness gates nothing in a default workspace run.

Assert-per-test ratios, worst first: `comprehensive_benchmarks.rs` 0.00 (5 tests
/ 0 assertions), `bootstrap_parameter_exploration.rs` 0.29, `entropy_extremes.rs`
0.33, `ema_numerical_stability.rs` 0.50, `depth_stress_tests.rs` 0.80,
`gso_fhe.rs` 0.94 — against `basis_invariance.rs` at **7.75**.

### 5.4 The repo already contains the antidote

**Strong, verified:**

- **`tests/basis_invariance.rs`** — 12 tests / 93 assertions. The negative
  control is real: `mod_switch_ladder_is_the_negative_of_this_invariant` (:829)
  applies the same assertions to the retired `mod_switch_ct_down` and asserts
  they **fail**. `:363` asserts residue equality on every lane *and* that the
  decryption margin is **identical** (`assert_eq!(margin_before, margin_after,
  "rounding margin moved — a budget was spent")`) — the correct discriminator,
  not a tolerance. `:761` closes the cosmetic-invariant loophole explicitly.
- **`tests/residue_space_ciphertext.rs`** — 9 tests / 51 assertions. Carries an
  *anti*-control (`:720`, `assert_ne!`, "assertion — do not delete it"), lane
  permutation equivariance probes (`:860`, `:903`), and anti-vacuity guards
  written into the assert messages ("otherwise basis invariance is vacuous").
- **`exact_transcendentals/tests/a2_residue_native.rs`** — sweeps all **30,030**
  values and guards against the sweep silently shrinking (`assert_eq!(checked,
  30_030, "must sweep the whole corridor, not a sample")`). The lane-order
  permutation probe genuinely separates a Garner cascade from independent reads.
- **`cram-core/tests/workload_scales.rs`** — asserts the architecture counters
  (`internal_projections`, `crt_reconstructions`, `scalar_materializations`,
  `garner_calls`, `mixed_radix_calls`) are **exactly 0**. Posture as exact
  equality, not threshold.
- **`tests/audit_regressions.rs:36`** — does what `test_no_floating_point` only
  claims to: `include_str!`s the source and asserts forbidden tokens absent.
  **This is the pattern the workspace-wide A1 claim needs.**
- **`tests/depth_and_noise.rs:628`** — the one depth test with a real floor
  (`DEPTH_REGRESSION_FLOOR = 32`) plus per-sample `assert!(s.correct, "depth {}
  counted but decrypted wrong")`. The `>= 1` sites at `:668`/`:707` should read
  from this same constant.

Every Tier-1 and Tier-2 weakness above is fixable by copying one of these files'
three techniques: **full-domain sweep with an anti-shrink guard; a negative or
permutation control that asserts the property fails where it should; exact
equality on the discriminating quantity** (residues, margins, counters-at-zero)
rather than a tolerance.

Incidentally: `test_mul_dual_symmetric_depth2_secure_128_deep` (`rns_fhe.rs:10568`)
asserts exact equality at both depths and now **passes** — the note in
`depth2_isolation.rs:3` calling it "currently failing" is stale.

---

## 6. Open items, ranked

1. **Assert `hRange` (`X < M·A`) at the rescale.** Converts the entire §1.1
   class from silent-wrong-plaintext into a loud refusal. Highest value per
   line changed.
2. **Route the FHE rescale through FPD** (§3) — gets the fail-closed bound and
   the ephemeral aux lane, and removes the frozen 5-prime anchor.
3. **Fix the doubled `#[cfg]`** (2 lines) and decide the fate of the two
   never-compiled metadata regression targets (delete, or build the API they
   assert). Unblocks CI.
4. **Correct the 3 stale test expectations** (§5) — none require code changes.
5. **Strengthen vacuous assertions** (§5.1), starting with anything gating
   K-Elimination exactness or basis invariance.
6. Depth 4 noise budget (§1.2) — parameter work, not a defect.
7. MANA remains disconnected from the default build; `accelerated.rs` is typed
   against the legacy single-modulus `RNSPolynomial`, not `DualRNSCiphertext`
   (`RESIDUE_SPACE_AUDIT.md` §1).
8. `nine65_vs_seal_comparison` bench hangs permanently on a linear-scan
   `find_primitive_root` (`arithmetic/cyclotomic_phase.rs:31`), and contains
   zero SEAL calls.

---

## 7. One line

Two real defects fixed and independently verified; four mechanisms confirmed
nominal with a green suite throughout; and the structural finding underneath all
of it — the exact-division machinery this substrate is built on is implemented,
tested, shipping as a default dependency, and **not called by the FHE path**,
which reimplements it with a permanent CLASS-F anchor that the project's own
contract, its own FPD module, and its own Lean theorem each independently say it
should not have.
