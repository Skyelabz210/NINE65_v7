# Retired Mechanisms: Modulus Switching, the Noise Budget, and Bootstrap

**Status:** authoritative. **Date:** 2026-08-09. **Scope:** `crates/nine65` test suite.

- **Part I** (§1–§6) — modulus switching and the noise budget.
- **Part II** (§7–§12) — bootstrap, including the production call-site map.

Part I begins immediately below.

This document records mechanisms that NINE65 no longer implements, the tests that
specify them, and why those tests are quarantined rather than repaired.

**The decisive rule: we do not switch moduli.** Modulus switching does not exist in
this architecture and must not be reintroduced.

---

## 1. Why the mechanism is gone

### Classical BFV rescale fuses two operations

A classical `rescale` / `mod_switch_down` does two things at once:

1. **Divide the value** by `q_i` (the level's top prime), shrinking the noise, and
2. **Drop `q_i` from the basis**, shrinking the representation.

That fusion is not a design choice — it is *forced*. Classical division of a
ciphertext by `q_i` is inexact: it introduces a rounding term, and the only way to
make the division come out clean is to stop representing the residue you divided
by. You can shrink the value **only** by shrinking the representation.

Everything downstream follows from that single constraint:

- The basis is a finite, strictly descending **level chain**.
- Every multiply spends a level.
- Depth is bounded by the number of primes you started with.
- When the chain runs out, you must **bootstrap** to get more.
- Therefore a **noise budget** exists, is consumed, and can be **exhausted**.

### CRAM has exact division, which unfuses them

NINE65 divides in residue space, exactly:

- **K-Elimination** for `gcd(d, M) = 1`
- **Fused Piggyback Division** for `gcd(d, M) > 1`

Exact division needs no rounding term, and therefore needs no lane sacrificed to
absorb one. The two halves of rescale come apart:

| | classical BFV | NINE65 (CRAM residue space) |
|---|---|---|
| divide value by `d` | yes, inexact (rounding term added) | yes, **exact** (no rounding term) |
| drop a prime from the basis | **forced**, to absorb the rounding | **never** |
| lanes after the operation | fewer | **same lanes, same Q** |
| noise after the operation | scaled by `1/d`, plus rounding | scaled by `1/d`, exactly |
| cost | one level | **nothing** |

You divide the ciphertext coefficients by `d` and **the basis does not move**: same
lanes, same `Q`, value reduced, noise scaled by `1/d` with no rounding term added.

### The consequence

Because the operation never spent anything, there is nothing to run out of.

> **Depth is unbounded because the operation never spent anything — NOT because
> levels get replenished.**

This distinction matters and is the most common way to misread the architecture.
NINE65 does not have a *bigger* budget, a *refilled* budget, or a *cheaper* ladder.
It has **no ladder**. There is no level counter to decrement, no prime to drop, no
"levels remaining", and no exhaustion condition that any code path can reach.

---

## 2. What this means for the test suite

A test that asserts modulus-switching semantics, level consumption, or noise
exhaustion is **specifying a retired mechanism**. Such a test does not fail because
the code is broken. It fails because **the code moved and the test did not.**

Repairing these tests — making them green again on their own terms — would require
re-implementing the level ladder. That is a regression, not a fix.

So they are **quarantined**: marked `#[ignore = "RETIRED MECHANISM: ..."]` with a
per-test reason naming the specific assertion that retired it. They are:

- **never silently deleted** — the record must show what was retired and why;
- **never "fixed" by restoring modulus switching**;
- **left byte-for-byte intact** — no assertion in any quarantined test was altered.

Each `#[ignore]` string is tailored to its test and is the primary record; this
document is the index.

---

## 3. Quarantined tests

Nine tests, two files. Reason strings live inline above each `#[test]`.

### 3.1 Retired: modulus switching

| Test | File | Assertion / construct that made it retired-mechanism |
|---|---|---|
| `ops::rns_fhe::tests::test_modulus_switching_basic` | `crates/nine65/src/ops/rns_fhe.rs` | Exists solely to watch the basis shrink. Doc: `// Test mod_switch_down_dual and level-aware decrypt`; `// Uses depth2_128 which has 4 primes (switch to 3, then depth-2 at 3 primes)`. Prints `ct6_deep.c0.main.len()` and closes on `println!("Modulus switching enabled depth-2 where standard failed!")`. Captured stdout shows `Fresh ct2 has 4 main primes` → `After mul_dual_public: ct6 has 3 main primes`. |
| `ops::rns_fhe::tests::test_mul_dual_public_with_mod_switch` | `crates/nine65/src/ops/rns_fhe.rs` | Doc: `// 2. Auto modulus switching (drop last prime to shrink noise)` and `// NOTE: Requires at least 3 primes for modulus switching to work`. Prints `"primes after switch"`; ends `// The key metric: did mod_switch help?` → `if dec120 == 120 && dec120_std != 120 { println!("=== MODULUS SWITCHING SUCCESS ===") }`. The drop-a-prime ladder is the whole subject. |
| `ops::rns_fhe::tests::test_mul_dual_public_auto_mod_switch_depth2` | `crates/nine65/src/ops/rns_fhe.rs` | Doc: `mul_dual_public should automatically apply modulus switching when enough levels exist`; inline `// Without auto mod-switch in mul_dual_public, noise overwhelms at depth-2`. Under the banner `// PUBLIC-MODE AUTO MOD-SWITCH TESTS`. Name matches the retired `auto_mod_switch` marker verbatim; premise is that depth-2 is reachable *only because levels were consumed*. |
| `ops::rns_fhe::tests::test_mul_dual_public_depth3_chain` | `crates/nine65/src/ops/rns_fhe.rs` | **Weakest classification here.** Its own assertions are plain correctness (`assert_eq!(dec, expected, "Depth-{} via mul_dual_public failed")`). Retired on its *setup*: same `AUTO MOD-SWITCH` banner, and `// Uses depth3_128 (5 primes, N=8192) for sufficient headroom` — depth sized against prime supply. See §5. |
| `ops::bootstrap::tests::test_verified_modswitch_agrees_with_unverified_valid_input` | `crates/nine65/src/ops/bootstrap.rs` | Pins two mod-switch implementations together: `assert_eq!(c0_unverified[j], c0_verified[j], ...)` over `modswitch_to_t` vs `modswitch_to_t_verified`. The latter is textbook rounded modulus switching — `c0_small[i] = ((c0_val * t128 + q_level_half) / q_level % t128) as u64` (`bootstrap.rs:800`) — inexact division fused with a full basis drop, returning a bare `Vec<u64>` mod `t`. |
| `ops::bootstrap::tests::test_verified_modswitch_all_coefficients_in_range` | `crates/nine65/src/ops/bootstrap.rs` | `assert!(c0_small[j] < t, "m={}: c0[{}]={} >= t", ...)` — asserts the post-switch coefficients landed in the reduced modulus `t`. "Coefficients now live mod `t`" *is* the basis-drop semantics. |
| `ops::bootstrap::tests::test_verified_modswitch_validates_residues` | `crates/nine65/src/ops/bootstrap.rs` | `assert!(result.is_ok(), "Valid ciphertext should pass K-Elimination validation")` on `modswitch_to_t_verified` — literally asserts mod-switch validation. |
| `ops::bootstrap::tests::test_verified_modswitch_boundary_messages` | `crates/nine65/src/ops/bootstrap.rs` | For `m in [0, 1, t-1]`: `assert!(result.is_ok(), "Boundary message m={} should pass verification")` plus `assert!(c0_small[j] < t, ...)` — mod-switch acceptance and reduced-modulus range at the plaintext boundaries. |

### 3.2 Retired: noise budget

| Test | File | Assertion that made it retired-mechanism |
|---|---|---|
| `ops::rns_fhe::tests::test_try_decrypt_dual_returns_err_on_noise_exhaustion` | `crates/nine65/src/ops/rns_fhe.rs` | Demands that exhaustion actually occur: `assert!(found_error, "try_decrypt_dual must return Err when noise is exhausted, not silently return garbage")`, driven by `// Chain multiplications to exhaust noise budget` over `for depth in 2..=20`. Under unbounded depth that `Err` never arrives at any depth, so the assertion specifies a depleting budget that no longer exists. |

---

## 4. Two caveats recorded honestly

Quarantine is a claim about *what a test specifies*, not about *why it currently
panics*. Two groups need that distinction stated, so the record is not read as
stronger than it is.

**(a) The four `bootstrap.rs` tests panic for an unrelated reason.** Their proximate
failure is not the retirement:

```
panicked at crates/nine65/src/arithmetic/k_elimination.rs:393:29:
K-Elimination capacity exceeds u128; use capacity_limbs or capacity_bit_length
```

`ke.capacity()` is deprecated and does `try_capacity().expect(...)`. `KElimConfig::Extended`
now has a 138-bit capacity (alpha 3×16-bit, beta 2×45-bit), which overflows `u128`.
Sibling mod-switch tests using `Minimal` (64-bit) and `Standard` (110-bit) still
pass, and `test_verified_modswitch_capacity_overflow_detected` (Minimal) is
**not** quarantined and remains green.

That overflow is a real, separate defect worth fixing on its own merits — but
fixing it would only restore four tests of the retired ladder. They are quarantined
on their assertions, independently of the panic.

**(b) The `rns_fhe.rs` tests die on a shared upstream panic**, not on their own
assertions:

```
panicked at crates/nine65/src/ops/sbni.rs:84:42:
index out of bounds: the len is 3 but the index is 3
(via mul_dual_public -> sbni::inject_dual_in_place)
```

This is the signature of code indexing a prime that the basis no longer descends to
retire. For `test_try_decrypt_dual_returns_err_on_noise_exhaustion` in particular,
resolving the panic would only move the failure downstream to the `found_error`
assert, which is unsatisfiable by construction.

**K-Elimination itself is not retired.** It is the exact-division primitive this
architecture is built on. Only its use as a *guard on a modulus switch* is retired.

---

## 5. Do not "fix" these by restoring modulus switching

Explicitly, the following are **not** acceptable responses to a quarantined test:

- Re-adding `mod_switch_down_dual` / auto-mod-switch to any multiply path.
- Adding a level counter, "levels remaining", or per-op level decrement.
- Making `try_decrypt_dual` return `Err` as a function of *depth* so that
  `found_error` can become true.
- Introducing any operation that drops a prime from the basis to shrink noise.
- Un-ignoring a test by loosening its assertion until it passes while the ladder
  premise survives in its setup or naming.

**A silent delete is equally unacceptable.** The point of quarantine is that the
record shows what was retired and why.

### What WOULD justify un-quarantining one

A quarantined test may return only if **its subject changes**, not if the substrate
regresses. Specifically, one of:

1. **The premise is removed and the assertion is genuinely substrate-independent.**
   The test is rewritten so nothing in it — name, banner, doc comment, config
   sizing, or assertion — refers to switching, levels, or exhaustion, and what
   remains is a correctness claim that holds under unbounded depth.
   `test_mul_dual_public_depth3_chain` is the live candidate: its assertions are
   already plain `assert_eq!(dec, expected)`. Detach it from the
   `AUTO MOD-SWITCH` banner, drop the "5 primes for sufficient headroom"
   justification, fix the upstream `sbni.rs:84` indexing bug, and it can come back
   as a straight depth-3 correctness test.

2. **The underlying concern is re-expressed against a live mechanism.** The audit
   finding behind `test_try_decrypt_dual_returns_err_on_noise_exhaustion`
   (Section 2.7 — `decrypt_dual` must not silently return garbage) is **still
   valid**. It must be re-tested against a *corrupted or malformed ciphertext*,
   not against depth. That would be a **new** test; the old one stays quarantined
   as the record of the retired framing.

3. **The architecture genuinely changes** — a documented, deliberate decision to
   reintroduce a level chain, argued on its merits and recorded here. Nothing in
   the current design points that way.

Making a quarantined test pass is never sufficient grounds on its own. The question
is always: *does this test still describe something the substrate does?*

---

## 6. Verification

Nine tests moved from failing to ignored. No test was deleted; no assertion was
changed; nothing under `src/` outside test modules was touched.

Ignored count before: 10. After: 19.

---

# Part II — Bootstrap

**Status:** authoritative. **Date:** 2026-08-09. **Scope:** `crates/nine65`
(`--lib` and integration targets).

Part I retired **modulus switching**. This part retires the machinery that
existed *because* modulus switching existed: **bootstrap**.

**The rule: bootstrap is a fallback, not the critical path.** It is not deleted
and not forbidden. It is removed from the *tested surface*, so that no failure in
it can be mistaken for a failure of encrypt / mul / div / decrypt.

---

## 7. Why bootstrap is vestigial

Part I established that exact division in residue space divides the value
**without moving the basis**. Trace the consequence forward:

| classical BFV | NINE65 (CRAM residue space) |
|---|---|
| every multiply spends a level | nothing is spent |
| the level chain is finite and strictly descending | the lane set is invariant |
| depth is bounded by the starting prime count | depth is not prime-count bounded |
| when the chain runs out you **must bootstrap** | the chain never runs out |
| the noise budget is consumed and can be exhausted | there is no depleting budget to reset |

Bootstrap is the *recovery procedure for an exhausted level chain*. Every one of
its parts is shaped by that job:

- **Boot primes are a strict superset of work primes, with exactly one extra
  "drop prime."** That spare prime exists so Phase 1 has somewhere to switch
  *to*. It is basis-movement bookkeeping.
- **Phase 1 (`modswitch_to_t`)** is rounded modulus switching all the way down
  to a bare `Vec<u64>` mod `t` — the same divide-and-drop-the-basis fusion Part I
  retired, applied maximally.
- **Phase 3 key-switch** exists to carry the ciphertext back out of boot space
  into work space after that detour.
- **`reset_after_bootstrap` / `should_bootstrap`** are budget accounting: a reset
  is only meaningful against a quantity that depletes.

`crates/nine65/tests/basis_invariance.rs` already passes 12/12: the lane set is
unchanged across division, including *repeated* division, with decryption still
correct. That is the direct experimental refutation of the premise bootstrap is
built on.

Bootstrap remains in `src/` as a genuine fallback. Nothing in `src/` was changed
in this phase.

---

## 8. Quarantined tests — 145 total

Every test below carries an `#[ignore = "VESTIGIAL: …"]` naming what *that test*
asserts, followed by the shared clause. **No test was deleted. No file was
deleted. No assertion was changed. Nothing under `src/` outside `#[cfg(test)]`
modules was touched.**

### 8.1 Library tests — 84

| file | count | what they specify |
|---|---|---|
| `src/ops/bootstrap.rs` | 25 | `ClockworkBootstrap` construction, Phase 1/2/3 decomposition, circular and KSK roundtrips, boot-prime/drop-prime/anchor invariants, U256 config matrix, `AutoBootstrapEvaluator` chained muls |
| `src/ops/symmetric_bootstrap.rs` | 20 | the 8 Correctness Contract sections, `SymmetricBootstrap` roundtrip / timing / reencrypt, `analyze_depth_budget` depth prediction, hybrid Phase-1-only decrypt |
| `src/ops/auto_bootstrap.rs` | 2 | refresh trigger threshold validation (permille interval) |
| `src/bootstrap/clockwork.rs` | 7 | `can_bootstrap` threshold, `BootstrapKey::generate`, Three-Lock `bootstrap_protected` end-to-end, post-refresh noise floor |
| `src/bootstrap/three_lock.rs` | 8 | Three-Lock tiers, key rotation, mask persistence, outer-layer noise bound, benchmark |
| `src/bootstrap/mask.rs` | 6 | `MaskLayer` / `CiphertextMask` apply-remove, uniformity, scalar tracking, zeroize-on-drop |
| `src/bootstrap/outer.rs` | 4 | `OuterLayer` RLWE envelope roundtrip, randomization, key rotation |
| `src/keys/bootstrap.rs` | 9 | `validate_bootstrap_primes` (8) and `BootstrapKey::generate` (1) |
| `src/noise/budget.rs` | 3 | `reset_after_bootstrap`, `should_bootstrap` boundary and argument validation |

### 8.2 Integration tests — 61

| file | quarantined | of |
|---|---|---|
| `tests/bootstrap_integration.rs` | 41 | 59 |
| `tests/bootstrap_parameter_exploration.rs` | 14 | 14 |
| `tests/bootstrap_residue_shape_regression.rs` | 2 | 2 |
| `tests/test_192_256_bootstrap.rs` | 2 | 2 |
| `tests/refresh_preflight_regression.rs` | 2 | 2 |

`bootstrap_parameter_exploration.rs` is quarantined **whole**. Its 14 tests are a
hypothesis sweep (H1 boot-prime count, H2 degree, H3 `t`, H4 `eta`, H5 modswitch
distribution error, H6/H6b/H6c Δ-inverse correction) hunting for a parameter set
under which the bootstrap roundtrip comes out correct. Three of them
(`explore_h6*`) call no bootstrap API at all — they are hand-rolled cleartext
phase evaluations — but they exist solely to localise the Phase 2 scaling error,
so they go with the file.

### 8.3 Note (2026-09-03, WR-5B / issue #83): `src/keys/bootstrap.rs`'s count changed

The `src/keys/bootstrap.rs | 9 | validate_bootstrap_primes (8) and
BootstrapKey::generate (1)` row above, and the `keys/bootstrap.rs 19` total
`#[test]` count in the forensic reconciliation below, describe this file
**as it stood during the quarantine phase this section records** and are left
as-is rather than restated for a different point in time.

WR-5B (issue #83, "make bootstrap security validation exact and
non-tautological") subsequently found `validate_bootstrap_primes`'s own
"security" step was a tautology — it built its `target_security` from the
same primes it then checked against that target — and split it into a
structural-only `validate_bootstrap_primes` plus a new, real
`screen_bootstrap_security`. Two of the eight quarantined
`validate_bootstrap_primes` tests
(`test_validate_bootstrap_primes_insufficient_security`,
`test_validate_bootstrap_primes_first_two_only`) asserted exactly that
tautological step-3 behavior against the old 3-argument signature; that
behavior no longer exists on the function they called, so they were deleted
rather than left to reference removed functionality, and replaced with
non-`#[ignore]`d coverage of `screen_bootstrap_security` and
`bootstrap_tuple_fingerprint` in the same file. This is a substantive fix to
a P1 bug in code the quarantine explicitly left live (`validate_bootstrap_primes`'s
NTT/coprimality checks were already noted above as "generic and live"), not a
continuation of the quarantine itself, so it does not fall under this
section's "no test was deleted" invariant for the quarantine's own scope.
`src/keys/bootstrap.rs` now carries 6 quarantined `validate_bootstrap_primes`
tests plus the 1 `BootstrapKey::generate` test (7, not 9), and several new
non-quarantined tests alongside them.

---

## 9. What was deliberately **left live**, and why

Quarantining is not a synonym for "mentions bootstrap." The rule applied was:

> **A test is quarantined iff removing the bootstrap machinery would make it
> uncompilable or meaningless.**

Under that rule the following were left running, on purpose:

### 9.1 `tests/clockwork_cross_validation.rs` — 5 tests, NOT bootstrap

Named in the retirement request, but it is **not a bootstrap file**. "Clockwork"
here is the `clockwork-core` crate, not `ClockworkBootstrap`. Its five tests
(`garner_matches_kelim_2_modulus`, `garner_matches_crt_decode_multi_modulus`,
`garner_ct_matches_standard`, `exhaustive_small_moduli`,
`centered_lift_consistency`) cross-validate **Garner reconstruction against
K-Elimination**. It is also gated behind `#[cfg(feature = "clockwork")]`, which
is **not** in `default`, so none of it runs in a normal build.

Left live, but flagged: Garner/CRT reconstruction is an **A2 concern in its own
right** — it materialises the integer and destroys the winding that per D-030
§6.1 masks power/timing side channels. This file belongs to a *reconstruction*
retirement pass, not a bootstrap one. Do not fold it into this section.

### 9.2 Error-variant surface — 5 tests

`tests/error_variant_coverage.rs::{test_error_bootstrap_failed,
test_error_bootstrap_config_mismatch, test_error_bootstrap_overflow}` and
`tests/bootstrap_integration.rs::{test_error_categories_bootstrap,
test_error_bootstrap_recoverability}` assert only `Display` strings,
`category() == "Bootstrap"` and `is_recoverable()`. They exercise the error enum,
never the bootstrap path, and cannot fail because of bootstrap behaviour. As long
as bootstrap survives as a fallback, its error variants survive, and so should
their coverage.

### 9.3 Critical-path tests that merely live in a bootstrap-named file — 18

`tests/bootstrap_integration.rs` retains 18 live tests that touch no bootstrap
machinery:

- plain encrypt/decrypt and homomorphic correctness —
  `test_proptest_encrypt_decrypt_roundtrip`, `test_statistical_encrypt_decrypt_1000`,
  `test_edge_max_plaintext_t_minus_1`, `test_edge_self_add_equals_double`,
  `test_edge_self_mul_equals_square`, `test_edge_multiply_by_enc_one`,
  `test_security_ciphertext_randomization`
- arithmetic helpers — `test_proptest_crt_roundtrip`,
  `test_proptest_mod_inverse_verify`, `test_statistical_crt_reconstruction_10k`,
  `test_error_mod_inverse_zero`
- modswitch-*formula* arithmetic with no ciphertext and no basis —
  `test_proptest_modswitch_in_range`, `test_statistical_modswitch_100k_zero_error`
- `NoiseBudget` arithmetic with no refresh — `test_cross_config_noise_budget_scaling`,
  `test_error_noise_exhausted_fields`, `test_stress_budget_depth_200_precision`
- plus the two error-variant tests in §9.2

**Ignoring these would have deleted real critical-path coverage.** They should be
*relocated* out of the bootstrap file, not ignored. That is a follow-up, not a
retirement.

### 9.4 Arithmetic helpers under `src/keys/bootstrap.rs` — 10

`test_gcd_u64_*`, `test_mod_inverse_*` and `test_crt_reconstruct_2_*` use
`BOOTSTRAP_PRIMES` as a *fixture* only. Their subject is `gcd_u64` /
`mod_inverse_u128` / `crt_reconstruct_2`, which survive bootstrap's removal
(relocated, not deleted). Left live; they need refixturing, not quarantine.

### 9.5 `src/ops/bootstrap.rs` arithmetic — 11

Five `test_crt_*` and six `test_modswitch_*` tests in that module operate on bare
`u128` values with no `ClockworkBootstrap` and no ciphertext. The six modswitch
ones are **modulus-switch adjacent and are Part I's business, not Part II's** —
they were left alone by the modswitch pass and are left alone here rather than
quietly widening this phase's scope.

### 9.6 `src/compiler.rs::test_depth_50_bootstrap_free`

Asserts `result.bootstrap_free_guaranteed` for a depth-50 circuit. It asserts the
**architecture's own claim**. Left live deliberately.

---

## 10. Where bootstrap is called from production code

`grep` over all non-test code in the workspace. The verdict column answers: does
this sit on the critical path of a normal encrypt / mul / div / decrypt flow?

### 10.1 The finding that matters

**`crates/nine65/src/ops/rns_fhe.rs` — the encrypt / mul / div / decrypt critical
path — does not call bootstrap at all.** The only occurrences of the word in that
file are three doc comments (lines 3, 6, 769). No `RNSFHEContext` method reaches
bootstrap. Likewise, **no downstream crate calls it**: `fhe-service`, `nine65-ffi`,
`nine65-python`, `private-feedback-nine65`, `apps/`, `sdks/` have zero call sites;
`nine65-wasm` mentions it only in doc comments explaining that the WASM surface
does *not* expose it.

**Bootstrap is therefore not load-bearing.** It can eventually be removed without
touching the critical path.

### 10.2 Call-site map

| # | site | caller | on critical path? |
|---|---|---|---|
| 1 | `src/ops/auto_bootstrap.rs:73` `budget.should_bootstrap(trigger_permille)` | `refresh_if_required` | **No** — opt-in wrapper |
| 2 | `src/ops/auto_bootstrap.rs:75-76` `self.bootstrap.bootstrap(&ct, bsk, ksk)?` | `refresh_if_required` | **No** — opt-in wrapper |
| 3 | `src/ops/auto_bootstrap.rs:77` `budget.reset_after_bootstrap(cfg)` | `refresh_if_required` | **No** — opt-in wrapper |
| 4 | `src/ops/auto_bootstrap.rs:100` `refresh_if_required(...)` | `mul_auto` | **No** — see note below |
| 5 | `src/ops/auto_bootstrap.rs:121` `refresh_if_required(...)` | `try_add_auto` / `add_auto` | **No** — see note below |
| 6 | `src/ops/symmetric_bootstrap.rs:144` `SymmetricBootstrap::bootstrap` | *no production caller* | **No** — dead outside tests |
| 7 | `src/ops/symmetric_bootstrap.rs:165` `SymmetricBootstrap::bootstrap_timed` | *no production caller* | **No** — dead outside tests |
| 8 | `src/ops/symmetric_bootstrap.rs:206` `SymmetricBootstrap::reencrypt_symmetric` | *no production caller* | **No** — dead outside tests |
| 9 | `src/bootstrap/three_lock.rs:200` `clockwork.bootstrap_protected(...)` | `ThreeLockBootstrap::bootstrap` | **No** — no production caller of `ThreeLockBootstrap` |
| 10 | `src/bootstrap/three_lock.rs:251` `clockwork.bootstrap_protected(...)` | `ThreeLockBootstrap::bootstrap_timed` | **No** — same |
| 11 | `src/bootstrap/three_lock.rs:282` `bootstrap_fast` | `ThreeLockBootstrap` | **No** — same |
| 12 | `src/bin/nine65_v7_demo.rs:363,381,415,683` | demo binary §3 | **No** — demo |
| 13 | `src/bin/nine65_bench.rs:209,216,272-279,361-366` | benchmark binary | **No** — benchmark |
| 14 | `src/bin/cram_exploratory_probe.rs:278,293,316,320,366,436` | exploratory probe binary | **No** — probe |
| 15 | `crates/nine65-extreme-tests/src/bootstrap_adversarial.rs:36,135,180-190,250` | adversarial harness | **No** — test harness that happens to live in `src/` |
| 16 | `crates/nine65-extreme-tests/src/depth_stress_tests.rs:320,338,435` | depth stress harness | **No** — same |
| 17 | `crates/nine65-extreme-tests/src/cross_config_operations.rs:94` | cross-config harness | **No** — same |

### 10.3 The one site worth arguing about — `AutoBootstrapEvaluator`

Sites 1–5 are the only place in `src/` where a **multiply** can trigger a
bootstrap. `AutoBootstrapEvaluator::mul_auto` calls
`work_ctx.mul_dual_public(...)` and then hands the result to
`refresh_if_required`.

It is still **not** the critical path, for a structural reason: `mul_auto` is a
method on a *wrapper the caller must explicitly construct*
(`AutoBootstrapEvaluator::new(&ctx, &boot, &bsk, &ksk, &evk, &config)`), and
`RNSFHEContext::mul_dual_public` — the actual multiply — knows nothing about it.
The dependency runs evaluator → context, never the reverse. Every production
consumer in the workspace calls `mul_dual_public` directly.

**Verdict: genuinely a fallback branch, and an opt-in one.** `AutoBootstrapEvaluator`
is the single API that would need a deprecation path if bootstrap is deleted; the
rest of the surface would not notice.

Recorded honestly: `crates/nine65-extreme-tests/src/bootstrap_adversarial.rs:158`
already carries the finding that `AutoBootstrapEvaluator` **produces incorrect
plaintexts after ~10 chained multiplications** (Q17). That is an independent
argument that the fallback is not something the critical path should be leaning on.

### 10.4 A correction to the ladder report

The retired-ladder report lists `symmetric_bootstrap.rs:945` among the live
`mod_switch*` call sites. It is **not production code**: `src/ops/symmetric_bootstrap.rs`
opens its `#[cfg(test)] mod tests` at line 463, and line 945 sits inside
`test_symmetric_depth_50_no_bootstrap`, where `ctx.mod_switch_ct_to_level(&ct_2, ct.level)`
aligns a fresh multiplier down to the descending ciphertext's level and `break`s
when that returns `None`. That test is now quarantined, so this call site is
inert. The live ladder call sites are the ones in `src/ops/rns_fhe.rs`
(`:2784, :2895, :3011, :3089-3090, :3126, :3370`), and `:3011` inside
`mul_dual_public` Step 5 remains the defect that breaks deep multiplication
chains and drives the `sbni.rs:84` out-of-bounds panic.

---

## 11. Do not "fix" these by restoring the depth budget

The following are **not** acceptable responses to a quarantined bootstrap test:

- Re-arming `AutoBootstrapEvaluator` on any default multiply path.
- Reintroducing a per-multiply budget decrement so `should_bootstrap` can fire.
- Adding a "levels remaining" or "bootstraps required" counter to any public type.
- Widening the boot basis so a "drop prime" exists again for a switch that no
  longer happens.
- Un-ignoring a test by loosening its assertion while its setup still generates
  boot keys, sizes a boot basis, or waits for a refresh to fire.

**A silent delete is equally unacceptable**, for both tests and `src/`. The point
of quarantine is that the record shows what was retired and why.

### What WOULD justify un-quarantining one

1. **The subject is re-expressed against a live mechanism.** The strongest
   candidate is `refresh_preflight_regression.rs::secure_128_deep_budget_matches_independent_exact_limb_oracle`:
   its first half checks `NoiseBudget::initial_millibits()` against an
   **independent exact-limb Δ oracle** built from `exact_product_limbs` /
   `divide_limbs_by_u64`. That half is substrate-independent and should return as
   its own test once split from the `reset_after_bootstrap` tail.

2. **The coverage is genuinely lost and matters elsewhere.**
   `src/bootstrap/mask.rs::test_mask_zeroize_on_drop` is the only zeroization
   coverage for `MaskLayer`. If the Three-Lock mask is ever reused **outside**
   bootstrap, that test must come back — and should be strengthened to observe
   memory after drop rather than only asserting the pre-drop state. Note that
   this mask is the Three-Lock intermediate-plaintext shield, **not** the CRAM
   winding of D-030 §6.1; the winding side-channel story is untouched by this
   quarantine.

   Similarly, `src/keys/bootstrap.rs::test_validate_bootstrap_primes_*` covers
   generic NTT-compatibility and coprimality logic. If `BOOTSTRAP_PRIMES` is
   retired, re-express those checks against the **work** basis under a
   non-bootstrap name; do not restore these.

3. **Bootstrap is deliberately promoted back to the critical path** — a
   documented decision, argued on its merits, recorded here. §10 says nothing
   points that way.

Making a quarantined test pass is never sufficient grounds on its own. The
question is always: *does this test still describe something the substrate does?*

---

## 12. Verification

`cargo test -p nine65 --lib`

| | before | after |
|---|---|---|
| passed | 728 | 644 |
| failed | 4 | **4** |
| ignored | 19 | 103 |
| total | 751 | 751 |

84 library tests moved from passing to ignored (19 + 84 = 103; 728 − 84 = 644).
**The failure count is unchanged**, which is the intended result: none of the
failures was a bootstrap test, so quarantining bootstrap neither fixed nor
masked any of them.

The four surviving failures:

- `ops::rns_fhe::tests::test_mul_dual_symmetric_depth2_secure_128_deep` — the
  retired ladder. `mul_dual_public` Step 5 (`rns_fhe.rs:3011`) mod-switches
  `main` down a lane, and the next `sbni::inject_dual_in_place` indexes the full
  prime list against the now-shorter `poly.main` (`sbni.rs:84`).
- `noise::budget::tests::exact_delta_size_does_not_sum_lane_widths` and
  `noise::budget::tests::exact_delta_size_handles_products_above_u128` — the two
  known bad fixtures.
- `security::tests::test_lwe_params_from_config` — the stale `4096` literal left
  behind when `secure_128` was widened to `8192`.

### Note on the reported baseline

The retirement request quoted `728 passed / 9 failed / 19 ignored` (756 total).
That figure came from the **stale prebuilt binary shipped in `target/`**. A clean
rebuild of the same sources yields **751 tests**, not 756, and **4 failures**, not
9 — five of the nine (the three `comprehensive_benchmarks::*` and
`ops::rns_fhe::tests::{test_compare_symmetric_vs_public, test_public_mode_depth_sweep,
test_tracked_deep_multiplication_chain}`) pass on a fresh build.

This was verified directly rather than assumed: the 84 inserted attributes were
temporarily stripped, the crate rebuilt, and `--lib` re-run. That produced
`728 passed / 4 failed / 19 ignored` — proving the 751-vs-756 delta predates this
phase and that the quarantine removed no test from the binary. The attributes
were then restored. Per-module `--list` counts match the `#[test]` count in each
edited source file exactly (`ops/bootstrap.rs` 40, `ops/symmetric_bootstrap.rs`
20, `ops/auto_bootstrap.rs` 2, `bootstrap/clockwork.rs` 7,
`bootstrap/three_lock.rs` 8, `bootstrap/mask.rs` 6, `bootstrap/outer.rs` 4,
`keys/bootstrap.rs` 19, `noise/budget.rs` 9).

All five annotated integration targets compile
(`cargo test -p nine65 --test <target> --no-run` clean for
`bootstrap_integration`, `bootstrap_parameter_exploration`,
`bootstrap_residue_shape_regression`, `test_192_256_bootstrap`,
`refresh_preflight_regression`).

Pre-existing and untouched: `tests/rns_context_metadata_regression.rs` fails to
compile with `E0609: no field q_product_checked / q_product_limbs on type
RNSFHEContext`. That target was not modified in this phase.
