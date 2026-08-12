# NINE65_v7 — `mul_dual_public` Depth-1 Root Cause, 2026-08-12

Synthesis of four independent investigation reports (A–D) into the public-key
multiplicative-depth cap first recorded as an open item in `7a2fcce`
("Public-relin depth-1 anomaly kept as a separate recorded measurement —
under investigation, not expected behavior"). This document is diagnostic
only. **No production code was changed to produce it or by it**, and none of
the four source investigations edited a production file — each used either
read-only static analysis, ran pre-existing unmodified tests, or added and
then deleted a scratch test file (confirmed via `git status --porcelain` in
each case). HEAD at time of writing: `0c99e7c`.

Every claim below carries the label **CORROBORATED** (independently
re-checked against the repo while writing this document — see the sparse
verification notes inline), **REPORTED** (taken from one of the four source
reports and not independently re-run here), or **UNRESOLVED** (the four
reports do not agree, or do not have the evidence to settle it).

---

## Executive Summary

**Root cause, established with high confidence:** `extract_digit_dual`
(`crates/nine65/src/ops/rns_fhe.rs:3165–3239`) — the per-gadget-digit
K-Elimination call inside `relinearize_dual`, reachable only from
`mul_dual_public` — reconstructs each coefficient's winding number `k` from
`extract_k_rns_level` and uses it **raw and unsigned**:

```rust
let k = self.dual_rns.extract_k_rns_level(v_m, &anchor_residues, level_primes);
let exact = v_m.add(k.mul_low(m_product_level));   // rns_fhe.rs:3202–3207, no sign step
```

The one other production call site that consumes the identical function with
identical bound arguments, `k_elim_rescale_dual` (`rns_fhe.rs:3358–3362`) —
the rescale shared by *every* multiply path, including the symmetric path
that is independently proven correct past depth 250 — converts that same raw
value to signed/centered form first:

```rust
let k_u = self.dual_rns.extract_k_rns_level(v_m, &anchor_residues, level_primes);
let k_signed = SignedK256::from_unsigned(k_u, a_n_product);   // rns_fhe.rs:3362
```

`extract_digit_dual` skips this conversion despite its own comment two lines
above promising "centered representation for correct digit extraction of
negative values" (`rns_fhe.rs:3169–3171`). When a coefficient's true winding
is negative — which Report A's corroborating in-repo diagnostic
(`diag_depth2_k_capacity_probe_secure_128_deep`) measured as common and large
(up to 128–130 bits) at depth 2 — `extract_k_rns_level` correctly returns the
large canonical-unsigned CRT residue, and `extract_digit_dual` adds that
residue times `m_product_level` straight into the "exact" value it digit-shifts,
producing a wrong digit for that coefficient on every affected gadget term.
That wrong digit is summed into `relin_c0`/`relin_c1` across all `num_digits`
gadget terms inside `relinearize_dual` (`rns_fhe.rs:3106–3157`), corrupting
the ciphertext returned by `mul_dual_public`.

This was **directly re-verified while writing this document**: lines
3202–3207 and 3358–3362 of `rns_fhe.rs` at HEAD (`0c99e7c`) read exactly as
Report A transcribed them — **CORROBORATED**, not merely reported.

**What is independently confirmed by all four reports, and rules out the
alternative hypotheses that motivated this investigation:**

- **Not a level/eval-key bookkeeping bug** (Report B). The public eval key
  and every ciphertext are permanently pinned to the full RNS level
  (`config.primes.len()`) by construction — `generate_eval_key_dual_with_base`
  can only ever build a full-level key, `encrypt_dual` only ever emits a
  full-level ciphertext, and rescale preserves level exactly. Report B's own
  runtime probe measured `evk_level == poly_level` (3 == 3) at the exact
  relinearization call site at both depth 1 (correct) *and* depth 2 (wrong),
  which is a direct empirical rule-out, not an inference from the static
  read alone.
- **Not a Div3/Fused-Piggyback-Division routing bug** (Report C). The FHE
  rescale divisor path (`k_elim_rescale_dual` → `round_div_signed_mod_u256` →
  `round_div_u256_small`) has zero references to `chimera_division`,
  `cram_ct`, or `select_division_lane` anywhere in `rns_fhe.rs` or
  `arithmetic/rns.rs`; and even under the counterfactual where it were wired
  in, `gcd(t, M_level) = 1` for every shipping config (verified by direct
  computation on the literal primes in `secure_configs.rs`), so FPD/lane 3
  would never be selected as primary even if reachable. This is a true,
  separate observation about `exact_transcendentals::cram_ct` being an
  unrelated, feature-gated, structurally disconnected subsystem, orthogonal
  to this defect.
- **Not a regression, and not previously attempted** (Report D). `git log -p
  5b34a04..HEAD -- rns_fhe.rs | grep -E
  'relinearize_dual|extract_digit_dual|generate_eval_key_dual|mod_switch_eval_key_to_level'`
  returns zero matches across all 44 commits in range (re-run while writing
  this document — **CORROBORATED**, identical output). `5b34a04` fixed two
  unrelated depth-2/3 defects in the *symmetric* path and states explicitly
  "`mul_dual_public` was never affected." `7a2fcce` re-confirmed the anomaly
  as still open the same day this report was commissioned. No commit between
  those two points, or since, has touched any of the four functions
  implicated here.

**One point remains genuinely open and this document does not paper over
it** (see "Unresolved tension" below): Report A characterizes the failure as
a *deterministic sign-handling defect* that injects a discrete, large,
wrong-integer corruption per affected coefficient — explicitly **not**
ordinary noise-budget exhaustion (a depth-2 run showed a large *positive*
ground-truth decryption margin on a wrong plaintext). Report B/D describe the
same call site's contribution in the vocabulary of "relinearization noise"
growth, correlated with the codebase's own bit-noise estimator (36.322 →
64.959 bits across the two public multiplies) and with the observation that
shrinking the eval key's `decomp_base` (more, smaller gadget digits)
measurably pushes the correctness horizon from depth 1 out to depth 4+. These
are not necessarily in conflict — a systematic per-digit corruption term is
exactly the kind of thing an amplitude-only noise estimator would report as
"more noise" without distinguishing it from genuine random error, and smaller
digits from a smaller `decomp_base` would also be less likely to have their
true signed `k` exceed the sign-ambiguous threshold — but **no report tested
this reconciliation directly**, and no report applied Report A's identified
fix and re-ran the depth-2 case to confirm it resolves the failure. That
experiment is the correct next diagnostic step before Phase 1 work begins,
and is called out explicitly in the Phase 1 recommendation below.

**Verdict: ONE definitive root cause, at the file:line granularity requested,
with independently corroborated evidence from three of the four
investigation angles and no report contradicting it.** The fourth angle
(noise-vs-deterministic-bug framing) is a characterization gap, not a
competing causal claim — no report proposes a different mechanism than
"`extract_digit_dual`'s independent, per-gadget-digit K-Elimination call,
reachable only from `mul_dual_public`'s relinearization." That structural
finding is unanimous across all four reports.

---

## 1. Report A — `relinearize_dual` / `extract_digit_dual` tracer

**Claim:** `extract_digit_dual` omits the `SignedK256::from_unsigned` sign
correction that its sibling call site, `k_elim_rescale_dual`, applies to the
identical `extract_k_rns_level` output — producing a silently wrong
ciphertext (failure mode (c): no panic, no `Err`, wrong plaintext) at depth 2
of `mul_dual_public`.

### Evidence (file:line preserved from source report)

- `crates/nine65/src/ops/rns_fhe.rs:3202–3207` (`extract_digit_dual`) — `k`
  from `extract_k_rns_level` used raw/unsigned, no sign correction, directly
  before digit-shift extraction at lines 3211–3224. **CORROBORATED** by direct
  re-read at HEAD.
- `crates/nine65/src/ops/rns_fhe.rs:3358–3362` (`k_elim_rescale_dual`) —
  `k_signed = SignedK256::from_unsigned(k_u, a_n_product)`; all downstream
  arithmetic operates on the signed/centered magnitude. **CORROBORATED**.
- `crates/nine65/src/arithmetic/rns.rs:1553–1658` (`extract_k_rns_level`) —
  identical bound/capacity arguments at both call sites (same `level_primes`
  slice, same anchor context, same `k_reconstruction_anchor_count()`); the
  divergence is entirely in what each caller does with `k` afterward, not in
  `extract_k_rns_level` itself.
- Scratch test `scratch_probe_depth2_public_squaring` (secure_128, m0=3,
  file created, run, then deleted; `git status --porcelain` confirmed clean):
  depth 1 `mul_dual_public(ct1,ct1)` → correct (9), Ok, no panic; depth 2
  `mul_dual_public(ct_d1,ct_d1)` → Ok, no panic, decoded 65471 vs expected 81.
  Both calls wrapped in `std::panic::catch_unwind`; neither panicked, neither
  returned `Err`.
- Scratch test `scratch_probe_depth2_public_times_one`: depth-2 margin still
  large and positive (~2^70 bits, against a per-config noise budget of
  72.260 bits) — i.e., the codebase's own noise measure reports **high
  confidence in a wrong plaintext**, not a value that merely crossed a
  threshold.
- Scratch test `scratch_probe_symmetric_then_public_depth2` (isolation): a
  depth-1 ciphertext produced entirely through the symmetric path (which
  never touches `extract_digit_dual`) is correct (9); the *first-ever* call
  to `mul_dual_public`/`extract_digit_dual` in that chain, applied to that
  clean input, still produces a confidently-wrong result (41 vs 81). This
  isolates the defect to `extract_digit_dual`'s handling of depth-2-magnitude
  input, independent of which path produced that input or of any
  accumulated-noise history.
- Existing, unmodified unit test `diag_depth2_k_capacity_probe_secure_128_deep`
  (`crates/nine65/src/ops/rns_fhe.rs:10637`): measures true signed `k`
  magnitude of the depth-2 tensor term at up to 130 bits, confirms
  `k_elim_rescale_dual`'s own k-reconstruction has 0/8192 mismatches (the
  shared function and the signed-conversion caller are both correct), and
  confirms the symmetric path decrypts correctly (81) at depth 2 in the same
  run — isolating the defect to the caller that skips the conversion.
- `grep -n "SignedK256::from_unsigned" crates/nine65/src/ops/rns_fhe.rs` —
  only production call sites are line 3362 (`k_elim_rescale_dual`) and an
  internal diagnostic probe (~line 10864); `extract_digit_dual`
  (3165–3240) has zero occurrences.

### Assessment

Directly corroborated at two of the report's central citations while writing
this document. The isolation experiment (depth-1 via symmetric path, then a
single public multiply) is the strongest evidence in the whole set: it
removes "two chained public multiplies accumulate noise" as an explanation
entirely, since the defect reproduces on the *first-ever* invocation of
`extract_digit_dual` in the chain.

---

## 2. Report B — eval-key level/decomposition tracer

**Claim:** No level or decomposition-base mismatch exists between the public
eval key and the ciphertext at any depth, including depth 2. The depth-2
failure is not a bookkeeping defect in `relinearize_dual`'s level-guard
branch.

### Evidence (file:line preserved from source report)

- `rns_fhe.rs:3059` — `eval_key_level(evk)` reads `main.len()` off the eval
  key, fixed at generation, never recomputed per-ciphertext.
- `rns_fhe.rs:1944–1945` — `num_digits` (hence eval-key level) derives from
  `self.q_bits`, a per-context constant, not from any ciphertext's current
  level; `generate_eval_key_dual_with_base` builds every `rlk` digit from
  `self.config.primes.iter()` directly (~1960–2048), so the eval key cannot
  be produced at a partial level in the first place.
- `rns_fhe.rs:2234` and `:2372` — `encrypt_dual`/`encrypt_dual_with_rng` set
  `ct.level = self.config.primes.len()` (full) on every fresh ciphertext.
- `rns_fhe.rs:2987` and `:2989–3003` — `mul_dual_public` sets `level =
  c0_new.main.len()`; the retired-Step-5 comment documents no lane is ever
  dropped after rescale (K-Elimination/Div3 divides the value, not the
  basis), so `ct.level` is invariant across the whole chain.
- `rns_fhe.rs:3316–3399` (`k_elim_rescale_dual`) — `result_main` allocated
  with `vec![...; ct_level]`; rescale preserves level exactly.
  `should_two_stage_rescale` (line 3433) hard-returns `false`, so the
  two-stage path is dead code too.
- `rns_fhe.rs:3106–3137` / `:3066–3093` — the level-mismatch/mod-switch
  branch in `relinearize_dual` (guarded by `mod_switch_eval_key_to_level`) is
  real code but provably unreached by `mul_dual_public`'s own call pattern,
  since evk level and poly level are always equal by construction.
- Scratch test `scratch_depth1_probe_lvlchk_9k3z7q` (secure_128, seed 1234;
  created, run, deleted, `git status --porcelain` clean): live probe of
  `relinearize_dual`'s own level check from outside the crate. Captured
  output shows `EQUAL? true` at both the depth-1 relin site (correct decode,
  9) *and* the depth-2 relin site (wrong decode, 100 vs 81) — level equality
  holds at exactly the point the corruption happens, which is a direct
  empirical rule-out of the level-mismatch hypothesis.
- Pre-existing tests in `residue_space_ciphertext.rs`, rerun (not authored):
  "secure_128 depth 1: correct 4/4 ... depth 2: correct 0/4" with lane count
  constant at 3 through depth 5; separately, shrinking the public eval key's
  decomposition base from 2^16 to 2^10 (`generate_keys_dual_full_with_base`)
  extends the correctness horizon from ~depth 1 to depth 4 (6/6) — a
  decomposition-base/noise-magnitude effect, not a level-index effect.
- `depth_and_noise.rs:75–93` header (pre-existing) — "Lane count was 3
  main / 5 anchor / level 3 at every one of those depths, in every chain."

### Assessment

The static argument (eval key and ciphertext level are both pinned constants
by construction) is airtight and independently confirmed by reading the same
construction sites during Report A's review. The runtime probe is the useful
addition: it demonstrates the level-equality check *passing* at the precise
moment of corruption, which forecloses the level-mismatch hypothesis this
report was commissioned to check, rather than merely arguing it away
statically. Report B's own bottom line frames the residual cause as "noise
growth" from `extract_digit_dual`'s per-digit K-Elimination call — this is
the same code site Report A implicates, described in different vocabulary;
see the Unresolved Tension section below.

---

## 3. Report C — Div3/`chimera_division` trigger-condition checker

**Claim:** Div3 (Fused Piggyback Division / `chimera_division`) is a red
herring for this defect: structurally unreachable from the FHE rescale path,
and even hypothetically would never dispatch to the FPD lane for any real
config.

### Evidence (file:line preserved from source report)

- `grep -c "chimera_division|cram_ct::|ChimeraLane|select_division_lane|FusedPiggyback"`
  over `rns_fhe.rs` and `arithmetic/rns.rs` → 0 matches in both files.
- `rns_fhe.rs:3316–3322` (`k_elim_rescale_dual`) — `m_level` = product of
  level primes; `(delta, r_u64) = m_level.div_mod_u64(self.t)` is the actual
  rescale divisor.
- `rns_fhe.rs:3374–3377`, `:4467–4510` (`round_div_signed_mod_u256`), and
  `:4437–4463` (`round_div_u256_small`) — self-contained binary-search long
  division directly on the reconstructed U256 value; no modular inverse, no
  lane selection.
- `rns_fhe.rs:3202–3204` (`extract_digit_dual`) — also contains zero
  chimera/cram references.
- `lib.rs:147–148` — `cram_ct_wrap` is the only bridge to
  `exact_transcendentals::cram_ct`, gated behind
  `exact_transcendentals_backend`; `grep -rln "cram_ct_wrap"
  crates/nine65/src/` returns only `lib.rs` — nothing in the
  multiply/relinearize/rescale call chain touches it.
- `exact_transcendentals/src/cram_ct.rs:1121–1159`
  (`select_division_lane`) — dispatch rule is `gcd(|divisor|,
  basis.product())`: `g == 1` → `ModularInverse` (D1) primary; `g != 1` →
  `FusedPiggyback` (D3) primary, further gated by an `AuxResidueSet` and a
  fusion-product bound check.
- `params/secure_configs.rs:187–245` — `t = 65537` (prime, Fermat F4) for
  every shipping config; computed directly: every basis prime mod 65537 is
  nonzero, so `gcd(M_level, t) = 1` for all four configs
  (secure_128/128_deep/192/256), and `gcd(delta, M_level) = 1` where `delta =
  floor(M_level/t)` for all four, computed explicitly in the report.

### Assessment

This report answers a narrower, orthogonal question the investigation was
also asked to close out ("is the previously-documented Div3-not-wired finding
from `5b34a04` related to this defect?") and the answer is clearly no on two
independent grounds: structural unreachability (zero references) and
dispatch-condition unreachability (coprimality of `t` with the modulus chain
is guaranteed by construction, not incidental, for every real config). This
report does not bear on the root cause directly, but it correctly closes off
a plausible-sounding alternative hypothesis and its evidence (the gcd
computations against the literal shipping primes) is concrete and
reproducible from `secure_configs.rs` alone.

---

## 4. Report D — historical/test-coverage timeline

**Claim:** The defect is confirmed still open at HEAD, was explicitly
excluded from `5b34a04`'s fix scope, was explicitly flagged as a separately-
tracked open item by `7a2fcce`, and zero commits since `5b34a04` have ever
touched the four implicated functions.

### Evidence (file:line preserved from source report)

- `depth_and_noise.rs:611–617` (Test 1, CHAIN A) and `:662` (Test 2, CHAIN
  A′) — both drive the chain exclusively via
  `ctx.mul_dual_symmetric_with_s2(...)`.
- `depth_and_noise.rs:696` (Test 3, CHAIN A″) — sole call in the file to
  `ctx.mul_dual_public(ct, &ct_one, &keys.eval_key)`;
  `grep -n "relinearize\|extract_digit\|eval_key"` over the whole file
  returns only this one line.
- `depth_and_noise.rs:118` — `const DEPTH_REGRESSION_FLOOR: usize = 32;`,
  enforced only on CHAIN A (`:627–633`); CHAIN A″ asserts only
  `max_correct_depth >= 1` (`:707–710`) — the file's own structure shows the
  authors already treated the public/relin path as categorically different.
- `git show -s 5b34a04`: "e2·s² winding leak ... Fixed with
  `canonicalize_dual_anchor` at all six sites. Depth 3 now decrypts
  correctly; tensor winding 152 → 130 bits. **`mul_dual_public` was never
  affected.**" — **CORROBORATED** verbatim by direct `git show` while
  writing this document.
- `git show -s 7a2fcce`: "**Public-relin depth-1 anomaly kept as a separate
  recorded measurement — under investigation, not expected behavior.**" —
  **CORROBORATED** verbatim.
- `git log -p 5b34a04..HEAD -- crates/nine65/src/ops/rns_fhe.rs | grep -E
  'relinearize_dual|extract_digit_dual|generate_eval_key_dual|mod_switch_eval_key_to_level'`
  → zero matches (44 commits in range; only 4 touch `rns_fhe.rs` at all:
  `c58a311`, `455939e`, `80b847d`, `05a9cd6`). **CORROBORATED**: re-run
  independently against HEAD `0c99e7c` while writing this document, same
  zero-match result, same 44-commit count, same four `rns_fhe.rs`-touching
  commits (confirmed via `git log --oneline 5b34a04..HEAD --
  crates/nine65/src/ops/rns_fhe.rs`).
- `git show 80b847d -- rns_fhe.rs`: both hunks rewrite the direct-s²
  symmetric relin-before-rescale ordering in `mul_dual_symmetric`/
  `mul_dual_symmetric_with_s2` only; `grep mul_dual_public` on that diff
  returns nothing.
- `git show c58a311 -- rns_fhe.rs`: touches
  `decrypt_dual_with_diagnostics` visibility and an anchor-count fix at the
  *caller* of `extract_k_rns_level`, not `relinearize_dual`/
  `extract_digit_dual`.
- Live rerun, `depth_and_noise_curve_public_mode`: depth 0 noise 6.697 bits;
  depth 1 noise 36.322 bits, OK; depth 2 noise 64.959 bits, "WRONG got 15
  want 5"; `max depth with CORRECT decryption : 1`, `stopped by: Noise`.
- Live rerun, `depth_and_noise_curve_deep_chain` (`NINE65_DEPTH_MAX=40`):
  reached depth 40, `stopped by: DepthLimitReached`, noise 23.147 →
  38.157 bits over depths 1–40 (~0.38 bits/doubling) — vs. the public path's
  ~29.6 bits burned on a single multiply.

### Assessment

The commit-message quotes and the zero-match `git log -p` grep were
independently reproduced against current HEAD while writing this document
and matched exactly, including the 44-commit range count and the identical
four `rns_fhe.rs`-touching commits. This report's conclusion — no fix attempt
has ever targeted this code path, and the defect is a known, explicitly
deferred, still-open item rather than a fresh regression — is the most
directly verifiable of the four and is confirmed without qualification.

---

## Unresolved tension: deterministic-bug framing vs. noise-growth framing

Flagging this explicitly rather than smoothing it over, per instructions.

Report A is emphatic that this is **not** ordinary noise-budget exhaustion:
one of its depth-2 measurements showed a large *positive* ground-truth
margin (the actual reconstructed value was far from any rounding boundary)
on a plaintext that was nonetheless a completely different integer — the
signature of a discrete corruption term (adding a spurious `A · M_level`-
scale quantity whenever a digit's true `k` is negative), not of accumulated
small-magnitude error creeping past a threshold.

Reports B and D describe the same call site's effect in the vocabulary of
"relinearization noise": the codebase's own bit-noise estimator climbs from
36.322 bits (depth 1, correct) to 64.959 bits (depth 2, wrong), and Report B
additionally observes that shrinking the eval key's `decomp_base` from 2^16
to 2^10 (more, smaller gadget digits) measurably extends the correctness
horizon from depth 1 to depth 4+, which reads as a magnitude/noise-scaling
effect.

These are not necessarily contradictory — a systematic, deterministic
per-digit corruption term is exactly what an amplitude-only noise estimator
would report as "more noise" without being able to distinguish it from
genuine random key-switching error, and smaller `decomp_base` digits would
plausibly be less likely to have their true signed `k` exceed the
sign-ambiguity threshold that triggers the bug in the first place. But
**no report tested this reconciliation directly**, and critically: **no
report applied Report A's identified fix (adding the `SignedK256`
conversion to `extract_digit_dual`) and re-ran the depth-2 case to confirm
it actually resolves the failure.** All four investigations were explicitly
diagnostic-only and did not modify production code, so this gap is expected
and not a flaw in the reports — but it means the fix hypothesis, while
strongly evidenced circumstantially and by direct code comparison, is
**unverified by experiment**. This is the single largest remaining unknown
and is called out as the first Phase-1 step below.

A second, smaller point worth surfacing: Report A's "large positive margin"
figures and Report D's "noise bits" figures from `depth_and_noise.rs` are
different quantities computed by different code paths (a ground-truth
decryption-margin computation in A's scratch harness vs. the codebase's
tracked noise-budget estimator in D's rerun of the existing test) and were
not cross-validated against each other on the same run. Both are internally
consistent with their own report's narrative, but a synthesis reader should
not assume they are the same number measured twice.

No other inconsistency, contradiction, or under-evidenced claim was found
across the four reports. Where reports overlap (all four touch on
`extract_digit_dual`/`relinearize_dual` as the locus, and B/C both had to
independently rule out their assigned alternative hypothesis), they agree,
and each report's central file:line evidence was either directly
re-confirmed while writing this document (Reports A and D, spot-checked) or
is static code-structure/arithmetic evidence of a kind that does not carry
meaningful risk of misreading (Report C's gcd computations, Report B's
construction-site reads).

---

## Minimal reproducing case

Derived from the overlapping evidence in Reports A and D (both independently
produced the same shape of failure from the same starting conditions).

**Setup:** `SecureConfig::secure_128()` (n=8192, t=65537, 3 main primes,
5 canonical anchor primes). Any fresh keypair; the specific seed does not
matter — Report D's run used `depth_and_noise.rs`'s default seeding and
Report A's scratch tests used an independent seed (1234 in Report B's
variant), and both reproduced the failure.

**Steps:**
1. `ct0 = encrypt_dual(m0)` for any small `m0` (e.g. 3).
2. `ct1 = mul_dual_public(ct0, ct0, &eval_key)` (or `mul_dual_public(ct0,
   encrypt_dual(1), &eval_key)`). Decrypts correctly at this depth in every
   run across all four reports.
3. `ct2 = mul_dual_public(ct1, ct1, &eval_key)`. Returns `Ok(ct2)`, no panic.
   `decrypt_dual(ct2)` does **not** equal `m0^4` (or the appropriate expected
   value for the chosen chain shape).

**Isolation variant (Report A, the strongest form):** replace step 2 with
`ct1 = mul_dual_symmetric_with_s2(ct0, ct0, sk, &s2)` (a path that never
calls `extract_digit_dual`), confirmed correct. Step 3, applied to that
clean `ct1` via `mul_dual_public`, still fails on its first-ever
`extract_digit_dual` invocation — ruling out any explanation involving
accumulated history across two public-mode operations.

**Existing in-repo reproduction, unmodified:**
```
cargo test -p nine65 --release --test depth_and_noise \
  depth_and_noise_curve_public_mode -- --nocapture
```
which is the file's Test 3 (CHAIN A″), asserting only
`max_correct_depth >= 1` — passing today precisely because the bar is set
below the depth at which the defect fires.

---

## Phase 1 recommendation (fix scope — not performed here)

This document is diagnostic only; no code changes are included. For the
follow-on fix phase:

1. **Before writing the fix, run the missing experiment.** Add the
   `SignedK256::from_unsigned` conversion to `extract_digit_dual`
   (`crates/nine65/src/ops/rns_fhe.rs:3202–3207`), mirroring
   `k_elim_rescale_dual`'s pattern at `:3358–3362` — likely inserting a
   `let k_signed = SignedK256::from_unsigned(k, a_n_product);` step and using
   `k_signed`'s signed magnitude/sign in place of the raw `k` when forming
   `exact` at line 3207 (the exact arithmetic needs care: `k_elim_rescale_dual`
   consumes `k_signed` via `.magnitude` and a separate sign branch further
   down its function body — `extract_digit_dual`'s use of `k` is structurally
   different, feeding straight into a digit-shift rather than a
   rescale-and-round, so the signed value must be reconciled with two's-
   complement-style digit extraction rather than substituted naively).
   Re-run the minimal reproducing case above and confirm depth 2 (and
   ideally several depths beyond) decrypts correctly. This closes the one
   unresolved item in this document.
2. **Primary fix site:** `extract_digit_dual`,
   `crates/nine65/src/ops/rns_fhe.rs:3165–3239`, specifically the `k`
   handling at `:3202–3207`. This is the proximate cause identified
   independently by Report A and directly corroborated in this synthesis.
3. **Do not touch** `k_elim_rescale_dual` (`:3316–3399`),
   `extract_k_rns_level` (`arithmetic/rns.rs:1553–1658`), or
   `mod_switch_eval_key_to_level`/`relinearize_dual`'s level-guard branch
   (`:3066–3093`, `:3106–3137`) — all three are independently confirmed
   correct/inert for this defect by Reports A, B, and D respectively, and
   changing them risks regressing the symmetric path's proven >250-depth
   correctness.
4. **Do not investigate or touch Div3/`chimera_division`/`cram_ct`** as part
   of this fix — Report C closes that off with concrete, reproducible
   evidence (structural unreachability plus guaranteed-coprime dispatch
   conditions for every shipping config).
5. **Regression coverage after the fix:** `depth_and_noise.rs`'s Test 3
   (CHAIN A″, `depth_and_noise_curve_public_mode`) currently asserts only
   `max_correct_depth >= 1` (`:707–710`) — the file's own author-set bar is
   the reason this defect has shipped un-flagged by CI. Once fixed, raise
   this assertion to a real floor (mirroring `DEPTH_REGRESSION_FLOOR = 32`
   used for the symmetric chain at `:118`/`:627–633`) so a future regression
   in `extract_digit_dual` fails CI instead of passing at `>= 1` again. This
   mirrors the general lesson already recorded in
   `AUDIT_FINDINGS_2026-08-09.md` §5.1/§5.4: assertion strength, not test
   presence, is what let this class of defect through.
6. **Do not treat `decomp_base` tuning as a substitute fix.** Report B's
   observation that shrinking `decomp_base` from 2^16 to 2^10 extends the
   correctness horizon from depth 1 to depth 4+ is real and reproducible via
   `residue_space_ciphertext.rs`, but per the Unresolved Tension section
   above, this is very plausibly a symptom-masking parameter change (fewer
   digits/coarser corruption threshold crossed less often) rather than a fix
   for the underlying missing sign correction, and should not be adopted in
   place of item 1–2 above without first confirming (per item 1) that the
   sign fix alone resolves the defect at the *default* `decomp_base = 2^16`.

---

## Provenance

Synthesized from four verbatim investigation reports (labeled A–D above,
each independently scoped to one hypothesis: sign-handling in
`extract_digit_dual`; eval-key level/decomposition bookkeeping; Div3/FPD
routing; and commit-history/test-coverage timeline). Cross-report
corroboration performed while writing this document: direct re-read of
`rns_fhe.rs:3165–3239` and `:3316–3399` at HEAD `0c99e7c`; independent
re-run of `git log -p 5b34a04..HEAD -- rns_fhe.rs | grep -E
'relinearize_dual|extract_digit_dual|generate_eval_key_dual|mod_switch_eval_key_to_level'`
(zero matches, matching Report D); independent `git show -s` on `5b34a04`
and `7a2fcce` (verbatim match to Report D's quotes). No production file was
modified in the production of this document; `git status --porcelain` is
clean of any new file besides this one.
