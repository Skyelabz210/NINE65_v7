# Execution Plan — NINE65_v7 Comprehensive Remediation (2026-08-12)

**Audience:** whoever (human or autonomous coding model) picks up remaining
work on this repo. **Scope confirmed by repo owner:** comprehensive — covers
correctness, CI truth, documentation truth, the full CRAM engineering ledger,
the winding-tower dead-code decision, and Lean/Coq formal-verification gaps.

**Prerequisite reading:** `docs/RETIRED_MECHANISMS.md` (authoritative record
of the 2026-08-09 bootstrap-quarantine decision), `docs/AUDIT_FINDINGS_2026-08-09.md`,
`docs/AUDIT_VERIFICATION_2026-08-12.md`, `docs/TIME_CRYSTAL_VERIFICATION_2026-08-12.md`,
`CRAM_OPPORTUNITY_REPORT.md` (the open engineering ledger, entries `[1]`-`[44]`).

## Context

CLAUDE.md's headline claims (three verified bootstrap paths, depth-50,
zero floats, N=4096 security numbers) are substantially stale. The repo
underwent a deliberate architectural pivot on 2026-08-09 (commit `5b34a04`,
authored by the repo owner with a prior Claude session): bootstrap was
quarantined on the bet that CRAM's exact residue-space division ("Div³" /
Fused Piggyback Division) would replace its job. That commit's own message
records the wiring was never finished. Today, public-key multiplicative
depth is capped at 1 — this is the live, top-priority defect this plan
starts from.

**Explicit direction from the repo owner (do not re-litigate):**
1. Plan scope is comprehensive — not just the depth-1 bug.
2. Bootstrap is not to be treated as abandoned. It was a deliberate bet
   (Div³ replaces its job) that's incompletely wired, not a dead end.
3. Top priority: investigate whether the missing Div³→rescale wiring (or
   something in the same family) explains the depth-1 cap, before touching
   bootstrap tests/code at all.

## Preliminary finding that reshapes Phase 0

A grep across `crates/nine65/src/ops/rns_fhe.rs` for every spelling of the
Div³ machinery (`chimera_division`, `FusedPiggyback`, `fused_piggyback`,
`div_div_div_chimera`, `Div3`) returns **zero matches**. Rescale on
`mul_dual_symmetric`/`_with_s2` (`rns_fhe.rs:2708`) and `mul_dual_public`
(`rns_fhe.rs:2907`) both go through the *identical* `k_elim_rescale_dual`
(`rns_fhe.rs:3316`) — no Div³ either way. Since that shared step is
identical on the path that reaches depth 128+ (symmetric,
`time_crystal_verification.rs:243`) and the path capped at depth 1
(public), the missing Div³ wiring cannot by itself explain the
*differential*.

The one structural difference: `mul_dual_public` alone calls
`relinearize_dual` (`rns_fhe.rs:3106`) → `extract_digit_dual`
(`rns_fhe.rs:3165`), which runs a **second, independent K-Elimination call
per gadget digit**, inside a loop over `evk.rlk` digits, each contributing
key-switching noise. `mul_dual_symmetric` instead folds the degree-2 term
directly by multiplying by a precomputed `s²` (`rns_fhe.rs:2758-2761`) — no
eval key, no gadget decomposition, no extra noise source.

**Phase 0 should investigate both** the relinearization/digit-extraction
K-Elimination call and the Div³ wiring gap, but should not assume Div³
wiring is the fix, since rescale is provably identical on the working and
broken paths.

---

## Phase 0 — Depth-1 root-cause investigation (mandatory first, no code changes)

**Goal:** Determine definitively why `mul_dual_public` decrypts correctly
at depth 1 but not depth 2+, while `mul_dual_symmetric`/`_with_s2` on the
identical rescale primitive reaches depth 128+.

**Concrete targets:**
- Instrument `relinearize_dual` (`rns_fhe.rs:3106`) and `extract_digit_dual`
  (`rns_fhe.rs:3165`) to log `k` magnitude and anchor-capacity margin from
  `extract_k_rns_level` at each gadget digit, depth 1 vs depth 2, compared
  against the margins in `k_elim_rescale_dual`'s own (working) call.
- Check `DualRNSContext::extract_k_rns_level` (`arithmetic/rns.rs:1553-1658`)
  for level/tier-dependent branches that could behave differently when
  called from inside digit decomposition (larger pre-reduction magnitude
  into `to_u256_level`) vs. from final rescale.
- Confirm whether `evk.rlk` (eval-key gadget vectors) are generated at a
  fixed level/decomp_base that stops matching the ciphertext's actual
  noise budget by depth 2 — trace `Self::eval_key_level`,
  `mod_switch_eval_key_to_level` (`rns_fhe.rs:3118`), and key generation.
- Separately confirm/refute the Div³ wiring gap as a *contributing*
  factor: examine `cram_ct.rs:1454` ("Phase-4 D3 rescale via Fused
  Piggyback Division") and `chimera_division.rs` — does the plan/mask
  logic trigger exactly when `gcd(Δ, M) ≠ 1`? Is that condition ever true
  on the rescale divisor `Δ = M_level/t` used in `k_elim_rescale_dual`?
  If `gcd` is always 1 for this scheme's parameters, Div³ is structurally
  irrelevant to rescale and commit `5b34a04`'s "headline open item"
  language refers to a currently-dormant capability, not the depth-1
  bug's cause. **Verify during implementation** against `t` and the
  prime-family construction in `params/secure_configs.rs`.
- Cross-check `depth_and_noise.rs:593` `depth_and_noise_curve_deep_chain`
  (floor 32, uses `mul_dual_symmetric_with_s2`) to confirm it's genuinely
  on the no-relin path, ruling it out as counter-evidence.
- Reconcile with commit `7a2fcce` ("Public-relin depth-1 anomaly kept as a
  separate recorded measurement — under investigation") and `5b34a04`'s
  note that `mul_dual_public` "was never affected" by the e2·s² winding-leak
  fix — this is a third, distinct, still-open defect in the same family.

**Dependencies:** None — entry point. Nothing downstream assumes a
diagnosis until this closes.

**Definition of done:** A written finding (`docs/DEPTH1_ROOT_CAUSE_<date>.md`,
following the `AUDIT_FINDINGS_2026-08-09.md` precedent) identifying the
exact divergence point, a minimal reproducing case, and an explicit
verdict on whether Div³/FPD wiring is (a) root cause, (b) contributing,
or (c) orthogonal. Diagnostic only — no test/CI changes required to close.

**Priority/risk:** Highest priority, per explicit direction. Low risk
(read-only/instrumentation), but the diagnosis materially changes Phase 1's
shape — don't let time pressure truncate it into a guess.

---

## Phase 1 — Fix the depth-1 defect and adjacent correctness bugs

**Goal:** Land the fix Phase 0 identifies, plus already-diagnosed bugs in
the same family, and replace test floors that currently document the
defect instead of catching it.

**Concrete targets:**
- The fix at whatever site Phase 0 identifies — most plausibly inside
  `relinearize_dual`/`extract_digit_dual` (`rns_fhe.rs:3106-3235`), possibly
  requiring eval-key regeneration parameters, additional anchors for the
  digit-decomposition K-Elimination call, or (if Phase 0 confirms it) wiring
  `chimera_division::FusedPiggyback` into the affected step.
- `depth_and_noise.rs:679-710` `depth_and_noise_curve_public_mode` —
  replace `assert!(reached >= 1)` with a real floor once fixed.
- `time_crystal_verification.rs:275` `public_relin_chain_depth_measured` —
  same; "No floor asserted" becomes a real assertion.
- `depth_and_noise.rs:645` `depth_and_noise_curve_squaring_chain` — tighten
  once understood; **verify during implementation** whether it inherits the
  fix or is a separate, already-working case with just a weak assertion.
- `arithmetic/rns.rs:1675-1678` — `DualRNSContext::reconstruct`'s overflow
  else-branch silently wraps mod 2^128 on secure_192/256; make it fail
  loudly like every sibling path. Independent bug, fix regardless of
  Phase 0's outcome.
- `exact_transcendentals/src/k_elim.rs:302-321` `k_elim_divide_named` —
  resolve the docstring/body contradiction (docstring at `:293-294`
  promises no mixed-radix fuse; body at `:315-317` calls
  `garner_reconstruct` anyway). Prefer fixing the body to match the
  docstring's promise if a Garner-free path is achievable (consistent with
  ledger `[42]`/`[43]`'s direction) — see also the U1/U2 candidate
  implementations noted in "New material" below.

**Dependencies:** Phase 0 must produce a diagnosis first. Documentation
(Phase 3) and the CRAM ledger (Phase 4) both need to cite the *resulting*
depth story, not the current broken one.

**Definition of done:** `depth_and_noise_curve_public_mode` and
`public_relin_chain_depth_measured` both assert a real floor > 1 (target:
parity with the symmetric floor, or an explicit documented reason for a
lower one). Full `cargo test -p nine65` green, including
`depth_and_noise_curve_deep_chain` (floor 32) and
`symmetric_depth_is_unbounded` (floor 128) as regression checks. The
`rns.rs` overflow branch has a test forcing the overflow condition and
asserting `Err`/panic, not silent wraparound.

**Priority/risk:** Highest priority. The fix may require eval-key/parameter
changes touching every eval-key-consuming call site — scope only after
Phase 0 narrows it.

---

## Phase 2 — CI / quality-gate repair

**Goal:** Make CI tell the truth: fix the 5 gates that currently fail,
repair gates that structurally cannot fail, remove/re-point dead workflow
references.

**Concrete targets:**
- *Stale references:* `scripts/check_stale_claims.sh` — drop 3 retired
  claim IDs and the removed README benchmark-table parse (per
  `docs/CLAIM_RETIREMENTS_2026-07-13.md`). `scripts/audit_modulus_classes.py`
  `parse_anchors` regex — stop scraping inline-comment digits, see anchors
  past the first `]` (`rns.rs:1246-1258`). `scripts/check_residue_native_architecture.py`
  — drop references to nonexistent `crates/cram-poly`/`crates/cram-fhe`.
- *Dead-branch gating:* re-point or explicitly retire the 7 workflows gated
  to deleted branches (`hardening/beyond-100-app-platform`,
  `cram/residue-native-scale-dag`, `cram/exploratory-comparative-v2`,
  `audit/remediate-followup-2026-07-13`) — `app_platform_gates.yml:6`,
  `audit_remediation.yml:23`, `cram_residue_native_gates.yml:17`,
  `cram_exploratory_matrix.yml:17`, `cram_v6_v7_comparative.yml:19`,
  `cram_v7_scale_sweep.yml:13`, `apply_issue29_metadata_patch.yml:6`, plus
  the two PR-base-gated workflows that never fire
  (`cram_real_refresh_evidence.yml`, `cram_recumbency_followup.yml`).
  **Verify during implementation** which branch is current trunk.
- *Dead test references inside those workflows:* drop/replace
  `--test rns_context_metadata_regression`, `dual_rns_context_metadata_regression`,
  `ntt_roundtrip_prime_regression`, `--lib ... ops::sbni` (removed from
  `ops/mod.rs:16-19`).
- *Gates that cannot fail by construction:* `scripts/check_no_panics.sh:91`
  hardcoded `exit 0`; `ci.yml:130-134` Coq-presence `ls`; `ci.yml:136-142`
  Lean4-presence `echo`-only (also fix its glob to include `AHOP/`/`Lattice/`);
  `ct_verification.yml:51` missing `--ignored`/`--include-ignored` (runs
  zero of 8 CT tests currently); `ci.yml:340`
  `extract_criterion_summary.py || true`.
- *Gate calibration:* `scripts/regression_scan.sh`'s hardcoded 1000-test
  threshold vs. actual 888 — correct the number; decide whether it should
  gain the same float/panic exclusion list `check_no_floats_runtime.sh`
  already has (flagged below).
- *CI structure:* `--exclude nine65-python/wasm/ffi` no-op flags
  (`ci.yml:96-99,187-191`) — remove, redundant with workspace-level
  `exclude`; `full-test` tier PR-to-`develop` gap (`ci.yml:149`);
  `google-labs-jules[bot]`/`dependabot[bot]` bypass of T1-T3.
- *Infra hygiene:* `Dockerfile` — add missing `cargo fetch`/`cargo build`
  layer-cache step, add the 5 missing workspace members;
  `.dockerignore` stale exclusions; wire `fuzz/`'s 5 targets into at least
  one workflow (currently run by none).

**Dependencies:** Mostly independent of Phase 0/1 (mechanical script/workflow
bugs). Exceptions: (a) `regression_scan.sh`'s test-count threshold and the
`#[ignore]` inventory should get final numbers *after* Phase 1's test
changes land — do mechanical fixes first, recalibrate thresholds last;
(b) turning `check_no_panics.sh` and the CT-verification `--ignored` gap
into real hard gates will surface 238 panic violations and 8
previously-unrun statistical CT tests — sequence as "add the mechanism,
run report-only/advisory first" (see Priority/risk).

**Definition of done:** Every script in `scripts/`/`.github/scripts/` runs
and reports its true current state. No workflow references a nonexistent
branch/file/module. Re-run each script locally and confirm output matches
reality — reuse the scripts themselves as the verification method.

**Priority/risk:** High priority. **Judgment call:** turning advisory
gates into hard gates will likely fail CI on `main` immediately given
current violation counts — recommend a ratchet approach (baseline current
count, gate on "no new violations") over a hard cutover, but this is the
repo owner's call.

---

## Phase 3 — Documentation truth-alignment

**Goal:** Every doc's claims traceable to a real, currently-passing test,
or explicitly labeled "not yet verified," using the already-honest in-tree
docs as source of truth.

**Concrete targets:**
- *Immediate honesty pass* (doesn't need to wait for Phase 1): rewrite
  CLAUDE.md's "zero floating-point, ever" claim (168 actual occurrences —
  cite counts per crate), the "first FHE system with fully verified
  bootstrap roundtrip" headline (contradicts `docs/RETIRED_MECHANISMS.md`),
  stale test counts (actual 1125 nine65 tests, 518 exact_transcendentals,
  21/216 Lean modules/theorems) — reconcile against
  `docs/AUDIT_FINDINGS_2026-08-09.md`, `docs/AUDIT_VERIFICATION_2026-08-12.md`,
  `docs/TIME_CRYSTAL_VERIFICATION_2026-08-12.md`, `docs/RETIRED_MECHANISMS.md`,
  `docs/LINEAGE.md`.
- Retire/correct the four conflicting depth-50-timing documents (CLAUDE.md,
  `docs/FAQ_HOTSHEET.md:20`, `docs/DEPTH_CORRECTNESS_MATRIX.{md,json}`,
  `docs/SECURITY_GAP_ANALYSIS.md:57`) — point at a real asserting benchmark
  (none exists today; `gso_fhe.rs:862,890` never decrypts or asserts) or
  label "unverified historical timing" until one is built.
- Fix the 4 `LATTICE_ESTIMATOR_BASELINE_*.md` docs' stale `n` values
  (secure_128 documented n=4096 vs actual n=8192, `params/secure_configs.rs:189`)
  and reiterate the estimator's own caveat that it isn't an independent
  security certificate.
- `lean4/KElimination/VERIFICATION_SUMMARY.md`/`README.md` — correct
  theorem count (216, not ~84), fix the nonexistent `ZMod.lean` reference,
  list all 21 modules, retract "Bootstrap-free"/"Accuracy 100% exact" per
  `docs/LINEAGE.md:74`.
- `docs/FORMALIZATION_INDEX.md` — correct "Coq is canonical" to match
  `docs/LEAN_FORMAL_VERIFICATION_2026-06-03.md`; stop citing
  `OrderFinding.v:lagrange_bound` (an Axiom) as proved.
- `docs/CLAIM_REGISTRY.csv` — bring performance/depth claims into the
  governance system it claims to enforce, or document it only covers a
  subset.
- *Post-fix numbers pass* (gated on Phase 1): once the real fixed depth is
  known, update CLAUDE.md's headline depth claim to the actual number.

**Dependencies:** Immediate honesty pass starts right after Phase 0 — don't
wait for Phase 1. Stating current reality accurately, including "public-path
depth is currently capped at 1, under active fix," is itself an improvement
over the current false claims. Final numeric refresh gates on Phase 1.

**Definition of done:** Reuse repaired `scripts/check_stale_claims.sh`
(Phase 2) for the `CLAIM_REGISTRY.csv`-governed subset. For the broader doc
set, manual cross-reference against the four honest source-of-truth docs.

**Priority/risk:** Medium-high (reputational/trust surface, not a
correctness blocker). **Judgment call:** the zero-float enforcement
boundary — `exact_transcendentals` has 77 float occurrences in
approximation algorithms (`agm.rs`, `cordic.rs`, `sqrt.rs`,
`continued_fraction.rs`, `binary_splitting.rs`). Classify each site as
(a) hot-path violation needing defloat, or (b) legitimate
approximation-to-exact-result needing an explicit justified
`#[allow(clippy::float_arithmetic)]`, before blanket-adding
`#![deny(...)]` — a blind deny will likely break real functionality.

---

## Phase 4 — CRAM engineering-ledger consolidation

**Goal:** Close or explicitly re-scope every open ledger entry
`[7]`,`[8]`,`[9]`,`[31]`-`[41]`, and resolve the five-implementation
K-Elimination duplication.

**Concrete targets:**
- `[7]` `composite_division.rs:144,167-238` `mixed_radix_garner()`,
  `[8]` `cram_pde.rs:127-140` `ExactState::to_u128` (called by
  `safe_basis_io.rs:38,92,130`), `[9]` `k_elim.rs:150-163`
  `garner_reconstruct` — open Garner sites on real arithmetic paths; each
  needs a decision: retire per the `[42]`/`[43]` precedent, or document as
  intentionally-Garner with reasoning.
- `[31]` `mana/src/parallel.rs` (rayon-gated, no deterministic lane
  executor) — build the deterministic executor or re-scope the claim in
  `mana/src/lib.rs:8`.
- `[33]`/`[37]` — `mana/src/anchor.rs:166-207` `exact_divide_stream`/
  `compute_partial_crt` vs. the "method-of-record staged" replacement in
  `[37]` (`k_elim.rs:272,370`, `cram_ct.rs:1390`) — directly informed by
  Phase 0's FPD findings; close using those conclusions. **See "New
  material" below — a concrete candidate implementation surfaced today.**
- `[34]`/`[38]` — `TransductionMap` ⇄ `ManaStream` u64 lane bridge, speced
  in `The5thOperator.md` per `[38]`; build or explicitly defer.
- `[35]` — verify whether `[43]`'s resolution actually satisfies `[35]`'s
  claim; if so, add the `RESOLVED->[43]` marker (bookkeeping gap, not open
  engineering work).
- `[36]` FORCED — `docs/cram-corpus/2026-08-12/qcram_composite_lib.rs.pending-defloat`,
  19 f64 sites; land the integer-expressible rewrite, drop the suffix.
- `[39]`/`[41]` — action item is implementing the conclusion (Shoup/Barrett
  lane constants, retire `mana`'s Montgomery `PersistentLane` machinery).
- `[40]` — 4 identified sequential sites; routes to `[31]`/`[33]`, sequence
  after those.
- *K-Elimination consolidation (cross-cutting):* five implementations —
  `nine65::arithmetic::k_elimination::KElimination` (validated, CT),
  `DualRNSContext::extract_k_rns_level` (hot-path, own guard model),
  `exact_transcendentals::k_elim` (hosts the dead winding tower),
  `mana::anchor::KAnchor` (unvalidated, variable-time),
  `clockwork-core::garner::k_eliminate`/`k_eliminate_ct`. Recommend:
  `mana::KAnchor::for_fhe()` delegates to (or is replaced by) the validated
  `nine65` implementation — confirmed to hardcode identical alpha/beta
  constants, a structural duplicate not an independent design.

**Dependencies:** Follows Phase 0/1 (`[33]`/`[37]` entangled with the
Div³/K-Elim wiring question). Independent of Phases 2/3.

**Definition of done:** `CRAM_OPPORTUNITY_REPORT.md` updated with
`RESOLVED->[N]` markers for closed entries, following the existing
convention. Deferred entries get an explicit re-scope note. K-Elimination
consolidation verified by `mana`'s test suite staying green after
delegating, plus a new test asserting `mana::KAnchor::for_fhe()`'s
constants match `nine65::KElimConfig::Standard`.

**Priority/risk:** Medium. Most entries are unwired/uncalled outside
tests — low risk, safe to defer relative to Phases 0-3 if time-constrained.

### New material relevant to this phase (uploaded 2026-08-12, needs review before use)

A candidate implementation for the missing `BoundedResidueDivider` was
surfaced today: `kelim_residue_divider.rs` implements `project_bounded` for
`crates/nine65/src/arithmetic/residue_division.rs`'s trait — which
currently has **zero implementors anywhere in the workspace** (confirmed by
direct read), exactly matching `check_cram_recumbency.py`'s failing
`project_bounded\s*\(` contract. Structural field/type names line up with
the real `ResidueDivisionRequest`/`ResidueBasisRef`/`ResidueDivisorRef`/
`ResidueDivisionCertificate` in the current file. **Not yet compiled or
tested against the real crate** — before landing it: (1) confirm
`Nine65Error::Overflow`/`ModulusZero` variant usage compiles (both exist in
`errors.rs`, spot-checked), (2) resolve that `project_bounded` never reads
`request.divisor.main_residues`/`anchor_residues` — it recomputes `d mod p`/
`d mod A` from `divisor.factors` directly instead, which is self-consistent
but leaves two validated-but-unused struct fields; decide whether that's
intentional (untrusted pre-supplied residues, safer to derive fresh) or a
sign the fields should be removed from the contract, (3) run its own
embedded unit tests (`exact_division_unit_divisor`, `truncating_divmod_nonexact`,
`shared_factor_lanes`) plus a differential check against
`k_elim_divide_repo`/`crt_reconstruct` on the same inputs.

Two verification Python scripts accompanied it (`verify_fpd_residue_native.py`,
`verify_a2_fix.py`) plus `division_operator_space.py`, all modeling — not
compiling against — the real Rust semantics. They propose the same U1
(`DIV_KELIM_NATIVE`)/U2 (`FPD_KELIM_NATIVE`) pattern already staged in
ledger `[37]`: quotient stays as residues, name recovered via one
anchor-ladder K-Elimination read, never a basis-wide Garner fuse. Treat as
design reference, not verified Rust, until compiled and tested in-repo.

**Also flagged: do not reuse the `patched2/` bundle from the same upload.**
Three of its six files (`auto_bootstrap.rs`, `secure_configs.rs`,
`k_elimination.rs`) are stale snapshots dated 2026-08-01 that predate real
hardening commits already in the tree. Applying them would **remove the
n≥8192 security-floor assertion** in `secure_configs.rs` and **revert
`k_elimination.rs`'s validators to a version that no longer rejects
unit/1-valued beta moduli** — both regressions, not fixes. The other three
files in that bundle are byte-identical to current `HEAD` (harmless
reference copies).

---

## Phase 5 — Winding-tower decision (dead code, real bug)

**Goal:** Resolve the `k_from_tower`/`k_to_tower`/`tower_add`/`add_carry`
dead-code question (`exact_transcendentals/src/k_elim.rs:408-470`), human
confirms, fix the underflow bug regardless of the outcome.

**Concrete targets:**
- `add_carry` (`k_elim.rs:459`): `let d = kd.len(); while i < d - 1 ...` —
  on empty `kd`, `d - 1` underflows (`usize`), causing a debug-mode panic
  or release-mode OOB access. `k_to_tower` (`:422`) has an analogous
  unchecked `mus[i]` index for `i < depth-1`.
- Zero callers anywhere in the workspace outside 4 unit tests
  (`k_elim.rs:677-718`).
- Already-open in-repo question: `docs/AUDIT_FINDINGS_2026-08-09.md:407-410`.
- Confirmed distinct from the tested, callered "telescoping tower" in
  `cram_anchor.rs` (tested to depth 4, `:828-842`) — don't conflate.

**Recommendation (human confirms, don't auto-apply):** Delete. It's dead
code with an active bug, doesn't match the recursive K-of-K
winding-of-winding lift described in the uploaded CRAM research docs (it's
a mixed-radix decomposition of an already-extracted single `k`), and no
part of this plan identifies a pending caller. Keeping it "as
experimental, bug-fixed" is defensible if there are forward plans not
visible in-tree — that's context only the repo owner has.

**Dependencies:** Independent, executable any time; blocks Phase 6's Lean
coverage scoping.

**Definition of done:** Either removed (`cargo test -p exact_transcendentals`
green, public surface no longer exports them) or fixed (bounds-checked, a
real caller, a regression test for empty input) with an explicit
experimental/unused-in-production comment.

**Priority/risk:** Low (zero current blast radius), but a genuine judgment
call — confirm before deleting research-relevant scaffolding.

---

## Phase 6 — Formal verification coverage repair

**Goal:** Close real Lean gaps, resolve the Coq-tree posture (delete vs.
archive) so the proof gates mean what they claim.

**Concrete targets:**
- `incrementalCRTStep` (`KElimination.lean:356`) — zero theorems on the
  actual reconstruction algorithm in use, only surrounding
  uniqueness/soundness facts. Highest-value Lean gap to close.
- `ahop_hardness` (`AHOP/Hardness.lean:133`) — declared, never consumed by
  any theorem. Either complete the reduction (construct a `tag` function
  satisfying the injectivity hypothesis for production parameters and
  derive the orbit bounds from it) or explicitly document AHOP-hardness as
  scaffolding wherever cited for security marketing (ties to Phase 3).
- Winding-tower proof — moot if Phase 5 deletes; otherwise needs Lean
  coverage matching `cram_anchor.rs`'s telescoping-tower precedent.
- Publish exact Lean/Mathlib/commit versions in `lean_proofs.yml`, as
  `docs/FORMAL_APP_CRITICAL_SPINE.md` requires but the workflow doesn't do.
- *Coq tree:* `verified-innovations/proofs/coq/` is a stale duplicate of
  `proofs/coq/` with more unrepaired defects (18 vs 7 `Admitted.`).
  `proofs/coq/MontgomeryContext.v:307` `montgomery_sub_correct` is a
  literally false theorem (counterexample q=5,R=8,x=4,y=3) sitting
  `Admitted`.

**Recommendation (human confirms):** Delete `verified-innovations/proofs/coq/`
entirely, fix `coq_proofs.yml:37`'s skip-list gap in the remaining tree,
delete the false `montgomery_sub_correct`. Consistent with Lean being
declared-authoritative and Coq explicitly legacy in its own CI header. The
alternative (archive both trees out of active CI, keep files, "historical,
not verified" label) is defensible if there's a reason to preserve the
record — genuine judgment call.
- `lean4/KElimination/coq/K_Elimination.v` (0 `Admitted`, currently
  compiled by neither workflow) — fold into whichever tree survives.

**Dependencies:** Depends on Phase 5 (winding-tower Lean coverage);
benefits from following Phase 1 and Phase 4.

**Definition of done:** `scripts/axiom_audit.sh` continues passing with
exactly the one intentional axiom. `coq_proofs.yml` either has an
empty/removed job or a corrected skip-list with zero silently-passing
`Admitted` outside it. New `incrementalCRTStep` theorems compile with 0
`sorry`.

**Priority/risk:** Medium — the Lean spine is real, load-bearing, and
under-advertised (not broken); this phase closes genuine gaps and cleans
up legacy Coq, except the one literally-false Montgomery theorem.

---

## Phase 7 — Bootstrap fate revisit

**Goal:** Now that Phase 0/1 establishes whether exact-division rescale
delivers deep multiplicative depth on both paths, revisit whether
bootstrap quarantine should stand, partially reverse, or become permanent
— per the repo owner's framing that this was a deliberate bet, not
abandonment.

**Concrete targets:**
- Decision input: does Phase 1's fix bring `mul_dual_public` to parity
  with the symmetric path's 128+ floor? If yes, the original bet is
  validated — quarantine should stand, possibly upgraded from "quarantined"
  to "confirmed unnecessary, formally retired."
- If only partial, the decision is genuinely open — needs repo-owner input
  on acceptable depth for the product's use cases.
- If kept quarantined: no code changes to the 145 `#[ignore]`d tests, but
  Phase 3's doc pass stops claiming "three verified bootstrap paths"
  anywhere.
- If ever revived: known unfixed defect
  `nine65-extreme-tests/src/bootstrap_adversarial.rs:158` (Q17 —
  `AutoBootstrapEvaluator` produces incorrect plaintexts after ~10
  multiplications) must be fixed first; `test_bootstrap_all_three_paths_same_plaintext`
  (`bootstrap_adversarial.rs:118`) needs to move into default CI.
- Separately, regardless of bootstrap: no ciphertext rotation exists on
  the production dual-RNS path (`GaloisEvaluator`, `ops/galois.rs:492`
  only operates on the legacy single-modulus type) — distinct capability
  gap, lower urgency than depth.

**Dependencies:** Gated on Phase 0 and should wait for Phase 1's fix to
land so the decision is made against real numbers.

**Definition of done:** A written decision doc (extending or superseding
`docs/RETIRED_MECHANISMS.md`) stating bootstrap's final status with the
depth evidence cited.

**Priority/risk:** High-stakes judgment call explicitly reserved for the
repo owner — this plan sequences the evidence-gathering ahead of the
decision, doesn't pre-decide it.

---

## Phase 8 — Test-suite / bench meta-cleanup

**Goal:** Address structural test/bench hygiene that doesn't block
correctness but reduces confidence in "green CI" as a signal.

**Concrete targets:**
- Triage the 165 `#[ignore]`d tests (100% in `nine65`) — categorize as
  (a) bootstrap-related (resolved by Phase 7), (b) stale/superseded,
  (c) should run in CI now. Decide whether `nine65-extreme-tests` (85
  tests, includes the only 3-path bootstrap test) should get a nightly CI
  job.
- Wire `fuzz/`'s 5 targets into a scheduled (not per-PR) workflow.
- Fix bench harness mismatches: `mana/benches/lane_ops.rs` and
  `exact_transcendentals/benches/performance.rs` both use `criterion_main!`
  but aren't declared in `Cargo.toml`'s `[[bench]]` — fix the declarations
  (`harness = false`), wire a real `cargo bench` job (also fixes Phase 2's
  "T4 Benchmark Regression" mislabeling).
- Expand `proptest!` usage (only 2 blocks exist despite 3 crates having it
  as a dev-dependency) — opportunistic, not a dedicated sweep.

**Dependencies:** `#[ignore]` triage depends on Phase 7; benefits from
Phase 1. Otherwise independent — can run in parallel with Phases 4-6.

**Definition of done:** Documented accounting of every `#[ignore]`d test's
reason. `cargo bench` runs for at least one crate as a smoke check.
`fuzz/` targets build.

**Priority/risk:** Lowest — genuine hygiene, reasonable to defer past a
release if time-constrained.

---

## Summary dependency graph

```
Phase 0 (investigate depth-1) --> Phase 1 (fix depth-1 + adjacent bugs)
                                        |
        +---------------+--------------+--------------+---------------+
        v               v              v              v               v
   Phase 2 (CI)    Phase 3 (docs,  Phase 4 (CRAM   Phase 7        Phase 5
  [mechanical part  2-pass: honest  ledger, incl.   (bootstrap     (winding
   independent of   pass starts     K-Elim          fate)          tower)
   0/1; thresholds   after Phase 0] consolidation)      |               |
   finalize after                        |               v               v
   Phase 1]                              |          Phase 8         Phase 6
                                          +-----------------------> (Lean/Coq,
                                                                     needs 1,4,5)
```

## Critical files for implementation

- `crates/nine65/src/ops/rns_fhe.rs` — `mul_dual_public` (:2907),
  `mul_dual_symmetric`/`_with_s2` (:2708), `relinearize_dual` (:3106),
  `extract_digit_dual` (:3165), `k_elim_rescale_dual` (:3316) — Phase 0/1
  centers here.
- `crates/nine65/src/arithmetic/rns.rs` — `DualRNSContext::extract_k_rns_level`
  (:1553-1658) and the `reconstruct` overflow branch (:1675-1678).
- `crates/exact_transcendentals/src/cram_ct.rs` and `chimera_division.rs`
  — the Div³/FPD implementation whose non-wiring into rescale Phase 0 must
  settle.
- `crates/nine65/src/arithmetic/residue_division.rs` — the
  `BoundedResidueDivider` trait with no implementor; see Phase 4's "New
  material" section.
- `CRAM_OPPORTUNITY_REPORT.md` — the append-only ledger, Phase 4's source
  of truth.
- `.github/workflows/ci.yml` plus `scripts/check_stale_claims.sh`,
  `scripts/regression_scan.sh`, `scripts/audit_modulus_classes.py`,
  `scripts/check_no_panics.sh` — Phase 2's repair targets and the
  mechanism used to verify every other phase's claims going forward.

## Verification checklist (run after every phase)

```
cargo build --release --workspace --exclude nine65-python --exclude nine65-wasm --exclude nine65-ffi
cargo test  --release --workspace --exclude nine65-python --exclude nine65-wasm --exclude nine65-ffi
cargo test -p nine65 --test depth_and_noise --release
cargo test -p nine65 --test time_crystal_verification --release
cd lean4/KElimination && lake build && bash scripts/axiom_audit.sh
bash scripts/check_stale_claims.sh   # once repaired in Phase 2
```

All must be green with zero compile errors. Commit per phase with
descriptive messages tied to this document; push and let PR CI run.
