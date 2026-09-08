# T4 — M4: Re-Pin the Measured Verdicts

**Tier: FABLE-TIER.** This is doctrine-driven re-scoping, not blind test
inversion — get the SCOPE distinction below right before touching any test.

**Status: LANDED (2026-08-26).** `EmissionClass::EliminationFirst` added;
`mul_manufactured_gadget` records it (never-vacuous test:
`manufactured_gadget_multiply_ledger_shows_elimination_first` in
`tests/m2b_manufactured_rescale.rs`). The general-path discriminators
(`multiply_is_recorded_as_a_materialization_pinned`,
`ct_multiply_is_not_lane_independent_every_lane_moves`) were correctly
LEFT UNCHANGED, per the scope distinction below — see
`docs/CRAM_PUBLIC_MODE.md` M4 for the landed, precisely-scoped claim
(rescale+relin core only; `canonicalize_dual_anchor` still materializes
separately; depth ≤ 2 per the M3 finding).

**Re-checked 2026-09-04 against issue #65.** Issue #65 cites `mul` still
showing `Materialization` in `EmissionClass` as an unmet M2b/M3
criterion. It is describing `mul_dual_public` / `eval.mul()` — the GENERAL
path in the scope table directly below, which this task deliberately left
unchanged and which the "Do not invert" rule right below names by
function. That path's classification is accurate to what the code does
today (still `k_elim_rescale_dual → to_u256_level` and
`extract_digit_dual`) and, per this document's own scope rule, must stay
`Materialization`. The manufactured-gadget path issue #65's title actually
refers to (M2b/M3) is complete and already ledgered `EliminationFirst`, as
this file says above. No inversion of the general path was made or is
planned here; see the comment thread on issue #65.

## Goal

After M3 (T3) lands, the manufactured-chain multiply path
(`mul_dual_public_manufactured` / `CramPublicEvaluator::mul_manufactured`)
performs zero raw-tensor materialization: M2b already made the rescale
elimination-first, and T3 makes the relinearization elimination-first too.
M4 records that honestly in the emission ledger and updates the tests that
currently pin the OLD (materializing) verdict — **for the manufactured path
only**.

## Critical scope distinction (read this before editing any test)

There are **two separate multiply paths** in this codebase, and only ONE of
them changes behavior after T3:

| Path | Config | Rescale | Relin (pre-T3) | Relin (post-T3) | Ledger class after T4 |
|---|---|---|---|---|---|
| `mul_dual_public` / `eval.mul()` | general (`secure_128`, `secure_192`, `test_medium_insecure`, ...) | `k_elim_rescale_dual` (materializing) | `extract_digit_dual` (materializing) | **unchanged** — T3 does not touch this path | `Materialization` (unchanged) |
| `mul_dual_public_manufactured` / `eval.mul_manufactured()` | manufactured chains only | `k_elim_rescale_manufactured` (elimination-first, M2b) | `extract_digit_dual` (materializing, pre-T3) → RNS-limb gadget (elimination-first, post-T3) | elimination-first | `EliminationFirst` (new, post-T3) |

**Do not invert `multiply_is_recorded_as_a_materialization_pinned`**
(`tests/cram_public_mode.rs`) — it tests the GENERAL path (`eval.mul()` on
`SecureConfig::test_medium_insecure()`), which stays a materialization
forever; T3 never touches it. Inverting it would be a false claim.
Similarly, **do not invert
`ct_multiply_is_not_lane_independent_every_lane_moves`**
(`tests/residue_space_ciphertext.rs`) — it also runs on a general
(`secure_128`) config. Both stay as permanent, correctly-scoped
measurements of the general path.

What DOES need a new (not inverted) test: the manufactured path's ledger,
which currently already shows 0 `Materialization` for the RESCALE half
(M2b) but still shows materialization events from relinearization until T3
lands. Once T3 lands, add a NEW assertion (do not repurpose the existing
pinned test) that `eval.mul_manufactured()`'s ledger shows **zero**
`Materialization` events and (once this task adds it) the
`EliminationFirst` class instead.

## Files

- `crates/nine65/src/ops/cram_public.rs`:
  - `EmissionClass` enum (near the top) — add `EliminationFirst` alongside
    the existing `LaneLocal` / `Materialization` variants. Doc comment
    should state: R4-under-certificate composition, zero raw-tensor
    materialization, and point at the M2b/M3 sections of
    `docs/CRAM_PUBLIC_MODE.md`.
  - `EmissionLedger::materialization_count` / `lane_local_count` — add a
    matching `elimination_first_count`, and update `report()`'s summary
    string to include it.
  - `mul_manufactured` (search for the function) — currently likely records
    `Materialization` unconditionally (inherited from `mul_dual_public_manufactured`'s
    relin step); once T3's RNS-limb relin lands, change this call site to
    record `EliminationFirst` instead.
- `tests/cram_public_mode.rs`: `multiply_is_recorded_as_a_materialization_pinned`
  — read only, do not modify (see scope distinction above).
- `tests/residue_space_ciphertext.rs`: `ct_multiply_is_not_lane_independent_every_lane_moves`
  — read only for its doc comment (reword per below), do not invert its
  assertion (it is about the general path).
- `tests/m2b_manufactured_rescale.rs` — add the new
  `manufactured_multiply_ledger_shows_zero_materialization` test here (or a
  new `m2b_manufactured_rescale.rs`-adjacent file if this one is getting
  long).

## DO NOT

- **Do not delete or invert the general-path discriminator tests** —
  see the scope table above. They measure a different, unchanged path.
- **Do not claim i.i.d. lane-locality for the manufactured multiply.** Even
  after M2b+M3, the multiply still couples lanes through COMPLIANT
  cross-lane reads (Δ-lane drops, the anchor-certificate ladder read) — that
  coupling is not a fault (arrow-harness qualified, see roadmap README rule
  3), but it also means an i.i.d.-independence claim would be false. The
  honest claim is "elimination-first (no raw materialization) + gate-
  compliant coupling," not "lane-independent."
- **Do not extend any claim to physical side channels.** The scope
  statement in cram-substrate `docs/CLAIM_SCOPE.md` (algorithmic/logical
  domain only) stands unchanged by this task.
- **Do not delete `Materialization` as an `EmissionClass` variant** — the
  general path still uses it and always will.

## Steps

1. Add `EmissionClass::EliminationFirst` with a doc comment distinguishing
   it from `Materialization` (same shape as the existing variants' doc
   comments — cite the gate qualifications, per `docs/CRAM_PUBLIC_MODE.md`
   §Arrow-harness qualification).
2. Add `EmissionLedger::elimination_first_count()`, update `report()`.
3. Update `mul_manufactured`'s recording call — **only if T3 has landed**;
   if T3 has not landed yet, this task should record `EliminationFirst` for
   the rescale-only portion is NOT a valid interim state (recording a class
   that claims "zero raw-tensor materialization" while relin still
   materializes would be dishonest) — sequence T3 first, or scope this
   task's ledger-class change to land atomically with T3's relin swap.
4. Add the NEW manufactured-path ledger test (see scope distinction above)
   asserting `materialization_count() == 0` and `elimination_first_count()
   > before` after a manufactured multiply.
5. Reword `ct_multiply_is_not_lane_independent_every_lane_moves`'s doc
   comment (general path, unchanged assertion) to add a note pointing at
   the manufactured path's DIFFERENT and separately-tested status, so a
   future reader does not assume this test covers both paths.
6. Wire the T2 counter guardrails (no-Garner, no-centering) into CI as
   blocking checks — this is T6's job, but note the dependency here so T4
   doesn't ship without it being picked up next.
7. Add a proof-sketch entry recording the M4 re-scope (extend PS-CP-3's
   "gate-qualified conclusion" language, or add a new PS-CP-n specifically
   for the manufactured path's elimination-first status).

## Commands

```
cargo test -p nine65 --test cram_public_mode --release --features allow_insecure
cargo test -p nine65 --test m2b_manufactured_rescale --release --features allow_insecure
cargo test -p nine65 --test residue_space_ciphertext --release --features allow_insecure
cargo test -p nine65 --lib --release
```

## Acceptance criteria

- General-path tests (`multiply_is_recorded_as_a_materialization_pinned`,
  `ct_multiply_is_not_lane_independent_every_lane_moves`) still pass,
  UNCHANGED assertions (only doc comments touched).
- New manufactured-path ledger test passes: 0 `Materialization`, nonzero
  `EliminationFirst`, after a real `mul_manufactured()` call.
- `docs/CRAM_PUBLIC_MODE.md` M4 milestone entry updated from "invert the
  pins" language to the actual scoped outcome (this card's scope
  distinction, condensed).
- Full lib suite green.

## Escalate-if

- T3 has not landed and there is pressure to ship the ledger-class change
  anyway — do not; a claimed `EliminationFirst` multiply that still
  materializes internally is worse than the current honest
  `Materialization` label. Escalate rather than ship a false claim.
- Any test outside the two named general-path discriminators looks like it
  ALSO needs inversion — stop and check its config (grep for
  `SecureConfig::` or `FHEConfig::manufactured_m2b_insecure` in the test
  function) before touching it; the manufactured/general split is the whole
  point of this task.
