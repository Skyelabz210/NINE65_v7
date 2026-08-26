# T7 — Breakthrough-Recording Protocol + Lean Skeletons

**Tier: HANDOFF-SAFE scaffolding.** The protocol doc and skeleton templates
below are meant to be written now. **Do not create any actual `.lean`
file, and do not run `lake build` to "try one" — execution of this
protocol (recording an actual proof) happens only when the owner
explicitly declares a specific result a breakthrough.**

## Why this task looks different from T3–T6

Per the owner (2026-08-26): *"we are still in exploratory phase all proofs
should be sketched and in the event of breakthrough recorded with a formal
proof fit reproducibility."* This is NOT a formalization program — it is a
reproducibility MECHANISM that sits idle until triggered. Building the
mechanism (this task) is safe and mechanical. Using it without a trigger
would be scope creep against an explicit owner instruction.

## Goal

Produce `docs/roadmap/BREAKTHROUGH_RECORDING.md`, containing:

1. The protocol itself (numbered steps, below).
2. Ready-to-use skeleton templates for the strongest current SKETCH+WITNESS
   candidates, as FENCED CODE TEXT inside the markdown doc — NOT as `.lean`
   files. This is deliberate: a skeleton with a `sorry` or an unproven
   `theorem` statement must never enter the Lean build tree, because
   `lean4/KElimination/lakefile.lean` globs and builds every submodule
   automatically (`globs := #[.andSubmodules \`KElimination]`) — dropping a
   half-proved file in would either fail the build or (worse) succeed with
   a silent `sorry`.

## Files (read these first)

- `lean4/KElimination/lakefile.lean` — confirms the glob-all-submodules
  behavior above. Any file placed at
  `lean4/KElimination/KElimination/<Name>.lean` is automatically part of
  `lake build`.
- `lean4/KElimination/KElimination/*.lean` — existing proof files, for
  style reference (imports, namespace conventions) when a real
  breakthrough eventually gets recorded. Do not copy content, just note the
  file header/import style.
- `.github/workflows/lean_proofs.yml` — already builds the globbed library;
  confirm it exists and read what it runs (should just be `lake build` or
  equivalent) — this task does not need to touch it, just confirm it will
  pick up a future recorded proof automatically.
- `CLAUDE.md` (repo root) §Formal Verification — "Lean 4 is the
  formalization of record... a single documented axiom `ahop_hardness`."
  Any new recorded proof should not introduce a second unexplained axiom
  without the same level of documentation this one has.
- cram-substrate `docs/PROOF_SKETCHES.md` — the PS-n register this
  protocol's step 3 (below) updates. Read its current format (PS-1..PS-11)
  before adding to it.
- `docs/CRAM_PUBLIC_MODE.md` §Proof sketches — the PS-CP-n register (the
  CRAM-public-specific sketches) — same format, same update mechanics.

## DO NOT

- **Do not create any `.lean` file as part of this task.** The skeletons
  belong in the markdown protocol doc as fenced text only.
- **Do not run `lake build`** to test a skeleton — there is nothing to
  build yet, and doing so risks leaving stray build artifacts or, worse,
  tempting a "let me just quickly prove this" detour that is exactly the
  scope creep the owner's instruction rules out.
- **Do not mass-formalize.** The candidate list below is candidates ONLY —
  do not start proving any of them as part of executing T7.
- **Do not weave multiple recorded proofs into a shared structure.** The
  protocol's step 2 is explicit: one standalone file per proof, minimal
  imports, zero cross-imports between recorded proofs. A future agent
  executing the PROTOCOL (not this scaffolding task) must follow that too.
- **Do not mark anything PROVED in any doc without the `lake build`
  artifact existing on disk.** This is the corpus-wide verification policy
  (cram-substrate `docs/CLAIM_SCOPE.md`) and applies to this protocol doc's
  own future entries.

## The protocol (write this into `BREAKTHROUGH_RECORDING.md`)

1. **Owner declares a result a breakthrough.** Nothing below fires without
   this. A frontier agent noticing "this sketch looks provable" is not a
   trigger — the trigger is the owner naming a specific PS-n or PS-CP-n
   entry as ready to formalize.
2. **One standalone Lean file per proof.** Self-contained, minimal imports
   (import only what the specific statement needs, not a broad Mathlib
   sweep). Header block (as a doc comment at the top of the file) must
   contain: the statement in prose, the empirical witness test's file path
   and test name, the `lake build` command, today's date, and the git
   commit hash of the code the proof is witnessing. No monolith — each
   file elaborates independently. `lean4/KElimination/lakefile.lean`'s glob
   picks it up automatically; no lakefile edit needed. Zero cross-imports
   between recorded proofs — if two recorded proofs share a lemma, restate
   it in both rather than creating a shared import.
3. **Register transition.** The corresponding PS-n or PS-CP-n entry in
   `cram-substrate/docs/PROOF_SKETCHES.md` or
   `NINE65_v7/docs/CRAM_PUBLIC_MODE.md` moves from status `SKETCH +
   WITNESS` to `MACHINE-CHECKED`, naming the new `.lean` file and recording
   the `lake build` output (0 errors, 0 `sorry`) as evidence.
4. **CI.** `.github/workflows/lean_proofs.yml` already builds the globbed
   library — confirm the new file is picked up (it will be, automatically)
   and that CI goes green on the PR that adds it. No workflow changes
   needed for this step.

## Candidate list (for the owner to pick from — do not act unilaterally)

- **F1 — star-family free inverse** (PS-3): `t⁻¹ mod (c·t+1) = (c·t+1) - c`.
- **F2 — adjacency collapse** (PS-4): the `A = M+1` self-inverse
  K-Elimination shortcut.
- **F4 — parallel-summation CRT** (referenced by PS-CP-6): the Lagrange-
  idempotent identity `Σ r_i·E_i ≡ CRT(r, m) (mod M)`.
- **F8 — one-wave digits**: relevant once T3 (M3) lands and its RNS-limb
  gadget identity has a real implementation to witness.
- **F9 — M2b rescale** (PS-CP-7, capstone): the full elimination-first
  rescale correctness statement — the most valuable but also the most
  involved; likely the last one the owner triggers, not the first.

## Skeleton templates (fenced text ONLY — copy into `BREAKTHROUGH_RECORDING.md`, never into a `.lean` file until triggered)

```lean
-- SKELETON F1 (star-family free inverse)  [PS-3]
-- Statement only. Do NOT create this as a .lean file until the owner
-- triggers F1 specifically.
theorem star_free_inverse (t c : ℕ) (ht : 0 < t) :
    (t * ((c * t + 1) - c)) % (c * t + 1) = 1

-- SKELETON F2 (adjacency collapse)  [PS-4]
theorem adjacency_collapse (M : ℕ) (X : ℕ) (h : X < M * (M+1)) :
    X / M = (X % M + (M+1) - X % (M+1)) % (M+1)

-- SKELETON F9 (M2b rescale, capstone)  [PS-CP-7] — statement sketch only:
--   for the manufactured chain (t, D1, D2, ...), |X| <= 2*N*Q^2:
--   pipeline(X) = floor((X + Delta/2)/Delta) mod Q, under certificate
--   4*N*Q + 1 < C (the anchor-subset capacity).
-- This one needs the most care translating into Lean's type system
-- (U256/fixed-width arithmetic vs. ℕ/ℤ) — expect it to need real design
-- work, not a direct transcription, when it is eventually triggered.
```

## Acceptance criteria

- `docs/roadmap/BREAKTHROUGH_RECORDING.md` exists with the protocol (4
  numbered steps above) and the skeleton templates as fenced text.
- No `.lean` file created anywhere in this task.
- No `lake build` run as part of this task.
- The candidate list is present but explicitly marked as owner-selectable,
  not a work queue.

## Escalate-if

- Someone (a future agent, or a misreading of this card) starts treating
  the candidate list as a to-do list — stop, re-read the "why this task
  looks different" section above, and confirm with the owner before
  proceeding.
