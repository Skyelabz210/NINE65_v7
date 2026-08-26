# Breakthrough-Recording Protocol

This is a **reproducibility mechanism, not a formalization program.** The
CRAM-public work is in an exploratory phase: proof sketches
(`docs/CRAM_PUBLIC_MODE.md` §Proof sketches, cram-substrate
`docs/PROOF_SKETCHES.md`) are the primary, living record. Lean formalization
happens only for a result the owner has explicitly declared a breakthrough
— individually, reproducibly, one proof at a time. There is no queue, no
mass-formalization pass, and no agent-initiated trigger.

See `docs/roadmap/T7_BREAKTHROUGH_RECORDING_PROTOCOL.md` for the task card
that produced this document (context on why it exists in this shape).

## The protocol

1. **Owner declares a result a breakthrough.** This is the only trigger.
   Nothing below fires without an explicit owner statement naming a
   specific PS-n or PS-CP-n entry as ready to formalize.

2. **One standalone Lean file per proof.** Requirements:
   - Self-contained, minimal imports — import only what the specific
     statement needs.
   - A header doc comment containing: the statement in prose, the
     empirical witness test's file path and test name, the `lake build`
     command, today's date, and the git commit hash of the code the proof
     is witnessing.
   - No monolith. `lean4/KElimination/lakefile.lean` globs and builds every
     submodule automatically (`globs := #[.andSubmodules \`KElimination]`),
     so a new file at `lean4/KElimination/KElimination/<Name>.lean` is
     picked up with no lakefile edit.
   - Zero cross-imports between recorded proofs. If two recorded proofs
     need a shared lemma, restate it in both rather than introducing a
     shared import — this keeps each recorded proof independently
     auditable and independently removable.

3. **Register transition.** The corresponding entry in
   `cram-substrate/docs/PROOF_SKETCHES.md` or
   `NINE65_v7/docs/CRAM_PUBLIC_MODE.md` §Proof sketches moves from status
   `SKETCH + WITNESS` to `MACHINE-CHECKED`, naming the new `.lean` file and
   recording the `lake build` result (0 errors, 0 `sorry`) as the evidence.
   Per the corpus-wide verification policy (cram-substrate
   `docs/CLAIM_SCOPE.md`): PROVED means a machine-checked artifact on disk.
   Nothing is PROVED before this step completes.

4. **CI.** `.github/workflows/lean_proofs.yml` already builds the globbed
   `lean4/KElimination/` library. A newly recorded proof is picked up
   automatically — no workflow change needed. Confirm the PR that adds the
   file goes green on this workflow before merging.

## Candidate list

For the owner to pick from. This is not a work queue — an agent does not
start proving one of these unprompted.

- **F1 — star-family free inverse** (PS-3): `t⁻¹ mod (c·t+1) = (c·t+1) - c`.
- **F2 — adjacency collapse** (PS-4): the `A = M+1` self-inverse
  K-Elimination shortcut.
- **F4 — parallel-summation CRT** (referenced by PS-CP-6): the Lagrange-
  idempotent identity `Σ r_i·E_i ≡ CRT(r, m) (mod M)`.
- **F8 — one-wave digits**: relevant once M3 (T3) lands and its RNS-limb
  gadget identity has a real implementation to witness.
- **F9 — M2b rescale** (PS-CP-7, capstone): the full elimination-first
  rescale correctness statement. Most valuable, most involved — expect
  this to need real Lean design work (translating the U256/fixed-width
  arithmetic into Lean's type system), not a direct transcription.

## Skeleton templates

Statements only — NOT proofs, and NOT `.lean` files. These are fenced text
in this document so nothing half-proved can ever enter the Lean build tree
by accident. Copy the relevant one into a real file ONLY after step 1
(owner trigger) fires for that specific candidate, and only after actually
proving it (a skeleton with an unproven `theorem` line and no proof body
would fail `lake build` — these are statement shapes to prove FROM, not
files to drop in as-is).

```lean
-- SKELETON F1 (star-family free inverse)  [PS-3]
theorem star_free_inverse (t c : ℕ) (ht : 0 < t) :
    (t * ((c * t + 1) - c)) % (c * t + 1) = 1

-- SKELETON F2 (adjacency collapse)  [PS-4]
theorem adjacency_collapse (M : ℕ) (X : ℕ) (h : X < M * (M+1)) :
    X / M = (X % M + (M+1) - X % (M+1)) % (M+1)

-- SKELETON F9 (M2b rescale, capstone)  [PS-CP-7] — statement sketch only:
--   for the manufactured chain (t, D1, D2, ...), |X| <= 2*N*Q^2:
--   pipeline(X) = floor((X + Delta/2)/Delta) mod Q, under certificate
--   4*N*Q + 1 < C (the anchor-subset capacity).
```

## What this protocol is NOT

- Not a mandate to formalize everything in the proof-sketch registers.
- Not a signal that SKETCH + WITNESS status is insufficient for ongoing
  work — it is the normal, expected status during the exploratory phase.
- Not something an agent self-triggers by noticing a sketch "looks
  provable." The owner's explicit declaration is the only trigger.
