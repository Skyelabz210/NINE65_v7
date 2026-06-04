# Lean Formal Verification — Status Record (2026-06-03)

This document records an **actual, reproduced** machine-check of the NINE65
Lean 4 formalization, and clarifies the status of the older Coq proofs.

## Summary

- **Lean is the formalization of record.** The Coq proofs under `proofs/coq/`
  and `verified-innovations/proofs/coq/` are a **legacy NINE65 v2-era
  exploration**, predating the decision to standardize on Lean. They are **not**
  the current verification basis and are not maintained; several do not compile
  and several contain `Admitted` lemmas (see "Legacy Coq" below).
- The Lean development in `lean4/KElimination/` now **builds cleanly end to
  end** with no `sorry` and a single, documented axiom.

## What was verified

- Toolchain: `leanprover/lean4:v4.27.0-rc1` (per `lean-toolchain`), Mathlib at
  the revision pinned in `lake-manifest.json` (`3bdc7047…`).
- Command: `lake build` from `lean4/KElimination/`.
- Result: **`Build completed successfully (3082 jobs)`** — `0` errors, `0`
  "declaration uses 'sorry'" warnings.
- Scope: the `lean_lib` now globs `KElimination` **and all submodules**
  (`globs := #[.andSubmodules \`KElimination]`), so every proof file is
  elaborated. Previously the library target built only the near-empty root
  module (which imports just Mathlib), so **none** of the 19 proof modules were
  ever machine-checked by `lake build` or CI — the prior "Lean4 proofs" CI step
  only checked that the files *existed*.

### Trust base (axioms)

The only `axiom` declared anywhere in the Lean source is:

```
KElimination/AHOP/Hardness.lean:  axiom ahop_hardness …
```

This is an intentional, documented **cryptographic hardness assumption** (the
average-case hardness underlying the AHOP construction). It cannot and should
not be "proved" — it is the security assumption, analogous to assuming LWE/RLWE
hardness. All other results reduce to the standard Lean/Mathlib axioms
(`propext`, `Classical.choice`, `Quot.sound`). No `sorryAx` is reachable.

## What was repaired to get here

The 19 modules had bit-rotted against the pinned Mathlib and 12 of 19 failed to
compile. Repairs were genuine (no `sorry`/`admit`/`axiom`/`native_decide`
introduced, no theorem statements weakened to triviality), and included:

- **Mathlib API drift**: e.g. `List.length_range` now takes an implicit `{n}`;
  `Nat.lt_of_decide_eq_true` removed; `List.not_mem_nil` element implicit; uses
  of `Nat.mod_add_div'`, `Nat.div_lt_iff_lt_mul`.
- **Tactic repairs**: failed `omega`/`split_ifs`/`interval_cases`, redundant
  post-closure tactics, `calc` step realignment, missing typeclass instances,
  and one literal syntax error (`ShadowNTTButterfly`).
- **One genuinely-unprovable statement** (an `interval_cases` over an unbounded
  tail in `StateCompression`) was replaced with a correct induction proving the
  intended bound, rather than papered over.

## Reproducing

```bash
# Install Lean toolchain manager (network: GitHub reachable; release.lean-lang.org is not)
curl -sSfL https://github.com/leanprover/elan/releases/latest/download/elan-x86_64-unknown-linux-gnu.tar.gz | tar xz
./elan-init -y --default-toolchain none
# The pinned toolchain tarball was fetched directly from GitHub and unpacked into
# ~/.elan/toolchains/leanprover--lean4---v4.27.0-rc1 (elan's metadata server was blocked).

cd lean4/KElimination
lake exe cache get   # NOTE: Mathlib olean CDN (lean-lang.org / blob.core.windows.net) was 403 on this
                     # network, forcing a from-source Mathlib build (~3000 modules). On GitHub CI it works.
lake build           # expect: Build completed successfully, 0 errors, 0 sorry
```

## Legacy Coq (not the verification basis)

Inventory as of this date (`coqc` 8.18.0): of 29 `.v` files, **6 did not
compile** and ~12 compiled but contained the **31 `Admitted`** lemmas; several
`Axiom`s are present. Three files are blocked on genuine defects:

- `MontgomeryContext.montgomery_sub_correct` is **false** over `nat` truncated
  subtraction (counterexample `q=5, R=8, x=4, y=3`); the file also contains an
  ill-formed `Fixpoint` (`nat_to_bits` recurses on `n/2`).
- `CyclotomicPhase.distance_symmetric` is **false** without `a<m, b<m`.
- `KElimination_Completed` references `Nat.Prime`, which is undefined in the
  repo / Coq 8.18 stdlib.

Three previously-broken Coq files were repaired to compile during this pass
(`SideChannelResistance`, `OrderFinding`, `MQReLU`) as low-risk cleanups, but
the Coq tree as a whole is **superseded by Lean** and should not be cited as
machine-checked verification.
