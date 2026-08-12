# mana

CRT/RNS lane substrate with Glowworm swarm optimisation over `ManaStream`
positions. Currently **disconnected from the nine65 FHE path**.

## CRAM opportunity action items

Mirrored from `CRAM_OPPORTUNITY_REPORT.md` (pass 1). Level-2 nodes are
`pending`.

- `[24]` `src/anchor.rs:93,100` — `exact_divide(v_alpha, v_beta, divisor)` and
  its checked variant are already a two-anchor exact division, which is the
  mechanism `nine65` lacks (see that crate's `[23]`). The opportunity is the
  connection, not a rewrite. → `fifth-operator-rescale`
- `[29]` `src/lane.rs:214-248`, `src/parallel.rs:86-154` — rayon over CRT
  lanes. The lanes are i.i.d. and statically enumerable, so work-stealing
  nondeterminism buys nothing and costs reproducibility.
  → `deterministic-lane-parallelism`

**A1 status:** clean. The only `f32`/`f64` occurrence in this crate is the
claim about A1 in `src/lib.rs:14`, not a use of one.

## CRAM Opportunity Index — open action items (2026-08-12)

Mirrored from `CRAM_OPPORTUNITY_REPORT.md` entries [31]–[34]; Level-2 nodes pending — do not improvise the refactors:
- [31] No deterministic lane executor: parallel dispatch is rayon-only (now off). Route: `deterministic-lane-parallelism`.
- [32] `Lane::mul` uses `%` reduction; `PersistentLane` Montgomery chain measures 2.41x faster — `ManaStream` doesn't use it. Route: `crt-to-cram-substrate`.
- [33] `AnchorContext::exact_divide_stream` does per-coefficient partial-CRT of both codices — audit before hot-path use. Route: `reconstruction-retirement`.
- [34] No bridge between `TransductionMap` (exact_transcendentals) and `ManaStream` lanes. Route: `iid-heterogeneous-transduction`.

Pre-change sequential baseline (4-core idle box, no rayon): mul 310/270/229/224 M coeff-ops/s at LOW(3×1024)/MED(6×4096)/HEAVY(10×16384)/ULTRA(16×32768); add 1529/938/506/450.
- [39] REFINES [32]: the mul speedup is divider-avoidance, not Montgomery. Measured: Shoup fixed-b on TRUE residues 3.33x ≥ Montgomery 3.25x (twisted) ≥ Barrett 1.43x ≥ plain % 1.00x, outputs bit-identical. Method of record: precomputed lane constants (Shoup/Barrett), residues stay true; PersistentLane's Montgomery form is a retirement candidate. Route: `crt-to-cram-substrate`.
