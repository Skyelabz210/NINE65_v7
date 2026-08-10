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
