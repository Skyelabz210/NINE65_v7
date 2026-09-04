# WR-4 — Typed Lift-Aware Transduction Provider

## Objective

Promote staged lifted transduction into a typed provider for exact CRAM operations without storing a general scalar winding or leaking coprime residues on the wire.

## Required implementation

1. Re-run the theorem battery on current main.
2. Export lifted transduction only after proof/test gates pass.
3. Provide typed on-demand K modulo target-lane lift evidence.
4. Return typed failure for absent evidence or invalid target-basis/range contracts.

## Invariants

X equals g plus K times M_A. Target residue equals g residue plus K modulo target times M_A modulo target. Keep product-space, reversible topology, disjoint repacking, and overlapping-view LCM capacity distinct. Shadow-11 is integrity/disambiguation, not a coprime K-Elimination anchor. D1/D2/D3 use is allowed; D4 publication is prohibited.

## Acceptance

Exact theorem regression on current main; no scalar K convenience state; typed target/corridor failures; no new serialization of coprime lift/anchor data; and a WIRE-Q source gate.
