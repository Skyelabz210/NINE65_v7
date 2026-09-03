# WR-1 — Derived-Transient Exact Evaluator Integration

## Objective

Wire MainOnlyBaseExt and ExactScaleRound into an explicit certified evaluator multiply route. Ciphertext input and output remain mod-Q-only; auxiliary state is derived per operation and dropped before return.

## Required implementation

1. Add a route type and typed failure for unsupported or capacity-invalid contexts.
2. Tensor multiply inputs, derive auxiliary residues from main residues only, then exact scale-and-round.
3. Carry relinearization through the exact route.
4. Prove auxiliary coprimality, NTT compatibility where used, and capacity at construction.
5. Drop or zeroize transient D3 scratch before return.
6. Remove old limb-local rescale from every route selected for exact evaluation.

## Constraints

No float, Garner, MRC, canonical coefficient reconstruction, or persistent auxiliary wire state in production. Safe Basis is the CRAM identity/factor substrate; it does not authorize extra coprime D4 ciphertext lanes. Every capacity or range proof fails closed.

## Acceptance

Keep the old failing vectors and pass them unchanged through exact mul_no_relin and mul. Require bigint oracle equality for tensor, rescale, and relinearization; boundary/tie/negative/u128/U256 cases; ordering invariance where applicable; forbidden-call source gate; and mod-Q-only serialized output. Record BASE/HEAD SHA, tuple, commands, integer timings, and scratch allocation delta.
