# S02 review of composite operator correction

Reviewed source: `crates/exact_transcendentals/src/cram_ops.rs`,
`cram_machine.rs`, and `tests/composite_operator_domains.rs` in the
2026-10-03 execution tree. The arithmetic review used an independent agent;
the coordinator checked the resulting scope and tests before publication.

The patch changes `Inv` and `Div` to checked unit inverses for admitted
composite rings. The explicit mod 9, 15 and 15015 results, exhaustive small
ring product search, nonunit refusal, long Euclidean-chain case and lane
permutation/locality tests exercise its main correctness claim. The reviewer
found no blocking defect in the local operator patch. `Schema::apply` returns
residue coordinates. The retired `apply_and_reconstruct` helper is removed;
the review did not treat a sequential CRT observation loop as acceptable.

The implementation is a **local generic schema correction**. It does not
establish the owner's phase-locked sister-tray inverse placement, constant-time
behavior for secret operands, arbitrary shared-factor source frames, or
public BFV integration. Those remain S00/S03/S05/V01 gates. Arrow/emission
tests check their specified reversible and refusal cases; they are not a
repository-wide proof that Garner is absent from every path. Client-side and
isolated test oracles may still reconstruct where their contract permits it.

The initial failing regression and superseded attempts are preserved in the
logs. Final acceptance requires the current-source checks and dependency
review, recorded separately from this review note.
