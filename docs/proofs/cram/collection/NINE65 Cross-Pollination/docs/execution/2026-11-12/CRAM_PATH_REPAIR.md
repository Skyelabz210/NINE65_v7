# CRAM path repair execution record

Base: `5481a1bec7c2c34e28b067d8365450d95b090753`.

The requested order is implementation repair, functional and security checks,
then proof closure. This bounded change does not replace encrypted BFV with an
unverified transduction adapter or assert a new proof.

| Work | Reason and scope | State | Evidence and next step |
| --- | --- | --- | --- |
| P1 | Remove the exported reference machine's implicit Garner/default-zero projection. Preserve declared canonical boundary projection with a prepared direct-CRT sum, distinct from residue computation. | Complete | Baseline regression observes a Garner call; repaired public execution/projection path preserves residues and returns the same canonical result without that call. |
| P2 | Enforce target-lane identity in typed lift evidence, in addition to its target modulus. | Complete | Same-modulus/wrong-lane evidence is refused; correctly bound repeated target views remain supported. |
| P3 | Run existing affected tests, new boundary regressions, no-float and no_std checks, and independent code review. | Complete for this slice | 692 package tests pass, zero failed/ignored; no_std, strict library Clippy, dependent nine65 library check and runtime no-float checks pass. Independent review found no blocker and reran 39 focused tests. |
| P4 | Record scope and remaining routing/state obligations. | Complete | Limits below and README/proof-map links distinguish this repair from remaining architecture work. |

Implementation owner: CRAM path repair task. Review is independent and read-only.
Only the isolated `codex/cram-projection-no-garner-2026-11-12` worktree is edited.
Existing snapshots and historical evidence remain unchanged.

## Repaired behavior

`Cram::project` is an explicitly requested boundary operation. It preserves
the anchored read when the reference adapter has a known winding. Otherwise
it now uses a prepared direct CRT sum, instead of calling Garner and
substituting zero when that call fails. It returns the canonical representative
in `[0,M)`, not an invented integer-line lift of heterogeneous operations.
`project_integer` continues to refuse states with no integer winding.

The constructor now rejects empty bases, zero/unit moduli, overlapping factors
and products whose adjacent anchor cannot fit. Pairwise-coprime composites
remain supported. This is an intentional tightening of previously unchecked
input, not a claim that overlapping dependent views are inherently invalid:
this particular adapter has a product-capacity contract. `configure` returns
`InvalidBasis` rather than panicking for those inputs. Projection-request
counts and the old `destructive_reads` accessor remain compatible; the clearer
`canonical_reconstructions` accessor states what is actually counted. Neither
read destroys the source state.

Typed lift evidence already carried a lane index and modulus. The consumer
checked only the modulus. It now also checks the lane identity, including
when two requested target views share a modulus. This binds the label, not
the provider's mathematical source/provenance.

## Direct-CRT review argument (not a new formal theorem)

For pairwise-coprime moduli `p_i>1`, let `M=product p_i`, `M_i=M/p_i`, and
`e_i=M_i*(M_i^-1 mod p_i)`. The public inverse exists by the constructor's
coprimality check. `e_i` is 1 modulo `p_i` and 0 modulo every other lane, so
`sum r_i*e_i mod M` has every required residue. The pairwise-coprime product
gives a unique representative in `[0,M)`. No sequential digit/carry emission
or reconstruction of earlier partial solutions occurs.

Each prepared weight is below M. Each term is reduced using the existing
overflow-safe `mulmod` before accumulation. For normalized sum and term,
`sum >= M-term` chooses `sum-(M-term)`; otherwise `sum+term < M`. Thus neither
branch needs an overflowing i128 intermediate. This argument concerns this
projection only, not every stored-winding arithmetic operation in the adapter.

Tests exhaust all 105 states of `{3,5,7}` and all 30,030 states of composite
`{6,35,143}`, plus selected near-i128-limit cases and the actual configured
heterogeneous execution API. The no-Garner test instruments the named
primitive; source review separately checks the direct weighted-sum algorithm.

## Executed validation

Rust 1.89.0; offline builds; test profile opt-level 3 with debug assertions and
overflow checks retained. Commands were run in this isolated worktree:

```sh
CARGO_PROFILE_TEST_OPT_LEVEL=3 cargo test --offline -p exact_transcendentals --no-fail-fast -- --test-threads=1
cargo check --offline -p exact_transcendentals --no-default-features
cargo clippy --offline -p exact_transcendentals --lib -- -D warnings
cargo check --offline -p nine65 --lib
(cd crates/exact_transcendentals && python3 scripts/check_no_floats.py)
python3 scripts/check_no_floats_runtime.py --self-test
```

The package run executes 605 unit and 87 integration tests: 692 passed,
zero failed and zero ignored. The doc-test target contains zero tests and is
not counted as test evidence. Library Clippy passes with warnings denied.
Runtime no-float scanners report zero violations in 34 leaf-crate files and
147 nine65 runtime files. The leaf scanner initially failed because it was
invoked from the workspace root; rerunning from its documented crate root
passed. The failed invocation and baseline red regression are preserved with
the successful logs in the [artifact packet](../../../artifacts/execution/2026-11-12/cram-path-repair/manifest.json).

## Remaining work and safety boundary

- `Cram` still stores `Winding`; this patch labels that reference behavior and
  does not claim it has become the no-stored-K substrate.
- The encrypted public/main wrappers still route to their existing BFV/exact
  evaluators, not to the adjacent-anchor heterogeneous provider. Their required
  phase, bound, noise and key contracts need an explicit integration change.
- Generic evidence providers still require caller-certified source/phase
  provenance. Matching lane/modulus labels alone do not establish it.
- Other reference modules still expose Garner routines. This patch removes
  the actual `Cram::project` route, not every occurrence in the repository.
- Direct boundary CRT and existing `mulmod` make no new constant-time claim.
  There was no full security audit, encrypted rerun, Lean run or production
  admission change. Those remain subsequent, separately scoped work.
