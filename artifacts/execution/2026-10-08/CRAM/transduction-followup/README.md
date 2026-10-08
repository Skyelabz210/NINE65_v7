# CRAM transduction review follow-up

Reviewed start: `45ecd6b787e7bd98653470911666c92efaeb9202` (PR #171 merge).
Toolchain: Rust 1.89.0. These focused checks use direct `rustc`, so they do
not claim a full workspace Cargo/CI pass. Full output and the exact commands
are retained beside this file.

## Changes

- Connected both lifted-transduction entry points to `TransductionMap::try_build` (merged separately as PR #171).
- Added typed refusal for zero and negative target moduli. Composite targets and overlapping views remain supported.
- Replaced signed-overflow-prone modular normalization with `rem_euclid`; made large-modulus multiplication reduce through `u128`; reject non-positive moduli for modular inverse.
- Restored the ignore patterns that PR #170 removed and fixed a missing `alloc::vec` import, verified by the `no_std` build.
- Corrected the transduction formula and comments: CRT rank `t` corrects the canonical representative; it is not external winding `K`. Correct residues and shuffle invariance do not establish architecture compliance. The scalar rank aggregate remains an explicit gap against the application contract.
- Added thread-local test instrumentation around `garner_reconstruct`. The transduction unit test proves a direct Garner substitution fails; this counter only covers that named primitive.
- Added public-boundary tests for invalid moduli, shared-factor/overlapping targets, capacity errors, and signed `i128` boundaries.

## Results

- Standard library build: passed.
- `no_std` library build: passed after adding the missing macro import.
- Library unit tests: 558 passed.
- `a2_residue_native`: 5 passed.
- `lifted_transduction_module`: 5 passed.
- `safe_basis_lifted_transduction`: 9 passed.
- `cram_gates`: 16 passed.
- New public boundary tests: 6 passed in debug and 6 passed with optimized Rust.
- Seeded Python unbounded-integer oracle: 2,048 modular-reduction/multiplication/inverse cases; all 6,144 outputs matched.
- Deliberate Garner mutation: new call counter fails the test with 25 calls; the prior permutation-based test alone passed that mutation.
- `clippy-driver` direct library check with `-D warnings`, formatting and whitespace checks: passed.
- PR #174 follow-up: both renamed `mul_no_relin + decrypt_degree2` diagnostics passed in Cargo; the new `test_retired_mul_fails_closed` regression also passed. The tests distinguish supported degree-two diagnostics from retired `BFVEvaluator::mul()`.
- Hosted run for `ff1f633`: CRAM correctness and ordinary CI T1 gates passed. Broader gates remain red: architecture scans still find scalar Garner/CRT reconstruction (21 constructs across 11 files), recumbency enforcement fails, and exact noise-accounting is not active. See [CRAM-public gates](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37741047363), [residue-native gates](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37741047472), and [recumbency gate](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37741047468). These are open architecture/workflow requirements, not passed checks.

## Open CRAM architecture work

The reference `TransductionMap::apply` still forms `raw = sum(r_i*e_i)` and
rank `t = raw/M_A`. The call counter catches the known Garner helper but does
not prove the absence of other scalar reconstruction. The staged PDE and
Safe Basis operators also read canonical scalars internally. Their comments
now say so plainly; this follow-up does not claim the no-internal-projection
application contract is implemented.

PR #173's draft `WindingCRT::try_add` fixes the wraparound output by
reconstructing both operands into `i128` and re-encoding the sum. That is a
functional fail-closed path, but it is not the accepted residue-native
phase/witness implementation. It also deletes `add_windings` without removing
the now-unused private helper, so strict Clippy may reject the draft. Review
the full-tree draft against `gh pr checks` before any merge. Keep the S8 carry
defect open until an explicitly admitted witness exists or the arithmetic
operation is disabled fail-closed under the required interface.

## Remaining ordered work

1. Fetch the latest `main`; rebase/review this follow-up against any intervening merge; rerun the focused compiler checks on the exact candidate SHA.
2. Keep PR #173 draft separate. Specify and prove the bounded phase/parking witness and how it recovers the carry. Add signed, multiround, overflow and instrumentation checks. Preserve the known counterexample until the chosen behavior passes.
3. Replace the transduction scalar-rank aggregate only after specifying an input phase witness that determines each canonical carry within a proved uniqueness range. Test source alias pairs such as identical S6 trays with `K=0` versus `K=1`, and use execution counters plus deliberate forbidden-path mutations. Do not assert blanket IID preservation when expanding S6 into `(17,19)`.
4. Keep #148's scalar `canonical()` reads and full-integer nonlinear PDE path out of claims of application hot-path compliance until redesigned or explicitly classified as reference/oracle code. Add caller-level architecture and boundary tests after that routing decision.
5. Resolve the remaining #170 review defects on current main: reject invalid target bases in `try_build` (done in this follow-up) and restore `.gitignore` (done here); check CI on the exact merged SHA.
6. Resume the repository's session DAG from F00/F02 gates: complete the interrupted 27-target debug feature matrix, run the separate extreme target, preserve all failure counts, then advance the earliest unblocked cards. Keep full workspace and hosted CI distinct from the focused results above.
7. PR #174 test follow-up is now in `main`: keep the degree-two diagnostics under accurate names and retain the fail-closed regression for the retired `BFVEvaluator::mul()`. Review its CI on the new `main` SHA, and continue auditing its remaining issue #130/#135 claims before considering the draft resolved.
