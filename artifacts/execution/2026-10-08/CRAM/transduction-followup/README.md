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
- Hosted run for `fb656c6`: CRAM correctness and CRAM core formatting/tests/Clippy passed; the architecture and recumbency gates failed again. The focused test commit did not change those production paths. New run: [residue-native gates](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37742019432) and [recumbency gate](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37742019429). Other workflows are still running as of this evidence update.
- Exploratory run [37742221872](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37742221872) passed at `140be8e`. It records five small seeded BFV workload groups with no observed plaintext mismatches. They use the shadow test RNG, debug profile, no refresh and an unverified candidate winding; each comparison group has one NINE65 record, so this is not a v6 comparison or a production refresh/security/performance result. The raw reports and logs are preserved in [`ci-run-37742221872`](ci-run-37742221872/), with hashes in [`SHA256SUMS`](ci-run-37742221872/SHA256SUMS). The degree-256 NTT probe accepted 998244353 and rejected three composite candidates.

## Open CRAM architecture work

The reference `TransductionMap::apply` still forms `raw = sum(r_i*e_i)` and
rank `t = raw/M_A`. The call counter catches the known Garner helper but does
not prove the absence of other scalar reconstruction. The staged PDE and
Safe Basis operators also read canonical scalars internally. Their comments
now say so plainly; this follow-up does not claim the no-internal-projection
application contract is implemented.

PR #173's draft `WindingCRT::try_add` fixes the small counterexample by
reconstructing both operands into `i128`, using `checked_add`, and re-encoding
the sum. Issue #159 explicitly allows making the API fail closed until the
phase contract exists; this is a correctness workaround, but it does not
implement phase transduction. The draft says one reconstruction per add, while
the code calls `to_i128()` on both operands: the existing counter records two
Garner reconstructions per successful add. Its new tests cover addition
boundaries but omit the issue's multiplication-across-laps and parking-overflow
cases. The PR also leaves the old private `add_windings` helper unused after
removing its only call; its T1 fast gate failed at formatting, so Clippy did
not execute and the potential dead-code lint remains unverified. The PR body
says it has no toolchain test results or mandatory performance evidence. Keep
#159 open until the admitted fail-closed API contract and required tests/evidence
are satisfied, or a bounded phase witness is implemented. The issue itself
cautions that this carrier is not the GSO depth-4 FHE path.

PR #174 remains a draft at the old head `457cdc3`. It only adds `#[ignore]` to
two valid `mul_no_relin + decrypt_degree2` diagnostics; it does not test the
retired `BFVEvaluator::mul()` behavior. Issue #130's `--no-fail-fast` command
change was already merged in PR #136; #130 remains open for triage of failures
that the full run exposed, and #174 contains no such triage. The follow-up now
on `main` renames and runs those diagnostics and adds a regression that asserts
`mul()` returns `InvalidParameter`. The old PR run also had three fuzz failures
and its T1 fast gate failed; its T2 suite was skipped. Re-review the PR against
current `main` before treating its claims as resolved.

The separate #135 near-modulus encode/decode defect remains open. An exact
noise-free integer oracle for the exposed single-modulus pair
`q=998244353`, `t=65537` gives `delta=floor(q/t)=15231` and `q mod t=50306`.
With `c=delta*m` followed by the current rounded `t*c/q` decoder, 55,615 of
65,537 messages do not round-trip; the error is deterministic and downward,
up to 3 units (`65536` decodes as `65533`). This isolates the floor-scale
encoding bias from encryption noise. Retiring `BFVEvaluator::mul()` does not
fix it; changing encoding needs separate additive/multiplicative compatibility
tests and parameter review. The exhaustive integer calculation is reproducible
with [`encoder_bias_oracle.py`](encoder_bias_oracle.py); its result is in
[`encoder_bias_oracle.json`](encoder_bias_oracle.json).

## Remaining ordered work

1. Fetch the latest `main`; rebase/review this follow-up against any intervening merge; rerun the focused compiler checks on the exact candidate SHA.
2. Keep PR #173 draft separate. Specify and prove the bounded phase/parking witness and how it recovers the carry. Add signed, multiround, overflow and instrumentation checks. Preserve the known counterexample until the chosen behavior passes.
3. Replace the transduction scalar-rank aggregate only after specifying an input phase witness that determines each canonical carry within a proved uniqueness range. Test source alias pairs such as identical S6 trays with `K=0` versus `K=1`, and use execution counters plus deliberate forbidden-path mutations. Do not assert blanket IID preservation when expanding S6 into `(17,19)`.
4. Keep #148's scalar `canonical()` reads and full-integer nonlinear PDE path out of claims of application hot-path compliance until redesigned or explicitly classified as reference/oracle code. Add caller-level architecture and boundary tests after that routing decision.
5. Resolve the remaining #170 review defects on current main: reject invalid target bases in `try_build` (done in this follow-up) and restore `.gitignore` (done here); check CI on the exact merged SHA.
6. Resume the repository's session DAG from F00/F02 gates: complete the interrupted 27-target debug feature matrix, run the separate extreme target, preserve all failure counts, then advance the earliest unblocked cards. Keep full workspace and hosted CI distinct from the focused results above.
7. PR #174 test follow-up is now in `main`: keep the degree-two diagnostics under accurate names and retain the fail-closed regression for the retired `BFVEvaluator::mul()`. Review its CI on the new `main` SHA, and continue auditing its remaining issue #130/#135 claims before considering the draft resolved.
8. For #173/#159, correct the claimed add reconstruction count to two, decide whether the API must refuse arithmetic until the phase contract exists, add multiplication-across-laps and parking-overflow acceptance tests, remove the unused helper, then supply the missing toolchain and performance evidence. Keep this distinct from GSO depth-4 FHE, which #159 explicitly says it does not affect.
