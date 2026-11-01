# PR integration and corrected gates — 2026-11-01

PRs [#197](https://github.com/Skyelabz210/NINE65_v7/pull/197) and
[#198](https://github.com/Skyelabz210/NINE65_v7/pull/198) merged independently.
[#201](https://github.com/Skyelabz210/NINE65_v7/pull/201) reconciles their
changes, the recumbent work in #195 and the older conflicting branch #187.
See [current refresh status](../PUBLIC_REFRESH_STATUS.md) for capability and
production-security scope. The original native refresh evidence is unchanged.

| Finding | Repair and enforced behavior |
| --- | --- |
| #187 malformed target modulus | Preserve later typed target validation; reference NTT construction now rejects zero, one, even moduli and overflowing root orders before arithmetic |
| #187 generated files and release probe | Preserve generated-output ignores; seeded exploratory runner accepts debug only; recorded probe profile reaches comparison normalization |
| Overflow metadata and obsolete issue-29 patch | Use checked/exact modulus metadata for runtime decisions; retain scalar field only for compatibility; negative controls reject its production use |
| New research unwrap/expect sites | Propagate typed errors, validate DAG dependencies, and name the separate native test file as a test module; panic baseline unchanged |
| Symmetric multiplication boundary | Center input lifts, evaluate exact BFV tensor scale, then relinearize with the secret square; test nonconstant coefficients and the minus-one boundary |
| GSO metadata-only collapse | Private local bounds admit checked multiplication before evaluation; every admitted result is checked; exhausted or unknown provenance refuses |
| Unfunded chain fixtures | Six-prime test fixture proves three worst-case layers with the existing scalar noise model; original plaintext oracles remain |
| Unbound sister-tray claim | Execute encrypted counterexamples and exact phase/scale/error identities; refuse missing source-phase binding; retain historical attempt as explicitly opt-in known failure |
| Stale triple-precharge resource assertion | Pin exact 113-bit ledger; first square refuses at 138 error bits against a 137-bit limit; no admission threshold raised |
| Float grep matched prose/version strings | Use the existing tested Rust token scanner on the same paths; missing files still fail |
| Modulus audit compared with dated evidence | Keep dated snapshot unchanged; regenerate and check `modulus_class_audit_current.json` |
| Full-suite execution time | Optimize nine65 test arithmetic at level 2; default targets, assertions, overflow checks and `--no-fail-fast` remain enabled |

The GSO field privacy change affects a experimental API. Use
`inner()` for read-only access and `try_mul_symmetric` for bounded operations.
The local bound assumes well-formed matching keys; it is not a malicious-key
proof or production-security certificate. Public GSO multiplication refuses
until its arithmetic and complete error bound are admitted.

Focused verification includes 15 GSO tests, five benchmark tests, two optional
GSO integration tests, both sister-tray counterexamples, the triple-precharge
preflight, all 20 reference NTT tests, ten main-only base-extension tests,
metadata negative controls, and the relevant feature compile check. Full
workspace execution reached every target; the service socket tests were rerun
with socket access (28 passed). The repaired nine65 library target passed
1,129 tests with zero failures and 139 explicitly ignored tests in 298.23s.
Workspace/all-target Clippy passed with warnings denied. Hosted results are
attached to PR #201's exact checked head; the native five-cycle archive is not
presented as a new run of this integration.


Further hosted checks exposed an absent `ntt_roundtrip_prime_regression` target
and an old expanded-phase refusal fixture at the former 512-bit boundary.
The restored target exercises all 37 current main/anchor `(degree, modulus)`
pairs, including the distinct N32768 anchor basis. Both fallible backends also
reject invalid moduli and full-width primes outside the Montgomery range before
arithmetic. The expanded-phase fixture
now proves nine squared lanes fit U1024 and that sixteen full-width coprime
lanes exceed its actual capacity; no capacity threshold changed.

The hosted Montgomery timing observation is preserved in
[ct_observation.json](../../artifacts/execution/2026-11-01/pr-integration/ct_observation.json).
The old test confounded input class with separate batch addresses. Its repair
copies operands into one fixed-address buffer before timing; the threshold,
sample count, crop and control stay unchanged. An injected class-timing
negative control checks the sampler. One local optimized diagnostic was
inconclusive, so it is not presented as resolution of the hosted observation
or constant-time admission. The new hosted run must evaluate the repaired
harness; the circuit's constant-time posture remains unestablished.


A subsequent hosted run completed the restored NTT target and reached the
legacy shape target, revealing its missing `allow_insecure` fixture feature
and two historical ignored tests. The workflow now enables that fixture
feature and executes an active test of typed legacy refusal, unchanged
residue lanes and unchanged plaintext. The old success claims remain marked
historical, with their misleading unlimited-depth explanations removed.

The same all-measurements timing run exposed a prime-drop class association.
Both prime-drop contrasts now reuse fixed lane addresses before timing. An
address/output regression and the independent integer-division oracle pass;
one local run per contrast was below the existing threshold. Both the hosted
observation and local diagnostics remain in the observation artifact, without
claiming the original cause was established or that the circuit is constant-time.


The runtime float gate also had a 2,000-line test-code heuristic. Extending the
timing module made it misclassify two statistical reporting casts as production
arithmetic. It now reuses balanced test-item detection and Rust comment/string
stripping. Negative controls reject production code after a long test module,
feature-enabled floats, scientific notation and suffixed float literals. The
existing explicit offline exemptions and separate benchmark/test gate remain;
no runtime floating-point operation was introduced.


The seeded legacy-shape fixture runs in the optimized test profile. The release
library's `allow_insecure` compile-time prohibition is preserved; adding the
fixture feature to a release integration invocation correctly fails compilation.
This fixture's debug-profile command is the one validated locally.


The same profile review caught incompatible release/example instructions in
README, the example header, its design note and two CLAUDE feature descriptions.
They now use the supported optimized development profile. Release-only library
protection remains unchanged. Historical benchmark numbers are not remeasured
or relabeled by these instruction fixes.


Inline review also found three accepted-input boundary errors in the imported
`qmnf_crtbigint` reference crate. Montgomery reduction now retains the 129th
sum bit for full-width odd moduli; WASSAN reconstruction uses Horner evaluation
so the unused final base power cannot overflow; rational ordering compares
continued fractions instead of overflowing cross-products. The regressions
first reproduced all three failures. All 26 unit and 12 integration tests,
26 release unit tests and warnings-denied all-target Clippy pass.


The final-head timing run subsequently found a Montgomery multiplication class
association (signal 6.0288, control 2.0404; threshold 5). Its raw statistics are
retained in the observation artifact. The other scalar blocking harnesses still
used class-specific batch addresses, so they now receive the same fixed-address
preparation outside timing. Sampling power and failure criteria remain intact.
A standalone Rust 1.89 release-style multiplication probe emits straight-line
arithmetic and conditional moves, but does not establish the behavior of the
hosted inlined call site or identify the cause of the measurement.


The next hosted observation found an adjacency magnitude association (signal
27.1730, control 2.3294). Multiplication was inconclusive, and is not relabeled
as established constant-time behavior. All remaining blocking data inputs now
use fixed-address preparation: both adjacency contrasts, both modulus-switch
polynomials and their U512 precheck. The adjacency region still runs 340 sweeps
and 8,000 rounds. A standalone subtraction/mask assembly probe has no operand
branch, but does not identify the hosted association's cause. The unchanged
control/threshold and injected-signal negative control remain mandatory.
