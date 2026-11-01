# Repository assessment remediation

The uploaded technical assessment reviewed `main@924f52e`. These changes are
on [draft PR #203](https://github.com/Skyelabz210/NINE65_v7/pull/203), source commit `1c553f6d723ecf52c4f131ca4060c794b59e52e6`;
they do not change main or constitute release admission. The system's goal
remains exact public encrypted computation with useful original-key refresh,
while keeping arithmetic evidence separate from confidentiality and deployment
security. The working refresh here is the explicit PublicRefreshCircuit;
legacy Clockwork entry points remain gated.

| Priority | Result | Remaining obligation |
| --- | --- | --- |
| Security policy | Root policy reconciled; mutation controls reject the former production and complete-timing assertions | Keep claims tied to actual evidence |
| Montgomery timing | Five controlled local repeats and compiled-loop inspection archived | Original hosted finding remains open; dedicated controlled measurements and machine-code review required |
| Architecture counters | Opt-in counters wired to actual context-owned FHE paths, with encrypted integration and emission fault controls | Extend the measured call inventory; clean scoped counters do not prove global coverage |
| Scale-sweep diagnosis | Supported arithmetic, expected legacy refusal and unverified/crashed evidence classified separately | Complete comparison remains unsupported and its strict gate stays nonzero |
| Joint-key analysis | Existing conditional reduction and exact graph packaged as a concrete review request | Joint-setup confidentiality premise is still unestablished |
| External attestation | Reproducible key-free exact tuples and review requirements exported | Independent review and signed exact-tuple conclusions have not been obtained |
| Integrated acceptance | Full library and feature checks pass; fresh native run recorded below | Revalidate the actual selected release commit after integration |

## Security policy and timing

SECURITY.md now reports the four profiles as internally screened, including
secure_256's 240-bit MATZOV result. It removes unsupported production, high-depth
and completed constant-time claims, documents the release-feature rejection,
and reflects the actual service decrypt controls. Reporting contact, disclosure
timelines and vulnerability scope are preserved; no exclusion was added.
The public-refresh claim guard now reads root SECURITY.md and tests regressions
of its former assertions.

The actual failing main timing job is
[124862982875](https://github.com/Skyelabz210/NINE65_v7/actions/runs/41311607984/job/124862982875):
control 1.4003, signal 8.6550, blocking threshold 5. Five local CPU0-affinity
repeats used the release binary built at task base `7ddb2b4`; each executed
the exact Montgomery test, not an empty filter. Montgomery and timing-harness
source are unchanged by this remediation.

The local environment is a shared AMD EPYC virtual machine with three exposed
CPUs; affinity does not provide exclusive scheduling or fixed CPU frequency.
These are controlled test selections, not dedicated-machine certification.

| Local repeat | Control t | Signal t | Interpretation |
| --- | --- | --- | --- |
| 0 | 7.1061 | 2.2331 | Inconclusive: same-class control exceeds5 |
| 1 | 2.1225 | 0.8726 | Both below5 at this sample size |
| 2 | 1.7036 | 3.0186 | Both below5 at this sample size |
| 3 | 2.1649 | 0.6861 | Both below5 at this sample size |
| 4 | 3.0570 | 1.5870 | Both below5 at this sample size |

Exit 0 on repeat 0 does not convert its inconclusive verdict into a timing pass.
The sampled compiled hot loop at 5a3410–5a345a contains fixed-address operand
loads, multiplication, add/adc, subtraction and cmovs; the observed conditional
jump is its public loop backedge. No operand-conditioned jump was observed
in that loop. This limited inspection and four below-threshold repeats do not
prove constant-time behavior or resolve the original signal. No kernel change,
threshold relaxation or timing-test suppression was made.

## Actual architecture instrumentation

The `architecture-meter` feature shares an Arc of cram-core counters across
an owning FHE context's main and anchor RNS contexts. Calls to `to_int`,
partial-level reconstruction and `to_u256_level` record CRT events. Main and
DualRNS decode entry points record output projections. The feature is off by
default, keeping new atomic counters out of default timing measurements.

The integration test encrypts 3, performs a genuine exact public product and
decrypts 9; it also encrypts/decrypts DualRNS 7, exercises anchor reconstruction,
and checks context isolation. Negative controls reject injected Garner and
mixed-radix counts. Weighted CRT reconstruction is permitted under the user's
emission policy. The historical stricter guard remains unchanged. The new
scoped guard complements the structural scanner and actual-operation arrow
checks; free projectors and other contexts are not a complete measured inventory.
The exactness workflow now runs the core fault controls and real FHE meter test.
At `1c553f6`, the new
[hosted FHE meter job](https://github.com/Skyelabz210/NINE65_v7/actions/runs/41353194043/job/124987606455)
also passes both the core negative control and the actual encrypted integration
test. Its raw log is archived with the local evidence.

## Comparison evidence and review inputs

The actual two-case sweep uses v6_compat_4096 and secure_128, seed 42, one
iteration, and two required depth steps. Both depth chains pass. It reports
zero wrong plaintexts, zero supported-operation correctness failures, zero
unexpected process failures and two expected legacy refusals. Raw nonzero
exits remain visible. The strict runner returns 1 because complete capability
coverage is still unsupported. Crash 137 with refusal metadata is classified
as unrun, and wrong-plaintext controls remain failures. Historical manifests
are not rewritten.

Hosted checks at `1c553f6` reproduced the two expected unsupported scale cases,
with zero arithmetic/process failures. They also exposed two integration
follow-ups: the regenerable current modulus ledger still bound the previous
RNS source, and the separate smoke validator expected only the old FAIL/exit1
probe contract. At `2e66701`, the ledger is regenerated and the validator
accepts exactly the historical FAIL/exit1 or current UNSUPPORTED/exit2 pair,
while retaining every supported-operation and plaintext check. Its 15 controls
and the actual two-depth comparison payload pass. Eight modulus-audit controls
pass and repeated generation reproduces the committed current ledger. Frozen
historical audit files remain unchanged. Raw hosted failures are archived;
follow-up hosted checks must be assessed at their own source commit.

The [independent review request](INDEPENDENT_REVIEW_REQUEST.md) and unsigned
machine-readable packet bind three native domains, seven publication relations
and four named profiles. This is preparatory material, not an external review,
joint/KDM proof or security grant. No outside messages were sent.

## Acceptance and provenance

The optimized library run passes 1118 tests, with 0 failures and 140 existing
ignores. The accepted feature test passes 1; cram-core passes 13 unit tests and
5 phase-lock tests. The comparison contract has 21 passing controls. Formatting,
workspace/all-target Clippy with the diagnostic feature, dependency policy,
source architecture scanner, panic ratchet and security-claim self-tests pass.
One earlier unoptimized library attempt was interrupted and is not counted.
One repeat of the Python controls initially lacked rustc on PATH; the complete
suite was rerun successfully with the pinned Rust1.89 environment.

Fresh native acceptance at the remediation source snapshot is recorded in the
[evidence manifest](assessment-remediation-evidence/manifest.json). The exact
N8192 test passes one original-key public refresh and following full-polynomial
square in 579.60 seconds, including setup and excluding compilation. All
16,384 plaintext comparisons and 24,576 ideal-grid error checks pass. The
maximum process VmHWM is 6,799,296 KiB (about 6.48 GiB), within the 8 GiB
cgroup limit. Maximum scaled errors match the prior deterministic fixture:
input 762490188487606471, returned 1043073383, following square
257071113810960355. The test never changes the immutable producer caps.
This repeats the same seed, not an independent random sample or failure-rate
estimate. Native/library source is unchanged by the later harness-only fix.
Earlier
five-cycle and phase-observer evidence retains its original source attribution.
This remains branch integration evidence, not a selected release-commit signoff.

