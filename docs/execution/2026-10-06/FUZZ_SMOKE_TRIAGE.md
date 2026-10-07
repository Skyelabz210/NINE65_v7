# Fuzz Smoke hosted triage

Run [37636203405](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37636203405)
executed on PR #164's merge ref for head `fc12b04`. All five jobs failed, but
for three distinct reasons. The follow-up run
[37639373719](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37639373719)
executed on PR #165's merge ref `b02a70e` (head `f0545a0`) after fixing the
nightly/action setup, release configuration and K-Elimination oracle. Every
target compiled and ran. Two bounded targets passed; three exposed failures:

| Target | Latest hosted result | Next action |
| --- | --- | --- |
| `fuzz_deserialize` | Still fails in `DualRNSCiphertext::from_bytes_validated`. The six-byte input `[252, 252, 252, 252, 252, 91]` (`/Pz8/Pxb`) makes AddressSanitizer report an attempted allocation of `0x17b7b7b7a0` bytes (101,866,518,432 bytes). This is a second witness for the short-payload/declared-length allocation problem; the earlier five-byte `/AoKCgo=` witness requested 4,042,320,960 bytes. The failing input is in artifact `fuzz-artifacts-fuzz_deserialize-b02a70ea6ef56bdf5ee5bcccd7260ad34272bd16`, file `crash-6bfe48687075a598a46896cecb6cbcf4c9ed82c0`, SHA-256 `cbb0cdb49f762e2b9387bf9baba9409565bf9517c71a8c4faed809cd39811ab1`. | Bound every attacker-declared collection length against remaining payload bytes before allocation. Add a regression for the six-byte input and the earlier five-byte input; repeat the bounded hosted run after the decoder patch. |
| `fuzz_encrypt_decrypt` | Fails the target's round-trip assertion: plaintext `3563036091075424882`, seed `8246779862454530674`, encrypted plaintext `16640`, decrypted plaintext `16639`. The minimized artifact is 17 bytes, file `crash-73253772bad476da0bd35beb0f089d0bb2d1dba5`, SHA-256 `ba8b3fb192529b27ff45baa1ff166d3fb1f618871345a100b3f66a9edfafbca3`, in `fuzz-artifacts-fuzz_encrypt_decrypt-b02a70ea6ef56bdf5ee5bcccd7260ad34272bd16`. | Reproduce against the exact PR merge SHA, trace encode/encrypt/decrypt with an independent integer oracle, and determine whether this is a production round-trip defect or an invalid fuzz tuple. Keep the assertion red until evidence establishes the cause. |
| `fuzz_homomorphic` | Fails addition for `HomomorphicInput { a: 18446744073709551370, b: 18446744073709551615, scalar: 134217727, seed: 0 }`: the target observed `65292 + 0 = 65289`, expected `65292`. The artifact is 32 bytes, file `crash-b0ea9ea94d773cc7ac37b1d985a4e2f789958639`, SHA-256 `329e66a7ed8cac62398ff57be6758758965cd1b5219bc7e787b002fd9d1aa575`, in `fuzz-artifacts-fuzz_homomorphic-b02a70ea6ef56bdf5ee5bcccd7260ad34272bd16`. Since addition asserts first, this run did not reach subtraction or scalar multiplication for this input. | Reproduce on the exact merge SHA, isolate the ciphertext add/decrypt path with an independent modular oracle, then retain the mismatch as a regression until explained or fixed. |
| `fuzz_k_elimination` | Passes its bounded run after replacing the unsafe harness oracle. | Keep checked overflow a refusal; expand with boundary corpus after the repository's source-bound F02 gates. |
| `fuzz_ntt` | Passes 7,591 executions in 61 seconds (`cov: 228`, `ft: 274`). | Preserve as a bounded smoke result only; it is not full fuzz coverage. |

The three failure artifacts were uploaded by the hosted workflow. Their hashes
above bind the downloaded input files; the run link contains the full logs.
The change from the previous run is useful: all five targets now compile and
execute. It does not make Fuzz Smoke green. The `for_depth(1, 4096, 0)` config
is an unscreened fuzz configuration with a zero security claim, not an
admitted or production security tuple.

An exact-toolchain local replay was attempted on head `f0545a0`, but the
AddressSanitizer-instrumented `nine65` build consumed most of this host's 2.7
GiB RAM. It was stopped before running a saved input when only 44 MiB was
reported free. No local replay result is claimed; the hosted logs and uploaded
artifacts above are the evidence for these failures.

The branch now uses `for_depth` in the three fuzz targets, corrects the
K-Elimination harness to use checked APIs, and uploads `fuzz/artifacts` on job
failure. Run `37639373719` confirms all five targets build and execute, with
two passes and three failures. The allocation and plaintext mismatches are
open gates; no fuzz assertion should be weakened to turn this run green.
