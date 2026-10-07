# Fuzz Smoke hosted triage

Run [37636203405](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37636203405)
executed on PR #164's merge ref for head `fc12b04`. All five jobs failed, but
for three distinct reasons:

| Target | Observed result | Next action |
| --- | --- | --- |
| `fuzz_deserialize` | A five-byte input `[252, 10, 10, 10, 10]` (`/AoKCgo=`) caused libFuzzer to report `malloc(4042322160)` from `DualRNSCiphertext::from_bytes_validated`. The method's 64 MiB input-size guard does not constrain a collection length declared inside a short bincode payload before allocation. | Reproduce with the saved input and repair bounded decoding so declared collection lengths cannot allocate beyond the payload budget. Add a short-payload/oversized-declared-length regression before treating the validated decoder as safe. |
| `fuzz_k_elimination` | Input bytes `9gouCPYAAAAAAAAAAAAAAAAAAAAAAAAA9vb29vb2GQAAAAAAAAD29gkJovUZ` (`KElimInput { v_alpha: 1056699190006, v_beta: 0, divisor: 0, config_choice: 246 }`) reached the documented `expect` panic at `k_elimination.rs:498` for boundary multiplication overflow. `config_choice % 4 == 2` selects `Extended`; the fuzz harness computed its expected winding and reconstructed value with unchecked `u128` multiplication, then called the panic-on-overflow API. | Correct the harness oracle: use `extract_k`, checked reconstruction and `exact_divide_validated`/`exact_divide_checked`. Preserve checked overflow as a refusal; do not infer a production arithmetic defect from this harness panic alone. |
| `fuzz_encrypt_decrypt`, `fuzz_homomorphic`, `fuzz_ntt` | The targets did not compile because `standard_128_insecure` is gated behind `allow_insecure` in release builds. A follow-up enabled `allow_insecure`, which correctly hit the crate's compile-time release guard. | Use release-available unscreened `FHEConfig::for_depth(1, 4096, 0)` in these fuzz targets. Keep `allow_insecure` out of the release fuzz graph. |

The branch now uses `for_depth` in the three fuzz targets, corrects the
K-Elimination harness to use checked APIs, and uploads `fuzz/artifacts` on job
failure. Hosted verification is still pending. The fuzz workflow must not be
called green until all five targets build and complete their bounded runs; the
deserialization input remains an unresolved allocation gate.
