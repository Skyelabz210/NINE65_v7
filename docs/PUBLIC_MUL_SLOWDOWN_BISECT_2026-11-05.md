# Public multiply slowdown: bisect result (2026-11-02..05)

Scope: `secure_128_deep` public mul, `crates/nine65/tests/op_timings.rs`
(`measure_core_op_timings`), debug-assertion build with `allow_insecure`,
`profile.test.opt-level=3`, LTO off, 2-core container, one run per commit.
Only ratios are meaningful: this machine is ~3x slower than the one that
produced the 2026-08-23 baseline in CLAUDE.md. Single runs; expect roughly
10-15% noise (e.g. 2e266e4 vs 8130a3e).

| commit | date | public mul ms | symmetric mul ms |
|---|---|---|---|
| d4f2e0e | late Aug | 1208 | 314 |
| 2e266e4 | 08-31 | 1575 | 447 |
| 8130a3e | 09-03 | 1447 | 357 |
| 3fa2b89 | 09-04 | 1507 | 402 |
| 3e1e078~1 | 09-04 | 1547 | 366 |
| **3e1e078** (F-2 fix) | 09-04 | **2519** | 454 |
| 02653a5~1 | before 10-12 | 2131 | ~400 |
| **02653a5** (fixed-work CRT) | 10-12 | **3987** | 678 |
| 7013310 | 10-23 | 3798 | 642 |
| HEAD 54cce69 | 11-02 | 3620 | ~300-760 (varies by config) |

Net on this box: ~1.2 s -> ~3.6 s (about 3x). Profiling HEAD (gdb stack
sampling) puts the time in the dual-RNS K-Elimination rescale
(`k_elim_rescale_dual`, `extract_digit_dual`, `canonicalize_dual_anchor`)
running on mana lane threads.

## Cause

Both jumps are constant-time hardening that replaced hardware division with
fixed-iteration bit-serial loops:

- 3e1e078: `U256::mod_u64_ct` / `div_mod_u64_ct`, 256 iterations per call,
  called per coefficient per lane in the rescale.
- 02653a5: `mod_u64_word_ct` (64 iterations) in CRT residue reduction and a
  512-iteration constant-time `U512::mod_u256`.

## Not done (blocked pending owner permission)

Fixes considered, none applied, none measured:
1. Barrett reduction for the u64-modulus cases. The modulus is a public
   prime and only the numerator is secret, so a reciprocal-multiply
   reduction keeps fixed work (4 limb steps instead of 256 iterations). The
   `*_iteration_count_is_input_independent` guardrails would assert 4, not
   256.
2. An off-by-default `vartime_reduction` feature that routes those three
   functions to hardware `%` / `/`. This reopens the F-2 timing leak and
   would be benchmark/non-observable-timing only.
3. Run the same benchmark on v6 for a direct comparison (v6 was not
   available in this session).

The edit-permission check blocked the F-2 code edits (including a
measurement-only scratch build), so none of the above was attempted.
