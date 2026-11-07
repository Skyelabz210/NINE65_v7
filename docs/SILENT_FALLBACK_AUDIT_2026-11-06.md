# Where native machinery is bypassed or recomputed (audit, 2026-11-06)

Scope: read-only audit plus one profile of public multiply. Each item is tagged
MEASURED (profiled or benchmarked), READ (seen in source, not measured) or
OPEN (a question, not a conclusion). Method for MEASURED items: gdb stack
sampling of worker threads during `op_timings` public mul, `secure_128`,
opt-level 3 debug-assertion build, 2-core container.

## Where public mul spent its time (before this change, sampled)

| share of samples | function |
|---|---|
| ~42% | `crt_reconstruct_u256` |
| ~22% | `U512::mod_u256` (the 512-iteration constant-time reduction inside it) |
| ~11% | `extract_k_rns_level_cached` (own frames) |
| ~9% | `mod_inverse` (extended Euclid, on the hot path) |
| ~9% | NTT (`ntt_fft`: butterflies, bit-reverse, inverse) |

The NTT, the part built on `PersistentMontgomery`, was about 9% of the time.
Roughly two thirds of public mul was reconstruction recomputing values that
depend only on the public prime set.

## Findings

1. MEASURED, FIXED: `crt_reconstruct_u256` recomputed per coefficient the
   modulus product, one wide division, one `mod_u64`, one extended-Euclid
   `mod_inverse` per prime, then a 512-iteration reduction. Replaced on the
   K-Elimination hot path by `CrtU256Plan` (built once per context, lazily):
   one persistent-Montgomery REDC per prime plus exactly `k - 1` masked
   conditional subtracts. Fixed work, no division, no secret-dependent
   branch. Public mul `secure_128_deep`: 3620 ms -> 959 ms on this box.
   The function was already named `..._cached` and its comments said the
   inverses were precomputed; the reconstruction below it was not.
2. MEASURED, FIXED (second pass): re-profiling after item 1 put the remaining
   `crt_reconstruct_u256` time in `RNSContext::to_u256_level` (rescale, relin,
   decrypt-side reconstruction), which recomputed per call at every level. It
   now uses a lazily built `CrtU256Plan` per level. `secure_128_deep` public
   mul 959 -> 343 ms (3620 ms before either change, ~10.6x); `secure_256`
   10.8 s -> 1.4 s. A level with no U256 CRT value (empty, or product wider
   than 256 bits) keeps the reference function's semantics. The ~15 other
   callers (bootstrap, phase clocks, base_ext) still recompute per call.
3. MEASURED, FIXED (third pass, 2026-11-07): after items 1-2 a re-profile put
   about half the samples in `extract_k_rns_level_cached`'s own frames, i.e.
   its inlined reductions. They now run on `PrimeReducer` (per anchor prime:
   four persistent-Montgomery REDCs against precomputed `2^(64k)*R mod p`
   constants for the 256-bit reduction, and a Montgomery multiply for
   `diff * inv mod a_i`, which also closes the variable-time `u128 %` gap
   noted in item 4). `secure_128_deep` public mul 343 -> 97 ms; `secure_256`
   1400 -> 352 ms. `mod_u64_ct`, `div_mod_u64_ct` and `mod_u64_word_ct`
   themselves are unchanged and still bit-serial for their remaining callers
   (rescale output lanes, other ops), which were not re-profiled.
   (Original note:) `U256::mod_u64_ct` (256 iterations), `div_mod_u64_ct` (256)
   and `mod_u64_word_ct` (64) are bit-serial. `extract_k_rns_level_cached`
   calls `mod_u64_ct` once per anchor prime per coefficient; the rescale in
   `ops/rns_fhe.rs` calls it once per output lane. A persistent-Montgomery
   reduction per prime (limb constants `2^(64k)*R mod p`, four REDCs) and an
   exact quotient via the inverse of the odd divisor mod 2^256 would remove
   them with the same fixed-work property. Not done yet.
4. FIXED with item 3: `(diff * inv) % a_i` in `extract_k_rns_level_cached` was a variable-
   time u128 modulo; the source comment flags it as a known gap and names
   the fix (a per-anchor-prime reduction context). The same Montgomery
   context closes it.
5. READ: `accelerated.rs` (`ManaStream`, `AnchorContext`, `Lane::from_coeffs`)
   has no caller outside itself. The only live MANA/UNHAL link is the
   generic `Accelerator::run_lanes` thread executor. UNHAL's own header says
   the SIMD path is a dead fallback ("SIMD module removed, fallback to
   sequential") and that earlier throughput claims were unbacked.
6. READ: `mana::executor::run_lanes` spawns scoped OS threads on every call.
   The rescale invokes it per coefficient chunk (16 chunks at n=8192). A
   persistent worker pool would remove the per-call spawn cost. Not measured.
7. READ / OPEN: `ops/exact_mul.rs` (WR-1 derived-transient exact multiply on
   main Q only) is documented as "explicitly routed, never auto-routed" and
   "not reachable from `mul_auto`". `RNSFHEContext::mul` is fail-closed to
   the `BajardSingle` route, so on the four-prime configs public mul goes
   through the dual-RNS path. Whether the WR-1 route is faster, and whether
   it should be reachable by default, is unmeasured.
8. READ: `PersistentMontgomery` is used by `ntt_fft` (good) but almost
   nowhere else outside tests. The non-persistent `MontgomeryContext` is
   still what ~20 `ops/` modules build on. 185 non-test `u128 % modulus`
   sites remain in `arithmetic/` and `ops/` (largest: `ops/rns_fhe.rs` 32,
   `arithmetic/ntt.rs` 16, `ops/prime_power_phase.rs` 11). `ntt.rs` is the
   reference DFT engine behind the `reference_ntt` feature, so its `%` sites
   are not on the default path; the others need a per-site look.
9. READ: `bootstrap.rs` still carries many "U256 CRT fallback" paths; the
   legacy bootstrap suites are `#[ignore]`d as vestigial, so these are not on
   the live path today.

## Not checked

NTT-FFT versus the reference DFT: `ntt_fft` is the default (`reference_ntt`
is off), so that selection is correct. Everything marked READ above is
unprofiled; rankings come from the sampled profile only.

## New finding from the direct timing gate (2026-11-07)

`test_ct_dudect_production_extract_k_cached_operand_magnitude` (new, blocking
in CI) times the production K-Elimination path directly, zero versus uniform
operands, on secure_128 and secure_192 (witness lanes live). Its first run
failed with a ~2% effect (t_signal 7-84 against control ~0.5) after the
arithmetic had already been made fixed-work. Two causes, both secret-
dependent control flow on the winding number `k_u`:

1. The capacity guard tested `k_u.ge(A/2 - margin) && k_u.le(A/2 + margin)`:
   early-exit limb comparators plus a short-circuiting `&&`. Now two
   borrow-based `ge_mask_ct` masks combined with `&`; only the error exit
   branches on the result.
2. The 10-anchor witness check branched on the sign of `k_u`
   (`if is_neg { a_recon.sub(k_u) } else { k_u }` and
   `if is_neg && mag_mod != 0`). Now a masked select.

A test-only `k_probe` block also computed the sign unconditionally; it now
runs only while a measurement is recording.

After the fix: medians equal to the nanosecond across both configs (e.g.
34513 vs 34508 ns per 128 calls), t_signal 0.09-0.80 over repeated runs.
A first attempt at the secure_192 case measured t_signal ~200, which was a
test-design error (random witness residues made class B return the allocating
error path); class B now uses witness-consistent residues with both signs of
`k`, and the test asserts every pool operand returns Ok.

## Result summary

`secure_128_deep` public mul on this 2-core box: 3620 ms (before) -> 959 ->
343 -> 97 ms. `secure_256`: 10803 -> 352 ms. Symmetric mul 305 -> 53 ms.
Lib 1124 passed / 0 failed; 58 test targets, 1410 passed, 0 failed.

## Follow-up 2026-11-07: NTT and relinearization

- `NTTEngineFFT::multiply` / `multiply_persistent` now run a fused negacyclic
  transform (twists merged into the butterflies, no data bit-reversal, Montgomery
  twiddle tables, iterative power tables). Per n=8192 multiply: ~461us -> ~341us.
  Bit-exact against the textbook reference in `fused_negacyclic_multiply_matches_textbook_reference`.
- `relinearize_dual` accumulates `sum digit_i * rlk_i` in the transform domain
  per lane (`multiply_sum_pair`: 3k+2 transforms instead of 6k). Bit-exact
  against summed products in `multiply_sum_pair_matches_summed_products`.
- Measured (`op_timings`, debug-assertions on, secure_128): public mul 97 -> ~76 ms,
  symmetric mul 53 -> ~41 ms; secure_256 public mul ~256 ms.
- Lib suite: 1127 passed, 0 failed, 144 ignored.
