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
2. READ: `crt_reconstruct_u256` still recomputes everything for its other
   ~20 callers (bootstrap, phase clocks, base_ext, `to_u256_level`). Same
   fix applies per call site once each has a stable prime set to hang a plan
   on. `RNSContext::to_u256_level` (rns.rs:1027) is the most likely next one.
3. READ: `U256::mod_u64_ct` (256 iterations), `div_mod_u64_ct` (256) and
   `mod_u64_word_ct` (64) are still bit-serial. `extract_k_rns_level_cached`
   calls `mod_u64_ct` once per anchor prime per coefficient; the rescale in
   `ops/rns_fhe.rs` calls it once per output lane. A persistent-Montgomery
   reduction per prime (limb constants `2^(64k)*R mod p`, four REDCs) and an
   exact quotient via the inverse of the odd divisor mod 2^256 would remove
   them with the same fixed-work property. Not done yet.
4. READ: `(diff * inv) % a_i` in `extract_k_rns_level_cached` is a variable-
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
