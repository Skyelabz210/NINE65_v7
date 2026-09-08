# nine65

The FHE core: BFV over a dual-RNS ciphertext, with the CRAM substrate reached
through `src/cram_ct_wrap.rs`.

Build and test from the workspace root:

```
cargo test -p nine65 --lib
```

Current baseline: **652 passed / 3 failed / 103 ignored**. The three failures
are pre-existing and named in `docs/AUDIT_FINDINGS_2026-08-09.md` §5:
`noise::budget::tests::exact_delta_size_does_not_sum_lane_widths`,
`noise::budget::tests::exact_delta_size_handles_products_above_u128`,
`security::tests::test_lwe_params_from_config`.

## CRAM opportunity action items

Mirrored from `CRAM_OPPORTUNITY_REPORT.md` (pass 1). Entry numbers route back
into that report. Every Level-2 node is currently `pending`, so these are
logged for action — do not improvise the procedure against them.

### FORCED — A1 (float in production source)

- `[1]` `src/compiler.rs:118-126` — `NoiseModel` carries six `f64` fields.
  `src/lib.rs:42-43` declares the exemption as offline/static analysis, but the
  winding now gives an exact magnitude read, so the exemption is a choice.
  → `a1-defloat`
- `[3]` `src/security/ct_verification.rs:34-48` — `f64` median / MAD / t-test.
  **The constant-time layer is off-limits.** Logged so the site is known and
  not "fixed"; timing statistics are genuinely real-valued. → `a1-defloat`
- `[4]` `src/comprehensive_benchmarks.rs:52,82,89,125,134` — `f64` wall-clock
  in the measurement harness, not on a compute path. → `a1-defloat`

### CANDIDATE

- `[10]` `src/arithmetic/rns.rs` — RNS carries the whole FHE path with
  homogeneous lanes; safe-basis roles and per-lane operators uninstantiated.
  → `crt-to-cram-substrate`
- `[13]` `src/cram_ct_wrap.rs` — the BFV↔CRAM seam. `wrap_default` leaves
  `c0_aux: None` and `lane0_as_i128` fingerprints `c0.main[0]` only, so the FPD
  path exists but is unreachable. → `crt-to-cram-substrate`
- `[15]` `src/arithmetic/ntt.rs`, `ntt_fft.rs` — the butterfly is a staged
  cascade with cross-coefficient dependency at every stage.
  → `sequential-to-heterogeneous`
- `[16]` `src/arithmetic/barrett.rs`, `montgomery.rs`,
  `persistent_montgomery.rs` — reduction machinery that exists to make a
  positional cascade cheap. → `sequential-to-heterogeneous`
- `[17]` `src/arithmetic/ntt.rs`, `ntt_fft.rs`, `cyclotomic_phase.rs` — audit
  whether lanewise residue arithmetic removes the NTT requirement entirely,
  which would also drop the CLASS-F primality constraint on those moduli.
  → `ntt-necessity-audit`
- `[18]` `src/arithmetic/persistent_montgomery.rs`, `barrett.rs` — downstream
  of `[17]`. → `ntt-necessity-audit`
- `[19]` `src/params/primes.rs`, `secure_configs.rs`, `production.rs` — moduli
  selected by NTT compatibility and bit width alone; no prime-family role is
  assigned. → `prime-family-engineering`
- `[20]` `src/arithmetic/ntt.rs` (primitive-root search),
  `src/arithmetic/k_elimination.rs` — CLASS-F and CLASS-R are not distinguished
  at the selection site, so anchors inherit a primality constraint they do not
  have. → `prime-family-engineering`
- `[22]` `src/ops/rns_mul.rs` — rescale on the multiply path, generic rather
  than lanewise `x_i·d_i⁻¹ mod m_i` with a coprimality gate.
  → `fifth-operator-rescale`
- `[23]` `src/arithmetic/residue_division.rs`, `exact_divider.rs` — two general
  division paths alongside the seven-chimera catalogue; a modular-only `Div`
  result and an integer quotient are not distinguished at the type level.
  → `fifth-operator-rescale`
- `[25]` `src/noise/budget.rs:13-291` — the budget is a millibit counter beside
  the data: `consume()` debits a static per-op cost and
  `remaining_millibits()` never reads a ciphertext. → `winding-magnitude`
- `[26]` `src/arithmetic/bounded_rns.rs` — range bought by sizing the modulus
  product rather than by an orthogonal winding track. → `winding-magnitude`
- `[27]` `src/ops/gso_fhe.rs:52-96` — `NoiseEstimate` is bookkeeping:
  `collapse()` zeroes `distance` without touching the ciphertext.
  → `transduction-state`
- `[28]` `src/ops/parallel.rs:86,106,120,137,219,237` — six rayon work-stealing
  dispatches over lane- and coefficient-indexed operations.
  → `deterministic-lane-parallelism`
- `[30]` `src/arithmetic/ntt.rs:417-454` — rayon parallel NTT; probabilistic
  scheduling on top of a staged cascade. → `deterministic-lane-parallelism`

### RESOLVED

- `[2]` `src/ops/sbni.rs` was deleted entirely (issue #68), taking its `f64`
  chi-square/mean/stddev test helpers with it — there is no module left to
  defloat. See `CRAM_OPPORTUNITY_REPORT.md` `[45]`.

## Standing constraints

- **Modulus switching is retired.** Never reintroduce it into a multiply path.
  The `mod_switch_*` definitions stay alive only as the negative control in
  `tests/basis_invariance.rs`.
- **SBNI is retired and its source file is deleted.** Do not reintroduce it.
- **`WassanNoiseField` (WASSAN Holographic Noise Field) is retired and its
  source file is deleted.** It had zero production callers; do not
  reintroduce it as an entropy source without a documented security review
  (see `docs/ENTROPY_MODEL.md`).
- **The `_ct` constant-time layer is off-limits to optimization.**
