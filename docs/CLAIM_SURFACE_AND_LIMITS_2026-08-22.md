# Claim Surface and Limits — 2026-08-22

Internal companion to `README.md`. The README states scope, verified
capability, and current limits. This document holds the things that belong
behind the front door: per-number provenance, the discrepancies between
independent measurements, and the engineering self-assessment that used to sit
in the README itself.

Governed by `docs/LINEAGE.md` (deprecation rules for claim language),
`docs/BENCHMARK_PROFILE_POLICY.md`, and `docs/CLAIM_EVIDENCE_LEDGER.md`.

---

## 1. Verified capability table

| Config | N | main lanes | log2(q) | public mul | symmetric mul | public direct-square depth (last correct) | public refresh |
|---|---|---|---|---|---|---|---|
| `secure_128` | 8192 | 3 | 90 | 158.994 ms (4x5) | 44.371 ms | 2 | **refused — corrupts** |
| `secure_128_deep` | 8192 | 4 | 119 | 207.956 ms | 47.262 ms | 2 (see §4) | pass |
| `secure_192` | 16384 | 5 | 146 | 564.238 ms | 122.927 ms | 3 | pass |
| `secure_256` | 16384 | 6 | 175 | 520.801 ms | 129.971 ms | 4 (unverified here) | admitted, unexercised |

Provenance, column by column:

- **N, main lanes, log2(q)** — read off `crates/nine65/src/params/secure_configs.rs`
  and recomputed exactly by `exact_product_bit_length`. Re-measured 2026-08-22.
- **public mul / symmetric mul timings** — from the orchestrator's
  correctness-gated benchmark run. **Not re-measured in this pass.** Treat as
  indicative until reproduced under `docs/BENCHMARK_PROFILE_POLICY.md`.
- **public direct-square depth** — re-measured 2026-08-22 for `secure_128`,
  `secure_128_deep`, `secure_192` (see §3). `secure_256` is the benchmark's
  figure, not re-measured.
- **public refresh** — re-measured 2026-08-22 for the same three configs
  (§3). `secure_256` is admitted by the predicate but was not exercised end to
  end in this pass; "admitted" is a statement about the chain, not a verified
  roundtrip.

---

## 2. Screened security levels (measured 2026-08-22)

Produced by `params::secure_configs::tests::screened_levels_for_named_configs`:

```
cargo test -p nine65 --lib --release \
  params::secure_configs::tests::screened_levels_for_named_configs -- --nocapture
```

| config | n | lanes | log2(q) | claimed | Core-SVP | MATZOV | binding | classical | hybrid | quantum |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| secure_128 | 8192 | 3 | 90 | 128 | 259 | 233 | 233 | 305 | 259 | 173 |
| secure_128_deep | 8192 | 4 | 119 | 128 | 196 | 176 | 176 | 231 | 196 | 131 |
| secure_192 | 16384 | 5 | 146 | 192 | 320 | 288 | 288 | 377 | 320 | 214 |
| secure_256 | 16384 | 6 | 175 | 256 | 267 | 240 | 240 | 314 | 267 | 178 |
| hardware_opt | 8192 | 3 | 90 | 128 | 259 | 233 | 233 | 305 | 259 | 173 |

Readings:

1. **No named config is relabelled.** Every name clears its own number under
   Core-SVP, which is the model `SecureConfig::new_verified` gates on. There is
   no case here for a breaking rename, a `secure_224()`, or a deprecated alias.
2. **`secure_256` is the one name its own screen does not fully support.**
   Core-SVP 267 clears; MATZOV 240 is 16 bits short. The gap is recorded in the
   `secure_256` doc comment and readable at runtime via
   `SecureConfig::screened_security_dual()`. Quote 240 wherever the aggressive
   model is the relevant one.
3. **A "secure_256 screens at ~227 bits" figure is in circulation and is stale.**
   It describes the *superseded* chain at `log2(q) = 203`, replaced 2026-02-25
   (`docs/LATTICE_ESTIMATOR_BASELINE_2026-02-25.md` records the change:
   old `log2(q)` 203.38 → 226 bits, new 174.18 → 264 bits). It must not be
   quoted against the current 175-bit chain. Anyone reproducing 227 has run the
   old prime list.
4. **Two in-tree paths compute `log2(q)` differently for the same tuple.**
   `SecureConfig::new_verified` gates on `exact_product_bit_length` (the exact
   bit length of the prime product: 90 / 119 / 146 / 175). The
   `security_estimator_baseline` binary uses `log2_product_floor_bits` (the sum
   of per-prime bit widths: 90 / 119 / 147 / 177), which over-estimates `q` and
   therefore returns slightly *lower*, more conservative bits — 264 rather than
   267 for `secure_256`, 318 rather than 320 for `secure_192`. Both are
   defensible; they are not interchangeable, and a figure quoted without saying
   which one produced it is ambiguous by 2–3 bits. Not reconciled in this pass.
5. **These are screening numbers, not certificates.** The in-tree estimator is a
   deterministic integer heuristic (`3.36 * n / log_q` with a ternary penalty).
   It returns 259 bits for `secure_128`, which no one should read as a claim
   about `secure_128`'s lattice security. `secure_configs.rs`'s stated policy —
   an archived external lattice-estimator run for the exact shipped tuple — is
   still unmet for `n = 8192 / 16384`. That debt is unchanged by this pass.

---

## 3. Public refresh: the measurement, and the refusal it forced

`ClockworkBootstrap::bootstrap` / `bootstrap_with_ksk` is the **public** refresh:
the evaluator refreshes using public bootstrap key material only. The
**symmetric** refresh (`SymmetricBootstrap::bootstrap`) takes the secret key and
is a different, single-party path; none of this applies to it.

Measured 2026-08-22 with the in-tree diagnostic, which encrypts under each
config, performs one public refresh, and checks against the decryption oracle:

```
cargo test -p nine65 --lib --release diag_measure_noise_growth -- --nocapture
```

```
=== secure_128 : budget 63000 mb, mul_ct 32000 + relin 13000 = 45000 mb, remaining_muls 1
  depth 1: dec=4     expected=4     OK=true
  depth 2: dec=16    expected=16    OK=true
  depth 3: dec=18121 expected=256   OK=false
  bootstrap(fresh 7): dec=8                          <-- WRONG, plaintext was 7
  bootstrap(7)^2:     dec=51445 expected=49          <-- margin 0 bits

=== secure_128_deep : budget 92000 mb, mul_ct 32000 + relin 13000 = 45000 mb, remaining_muls 2
  depth 3: dec=255   expected=256   OK=false         <-- off by one, see §4
  bootstrap(fresh 7): dec=7                          correct
  bootstrap(7)^2:     dec=49 expected=49             correct, 102 margin bits

=== secure_192 : budget 117000 mb, mul_ct 34000 + relin 14000 = 48000 mb, remaining_muls 2
  depth 3: dec=256   expected=256   OK=true
  depth 4: dec=4150  expected=65536 OK=false
  bootstrap(fresh 7): dec=7                          correct
  bootstrap(7)^2:     dec=49 expected=49             correct
```

`secure_128`'s public refresh returns a wrong-but-plausible plaintext: 7 comes
back as 8. Nothing in the pipeline reports an error — the noise diagnostic still
prints "73 margin bits" for that refresh. Only the decryption oracle catches it.
That is the worst failure shape a crypto library has, and it is why this is
refused in code rather than noted in a report.

### The refusal

`params::secure_configs::ensure_public_refresh_supported` returns
`Nine65Error::BootstrapConfigMismatch` (typed, never a panic) and is called as
the first statement of both `ClockworkBootstrap::bootstrap` and
`bootstrap_with_ksk`.

The predicate reads arithmetic, not names. Let `Delta = floor(Q / t)`:

```
headroom_bits = bit_length(Delta) - (t_bits + eta_bits + log2(n))
required_bits = (NoiseBudget::mul_ct_cost + NoiseBudget::relin_cost) / 1000
supported     = headroom_bits >= required_bits
```

| config | lanes | Delta bits | refresh noise | headroom | required | supported |
|---|---|---|---|---|---|---|
| secure_128 | 3 | 74 | 32 | 42 | 45 | **no** |
| hardware_opt | 3 | 74 | 32 | 42 | 45 | **no** |
| secure_128_deep | 4 | 103 | 32 | 71 | 45 | yes |
| secure_192 | 5 | 130 | 34 | 96 | 48 | yes |
| secure_256 | 6 | 159 | 34 | 125 | 48 | yes |

Two derivation choices are load-bearing and should be challenged if this gate
ever misfires:

- **`log2(n)`, not `sqrt(n)`, for the refresh's noise deposit.** Phase 2 of the
  public refresh (`homomorphic_inner_product`) is an `n`-term accumulation, so
  worst case its noise grows by a factor of `n`. `noise::budget`'s
  `bootstrap_noise_bit_bound` charges `root_n_bits` — the averaged growth. Under
  the averaged bound `secure_128` is predicted to clear the bar at 49 bits
  against 45, and the oracle above says it does not. The worst-case bound puts
  it at 42 against 45 and refuses it, while every 4+-lane config still clears by
  23 bits or more. The budget ledger is left alone; only this gate uses the
  worst-case bound.
- **"One multiply cycle" as the bar.** A refresh that leaves too little to fund
  a single ct×ct multiply plus relinearization has not accomplished anything a
  caller can use.

The 3-bit margin by which `secure_128` fails is thin. If the noise ledger moves,
`params::secure_configs::tests::public_refresh_predicate_matches_the_decryption_oracle`
fails loudly rather than silently re-admitting a corrupting path — that is
deliberate. Re-run the diagnostic before changing the constants, not after.

---

## 4. Open discrepancy: `secure_128_deep` public depth 3

The benchmark table (§1) records `secure_128_deep` at public direct-square
depth 3. The 2026-08-22 diagnostic re-measurement records depth 3 returning
**255 where 256 was expected** — off by exactly one — making the last correct
depth 2 under that run.

Not resolved in this pass. The two runs differ in at least seed and harness
(`ShadowHarvester::with_seed(42)`, `mul_dual_public`, repeated squaring of 2).
An off-by-one at the boundary is the signature of a configuration sitting right
at the decryption threshold rather than of a coding error, which would make
`secure_128_deep`'s depth-3 public capability **seed-dependent**. Until someone
runs it across seeds, the README states depth 2 for this config and this
paragraph is the reason.

---

## 5. Not established

State plainly, and do not let any of these back onto the public claim surface
without a dated artifact:

- **Nonlinear public FHE beyond the direct boundary.** What is measured is
  direct squaring/multiplication chains against a decryption oracle. Nothing
  here establishes general nonlinear circuits under the public evaluator.
- **Any unbounded-depth claim.** "Unlimited depth", "depth 50", and
  "bootstrap-free" are on `docs/LINEAGE.md`'s deprecation list. The measured
  public direct-square depths are 2–4. The public refresh that would extend them
  is refused on `secure_128` and unexercised end to end on `secure_256`.
- **`secure_256` public bootstrap.** Admitted by the predicate; no verified
  roundtrip in this pass.
- **"Fully verified bootstrap roundtrip across all three paths."** The bootstrap
  roundtrip tests in `ops/bootstrap.rs`, `tests/bootstrap_integration.rs`,
  `tests/bootstrap_parameter_exploration.rs` and
  `tests/bootstrap_residue_shape_regression.rs` are `#[ignore]`d as VESTIGIAL or
  RETIRED. Whatever one thinks of that quarantine, the claim cannot be sourced
  to a test the suite does not run.
- **External lattice-estimator attestation** for the shipped tuples. See §2.5.
- **Constant-time.** Blocked on the CT-NTT/cache gates in
  `docs/CT_NTT_CACHE_ROADMAP.md`.

---

## 6. Engineering self-assessment

Moved out of `README.md` on 2026-08-22. A README states what a thing does and
where its edges are; a running list of the team's doubts about its own head
belongs here.

- The hardening line is a draft until the Rust, Lean, WASM, audit-remediation
  and residue-native gates all execute successfully on the exact head. Named
  parameter profiles are candidate tuples until independently attested with the
  exact estimator input and raw output artifact.
- Do not merge or build applications on an unverified head while any required
  Rust, Lean, WASM, audit-remediation, residue-native, or claim gate is absent
  or failing.
- The bootstrap surface is largely quarantined. Most roundtrip tests carry
  VESTIGIAL/RETIRED ignore reasons asserting that exact division in residue
  space makes refresh a fallback rather than the critical path. That is a
  coherent position, but while it holds, the refresh paths are not covered by
  the running suite and regressions in them will not be caught.
- The in-tree estimator returning 259 bits for `secure_128` should be read as a
  statement about the estimator's calibration, not about `secure_128`. It is
  fit for relative screening between tuples and for fail-closed gating. It is
  not fit for quotation.
