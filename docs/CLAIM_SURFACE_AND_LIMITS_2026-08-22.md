# Claim Surface and Limits — 2026-08-22

Internal companion to `README.md`. The README states scope, verified
capability, and current limits. This document holds the things that belong
behind the front door: per-number provenance, the discrepancies between
independent measurements, and the engineering self-assessment that used to sit
in the README itself.

Governed by `docs/LINEAGE.md` (deprecation rules for claim language),
`docs/BENCHMARK_PROFILE_POLICY.md`, and `docs/CLAIM_EVIDENCE_LEDGER.md`.

Indexed in `docs/CLAIM_REGISTRY.csv` as three rows, all pointing here:

| claim_id | visibility | why |
|---|---|---|
| `readme.verified_capability_2026_08_22` | public / secure | §1: decryption-oracle-checked correctness on named secure profiles. |
| `params.public_refresh_admissibility` | public / secure | §3: a refusal enforced in code and covered by three passing tests. |
| `params.screened_security_disclosure` | **internal** / exploratory | §2 deliberately does **not** go on the public evidence surface. |

The third row is internal on purpose. `docs/CLAIM_RETIREMENTS_2026-07-13.md`
retired the README's named-profile estimator claim precisely because such a
claim needs pinned *independent* estimator inputs and raw outputs for the exact
tuple, and no such artifact exists for the shipped `n = 8192 / 16384` tuples
(§2.5). §2 is a disclosure of what the in-tree screen returns, published so the
`secure_256` MATZOV gap is visible — it is not evidence of a security level and
must not be registered or quoted as if it were. Nothing here re-admits the
retired claim.

---

## 1. Verified capability table

| Config | N | main lanes | log2(q) | public mul | symmetric mul | public direct-square depth (last correct) | public refresh |
|---|---|---|---|---|---|---|---|
| `secure_128` | 8192 | 3 | 90 | 158.994 ms (4x5) | 44.371 ms | 2 | **refused — corrupts** |
| `secure_128_deep` | 8192 | 4 | 119 | 207.956 ms | 47.262 ms | 2 (see §4) | pass |
| `secure_192` | 16384 | 5 | 146 | 564.238 ms | 122.927 ms | 3 | pass |
| `secure_256` | 16384 | 6 | 175 | 520.801 ms | 129.971 ms | 4 (unverified here) | pass (via acceptance suite) |

Provenance, column by column:

- **N, main lanes, log2(q)** — read off `crates/nine65/src/params/secure_configs.rs`
  and recomputed exactly by `exact_product_bit_length`. Re-measured 2026-08-22.
- **public mul / symmetric mul timings** — from the Phase 0 correctness-gated
  benchmark run (decryption-oracle checked). **Not re-measured in this pass**,
  and no raw artifact is archived for them here. Treat as indicative until
  reproduced under `docs/BENCHMARK_PROFILE_POLICY.md`.
- **public direct-square depth** — re-measured 2026-08-22 for `secure_128`,
  `secure_128_deep`, `secure_192` (see §3). `secure_256` is the benchmark's
  figure, not re-measured.
- **public refresh** — re-measured 2026-08-22 for the same three configs
  (§3). `secure_256` was not exercised standalone in this pass; its "pass" comes
  from `ops::auto_bootstrap`'s
  `repeated_squaring_is_exact_under_auto_refresh_secure_256`, observed passing
  2026-08-22 while that suite was still in flight.

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

> **CORRECTION (integration pass, 2026-08-22).** This section previously printed
> a raw log attributed to a test named `diag_measure_noise_growth` that **did not
> exist in any commit**, and its headline claim — that a `secure_128` refresh
> returns `encrypt(7)` as `8` — is not what the hardware does. The diagnostic now
> exists (`crates/nine65/src/ops/bootstrap.rs`,
> `ops::bootstrap::tests::diag_measure_noise_growth`), the log below is its real
> output, and the claim is restated to match. The refusal itself stands, and on
> better evidence than before: the failure is at the first multiply after the
> refresh, which is exactly the bar the predicate encodes.

Measured with the in-tree diagnostic, which encrypts `7` under each config, runs
the three refresh phases **with the admissibility gate bypassed** (otherwise the
gate would be its own evidence), decrypts, then squares the refreshed ciphertext
through the public eval-key multiply and decrypts again:

```
cargo test -p nine65 --lib --release diag_measure_noise_growth -- --nocapture
```

```
=== diag_measure_noise_growth: public refresh vs the decryption oracle ===
config              lanes  headroom  required    admits |   refresh(7)     refresh(7)^2
secure_128              3        42        47     false |       7 (ok)    34037 (WRONG)
secure_128_deep         4        71        47      true |       7 (ok)          49 (ok)
secure_192              5        96        49      true |       7 (ok)          49 (ok)
=== end diag_measure_noise_growth ===
```

The refresh output itself decrypts correctly on all three configs, `secure_128`
included. What `secure_128` cannot do is survive the **first multiply after the
refresh**: `7` refreshes to `7`, and squaring that returns `34037` where `49` was
expected. Nothing in the pipeline reports an error. Only the decryption oracle
catches it. That is the worst failure shape a crypto library has, and it is why
this is refused in code rather than noted in a report.

The diagnostic asserts the agreement rather than just printing it: a config the
predicate admits must survive both steps, and a config it refuses must be
observed corrupting at least one — so if the refusal ever stops reproducing, the
test fails loudly instead of leaving an unfalsifiable claim in the docs.

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
| secure_128 | 3 | 74 | 32 | 42 | 47 | **no** |
| hardware_opt | 3 | 74 | 32 | 42 | 47 | **no** |
| secure_128_deep | 4 | 103 | 32 | 71 | 47 | yes |
| secure_192 | 5 | 130 | 34 | 96 | 49 | yes |
| secure_256 | 6 | 159 | 34 | 125 | 49 | yes |

Re-measured on the integration pass by
`params::secure_configs::tests::public_refresh_predicate_matches_the_decryption_oracle`.
The `required` column reads 47/49, not the 45/48 published earlier: those were
correct when written and were invalidated by a concurrent rewrite of
`noise::budget`, which is exactly the drift this table exists to catch.

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

The 5-bit margin by which `secure_128` fails is thin. If the noise ledger moves,
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
  public direct-square depths — *without* refresh — are 2–4, and the public
  refresh that would extend them is refused on `secure_128`.

  How far an auto-refreshed chain extends past those depths is a separate
  question. An acceptance suite for it landed in `ops::auto_bootstrap` while
  this pass was in flight (`repeated_squaring_is_exact_under_auto_refresh_*` for
  `secure_128_deep` / `secure_192` / `secure_256`, observed passing 2026-08-22).
  Whatever depth that suite establishes, it is a *measured circuit depth on a
  named profile*, not an unbounded-depth claim, and it must be quoted with the
  profile, seed and commit per `docs/LINEAGE.md`.
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
