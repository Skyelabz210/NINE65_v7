# Aider source review

Unaccepted reviewer suggestions; see REVIEW_DISPOSITIONS.md. Only the final answer is retained.

## 1. Concrete contradictions and gaps

- **Stale WR-1 bound/oracle coverage.** `exact_mul.rs:49-74` says production
multiplication requires `N/2`, while the verifier is reported to use `N/4`; it
further admits the oracle tests one product but not the `d1` sum of two
products. This is documented test/implementation provenance drift. The omitted
verifier lines prevent direct confirmation.
- **Metadata is presented as plaintext correctness.**
`generate_depth_correctness_matrix.py:94-100` sets `correctness_verified` from
`max_depth > 0` and zero collapses. Neither proves encrypted output decrypts to
the expected plaintext. This conflicts with the stronger standard documented for
the showcase at `CRAM_SHOWCASE.md:9-14`.
- **Benchmark configuration provenance is unused.**
`parse_benchmark_output(output, config)` accepts `config` at line 59 but never
uses it. Output from another configuration can therefore be accepted under the
supplied label. Feature flags, source/build identity, test-vector identity, and
expected depth are also not checked.
- **Configuration values are independently hard-coded.**
`verify_wr1_transient_exact.py:22-47` hard-codes parameter tuples and names. The
matching `secure_128_deep` label in `CRAM_SHOWCASE.md:9-10` does not prove those
values equal the runtime `FHEConfig`, AUX capacity, ring degree, or enabled
features.
- **The tracked-state privacy claim is contradicted by the API.**
`auto_bootstrap.rs:68-71` says the private budget keeps `ct` and budget
synchronized, but `ct` is public at line 67. Callers can potentially mutate or
replace it without advancing the ledger.
- **Construction does not visibly bind ciphertext to configuration.**
`TrackedCiphertext::fresh` at `auto_bootstrap.rs:74-85` accepts any
ciphertext/config pair and initializes a budget from that config. No excerpt
shows validation that the ciphertext was produced under the same parameters.
- **Auxiliary-capacity claim lacks linkage.** `exact_mul.rs:64-67` claims zero
extra AUX lanes, but the supplied evidence only shows a hard-coded `AUX_10`; it
does not connect that tuple to runtime capacity or per-config boundary tests.

## 2. Five work tickets

1. **Target: configuration provenance.**
   **Negative test:** Label `secure_192` output as `secure_128_deep`, or change
one AUX lane; acceptance must fail.
   **Done:** Reports contain and validate a canonical parameter/feature
fingerprint from the actual `FHEConfig`.

2. **Target: matrix correctness evidence.**
   **Negative test:** Produce positive depth and zero collapses with wrong or
absent client-decrypted plaintext; it must not pass.
   **Done:** `correctness_verified` is true only after an explicit
expected-plaintext decryption comparison.

3. **Target: WR-1 `d1` bound.**
   **Negative test:** Add a near-`NQ²/2` two-product `d1` case that an `N/4`
oracle misclassifies.
   **Done:** Verifier and implementation pin `N/2`, and the test exercises
summed `d1`, not only one product.

4. **Target: `TrackedCiphertext::fresh` parameter identity.**
   **Negative test:** Pair ciphertext from one configuration with another
configuration’s budget; construction must fail.
   **Done:** A ledger is created only after ciphertext/configuration identity is
validated.

5. **Target: atomic tracked-state transitions.**
   **Negative test:** Replace/mutate public `ct`, fail an operation midway, and
clone then advance one value; ledger/ciphertext drift or cross-clone mutation
must be impossible.
   **Done:** `ct` is encapsulated, state commits atomically, and clones have
independent ledgers.

## 3. Unknowns

- The verifier’s omitted bound checks and plaintext/decryption evidence.
- Runtime `FHEConfig` values and feature-dependent parameters.
- `NoiseBudget` calculations and evaluator failure/commit behavior.
- Whether an external matrix runner performs checks absent from the parser.
- The exact security scope of the `allow_insecure` acceptance suite
(`CRAM_SHOWCASE.md:31-35`).

Tokens: 3.4k sent, 5.0k received.
