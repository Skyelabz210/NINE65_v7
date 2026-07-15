# NINE65 Physical Audit Remediation - 2026-07-13

## Evidence accepted

The independent audit identified two release-blocking discrepancies:

1. the former `secure_128` tuple (`N=4096`, approximately 90 ciphertext-modulus bits) was assessed below its 128-bit claim;
2. documented depth-80 behavior did not match real ciphertext-ciphertext correctness failures observed near depth 8 for `secure_128` and near depth 5 for `secure_192`/`secure_256`.

The audit's latency and throughput figures remain benchmark observations for its stated Xeon environment; they are not portable security or depth guarantees.

## Corrections implemented

### Parameter security

- `SecureConfig::secure_128()` now uses `N=8192` with the same three-prime RNS chain.
- `hardware_opt()` uses the same audited ring-dimension floor.
- named claims are stored separately from internal screening outputs;
- the internal screening gate must meet the complete named claim, with no 90%-of-claim relaxation;
- HE Standard bounds and the audited `N>=8192` floor are both required;
- release security still requires an archived external lattice-estimator record. The in-tree estimator is a deterministic screening tool, not a certificate.

### Depth and benchmark semantics

- `nine65_bench --max-depth` is documented and emitted as a requested mixed-operation count;
- the chain contains ciphertext-plaintext operations and is not represented as ciphertext-ciphertext multiplicative depth;
- unbootstrapped runs stop before the next operation when the modeled budget is insufficient;
- budget resets without real ciphertext refresh have been removed;
- `--auto-bootstrap` and `--statistical-test` require real bootstrap keys and real refresh operations;
- all benchmark percentages, rates, and timing summaries use integer arithmetic; no `f32` or `f64` path remains;
- duplicate ciphertext initialization and duplicate budget consumption were removed.

### Regression gates

`crates/nine65/tests/audit_regressions.rs` verifies:

- the 128-bit production candidate uses `N=8192`;
- every named production candidate satisfies its complete internal claim and HE bound;
- all `secure_128` lanes satisfy `q_i = 1 mod 2N` for the new dimension;
- the audited benchmark contains neither floating-point types nor a simulated-refresh path;
- operation-count language is preserved explicitly.

## CRAM/RNS separation

The remediation preserves the field/ring separation:

- NTT and BFV polynomial lanes remain prime, NTT-friendly field lanes;
- K-Elimination and anchor tracking remain coprime ring operations;
- no Garner reconstruction or mixed-radix conversion was added to the hot path;
- no floating-point variable was introduced.

## Remaining release gates

Before merging a release candidate:

1. run `cargo fmt --all -- --check`;
2. run `cargo check -p nine65 --all-targets --features serde`;
3. run `cargo test -p nine65 --test audit_regressions`;
4. run the existing level-aligned ciphertext-ciphertext depth survey for every production tuple;
5. run an independent lattice estimator for each exact production tuple and archive the inputs, tool version, commit SHA, and output;
6. attach real bootstrap statistical results. A budget reset or simulated refresh is inadmissible evidence.

The unbootstrapped ceiling is a measured property of a specific chain. Unlimited-depth language is valid only for a path that performs successful real bootstrap refreshes and preserves decrypt-and-compare correctness across the requested circuit.
