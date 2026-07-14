# Strict Comparative FHE Harness

This directory defines the interchange contract for comparative analysis. It is designed for exploratory work and refuses comparisons when the records are not equivalent.

## Required normalized record

```json
{
  "schema": "fhe-comparison-record-v1",
  "implementation": "NINE65",
  "version": "commit-or-release",
  "operation": "mul_ct",
  "samples_ns": [13960000, 14010000],
  "correctness": {
    "trials": 2,
    "failures": 0
  },
  "compatibility": {
    "scheme": "BFV-DualRNS",
    "plaintext_semantics": "scalar-mod-t",
    "target_security_bits": 128,
    "security_estimator": "named-estimator-and-version",
    "n": 4096,
    "log_q_bits": 90,
    "plaintext_modulus": 65537,
    "slots": 1,
    "refresh_kind": "none",
    "hardware_fingerprint": "sha256-of-hardware-document",
    "threads": 1,
    "build_profile": "release-fat-lto-cgu1",
    "sample_policy": "warm-steady-state"
  },
  "provenance": {
    "repository": "owner/repository",
    "commit": "full-sha",
    "command": ["executable", "--flag", "value"],
    "raw_artifact": "relative/path.json"
  }
}
```

## Compatibility rule

Two records are ranked only when every field in `compatibility` and the `operation` field are identical. A mismatch produces an `INCOMPARABLE` result with the differing fields listed.

This deliberately blocks misleading comparisons such as:

- BFV ciphertext multiplication versus TFHE programmable bootstrapping;
- scalar messages versus packed SIMD throughput;
- 98-bit estimates versus 128-bit estimates;
- different CPUs or thread counts;
- simulated refresh versus real bootstrap;
- N=1024 testing parameters versus N=4096 production parameters;
- cold key generation versus warm key retrieval;
- published figures from another machine versus local measurements.

## Statistical representation

All timings are integer nanoseconds. The analyzer reports:

- sample count;
- minimum and maximum;
- median as an exact numerator/denominator pair;
- nearest-rank p95 as integer nanoseconds;
- comparison ratios as reduced integer fractions;
- correctness failures separately from timing.

No floating-point statistic is required for a gate.

## External adapters

SEAL, OpenFHE, TFHE-rs, and other systems may be tested by any adapter that emits the normalized record. The adapter must preserve its native scheme name and operation semantics. It must not relabel a PBS, gate, packed vector operation, or approximate CKKS operation as BFV scalar multiplication merely to force a comparison.

## Baseline and candidate use

Use `scripts/cram_compare_results.py` with one or more matrix manifests or normalized records. The output groups compatible records and marks all other pairs incomparable. Baseline identity is provided through the record's `version` or `provenance.commit`; it is not inferred from file order.
