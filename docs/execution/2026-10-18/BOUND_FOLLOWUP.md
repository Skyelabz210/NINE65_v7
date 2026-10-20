# Noise-bound follow-up — 2026-10-18

This follow-up advances C01 without changing its acceptance status. The
repository now has a partial exact-integer FPD oracle and a draft contract:

- `docs/execution/2026-10-03/BOUND_CONTRACT.md` records the selected FPD
  rounding rule, strict auxiliary capacity, and the `N/2` summed tensor bound.
- `scripts/certified_noise_oracle.py` implements independent integer
  reference functions; it does not issue a production certificate.
- `scripts/test_certified_noise_oracle.py` exhausts the stated toy domains and
  includes negative fixtures for the FPD floor term and omitted `d1` cross
  product.

Verification run:

```text
$ python3 -m unittest discover -s scripts -p test_certified_noise_oracle.py
......
Ran 6 tests in 0.241s
OK

$ git diff --check
passed

$ curl http://127.0.0.1:8080/healthz
{"service":"fhe-service","status":"ok","timestamp_unix":1792383779}
```

## Main-Q scalar service route — 2026-10-18

The HTTP service has since been moved off the old dual-RNS wire refusal and
onto a bounded scalar main-Q route:

- `nine65::ops::cram_main` issues private immutable ciphertext wrappers and
  tracks a per-ciphertext exact integer error bound. It admits encrypt, add,
  subtract, negate, scalar add/multiply, and exact ciphertext multiply only
  while `2V < Q`; it refuses depth before publishing a result.
- `wire_q` exports a strict main-Q-only v1 encoding. Imports require the exact
  bytes to have been issued by that session's producer registry, so a caller
  cannot establish a fresh bound by wrapping or modifying serialized data.
- Service handlers now use that route. The service remains a server-keyholder
  deployment: its session owns both evaluator and decryption material, and
  `/decrypt` remains disabled by default and operator-token gated when enabled.

Validation after integration:

```text
cargo check --locked --offline -j1 -p fhe-service                 passed
cargo test --locked --offline -j1 -p fhe-service --no-fail-fast  54 passed, 27 ignored
python3 -m unittest test_certified_noise_oracle test_benchmark_contract 28 passed
HTTP secure_128 encrypt [6,7] -> multiply -> decrypt 42             passed
```

The service was started on `127.0.0.1:8081`; the pre-existing listener on
`:8080` was left untouched. This closes the service transport gap for the
certified scalar subset only. It does not close all of C01: the exact bound is
not yet established for every legacy transition, especially modulus switching
and encrypted refresh/digit removal. C02/C03 are implemented only for this
producer-issued main-Q route, and the 27 legacy DualRNS/heuristic-budget tests
remain ignored. The main-Q proof also needs independent cryptographic review
before production/security acceptance. Full CRAM refresh, external
client-secret key separation, and issue #92 completion remain open.
