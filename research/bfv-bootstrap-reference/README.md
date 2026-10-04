# Public BFV bootstrap reference at t = 65537

This standalone executable tests a complete public refresh construction using
`fheanor = 0.11.9`. It is outside the NINE65 Cargo workspace and does not enable
NINE65's disabled public bootstrap API. Its dependencies and nightly compiler
are pinned in this directory. Fheanor is an MIT-licensed research implementation;
it is not a production security or side-channel attestation.

The evaluator boundary `public_refresh` accepts ciphertexts and evaluation keys,
with no secret key or plaintext argument. It always disables the upstream
secret-key debugging option. The client uses its secret only for initial key
generation, encryption, and external correctness/noise measurements.

The workload checks fresh encryption, ciphertext addition, two relinearized
squares, and then repeated **refresh → square** cycles. Every plaintext
coefficient is checked after each refresh and subsequent square. Expected
products come from a separate integer negacyclic NTT oracle; a schoolbook
convolution test checks that oracle. A mismatch exits unsuccessfully.

## Reproduce

From this directory:

```sh
cargo fetch --locked
cargo test --release --locked --offline -j1
cargo build --release --locked --offline -j1
# Repeated functional smoke test: not a secure parameter set.
target/release/nine65-bfv-bootstrap-reference --log-n 10 --rounds 3 --digit-bound 17
# Larger functional test: not a secure parameter set; took about 9 minutes and 1.2 GiB here.
target/release/nine65-bfv-bootstrap-reference --log-n 13 --rounds 2 --q-bits 1000 --digit-bound 32
# Retain stdout, stderr, resources, parameters and source/binary hashes:
python3 run_reference.py --name local_n1024_run1 -- --log-n 10 --rounds 3 --digit-bound 17
```

All arguments are unique flag/value pairs. Other options are `--q-bits` (820),
`--digit-bound` (32), `--transform-levels` (4), `--gadget-digits` (5), and
`--pre-squares` (2). Changing a parameter is an experiment, not a certificate of
admissibility. Random keys and errors are newly sampled on every run.

Progress goes to stderr and the successful result JSON goes to stdout. The JSON
explicitly records absent security attestation and disabled native NINE65
refresh. Secret keys and ciphertext material are not included in the report.
The runner writes under `../../artifacts/bootstrap/` and refuses to overwrite
an existing run name. Its `.run.json` records unsuccessful exits as failures.

## Construction and limits

The construction uses a full ciphertext modulus near 820 bits, a uniform ternary
work secret, coefficient/slot transforms, temporary encapsulation under a
weight-32 sparse secret at a smaller modulus, and bounded-error digit removal
over `65537^2`. Each tested power-of-two cyclotomic index divides `65536`, so
every plaintext slot has degree one: the thin bootstrap supports the complete
plaintext polynomial ring at these geometries.

The error radius 32 is a circuit input assumption. This harness does not yet
prove an operation-history bound that enforces it for every possible key,
error sample, and admitted ciphertext. Its successful runs are functional
evidence, not an unconditional 100% correctness guarantee. Upstream Gaussian
sampling and floating-point parameter calculations also differ from NINE65's
integer-only runtime contract.

All listed parameters are for correctness experiments and are **insecure
examples**, especially the tiny `N=1024` smoke ring. The `N=8192`,
`log2(Q)≈990` configuration is far beyond the Homomorphic Encryption Standard
v1.1 128-bit guidance at that degree, and the standard does not recommend
sparse-secret parameters. The possible larger target `N=32768`,
`log2(Q)≈810` still needs evaluation-key and sparse-switch security review.
Never reuse experiment keys or publish these test configurations as secure.

Sources:

- [Fheanor bootstrap source, reviewed commit](https://github.com/FeanorTheElf/fheanor/blob/2ba00539204cc03816dd258b57fad94904f54d41/src/bfv/bootstrap.rs)
- [Bootstrapping for BGV and BFV Revisited](https://eprint.iacr.org/2022/1363)
- [Bounded-error digit extraction via null polynomials](https://eprint.iacr.org/2024/115)

See `../../docs/PUBLIC_FHE_SOLUTION_2026-09-28.md` for the native implementation
requirements and the independent bounded-polynomial identity certificate.
