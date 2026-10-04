# CRAM public evaluator showcase

From the repository root, run:

```sh
cargo run --offline -p nine65 --example cram_public_showcase
```

The example generates separate evaluator and client key bundles using the
`secure_128_deep` configuration. It encrypts 6 and 7, evaluates an addition and
a public ciphertext multiplication, and checks the results by client-side
decryption. It also multiplies an encrypted 6 by 97 and exactly divides by 97
in the residue lanes. A divisor that is not invertible in a lane is refused.
Any wrong result or accepted non-unit divisor makes the command fail.

The last line from the emission ledger classifies the operations the example
actually ran. Addition, plaintext multiplication, and exact unit division
are lane-local. The general public ciphertext multiplication is recorded as
an R8 materialization. For the precise distinction between that path and the
manufactured-chain elimination-first rescale and relinearization path, see
[CRAM Public Mode](CRAM_PUBLIC_MODE.md). The example is a small executable
tour, not a throughput benchmark or a general circuit-depth claim.

Native public refresh is currently blocked. The older `nine65_v7_demo`
retains a historical “Bootstrap Complete” title; use the example above for a
current CRAM demonstration. The [README claim surface](../README.md#current-limits)
and [public FHE solution route](PUBLIC_FHE_SOLUTION_2026-09-28.md) describe
the refresh gap and the independent reference results. Those reference results
do not establish a native NINE65 refresh or production security claim.

To run the public-mode acceptance suite:

```sh
cargo test --offline -p nine65 --test cram_public_mode --features allow_insecure
```
