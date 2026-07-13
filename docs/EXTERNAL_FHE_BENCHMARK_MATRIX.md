# External FHE Benchmark Matrix

This protocol compares implementations without converting unlike schemes or security models into a single misleading ranking.

## Implementations

The harness has adapters for:

- NINE65;
- Microsoft SEAL;
- OpenFHE;
- Lattigo;
- TFHE-rs.

An implementation is recorded as `unavailable` until a pinned command is supplied. Missing data is never estimated.

## Required pinning

Every result records:

- implementation commit or release;
- compiler and optimization flags;
- CPU model and instruction-set availability;
- operating system;
- thread count;
- scheme and security mode;
- polynomial degree;
- plaintext modulus or message space;
- full ciphertext modulus chain;
- decomposition/key-switch parameters;
- bootstrap type;
- exact operation circuit;
- trial count.

## Integer-only result schema

Latency is recorded in integer nanoseconds. Size is recorded in integer bytes. Trial counts and operation counts are integers. The repository comparison path does not use floating-point values.

```json
{
  "implementation": "nine65",
  "commit": "<sha>",
  "parameter_id": "<exact tuple id>",
  "mode": "public-evaluator",
  "records": [
    {
      "operation": "mul",
      "median_ns": 0,
      "p95_ns": 0,
      "bytes": 0,
      "trials": 0
    }
  ]
}
```

## Operation groups

### Group A — primitive arithmetic

- key generation;
- encryption;
- decryption;
- ciphertext addition;
- plaintext addition;
- plaintext multiplication;
- ciphertext multiplication;
- relinearization/key switching;
- rotation where supported.

### Group B — refresh

Report separately:

- leveled depth before refresh;
- bootstrap/refresh latency;
- post-refresh usable depth;
- circular, KSK-separated, or symmetric protected mode;
- number of live RNS lanes before and after refresh.

A software budget reset is excluded.

### Group C — application circuits

- private counters and histograms;
- bounded scoring;
- private-feedback structured signal aggregation;
- comparison/lookup circuits only where semantically comparable;
- serialization and network payload size.

## Comparison rules

1. BFV/BGV exact modular arithmetic is compared directly only against an equivalent exact circuit.
2. CKKS approximate arithmetic is listed separately; approximate error is not converted into an exact-equivalence claim.
3. TFHE programmable bootstrap results are listed by gate/message circuit and are not treated as identical to BFV ring multiplication.
4. Public evaluator, symmetric protected, and server-key-holder results occupy separate rows.
5. Hardware acceleration is reported as a distinct substrate.
6. NINE65 Recumbent/persistent-Montgomery gains are decomposed into saved boundary conversions, lane arithmetic, K-Elimination, and bootstrap costs.
7. Garner and mixed-radix activity in a NINE65 production run invalidates the residue-native benchmark row.

## Execution

Set one or more pinned commands and run:

```bash
NINE65_BENCH_CMD='<command>' \
SEAL_BENCH_CMD='<command>' \
OPENFHE_BENCH_CMD='<command>' \
LATTIGO_BENCH_CMD='<command>' \
TFHERS_BENCH_CMD='<command>' \
python3 scripts/external_fhe_matrix.py
```

The initial CI gate executes `--self-test` to validate the schema. Claim-grade external measurements require controlled same-machine execution and checked raw artifacts.
