# Lattice Estimator Baseline (2026-01-27)

> **Superseded (2026-08-19):** parameters below (`secure_128` n=4096,
> `secure_192` n=8192) predate the current `secure_configs.rs` (`secure_128`
> n=8192, `secure_192`/`secure_256` n=16384). This is nonetheless the only
> baseline in this directory produced with the real external
> `lattice-estimator` tool rather than the in-tree Rust heuristic — see
> `docs/LATTICE_ESTIMATOR_BASELINE_2026-02-25.md` for the fuller staleness
> and regeneration note.

Tooling:
- Lattice estimator: malb/lattice-estimator @ 66771ec3d331e2021eccf17331a5ed1ff71f3ddb
- Runtime: sagemath/sagemath:9.5 (via Docker)

Method:
- Estimator: LWE.estimate.rough
- Secret distribution: ND.Ternary
- Error distribution: ND.CenteredBinomial(eta)
- Samples: m = n
- Modulus: q = product of RNS primes in SecureConfig

## secure_128
- n=4096, eta=3, q_bits=89.26
- usvp: rop ~= 2^124.7
- dual_hybrid: rop ~= 2^123.6 (min)

## secure_192
- n=8192, eta=4, q_bits=145.39
- usvp: rop ~= 2^166.7
- dual_hybrid: rop ~= 2^165.6 (min)

## secure_256
- n=16384, eta=5, q_bits=203.81
- usvp: rop ~= 2^269.5
- dual_hybrid: rop ~= 2^268.1 (min)
