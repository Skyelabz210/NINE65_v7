# Exact inputs for independent public-refresh security review

This is a prepared review request, not an external assessment or attestation.
No reviewer has signed it and no material has been sent outside this repository.
The key-free exporter at source commit `1c553f6d723ecf52c4f131ca4060c794b59e52e6`
emits the [exact input packet](assessment-remediation-evidence/independent-review-inputs.json).
All prime moduli are decimal strings to prevent accidental floating-point rounding.

Reproduce in the documented research development environment:

```sh
cargo run --locked --config profile.dev.package.nine65.opt-level=2 \
  -p nine65 --features allow_insecure,serde \
  --example public_refresh_review_packet > independent-review-inputs.json
```

The exporter generates no secret or evaluation key. It obtains ordered tuples
and publication counts directly from the native planner and key graph. The
native domains are Work N=8192/four primes, Source N=8192/two primes/H96, and
Outer N=32768/13 primes. The four shipped named profiles are listed separately;
they are not the native circuit's security classification. Rings are the
negacyclic rings Z_Q[X]/(X^N+1); review must preserve the factorized moduli.

## Questions requiring independent conclusions

1. Verify each actual secret/error sampler, its bias, and every assumption
   needed to model it. Check `public_refresh_key_graph.rs`, the source setup,
   `rns_fhe.rs`, and entropy producers against the packet. An eta or a nominal
   distribution name alone is insufficient to establish the implemented law.
2. Assess classical and quantum attacks for the exact factorized rings,
   including sparse-source and reduced-dimension/embedded return-secret
   attacks. The return secret's effective degree is 8192, not outer degree 32768.
   Preserve tools, versions, model choices, raw output and limitations.
3. Analyze the complete seven-relation publication graph, including the
   W→S→B→W cycle, self/relinearization/Galois relations, and both phase banks.
   The graph fingerprint binds the inventory; it is not a security proof.
   Separate individual-domain estimates do not prove joint confidentiality.
4. Establish a reduction or explicitly reviewed assumption for the
   [joint-setup work IND-CPA experiment](../2026-10-31/PUBLIC_REFRESH_SECURITY_REDUCTION.md).
   The existing public-evaluation simulation only preserves that unestablished
   premise. It does not derive it from ordinary independent-key RLWE.
5. State precisely which tuples and attack models an independent conclusion
   covers. Include independent reviewer identity, pinned source and tool
   revisions, reproducible commands, raw results, exclusions, and a signed
   conclusion. A signed estimate of separate domains alone must not become
   acceptance of the correlated setup.

## Separate engineering obligations

An estimator or joint-key analysis does not establish constant-time execution,
a probabilistic decryption-failure bound, service authentication, or correctness
for all histories. Those need their own evidence. The native tuple continues
to carry `security_bits=0`; named-profile screen results remain heuristic,
including the secure_256 MATZOV shortfall. External parameter attestation is
not obtained. Production admission remains closed.

