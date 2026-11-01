# Correctness evidence for PublicRefreshCircuit

Current routing: [public refresh status](../PUBLIC_REFRESH_STATUS.md).

Three layers. They are not substitutes for each other.

## Observed

The archived native run checked five refreshes and five following squares, 8,192 coefficients after each operation: 81,920 comparisons. The transcript and manifest are hashed in `docs/public_refresh_status_sources.json`. The run took 56.6 minutes including setup and peaked near 8.70 GiB. It used seeded research randomness on one arithmetic snapshot.

That snapshot predates the canonical-root and key-inventory additions. It is not a latest-head rerun. It is not a sample of the plaintext space. It is not a statistical coverage argument.

## Bounded, inside the noise model

The algebraic certificate says the G/H identity recovers `K_native` on the stated support, the fused add restores the message, and `ReturnNoisePlan` refuses a return whose infinity-norm envelope exceeds `Q/2`. The native plan's published envelope is 562 bits after slot return against a 633-bit threshold, with next radius 48 inside support 49. The lift note records an independent oracle over all 97 signed quotients and 99 residuals (9,603 combinations).

This is bounded correctness under those hypotheses. A probabilistic decryption-failure bound is not derived. Bounded correctness is not confidentiality.

Negative controls that do exist in source: the key-inventory check refuses a mismatched sample count; refresh refuses a phase output whose lineage, radius, or bounds disagree with the plan; the return refuses a family or context mismatch. This note does not promote those checks into a completed malformed-ciphertext, wrong-KSK, and wrong-epoch suite. No such suite is claimed.

## Formal

Lean 4 has not been extended to this circuit. `formal.lean_record` does not cover it. The lift note says the refinement is not a Lean verification.

## Not security

Nothing in the observed column or the bounded column establishes related-key confidentiality, external parameter attestation, constant-time behavior, or production admission.
