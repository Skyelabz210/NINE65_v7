# M1 Report - Formalization Invariant Tests

Added deterministic integration tests exercising proof-aligned invariants:
- Exact-sum softmax (IntegerSoftmax.v)
- Mobius signed arithmetic (MobiusInt.v)
- Pade zero identities (PadeEngine.v)
- Exact divider reconstruction (ExactCoefficient.v)

See: crates/nine65/tests/formalization_invariants.rs

Existing unit tests in arithmetic modules continue to cover K-Elimination and
Order Finding invariants.

Test run:
- cargo test -p nine65 formalization_invariants -- --nocapture
- log: swarm_run/jobs/M1/output/test.log
