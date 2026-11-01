# Repository guidance for public-refresh work

Read [current refresh status and notation](docs/PUBLIC_REFRESH_STATUS.md)
before diagnosing refresh from a historical handoff, issue or test name.
Use [CLAUDE.md](CLAUDE.md) for the repository's coding conventions.

* The explicit `ops::public_refresh_circuit` research backend has a real
  encrypted carry producer and archived native repeated execution. The legacy
  `ops::bootstrap` default entry points remain gated. State which one you mean.
* Scope legacy K_0, the source quotient K_native, residual rho and adjacent
  kappa to their defining equations. Do not transfer one producer's bound or
  impossibility result to another merely because both use the letter K.
* Separate functional correctness, performance, root/provenance binding and
  confidentiality of the full key setup. No production-security grant follows
  from successful arithmetic or a parameter estimator alone.
* Preserve historical evidence. Add dated scope notes and current-status links;
  do not rewrite raw measured results, frozen baselines or their hashes.
* New correctness evidence must identify the actual executed test and snapshot.
  A cost model, zero matching tests, or metadata reset is not an encrypted run.
* Do not enable legacy gates or claim that independent protected S8 remainder
  ciphertexts exist because canonical plaintext-root preservation is implemented.
