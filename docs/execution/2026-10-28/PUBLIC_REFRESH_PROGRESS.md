# Public refresh implementation progress

The named-profile public refresh gate remains closed. The forced
`secure_128_deep` benchmark still fails at the original Phase-1 soundness
gate. This continuation implements a conditional encrypted phase producer
and repairs the acceptance harness; it does not mark that benchmark green.

## Implemented encrypted producer

`ops::public_phase_clock::PublicPhaseClockEvaluator` is executable library
code, promoted from the test-only direct-selector clock. Its evaluator
receives public rotations or actual source ciphertext components and opaque
precharged selector keys. Neither source nor boot secret is an evaluation
argument. Key setup validates consistent ternary source lanes and the actual
secret weight, while each public evaluation traverses every source position.
Setup zeroizes temporary secret-dependent targets.

The producer performs:

1. Endpoint-preserving public component rounding directly from main residues.
2. An encrypted anti-periodic lookup using signed CMUX rotations and a
   Galois trace, yielding the carry modulo the selected chart coordinate.
3. For a chart covering the complete carry, encrypted affine recovery
   `A0 + A1*s + K`, yielding one plaintext coefficient under the boot key.

The new `PhaseClockPlan` binds the actual ordered source factor vector,
active level, degree, plaintext, declared phase-error allowance and secret
weight bound. It uses exact U512 geometry and quantization. Its source
error allowance is a precondition, not authenticated operation history.
An odd chart returns centered K modulo its coordinate; a parity chart
returns `(-1)^K`. Full-carry transduction explicitly requires a sufficiently
large odd chart and matching plaintext modulus.

The key binds its ring, main basis, plaintext, source basis, weight bound,
and error-distribution width eta. Context construction checks the exact
encoding scale. Deterministic error bounds charge every external product,
the entire trace, public encoding remainders, and affine correction.
Direct precharge has an exact polynomial-word storage estimate and a
512 MiB default limit, checked before key generation. An explicit-limit
method permits caller-selected limits; allocator and metadata overhead
remain additional. Geometry or noise admission alone does not admit a
hundreds-of-GiB native key allocation.

## What the encrypted regression proves

The live test uses source degree 8, boot degree 256, plaintext 65537, and
the actual four-prime 119-bit work modulus. The two keys are independently
generated. This is an explicitly insecure small-degree arithmetic fixture,
not a named parameter profile or security certificate.

The source is genuinely encrypted. A public signed perturbation of magnitude
`floor(Q/(512*t))` is applied consistently to its main and anchor lanes.
The observer independently checks `|S-Q*K| <= Q/128` for every coefficient;
no decoded carry or message is passed to the evaluator. There is at least
one nonzero hidden carry and the test covers negacyclic wrap.

All eight output coefficients are transduced independently. An external
test observer verifies their plaintexts, all 255 nonconstant boot-ring
coefficients, exact phase error against the emitted deterministic bound,
and an output bound below Q/1024. Each result survives an actual exact
ciphertext square under the boot key. This demonstrates phase-error
contraction, beyond plaintext-preserving identity calls. It does not
assemble a returned work-ring polynomial or perform a second refresh.

Negative tests cover malformed/mixed source keys, understated source weight,
randomness consumption on invalid setup, mismatched eta, poisoned/short
encoding scales, and explicit precharge storage refusal. Independent review
found the missing eta binding and scale checks; both were fixed before
final validation.

## Public preprocessing and geometry

`CanonicalScaleRound` now supports binary target 2 and returns a private-state
`CanonicalRoundedCoefficient` through `scale_round_unreduced`. This retains
the upper rounded endpoint T, which modular output represents as zero.
The existing modular method preserves its semantics. The existing research
full-polynomial preprocessing now delegates to this checked implementation.
For Q=35 and X=31, losing that endpoint changes the signed clock residual
from -1 to +11; a permanent regression preserves this witness.

The projection tests cover 7,510 exhaustive small cases and 42 independent
149-bit-Q integer vectors. The geometry tests independently check 31,212
admitted signed trit tuples, wide named-Q quantization, malformed/full-width
inputs and native window refusal. Q60/H96/outer-N16384 gives the previously
reported window 13,699. Dense H8192 at clock N8192 refuses.

## Acceptance harness corrections

The real-refresh workflow expected obsolete `depth_chain` fields while the
benchmark emitted `operation_chain`. Both preflight tests were ignored and
used outdated sqrt(N) bounds. They now execute with the deterministic bounds.

The benchmark now records independent expected/decrypted values immediately
after each refresh and each operation, including every statistical trial.
Scalar noise costs use the actual operand; its single-q scale test cannot
borrow RNS capacity. A strict checker requires completion, canonical plaintext
oracles, every forced refresh, all statistical trials, and integer-only data.
Fourteen negative-control tests reject missing, stale, contradictory, wrong,
partial and simulated evidence. An actual correct run without bootstrap is
rejected as real-refresh evidence. An actual forced run still fails at the
production soundness gate.

The forced benchmark also requires a separate renewal witness on the actual
public entry point. It injects `floor(Q/(8*N*t))` into coefficient zero,
checks the complete source phase against the Q/(2N) reserve, and requires
the entire returned polynomial's measured ideal-grid error below its declared
refresh bound. A no-op fails because the input error must exceed twice that
bound. The observer uses independent direct weighted CRT, exact U256/U512
arithmetic, and exact decimal reporting. Four arithmetic regressions cover
small exhaustive CRT states, full-width modular operations, wrapped phase
errors and decimal encoding. The current named-profile engine refuses this
witness; no successful renewal observation is reported for it.

## Conditions still required for named-profile green

* An authenticated dense-work ingress or reviewed dense-to-sparse source
  switch, including the real source error and support bounds.
* A scalable full-carry/common-encoding construction for native degrees.
  The current direct complete-carry chart cannot cover H8192 within the
  supported practical clock geometry. Modular chart outputs alone cannot
  be treated as a complete signed lift.
* Full-polynomial assembly, admitted work-key return, and repeated
  refresh/product cycles using the actual public entry point.
* Native storage/runtime bounds and security review of the additional
  selector/key-dependent material. The dense parameter screen does not
  supply that review.
* The forced named-profile workflow, with a stressed-input contraction
  witness connected to that entry point. Per-call plaintext oracles alone
  are insufficient evidence of noise renewal.

These are implementation and verification obligations, not requests for a
finished artifact upload. The new kernel advances the missing encrypted
transition; it is not wired around the named-profile guard.

## Validation

Projection: 6 tests per profile. Geometry: 4 per profile. Encrypted producer:
4 per profile. Restored preflight: 2 per profile. Evidence checker: 14 tests.
The benchmark observer has 4 passing arithmetic tests. Expanded preprocessing
integration has 7 passing debug tests; its binary-target and 512-bit accumulator
expectations now match the supported contracts.
The existing live research preprocessing test also passes. Focused CI now
runs the new arithmetic and encrypted producer in debug and release, and
the production source scanner includes all three new/extended paths.
Clippy, formatting, the panic ratchet and the 17-file architecture scan pass.
The broader library/workspace suite is not rerun in this continuation; its
previous four library failures remain unresolved.

See `public-refresh-evidence/validation.json` for source hashes, exact logs,
and expected failing named-profile evidence.
