# Encrypted public refresh circuit and admission boundary

The new `ops::public_refresh_circuit` module implements a complete public
research backend. It is available only with `allow_insecure` (or unit tests).
Its evaluator owns public evaluation keys; the original work secret remains
with `PublicRefreshSourceClient`. It does not enable legacy Phase 1, reset a
bound without evaluating the circuit, or issue CRAM root authority.

## Circuit

The native candidate uses work N8192, plaintext65537, and the existing119-bit
four-prime work basis. Public modulus drops and a key switch produce an
independent balanced-H96 source at the60-bit two-prime prefix. Every input
retains a producer-issued full-polynomial bound and immutable family/history.

The outer ring has N32768 and an exact650-bit,13-prime modulus Q satisfying
`Q = 1 mod 65537²`. Coherent low-noise precharges and public component
projections construct both encrypted views of `x = p*K + r` in slots, with
`|r| <= 49`. All slot copies, signs, source norms, and incoming error terms
belong to the certificate. No support-dependent secret shortcut is used.

For `G(X) = product_(j=-49)^49 (X-j)`, interpolation supplies
`H(j) = 1/G'(j) mod p`. Consequently

```text
G(r+p*K)/p = K*G'(r) mod p
(G(r+p*K)/p)*H(r) = K mod p.
```

G is evaluated at plaintext p²; its proved multiple of p is interpreted at
plaintext p without changing ciphertext components or ideal-grid error.
H and the final product are evaluated at p. The native circuit has68
ciphertext products. Its integer error ledger includes tensor windings,
rounding, plaintext norms, quadratic terms, and key-switch deposits.

The carry is added to the affine message term. A streamed inverse transform
uses32768 public plaintext diagonals and382 Galois calls, without an N²
matrix. Exact24-bit splitting and a certified auxiliary field share each
plaintext transform across main lanes. That field is transient arithmetic,
not an additional ciphertext modulus. Prepared keys and disjoint per-lane
workers preserve the reference result exactly.

The return stage first drops the outer modulus, switches to the embedded
original work key, and projects the work coefficients. Only this checked
stage can issue the sealed return proof. Acceptance validates family,
source lineage, shape, canonical residues, and the returned bound before
issuing the next working ciphertext.

The native preflight gives phase-error bound419222978561 and returned scaled
error bound122782933364666. A full-polynomial square of that returned bound,
followed by the actual source conversion, has certified residual radius48,
within the planned49. This repeated-operation forecast is checked before
key generation; actual inputs are checked again at refresh time.

## Measured native result

The expanded native test passed all five refresh/return/square cycles.
All8192 coefficients matched the independent plaintext oracle after every
refresh and every following multiplication:81,920 coefficient comparisons.
The first refresh consumed an already-squared full polynomial.

| Measurement | Result |
| --- | --- |
| Real encrypted refreshes | 5 |
| Following full-polynomial squares | 5 |
| Total wall time, including key setup | 3393.19seconds (56.6minutes) |
| Peak process resident memory | 9,125,340KiB (8.70GiB) |
| Host resource limits | 4CPU quota cores,16GiB RAM |

This is a functional run, not an isolated latency benchmark. The earlier
three-cycle run took2122.96seconds and remains in the evidence manifest;
reference and quality compilations overlapped parts of that run. The test used seeded
research randomness, optimized test code, overflow checks, and debug
assertions. The executable example uses OS randomness instead.

The [evidence manifest](../../../artifacts/execution/2026-10-28/public-refresh-circuit/manifest.json)
links both successful transcripts, exact binary/source hashes, stage timings,
and resource report. The first native run and subsequent quality build have
separate source manifests. The five-cycle test was rebuilt after the quality
cleanup; its only later source edit changed the example's cycle count. The
evaluated native arithmetic and tuple are unchanged.

The completed local verification also includes134 distinct default Rust
tests,23 exact CI selections (overlapping those tests), three reference-NTT
checks,32 Python tests, Clippy with warnings denied, formatting, and the
integer-only runtime scan. Hosted CI and deployment were not run.

## Use and verification

The executable example uses OS randomness and checks every coefficient after
each refresh and following square:

```sh
cargo run --release -p nine65 --features allow_insecure \
  --example public_refresh_circuit
```

This is an expensive native research computation. The4GiB argument to
`PublicRefreshCircuitPlan::native_research` limits the phase-bank coefficient
payload, not total resident memory. The inverse cache alone is4.375GiB.

The separate native test uses dense, sparse, zero, one, negative, and centered
boundary coefficients in one full polynomial, squares before its first
refresh, then checks five refresh/return/square cycles against independent
schoolbook plaintext arithmetic. Its name is:

```text
ops::public_refresh_native::native_public_refresh_returns_all_8192_coefficients_for_five_cycles
```

Reduced-ring API tests additionally cover three keys,27 refreshes, varied
input histories, branching/rejoining computations, foreign families,
malformed plans, exhausted support, and unchanged counters after refusal.
Independent wide-integer, scale-round, slot, prepared-key, and return-stage
oracles test the underlying arithmetic. The exact gate runner keeps these
research checks separate from production-admission refusal tests.

## Production admission remains separate

The actual Q650 ordered basis passes the in-tree factorization-aware screen
at143 effective Core-SVP bits and129 effective MATZOV bits. These are the
implemented classical/hybrid screening figures, not128-bit quantum
certification. The existing matching H96/Q60 source report has24 finite
estimates and minimum161.34bits; its missing attack-model and joint-key
coverage flags remain false. The embedded return secret must be assessed in
its N8192 work domain, not counted as a dense N32768 secret.

The complete key relationships include work→source→outer→work, together with
self-relinearization and Galois keys. Neither the parameter screen nor the
native execution is a proof of their joint/KDM security. Merely rotating the
final work key would not remove the self-key relationships.

The owner-required CRAM integration also remains distinct. Section7 of the
[root contract](../2026-10-03/PRIMING_ROOT_CONTRACT.md) leaves
`OWNER-LIVE2-11` unresolved and forbids silently substituting a reference
profile. Existing test-only Root211 denotes the full integer `S=g+q*K`, not
just K; attaching its name or a fingerprint to the new carry cannot create
that capability. A real integration must supply and consume the approved
same-source root/projection relations, retain their epoch/history, and
commit the returned root and work state atomically. The architecture permits
expanded digit arithmetic as an internal kernel, not a substitute for those
contracts. Production and legacy gates therefore remain closed.

The selected shadow-prime arithmetic now derives a bounded winding increment
from the difference between two 11-lane views while checking unchanged S8
payload lanes. That checker is not called by this encrypted refresh circuit:
its inputs are protected phase coordinates, whereas the circuit's public
source and return certificates expose lineage and bounds but no authenticated
shadow view of that phase. The earlier suggestion to StarLift a signed
`[-49,49]` carry confused two variables: radius49 bounds the **residual** `r`
in `x=r+p*K`. The encrypted output of `SplitDigitEvaluator` is `K mod65537`;
it does not have a proved `[-49,49]` range. A 36/37 frame of `r+49` would only
recover `r`, and its period1332 cannot uniquely represent every possible
canonical `K` in `0..65536`. The proposed clear carry helper was removed. The
current circuit derives `K` under encryption and consumes it without storing
StarLift coordinates. Any additional StarLift applied to `K` needs its own
protected coordinate producer and certified range; none is required for the
already passing research refresh. Source/value epoch provenance stays bound
to the returned ciphertext.

The [StarLift capacity proof](../2026-10-30/PUBLIC_REFRESH_STARLIFT_PROOF.md)
separates the recoverable canonical `K mod65537` from unbounded historical
`K`. It gives the explicit 36/37 collision, proves that 36/37/73 has enough
capacity for the canonical value, and records the protected-producer obligation.

The native pass establishes this research backend's functional repeated
refresh. It does not establish the separate production admission above.
