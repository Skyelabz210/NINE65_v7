# Application-Critical Formal Proof Spine

The application proof program is deliberately narrower than the full research corpus. It covers the properties an application must rely on before deployment.

## Formalization of record

Lean 4 is the machine-checked formalization of record. Legacy Coq files remain historical unless a current CI artifact demonstrates that the exact theorem compiles without `Admitted`.

## Spine F0 — mode capability separation

Prove that public evaluator modes do not possess a decrypt capability, while symmetric/service modes require an explicit key-holder capability. This prevents API composition from silently crossing security models.

**Lean module:** `KElimination.AppBoundary`

## Spine F1 — structured signal encoding

For the private-feedback reference application:

- field domains are bounded exact integers;
- slot encoding is deterministic;
- no raw text is present in the encrypted aggregation object;
- consent state is represented explicitly;
- each residue is in its declared lane range.

## Spine F2 — residue-native aggregation

Prove lane-wise addition preserves the residue representation of slot-wise aggregation modulo each basis lane. No theorem requires or introduces number-line reconstruction.

## Spine F3 — K-Elimination preconditions and correctness

The application may invoke K-Elimination only with:

- coprime main and anchor products;
- exact-divisibility promise where required;
- a proven bound below the main×anchor uniqueness range;
- a live anchor witness.

The existing K-Elimination proof modules remain the dependency. Application wrappers prove that their constructors establish the preconditions.

## Spine F4 — shared-factor division routing

Prove that shared-factor divisors cannot enter the K-Elimination-only API. Until FPD is machine-checked and integrated, the typed result is rejection. Once enabled, the FPD wrapper must carry the auxiliary-lane coprimality proof and the quotient-state bound.

## Spine F5 — boundary projection

Prove that public evaluator and aggregation functions return residue/ciphertext objects, not plaintext scalars. Number-line output is available only through an explicit boundary capability.

## Spine F6 — serialization validity

Prove or validate that accepted serialized objects satisfy:

- expected degree;
- expected live main and anchor lane counts;
- per-limb length;
- legal level;
- bounded payload size;
- parameter identity/version match.

Malformed objects are rejected before arithmetic.

## Spine F7 — bootstrap state transition

Prove the state transition contract:

- input and output encrypt the same plaintext;
- output has a refreshed usable budget;
- live lane and parameter identities are valid;
- KSK-separated mode returns to the work key;
- a counter reset without ciphertext refresh cannot inhabit the `Bootstrapped` type.

## CI gate

The Lean gate must:

1. build the root module and all submodules;
2. reject `sorry`, `admit`, and unexpected axioms;
3. retain only explicitly registered cryptographic hardness assumptions;
4. fail when `KElimination.AppBoundary` is absent;
5. publish the exact Lean, Mathlib, and commit versions.

## Completion labels

- `MACHINE_CHECKED`: Lean builds under the pinned toolchain and CI gate.
- `EXECUTABLE_CHECKED`: exhaustive/property tests pass, but no Lean theorem exists.
- `PROSE_PROVEN`: mathematical proof reviewed but not machine checked.
- `MEASURED`: finite experiment only.
- `OPEN`: no accepted proof or exhaustive closure.

No application document may collapse these labels.
