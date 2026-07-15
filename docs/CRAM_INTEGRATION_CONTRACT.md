# CRAM Integration Contract for NINE65 Applications

**Status:** Normative for new application code.

## 1. Canonical execution rule

Application values enter the CRAM/NINE65 substrate once, remain in residue coordinates throughout internal computation, and project to the number line only at an explicit I/O boundary.

Production hot paths must report zero activity for:

- CRT reconstruction;
- Garner reconstruction;
- mixed-radix conversion;
- hidden scalar materialization;
- internal number-line projection;
- floating-point arithmetic.

A diagnostic or test oracle may reconstruct outside the production path only when the boundary is explicit and the production architecture counters remain unchanged.

## 2. Safe basis and role coverage

The current canonical CRAM safe basis is:

```text
{2, 3, 5, 7, 11, 13, 17, 19}
```

Its use is role-aware rather than a flat interchangeable prime list:

| Prime | Required role in current CRAM work |
|---:|---|
| 2 | parity / binary boundary witness |
| 3 | triadic witness |
| 5 | surface / Ramanujan-family witness |
| 7 | bridge / Ramanujan-family witness |
| 11 | shadow / disambiguation / Ramanujan-family witness |
| 13 | boundary witness |
| 17 | structural-lift / saturation witness |
| 19 | spectral / saturation witness |

Applications may choose another pairwise-coprime basis, but must document which roles are preserved, omitted, or replaced. The name `safe basis` is reserved for a basis whose coprimality, dynamic range, role coverage, and operation preconditions have been validated.

## 3. Prime families and composite carriers

Prime-family metadata is retained when relevant to topology selection. The principal current families include twin, cousin, sexy, Sophie Germain, Polignac, Green–Tao progression, and Goldbach relations.

Applications compute with residue lanes and coprime composite carriers. Primes provide irreducibility and role witnesses; composite carriers may package multiple witnesses when pairwise-coprimality constraints remain satisfied.

Composite moduli are classified before use:

- **CLASS-F:** field structure required; modulus must satisfy the prime/NTT conditions.
- **CLASS-R:** ring and modular-inverse structure sufficient; pairwise coprimality is required, primality is not.
- **CLASS-A:** composite operation containing both CLASS-F and CLASS-R stages; each stage is checked independently.

NTT lanes remain CLASS-F. K-Elimination anchors, integrity lanes, and compatible base-extension support are CLASS-R.

## 4. Division routing

### 4.1 K-Elimination

Use K-Elimination only when its declared conditions are satisfied:

- the main and anchor products are coprime;
- the divisor is a unit against the relevant basis for the chosen form;
- the exact-divisibility promise is established;
- the tracked range guarantees uniqueness of the winding/overflow scalar;
- anchor capacity exceeds the maximum reachable scalar.

K-Elimination operates from residue and anchor phase information and returns a residue-native result. It must not invoke Garner or mixed-radix conversion on the hot path.

### 4.2 Fused Piggyback Division

Shared-factor divisors route to Fused Piggyback Division when that production path is enabled. The auxiliary modulus must be coprime to both the primary basis product and the divisor. The auxiliary lane is ephemeral, participates only for the division, and is discarded after residue-native quotient projection.

Until the FPD FHE path is implemented and gated, an application must reject shared-factor exact division rather than silently route through reconstruction.

## 5. Winding, anchor, and shadow state

A value that can exceed a basis product carries explicit winding or bound state. Wrap count is never inferred from a truncated scalar after the fact.

Anchor state must include:

- the live anchor basis;
- anchor-product capacity or exact limb representation;
- the phase/witness required for K-Elimination;
- a bound certificate proving the reachable value remains within the uniqueness range.

Shadow state is typed separately from ordinary hot-lane state. The 11-lane may serve a disambiguation role, but an application-specific shadow claim must identify its signature and falsification test.

## 6. Heterogeneous topology and transduction

Per-lane heterogeneous operators are permitted when declared by a validated topology. Cross-lane movement occurs only through an explicit Transduction edge with:

- source and destination lane types;
- exact integer transform;
- bound update;
- role/classification check;
- architecture-counter assertion;
- inverse or recovery rule when reversibility is claimed.

A topology must not smuggle an integer reconstruction through a helper function.

## 7. Application acceptance tests

Every application crate must provide:

1. basis coprimality and role tests;
2. residue range tests after every operation class;
3. K-Elimination precondition and negative tests;
4. shared-factor division rejection or FPD tests;
5. architecture-counter assertions;
6. small exhaustive tests;
7. large randomized exact-integer differential tests;
8. endurance tests;
9. serialization validation;
10. explicit boundary-projection tests.
