# CRAM Integration Contract for NINE65 Applications

**Status:** Normative for new application code.

## 1. Canonical execution rule

Application values enter the CRAM/NINE65 substrate once and retain an explicit
residue state and operation contract. Under the user's 2026-10-27 clarification,
reconstruction is permitted; synthetic emissions such as Garner and mixed-radix
digit conversions remain prohibited in residue compute.

Production hot paths must report zero activity for:

- synthetic emissions from Garner or mixed-radix conversions;
- information loss that violates the declared reversible operation;
- floating-point arithmetic.

Reconstruction and projection counters must accurately report their activity;
their nonzero values are not automatic policy failures. The user's IID model
concerns independently sampled driving digits and reversibility of the induced
carry process. When the Holte model applies, statistical reversibility means
Eulerian-weighted detailed balance; the carry sequence need not itself be IID.
Logical operation reversal is a separate property. Division retains its
remainder and required state when that reversible operation is claimed. Joint
output-coordinate uniformity is an additional diagnostic only when its product
domain is explicitly part of the contract. Structural emission checks remain
separate: reversibility and uniformity alone do not exclude Garner or
mixed-radix algorithms. Finite tests certify only their stated domain.
A diagnostic oracle cannot be substituted for the production algorithm.

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

Until a shared-factor FHE divider is implemented and gated, an application must
reject that division rather than silently use an unvalidated quotient path.

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

A topology must not conceal a forbidden synthetic emission, change its lift
without provenance, or omit a required recovery rule through a helper function.

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
