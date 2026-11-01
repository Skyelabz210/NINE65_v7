# Machine-checked arithmetic for public refresh

This change adds 50 explicit Lean theorems in five standard-library-only
modules. They are checked with the repository's pinned Lean 4.27.0-rc1
kernel. Every declaration's transitive axiom dependencies are inspected;
the slice admits no custom axiom or `sorryAx`. Lean's usual logical
foundations remain allowed.

The integration base is `924f52e`, after PRs #201 and #202. Read
[current refresh status](../../PUBLIC_REFRESH_STATUS.md) for the distinction
between the working opt-in research `PublicRefreshCircuit`, the conditional
small-degree phase-clock prototype, and the disabled legacy Clockwork APIs.
The archived five-cycle native run retains its original source snapshot.

## Native research producer

[PublicRefreshDigit.lean](../../../lean4/KElimination/KElimination/PublicRefreshDigit.lean)
proves the complete symbolic G/H digit identity for arbitrary integer
coefficient lists and every signed integer K. Its Taylor expansion is proved
by induction, rather than assumed:

```text
G(r+p*K) = G(r) + p*K*G'(r) + p²*E,  E an integer.
```

The final `certified_split_digit` theorem assumes exactly the arithmetic
certificates checked by `bounded_digit_circuit::polynomials`: `p>0`,
`G(r)=0 mod p²`, and `G'(r)*H(r)=1 mod p`. It proves

```text
((G(r+p*K) mod p²)/p) * H(r+p*K) = K mod p.
```

The division is exact on the certified multiple. Canonical p² reduction
and signed inputs are included. A separate theorem connects the Horner
derivative to the runtime's explicit indexed derivative coefficients.
Primality and distinct support are conditions used to construct the finite
certificates; they are not unstated assumptions of this conditional identity.

[PublicRefreshNativeLift.lean](../../../lean4/KElimination/KElimination/PublicRefreshNativeLift.lean)
proves the full 97-term centered phase norm `D=3,178,496`. Combining that norm
with the native producer relation `x=rho+65537*K` and `|rho|<=49` proves
`|K|<=48`. It also proves unique phase and quotient lifts, and the exact
36/37 query for authentic views of the same `Y=K+48` in `[0,96]`:

```text
((Y mod 36) - (Y mod 37)) mod 37 = floor(Y/36), in [0,2].
```

The target-residue formula is proved without requiring a persistent winding
ledger. This theorem does not produce independently encrypted remainder views.

## Conditional phase-clock prototype

| Module | Checked result |
| --- | --- |
| [PublicRefreshReturn.lean](../../../lean4/KElimination/KElimination/PublicRefreshReturn.lean) | General dense `c0+c1*s` class-zero return for `X=Y^D`, including every complementary secret block, its X shift and negacyclic sign |
| [PublicRefreshBounds.lean](../../../lean4/KElimination/KElimination/PublicRefreshBounds.lean) | Exact signed nearest rounding; odd-Q headroom; quadratic product envelope; complete coefficient assembly and all return-switch deposits; repeated-cycle budget closure |
| [PublicRefreshGeometry.lean](../../../lean4/KElimination/KElimination/PublicRefreshGeometry.lean) | Complete single-chart degree requirements and the feasible sparse fixture |

The ring-return proof covers arbitrary finite polynomial expansions and
ratios, rather than an enumeration of small ciphertext examples. It proves
an integer algebraic specification; it does not verify key-switch code or
prove the native backend's different return implementation.

The concrete degree-8/boot-degree-256 fixture has plaintext 65537, eta 3,
base 1024, 12 total gadget digits, and four-prime main product
`348959453350711275087786864768188417`. Its conservative checked bounds are:

| Quantity | Exact ideal-grid bound |
| --- | --- |
| Returned polynomial | `41914601470491648` |
| Next square plus largest canonical plaintext offset | `222503661906126014492421` |
| Reusable clock input allowance | `floor(Q/128)` |

`Fixture.arbitrary_cycles` proves admission for any iteration count under
explicit refresh-envelope and transition premises. It is an arithmetic model
theorem, not an end-to-end unlimited-depth FHE theorem. The existing Rust
roundtrip regression now checks each actual producer bound against these
proved caps and checks the independent plaintext oracle on every cycle.

The geometry lower bound applies only to this single complete-carry chart:
its two checked inequalities imply `N>(H+2)*(H+1)`. Dense support 8192
therefore needs `N>67,133,442`, above this prototype's degree cap. It does
not rule out the separate working G/H research backend. The support-96,
coordinate-99 fixture fits degree 16384 with uncertainty window 13699.

## Verification and limits

Run from the repository root, with the pinned Lean compiler available:

```sh
python3 scripts/check_public_refresh_proofs.py --output /tmp/public-refresh-proofs.json
python3 scripts/test_public_refresh_proofs.py
```

The checker builds fresh oleans, checks the compiler version, requires the
registered theorems, and audits every owned declaration, including unused
definitions and opaque declarations. Negative controls reject a missing
compiler/input/theorem, a wrong compiler version, a broken proof, a hidden
axiom, a theorem with `sorry`,
and an unused opaque proof with `sorry`. That last case was reproduced before
the audit was strengthened. CI runs this gate separately and retains the
existing full Mathlib build and library-wide axiom audit.

These proofs do not establish Rust refinement, finite-width overflow safety,
ciphertext-view coherence, slot-to-coefficient divisibility, producer history,
all native noise envelopes, or confidentiality of the correlated key graph.
Those remain separate implementation, regression and security obligations.
Production-security status and legacy support predicates are unchanged.

The local full Mathlib build is unverified: the pinned cache's Azure endpoint
returned 403, and the documented alternate lacked the requested cache objects.
The five new modules need no Mathlib cache and are checked independently.
Accepted commands, source hashes and executed runtime logs are recorded in
the adjacent `proof-evidence` directory; historical native logs are untouched.

Accepted local results at proof commit `5d52ca3`: all five proof modules,
nine proof-gate controls, 1,114 release library tests (zero failures, 139
previously ignored), and 16 focused debug tests pass. The full release
library run includes the 100-cycle bound-conformance regression; debug runs
two cycles. Workspace/all-targets Clippy, formatting, the 20-file architecture
scan, panic ratchet, and status/security claim checks pass. The full workspace
test suite was not rerun locally. The source commits and hashes in
[`validation.json`](proof-evidence/validation.json) distinguish these results
from the unchanged historical full native execution.

Hosted verification also completes the **full Mathlib-based package build**
and its existing library-wide axiom audit at `5d52ca3`
([job](https://github.com/Skyelabz210/NINE65_v7/actions/runs/41320132852/job/124888354361)).
The latter retains the separately documented AHOP hardness assumption; none
of the five new modules depends on it. This resolves the full-build check on
GitHub despite the local cache restriction described above.

The first hosted core-checker invocation exposed Elan's first-use installation
messages on stderr contaminating the version string. Commit `e44ba19` fixes
that parser and adds a tenth passing control. The pinned-version comparison,
all proof statements and both axiom audits remain enforced. The original
nine-control evidence is preserved; the additional accepted checks and hashes
are in [`ci-checker-followup.json`](proof-evidence/ci-checker-followup.json).
The corrected [hosted refresh proof job](https://github.com/Skyelabz210/NINE65_v7/actions/runs/41320375971/job/124889082370)
passes all five modules and all ten controls at that commit.
