# S00 draft: intact priming root and bounded phase coordinates

Status: **reference-contract draft; S00 is not accepted**. The owner's live
2/11 phase construction remains unresolved. The reference profiles below do
not substitute for it and do not authorize dependent production integration.
S02-A's independently reproduced composite-inverse correction does not depend
on choosing that live phase construction.

Owner clarification incorporated: modular inverse is assigned as an instruction
to lanes of a phase-locked sister CRT operator tray. Garner and sequential
mixed-radix synthetic emission, including the retired R9 path, are not part of
the requested runtime. The replacement is the owner's heterogeneous polyunitary
operation; its live phase/transition equations still require the bindings below.

This draft specifies equations and transition obligations. It does not claim
that the proposed bindings, signed adapter, or sister-frame transitions are
implemented. Machine-readable profiles and oracle fixtures are in
[priming_root_profiles.json](../../../artifacts/execution/priming_root_profiles.json).

## 1. Root roles, payload factors, and semantic state

Retain all eight logical root lanes, in canonical order:

| Modulus | Logical role |
|---:|---|
| 2 | Parity / binary boundary |
| 3 | Triadic witness |
| 5 | Surface / Ramanujan-family witness |
| 7 | Bridge / Ramanujan-family witness |
| 11 | Shadow / disambiguation witness |
| 13 | Boundary witness |
| 17 | Structural-lift / saturation witness |
| 19 | Spectral / saturation witness |

Their topology product is `P_S = 9699690`. This is not automatically an
operation's payload modulus, its full represented range, or a BFV security
parameter. A selected payload factor set has its own product `M`; its selected
phase coordinates have anchor modulus `A`. A root lane may be outside the
payload while retaining its root role. Physical composite packing must retain
each logical role and its exact reduction; overlapping views are not counted
as independent factors.

An `IntegerNamed` root describes one quantity `X`: each root lane is `X mod p`.
A `TopologyProduct` frame describes explicitly typed coordinate values and
operators. A heterogeneous output may retain its parent root as a source
reference without claiming that the parent root describes the output. Moving
back to `IntegerNamed` semantics requires a specified compatibility and lift
rule; a name such as `shadow` or `prime` supplies no such rule.

### Inverse as a sister-tray lane instruction

An operator assignment such as `Inv` belongs to a dependent sister tray that
names its authoritative S8 root, source epoch, phase relation, input view,
lane modulus and instruction identity. The instruction operates on that lane;
it does not replace a root role or independently change the root's value.
Its output is typed as an operator/topology frame unless an admitted shared-
integer operation relation and lift rule justify committing an integer result.

For the nondegenerate unit-domain reference contract:

```text
Inv lane input: (source, epoch, frame, lane, a mod m), m > 1
admission: gcd(a,m) = 1 and valid source/phase/instruction binding
output: z in [0,m), (a*z) mod m = 1
failure: explicit refusal for zero/nonunits or absent binding
```

Sister placement does not create inverses for nonunits. A separately specified
shared-factor division route is not implicitly an implementation of `Inv`.
Modulus1 remains a valid constant projection view; the inverse instruction above
does not admit it. Composite lane support requires correct unit inversion,
not a blanket prime-field exponent rule.

The EEA/unit-inverse reference and schema regressions establish local arithmetic
correctness. They do not prove the complete phase-locked sister realization,
operator routing, concurrency, or encrypted realization is wired. The `inv(...)`
terms in this document specify mathematical values and equations; they do not
silently choose a new runtime inverse algorithm or replace the owner's required
sister-tray placement. Live placement and phase validity must be traced through
the admitted operator fabric. Any separately precomputed public profile constant
must retain its own role and verified inverse equation.

Each source capability must bind these proposed contract fields:

* context/profile identifier and version, ordered role/factor definitions;
* source identity, immutable value epoch, and source-operation lineage;
* semantic domain and observer classification;
* public admitted interval and checked implementation-width certificate;
* authoritative coordinate identities, moduli and same-quantity relation.

A layout version is separate from the value epoch. Attaching a read-only view
changes the layout, not `X`. Committing an arithmetic result creates a new
value epoch. Bindings must be established by validated producers, not accepted
because caller-supplied tags agree. They are not cryptographic authentication
unless a separate authenticated transport/provenance mechanism provides that.

## 2. Shared bounded lift and projection contract

For a nonnegative profile, require

```text
M > 1, A > 1, gcd(M,A) = 1
0 <= X <= U < M*A
g = X mod M, a = X mod A
k_A = ((a - (g mod A)) * inv(M,A)) mod A
```

The interval implies `floor(U/M) < A`, so the canonical `k_A` is exactly
`K = floor(X/M)`. With inclusive maximum `U`, the capacity condition is
`A > floor(U/M)`, not an inequality that admits the alias boundary `X=M*A`.
For every target `b > 0`, including noncoprime, composite and repeated targets,

```text
X mod b = ((g mod b) + (K mod b)*(M mod b)) mod b.
```

The canonical payload transduction can supply `g mod A` and `g mod b` directly
from payload residues. No stored aggregate `g`, full `X`, or scalar `K` is
required. A bounded transient quotient may be derived inside a query, reduced
into the requested target, then discarded. Neither it nor a running winding
tower may be retained in live state, serialized, or used as an undeclared cache.
No hot-path full-integer materialization is permitted. Garner and sequential
mixed-radix conversion/emission are prohibited throughout the requested runtime,
including R9 and helpers labeled observation or emission. Fixed-width/rank
arithmetic must have its own capacity and work
certificate; calling a large integer a residue does not exempt reconstruction.

The provider must prove its phase belongs to the same source, epoch, quantity
and interval as the payload residues. Range checks on two unrelated residues
do not prove that relation. `X` and `X+M*A` have identical coordinates: residue
inspection cannot detect an already lost sheet. Admission occurs before growth.

## 3. Bounded reference profiles

None of these profiles is identified as the owner's unresolved live profile.
Their status is `specified_reference` or `specified_reference_family`, not
production-admitted. Existing code coverage is recorded separately in JSON.

### R-S8-ADJACENT-1

```text
M = P_S = 9699690
A = M+1 = 9699691 = 347*27953
capacity = M*A = 94083995795790
0 <= X < capacity
K = ((g mod A) - a) mod A
```

This preserves the full S8 payload and adds an independent adjacent coordinate.
Its inverse is `M^-1 mod A = -1 mod A`. The subtraction returns `K`, not
generally `X`. `cram_anchor::Anchor::winding` implements that equation;
`AdjacentWindingEvidence` derives a per-query winding without caching it.
Current construction does not establish the full source/epoch binding above.

### R-S8-SHADOW11-SPLIT-1

```text
payload factors = [2,3,5,7,13,17,19]
M = P_S/11 = 881790
A = 11; a = root residue at 11
M mod 11 = 8; inv(M,11) = 7
K = ((a - (g mod 11))*7) mod 11
0 <= X < 9699690
```

Root2 remains a payload/parity coordinate; root11 is outside this payload and
serves as its anchor. This reorganizes the existing root information and does
not enlarge its range. It requires a new bound provider; it is not what the
current snapshot-only `Shadow` evidence implements.

### R-S8-JOINT2-11-SPLIT-1

```text
payload factors = [3,5,7,13,17,19]
M = P_S/22 = 440895
A = 22
a = r11 + 11*((r2-r11) mod 2)        # canonical residue X mod 22
M mod 22 = 15; inv(M,22) = 3
K = ((a - (g mod 22))*3) mod 22
0 <= X < 9699690
```

Here2 and11 jointly supply a small anchor coordinate while both logical roles
remain present. Computing this declared mod22 coordinate is not emitting the
whole integer. This is a reference split, not an inferred description of the
owner's live 2/11 lock.

### R-S8-POWERS2-11-1 family

For public positive integers `alpha,beta`, retain the same six payload factors
as the joint split and maintain actual phase coordinates

```text
u = 2^alpha, v = 11^beta, A = u*v, M = 440895
r_u = X mod u, r_v = X mod v
r_u mod 2 = root2; r_v mod 11 = root11
a = r_v + v*(((r_u-r_v)*inv(v,u)) mod u)
K = ((a - (g mod A))*inv(M,A)) mod A
0 <= X < M*A
```

`gcd(u,v)=gcd(M,A)=1`; both inverses exist and may be precomputed from public
parameters. Actual power coordinates supply the extra information. Repeating
mod2/mod11 views under new labels does not. Every selected instance needs
bounded exponent, product and intermediate-width certificates. The JSON
example uses `alpha=2,beta=2`, `A=484`, `inv(M,A)=267` and capacity `213393180`.
No general higher-power runtime provider is claimed here.

## 4. Signed interval adapter

An optional mathematical adapter binds a public interval `[L,U]`, with
`L <= U` and `U-L < M*A`, and uses `Y = X-L`. For each authoritative modulus
`q`, obtain `Y mod q = (X mod q - L mod q) mod q`; apply the nonnegative
profile to `Y`, and answer

```text
X mod b = (L mod b + g_Y mod b + (K_Y mod b)*(M mod b)) mod b.
```

The root still names `X`; the shifted provider explicitly names `Y`. Bind that
transform and offset to its capability. This is proposed mathematics, not an
existing signed-provider implementation. Public bounds may not be replaced by
measured secret-dependent values. Sign/order queries compare against the
declared threshold using the corresponding bounded coordinates; they may not
emit a protected sign or phase merely because its arithmetic is exact. Round I
T4/T13 supply an ordering relation, not a free implementation of coordinate
acquisition or an unbounded fixed-memory representation.

## 5. Allowed transitions and refusal points

| Transition | Required behavior |
|---|---|
| Initialize | Trusted input encoding or admitted conversion establishes the same-quantity relation and interval; preserve all eight root roles. |
| Attach view b | Require b>0 and a provider bound to current source/epoch; derive its residue. Modulus1 is constant0. |
| Drop/replace dependent view | Preserve root and all authoritative phase information required by later operations. Invalidate references to the removed view. |
| Remove authoritative coordinate | Refuse unless a reviewed new profile and independently established narrower bound retain uniqueness. |
| Extend capacity | Derive and admit added coordinates while the old state still uniquely identifies X, before an operation crosses old capacity. |
| Change payload/anchor split | Derive new coordinates from the current admitted state; establish new inverse/range/width conditions; invalidate old provider capabilities. |
| Homogeneous add/multiply | Preflight output bounds; update every authoritative modulus from a consistent input snapshot; publish one new epoch atomically. |
| Signed operation | Update public interval using sound integer interval algebra, including all multiplication endpoint extrema, and bind the new offset adapter. |
| Exact division | Name output semantics; require divisibility and unit conditions for the selected lane algorithm; shared-factor lanes need an independently admitted route. |
| Sister-lane Inv | Preserve authoritative root; check the lane's unit domain and phase/source binding; emit a typed operator-frame result; refuse nonunits or missing evidence. |
| Heterogeneous frame update | Produce explicitly declared topology semantics; retain parent source lineage; do not claim unmodified root coordinates describe the output. |
| Commit shared integer output | Establish compatible congruences, the intended operation relation and a unique selected lift before publishing new authoritative coordinates. |
| Change BFV Q, t or key domain | Use the separate admitted encoding/noise/key transition; changing a sister view alone is insufficient. |

For a proposed common integer, target residues must satisfy
`u_i == u_j mod gcd(b_i,b_j)`. Their joint period is the LCM of their moduli,
not generally their product. Compatibility establishes a congruence class;
the bound and operation relation establish the intended integer. A heterogeneous
frame can remain valid as a product of coordinate states even when that common
integer assertion is absent. Reversibility is claimed only with an inverse or
explicit retained-information rule for the selected operator domain.

The independent coordinate work of Round I T7 may run concurrently, but source
snapshots, operation dependencies and commit barriers remain. No latency or
single-cycle claim follows from the equations.

## 6. Observers and protected quantities

Classify each provider as `public_component`, `protected_plaintext_phase`, or
`clear_authorized_value` (or a separately specified semantic domain).

* Public-component coordinates describe the selected public ciphertext
  polynomial component. They do not establish a secret decryption phase.
* A protected-phase provider requires an admitted encrypted/protected realization
  of the needed operations. These clear-coordinate reference equations do not
  authorize publishing its phase, sign, quotient, mask or key-dependent residue.
* Explicit authorized observation is distinct from live arithmetic and from
  oracle-only reconstruction. It may not invoke the retired R9 Garner/MRS
  emission path or hide it behind an observation helper. The owner's withdrawn
  MRS-emission paragraph is not an instruction to add that pipeline. Any required
  observation must use an admitted operation from the intended heterogeneous
  polyunitary design with its own exact output contract.

Independent test/diagnostic oracles may reconstruct only outside the production
runtime graph, with an explicit boundary and separate instrumentation. That
allowance is not a fallback reachable from live arithmetic or observation.

The existing main-Q wire rule remains applicable to emitted ciphertexts.
Internal root preservation does not require publishing additional coordinates.
Conversely, omitting coordinates from wire is not authorization to delete
necessary internal phase state. Entropy and physical-protection claims retain
their separate observer/source contracts.

## 7. Unresolved live 2/11 contract

Profile `OWNER-LIVE2-11` is `unresolved`. Dependent integration must not silently
select a reference profile as its replacement. The remaining equations are:

1. Exact payload factors/powers M and whether2 is payload, anchor or both by
   separate roles; the monograph already places11 outside its anchor's payload.
2. `coordinate2 = f2(quantity, state)` and `coordinate11 = f11(quantity, state)`:
   which quantity, quotient, phase or higher-power value does each encode?
3. The actual cross-tray phase relation and provider equation deriving the
   requested lift from those coordinates, including auxiliary inputs.
4. Its uniqueness interval and the information distinguishing identical partial
   2/11 observations; its extension and alias-refusal conditions.
5. Coordinate update equations for each permitted homogeneous/heterogeneous
   instruction, and exact add/drop/rebind rules for higher-power coordinates.
6. The signed/order/division convention and any encoding for which subtraction
   directly returns the requested value rather than a quotient.
7. Public/protected quantity classification and same-source/epoch binding.

The current `cram_ct` graph names a 2-to-11 Shadow edge, but its verifier checks
only the target11 snapshot; it does not evaluate a relation involving source2.
That evidence does not resolve these equations. S00 remains unaccepted even if
all reference fixtures below pass.

## 8. Sources and reproducible oracle fixtures

Source basis: [integration contract](../../CRAM_INTEGRATION_CONTRACT.md),
[owner reconciliation](OWNER_MODEL_RECONCILIATION.md),
[Round I traceability](ROUND_I_TRACEABILITY.md), and
[lifted-transduction packet](../../CRAM_SAFE_BASIS_LIFTED_TRANSDUCTION_EXECUTION.md).
Concrete implementations are `cram_anchor.rs:154,177`,
`lifted_transduction.rs:339`, and `cram_ct.rs:342,650` under
`crates/exact_transcendentals/src/`. The historical proof correspondence is
[K_ELIMINATION_PROOF_BRIDGE.md](K_ELIMINATION_PROOF_BRIDGE.md).

The following command checks the JSON's finite reference equations using only
Python integers. Full values appear here only as an independent oracle. This
command does not test a production provider, protected-phase implementation,
theorem build, or owner-live profile. No test count is claimed by this draft.

```sh
python3 - <<'PY'
import json, math
from pathlib import Path
p = Path('artifacts/execution/priming_root_profiles.json')
data = json.loads(p.read_text())
assert data['s00_accepted'] is False
root = data['root']['logical_moduli']
assert root == [2, 3, 5, 7, 11, 13, 17, 19]
assert math.prod(root) == data['root']['topology_product']
for f in data['finite_reference_fixtures']:
    M, A = f['M'], f['A']
    C = M*A
    assert math.gcd(M, A) == 1
    assert C == f['capacity_exclusive']
    assert pow(M, -1, A) == f['inverse_M_mod_A']
    assert math.prod(f['payload_moduli']) == M
    for X in f['oracle_values']:
        assert 0 <= X < C
        g, a = X % M, X % A
        k = ((a-g)*f['inverse_M_mod_A']) % A
        assert k == X // M
        if f['anchor_kind'] == 'adjacent':
            assert k == (g-a) % A
        if f['anchor_kind'] == 'joint_2_11':
            assert a == X % 11 + 11*((X % 2-X % 11) % 2)
        if f['anchor_kind'] == 'powers_2_11':
            u, v = 2**f['alpha'], 11**f['beta']
            assert a == X % v + v*(((X % u-X % v)*pow(v, -1, u)) % u)
        for b in data['target_moduli']:
            assert (g % b+(k % b)*(M % b)) % b == X % b
    assert (C % M, C % A) == (0, 0)  # rejection requires provenance/range
    for s in f['signed_oracle_intervals']:
        L, U = s['lower'], s['upper']
        assert L <= U and U-L < C
        for X in s['values']:
            assert L <= X <= U
            Y = X-L
            g, a = Y % M, Y % A
            k = ((a-g)*f['inverse_M_mod_A']) % A
            for b in data['target_moduli']:
                assert (L % b+g % b+(k % b)*(M % b)) % b == X % b
print('Reference equations match the declared oracle fixtures; S00 remains unaccepted.')
PY
```
