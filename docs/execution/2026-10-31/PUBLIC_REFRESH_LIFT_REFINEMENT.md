# Derived native lift and conservative continuum refinement

The native refresh producer has the signed quotient bound **`|K| <= 48`**.
Consequently a 36/37 pair is sufficient for `Y=K+48` in `[0,96]`. This
corrects the earlier application of the standalone digit primitive's entire
65,537-element output domain to this particular producer. The derivation
uses the existing source norm and public digit weights; it does not identify
the radius-49 residual with the quotient.

The starting attachment is `Pasted text.txt`, SHA-256
`d0fbbf30bc2dcfdf1a6b3dbf71456282a267adaa8f3466b95f3eb7f0a93c44af`.
Its numbered citations have no accompanying bibliography and are not used
as verification evidence. Its equations are treated as proposed mathematics.

## 1. Source-bound proof and implementation

Let `p=65537`. In `DirectSlotPhaseKey::evaluate_with_progress`, each public
weight is explicitly centered modulo p, hence `|d_i[j]| <= (p-1)/2 = 32768`.
The source secret has exactly H=96 nonzero ternary coefficients. The phase
bank implements the full negacyclic convolution, including its sign changes,
so each integer phase coefficient satisfies

```text
x = d0 + d1*s,
|x| <= D = (H+1)*floor(p/2) = 97*32768 = 3178496.
```

The source error certificate independently gives `x = rho + p*K` with
`|rho| <= 49`. Therefore

```text
p*|K| = |x-rho| <= D+49,
|K| <= floor((3178496+49)/65537) = 48.
```

Both `2D < p²` and `2*48 < p` hold. Thus the centered p² phase represents
the integer x uniquely, and the extracted `K mod p` represents signed K
uniquely in this interval. The bound is sharp for the stated norm/support
class: 96 terms of 32768 and `d0=48` sum to `48*p`, with `rho=0`.

The source certificate now exposes the integer phase bound and quotient
radius. The phase-key setup verifies the actual source norm against its plan;
the private phase producer propagates both bounds with its source lineage.
The refresh plan checks the unique signed lift and checks these producer
bounds before extracting the digit. `carry_radius` remains the residual
polynomial support; `signed_carry_radius` is the separate quotient bound.
No secret-dependent bound is measured or reset at runtime.

## 2. On-demand K-elimination, with no winding ledger

Keep K as a semantic quantity rather than a persistent field in the proposed
state tuple. For authentic same-source views of `Y=K+48`, define

```text
g = Y mod 36,       a = Y mod 37,
kappa = (g-a) mod 37 = floor(Y/36),       0 <= kappa <= 2.
```

The equality follows from `Y=g+36*kappa` and `36=-1 (mod 37)`; the interval
excludes every alias. A target residue is obtained without assembling Y:

```text
K mod b = (g mod b + (36 mod b)*(kappa mod b) - 48 mod b) mod b.
```

The query uses no carried epoch or saved quotient. It still needs independently
produced views of the same shifted K. Using views of `rho+49` would answer a
different question. Source lineage is also different from an arithmetic
epoch: removing an arithmetic counter does not remove input/output binding.

## 3. Refinements to the supplied state equations

The materialization identity `X=gamma_B(r)+M_B*K` is a semantic identity,
not an instruction to materialize `gamma_B(r)` on the runtime path. In the
multiplication rule, the symbols multiplying K must mean the scalar canonical
representatives `g_A=gamma_B(r^A)` and `g_B=gamma_B(r^B)`, not residue vectors:

```text
K_product = M_B*K_A*K_B + g_A*K_B + g_B*K_A + floor(g_A*g_B/M_B).
```

This follows by expanding the integer product. An implementation can instead
update bound same-source residue views and query its quotient when needed.
Likewise the translation rule is consistent, but the new kappa can be derived
from the updated views instead of retaining the old kappa.

The displayed WASSAN formula with `v_Pj=X mod Pj` at every level describes
independent quotients `floor(X/Pj) mod Qj`. A recursive quotient tower would
instead need views of the preceding quotient at each level, with new interval
proofs. Naming the levels does not provide those views or increase capacity.

The shared-factor lift is directly relevant to the existing encrypted digit:

```text
K mod p = (((x mod p²)-rho) mod p²) / p.
```

The numerator is a multiple of p; no inverse of p modulo p is used.
The existing G/H circuit computes this quotient without a clear rho witness:
`G(rho+pK)/p = K*G'(rho) mod p` and `H(rho)=1/G'(rho) mod p`.
All 97 signed K values and all 99 residual values satisfy both expressions
in the independent oracle (9,603 combinations).

Finally, a phase defect calculated from a kappa just derived from the same
two residues is identically zero. It checks congruence, not provenance or
cryptographic authenticity. Those require the actual producer relation.

## 4. A continuum lift that does not choose the soliton update rule

The attachment does not specify a box-ball evolution equation. A useful
refinement can nevertheless be proved for any supplied finite transition
`b -> b'` of binary occupancies that conserves total mass B. Retain both
snapshots and their absolute cell positions in finite-support state F. Fix
the left-boundary flux to zero and define prefix potentials

```text
U_i = sum_{j<i} b_j,       V_i = sum_{j<i} b'_j,
C_i = U_i - V_i,          -B <= C_i <= B,
H_i = i - 2*U_i,          H'_i = i - 2*V_i.
```

Then **`H'_i = H_i + 2*C_i`** exactly. The flux C is derived from the two
snapshots; it is not a stored carrier. For rightward box-ball flows C is
nonnegative, but that restriction is unnecessary for this signed theorem.
For any rational `theta` in `[0,1]`, linearly interpolate all three quantities
between adjacent grid vertices. Linearity proves
`H'(i+theta)=H(i+theta)+2*C(i+theta)` and preserves `|C|<=B`. This is an exact
continuum embedding, not a claim about a KdV limit or soliton integrability.

K-elimination consumes the prefix views of `Y_i=C_i+B`: subtract the U/V
views lane-wise and add B. If `2B < M*A`, the paired query derives the unique
sheet and projects C to any target. The research oracle verifies this for all
924 mass-conserving pairs of six-cell binary snapshots, both transport
directions, and exact rational points. It does not invent the successor or
claim these 924 transitions all satisfy the user's soliton dynamics; that is
the separate topology/operator relation T must establish.

This gives a general interface for the requested hybrid lift without assuming
the standard running-maximum/Pitman evolution previously declined. A periodic
or nonzero-flux boundary needs its own reference: conservation alone determines
C only up to an additive constant. Also, identifying C with the refresh K
requires a proved source map; a conserved box-ball mass is not automatically
the native residual radius.

## 5. Protected-view cost and next implementation boundary

The native circuit already obtains a temporary encrypted K. Adding the public
constant 48 gives encrypted Y in `[0,96]` without a stored frame. However,
producing the *canonical integer remainders* `Y mod 11`, `Y mod 36`, and
`Y mod 37` as encrypted F_p values is nonlinear. Exact interpolation on all
97 inputs gives degree 96 for each map, so a direct field-polynomial circuit
needs at least seven ciphertext-product levels after Y is available.

Under the current `Noise::multiply` certificate, each such level contributes
at least a factor
`F=N*(p-1)/2 + N*p*(N/2+1)` to any error-bearing input path. With the native
carry error E, even `E*F^7` has **832 bits**, exceeding the native half-Delta
budget of **633 bits**. This rejects appending those lookup polynomials under
the current ledger; it does not prove every alternate protected-view
construction impossible. The field interpolation and this native preflight
are executable regression checks.

The [review of the linear, factorized, and defect paths](PROTECTED_VIEW_ADJACENCY_REVIEW.md)
separates view production from consumption. With authentic views already
available, it supplies a degree-4 native-field adjacency consumer using
three products over two levels: its conditional bound is 622 bits. The
existing slot return would raise that to 667 bits. Neither the conditional
consumer nor a zero phase defect produces the missing protected views.

The useful direction is therefore to retain the already-derived encrypted
bounded lift and design a source-bound view producer/consumer with its own
noise budget, or a jointly evaluated alternative. A clear box-ball oracle
cannot fill that role. The CRAM root's full state is also distinct from K;
its approved source relation must be proved before attaching root authority.
The sparse/joint-key security admission remains a separate obligation.

## Verification

Run `python3 -m unittest discover -s scripts -p test_public_refresh_lift_refinement.py -v`.
Rust coverage includes `direct_phase_quotient_bound_covers_signed_lifts_and_native_endpoints`,
`native_plan_certifies_signed_carry_separately_from_residual_support`, the
encrypted `coherent_source_phases_extract_all_carries_and_restore_affine_message`
oracle, and the public refresh API conformance/refusal tests. The earlier
five-cycle native execution is unchanged arithmetic evidence; this refinement
does not claim a new full native run or a formal Lean verification.
