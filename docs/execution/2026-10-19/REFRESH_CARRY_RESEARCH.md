# Refresh carry: collected equations, evidence, and next construction

Date: 2026-10-19. Source baseline: `4f835d35623f1392b782bb6650a6d2466fe977f9`.
Scope: research preparation and exact clear-oracle checks. Public refresh is
still unadmitted. No production evaluator, ciphertext format, or gate changes.

## The concrete connection

For odd Q define nearest rounding `n_Q(z)=floor((z+floor(Q/2))/Q)` and the
centered representative `sigma_Q(z)=z-Q*n_Q(z)`. There are no half-integer
ties for integer z. Its addition defect is

```text
kappa(a,b) = (sigma_Q(a)+sigma_Q(b)-sigma_Q(a+b))/Q.
kappa(a,b)+kappa(a+b,c) = kappa(b,c)+kappa(a,b+c).
```

This is an exact identity: both sides telescope to the same sum of three
representatives minus the representative of their sum, divided by Q. It
describes the lattice correction introduced when choosing representatives
in a quotient. For ternary secrets, accumulating this defect across signed
negacyclic terms gives precisely the original BFV component-rounding carry:

```text
A_i = n_Q(t*c_i),  R_i = t*c_i-Q*A_i
K_j = n_Q(R0_j+(R1*s)_j)
n_Q(t*(c0+c1*s)) = A0+A1*s+K.
```

This correspondence is a derivation here, not a theorem claimed from a
tropical paper. In particular, it supplies an identity for K, not a public
procedure to compute secret-dependent K cheaply under encryption.

[Mikhalkin–Zharkov](https://arxiv.org/abs/math/0612267), sections 5–6,
describe tropical Jacobians as real vector spaces modulo period lattices;
the Abel–Jacobi construction is independent of path modulo that lattice.
[Inoue–Takenawa](https://arxiv.org/abs/0902.0448) identify a generic
ultradiscrete periodic Toda isolevel set with its tropical Jacobian.
These support the quotient/lattice connection. Neither supplies a BFV
refresh circuit or a bound on its encryption noise. No spectral curve or
Toda dynamics corresponding to this BFV implementation has been constructed.

The scalar derivative used below is a separate connection: a one-variable
Jacobian condition can cancel a p-adic displacement. It should not be
conflated with the tropical Jacobian variety. Replacing addition by max, or
using a log-sum-exp correction, has no established exact BFV realization here.

## Three quantities that must stay distinct

| Quantity | Role | Required treatment |
| --- | --- | --- |
| Original K above | Missing correction in the old public Phase 1 | Cannot discard it before encrypted digit removal |
| Expanded winding in Z=w+k* p² | Choice of representative modulo p² | Its contribution k*p vanishes modulo p after contraction |
| Low digit or signed residual of w | Distinguishes neighboring message intervals | Must be removed under encryption with the correct encoding and bound |

For the current canonical route, `h=(p-1)/2`, `x=(w+h) mod p²`,
`r=x mod p`, and `d=(x-r)/p mod p`. This is integer division of an exactly
divisible plaintext, not multiplication by a modular inverse of p.
An `Enc_p(r)` cannot be substituted for `Enc_{p²}(r)`.

The relevant implementation is in
[prime_power_phase.rs](../../../crates/nine65/src/ops/prime_power_phase.rs),
[prime_power_digit_lift.rs](../../../crates/nine65/src/ops/prime_power_digit_lift.rs),
and the [contraction contract](../../PRIME_POWER_BOOTSTRAP_CONTRACTION.md).
The [BFV bootstrap paper](https://eprint.iacr.org/2022/1363) by
Geelen–Vercauteren is the existing scheme reference; its abstract confirms
a unified BGV/BFV treatment and an implementation. The repository's equation-9
mapping is recorded in [the Phase-1 derivation](../../PUBLIC_BFV_PHASE1_SOLUTION.md).
The paper's full PDF could not be retrieved in this session, so that mapping
has not received a new paper-to-code audit here.

## The smaller candidate already available

The existing [bounded polynomial builder](../../../scripts/bounded_digit_polynomial.py)
constructs F with `F(r)=r mod p²` and `F'(r)=0 mod p` for `-B<=r<=B`.
Taylor expansion then proves

```text
F(r+p*m) = F(r)+p*m*F'(r) = r mod p².
```

Consequently `(w-F(w))/p mod p` recovers m when `w=r+p*m mod p²` and the
support condition holds. The script constructs public polynomial constants;
it does not compute a hidden digit for an evaluator.

| p | Assumed B | Existing polynomial degree | Degree-based multiplication-depth lower bound |
| --- | --- | --- | --- |
| 65537 | 17 | 69 | 7 |
| 65537 | 32 | 129 | 8 |

These depth numbers are lower bounds for these polynomials in an ordinary
arithmetic circuit, not an implemented schedule or noise admission. The
full-domain baseline has degree 65537 and a corresponding lower bound of 17.

There are two immediate integration requirements:

1. **Prove the support from live ciphertext history.** The current uniform
   ternary bound already includes `(N+1)/2` from component rounding, which
   is `8193/2` at N=8192 before input-noise terms. That certificate cannot
   justify B=17 or 32. This is a limitation of the current bound, not proof
   that each actual residual is that large. A sharper supported invariant
   or a separately assessed temporary-key construction is needed.
2. **Preserve the signed section.** For residual -1 the bounded polynomial
   returns `p²-1`, whereas the canonical low digit is `p-1`. Substituting
   one for the other changes the contracted answer by one modulo p.
   The bounded route needs a separately specified producer/contraction
   contract on its unshifted phase; it cannot claim the existing
   `CanonicalLowDigitLift` contract merely because it has the same residue
   modulo p. The algebra and encrypted output-error certificate both matter.

The existing task order remains appropriate: [R01](../2026-10-03/tasks/R01.md)
input radius, [R02](../2026-10-03/tasks/R02.md) explicit bounded circuit,
[R03](../2026-10-03/tasks/R03.md) complete tuple admission, then B04–B09
integration. The promised `DIGIT_RADIUS_CONTRACT.md` is absent. Do not
invent its acceptance or select B from a successful sample.

## Reproducible collection

Run `python3 scripts/refresh_carry_bridge.py`. The
[recorded output](../../../artifacts/execution/2026-10-19-carry/clear-oracle.json)
binds both Python sources by SHA-256. It checks:

- 34,856 centered-section cocycle triples;
- 3,825 scalar and 5,625 exhaustive N=2 negacyclic cases; 3,116 cases expose
  a wrong uncorrected affine answer, while the corrected identity holds;
- 1,284 contractions and 8,988 expanded-winding invariance cases;
- the existing 9,482 exhaustive bounded-polynomial cases;
- value/derivative certificates at native p for B=17 and32, sampled signed
  contractions, and explicit outside-support failures at residual18 and33.

The certificates imply the polynomial identity for every message m on the
declared support; the sampled contractions alone do not claim exhaustive
native testing. All of this is clear integer arithmetic, not encrypted
execution or security evidence.

The archived candidate search currently refuses with
`canonical probe source changed: Cargo.lock`. Preserve that historical
evidence and record fresh source-bound probes; do not rewrite old hashes to
make the search pass. The old report cannot certify this source revision.

A [fresh production probe](../../../artifacts/execution/2026-10-19-carry/canonical-probe.json)
and [independent feasibility calculation](../../../artifacts/execution/2026-10-19-carry/canonical-feasibility.json)
reproduce the 14-candidate refusal. Eight constructor noise results and 23
quadratic bounds cross-check; the secure_128 first multiply still needs
131 error bits against 86 half-scale bits. This is a failed admission, not
a failed oracle. Six candidates stop at other constructor gates.

Provenance caveat: the freshly run executable embeds the old build SHA
`0ec19eb2e142f8ae86d86c747c267e65fb5f1f8e` from Cargo's cached build script.
Its emitted source-file hashes were checked against the working tree; the
actual checkout is the baseline at the top of this note. Preserve both
values rather than silently relabeling the emitted artifact. This package
does not accept a release fingerprint or repair build metadata.

The next useful construction is a certified bounded residual producer and
its signed subtraction contract. The lattice identity gives us an exact
test oracle; its value will depend on whether a public encrypted realization
can beat the current noise and resource costs. The required acceptance run
is still all-coefficient refresh, subsequent multiplication, and another
refresh under one admitted key/parameter family.
