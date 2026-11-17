# Tropical and continuum bridge audit

Date: 2026-11-12. SOURCE OBSERVED: NINE65_v7 commit `88a7bdadbf0e1f8fbfdb2b37e9843101b8db3484`, clean before and after the checks below. This is a bounded specialist audit, not a whole-system FHE/security assessment.

**Follow-up source update:** the user has now supplied *CRAM, NINE65 and Tropical FHE*, dated October25, as `Untitled.docx`. It has been read in full and explicitly identifies this rank-one construction. The [follow-up addendum](../TROPICAL_FHE_ADDENDUM.md) also adds the later conservative continuum embedding and reconciles historical FHE claims. This original specialist report retains its rank-one/lattice scope; the earlier unidentified-source limitation is superseded.

## Result

There is a precise, valid connection: K-Elimination recovers the lattice-sheet coordinate of a rank-one tropical theta function from authentic paired coordinates and a uniqueness corridor. The construction extends mathematically to higher-dimensional lattices. This supports a broad **observable-assisted lifting principle**, with injectivity as its necessary and sufficient condition. It does not establish that arbitrary information-losing maps can be inverted, that finite residue data determine arbitrary real numbers, or that a tropical/BBS state uniquely determines its pre-ultradiscrete continuous model.

The current evidence is stronger than a loose analogy: the repository contains the rank-one derivation, independent theta minimization, negative aliases, and working clear arithmetic tests. It is narrower than a proof of universal continuum reconstruction. Distinguish covering-space lifting, real-valued tropical dynamics, inverse ultradiscretization, a continuum/PDE scaling limit, and profinite completion.

## Sources inspected and executed

Read: `AGENTS.md`, `CLAUDE.md`, `docs/PUBLIC_REFRESH_STATUS.md`, all of `docs/execution/2026-10-22/TROPICAL_LIFT_K_ELIMINATION.md`, all of `crates/exact_transcendentals/tests/tropical_theta_k_lift.rs`; relevant mathematical and limitation sections of `docs/execution/2026-10-19/REFRESH_CARRY_RESEARCH.md`; paired-coordinate encrypted consumer at `crates/nine65/tests/coefficient_slot_gate.rs:377`; lifted-state structure/composition and native-alias check in `tests/research/tropical_cocycle_state.rs:26`, `:87`, `:605`; local polynomial/domain evidence summarized in the October 22 document and searched against test symbols in `tropical_chart_transition.rs`. The full encrypted research test bodies and current native refresh implementation were not audited end to end here.

Primary literature read through fetched extracts:

* Rei Inoue and Tomoyuki Takenawa, *Tropical Jacobian and the generic fiber of the ultra-discrete periodic Toda lattice are isomorphic*, [arXiv:0902.0448](https://arxiv.org/abs/0902.0448), §1.2, §1.4, Remark 1.5, and opening of §2. Its genericity conditions and specific period matrix are part of Theorem 1.3; this is not a theorem about arbitrary dynamical systems.
* Rei Inoue, Atsuo Kuniba and Taichiro Takagi, *Integrable structure of box-ball systems: crystal, Bethe ansatz, ultradiscretization and tropical geometry*, [arXiv:1109.5349](https://arxiv.org/abs/1109.5349), introduction and its distinction between continuous dependent variables, tropicalization and integer restrictions. Parent research has the §4.1 formulas. Full PDFs were not exhaustively read in this specialist pass.

Preserved extraction: `evidence/tropical-primary-extract.json`. Primary-paper text is evidence, not permission to import its conclusions beyond its hypotheses.

EXECUTED:

```sh
PATH=/workspace/.tooling/cargo/bin:$PATH \
CARGO_HOME=/workspace/.tooling/cargo \
RUSTUP_HOME=/workspace/.tooling/rustup \
CARGO_TARGET_DIR=/workspace/k-elimination-audit/experiments/tropical/target \
cargo test --locked --offline -j1 -p exact_transcendentals \
  --test tropical_theta_k_lift --no-fail-fast
```

Rust `1.89.0 (29483883e 2025-08-04)`. **7 passed, 0 failed, 0 ignored, 0 filtered out**. Raw output: `evidence/tropical-rust-test.log`. The October 22 document says six tests at line 388; the current source and fresh run have seven. The test file SHA-256 is `2e7c7ff7ce8a1d26d18700323de4e726a0602577425024d96da0e1867e63f75b`; document SHA-256 is `9ee2a02a448948e340f0490934d064d8b2f328836cf37dad15c9a290f7eb805e`.

Also executed `python experiments/tropical/lattice_observer_checks.py`, an independent standard-library exact oracle created for this audit: 49 invertible-matrix residue states; 16 fused nonunit-observer states; 441 two-dimensional rational theta cases; explicit theta-wall tie; and the native small-chart alias. Output: `evidence/tropical-independent-checks.json`. Finite checks support the derivations; they are not machine-checked universal theorems or FHE tests.

## 1. The exact rank-one theorem

Let Q>0, z in R, and choose a centered chart g with z=g+QK, K in Z. Define

`T_Q(z) = min_{n in Z} (Q*n^2 + 2*n*z)`.

Substitute n=-K+d. Its value is

`-2*K*g - Q*K^2 + Q*d^2 + 2*d*g`.

If `|g|<Q/2`, every nonzero d has

`Q*d^2+2*d*g >= |d|*(Q*|d|-2*|g|) > 0`.

Therefore the unique minimizer is n=-K and `T_Q(z)=-2Kg-QK²`. This argument works for real chart coordinates; Q need not be odd for this analytic theorem. Odd integral Q and integral z are the repository's useful specialization: the chart `-(Q-1)/2 <= g <= (Q-1)/2` never meets a theta wall.

At g=Q/2 the minimizers tie. The executed negative test Q=6,z=3 obtains n=-1 and n=0, both value zero. Thus extending to even or real periods requires an explicit boundary convention or a set-valued minimizer theorem.

With **authentic same-z** coordinates g and `z mod A`, integral Q,A coprime, the identity gives

`K mod A = ((z mod A)-(g mod A))*Q^{-1} mod A`.

For integer K in [-B,B], `2B<A` makes the residue unique. Dropping that premise yields aliases K and K+A. Deriving a candidate inside the corridor cannot itself certify that the true state was inside; the bound must come from the producer or history. No persistent scalar K is required by the theorem: it is an observable derived from the paired state.

Source: October 22 document lines 20–74 and test lines 9–31, 47–74, 195–219.

## 2. The 2/11 identity is a branch observable, not an automatic producer

For odd integral Q and integral z=g+QK in the centered chart, define D=T_Q(z+1)-T_Q(z). For interior g, D=-2K; at the right endpoint g=(Q-1)/2, the next chart crosses a wall and D=-2K-1. Thus

`D=-2K-b`, `b=D mod 2`, `K mod 11=-(D+b)*6 mod11`.

The same formula holds modulo every odd m using `2^{-1} mod m`; 11 is not required by this algebraic statement. The project can assign 11 its own architectural role without making it uniquely forced by this identity.

The test derives D from known K in one part and from an independent theta minimization in another. This validates the identity. It does not make an unknown encrypted D or b available for free. The same-history producer, ciphertext encoding, noise bounds and return path are separate obligations.

Prime-power sisters 49,121,25 have product 148225 and can separate every K in [-4096,4096] **if their authentic D residues are available**. A residue modulo 7 does not by itself supply a residue modulo 49; the stronger observer carries additional information. The test's loop at lines 144–153 combines the stronger residues through an accumulated scalar CRT representative. It is a clear test/projection, not evidence that a strict production no-Garner path implements this combination.

Source: October 22 document lines 76–116; test lines 95–160.

## 3. What the executed native test covers

It uses Q=348959453350711275087786864768188417 and A=9699690; gcd(Q,A)=1. It covers all 8193 K values from -4096 to 4096, but only **seven** chart values `[-h,-h+1,-1,0,1,h-1,h]`, h=floor(Q/2). That gives 57,351 source-coordinate cases and eleven arbitrary-target projections per case. It never materializes the potentially overflowing z=g+QK at native Q. The test constructs authentic coordinates by modular products using its known oracle K.

The document's lines 67–68 say the native test covers the entire rectangular corridor. This is too broad as a test claim. The written inequality proves the theta property for the whole corridor; the executable samples seven chart positions. Preserve that distinction in an updated proof/report.

Source: test lines 163–192. This fresh run does not execute any encrypted target. The repository also contains a conditional encrypted consumer at `coefficient_slot_gate.rs:396`, where a fixture supplies both encrypted source and chart coordinates. The source explicitly calls the N=8 configuration insecure, and the test checks a dependent square. Its functional source is real; it is not a complete native encrypted producer or a security proof.

## 4. The higher-rank theorem available for formalization

Let Omega be a real symmetric positive-definite d by d matrix, and define

`T_Omega(z)=min_{n in Z^d}(nᵀ Omega n+2 nᵀ z)`.

Positive definiteness makes the minimum attained. For every k in Z^d, changing variables n=m-k yields the universal quasi-periodicity identity

`T_Omega(g+Omega*k)=T_Omega(g)-2 kᵀg-kᵀOmega*k`.

This is twice the standard tropical theta quasi-periodicity in Inoue–Takenawa Remark 1.5. It is not a new priority claim.

Define the open theta cell

`C0={g: mᵀOmega*m+2mᵀg>0 for every nonzero m in Z^d}`.

For g in C0, zero is the unique minimizer of T_Omega(g), so -k is the unique minimizer at z=g+Omega*k and the rank-one formula generalizes. At the cell boundary, retain minimizer ties. An arbitrary lattice parallelepiped is not necessarily this theta/Voronoi cell; independent coordinate rounding can choose the wrong theta branch for a coupled Omega.

Now restrict to an integral matrix B and integer x,r with `x=r+B*k`. Given paired componentwise residues modulo a, we have

`B*k = x-r (mod a)`.

If det(B) is a unit modulo a, B is invertible over Z/aZ, and `k mod a = B^{-1}(x-r)`. Then an allowed set S of k is recoverable exactly iff reduction modulo a is injective on S. Boxes of coordinate width less than a suffice. With nonunit determinant, the exact obstruction is the kernel of the observation matrix; multiple observers can still separate a bounded S even when no one observer does. Smith normal form is a natural way to describe the kernel for integer lattices.

The independent test includes B=diag(2,3), anchors 4 and 9. Each observer aliases on S={0,1,2,3}², but their combined observation separates all 16 S states. The combined observer still aliases (0,0) and (18,12). This is a concrete extension beyond demanding an inverse in every lane, with a precise bounded-domain guarantee.

The theorem recovers the sheet from a **given correct chart**. It does not solve the higher-dimensional chart-selection/lattice-reduction problem. The source itself acknowledges this at October 22 lines 361–363.

## 5. A general lifting theorem, with an exact boundary

Let G,H be abelian groups, Lambda a subgroup of G, and sigma:G/Lambda→G a chosen set-theoretic section of the quotient. For a state x define r=sigma([x]) and its lift `ell=x-r in Lambda`. Let h:G→H be an observer homomorphism. Paired observations give

`h(ell)=h(x)-h(r)`.

Let S be the admissible set of lifts. **The lift is uniquely recoverable from these data for every ell in S if and only if**

`(S-S) intersection ker(h) is a subset of {0}` (equivalently equality when S is nonempty).

Proof: if h(ell1)=h(ell2), their difference is in the displayed intersection; triviality forces equality. Conversely, a nonzero difference in that intersection gives two admissible lifts with identical observed data. This proves both sufficiency and necessity, with no appeal to finite experiments. It is a hand-derived ordinary proof here, not a newly compiled Lean theorem.

Integer K recovery is G=Z, Lambda=MZ, h=mod A, ell=MK. The noncoprime case and coupled-anchor resolution are kernel calculations. Lattice-sheet recovery is Lambda=B Z^d. A torus covering is G=R^d with a lattice subgroup and an appropriate observer group. This formulation captures the reusable mechanism while refusing unsupported universality.

The section's addition defect `c(u,v)=sigma(u)+sigma(v)-sigma(u+v)` belongs to Lambda and satisfies

`c(u,v)+c(u+v,w)=c(v,w)+c(u,v+w)`

by telescoping. This explains winding composition and the familiar carry cocycle. It does not say the section is a homomorphism, or that evaluating a secret-dependent observer is cheap.

For a nonabelian covering/generalized fiber, replace subtraction by an appropriate group action and require a free action plus a separating observer; there is no automatic modular-inverse formula. Arbitrary non-algebraic systems need an explicit observation map and an injectivity theorem. Calling every such operation K-Elimination without identifying that map makes the generalization unfalsifiable.

## 6. Five meanings of a continuum lift

| Construction | What it establishes | Additional obligation for the user's stronger claim |
|---|---|---|
| Rank-one covering-space lift | Recovers a bounded integer sheet of R/QZ, given the chart and independent anchor phase | Correct chart/phase producer and bound; no unlimited finite-state claim |
| Real-valued tropical Toda dynamics | Piecewise-linear equations already make sense on real variables; Inoue–Takenawa's generic isolevel set is a real tropical Jacobian | Specify mapping from CRAM states to that particular period matrix, conserved quantities and flow |
| Inverse ultradiscretization | Can construct a continuous/discrete precursor under chosen structure | Specify a lifting rule and prove it maps forward to the desired dynamics; uniqueness does not follow |
| PDE/hydrodynamic continuum limit | A scaled sequence of discrete dynamics converges to a continuous equation | Define space/time scaling, topology, initial-data class, consistency, stability/compactness and convergence |
| Profinite completion | Compatible residue systems give an inverse-limit arithmetic object | A separate map/limit is required for real topology; profinite completion is not R |

Tropicalization is not injective. For every c>0 and fixed a,

`lim_(epsilon->0+) [-epsilon*log(c*exp(-a/epsilon))]=a`.

Distinct positive coefficients c disappear. Knowing a, even with a recovered discrete sheet, does not recover every c. This does not forbid a constructive choice of lift; it refutes automatic unique lossless inversion of tropicalization. Algebraic cancellations can lose still more data when subtraction is allowed, which is why standard constructions impose subtraction-free hypotheses or add sign/phase data.

A finite residue state has finitely many distinguishable states, so it cannot injectively encode all of R. If a real chart g is retained exactly, a bounded discrete sheet can indeed be added back, but the continuous information was supplied by g. Finite-valued group homomorphisms from the divisible group R^d to a finite abelian group are trivial; finite modular observers therefore need an integer/fixed-denominator state subgroup, or must be replaced by richer phase observations. Exact irrational charts cannot be recovered merely by increasing a fixed finite anchor pool.

The profinite integers are compact and totally disconnected; R is connected and noncompact. They are not isomorphic as topological rings. Integers n! converge to 0 profinitely because every fixed modulus eventually divides n!, while n! diverges in the usual real metric. This directly exhibits the distinct limiting notions. An adelic construction includes additional archimedean data; it does not conjure that data from finite residues.

## 7. Implementation and chronology boundaries

The small-chart cocycle experiment stores a `winding: Option<V>` alongside selectors (`tropical_cocycle_state.rs:26–34`) and updates it during composition (`:87–124`). That is a research representation carrying an encrypted/clear winding coordinate depending on V, not the current on-demand-only architecture contract. Preserve its arithmetic evidence as a distinct prototype; do not cite it as implementation proof of a no-carried-K design.

That small-chart scheme requires O(q) remainder selectors. Its typed refusal prevents substituting a native 119-bit period for q=13. The exact native alias is:

`A=9699690`, `L=13*A=126095970`,
`Q=348959453350711275087786864768188417`,
`D=floor(Q/L)*L=348959453350711275087786864715221600`.

Sources S0=0 and S1=D have identical `(center_13(S), floor_nearest(S/13) mod A, S mod A)` but native nearest-Q sheets 0 and 1. Their native centered phases are 0 and -52966817. This is a source-form algebraic fixture, not a demonstrated collision between two fully authenticated ciphertext histories; the original encrypted source selectors still distinguish them. It precisely refutes this projected small-chart state as a sufficient native-Q observer, not every CRAM construction. Independently reproduced in the audit oracle.

The October 22 note says native refresh remains open. The current November 4 status explicitly documents a separate working encrypted research refresh backend and archived native cycles, while maintaining legacy gates and unestablished full-setup confidentiality. Do not use an old local-chart gap to deny that newer scoped functionality. Conversely, the newer research refresh does not automatically prove a Toda/BBS flow equivalence or a continuum limit.

## 8. Recommended proof modules

1. `LiftObservation`: the subgroup/section observer-separation theorem and the obstruction direction.
2. `SignedLift`: Euclidean versus centered conventions, a proved corridor, and aliases when the bound fails.
3. `LatticeLift`: matrix modular solve, invertible determinant case, combined-observer kernel, optionally Smith normal form.
4. `SectionCocycle`: telescoping identity and operation-sequence invariance, with observable production separate from algebra.
5. `TropicalThetaLift`: positive-definite coercivity, theta quasi-periodicity, interior-cell argmin and boundary ties.
6. `DomainBridge`: a separate theorem for each specific BBS/Toda/FHE mapping, stating its state encoder, commuting evolution diagram, range, and information retained. A theorem about the observer algebra should not stand in for this module.

The strongest supportable general claim is: **Whenever a system admits a quotient/lattice decomposition and authentic complementary observations separate the permitted lifts, K-Elimination's observer mechanism generalizes to exact lift recovery.** The separation condition characterizes both its reach and its failure boundary. Mathematical novelty, historical priority and computational advantage must then be evaluated for each realization rather than inferred from the abstract theorem alone.
