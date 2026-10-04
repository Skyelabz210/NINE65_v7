# K-elimination: reusable proof content and the implementation connection

This review incorporates the owner's December2025 paper and two additional
repositories. The owner has explicitly identified the Garner/MRS reconstruction
account as historical. No plan task should restore that account as the live
architecture. Both repositories were inspected at pinned revisions; neither
proof project was rebuilt in this pass.

## Pinned evidence

* [`k-elimination-lean4`, 7cae414c](https://github.com/Skyelabz210/k-elimination-lean4/tree/7cae414c0c33a36774cdf9793a0fa7d279b69634), January6,2026.
* [`NINE65-v5-proofstack`, 6b14d5cf](https://github.com/Skyelabz210/NINE65-v5-proofstack/tree/6b14d5cfa1efa60d61e24f8383d661c51d2ecbdb), selected source checkout.

The local paths and reviewed-file hashes are in `safe_basis_review.json`.
The nested v5 technical paper is dated January2026; do not silently treat its
text as the same edition as the supplied December paper.

## What the proof establishes

`Soundness.k_elimination_sound` in the standalone repository's
[`KElimination.lean:249`](https://github.com/Skyelabz210/k-elimination-lean4/blob/7cae414c0c33a36774cdf9793a0fa7d279b69634/KElimination.lean#L249)
contains the inverse-formula proof. Its assumptions bind both coordinates to
the same X, give positive coprime M/A, require `X < M*A`, and supply a checked
inverse. It establishes that the computed modular phase expression equals
`X / M`.

This is substantive support for on-demand K derivation. Defining the
mathematical target as `X/M` does not mean an implementation must store K.
The proof does not require Garner or prescribe how the coordinate projections
are obtained. `modular_inverse_exists` at line117 allows composite M and A
provided they are coprime and A>1. A primality requirement must not be added
where only this unit condition is needed.

For A=M+1, `M^-1 = -1 mod A`, so the phase step reduces to
`K=(v_M-v_A) mod A`. The live `Anchor::winding` implements this subtraction;
`Anchor::lift` separately returns `v_M+M*K`. If a different coordinate system
encodes the requested value itself as that winding, specify and prove that
encoding. The current pair convention does not make K and X identical.

## Statement-level inventory

| Source and symbol | Scope to reuse |
|---|---|
| Standalone `key_congruence`, line98 | Division-algorithm identity in residue form |
| Standalone `modular_inverse_exists`, line117 | Inverse for coprime positive composite-or-prime moduli |
| Standalone `kElimination_core`, line167 | Congruence plus bounded winding; not alone the inverse-formula proof |
| Standalone `k_elimination_sound`, line249 | Computed phase/inverse expression equals bounded K |
| Standalone `division_exact`, line219 | Divisibility implies zero remainder |
| Standalone `division_correct`, line223 | Quotient/remainder identity and bound; not an executable RNS division refinement |
| Standalone `complexity_improvement`, line235 | Inequality between stipulated cost expressions, not measured or proved runtime of the implementation |
| Standalone Coq `K_Elimination.v` | Range/congruence lemmas; inspected source does not independently contain the full Lean inverse-formula proof |
| v5 `KElimination/ZMod.lean::k_recovery_zmod`, line50; `k_recovery_sound`, line97 | Residue formula and bounded natural-number recovery |
| v5 `KElimination/ZMod.lean::k_recovery_int`, line138 | Integer formulation with nonnegative X and range assumptions; not unrestricted signed comparison |
| v5 root `KElimination.lean::SignedK.signed_k_in_range`, line527, and `signed_k_reconstruction`, line573 | Proof bodies for the selected signed-K range and reduction back to its residue; retain exact midpoint/bound convention |
| v5 root `LevelAware.level_inv_exists`, line649, and `level_k_elimination_sound`, line654 | Level-specific inverse and bounded phase recovery proof bodies; useful for live level changes |
| v5 `proofs/coq/KElimination.v::k_elimination_sound`, line376 | Completed inverse-formula proof body with positivity, range and inverse assumptions; stronger than the separate standalone Coq file |
| v5 `proofs/coq/KElimination.v::signed_k_positive`, line583, and `signed_k_negative`, line594 | Proved branches of a specified signed-K interpretation |
| v5 same file: incremental CRT, signed range and level inverse sections | Includes `Admitted` at lines530,618,667; do not promote these unfinished extensions to proved implementation properties |

The standalone main/basic Lean and Coq sources contain no custom axiom,
`sorry` or admitted proof found by this source inspection. This does not replace
compilation, imported-assumption reporting or implementation correspondence.
The v5 proof stack has a different completion status, so do not apply the
standalone repository's status to the entire historical corpus. In particular,
the unfinished Coq signed-range extension does not erase the Lean signed-range
proof body: the two versions must be inventoried independently.

## What live magnitude/division/disambiguation still needs

The identity can be reused for more than naming an overflow count. Its actual
application must establish what the coordinates represent. S00/S01 and V02
must supply these links for each admitted operation:

1. Both tracks correspond to the same current state and epoch, with a proved
   range covering its whole operation history. A well-formed residue pair
   alone does not reveal whether an earlier operation overflowed its range.
2. Required `v_M mod A` or equivalent per-target contributions are obtained
   without the forbidden running reconstruction/carry state. Include this
   acquisition in cost and memory measurements.
3. Exact division establishes divisibility, quotient/remainder semantics or
   a rational/modular output convention. A winding-recovery lemma alone is
   not a checked implementation of every general-division case.
4. Signed magnitude and ordering have an explicit interval and midpoint rule.
   In particular, the historical Coq signed-K branches and a current balanced
   odd-modulus convention must be compared before reusing their labels.
5. A public FHE evaluator obtains any required secret-dependent phase through
   admitted encrypted operations, not a clear witness. Public coefficient
   magnitude and decrypted phase magnitude are different inputs to this proof.

Use the strict range `X_max < M*A`, equivalently
`A > floor(X_max/M)` for an inclusive nonnegative maximum. The paper's prose
`A >= max(X)/M` is not sufficient when the endpoint equals M*A. After aliasing,
the pair is indistinguishable from a smaller value; prevention needs a bound
or additional independent evidence, not a promise to detect overflow from
the same wrapped pair.

The corpus's `star_lift.py` makes this distinction concrete: for X=35113 and
M=36, the anchor37 recovers K mod37=13, whereas the full K is975. Its additional
anchor ladder recovers the larger K. That script was run successfully as a
reference model; it selects capacity using the known integer X and combines
K residues by CRT. Preserve the algebraic example without mistaking those
oracle choices for the completed K-free production provider.

## Historical claims to reconcile before publication

The December paper is useful design provenance, but its blanket claim that
mixed-radix/CRT methods are inherently approximate is incorrect. Exact integer
CRT reconstruction predates CRAM; the same two-coordinate correction appears
in [HAC chapter14, Algorithm14.71 and Note14.75](https://cacr.uwaterloo.ca/hac/about/chap14.pdf).
This does not decide the originality or value of CRAM's full architecture;
it means that novelty/performance claims must identify the particular new
organization, algorithm or implementation rather than this identity alone.

Likewise, the supplied Rust example returns u128 while its sample combined
range is about158 bits. It is not a valid fixed-width implementation of that
entire range without checked wider arithmetic. Keep the current checked
capacity work and the K-free design; do not port this historical snippet.

The reported190,000 historical tests and model-review counts were not rerun or
independently reconstructed here. Record them as historical claims until their
programs, input provenance and logs are located. They are not replacements for
the completed current Rust transduction tests or the future formal build.
