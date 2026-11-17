# Independent review of arithmetic closure and anchor resolution

12 November 2026. This is an independent source and mathematical review of [CoupledAnchors.lean](CoupledAnchors.lean), [ResidueAlgorithms.lean](ResidueAlgorithms.lean), [ResiduePrimitives.lean](ResiduePrimitives.lean), [ReferenceChange.lean](ReferenceChange.lean), and [StarLift.lean](StarLift.lean). Their individual compiler/axiom logs were inspected. The package's final [verification manifest](verification.json) records the fresh integrated build and source hashes; this review does not substitute for that build.

The principal result is substantive: the abstract division/GCD primitive contract is discharged by the actual paired-residue implementation. No correct division or GCD result is assumed as a primitive. The executable loops retain represented quotient/remainder states and use public capacity as fuel. No mathematical or specification error was found in the reviewed statements.

## 1. Runtime inputs and proof-only semantics

`ResidueAlgorithms.Ops S` contains a public capacity, a zero state, increment, subtraction, comparison and a zero predicate. It contains no encoding function, semantic operand, reconstruction function or stored winding coordinate. `Correct ops encode` is a separate proposition: the encoding appears in the proof contract and not in the executable loop.

The concrete `ResiduePrimitives.State` has exactly two integer fields, `main` and `anchor`. `Frame` stores public moduli/inverse and their validity certificates. Its runtime operations are modular increment/subtraction, the on-demand K query, lexicographic comparison, and equality with the zero pair. `Frame.ops` contains those actual operations. `ops_correct` fills every field of the generic contract using proved primitive lemmas.

The use of `encode n` in theorem statements specifies what a state represents; it is not a runtime call to a scalar oracle. In particular, the definitions of `divLoop`, `divmod`, `gcdLoop`, and `gcd` do not invoke `encode`, integer quotient/remainder on the hidden source, or `Nat.gcd`. Those arithmetic functions occur in the correctness conclusions and proofs.

The separate `encode_injective_on` lemma derives bounded faithfulness from the exact comparison contract. The concrete module also proves faithfulness directly using its exact K query and main residue. Consequently, agreement with the encoded arithmetic result is not a statement about a potentially constant encoding.

## 2. Division: sufficient invariants and fuel

The generalized division-loop invariant is

\[
q+r<C,\qquad 0<d<C,\qquad r\le f,
\]

where C is the public capacity and f is the remaining public fuel. The program receives E(q), E(r), E(d), not the proof variables q,r,d.

If r<d, the loop returns the current represented pair; r/d=0 and r mod d=r justify that result. Otherwise d≤r and d≥1, so the recursive state is E(q+1), E(r−d), E(d). The inequalities

\[
(q+1)+(r-d)\le q+r<C,\qquad r-d\le f-1
\]

justify the bounded increment and recursion. The standard division identities establish

\[
q+1+(r-d)/d=q+r/d,
\qquad (r-d)\bmod d=r\bmod d.
\]

At fuel zero the program still performs the terminal comparison. Under the invariant r≤0, r=0<d, so success is guaranteed. This terminal check is why the non-strict fuel bound is sound.

The wrapper initializes q=0 and f=C. Every admitted dividend n<C therefore satisfies the invariant. Its zero-divisor test returns `none` for the represented zero. For every positive admitted d, `divmod_correct` returns exactly E(n/d), E(n mod d). There is no assumption d|n and no assumption that d is coprime to either frame modulus. The frame itself retains its distinct valid-inverse requirement for the K comparator.

## 3. GCD: full loop correctness

The Euclidean induction uses

\[
a<C,\qquad b<C,\qquad b\le f.
\]

If b=0, it returns E(a), which is E(gcd(a,0)). For b>0, the proved division call returns E(a mod b). That value is strictly below b, preserving both the original capacity and the decremented fuel bound. The identity gcd(a,b)=gcd(b,a mod b) closes the step. At zero fuel, b=0 and the terminal zero test succeeds.

Thus the public original capacity suffices for the entire computation. The result covers all admitted nonnegative inputs, including a=0, b=0 and (0,0). The quotient discarded between Euclidean steps is an ordinary temporary result in residue representation; it is not a retained scalar winding register.

`ResiduePrimitives.divmod_correct` and `gcd_correct` instantiate these loop proofs with `ops_correct`. They leave no abstract correct-comparator or correct-division oracle as an unproved hypothesis.

These are complete functional proofs of a clear arithmetic reference algorithm. Repeated subtraction and the Euclidean loop have operand-dependent branches and iteration counts. The two-operation K readout does not make the complete algorithms two-operation computations. An encrypted circuit or efficient NINE65 implementation requires its own refinement, control-flow treatment and cost analysis.

## 4. Coupled anchors: exact information and target criterion

For a finite list of positive anchor moduli, the definitions compute

\[
L=\operatorname{lcm}(A_1,\ldots,A_n),\qquad
R=L/\gcd(M,L).
\]

`combined_kernel` proves both directions of

\[
\bigl(\forall i,\ A_i\mid M\delta\bigr)
\quad\Longleftrightarrow\quad R\mid\delta
\]

for signed integer differences. It uses actual GCD/LCM library facts rather than assuming the claimed reduced period. `resolution_eq_lcm_reduced` proves equality with the LCM of individual reduced resolutions. `resolution_minimal` proves that the positive computed resolution is itself invisible and that every positive invisible difference is at least that large.

`same_affine_readings_iff` connects this kernel to equality of actual residues of r+Mk. `signed_window_unique` then proves uniqueness when both coordinates lie in the same half-open interval [lo,lo+R); it does not infer a bound from the size of an anchor alone. `main_and_anchor_readings_iff` proves that full source readings agree exactly modulo MR. Repeated/dependent anchors add no resolution when their modulus already divides L.

`combined_target_iff` proves necessity as well as sufficiency for an arbitrary target modulus: with a fixed reference, the target query is determined by all observed affine readings exactly when the target divides MR=lcm(M,L). Necessity compares coordinate differences R and zero; sufficiency transports the divisibility through the target reduction. This is the arithmetic instance of the universal kernel-inclusion criterion.

The empty anchor list has L=1, correctly expressing no additional coordinate observations. Operational statements use positive moduli; some algebraic identities also remain true for zero under Lean's totalized arithmetic conventions. The source assumptions remain actual same-source residue observations with the stated common reference. The module classifies resolution and target recoverability; it does not implement an arbitrary multi-anchor fusion solver or prove that a new authentic observation can be created from insufficient old state.

## 5. Reference changes and StarLift orientation

`ReferenceChange` correctly replaces r by r+ι(a) and k by k−a. The observed defect changes by −(h∘ι)(a). Its target-invariance theorem permits different old/new admissible sets and readout functions, provided each satisfies its own decoder law and the shifted coordinate is admitted. This is reference change under the same lift, observer and target maps. Changing the anchor or other frame maps, and producing their new authentic views, require additional statements.

`StarLift` distinguishes the two adjacent-anchor orientations. For A=M+1,

\[
(v_M-v_A)\bmod A=K\bmod A,
\qquad
(v_A-v_M)\bmod A=(-K)\bmod A.
\]

The congruences hold for arbitrary signed finite X. Exact integer K is selected using the stated public window. The negative-class decoder first negates the class and then applies that window selector. It does not mistake a negative coordinate residue for a positive integer quotient.

The accompanying [StarLift specification](STARLIFT.md) correctly distinguishes the raw defect δ=v_A−v_M from the positive coordinate result q: on δ the negative-coordinate decoder is the identity and the positive-coordinate decoder is negation. With B(k)=Mk mod A, the coordinate consumers are C₊(k)=k mod A and C₋(k)=−k mod A. If they are expressed as source target maps, p₊(x)=ux mod A and p₋(x)=−ux mod A give the required C=p∘ι. Choosing p(x)=x mod A would instead request Mk mod A.

The phrase “unbounded coordinate” concerns a family of finite integers. It does not introduce a literal infinity element into integer arithmetic. Knowing either signed orientation modulo A gives the same information, because negation is an involution. The general inverse and reduced-nonunit negative variants retain their explicit certificates and resolution.

## 6. Assurance boundary

The inspected compiler logs contain only standard Lean foundational dependencies (`propext`, `Quot.sound`, and where inherited, `Classical.choice`), with no admitted proof or project axiom. The main gain is that executable primitive and loop definitions now have conditional mathematical correctness proofs for every admissible input, rather than only finite test evidence or an abstract composition promise.

Authenticity and admission are theorem premises; these modules do not implement cryptographic source authentication or validate arbitrary malformed states. The concrete loops are an independent proof implementation, not a claim that the production NINE65 Rust paths execute these definitions. Polynomial/degree instances, higher-dimensional geometry, continuum dynamics and concrete encrypted refinements remain separate from this reviewed closure layer.
