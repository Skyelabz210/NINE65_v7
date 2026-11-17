# CRAM proofs across the NINE65 innovation system

12 November 2026. This map connects Anthony Diaz's K-Elimination/CRAM framework to the other constructions in the supplied corpus and the inspected NINE65 source. It is a reusable integration specification: each connection identifies the source observations, the query, the consuming operation, and the proof still needed at the implementation boundary.

The shared core is now a **130-declaration Lean package**, including explicit StarLift readouts, combined-anchor resolution, and complete bounded residue-space divmod/GCD. [The universal theorem](UNIVERSAL_THEOREM.md), [closure results](CLOSURE_PROOFS.md), and [verification manifest](universal-theorem/verification.json) state the checked scope. Concrete NINE65 observations below refer to commit `88a7bdadbf0e1f8fbfdb2b37e9843101b8db3484`.

**Status vocabulary.** **LEAN-CHECKED** identifies a compiled statement in the included package or separately identified native-refresh slice. **SOURCE-OBSERVED** identifies a construction actually read in the documents/code. **WRITTEN DEDUCTION** gives an algebraic consequence proved here but not newly added to Lean. **PROPOSED INTEGRATION** identifies an implementation or formalization to build. These labels avoid treating a connection between working components as an already verified combined system.

## The reusable contract

An application supplies a source relation `x = r + iota(k)`, authentic observations of the source and reference, and a requested consumer. With observed coordinate map B and requested coordinate map C, exact transport is possible on the full coordinate group precisely when

\[
\ker B\subseteq\ker C.
\]

A concrete factor D with DB=C computes the requested correction from the observed defect. On an admitted restricted domain, the corresponding condition is constancy on the observation fibers. Full K recovery is one possible consumer, not a mandatory intermediate. The runtime retains observed state and public bounds; K is derived when requested.

**WRITTEN DEDUCTION — reusable consumer graph.** If C₁ and C₂ both annihilate ker B, the pair C=(C₁,C₂) does too. Therefore one authentic defect can feed multiple proved consumers. If a later query is F∘C₁, it factors through C₁ and requires no stronger observation than C₁. Proof: equality under B implies equality under each Cᵢ, and applying F preserves equality. This supplies a precise basis for sharing a transient readout across an operation without serializing a persistent K ledger. An implementation must still preserve source/epoch bindings during that operation.

## 1. StarLift selects the tropical-theta minimizer

**LEAN-CHECKED core.** For adjacent A=M+1, the two orientations are

\[
\operatorname{Star}_+=(v_M-v_A)\bmod A=K\bmod A,
\quad
\operatorname{Star}_-=(v_A-v_M)\bmod A=(-K)\bmod A.
\]

**SOURCE-OBSERVED and WRITTEN DEDUCTION.** In the supplied tropical construction,

\[
T_Q(z)=\min_{n\in\mathbb Z}(Qn^2+2nz),\quad z=g+QK,\quad |g|<Q/2,
\]

the unique minimizing index is **n=−K** and the value is −QK²−2Kg. Consequently the negative StarLift orientation is directly a residue of the desired minimizing index. Under a public window selecting that index, it can drive branch selection without first emitting z. This gives a specific consumer for the negative winding query, rather than treating its sign as a naming convention.

**Producer / consumer.** For integer Q=M and integer g,z, use authentic z mod A and g mod A with A=M+1. The arbitrary-reference query returns the centered-chart coordinate K=(z−g)/Q modulo A. This K can differ from floor(z/Q) when g is negative; a canonical Euclidean readout needs the corresponding reference-shift correction. The consumer selects n in its certified window and evaluates the quadratic formula. **Remaining bridge:** prove the chart producer, wall/tie policy and index window. For real g or Q, specify a compatible observation of this same chart coordinate separately; the compiled integer StarLift theorem alone does not provide that real-valued instance. Sources: [StarLift](universal-theorem/STARLIFT.md), [theta derivation](TROPICAL_FHE_ADDENDUM.md).

## 2. Safe Basis, shadow 11, and consumer-specific anchor selection

**SOURCE-OBSERVED.** The inspected S8 split has payload M=881790, anchor 11, M mod11=8, and inverse 7. Its shadow-successor route preserves payload views and reads

\[
\Delta K\bmod11=7(\mathrm{shadow}_B-\mathrm{shadow}_A)\bmod11.
\]

The producer's successor bound selects the increment; it is not supplied by a caller as a hidden scalar. For absolute values in [0,M·11), the same split identifies K∈[0,11). The exact current source is `docs/execution/2026-10-03/PRIMING_ROOT_CONTRACT.md`, section “Owner-selected shadow-prime K-elimination.” Disjoint composite repacking preserves the represented signature; overlapping views have LCM capacity.

**LEAN-CHECKED core.** [CoupledAnchors](universal-theorem/CoupledAnchors.lean) proves that the total source period is P=lcm(M,A₁,…,Aₙ), and a target residue modulo b is determined on all compatible affine coordinates exactly when b|P.

**WRITTEN DEDUCTION — choose anchors for the consumer.** To add a genuine new observation modulo a, the new period is lcm(P,a). For a set of target moduli, let D be their LCM. The smallest a under divisibility that makes D|lcm(P,a) is

\[
a_{\rm req}=\prod_{p:\ v_p(D)>v_p(P)}p^{v_p(D)}.
\]

Proof: at every prime p the new period has exponent max(v_p(P),v_p(a)); whenever the existing exponent is insufficient, a must supply the target's entire exponent. At other primes no factor is needed. In particular D/gcd(D,P) is not generally sufficient: P=12,D=18 gives 3, but lcm(12,3)=12; the required anchor factor is 9. A simple sufficient choice is a=D.

**PROPOSED INTEGRATION.** A public planner can select the observations required by upcoming consumers, and certify their LCM before execution. It must obtain those new readings from an authentic source before distinctions are lost. This is not a method for synthesizing a missing residue from an insufficient old state. Sources: [combined-anchor proof](CLOSURE_PROOFS.md), [Safe Basis review](expanded-corpus/reviews/division.md).

## 3. Recumbent lane dropping is a change of quotient source

**SOURCE-OBSERVED.** `RecumbentCoefficient::drop_main` takes an observed divisor-lane remainder r_d, updates the signed interval, and computes each surviving quotient lane as

\[
q_i=(x_i-r_d)d^{-1}\bmod m_i,
\qquad X=r_d+dq.
\]

This is the ring constructor with multiplier d, independently applied in each surviving lane. Exact mode requires r_d=0. Floor mode uses the Euclidean remainder. The nearest-ties-positive mode shifts the remainder by d when its midpoint rule applies; the quotient changes accordingly.

**WRITTEN DEDUCTION.** If r'_d=r_d+d·a, then q'=q−a. The new [ReferenceChange](universal-theorem/ReferenceChange.lean) law explains this coordinate shift and preservation of the represented source under fixed observer maps. Removing a lane also changes the representation, so the complete drop operation additionally needs its destination-domain proof.

**Producer / consumer.** The divisor lane produces r_d; provisioned inverses and the new interval feed surviving quotient lanes. **PROPOSED INTEGRATION:** prove each rounding selector, destination capacity, and the exact Rust route's refinement to the ring identity. The inspected `RankResidueDivider` is a separate full-basis quotient projector and should retain its own proof and cost. Source: [current runtime routes](expanded-corpus/reviews/runtime.md).

## 4. Divmod and GCD enable exact rational normalization

**LEAN-CHECKED.** The concrete two-residue model computes quotient/remainder and Euclidean GCD for all admitted nonnegative inputs. Its divisor may share factors with either observer modulus. Zero division is refused, and gcd(0,0)=0 is represented correctly. These are complete loop proofs, not calls to a hypothetical correct division primitive.

**WRITTEN DEDUCTION.** Represent a rational by a numerator/positive-denominator pair (n,d), retaining each integer in an admitted residue representation. Set g=gcd(|n|,d). Since d>0, g>0; exact division yields (n/g,d/g), the same rational with coprime numerator and denominator. A zero numerator normalizes to (0,1). No denominator inverse in every residue lane is needed for this pair representation.

**Producer / consumer.** Ingress supplies the pair and sign; the GCD/divmod consumers normalize it. Multiplication and addition may use cross-cancellation to reduce growth, but their intermediate bounds must be proved. **PROPOSED INTEGRATION:** add signed-pair semantics, canonicalization uniqueness, and a capacity planner before connecting to exact-rational APIs. This represents rationals as pairs; it does not assert an embedding of all rationals into a single finite residue ring. Sources: [concrete closure](CLOSURE_PROOFS.md), [rational specification](expanded-corpus/reviews/framework.md).

## 5. Transduction transports operators as well as values

**LEAN-CHECKED core.** Exact encoded operations and valid-state transfers compose. Concrete target projections can transport the requested residue without constructing the source integer. Metadata equality remains a distinct contract.

**WRITTEN DEDUCTION — operator commuting square.** Suppose faithful encodings E_A,E_B represent a common admitted domain, transfer T satisfies T(E_A(x))=E_B(x), and implementations F_A,F_B represent the same semantic operation f. Require f to preserve that domain, or discharge the relevant partial-operation guards. Then

\[
T\circ F_A=F_B\circ T
\]

on valid source states. Proof: both sides applied to E_A(x) equal E_B(f(x)). For mutually inverse transfers, F_B=T F_A T⁻¹ on the common valid image.

This gives a precise way to connect heterogeneous operator trays: name their semantics and prove the transfer intertwines the chosen operations. A topology-product operator need not be ordinary integer arithmetic. If the two operators have different semantics, use the explicit semantic map that relates them rather than imposing a false integer identity.

**PROPOSED INTEGRATION:** give each transduction a value/query map, instruction/schema map and source-binding map; prove the appropriate square and the intended equality notion. Reversible value transport does not reverse append-only history. Sources: [framework and transduction](expanded-corpus/reviews/framework.md), [finite composition](universal-theorem/ExactObservation.lean).

## 6. Polynomial quotient recovery and derivative-weighted lifting

**LEAN-CHECKED generic constructor; WRITTEN polynomial instance.** For X=r+MQ in F[z], coprime polynomial anchors M,A give

\[
Q\bmod A=(X\bmod A-r)M^{-1}\bmod A.
\]

A degree window deg Q<deg A selects the exact quotient polynomial. The shared-factor fiber is governed by the ideal quotient; over F[z] it reduces to resolution modulo A/gcd(M,A), with a normalization convention.

**Producer / consumer.** The source is an unreduced polynomial with authentic modular views; the consumer requests Q or a target projection of Q. Degree is a representative bound, not an integer winding count. **PROPOSED INTEGRATION:** formalize the polynomial remainder/degree instance and connect its lanes to the actual negacyclic polynomial representation. One polynomial multiplication is not one coefficient operation. Source: [polynomial derivation and tests](expanded-corpus/reviews/portfolio.md), [ring theorem](universal-theorem/RingReadout.lean).

The same coordinate idea connects to local derivative lifting in the next section; the nonlinear producer must be linearized on its declared source chart before applying the linear transport argument.

## 7. NINE65 G/H refresh is a local observed-coordinate construction

**SOURCE-OBSERVED and separately LEAN-CHECKED arithmetic.** For x=ρ+pK, a polynomial G with G(ρ)=0 mod p² and a derivative inverse H(ρ) satisfies the first-order relation

\[
G(\rho+pK)\equiv G(\rho)+pK G'(\rho)\pmod{p^2}.
\]

Hence the divisible defect δ=(G(x) mod p²)/p obeys δ≡K G'(ρ) mod p, and multiplication by H recovers K mod p. The included native-refresh proof slice checks the Taylor remainder, exact division, reduction and inverse coherence under its hypotheses.

**WRITTEN DEDUCTION.** On this local chart, the observed coordinate map is K↦G'(ρ)K mod p, and the consumer is K mod p. Its unit-kernel criterion is the same one as K-Elimination. G itself is nonlinear and is not being declared a global additive observer. The expensive part of this realization is producing the protected defect and evaluating the polynomials; the final inverse-weighted readout does not erase that work.

The native source bound is |K_native|≤48. For Y=K_native+48∈[0,96], authentic 36/37 views would suffice to select the exact coordinate. That is an admissible alternate observer contract; it is not proof that such protected views are already independently available. K_phase, K_native, the residual ρ, and the adjacent quotient floor(Y/36) are different source quantities.

**PROPOSED INTEGRATION:** bind the real G/H producer and its consumed correction to the universal contract, preserving the existing key/noise/provenance conditions. Keep coefficient scaling, protected decryption-phase correction, and encrypted bit-word integer division as distinct typed operations. Sources: [native polynomial identity and proof slice](TROPICAL_FHE_ADDENDUM.md), [current encrypted division/rescaling routes](expanded-corpus/reviews/runtime.md).

## 8. Vector/lattice queries preserve only the displacement the consumer needs

**LEAN-CHECKED additive criterion; WRITTEN matrix/lattice instances.** For linear observed displacement B and target C over a field, ker B⊆ker C is equivalent to a factor D with DB=C. Full K requires an injective B; a selected linear target can remain recoverable at lower rank.

For lattice observations B(k)=Ak mod Λ with k∈ℤᵈ, define

\[
N=\{v\in\mathbb Z^d:Av\in\Lambda\}.
\]

The source ambiguity is k+N. A target Ck mod Γ is exact precisely when CN⊆Γ. This generalizes integer anchor resolution from a one-dimensional period Rℤ to an ambiguity lattice.

**Producer / consumer.** The producer supplies actual lattice/chart coordinates and a reference; the consumer requests a projection, flux, phase or correction. **PROPOSED INTEGRATION:** construct normal forms and domain selectors for a concrete finite-dimensional operator. An energy, skew-adjointness or polyunitary claim additionally needs its stated bilinear form and an operator preservation proof; invertibility alone does not establish those properties. Source: [matrix/lattice mathematical review](universal-theorem/MATHEMATICAL_REVIEW.md).

## 9. Conservative box-ball data yields an exact continuum interpolation query

**WRITTEN and previously EXECUTED.** For two given equal-mass binary configurations, prefix counts U_i,V_i produce C_i=U_i−V_i and heights H_i=i−2U_i, H'_i=i−2V_i. Conservation gives

\[
b'_i-b_i=C_i-C_{i+1},\qquad H'_i=H_i+2C_i.
\]

Linear interpolation E therefore satisfies E(H')=E(H)+2E(C) at every real spatial coordinate. The source is the supplied transition and its boundary convention. With total mass B, |C_i|≤B; shifted values Y_i=C_i+B have a finite certified observation window.

**WRITTEN DEDUCTION using the new combined-anchor result.** If actual combined observations of Y_i have total period P>2B, they identify every Y_i∈[0,2B], including when the moduli overlap. For a consumer needing only C_i mod b, the full-window selector can be replaced by the target-period criterion when b|P. Thus a modular flux consumer may require less observation capacity than a full continuous-height reconstruction.

**PROPOSED INTEGRATION:** formalize the prefix producer, interpolation linearity and the particular box-ball transition map. Proving that an embedding intertwines that evolution is a separate step from interpolating a given transition. A PDE scaling limit additionally requires a convergence theorem. Source: [conservative continuum construction](TROPICAL_FHE_ADDENDUM.md).

## 10. Coherent anchor towers and profinite computation

**LEAN-CHECKED finite resolution; WRITTEN extension.** For nested periods P_n|P_(n+1), compatible states x_n∈ℤ/P_nℤ satisfy x_(n+1) mod P_n=x_n. If stage operations F_n commute with the reductions,

\[
\pi_n F_{n+1}=F_n\pi_n,
\]

they define an operation on the inverse limit by applying F_n coordinatewise. Proof: the commuting equation preserves every compatibility condition. A target modulus b dividing some P_n can then be answered consistently from that stage onward.

This is a rigorous route from finite exact observations to a coherent infinite system. Finite products of distinct primes alone give a different completion from the full profinite integers: recovering the latter requires a divisibility-cofinal family with arbitrarily high powers of every prime. An inverse limit is not automatically the real continuum with its usual topology.

**PROPOSED INTEGRATION:** formalize compatible observation refinement, prime-power growth, and transition commutation. Generate each additional view from the authenticated source or an already sufficient finer state. For real-valued analysis, add a separately specified approximation/error or chart topology. Sources: [completion distinction](expanded-corpus/reviews/framework.md), [generalization boundaries](ANALYSIS.md).

## Four concrete integrations to prioritize

| Priority | Deliverable | Acceptance proof / execution |
|---|---|---|
| 1 | A shared query contract for StarLift, shadow11, recumbent and native G/H consumers | Each adapter identifies its source quantity, reference, authentic readings, public admissible domain and consumer. Prove its implemented output equals that consumer; keep K ephemeral. |
| 2 | Consumer-driven multi-anchor planner and fusion decoder | Use the checked LCM/GCD resolution and the prime-power selection rule above; implement compatibility checks and a concrete solver; prove returned classes and target projections. Additional source readings must be produced before information is discarded. |
| 3 | A production divmod/GCD/rational refinement path | Keep the checked residue loops as the specification witness. Refine the intended efficient NINE65 implementation to the same results, including zero policy and capacity propagation. Measure whole-path cost separately from the K readout count. |
| 4 | Two domain-specific bridges: StarLift-to-theta branch and G/H-to-universal query | Formalize the theta chart/window/tie rule, and the exact protected phase producer consumed by G/H. These yield stronger concrete cross-domain theorems than an unspecified universal continuum assertion. |

The initial archive and upload can contain this map alongside the checked proof sources, raw build evidence and source reviews. It is not a change to production implementations, a new encrypted execution, or a historical-priority determination. Its contribution is to identify precise reusable mathematics and the next connections that can actually be proved and implemented.
