# CRAM core: architecture lock baseline

Date: 2026-11-17, amended for the owner's fixed-primary/dependent-sister clarification. Status: **normative implementation target**, with verification status in [PROOF_OBLIGATIONS.md](PROOF_OBLIGATIONS.md). This document does not assert that the current Rust implementation already satisfies every clause.

## 1. Engine ownership

CRAM is the exact arithmetic engine on which NINE65 is intended to run. CRAM owns representation, arithmetic, observation admission, operator topology and frame transport. NINE65 will consume these contracts through an adapter with its own representation and cryptographic obligations. CRAM correctness does not depend on proving that adapter first.

The current independent `cram-core` package is the implementation ownership target. At NINE65 commit `88a7bdadbf0e1f8fbfdb2b37e9843101b8db3484`, its integration into `nine65` is principally optional architecture metering, not the completed arithmetic-engine connection. This is an implementation gap, not a change in the intended architecture.

**Definition.** CRAM is a configurable exact-arithmetic machine with an intact, fixed primary Safe Basis and authentic phase-locked dependent sister trays. Sisters may use arbitrary positive moduli. It executes typed operators, preserves the declared relationships between trays, and derives lift, comparison, division and transport results from sufficient observations. Adding a sister does not add a modulus to the primary tray.

## 2. Values, frames and state

The specification distinguishes three semantic domains: integers, exact rationals, and heterogeneous products of residue rings. A value's domain is explicit. Signed integer interpretation uses a declared admissible interval and Euclidean remainder convention; centered representations use a separately declared section. A rational has a positive denominator and a canonical normalization contract; its numerator and denominator are represented by the exact substrate, not floating-point approximations.

A prepared frame specifies positive nontrivial moduli, logical roles, observation maps, numeric domain, operator topology, admissible domains and prepared public arithmetic constants. Runtime state contains canonical observations, frame/view identity and the source/operation bindings required by its producer contract. A mathematical source value is a ghost variable in proofs, not an independently carried runtime integer.

The primary frame and sister frames have distinct identities. The selected primary Safe Basis is immutable throughout execution: no operator adds, removes or replaces a primary modulus. Extension changes the supported sister observations or their precision while preserving the primary frame. The primary supplies the structural contract; the full coupled state supplies the observations needed by each query. Dependent means related by the declared source/phase/operation law; it must not silently be assumed to mean computable from the primary snapshot alone.

K, scalar magnitude, and a running winding tower are not independently maintained or serialized payloads. Derived query temporaries are allowed for their consumption. Persistent bounds are declared public/workload bounds with proved interval propagation; they must not independently track the exact source magnitude under another name. An exact public constant or singleton boundary value has an explicitly declared boundary scope. A bound initialized to arbitrary exact input and then used as magnitude-bearing payload does not meet the general residue-state contract.

Frame identity, value revision, layout revision and instruction identity have different meanings. Matching identifiers is necessary for some operations but is not proof that an observation was produced correctly. Invariant-bearing state constructors must prevent unchecked creation, cross-frame reinterpretation and mutable bypasses.

## 3. Safe Basis and observation capacity

The core theory is parameterized. It supports named profiles S6 = {2,3,5,7,11,13}, product 30030, and S8 = S6 union {17,19}, product 9699690. A chosen primary profile remains intact. The coprime repacks {6,35,143} and {6,35,143,323} are mathematical product-ring equivalences; they are not permission to replace the owner's primary tray or switch its profile during execution.

Independent CRT carriers require pairwise coprimality, not primality. Dependent views may overlap or repeat factors. For direct modulo observations, the joint period is the LCM and compatible readings agree modulo pairwise GCDs. Repeating a factor does not multiply capacity. Whether an operator needs a unit, field, root of unity, ordering query or inverse is a separate contract.

Arbitrary-modulus sisters need not satisfy the independent-carrier conditions merely to exist as observations. Their admission follows their phase-lock and query contracts. Properties of the primary are inherited through proved transport laws; a transported source invariant is distinct from claiming that every sister residue ring has the primary's field, unit or transform structure.

The Prime Family corpus makes the primary's role and family signature part of the architecture: parking/parity, fabric, surface, bridge, shadow/navigation and boundary are not interchangeable modulus labels. Register these roles and each operator's permitted use explicitly. Composite sisters can carry the relevant factor roles through declared interface maps; role names alone do not establish the arithmetic or dynamical property they denote. The reference's composite docking example involving 17 is not an instruction to add 17 to a selected S6 primary.

For direct modulo observations (or proved invertible encodings of them), an integer interval [lo,hi] with width hi-lo < C, where C is the joint observation period, suffices for uniqueness. For |X| <= B, 2B < C suffices. Information-losing heterogeneous features cannot inherit this capacity merely from a modulus label. Exact queries can also be available without full integer uniqueness, as described next.

## 4. Universal query transport and derived lifts

For source domain D, observation h:D -> O and requested query q:D -> Q, a readout on h(D) exists exactly when h(x)=h(y) implies q(x)=q(y). It is unique on the observed image. For additive homomorphisms this specializes to kernel containment. An abstract existence proof does not supply an efficient executable algorithm; each admitted readout needs its own constructive implementation and refinement proof.

For positive M,A and authentic observations r=X mod M and a=X mod A of the same integer, X=r+MK and gcd(M,A)=1 give

    K mod A = ((a-r) * inverse(M,A)) mod A.

If A=M+1, this becomes (r-a) mod A. A domain certificate can promote the quotient class to a full quotient; for K in [lo,lo+A), K=lo+((k-lo) mod A). No range certificate is required merely to return the correctly typed congruence class.

For nonunit M modulo A, d=gcd(M,A) gives resolution A/d, with the reduced congruence solved after exact division of the compatible defect by d. For multiple positive anchors, L=lcm(A_i) and R=L/gcd(M,L) give the combined quotient resolution. With fixed r, positive target b and unrestricted K known modulo R, X mod b is determined iff b divides MR. Restricted domains may admit more queries. Modulus-one constant queries are trivial views, distinct from nontrivial independent carriers.

Prepared inverses are public frame constants. One subtraction and multiplication describe the generic fixed-width readout once its observations exist. Adjacent anchors remove the multiplication. Obtaining observations, reductions, word width, allocation, capacity admission and transport remain separately accounted costs.

Here and in existing theorem names, 'anchor' denotes a mathematical role in a readout equation. It does not authorize introducing an independent channel into the primary Safe Basis. An implementation must identify the corresponding phase-locked observation in its actual sister-tray construction.

The complete extensible construction need not have a fixed global magnitude ceiling. In a p-adic instance with p not dividing M, authentic compatible sister readings a_n modulo p^n give compatible queries k_n=(a_n-r)*inverse(M,p^n) modulo p^n for a fixed remainder r. The winding component is an inverse-limit element; for integer-source readings it is the embedded quotient. No absolute bound on X is needed for these modular or coherent-family statements. Finite precision, integer representative selection and a global representation ceiling are different notions. The constructor and update laws must prove compatibility between levels; unrelated adjacent pairs do not establish it by their names. This inverse-limit instance is a written proof target, not an additional claim about the current Lean inventory or Rust implementation.

## 5. Authentic producers and phase-locked sister trays

A sister-tray contract states the common source or explicit source transformation, observation maps, frame, operation, phase relation and value revision. Initialization establishes these relationships. Each transition proves that its emitted observations satisfy the relationships for the new source.

Primary roles 2 and 11 remain present. The designated shadow-11 observation is reserved for its disambiguation/phase role, not overwritten by unrelated payload instructions. 'Reserved' does not mean a source-independent blank or zero. Other sister moduli may differ freely when their actual observation and phase laws are proved.

Formally, define a joint relation Rep(x,b,(s_j)) with primary observation b=h_B(x) and sister observations s_j=h_j(x), or an explicitly richer phase relation. Each admitted instruction must preserve this joint relation and leave B unchanged. Updates may use permitted cross-tray dependencies; independent per-lane updating is not assumed. For every claimed inherited property P, prove its transport implication through the relation. Initialization plus transition preservation then makes inheritance automatic by induction, rather than an unchecked assertion about all possible properties.

The Prime Family document's conditional signature-transfer principle (PDF p. 35) has a direct specification: inverse representation maps e,d and T(e(x))=e(F(x)) transport an invariant I of F to J(s)=I(d(s)). These maps can be proof-only. A query-specific readout requires only constancy of that query on observation fibers, not a full inverse. This separates complete semantic transport from a particular derived observable without changing the fixed primary.

As a concrete dependent-view model, Z/1001 is isomorphic to the compatible pairs in Z/77 × Z/143 that agree modulo 11. The shared factor is an interface, not an invalid independent CRT lane. Applying the same integer polynomial preserves that relation; heterogeneous operations must prove their own interface compatibility. Since 1001 divides 30030, these particular views add no direct-observation capacity to S6. They illustrate carrier structure, not new precision or a verified live constructor.

The equation a-r-Mk = 0 mod A, when k was computed from that same defect using an inverse, holds for arbitrary r and a. It is not independent evidence of common origin. For example M=2,A=3, a main residue taken from 0 and an anchor residue taken from 1 pass the self-derived check but jointly describe 4 in [0,6). Producer correctness or independent transition evidence is required.

Shadow-11 and phase-lock-22 are distinct mathematical/reference profiles. In the S8 shadow factorization, M=881790 is the product of the factors other than 11 and inverse(M,11)=7. This auxiliary factorization does not remove 11 from the primary tray. A phase-lock-22 profile requiring gcd(M,22)=1 cannot silently reuse that even M. Neither profile is an assumed implementation of the owner's full dependent-sister mechanism; preserve all primary roles and prove the selected phase law.

For a declared shadow readout with gcd(M,11)=1 and authentic successive states X_next=X+M*delta with unchanged payload, shadow readings yield delta modulo 11 from their difference. This equation's M is not automatically the full primary product. A declared interval of eleven consecutive integers resolves that local increment without an absolute bound on X or its winding. Nonunit cases retain their reduced query resolution. Additional compatible sister precision can resolve larger increment queries. Recovering a complete arithmetic trajectory needs its sufficient observation/transition evidence; authentic instruction provenance is a separate property to transport.

An independently predicted relation can be an integrity check. A zero congruence alone is not authentication, and arbitrary valid CRT tuples need not contain redundancy for error detection.

## 6. Arithmetic and heterogeneous topology

The integer instruction contracts include add, subtract, multiply, compare, exact division, Euclidean quotient/remainder and GCD. Define divmod for positive divisor d by X=dq+r, 0<=r<d; signed divisors are handled by a declared normalization. GCD is nonnegative, including gcd(0,0)=0. Modular inversion is a different operation requiring a unit. Nonunit inverse refusal does not preclude quotient/remainder. Rational division rejects a zero denominator and preserves its represented rational value.

Each division kernel must prove its preconditions, result and termination. Dispatcher coverage and agreement on overlapping applicable routes are required; the routes need not be disjoint. FPD is admitted only with its actual auxiliary producer and fusion proof. Adding an auxiliary modulus does not remove factors already shared with the old base.

An `IntegerNamed` operation claims correspondence with a specified integer operation. A `TopologyProduct` operation claims the stated product-state semantics; heterogeneous lane instructions need not implement the same ordinary integer operation. Transitioning between these meanings needs a compatibility map and proof.

Thresholds, squaring and other information-losing functions can be exact operations or diagnostic queries. They are not thereby reversible encodings of their inputs. Exactness is mandatory; reversibility is an additional capability, proved by inverse laws or sufficient retained recovery evidence. This capability-based treatment is the planning default, not an assertion that every historical A2 formulation was equivalent.

Lane-order confluence is proved from the actual dependency relation and snapshot semantics. Logical parallelism does not imply zero communication time, statistical independence or physical synchronization.

## 7. Fifth Operator and capacity transitions

Reserve **Fifth Operator** for typed transduction. Its value map Phi, property/signature map Theta, topology map Pi and observation/recovery policy Omega specify the whole transformation. Omega governs retained observations and recovery, not a persistent K ledger.

Prove identity and composition on admitted domains. Lossless instances additionally prove inverse/round-trip laws, with canonicalization explicit. A semantic description that decodes X and re-encodes it is a useful specification; it is not a residue-native implementation proof.

Frames are immutable within an admitted operation. Sister-tray creation, refinement and retirement are explicit verified transitions undertaken while the source observations still suffice; the primary Safe Basis is unchanged. A new sister modulus's existence does not produce its reading. New views must be derived by a proved readout or supplied through a declared authentic input boundary. Queries that remain determined may proceed despite lack of full integer identification.

A compatible family of finite frames supports a mathematical inverse-limit interpretation. Finite runtime storage does not hold an arbitrary element of an infinite inverse limit, and such an element is not automatically an ordered integer. Profinite, geometric and physical interpretations receive separate precise theorems.

## 8. Execution and consumer contract

For relation Rep(F,s,x), prove that admitted operations produce the specified semantic result and preserve representation. Whole-program verification must establish soundness, progress for admitted inputs, algorithm termination, and state-preserving typed refusal for invalid requests. Admission conditions must not be defined circularly as execution success.

Trusted arithmetic uses exact integer, modular and rational operations. There is no IEEE arithmetic, hidden scalar reconstruction, or Garner/mixed-radix emission inside residue computation. Explicit encoding, output reconstruction and independent verification oracles have separately typed boundaries. Proof ghost variables must be absent from executable payload and control dependencies.

NINE65's eventual adapter must bind its inputs to CRAM's source, frame, numeric and operation contracts and consume the typed results without weakening their premises. Cryptographic keys, noise, ciphertext correctness and confidentiality remain adapter/application obligations. They do not change CRAM's arithmetic semantics.

## 9. Completion criterion

The locked direction is not a declaration of completed implementation verification. Closure requires compiled proofs for admitted operations and transitions, the actual Rust refinement, public-path integration, proof-only ghost erasure, negative controls, and pinned build/axiom evidence. See the obligation ledger for current coverage and open work.
