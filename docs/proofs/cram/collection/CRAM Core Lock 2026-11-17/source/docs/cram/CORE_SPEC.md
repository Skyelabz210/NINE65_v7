# CRAM core: architecture lock baseline

Date: 2026-11-17. Status: **normative implementation target**, with verification status in [PROOF_OBLIGATIONS.md](PROOF_OBLIGATIONS.md). This document does not assert that the current Rust implementation already satisfies every clause.

## 1. Engine ownership

CRAM is the exact arithmetic engine on which NINE65 is intended to run. CRAM owns representation, arithmetic, observation admission, operator topology and frame transport. NINE65 will consume these contracts through an adapter with its own representation and cryptographic obligations. CRAM correctness does not depend on proving that adapter first.

The current independent `cram-core` package is the implementation ownership target. At NINE65 commit `88a7bdadbf0e1f8fbfdb2b37e9843101b8db3484`, its integration into `nine65` is principally optional architecture metering, not the completed arithmetic-engine connection. This is an implementation gap, not a change in the intended architecture.

**Definition.** CRAM is a configurable exact-arithmetic machine whose computational state consists of authentic residue observations in declared frames. It executes typed operators, preserves the declared relationships between sister trays, and derives lift, comparison, division and transport results from sufficient observations.

## 2. Values, frames and state

The specification distinguishes three semantic domains: integers, exact rationals, and heterogeneous products of residue rings. A value's domain is explicit. Signed integer interpretation uses a declared admissible interval and Euclidean remainder convention; centered representations use a separately declared section. A rational has a positive denominator and a canonical normalization contract; its numerator and denominator are represented by the exact substrate, not floating-point approximations.

A prepared frame specifies positive nontrivial moduli, logical roles, observation maps, numeric domain, operator topology, admissible domains and prepared public arithmetic constants. Runtime state contains canonical observations, frame/view identity and the source/operation bindings required by its producer contract. A mathematical source value is a ghost variable in proofs, not an independently carried runtime integer.

K, scalar magnitude, and a running winding tower are not independently maintained or serialized payloads. Derived query temporaries are allowed for their consumption. Persistent bounds are declared public/workload bounds with proved interval propagation; they must not independently track the exact source magnitude under another name. An exact public constant or singleton boundary value has an explicitly declared boundary scope. A bound initialized to arbitrary exact input and then used as magnitude-bearing payload does not meet the general residue-state contract.

Frame identity, value revision, layout revision and instruction identity have different meanings. Matching identifiers is necessary for some operations but is not proof that an observation was produced correctly. Invariant-bearing state constructors must prevent unchecked creation, cross-frame reinterpretation and mutable bypasses.

## 3. Safe Basis and observation capacity

The core theory is parameterized. It supports named profiles S6 = {2,3,5,7,11,13}, product 30030, and S8 = S6 union {17,19}, product 9699690. Preserve the declared logical roles under physical packing. The coprime repacks {6,35,143} and {6,35,143,323} preserve the respective product-ring identity.

Independent CRT carriers require pairwise coprimality, not primality. Dependent views may overlap or repeat factors. Their joint period is the LCM; compatible readings agree modulo pairwise GCDs. Repeating a factor does not multiply capacity. Whether an operator needs a unit, field, root of unity, ordering query or inverse is a separate contract.

For direct modulo observations (or proved invertible encodings of them), an integer interval [lo,hi] with width hi-lo < C, where C is the joint observation period, suffices for uniqueness. For |X| <= B, 2B < C suffices. Information-losing heterogeneous features cannot inherit this capacity merely from a modulus label. Exact queries can also be available without full integer uniqueness, as described next.

## 4. Universal query transport and derived lifts

For source domain D, observation h:D -> O and requested query q:D -> Q, a readout on h(D) exists exactly when h(x)=h(y) implies q(x)=q(y). It is unique on the observed image. For additive homomorphisms this specializes to kernel containment. An abstract existence proof does not supply an efficient executable algorithm; each admitted readout needs its own constructive implementation and refinement proof.

For positive M,A and authentic observations r=X mod M and a=X mod A of the same integer, X=r+MK and gcd(M,A)=1 give

    K mod A = ((a-r) * inverse(M,A)) mod A.

If A=M+1, this becomes (r-a) mod A. A domain certificate can promote the quotient class to a full quotient; for K in [lo,lo+A), K=lo+((k-lo) mod A). No range certificate is required merely to return the correctly typed congruence class.

For nonunit M modulo A, d=gcd(M,A) gives resolution A/d, with the reduced congruence solved after exact division of the compatible defect by d. For multiple positive anchors, L=lcm(A_i) and R=L/gcd(M,L) give the combined quotient resolution. With fixed r, positive target b and unrestricted K known modulo R, X mod b is determined iff b divides MR. Restricted domains may admit more queries. Modulus-one constant queries are trivial views, distinct from nontrivial independent carriers.

Prepared inverses are public frame constants. One subtraction and multiplication describe the generic fixed-width readout once its observations exist. Adjacent anchors remove the multiplication. Obtaining observations, reductions, word width, allocation, capacity admission and transport remain separately accounted costs.

## 5. Authentic producers and phase-locked sister trays

A sister-tray contract states the common source or explicit source transformation, observation maps, frame, operation, phase relation and value revision. Initialization establishes these relationships. Each transition proves that its emitted observations satisfy the relationships for the new source.

The equation a-r-Mk = 0 mod A, when k was computed from that same defect using an inverse, holds for arbitrary r and a. It is not independent evidence of common origin. For example M=2,A=3, a main residue taken from 0 and an anchor residue taken from 1 pass the self-derived check but jointly describe 4 in [0,6). Producer correctness or independent transition evidence is required.

Shadow-11 and phase-lock-22 are distinct profiles. In the S8 shadow split, payload M=881790 omits 11 and inverse(M,11)=7. A phase-lock-22 profile requiring gcd(M,22)=1 cannot silently reuse that even payload. Preserve logical roles and each profile's actual assumptions.

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

Frames are immutable within an admitted operation. Capacity changes are explicit verified transitions undertaken while the source observations still suffice. A new modulus's existence does not produce its reading. New views must be derived by a proved readout or supplied through a declared authentic input boundary. Queries that remain determined may proceed despite lack of full integer identification.

A compatible family of finite frames supports a mathematical inverse-limit interpretation. Finite runtime storage does not hold an arbitrary element of an infinite inverse limit, and such an element is not automatically an ordered integer. Profinite, geometric and physical interpretations receive separate precise theorems.

## 8. Execution and consumer contract

For relation Rep(F,s,x), prove that admitted operations produce the specified semantic result and preserve representation. Whole-program verification must establish soundness, progress for admitted inputs, algorithm termination, and state-preserving typed refusal for invalid requests. Admission conditions must not be defined circularly as execution success.

Trusted arithmetic uses exact integer, modular and rational operations. There is no IEEE arithmetic, hidden scalar reconstruction, or Garner/mixed-radix emission inside residue computation. Explicit encoding, output reconstruction and independent verification oracles have separately typed boundaries. Proof ghost variables must be absent from executable payload and control dependencies.

NINE65's eventual adapter must bind its inputs to CRAM's source, frame, numeric and operation contracts and consume the typed results without weakening their premises. Cryptographic keys, noise, ciphertext correctness and confidentiality remain adapter/application obligations. They do not change CRAM's arithmetic semantics.

## 9. Completion criterion

The locked direction is not a declaration of completed implementation verification. Closure requires compiled proofs for admitted operations and transitions, the actual Rust refinement, public-path integration, proof-only ghost erasure, negative controls, and pinned build/axiom evidence. See the obligation ledger for current coverage and open work.
