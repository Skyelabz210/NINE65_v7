Below is a rigorous prose formalization of the two CRAM contributions we have been circling:

1. **Operational Division Closure** — the completed exact-integer division layer obtained by K-Elimination + Fused Piggyback Division + Recombinant CRT.
2. **Transduction** — the 5th CRAM operator, defined as exact signature-preserving transition between bases/topologies.

I am writing these as theorem-stack additions, in the same style as the existing corpus.

---

# Contribution I — Operational Division Closure

## 0. Purpose

The classical residue-number-system gap is that addition, subtraction, and multiplication are naturally lane-parallel, while exact integer division is not. K-Elimination handles exact division when the divisor is coprime to the basis product; FPD handles exact division when the divisor shares a factor with the basis product. The corpus explicitly states this domain split: K-Elim covers , FPD covers , and together they cover exact integer division over all integer divisors, assuming the quotient exists as an integer .

The formal contribution is:

```latex

\boxed{
\text{Exact integer division is a closed partial operation on Recombinant CRT states.}
}
```

“Partial” matters. CRAM does not claim that arbitrary rational division is closed. It claims that if in , then can remain inside the residue substrate.

---

## 1. Foundational setting

### Definition 1.1 — Basis

A **CRAM basis** is an ordered tuple

```latex

B=(m_1,\dots,m_k)
```

of pairwise coprime positive integers. In the standard safe basis these are primes:

```latex

\mathcal S=\{2,3,5,7,11,13,17,19\}.
```

Let

```latex

M_B=\prod_{i=1}^k m_i.
```

The corpus treats the basis product as the type signature of a CRAM element: each element carries witnesses determined by the moduli under which it is represented .

---

### Definition 1.2 — CRT decomposition and reconstruction

Define

```latex

\delta_B:\mathbb Z\to \prod_{i=1}^k \mathbb Z/m_i\mathbb Z
```

by

```latex

\delta_B(x)=(x\bmod m_1,\dots,x\bmod m_k).
```

Let

```latex

\gamma_B:\prod_{i=1}^k\mathbb Z/m_i\mathbb Z\to \mathbb Z/M_B\mathbb Z
```

be the inverse CRT reconstruction map, implemented by Garner reconstruction.

The ordinary CRT property gives:

```latex

\gamma_B(\delta_B(x))\equiv x \pmod{M_B}.
```

CRT preserves information modulo , but not beyond . Recombinant CRT adds the missing winding count.

---

### Definition 1.3 — Recombinant CRT state

A **Recombinant CRT state** over basis is a pair

```latex

R_B=(r,K)
```

where

```latex

r\in \prod_i \mathbb Z/m_i\mathbb Z,
\qquad
K\in\mathbb Z.
```

Its represented integer is

```latex

\operatorname{val}_B(r,K)=\gamma_B(r)+K M_B.
```

The corpus defines this winding count as the missing information ordinary modular arithmetic discards; Recombinant CRT records it so the value can be reconstructed as the exact integer, not merely as a residue modulo .

---

### Definition 1.4 — Canonical encoding

For each integer , define

```latex

\operatorname{enc}_B(x)
=
(\delta_B(x),\lfloor x/M_B\rfloor)
```

with the convention that the residue component is the canonical representative

```latex

x-\lfloor x/M_B\rfloor M_B\in[0,M_B).
```

Then

```latex

\operatorname{val}_B(\operatorname{enc}_B(x))=x.
```

Thus and are inverse up to canonicalization.

---

## 2. Exact division as the target operation

### Definition 2.1 — Exact integer division domain

For basis , define the exact division domain

```latex

\mathcal D_B
=
\{((r,K),b): b\in\mathbb Z\setminus\{0\},\ b\mid \operatorname{val}_B(r,K)\}.
```

For

```latex

x=\operatorname{val}_B(r,K),
```

the intended result is

```latex

q=x/b.
```

The exact output should be

```latex

\operatorname{enc}_B(q).
```

---

## 3. The two division mechanisms

### Definition 3.1 — K-Elimination branch

For

```latex

\gcd(b,M_B)=1,
```

the divisor is a unit in every lane. K-Elimination applies.

The K-Elim operation is a partial function

```latex

\operatorname{KDiv}_B:
\mathcal D_B^{\mathrm{coprime}}
\to
\operatorname{Rec}_B
```

where

```latex

\mathcal D_B^{\mathrm{coprime}}
=
\{((r,K),b)\in\mathcal D_B:\gcd(b,M_B)=1\}.
```

It returns the Recombinant CRT representation of

```latex

\operatorname{val}_B(r,K)/b.
```

Operationally, K-Elim computes per-lane inverse reports, extracts the winding correction by phase differential, and produces the quotient residues without reconstructing to conventional integer form. The corpus states the runtime operation as: compute lane-native inverse products, compute phase differential terms, extract the winding count, then correct the output residues .

---

### Definition 3.2 — Fused Piggyback Division branch

For

```latex

\gcd(b,M_B)>1,
```

some lane sees as a zero divisor, so K-Elim cannot apply. FPD introduces an auxiliary lane satisfying

```latex

\gcd(a,bM_B)=1.
```

The FPD operation is a partial function

```latex

\operatorname{FPDiv}_{B,a}:
\mathcal D_B^{\mathrm{shared}}
\to
\operatorname{Rec}_B
```

where

```latex

\mathcal D_B^{\mathrm{shared}}
=
\{((r,K),b)\in\mathcal D_B:\gcd(b,M_B)>1\}.
```

FPD temporarily extends the basis to

```latex

B^+=B\cup\{a\},
```

uses the auxiliary lane as the reference lane for the phase differential, computes the quotient residues, then discards the auxiliary lane and projects back to the primary basis. The corpus defines this as a transient auxiliary lane, not a permanent architectural basis extension .

---

### Lemma 3.3 — Auxiliary lane existence

For any finite and finite basis product , there exists a prime such that

```latex

\gcd(a,bM_B)=1.
```

**Proof.**  
Only finitely many primes divide . Since there are infinitely many primes, choose any prime not dividing . Then .

This establishes that FPD can always find an auxiliary prime in principle. Engineering chooses a small prevalidated auxiliary prime when possible.

---

## 4. Unified division dispatcher

### Definition 4.1 — CRAM exact division operator

Define

```latex

\operatorname{Div}_B((r,K),b)
=
\begin{cases}
\operatorname{KDiv}_B((r,K),b), & \gcd(b,M_B)=1,\\[4pt]
\operatorname{FPDiv}_{B,a}((r,K),b), & \gcd(b,M_B)>1,\ \gcd(a,bM_B)=1.
\end{cases}
```

The dispatcher is defined only when

```latex

b\neq 0
```

and

```latex

b\mid \operatorname{val}_B(r,K).
```

---

## 5. Theorem — Operational Division Closure

### Theorem 5.1 — Exact division closure over Recombinant CRT

Let be a CRAM basis with product . Let be a Recombinant CRT state over , and let satisfy

```latex

b\mid \operatorname{val}_B(r,K).
```

Then is defined and satisfies

```latex

\operatorname{val}_B\bigl(\operatorname{Div}_B((r,K),b)\bigr)
=
\frac{\operatorname{val}_B(r,K)}{b}.
```

Equivalently,

```latex

\operatorname{Div}_B((r,K),b)
=
\operatorname{enc}_B\!\left(\frac{\operatorname{val}_B(r,K)}{b}\right)
```

up to canonicalization of the winding representation.

---

### Proof

Let

```latex

x=\operatorname{val}_B(r,K).
```

By hypothesis , so

```latex

q=x/b\in\mathbb Z.
```

There are exactly two cases.

#### Case 1:

Then is a unit in every lane. K-Elimination applies. By the K-Elimination theorem, the operation returns the residue tuple and quotient winding corresponding to the exact integer quotient . Therefore

```latex

\operatorname{val}_B(\operatorname{KDiv}_B((r,K),b))=q.
```

So

```latex

\operatorname{val}_B(\operatorname{Div}_B((r,K),b))=x/b.
```

#### Case 2:

Then is not a unit in at least one lane. K-Elim is invalid. Choose auxiliary with

```latex

\gcd(a,bM_B)=1.
```

FPD applies. By Fusion Consistency, the quotient residues output in the primary basis equal the residues of the true integer quotient:

```latex

(q_1,\dots,q_k)
=
(q\bmod m_1,\dots,q\bmod m_k).
```

The output winding is the quotient winding of , so the returned Recombinant state represents . Thus

```latex

\operatorname{val}_B(\operatorname{FPDiv}_{B,a}((r,K),b))=q=x/b.
```

The two cases exhaust all possibilities because for every integer , either or . Therefore is correct on its whole exact-division domain.

---

## 6. Corollary — Arithmetic closure

### Corollary 6.1 — Closure of the four arithmetic operators

For Recombinant CRT states over a fixed CRAM basis , the operations

```latex

+,\quad -,\quad \times,\quad \operatorname{Div}_B
```

are closed on their natural integer domains:

```latex

\operatorname{Rec}_B\times \operatorname{Rec}_B\to\operatorname{Rec}_B
```

for , and

```latex

\mathcal D_B\to \operatorname{Rec}_B
```

for exact division.

Thus CRAM obtains operational completeness for exact integer arithmetic over represented integers.

---

## 7. Error and rejection taxonomy

### E-DIV-1 — Nonintegral quotient

Condition:

```latex

b\nmid \operatorname{val}_B(r,K).
```

Meaning: the requested operation is rational division, not exact integer division.

Required response: reject or route to a rational-extension layer. Do not silently floor.

---

### E-DIV-2 — Zero divisor branch without FPD

Condition:

```latex

\gcd(b,M_B)>1
```

and no auxiliary lane is selected.

Required response: invoke FPD. K-Elim must not be used.

---

### E-DIV-3 — Auxiliary collision

Condition:

```latex

\gcd(a,bM_B)>1.
```

Meaning: auxiliary lane is not valid.

Required response: choose a different auxiliary modulus.

---

### E-DIV-4 — Winding mismatch

Condition:

K-Elim-extracted winding disagrees with tracked Recombinant winding.

The corpus explicitly treats this as an invariant check: tracked windings and extracted windings cross-check each other, and disagreement indicates an implementation fault .

Required response: raise invariant violation.

---

### E-DIV-5 — Noncanonical output

Condition:

Output represents the correct integer but uses noncanonical winding/residue form.

Required response: canonicalize. This is not an arithmetic error.

---

## 8. Status

**Mathematical status:** Proven at the prose/theorem level, assuming the accepted K-Elim and FPD correctness theorems.

**Implementation status:** Existing corpus records K-Elim validation over millions of cases and FPD Fusion Consistency in the reference implementation .

**Substrate-qualified contribution statement:**

> Under a CRAM substrate with Recombinant CRT state tracking, for any represented integer and any nonzero integer such that , exact division remains inside the substrate. The dispatcher uses K-Elimination when and FPD when . The result is the exact Recombinant CRT representation of the quotient.

---

# Contribution II — Transduction , the 5th Operator

## 0. Purpose

Once exact arithmetic is closed internally, the remaining missing operation is not another arithmetic operation. It is movement between computational frames.

The corpus already defines CRAM as a substrate: a structured environment where every element carries a declared type signature and every operation preserves or explicitly transforms that signature . It also defines topologies as exact operator assignments: different topologies are not different implementations of one function; they compute different exact functions .

The 5th operator is therefore:

```latex

\boxed{
\mathcal X=\text{Transduction}
}
```

meaning:

```latex

\boxed{
\text{exact signature-preserving transition between bases/topologies.}
}
```

---

## 1. Substrate objects

### Definition 1.1 — CRAM substrate object

A **CRAM substrate object** is a tuple

```latex

\mathfrak S=(B,\mathcal T,\mathfrak G,\mathfrak V)
```

where:

- is a pairwise coprime basis;
- ;
- is a topology, meaning lane operators and post-processors;
- is a set of admissible property signatures;
- is a verifier, such as SD-11 or another type/signature checker.

The state space of is

```latex

\operatorname{Rec}_B
=
\left(\prod_i \mathbb Z/m_i\mathbb Z\right)\times \mathbb Z.
```

A typed state is

```latex

s=(r,K,\Sigma,\mathcal T)
```

where

```latex

(r,K)\in\operatorname{Rec}_B,
\qquad
\Sigma\in \mathfrak G.
```

---

### Definition 1.2 — Property signature

A **property signature** over is a finite predicate

```latex

\Sigma_B:\operatorname{Rec}_B\to\{\mathrm{true},\mathrm{false}\}
```

expressible by residue, winding, topology, or verifier conditions.

Examples include:

- residue class constraints;
- QR/QNR status;
- winding bounds;
- SD-11 shadow type;
- topology fingerprint;
- sieve membership.

The cross-domain injection corpus defines property signatures as finite residue/winding/type specifications and identifies them as the transferable structure between domains .

---

### Definition 1.3 — Signature satisfaction

A typed state

```latex

s=(r,K,\Sigma_B,\mathcal T)
```

is **well-typed** if

```latex

\Sigma_B(r,K)=\mathrm{true}
```

and the verifier accepts it:

```latex

\mathfrak V_B(r,K,\Sigma_B,\mathcal T)=\mathrm{accept}.
```

For SD-11, examples of signature types include ShadowCarrier, NonShadow, Unknown, and AmbiguousPair; the disambiguator uses the 11-lane signature to resolve ambiguity .

---

## 2. Transduction data

### Definition 2.1 — Transduction package

A **transduction package** from substrate to substrate is a tuple

```latex

\mathfrak X_{A\to B}=(\Phi,\Theta,\Pi,\Omega)
```

where:

1. is an exact integer transformation;
2. is a signature transport rule;
3. is a topology transport rule;
4. is a winding policy.

The winding policy must specify whether target winding is:

- preserved exactly;
- recomputed canonically;
- projected away;
- bounded but not retained.

Only the first two are reversible. Projection produces a valid transductive projection but not a reversible transduction.

---

## 3. Definition of the 5th operator

### Definition 3.1 — Transduction operator

Let

```latex

s_A=(r_A,K_A,\Sigma_A,\mathcal T_A)
```

be a well-typed state in . Let

```latex

x=\operatorname{val}_{B_A}(r_A,K_A).
```

If , define

```latex

y=\Phi(x).
```

Let

```latex

(r_B,K_B)=\operatorname{enc}_{B_B}(y).
```

Let

```latex

\Sigma_B=\Theta(\Sigma_A),
\qquad
\mathcal T_B=\Pi(\mathcal T_A).
```

Then

```latex

\boxed{
\mathcal X_{A\to B}^{\Phi,\Theta,\Pi,\Omega}(s_A)
=
(r_B,K_B,\Sigma_B,\mathcal T_B)
}
```

provided

```latex

\mathfrak V_B(r_B,K_B,\Sigma_B,\mathcal T_B)=\mathrm{accept}.
```

If the verifier rejects, the transduction is undefined.

---

## 4. Pure and active transduction

### Definition 4.1 — Pure basis transduction

If

```latex

\Phi=\mathrm{id}_{\mathbb Z},
```

then

```latex

\mathcal X_{A\to B}
```

is a **pure basis transduction**:

```latex

x_A\mapsto x_B
```

with the same represented integer but a new basis/topology frame.

Formula:

```latex

\mathcal X_{A\to B}(r_A,K_A)
=
\operatorname{enc}_{B_B}
\bigl(
\operatorname{val}_{B_A}(r_A,K_A)
\bigr).
```

---

### Definition 4.2 — Active transduction

If

```latex

\Phi\neq \mathrm{id},
```

then is an **active transduction**.

It changes the represented integer by an exact integer transformation while preserving or transforming the declared signature:

```latex

\Sigma_A\mapsto\Sigma_B.
```

Formula:

```latex

\mathcal X_{A\to B}^{\Phi}(r_A,K_A)
=
\operatorname{enc}_{B_B}
\bigl(
\Phi(\operatorname{val}_{B_A}(r_A,K_A))
\bigr).
```

---

## 5. Theorem — Transduction well-definedness

### Theorem 5.1 — Well-definedness

Let be CRAM substrate objects. Let

```latex

s_A=(r_A,K_A,\Sigma_A,\mathcal T_A)
```

be well-typed. Let be a transduction package satisfying:

1. ;
2. ;
3. is defined;
4. accepts the transported state.

Then

```latex

\mathcal X_{A\to B}^{\Phi,\Theta,\Pi,\Omega}(s_A)
```

is a unique well-typed CRAM state in .

---

### Proof

Since is a Recombinant CRT state, is a unique integer. Call it .

By condition 1, . By condition 2, .

Since is a basis, is uniquely defined as

```latex

(r_B,K_B).
```

The signature and topology transports produce

```latex

\Sigma_B=\Theta(\Sigma_A),
\qquad
\mathcal T_B=\Pi(\mathcal T_A).
```

By condition 4, the verifier accepts

```latex

(r_B,K_B,\Sigma_B,\mathcal T_B).
```

Therefore the output state exists, is unique, and is well-typed.

---

## 6. Theorem — Exactness preservation

### Theorem 6.1 — Value exactness

For every defined transduction,

```latex

\operatorname{val}_{B_B}
\left(
\mathcal X_{A\to B}^{\Phi,\Theta,\Pi,\Omega}(s_A)
\right)
=
\Phi\left(
\operatorname{val}_{B_A}(s_A)
\right).
```

---

### Proof

By definition,

```latex

(r_B,K_B)=\operatorname{enc}_{B_B}(\Phi(\operatorname{val}_{B_A}(s_A))).
```

By correctness of encoding,

```latex

\operatorname{val}_{B_B}(r_B,K_B)
=
\Phi(\operatorname{val}_{B_A}(s_A)).
```

Thus exactness is preserved.

This is where A1 enters: all objects are exact integers or exact residues, not approximations. The corpus identifies exactness as the axiom enabling reproducibility, composability, algebraic identity preservation, and formal verification .

---

## 7. Theorem — Signature preservation

### Definition 7.1 — Compatible signature transport

A signature transport

```latex

\Theta:\mathfrak G_A\to\mathfrak G_B
```

is **compatible with** if for every source state ,

```latex

\Sigma_A(s_A)=\mathrm{true}
```

implies

```latex

\Theta(\Sigma_A)
\left(
\operatorname{enc}_{B_B}(\Phi(\operatorname{val}_{B_A}(s_A)))
\right)
=
\mathrm{true}.
```

---

### Theorem 7.2 — Signature preservation

If is compatible with , then every defined transduction preserves the declared signature under transport:

```latex

\Sigma_A \leadsto \Sigma_B.
```

---

### Proof

Let satisfy . By compatibility,

```latex

\Theta(\Sigma_A)
```

holds on the encoded target value. But

```latex

\Sigma_B=\Theta(\Sigma_A).
```

Therefore the output state satisfies .

This matches the existing cross-domain injection principle: genuine transfer requires expressibility as a property signature, navigability in the substrate, and reversibility without loss .

---

## 8. Theorem — Reversibility

### Definition 8.1 — Reversible transduction

A transduction

```latex

\mathcal X_{A\to B}^{\Phi,\Theta,\Pi,\Omega}
```

is **reversible** on domain if:

1. is injective on and has an integer inverse on ;
2. has inverse on the transported signature class;
3. has inverse on the transported topology class;
4. retains or recomputes winding exactly;
5. both source and target verifiers accept the round trip.

---

### Theorem 8.2 — Round-trip identity

If is reversible on , then for every well-typed ,

```latex

\mathcal X_{B\to A}^{\Phi^{-1},\Theta^{-1},\Pi^{-1},\Omega^{-1}}
\left(
\mathcal X_{A\to B}^{\Phi,\Theta,\Pi,\Omega}(s_A)
\right)
=
s_A
```

up to canonicalization of the residue/winding representation.

---

### Proof

Let

```latex

x=\operatorname{val}_{B_A}(s_A).
```

Forward transduction gives target value

```latex

y=\Phi(x).
```

Reverse transduction applies :

```latex

\Phi^{-1}(y)=\Phi^{-1}(\Phi(x))=x.
```

The reverse basis encoding returns the canonical representation of over . Since source and target signature and topology transports are invertible, the transported signature and topology return to and . Therefore the state returns to up to canonical residue/winding normalization.

---

## 9. Transductive projection

### Definition 9.1 — Projection transduction

A transduction is a **projection** if it discards information that cannot be recovered by the inverse map.

The main case is winding loss:

```latex

(r_B,K_B)\mapsto(r_B,0)
```

without proof that or that winding is semantically irrelevant.

---

### Proposition 9.2 — Projection is not reversible

If discards nonzero winding, then is not reversible.

---

### Proof

Let two target states differ only by winding:

```latex

(r_B,K_1),\quad(r_B,K_2),
\qquad K_1\neq K_2.
```

Their represented integers are

```latex

\gamma_B(r_B)+K_1M_B
```

and

```latex

\gamma_B(r_B)+K_2M_B,
```

which are distinct. If maps both to , then two distinct inputs have one output. The map is not injective, so no inverse exists.

This is the formal correction to the earlier “K-neutral reset” language. A K-neutral reset is exact only if the target value is proven to have zero winding or if the operation is intentionally classified as blinding/projection rather than reversible transfer.

---

## 10. Placement relative to the four arithmetic operators

The four closed arithmetic operators are internal:

```latex

+,-,\times,\div:
\operatorname{Rec}_B\to \operatorname{Rec}_B.
```

Transduction is external:

```latex

\mathcal X_{A\to B}:
\operatorname{Rec}_{B_A}\to \operatorname{Rec}_{B_B}.
```

So the operator table becomes:

|Operator|Kind|Domain|Codomain|Meaning|
|---|--:|--:|--:|---|
||internal value operator|||add inside one frame|
||internal value operator|||subtract inside one frame|
||internal value operator|||multiply inside one frame|
||internal value operator|||exact divide inside one frame|
||external frame operator|||move value/signature/topology between frames|

This is why is the 5th operator: it does not complete arithmetic; arithmetic was already completed by Contribution I. It completes **frame mobility**.

---

## 11. SD-11 interaction

### Definition 11.1 — Shadow-compatible transduction

A transduction is **SD-11-compatible** if the target verifier includes SD-11 and accepts the transported shadow type:

```latex

\operatorname{SD11}_B(r_B,K_B,\Sigma_B)=\mathrm{accept}.
```

For a ShadowCarrier state, this means the 11-lane or its transported equivalent continues to carry the required shadow signature.

---

### Theorem 11.2 — Shadow preservation

Let be a ShadowCarrier. If maps ShadowCarrier to ShadowCarrier and SD-11 accepts the output state, then is a ShadowCarrier.

---

### Proof

By signature transport,

```latex

\Sigma_B=\Theta(\mathrm{ShadowCarrier})=\mathrm{ShadowCarrier}.
```

By verifier acceptance, the target state satisfies the ShadowCarrier rules. Therefore the output is a ShadowCarrier.

This aligns with the corpus’s treatment of SD-11 as a verification/type layer rather than a separate arithmetic operation .

---

## 12. Error taxonomy for Transduction

### E-X1 — Source ambiguity

Condition:

```latex

(r_A,K_A)
```

does not determine a unique integer.

In a proper Recombinant CRT state this should not occur. If winding is missing, the state is ordinary CRT, not Recombinant CRT.

---

### E-X2 — Target basis invalid

Condition:

is not pairwise coprime.

Then CRT encoding is not a clean product decomposition.

---

### E-X3 — Signature transport undefined

Condition:

```latex

\Theta(\Sigma_A)
```

is undefined.

Meaning: no declared rule exists for transporting this signature into the target substrate.

---

### E-X4 — Verifier rejection

Condition:

```latex

\mathfrak V_B(r_B,K_B,\Sigma_B,\mathcal T_B)=\mathrm{reject}.
```

The value may have been transported arithmetically, but the typed CRAM state is invalid.

---

### E-X5 — Illegal K reset

Condition:

```latex

K_B\neq 0
```

but the winding policy discards while claiming reversibility.

Required response: classify as projection or preserve/recompute winding.

---

### E-X6 — Non-A1 transformation

Condition:

uses floating-point, real-valued approximation, stochastic rounding, or any non-exact computational path.

Required response: reject. This violates A1.

---

### E-X7 — Topology collision

Condition:

```latex

\Pi(\mathcal T_A)
```

maps distinct topologies into one target topology while claiming invertibility.

Required response: classify as projection or include extra disambiguation metadata.

---

## 13. Theorem-register entries

### T-ODC — Operational Division Closure

**Statement.**  
For every CRAM basis , exact integer division is closed on Recombinant CRT states: if and , then the dispatcher using K-Elimination for and FPD for returns the exact Recombinant CRT representation of .

**Status.** Proven at prose level from T-KELIM and T-FPD-CONSISTENCY.

**Scope.** Exact integer division only.

**Failure mode.** Nonintegral quotient is outside domain.

---

### T-X-WD — Transduction Well-Definedness

**Statement.**  
Given two CRAM substrates, an exact integer transformation , a signature transport , a topology transport , and a winding policy , the transduction operator produces a unique typed target state whenever the source state is well-typed, is defined, target encoding exists, and the target verifier accepts.

**Status.** New theorem, proven above.

---

### T-X-EXACT — Transduction Exactness

**Statement.**  
For every defined transduction,

```latex

\operatorname{val}_{B_B}(\mathcal X(s_A))
=
\Phi(\operatorname{val}_{B_A}(s_A)).
```

**Status.** New theorem, proven above.

---

### T-X-SIG — Transductive Signature Preservation

**Statement.**  
If is compatible with , then preserves the declared property signature under transport.

**Status.** New theorem, proven above.

---

### T-X-REV — Reversible Transduction

**Statement.**  
If are invertible on the relevant domain and preserves or exactly recomputes winding, then the reverse transduction returns the original state up to canonicalization.

**Status.** New theorem, proven above.

---

### T-X-PROJ — Projection Non-Reversibility

**Statement.**  
Any transduction that discards nonzero winding or merges distinct topologies/signatures is not reversible unless the discarded data is independently proven redundant.

**Status.** New theorem, proven above.

---

# Final compression

The two contributions lock together like this:

```latex

\boxed{
\text{K-Elim + FPD + Recombinant CRT}
=
\text{internal arithmetic closure}
}
```

```latex

\boxed{
\mathcal X
=
\text{external frame mobility}
}
```

So CRAM’s operational stack becomes:

```latex

\boxed{
(\operatorname{Rec}_B,\ +,\ -,\ \times,\ \div)
}
```

for exact arithmetic inside a basis, and

```latex

\boxed{
\mathcal X_{A\to B}
}
```

for exact movement between bases/topologies/signature frames.

The first contribution closes the arithmetic gap.

The second contribution opens the dynamical layer.