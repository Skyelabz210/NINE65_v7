# Consumer demand, anchor synthesis and future-query compilation

These are written mathematical derivations supporting the two executed public-model prototypes in `reference/`. They are not a formal refinement of the Python implementation or a deployed ciphertext path. The dynamic quotient criterion and consumer composition rules have separate Lean proofs in [lean/](lean/README.md).

## 1. Periods are the information contract

For authentic observations `X mod m_i`, two unrestricted integer sources have the same readings precisely when their difference is divisible by

\[
P=\operatorname{lcm}_i m_i.
\]

The empty observation family has P=1. Overlapping or repeated moduli contribute their LCM, not their product. A query with least positive period D is determined by these readings exactly when D divides P. This is an existence/identifiability criterion: it does not by itself furnish a permitted, efficient decoder for every multichannel representation. The planner never receives readings and never reconstructs a source.

For the affine modular query `q(X)=(aX+c) mod b`, b>0, the condition is b|aP, so the least period is

\[
D_q=b/\gcd(a,b).
\]

It covers a=0, negative a, arbitrary c and b=1. A family of queries has demand `D=lcm(D_q)`, because every component must remain unchanged. Pulling a query backward through the public affine transition `X -> sX+t` replaces a by as and c by at+c. Its new demand divides its old demand. This gives a concrete compiler rule for avoiding unnecessary source information.

For `q(X)=floor(X/d) mod b`, d>0 and b>1, the least positive period is db. Sufficiency follows from `floor((X+db)/d)=floor(X/d)+b`. For necessity write a proposed positive period P=dt+r, 0<=r<d. At X=0 the quotient increment is t; if r>0, at X=d-r it is t+1. Both cannot be divisible by b>1. Thus r=0 and b|t. When b=1 the query is constant and its period is 1, not d. These arguments apply to signed Euclidean floor division.

The criterion is for the full integer domain. A restricted admitted set can need less information; a separate interval or fiber certificate must establish that. Exact sign or unbounded magnitude does not have a finite period. For every P>1, -1 and P-1 have identical residues modulo P but opposite signs.

## 2. Least additional anchor, without factorization

Given old source period P and consumer demand D, an additional authentic reading modulo a suffices exactly when

\[
D\mid\operatorname{lcm}(P,a).
\]

For a prime p let d=v_p(D), e=v_p(P). If d>e, a must contain p^d; if d<=e, this prime imposes no requirement on a. Consequently the least sufficient anchor under divisibility is

\[
a_* = \prod_{p:\,v_p(D)>v_p(P)}p^{v_p(D)}.
\]

Every feasible a is a multiple of a_*; a_* itself is feasible. This is an arithmetic minimum. Required NTT fields, Safe Basis roles, allowed word sizes, producer cost and actual lane availability may force a different engineering choice.

The implementation computes a_* without factoring:

\[
a_0=D/\gcd(P,D),\qquad a_{j+1}=\gcd(D,a_j^2).
\]

Stop when `a_(j+1)=a_j`. For each prime p, the initial exponent is max(d-e,0), and every iteration replaces the current exponent t by min(d,2t). A zero exponent stays zero. A positive exponent reaches d after finitely many doublings. The limit is exactly a_*. Each iterate divides D, and a strict update increases it under divisibility, proving termination independently of the prime-wise rate. With maximum positive exponent d_max, O(1+log d_max) iterations suffice; arithmetic is on public integers of size at most twice D's bit width. There is no constant-bit-cost claim.

**Why the missing-factor shortcut fails:** P=12, D=18 gives D/gcd(P,D)=3, but lcm(12,3)=12 is insufficient. Saturation yields gcd(18,3²)=9; lcm(12,9)=36 is sufficient. The full required prime power matters. The prototype tests this boundary and large powers up to exponent 151, including 2^151.

An instruction to add anchor 9 does not produce `X mod 9` from `X mod 12`: X=0 and X=12 demonstrate why that is impossible. The new reading must come from an authentic producer, an already sufficient finer representation, or a still-live source before information loss.

## 3. Choosing among actual public producers

The optional exact subset planner receives candidates `(name, modulus, public_cost)`. It minimizes total cost among subsets that cover D, then breaks ties by number of producers and lexicographic name. Costs are public positive integers; they may represent a chosen resource model, not measured speed unless separately justified.

For any selected set let L be its combined period with P. Only `coverage=gcd(L,D)` matters for feasibility. Adding modulus a updates coverage by

\[
\gcd(\operatorname{lcm}(L,a),D)
=\operatorname{lcm}(\gcd(L,D),\gcd(a,D)),
\]

as follows prime by prime from min(max(u,v),d)=max(min(u,d),min(v,d)). Thus dynamic programming over this coverage loses no relevant future state. At each candidate it retains the cheapest selection for each coverage. Future options are the same for equal coverage, so dominated selections cannot improve an optimum. Deterministic name ordering preserves the declared tie-break. The finite DP returns no selection when the available producers cannot meet demand.

Work is O(n*s) state transitions, with s bounded by both 2^n and the number of divisors of D; integer arithmetic and tuple bookkeeping have additional cost. This is a small reference optimization solver, not a scalable claim for arbitrary candidate catalogs.

## 4. Future-query closure: what must survive an entire computation?

Let S be a nonempty admitted state set, let F_i:S->S be the allowed total transitions, and let q_j be the desired outputs. For a finite word w of operations write F_w for their composition, including the identity. Define

\[
x\equiv_* y\quad\Longleftrightarrow\quad
\forall w,j,\ q_j(F_w(x))=q_j(F_w(y)).
\]

This is an equivalence relation. It is stable under every F_i, since applying F_i before an arbitrary future word is another finite word. It refines equality of the current output tuple by taking the empty word. Therefore the quotient S/~_* supports exact outputs and well-defined transitions.

It is the **coarsest equivalence relation with both properties**. If E already preserves all current outputs and is stable under all F_i, induction on word length shows x E y implies equality of every future output. Hence E is contained in ~_*. Every representation that supports autonomous transitions and exact requested outputs must distinguish at least these classes. This is a universal property of sufficient state for the declared operation/query family. It is related to observational equivalence, automaton minimization and observability; no historical priority is claimed for that abstract construction.

For additive transitions F_i and additive consumers C_j, the invisible subgroup is

\[
N_* = \bigcap_{w,j}\ker(C_j\circ F_w).
\]

It is the largest subgroup contained in every ker C_j and preserved by every F_i. This explicitly joins target-query recovery and dynamic kernel invariance. Finite modular observers can implement it only when their ambiguity subgroup lies inside N_*. Some problems require increasing precision or an infinite observation family.

The finite prototype starts with the partition by the current output tuple. Each pass adds the classes of every immediate successor to each state's signature. After t passes, equality means agreement for every operation word of length at most t. A stable pass gives a transition-stable partition; the preceding universal property makes it the coarsest sufficient one. Each strict pass increases the number of classes, so termination occurs after at most |S| minus the initial number of classes strict passes. All transition tables must be total on the specified finite domain. Partial operations need explicit refusal states/guards, rather than silently removing escaped states.

Two executed examples show the difference:

* On Z/16Z, the query X mod4 is closed under `3X+1` and `-X`. Four classes suffice for every finite composition.
* On {0,...,15}, parity followed by arbitrary repeated floor-halving eventually exposes every binary digit. Three strict refinement passes separate all 16 states. Parity alone is exact today but insufficient for the declared future.

This compiler enumerates a **public mathematical model**. It is not intended to enumerate secret ciphertext values or choose a secret-dependent execution schedule.

## 5. Verification and implementation boundary

`python3 -m unittest discover -s reference -v` executes 15 tests. Independent oracles enumerate anchors, candidate subsets, signed periods and all partitions of four states; they also exercise certificate tampering, missing producers, nonclosed models and invalid inputs. [Independent review](REVIEW.md) adds randomized factorization/subset oracles. [Evidence](evidence/verification.json) records source hashes and executed commands.

The Lean packet proves universal readout and dynamic closure statements. The Python planner and finite compiler have written proofs plus finite execution evidence; their source code has not been formally refined to Lean. The next integration is a typed public planning adapter in NINE65, with real producer identities, operation semantics, cost/noise bounds and permitted residue-native consumers. No new ciphertext decoder or synthetic source emission is supplied by these prototypes.
