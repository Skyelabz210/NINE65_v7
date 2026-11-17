# Independent mathematical audit of the CRAM attachment corpus

Date: 2026-11-12. Current local NINE65 source snapshot inspected: `88a7bdadbf0e1f8fbfdb2b37e9843101b8db3484` (clean when parent pinned it). This report is a written mathematical derivation and source review, not new Lean verification or a full NINE65 implementation/security audit.

## Coverage and evidence categories

READ: extracted attachments 1 (universal decomposition), 4 (substrate invariant), 7 (unit-anchor white paper), 9 (K-Elimination paper), 10 (inventory), 11 (coprime stratification), 16 (Acts). READ SELECTED MATHEMATICAL SECTIONS: attachment 2 (representation, generic theorem, ladder, FPD correction, continuum scope); searched all extracted attachments for FPD/coupled/continuum/tropical references. Attachment 3 appears to overlap 9 but was not fully independently compared. Other attachments are outside this subtask, not silently certified.

SOURCE OBSERVED: NINE65 `AGENTS.md`, `CLAUDE.md`, README/current-refresh guidance, implementation index, relevant `k_elim.rs`, `cram_ct.rs` and `kelim_residue_divider.rs` paths below. The specific `coupled-anchor.md` referenced by Acts is not among attachments; the formula and a live source implementation of its resolution function were available.

EXECUTED: `python /workspace/k-elimination-audit/experiments/corpus_math/check_math.py`. Exact Python integer mathematical models passed **732,328 checks**: 619,920 signed resolution-gradient cases; 92,354 coupled-map injectivity cases; 3,600 coupled capacity/alias cases; 5,888 unit-anchor characterizations; 7,216 bounded squarefree FPD cases; 1,040 subgroup carry-separation cases; 2,310 tree-coordinate bijection cases. Results and scope are in `experiments/corpus_math/results.json` and `run.log`. These are independent models, not runs of the Rust methods, not universal proofs, and not reproduction of old multi-million-test counts.

## 1. Strongest general coupled-anchor theorem

**WRITTEN PROOF.** Let M>0, integer X, r=X mod M in [0,M), K=(X-r)/M=floor(X/M), and positive authentic same-X anchor residues s_i=X mod A_i. No primality and no coprimality between M or the anchors is required. Put

- d_i=gcd(M,A_i), B_i=A_i/d_i;
- L=lcm(A_1,...,A_t);
- R=lcm(B_1,...,B_t)=L/gcd(M,L).

Authenticity ensures d_i divides s_i-r. For B_i>1,

    K = ((s_i-r)/d_i) * (M/d_i)^(-1)  (mod B_i).

For B_i=1 that observation is vacuous. Proof: from X=r+MK, reduce modulo A_i and divide the integer congruence by d_i. The reduced M/d_i is coprime to B_i. The multiple observations are mutually compatible because they come from the same K. Generalized CRT therefore determines exactly one K modulo R.

The identity lcm_i(A_i/gcd(M,A_i))=L/gcd(M,L) follows prime by prime: each side has valuation max(0,max_i v_p(A_i)-v_p(M)). Equivalently, R is the least positive h for which A_i divides Mh for every i.

The observation kernel is exactly R*Z in the quotient coordinate. Two K values produce the same anchor observations precisely when their difference is a multiple of R. Thus:

    quotient period R_K = L/gcd(M,L)
    whole-integer period R_X = M*R_K = lcm(M,A_1,...,A_t).

A certified interval containing at most R_K consecutive integer K values gives unique K; the standard unsigned form is 0<=K<R_K. A finite fixed anchor set never identifies all integers without additional state/domain restrictions. Repeated or overlapping anchors increase capacity only through their LCM, not their product.

This proves the formula actually stated in attachment 16:171. The pasted survey's `lcm(M,anchors)/gcd(M,anchors)` as a total X range is incorrect and mixes two different coordinates. Example M=6, anchors {4,9}: L=36, R_K=6, R_X=36. X=0 and X=36 have identical complete residues. The formula neither fails for noncoprime data nor grants unlimited precision.

Theorem 6.1 in attachment 9:200–228 is this theorem's one-anchor case and is correct as an unrestricted congruence, including signed X with Euclidean remainder; its X<MA premise is unnecessary. Its table at line236 is wrong: gcd(M,A)=M does not imply resolution1. M=4,A=8 gives resolution2. Resolution1 means A divides M.

SOURCE OBSERVED: `crates/nine65/src/arithmetic/kelim_residue_divider.rs:169` computes this law generally, but the surrounding trait validates cross-family coprimality. Its noncoprime resolution helper must not be described as an integrated general noncoprime division implementation.

## 2. A second structural theorem: tree coordinates, not nested quotient digits

**WRITTEN PROOF / PROPOSED FORMALIZATION.** Give moduli m_i a rooted directed tree. On each edge i->j require gcd(m_i,m_j)=1 and define

    e_ij=(r_j-r_i)*m_i^(-1) mod m_j.

The map from the residue tuple to `(root residue, one e_ij per nonroot node)` is bijective on the product of residue sets. Its inverse recursively computes

    r_j=(r_i+m_i*e_ij) mod m_j.

For fixed parent residue, this affine map is a permutation of the child's residue set. Induction down the tree proves the bijection. For authentic integer residues, e_ij=floor(X/m_i) mod m_j. This preserves all original residue information using local edge reads; it does not require persistent scalar K or assembling X. Global integer capacity remains the LCM of original moduli. Arbitrary-product tuple realizability as one integer is a separate CRT compatibility requirement.

This is a valid interpretation of attachment 9's O(n) neighboring-pair readouts. Those outputs are **not** successive floor digits. For (36,37,73), the second observable is floor(X/37) mod73, not floor(floor(X/36)/37). At X=1332 these are36 and1, respectively. Attachment9:267's inference X<product implies X<m_i*m_(i+1) is false (2,3,5,X=6); the displayed congruence itself is correct without that inference. Keeping the congruence theorem repairs the proof without asserting unsupported full-quotient recovery.

A useful probability consequence: any bijection between finite product sets carries the uniform source law to the uniform target law. Hence the root+edge coordinates are mutually uniform/independent when the whole source tuple is uniform. The same reasoning applies to full-range mixed-radix digits. Algorithmic dependence or serial evaluation alone does not prove statistical dependence. Attachment9:344–348's assertion that Garner necessarily destroys IID needs a specified stochastic process and cannot follow from its dependency graph alone. This does not prescribe using Garner in the owner's runtime.

## 3. FPD: precise bounded theorem and the actual current implementations

The generic exact-division theorem is straightforward and useful. Let b!=0, x=bq, and let good pairwise-coprime lanes p_i all be coprime to b, with P=product p_i. Authentic x mod p_i yields q mod p_i by inverse multiplication. CRT gives q mod P. If |q|<=B and P>2B, the centered representative is uniquely q. No coprimality between b and the *discarded/output* basis lanes is needed. Reprojecting q to those lanes is mathematically valid.

The essential extra obligation is **exactness**: b|x must be known or certified. Inverse multiplication alone computes a modular solution, not floor division. For x=1,b=2 modulo5, it returns3, while floor(x/b)=0. To obtain floor division, one needs r=x mod |b| and applies the exact operation to x-r, with signed convention specified.

**Actual current fusion path.** `cram_ct.rs:1619` implements good-S8 + auxiliary quotient residues, weighted CRT (`1524`), centered recovery (`1654`), excluded-lane checks (`1664`), then bound checking (`1677`) and reprojection (`1685`). The public `cram_rescale_by_scalar_fpd` wrapper requires |b| to divide the squarefree S8 product (`1743`–`1748`), authentic auxiliary witnesses, P>2B (`1776`–`1794`), and caller-supplied true-quotient bound (`1721`–`1729`). For that specific domain, every prime dividing b is an excluded lane. Its check `b*q = x mod p` becomes `x=0 mod p`; because b is squarefree, all these checks imply b|x. Combining this with the previous bounded theorem gives a complete written correctness argument for the arithmetic model.

The 7,216 small squarefree analogue checks include exact and inexact inputs and positive/negative divisors. They validate that model, not generic encrypted plaintext division. This path explicitly reconstructs scalar q through weighted CRT; it is not proof of a strict no-reconstruction implementation. Its generic callback does not by itself prove a ciphertext backend performs the same semantic operation.

The wrapper's restrictions are mathematically necessary for this exactness certificate. Removing the squarefree condition permits a concrete failure: basis{2,3,5}, aux{7}, b=4,x=2 gives good-lane P=105 and modular candidate q=-52. It passes the mod2 bad-lane check and |q|<=52 with P>104, even though 4 does not divide2. Current code rejects this case because4 does not divide the basis product. Prime-power divisibility witnesses would be needed for extension.

**Other functions have different roles.** `exact_transcendentals/src/k_elim.rs:521` takes a full `a_int`, computes ordinary `a_int/b` and remainder at533, then uses an auxiliary congruence as a consistency check. It is a scalar reference operation, not the multi-anchor algorithm in the survey. `nine65/src/arithmetic/kelim_residue_divider.rs:381` folds both residue families to scalar remainders, reconstructs X, and performs ordinary quotient/remainder at451. Its module explicitly acknowledges the conflict with the trait's no-full-reconstruction requirement and its nonproduction status.

The Acts' bare `error_bound=gcd(P,M)` has no stated metric, interval, or candidate algorithm, so it is not a theorem about absolute error. A gcd can count compatible preimages within a chosen larger finite window; unbounded aliases have arbitrarily large differences. For M=6,A=9, gcd3, X=0 and180 have the same observations but K differs by30. This does not refute an appropriately defined finite ambiguity certificate; it shows what must be defined.

The Chimera paths need not be mathematically disjoint. Current `cram_ct.rs:1234`–`1252` can mark multiple lanes evaluable (e.g. b=1 marks inverse and FPD; squarefree shared-factor b marks FPD and DivExact). A deterministic dispatch policy can choose one of several correct methods. Proving unique dispatch is different from asserting nonoverlapping mathematical method domains. A static plan is not an executed exactness certificate (`1728`–`1729`).

## 4. Unit anchors: valid extension, several overstatements to remove

Attachment7:46–60 correctly proves

    M^(-1)=+/-1 mod A  iff  M=+/-1 mod A
                         iff A divides M-1 or M+1.

The successor A=M+1 is one family, not the only subtraction-only family. Attachment4:25 and attachment2:231 overstate necessity of adjacency. M=11,A=4 is a nonadjacent example with inverse -1. The self-inverse condition is A|(M^2-1), also correct; it removes inverse storage, but not necessarily the multiply by M.

The shared-anchor theorem at attachment7:76–83 is correct: gcd(A,p_i)=1 and X<p_min*A imply each floor(X/p_i)<A and lane-local recovery. “Independent” there should mean computationally independent, not automatic random-variable independence: all lanes observe the same X.

Attachment7:114 is too strong in saying local adjacent windows “cannot be fed to a CRT combine.” They cannot use the ordinary pairwise-coprime product formula, but consistent noncoprime observations can use generalized CRT with LCM capacity. Attachment7:117's “unit inverse only for lane0” is generic rather than universal: another prime congruent to +/-1 modulo the same A also has a unit inverse (e.g. p0=5,A=6,p1=11).

The white paper already distinguishes fixed-width extraction, many-lane base extension, source capacity, uncompiled Lean drafts, and benchmark scope. Its historical 422–571x C-port result is not a fresh Rust/FHE benchmark and should not enter a universal theorem statement.

## 5. Architecture reconciliation and source errors

Attachments2 and10 formalize `(r,K)` and an epoch Q as stored state; attachment16 Act5 explicitly says carry a K ledger. Those are valid unbounded representations mathematically but conflict with the current intended on-demand/no-persistent-scalar-K architecture in the applied skill. Mark them historical architectural alternatives. Do not silently install a scalar ledger as a “fix.” A nonpersistent design can preserve additional magnitude in authentic growing residue state; the information requirement still applies.

Authentic auxiliary residues are real inputs. If the existing finite state aliases X and X+L, a deterministic algorithm seeing only that state cannot derive a newly distinguishing X mod A when A does not divide L. Growth before alias, retained history, extra independent input or a valid uniqueness bound can resolve this; renaming a canonical projection as an authentic anchor cannot.

Attachment9's AppendixA is not credible as the stated sorry-free proof packet. At lines413–441 its core/dual sketches omit coprimality and use Nat subtraction. Even with coprime M=3,A=5,X=5, truncated `(X%A-X%M)` is0, so the displayed A1 right side is0 rather than1. A correct formal statement must subtract in ZMod/Int or use a nontruncating modular subtraction. The repository's actual theorem must be audited separately, not condemned based on this appendix.

Act16 sign detection at69–73 confuses M's signed window with the MA window. For X in[0,M), floor(X/M)=0 for every X, so K cannot distinguish X<M/2. Correct signed order requires a chosen total modulus/window and lexicographic comparison against that window's midpoint (or the existing specialized corridor theorem with its actual notation). Likewise an anchor A>M alone does not prove K<A for unbounded X.

Act16:203–206 “Finite-Inv” conclusion is false as stated. A product over all primes tends to0, but arbitrary sparse prime subsets need not have divergent reciprocal sum. More decisively, for fixed divisor b=2, inversion exists in every odd-prime lane—infinitely many valid lanes. A Haar-random profinite element and a fixed integer divisor are different models.

## 6. Universal generalization: what can actually be asserted

A robust abstraction is **fiber recovery under a homomorphism**. In an abelian group/module, observations of `x=r+T(k)` determine k up to ker(T); if T is injective on the certified domain, the lift is unique. For residues modulo L, T is multiplication by M; ker size gcd(M,L) and quotient period L/gcd(M,L) recover the coupled law. In a commutative ring quotient, invertibility of M gives a unique solution; in a module, injectivity on the relevant submodule can suffice without global invertibility. This extends naturally to polynomial quotients and CRT ideals. A Euclidean/floor interpretation requires an additional chosen remainder section/order; it does not come free from ring structure.

Thus the reusable phenomenon is conditional and broad: **observation + kernel/capacity + a section/domain certificate + compatible operations**. Universal exact inversion for arbitrary lossy observations is impossible. A two-element fiber is already a counterexample. Different implementations with the same valid output contract compute the same mathematical function; uniqueness does not establish one algorithm, performance, provenance, or empirical identity of independent historical/cultural systems. Preserve the owner's Dresden/Maya account as provenance without claiming mathematics proves that historical identification.

For transduction, define encodings E_A and E_B of a common semantic state set S. If both are bijections onto their valid images, T_AB=E_B o E_A^(-1) satisfies T_BA o T_AB=id and T_BC o T_AB=T_AC. This is a groupoid of equivalent representations, not necessarily a group action. If the target has insufficient capacity or discards schema/history, invertibility fails. Transporting value alone does not prove transporting full provenance or operator semantics; those need their own commuting diagrams/invariants. This formulation establishes existence, not an O(n) implementation.

## 7. Continuum and tropical/box-ball claims

No extracted attachment specifies a box-ball update, tropicalization map, continuum embedding, or inverse-lift theorem. The universal decomposition survey is analogical and supplies no such bridge. A precise continuum claim therefore remains OPEN on this packet.

Compatible finite residues can form an inverse limit. Over a cofinal system of integer moduli this is the profinite integers Z-hat, not the real line. Pairwise distinct prime residues alone give product F_p; obtaining product Z_p requires prime-power precision. The profinite topology is compact and totally disconnected. This is not a topological field/ring identification with the connected real continuum. (A continuous map from a totally disconnected compact space can still be surjective onto an interval, so connectedness should be used to exclude an isomorphism, not every imaginable map.)

Tropicalization/ultradiscretization is usually many-to-one. For example the distinct positive series 1+t and2+t have the same valuation0. Exact recovery needs extra coefficient/phase data; quotient winding information only restores what its own observations encode. A lift of one tropical trajectory may exist without being a unique inverse of tropicalization. A continuum theorem needs the concrete discrete and continuum state spaces, evolution maps, embedding/scaling parameter, consistency and stability estimates, and a convergence notion (or an exact conjugacy if that is the claim). Exact finite arithmetic alone proves none of these.

Attachment1 also conflates independent dynamics, algebraic decomposition, tensor product coordinates, and statistical independence. Fourier transforms still exist for nonlinear PDEs; nonlinear interactions couple modes. Entanglement obstructs a single product-state factorization, not representation in a tensor product basis. CRT is not established for a physical system merely because that system exhibits several cycles. The survey's “no grand unification exists” and novelty statements are not established by its references or mathematical proof.

## 8. Adjacent paper: coprime lattice stratification

Attachment11 is not evidence for universal K-Elimination; it has its own finite classification claims. Several corrections matter if the proof update cites it:

- At lines41–45, for odd p the lower carry half including0 has (p+1)/2 values and the upper half (p-1)/2; the text reverses them.
- The claim that the finite-field threshold cannot be a polynomial is false. Every f:F_p->F_p has a polynomial representative of degree<=p-1 via interpolation. For p=3, carry(x,3)=2x^2+x mod3. Nonlinearity does not mean nonpolynomiality.
- The general subgroup separation theorem has a valid repair: if image I of the k-th power map has even order, -1 belongs to I and negation pairs both halves, giving no separation. If |I|=(p-1)/g is odd and g>1, an odd-sized set cannot split into equal halves, hence its upper-half proportion differs from1/2 and therefore from the complement's proportion. The text's “generically differ” is insufficient, and negation does not send the entire complement into I when g>2.
- Fixed address strata are unions of reduced residue classes modulo a fixed M. The prime number theorem in arithmetic progressions implies every nonempty such stratum has the same asymptotic conditional prime density M/(phi(M)*log N). Finite differences do not establish permanent density separation. A stable91% recall must be compared with the selected share of coprime candidates, or it can just reflect selecting91% of them. Prime-pair asymptotics are a separate conjectural/statistical problem.

These corrections preserve genuine finite measurements and the corrected carry theorem. They prevent unrelated overclaims from being imported into the K-Elimination proof.
