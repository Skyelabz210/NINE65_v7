# Mathematical audit of the uploaded tropical FHE report

Date: 12 November 2026. New input: **CRAM, NINE65 and Tropical FHE**, dated 25 October 2026, supplied as `Untitled.docx`; extracted text is `extracted/20-Tropical_FHE_Untitled.txt`. The paragraph/line citations below refer to that extraction. The document names repository snapshot `bbfa754`; this audit inspects the existing clean checkout at `88a7bdadbf0e1f8fbfdb2b37e9843101b8db3484`.

This bounded review covers the mathematical Holte, finite-function, valuation and fiber claims. It does not certify FHE confidentiality or replicate the missing original Rust programs `holte.rs` and `trop.rs`. Those filenames are mentioned at lines 10 and 126, but neither was attached with the DOCX or found under those names in the checkout. Independent checks below use newly written exact Python models and the current repository's existing Holte checker.

## 1. The Holte reversibility question is resolved in the later source

**SOURCE OBSERVED / PROVED under the stated model:** the current repository's `docs/execution/2026-10-27/HOLTE_REVERSIBILITY.md` supplies an ordinary all-arity, all-base proof that the standard carries chain is reversible exactly for n<=3. Thus the new document's lines 120 and 124, saying a general proof is still owed, are superseded by later source evidence. This is a written proof, not a Lean/Coq certificate.

The model is essential. For independent uniform base-M digits D[t,r] in {0,...,M-1}, n>=1 and M>=2,

    C[t+1] = floor((C[t] + sum_r D[t,r])/M),
    P[i,j] = T[i,j]/M^n,        i,j in {0,...,n-1}.

The driving digits are IID. The carry states need not be IID, even at stationarity and even when the chain is reversible. At n=2,M=36, pi(0)=1/2 but P[0,0]=37/72. The document's distinction between deterministic BBS and stochastic Holte dynamics is appropriate.

The stationary law pi(j)=A(n,j)/n! is the Eulerian law. A direct stationarity argument is available: take independent uniforms U_r in [0,1), write M U_r=D_r+W_r, and let C=floor(sum W_r). The D_r are independent uniform digits, independent of the W_r. Then

    floor((C+sum D_r)/M) = floor(sum U_r),

which has the same Eulerian distribution as C. The Eulerian weights are the volumes of the slices j<=sum U_r<j+1 of the unit cube. This mathematical argument does not prescribe floating-point runtime computation. Uniqueness follows from irreducibility: k transitions are equivalent to one base-M^k step; when M^k>=n every transition count is positive.

The all-arity obstruction is one corner. Inclusion-exclusion gives

    T[0,1] = binom(2M+n-1,n) - (n+1)binom(M+n-1,n),
    T[1,0] = binom(M+n-2,n).

Define Delta=T[0,1]-(2^n-n-1)T[1,0]. Since A(n,0)=1 and A(n,1)=2^n-n-1, the signed stationary flux is Delta/(n! M^n). Put t=M-1, B_n=binom(M+n-2,n), R_n=binom(2M+n-1,n)/B_n, and H_n=2^n+n(n+1)/t. Then

    Delta/B_n = R_n-H_n,
    R_3=H_3,
    R_(n+1)=R_n f_n,    f_n=(2t+n+2)/(t+n)>0,
    H_(n+1)-H_n f_n=(n-2)(2^n-n-1)/(t+n)>0  for n>=3.

Induction gives Delta<0 for every n>=4,M>=2. At n=1 there is one state. At n=2 the transition matrix is symmetric with stationary law (1,1)/2. The explicit n=3 matrix in the repository, lines 177–186, has symmetric Eulerian-weighted matrix with weights (1,4,1)/6. This proves both directions. At n=4,M=2 the weighted integer counts are indeed 10 and 11, as the uploaded report states.

The theorem does **not** follow for heterogeneous residue lanes merely because each lane is uniform. For example, two independent digits drawn respectively from {0,1} and {0,1,2}, with carry base 3, give transition matrix [[5/6,1/6],[1/2,1/2]] and stationary law (3/4,1/4), not the two-summand Eulerian law (1/2,1/2). Applying Holte to CRAM therefore requires the actual common-base driving-digit model.

**EXECUTED:** the current `scripts/check_holte_reversibility.py` passed 144 transition-DP cases, 1,914 arbitrary-precision formula cases, Newton rows through n=30, and 539 centered-chart states. Raw output: [holte-existing-run.json](../experiments/tropical_paper_math/holte-existing-run.json). A new independent inclusion-exclusion model also reproduced the uploaded document's entire n=1..8,M=2..24 grid (184 cases), and checked 15 small transition matrices by exhaustive digit-word enumeration.

## 2. Finite integer lane maps do have tropical-rational extensions

**PROVED:** for any integer values f(0),...,f(N), define d_i=f(i+1)-f(i), delta_j=d_j-d_(j-1), and h_j(x)=max(0,x-j). Their continuous linear interpolant is

    F(x)=f(0)+d_0 x + sum_(j=1)^(N-1) delta_j h_j(x).

Split each coefficient into positive and negative parts:

    P_+(x)=f(0)+max(d_0,0)x + sum max(delta_j,0)h_j(x),
    P_-(x)=max(-d_0,0)x + sum max(-delta_j,0)h_j(x).

Then F=P_+-P_-. Both P_+ and P_- are convex piecewise-linear functions with nonnegative integer slopes, hence tropical polynomials in the max-plus convention. This proves the finite-lane claim under the usual integer-exponent definition, without any special property of K-Elimination. It supplies an extension from the finite domain; it is not a canonical homomorphism of the residue field into the tropical semiring. Its representation cost can grow with the number of lane values.

An arbitrary real-weight ReLU network needs a qualification absent from line 8. With ordinary integer-exponent tropical polynomials, all slopes of their difference are integral where differentiable. The real-weight network sqrt(2)*ReLU(x) therefore cannot be such a tropical rational function. Integer-weight ReLU networks fit the ordinary class; general real weights require generalized tropical polynomials allowing real slopes. The parent analysis checks the cited literature's conventions; this counterexample establishes the mathematical distinction directly.

The number of equal-increment runs also depends on conventions. With the stated consecutive-increment metric, adding a shift b=3 modulo 11 gives values

    3,4,5,6,7,8,9,10,0,1,2

and increments 1,...,1,-10,1,1: **three runs**, not two. Shift b=1 has two; b=0 has one. Thus the table's `add b: 2` cannot be a statement about every b. Two affine branches of a discontinuous modular sawtooth are a different metric from runs in its continuous linear interpolation. The inverse map additionally needs a convention at zero; the checks here extend inverse(0)=0 explicitly.

**EXECUTED:** 3,752 interpolation values passed over seven maps and eight primes from 11 to 257. Under the stated conventions, multiplication by 3 had five runs, multiplication by floor(p/2) had p-2, and square and zero-extended inverse had p-1. These counts are finite checks, not a minimal encrypted-circuit complexity bound.

## 3. Valuation gives a tropical invariant, with two necessary limits

The valuation identities at lines 26 and 86 are correct:

    v_p(xy)=v_p(x)+v_p(y),
    v_p(x+y)>=min(v_p(x),v_p(y)),

with v_p(0)=infinity and equality in the second formula when valuations differ. However, they do not make v_p an ordinary semiring homomorphism from integer addition to min for all inputs. For p=3,x=1,y=2,

    v_3(x)=v_3(y)=0,  but v_3(x+y)=1.

Equal-valuation terms can cancel. A valued-ring filtration, initial forms/leading coefficients, or a tropical hyperaddition formalism describes that behavior; silently replacing the inequality by equality loses information.

A mod-p lane also does not supply a full p-adic valuation. The integers p and p^2 have the same residue zero modulo p and valuations 1 and 2. More generally a mod-p^e observation determines v_p(x) exactly only if x is nonzero modulo p^e, in which case v_p(x)<e. A zero observation gives the lower bound v_p(x)>=e. Calling a lane a “p-adic place” is acceptable as an indexing interpretation, but it is not an observation of the full p-adic completion or valuation. Compatible higher prime-power observations add precision and must actually be available.

Likewise, if a fiber has size p^k, then k=v_p(|fiber|) by definition. That does not identify k with v_p(the source value), or with the source's Euclidean winding, without a theorem linking the particular fiber map to a p-adic filtration.

There is still a constructive direction here: enrich a valuation with leading unit/coefficient information and a certified precision. The current repository's separate G/H lift construction, pointed out in the companion source review, does precisely more than retaining valuation alone: G(x)/p modulo p contains K*G'(rho), and the unit factor can be canceled. That identity's domain and source bindings belong to its own proof; the valuation inequality alone does not establish it.

**EXECUTED:** all product and sum laws passed for six primes and 99,846 signed pairs per law, including zero via an exact infinity sentinel; 34,000 unequal-valuation cases satisfied equality. The cancellation and finite-precision counterexamples are retained in [paper-math-checks.json](../experiments/tropical_paper_math/paper-math-checks.json). These are fresh checks of the algebra, not reproduction of the missing Rust program's claimed 955,206-pair ranges.

## 4. Quantizer fibers and entropy

For integers 1<=t<=Q and c in {0,...,Q-1}, set f_t(c)=floor(tc/Q). For y=0,...,t-1, the fiber is the contiguous integer interval

    ceil(yQ/t) <= c <= ceil((y+1)Q/t)-1,

of size n_y=ceil((y+1)Q/t)-ceil(yQ/t). These sizes are floor(Q/t) or ceil(Q/t). The uploaded document's correction of the stride-t interpretation is valid.

For **uniform scalar C**, the exact conditional entropy is

    H(C | f_t(C)) = sum_y (n_y/Q) log2(n_y).

It equals log2(Q/t) exactly when t divides Q, because that is precisely when the output is uniform over all t outputs. For Q=5,t=2 the fibers have sizes 3 and 2, and the entropy is (3 log2(3)+2 log2(2))/5.

The line-106 two-component value 2 log2(Q/t) additionally needs an independent uniform joint model for the two inputs, or a separate proof that the actual conditional joint distribution has that entropy. The scalar fiber theorem alone establishes no such model for RLWE ciphertext components, especially conditioned on a message, key, or retained side information. A secret-dependent convolution carry is correctly distinguished from one scalar quantizer's fiber coordinate, but this does not by itself prove the asserted exact entropy of a cryptographic transformation.

The stated bound |K|<=4096 allows 8,193 integer values. “About 13 bits” is a fair entropy-scale description, but an unrestricted fixed-length encoding of all these values needs 14 bits. Whether both endpoints are reachable depends on the precise producer and tie convention.

The Landauer correction is appropriate: information erasure yields a lower bound under a specified physical model; equality is not guaranteed by an algebraic entropy count. Retained side information and memory reset operations must be specified. The document's statements about the unnamed full Welds 4 and 5 cannot be independently verified from this excerpt, which does not reproduce their propositions.

**EXECUTED:** 3,239 (Q,t) pairs through Q=80 satisfied the exact fiber formula and uniformity criterion; 88,559 individual fibers were checked contiguous.

## 5. Carry hinges, box-ball recurrence, and chart boundaries

For integers p>=2 and 0<=v<p, the displayed hinge formula is exactly the doubling carry:

    floor(2v/p)=min(1,max(0,2v-p+1)).

This follows by splitting v<ceil(p/2) and v>=ceil(p/2). It is a useful bounded scalar identity; using it under encryption still requires its max/min implementation.

For a binary box occupancy u in {0,1} and nonnegative incoming carrier C, the infinite-capacity BBS local rule is

    u'=min(1-u,C),       C'=C+u-u'.

The carrier update and boundary condition are essential. This formula is precisely the elementary pickup/deposit rule, but alone is not an equivalence of arbitrary periodic BBS trajectories, Holte chains, and CRAM operations. The positive finite checks here use an initially empty carrier and an empty tail long enough to discharge every ball.

**EXECUTED:** all 2,000,999 doubling-carry states for p=2..2000 passed; 2,046 binary input words of lengths 1..10 passed their full flushed BBS evolution, with 27,651 checked local steps.

For odd integral Q, g=(Q-1)/2 is the **last integral point before** the real theta-cell wall, not the wall itself. The analytic wall is g=Q/2. The next increment g+1 crosses it, explaining the boundary bit in the discrete theta difference. Line 49 should use that distinction. The earlier report already establishes the rank-one theta identity with the strict open-cell assumption.

## Reproduction and disposition

Commands executed:

```sh
python3 /workspace/NINE65_v7/scripts/check_holte_reversibility.py
python3 /workspace/k-elimination-audit/experiments/tropical_paper_math/check_paper_math.py
```

The first output is saved as `holte-existing-run.json`; the second as `independent-run.log` and `paper-math-checks.json` in the owned experiment directory. The current repository remained clean. No existing historical evidence was rewritten. The results support several concrete bridges while narrowing the claims about valuation, general ReLU weights, entropy and lane complexity. The missing original Rust files and unquoted Weld statements remain a reproducibility/source limit, not evidence that the verified mathematical identities fail.
