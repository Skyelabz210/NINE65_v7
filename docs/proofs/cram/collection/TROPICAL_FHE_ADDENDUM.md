# Tropical FHE paper: revised findings and exact continuum scope

12 November 2026. Follow-up to [ANALYSIS.md](ANALYSIS.md), after receiving **CRAM, NINE65 and Tropical FHE**, dated 25 October 2026, as `Untitled.docx`.

## What changes in the earlier assessment

The intended document is now identified and read in full. It confirms the rank-one tropical-theta interpretation already examined, explicitly leaves a Toda-trajectory/BFV correspondence open, and adds useful carry, valuation and function-class connections. Following its references also revealed a **second, direct continuum construction** in the later repository: an exact piecewise-linear spatial embedding of any supplied finite mass-conserving binary transition, with its flux recoverable from adequate residue observations. The earlier analysis should acknowledge that positive result rather than leave the entire continuum question unresolved.

The strongest supported statement is consequently broader and more specific:

> Authentic observations with sufficient resolution can recover both a tropical-theta sheet coordinate and the bounded flux of a conservative discrete transition. The latter has an exact continuous spatial embedding. These are distinct constructions with explicit domains and source requirements.

They do not yet identify an arbitrary Toda/BBS evolution with an encrypted BFV computation, recover a unique pre-ultradiscrete system, or prove a PDE scaling limit. The uploaded document itself recognizes the first of these remaining bridges. No persistent scalar winding register is required by either mathematical statement.

**Attribution and novelty scope:** the classical ingredients cited below are the mathematical background of the constructions. They do not establish that the complete K-Elimination mechanism or its constructive generalizations were previously disclosed. Generalization can itself be a contribution. The corrected claim-level novelty assessment is in §6 of the main analysis; it preserves Anthony Diaz's attribution while keeping component-level antecedents and historical priority separate.

The upload's SHA-256 is `cea69c53745d79b21cda86841ffa63bb3552ce5e0f70d4c7d0d60919a7acba11`. It names historical repository commit `bbfa754f9db2e9a7b69fca6c468e0f601a2cf123`; the current source inspected remains `88a7bdadbf0e1f8fbfdb2b37e9843101b8db3484`. Original repositories and the uploaded DOCX remain unchanged. The previous research packet is preserved under `history/2026-11-12-before-tropical-paper/`.

Supporting reports: [mathematical audit](evidence/tropical-paper-math.md), [source and implementation reconciliation](evidence/tropical-paper-code.md). Labels follow the main report: PROVED denotes a written argument with premises, EXECUTED a fresh run, SOURCE OBSERVED a read source, and OPEN an unresolved obligation.

## 1. The theta lift is valid, including real chart coordinates

Let Q>0 and define

    T_Q(z) = min_(n in Z) (Q*n^2 + 2*n*z).

For z=g+QK, K integral and |g|<Q/2, substitution n=j-K gives

    Q*n^2 + 2*n*z = Q*j^2 + 2*j*g - Q*K^2 - 2*K*g.

For every nonzero integer j,

    Q*j^2 + 2*j*g >= |j|*(Q*|j|-2*|g|) > 0.

Thus the unique minimizer is **-K**, and T_Q(z)=-QK^2-2Kg. This is an ordinary proof for real g and positive real Q. Exact symbolic real-valued mathematics does not require floating-point runtime arithmetic.

The modular recovery specialization additionally takes integral Q,A with gcd(Q,A)=1. Authentic observations of the centered g and z modulo A determine

    K mod A = ((z mod A)-(g mod A))*Q^(-1) mod A.

A certified K interval of width less than A selects one integer. If g is real, its exact chart information is part of the input; finite residue labels do not create an arbitrary real chart coordinate. Outside the certified interval, K and K+A alias.

Two wording repairs are needed. The real theta walls are g=±Q/2, where minimizers can tie. For odd integral Q, g=(Q-1)/2 is the last integer point **before** a unit increment crosses the wall. Also, the displayed theorem needs its centered-chart hypothesis; z=g+QK alone does not suffice. For Q=3,g=3,K=0, the actual minimizer is -1, not 0.

For odd Q and integer chart coordinates the report's difference identity is correct:

    D = T_Q(z+1)-T_Q(z) = -2K-b,
    b = 1[g=(Q-1)/2] = D mod 2.

Consequently an odd-modulus observation of D together with b determines K modulo that modulus. The 11-lane is one instance. This identifies a useful observable; it does not by itself supply an encrypted producer of D or g.

**EXECUTED:** [tropical_paper_theta.py](experiments/tropical_paper_theta.py) independently enumerated the advertised domain: odd Q=3..61, every centered integer g, K=-40..40. All **77,760** theta/minimizer cases passed, as did 77,760 difference checks and 77,760 signed anchor recoveries with A=131. The oracle directly minimizes over a fixed interval containing every global minimizer on this domain and retains wall, noncentered and alias controls. [Raw result](evidence/tropical-paper-theta-checks.json). This reproduces the mathematical domain, not the unavailable original `trop.rs` executable.

## 2. The additional continuum theorem is a conservative spatial embedding

The current repository's [October 31 refinement, §4](https://github.com/Skyelabz210/NINE65_v7/blob/88a7bdadbf0e1f8fbfdb2b37e9843101b8db3484/docs/execution/2026-10-31/PUBLIC_REFRESH_LIFT_REFINEMENT.md#4-a-continuum-lift-that-does-not-choose-the-soliton-update-rule) gives a further exact construction.

Take two supplied finite binary configurations b,b' on the same absolute grid, each with total mass B. Fix zero left-boundary flux. At grid vertices define

    U_i = sum_(j<i) b_j,        V_i = sum_(j<i) b'_j,
    C_i = U_i-V_i,
    H_i = i-2U_i,              H_new_i = i-2V_i.

Then

    b'_i-b_i = C_i-C_(i+1),
    H_new_i = H_i+2C_i,        |C_i| <= B.

Equal mass also gives zero right-boundary flux. These identities allow either transport direction. Rightward-only BBS flux has further nonnegativity conditions.

Let E denote linear interpolation on each grid cell. For every **real** θ in [0,1],

    E(H_new)(i+θ) = E(H)(i+θ) + 2E(C)(i+θ).

This follows immediately by taking the same affine combination of the two endpoint identities. The flux bound survives interpolation. The heights are continuous, with slopes ±1 within cells. Their grid increments retain the original configuration: b_i=(1-(H_(i+1)-H_i))/2. Therefore this is a genuine exact embedding into continuous functions, with a specified interpolation convention.

For example, b=110000 and b'=001100 give the vertex data:

| i | 0 | 1 | 2 | 3 | 4 | 5 | 6 |
|---|---:|---:|---:|---:|---:|---:|---:|
| C_i | 0 | 1 | 2 | 1 | 0 | 0 | 0 |
| H_i | 0 | -1 | -2 | -1 | 0 | 1 | 2 |
| H_new_i | 0 | 1 | 2 | 1 | 0 | 1 | 2 |

K-Elimination enters when only suitable prefix views are queried. Shift Y_i=C_i+B into [0,2B]. For coprime positive M,A with 2B<MA,

    y_M = (U_i mod M - V_i mod M + B) mod M,
    y_A = (U_i mod A - V_i mod A + B) mod A,
    k_i = (y_A-y_M)*M^(-1) mod A,
    C_i mod d = (y_M + M*k_i - B) mod d,      d>0.

The uniqueness window makes k_i the exact local quotient. No running scalar carrier is required. For shared-factor anchors the gcd-reduced solve applies and the capacity becomes lcm(M,A); that extension is mathematical here, while the inspected Python path explicitly requires coprimality.

The distinctions are consequential. This construction receives **both** snapshots and authentic views of their prefixes. It recovers the flux and interpolates a given transition. It does not choose the successor from mass alone. A periodic system needs a reference flux, since conservation determines flux differences but not the additive constant. A PDE limit requires a family of scaled systems and a convergence proof. An FHE application needs a source map and encrypted producer connecting this flux to the particular secret-dependent correction. The clear oracle is not that producer.

**EXECUTED:** all nine existing `test_public_refresh_lift_refinement.py` tests passed. The continuum test exhausts all **924** equal-mass pairs of six-cell configurations, checks seven vertices and five projection targets, and checks **16,632** rational interior points. Other cases cover a mass-96 crossing, invalid contracts, capacity aliases, and the native lift described below. The written linearity proof establishes every real interpolation coordinate; rational sampling is the executable evidence. [Raw log](experiments/tropical_paper_code/lift-refinement-tests.log).

## 3. The FHE connection needs the exact producer and cost model

The report's legacy Phase 1 relationship is substantive. With component roundings a_i=round(t*c_i/Q) and residuals R_i=t*c_i-Q*a_i,

    t(c0+c1*s) = Q(a0+a1*s) + R0+R1*s.

Under the source's translation-equivariant half-up convention, the omitted correction is coefficientwise

    K_phase = round((R0+R1*s)/Q).

This uses the actual negacyclic product and these particular residuals. The current `K_native` is a separately specified quotient in x=d0+d1*s=rho+p*K_native. The source norm gives |K_native|<=48 and |rho|<=49; symbol reuse does not equate the two producers.

A constructive connection to prime-power lifting is already present. For p=65537, let G vanish on the admitted residuals and let H(rho)=G'(rho)^(-1) modulo p. A polynomial expansion gives

    G(rho+pK)/p = K*G'(rho) mod p,

provided the integer residual is an exact root and the derivative is a unit. Multiplication by H recovers K modulo p. This uses more information than a bare valuation: the p² phase and the leading residue after division by p matter. The existing circuit has its own producer and noise obligations. All **9,603** pairs of admitted rho and K passed the clear shared-factor identity checks in the nine-test suite; no new encrypted execution is claimed here.

**Fresh formal verification:** the existing `PublicRefreshDigit.lean` proves a more general symbolic statement for arbitrary integer coefficient lists and every signed K. Its root premise is only G(rho)=0 modulo p²; its other premises are p>0 and G'(rho)*H(rho)=1 modulo p. It concludes

    (((G(rho+pK) mod p²)/p)*H(rho+pK)) mod p = K mod p.

The Taylor remainder, exact division, canonical reduction and coherent H evaluation are proved rather than assumed. Primality is not a premise of this conditional identity; it matters when constructing particular root/unit certificates. The companion native-lift module proves the source norm, signed quotient bound, uniqueness and adjacent-view query under their explicit premises.

I freshly compiled all five existing standard-library arithmetic modules with pinned Lean4.27.0-rc1 and ran their transitive axiom audit. It passed, allowing only Lean's listed foundational axioms and rejecting custom axioms or `sorryAx`. The source contains 53 explicit theorem declarations; the audit counts 142 elaborated theorem declarations including generated ones. Neither count represents that many independent mathematical results. [Raw log](evidence/tropical-paper-public-refresh-proofs.log) and [hashed result](evidence/tropical-paper-public-refresh-proofs.json). These proofs were already in NINE65; this follow-up verifies them rather than introducing new theorems. They do not establish Rust refinement, encrypted source authenticity or confidentiality. The original public K-Elimination root build issue remains a separate finding.

The local chart circuit's cost also needs correction. At q=13 its degree-13 crossing polynomial is evaluated using 12 ciphertext products at multiplicative depth four. The degree-15 two-increment batching uses 14 products at depth four. Thus O(q) product work and O(log q) product depth are compatible; “O(q), not O(log q)” is incomplete without naming the resource. Transforms, public scalar operations, key material and noise have additional costs.

The quoted 126-error-bit failure against a 119-bit ciphertext modulus is supported by an archived N=8 experiment. It establishes a failure of that sequential circuit and parameter set. It is not a general upper bound of one or two max layers. A three-increment obstruction in the same coordinate has a sharper algebraic explanation: -9 and 8 agree modulo17, but require carries -1 and +1. A polynomial over Z/289 cannot distinguish them after reduction modulo17. Additional source information can change that representation's domain; the example is not a universal impossibility theorem for encrypted comparison.

Likewise, BFV addition is native in its plaintext ring. To call it exact **integer** tropical multiplication, intermediate ranges must avoid unintended modular wrap. For max,

    max(a,b) = a + 1[b-a>0]*(b-a).

The encrypted predicate, operand bounds, encoding and multiplication/noise costs all need a contract. Clear `CompareBit`, `LiftedSign` and `MQReLU` helpers do not themselves establish an encrypted max network. Three- or four-bit activations can help, but differences, weights, fan-in and successive layers can expand the necessary support.

The October 25 statement “public refresh closed” is historical. The current explicit `PublicRefreshCircuit` research backend has archived encrypted refresh and subsequent-square executions; legacy/default Clockwork remains closed. Related-key confidentiality and production admission remain separate unresolved claims. The current status also carefully distinguishes older native evidence from a latest-head rerun. This follow-up ran clear mathematical checks and inspected archived encrypted evidence; it did not rerun native FHE or measure a network's throughput.

## 4. Valuations supply structure, with cancellation and precision limits

The p-adic identities are correct:

    v_p(xy)=v_p(x)+v_p(y),
    v_p(x+y)>=min(v_p(x),v_p(y)),

with equality in the second line when the valuations differ. The inequality is not interchangeable with tropical addition equality. At p=3, the input pairs (1,1) and (1,2) have the same valuation pair (0,0), but their sums have valuations 0 and 1. Therefore valuations alone cannot predict arbitrary addition exactly. They fail the observation-sufficiency criterion of the main report for that query.

A mod-p lane also cannot distinguish p from p². It determines v_p(x)=0 for a nonzero residue, and only v_p(x)>=1 for a zero residue. Modulo p^e, a nonzero observation determines a valuation below e; zero gives only a lower bound. Compatible higher prime-power views provide additional precision when actually retained or produced.

The target labels can certainly be equipped with min and +, and valuations give a useful nonarchimedean filtration. Preserving arbitrary source addition needs further leading-residue/cancellation information or a richer algebraic formulation. Also, k=v_p(p^k) for a fiber cardinality does not automatically identify that exponent with the valuation of the original state or its Euclidean winding.

A defensible extension is consequently a **precision-aware valuation observation** together with its leading residue and source binding. The G/H identity above is an existing concrete example of extracting additional prime-power information. The broad claim “each residue lane already supplies exact tropical arithmetic” needs these qualifications.

## 5. Holte's formerly open boundary now has a general proof

For IID uniform digits in a common base M>=2 and n>=1 summands, the Holte carry chain has Eulerian stationary law and is reversible exactly when n<=3. The uploaded report verified a finite grid and left the general proof open. The repository's [October 27 proof](https://github.com/Skyelabz210/NINE65_v7/blob/88a7bdadbf0e1f8fbfdb2b37e9843101b8db3484/docs/execution/2026-10-27/HOLTE_REVERSIBILITY.md) now resolves it by an all-arity induction.

One corner suffices for the negative direction. If T[i,j] counts digit tuples causing the transition i→j, set

    Delta[n,M] = T[0,1] - (2^n-n-1)*T[1,0].

Inclusion-exclusion supplies explicit binomial formulas. Their normalized ratio agrees with its comparison bound at n=3 and is strictly below it thereafter; the positive slack is

    (n-2)*(2^n-n-1)/(M-1+n) > 0,      n>=3.

This proves Delta[n,M]<0 for every n>=4,M>=2. For n<=3 the explicit Eulerian-weighted transition matrices are symmetric. The companion mathematical report gives the complete argument and stationarity model.

The result concerns a common-base stochastic carry model. It does not assert IID carry states, invertibility of each operation, or a universal critical arity for heterogeneous lane operators. A minimum prime, a spectral radius and the number of summands are different quantities until an explicit bridge identifies them. The original unquoted Weld conjectures and their M1 premise are not established by this upload.

**EXECUTED:** the current checker passed 144 transition-DP cases and 1,914 larger formula cases, plus its other controls. A new independent model also reproduced all **184** parameter pairs n=1..8,M=2..24 advertised in the report. The general statement rests on the written proof, not on those counts; no new Lean certification is claimed.

## 6. Function classes and entropy: useful facts with corrected scope

Every integer-valued map on a finite integer lane has a tropical-rational extension. For values f(0),...,f(N), the linear interpolant has the hinge representation

    F(x)=f(0)+d_0*x+sum_(j=1)^(N-1)(d_j-d_(j-1))*max(0,x-j),
    d_i=f(i+1)-f(i).

Separating positive and negative coefficients expresses it as a difference of tropical polynomials with nonnegative integer slopes. This is a valid constructive representation theorem. It does not discriminate special lane maps or prove a cheap circuit. “Empty” is stronger wording than needed; an efficiency claim requires a size/depth bound and comparison.

For neural networks the slope convention matters. Zhang–Naitzat–Lim's original [ICML 2018 theorem](https://proceedings.mlr.press/v80/zhang18i.html) explicitly assumes integer weights. Chu–Kuo's cited Proposition3.15 states a broader formulation while its preceding ordinary tropical definitions use integer exponents. Under that ordinary definition, sqrt(2)*ReLU(x) is a counterexample: the positive-side slope is irrational, whereas a difference of those tropical polynomials has integer slopes wherever differentiable. General real-weight ReLU networks fit generalized tropical polynomials allowing real slopes. Quantized integer networks fit the ordinary class.

The lane table also needs to specify its complexity metric. Addition by 3 modulo11 has three runs of equal consecutive increment, while addition by1 has two. Two affine branches of a modular sawtooth are not the same count as those interpolation runs. Inverse at zero also requires a convention.

The quantizer correction is sound. For 1<=t<=Q,

    f_t(c)=floor(t*c/Q),     0<=c<Q,
    n_y=ceil((y+1)*Q/t)-ceil(y*Q/t).

Fibers are contiguous intervals of size floor(Q/t) or ceil(Q/t). For a uniform scalar C,

    H(C | f_t(C)) = sum_y (n_y/Q)*log2(n_y),

which equals log2(Q/t) when t divides Q. Doubling that entropy for two components additionally requires an appropriate joint distribution; it does not follow from scalar fiber sizes for actual RLWE ciphertext components. The report appropriately retracts automatic equality in Landauer's bound. Its blanket approval of Welds4/5 cannot be verified without the propositions themselves.

## 7. External tropical FHE literature and reproducibility

The [official Illinois Tech announcement](https://datasys.cs.iit.edu/seminar/wang-2026-02-18.html) confirms Wang's talk title, date and abstract. It says tropical rational functions are directly implementable in a tropical FHE scheme and announces approximation/training work. Neither that abstract nor the retrieved author publication page specifies the encryption algorithms, security assumptions, comparison circuit or performance. A construction-level comparison remains open; a missing retrieved paper is not evidence that none exists.

The upload mentions accompanying `holte.rs` and `trop.rs`, but its DOCX contains no embedded attachments, and neither source was supplied separately or found under those names in the checkout. All newly executed evidence is therefore labeled as current repository code or independent models. No original Rust run is claimed.

| Fresh follow-up check | Result | Scope |
|---|---|---|
| Theta/minimizer domain | 77,760 passed | Odd Q3..61, all integer chart points, K-40..40 |
| Theta differences and signed anchors | 77,760 each passed | Same domain; anchor131 |
| Current lift-refinement suite | 9 tests passed | Includes924 conservative transitions and9,603 native digit cases |
| Existing Lean refresh arithmetic slice | Five modules and axiom audit passed | Fresh oleans; symbolic arithmetic/model premises; no Rust/security admission |
| Current Phase1 oracle | 1,280 coefficient cases plus495 corridor cases passed | Clear secret-dependent reference, not encrypted execution |
| Local chart model | 39 single and117 batched cases passed | Exact composite-ring arithmetic and circuit schedule |
| Independent Holte grid | 184 parameter pairs passed | Plus15 brute transition matrices |
| Doubling-carry hinge | 2,000,999 states passed | All p2..2000 and v0..p-1 |
| Valuation laws | 99,846 prime/input pairs per product/sum law passed | Total across six primes, signed x,y=-64..64; cancellation controls retained |
| Finite-lane interpolation | 3,752 values passed | Seven maps, eight primes11..257 |
| Quantizer fibers | 3,239 parameter pairs passed | Q2..80; 88,559 individual fibers |
| Flushed BBS recurrence | 2,046 input words passed | Lengths1..10, initially empty infinite-capacity carrier |

The reports and scripts state their domains and preserve failures/aliases as negative controls. These are correctness checks, not cryptographic benchmarks or proofs that finite tests establish universal claims.

## 8. Consequences for the Lean update

Keep the integer observer/congruence/capacity foundation. Add two separate geometric specializations:

1. **Tropical theta sheet recovery:** centered-chart minimum, real-coordinate identity, boundary ties, discrete difference and authenticated modular readout.
2. **Conservative continuum embedding:** finite configurations, equal mass, fixed boundary flux, discrete continuity, real piecewise-linear interpolation and bounded residue projection of the flux.

Treat the evolution operator as an explicit input until its actual BBS/Toda compatibility is proved. Prove a separate source relation before identifying geometric flux with an FHE quotient. A precision-aware valuation module should state its cancellation and truncation limits. Holte reversibility is a useful independent theorem family; it need not block the arithmetic or geometric modules.

Reuse the existing `PublicRefreshDigit` and `PublicRefreshNativeLift` developments after reconciling their interfaces with the public proof project. They already supply substantive symbolic arithmetic, so that work should not be described as entirely missing or re-created from finite tests.

The [updated specification](PROOF_UPDATE_SPEC.md) records those obligations. The exact tropical and continuum constructions strengthen the proposed general framework. Their hypotheses also give precise counterexamples to overly broad claims, which should become formal boundary tests rather than reasons to discard the valid mechanisms.
