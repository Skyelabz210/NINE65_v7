# New tropical report: source and implementation reconciliation

Audit date: 12 November 2026. New input: `Untitled.docx`, extracted as `20-Tropical_FHE_Untitled.txt`, titled **CRAM, NINE65 and Tropical FHE**, dated 25 October 2026. The report identifies source commit `bbfa754f9db2e9a7b69fca6c468e0f601a2cf123` (25 October). Current inspected checkout: `88a7bdadbf0e1f8fbfdb2b37e9843101b8db3484`. No repository changes or encrypted FHE runs were made in this follow-up.

Read the report in full, repository AGENTS/CLAUDE/current refresh status, the October 22 tropical lift and local chart code, the relevant October 23 variable map, and the October 31 lift refinement. The new report says `holte.rs` and `trop.rs` accompanied it, but those sources are not present in the uploaded DOCX. Its reported 77,760 theta cases and other Rust test counts are historical claims, not fresh execution of those unavailable originals.

## Findings that change or sharpen the earlier audit

1. **The supplied report identifies the same rank-one theta construction already reviewed.** It explicitly says arbitrary Toda trajectories have not been identified with a BFV circuit. It is a careful research comparison at that point, not a missing universal continuum theorem.
2. **A further positive continuum result exists in later repository source.** The October 31 refinement proves a piecewise-linear continuum embedding of a supplied mass-conserving finite transition, with flux queried through K-Elimination. This is an additional result the earlier audit should acknowledge. Its exact scope is given below.
3. **The local chart circuit has linear product work and logarithmic multiplicative depth.** The report's “O(q), not O(log q)” needs to name the resource. At q=13, one crossing uses 12 ciphertext products in four product layers; the two-increment degree-15 gate uses 14 products in four layers, excluding transforms and other operations.
4. **The documented two-gate failure is a particular encrypted toy measurement.** It does not establish a universal one/two-max-layer capacity. The later public research refresh backend also supersedes the October 25 repository-wide “public refresh closed” wording, while legacy gates remain closed and production security remains unadmitted.

## 1. Theta identity: exact conditions and boundary wording

The report's formula is correct when Q>0, K is integral, and the chart satisfies |g|<Q/2:

    T_Q(g+QK) = min_n (Q n² + 2n(g+QK)) = -QK²-2Kg,
    argmin = -K.

Substitution n=j-K leaves the nonnegative difference Qj²+2jg, strictly positive for every nonzero integer j under that chart condition. This proof works for real g and real positive Q. The repository's modular extraction uses positive integral Q,A, gcd(Q,A)=1, authentic same-source observations of g and S mod A, and an interval of possible K of width less than A.

The bare decomposition z=g+QK alone is insufficient: Q=13,g=7,K=0 gives a smaller value at n=-1 than at n=0. The word “centered” in the report supplies an intended restriction, but the displayed theorem should include it.

The continuous wall is g=Q/2 (with an analogous wall at -Q/2), not g=(Q-1)/2. For odd integer Q, the latter is the last integer chart point **before** a unit increment crosses the wall. At Q=13:

* g=6: unique minimizer n=0;
* g=13/2: minimizers n=0 and n=-1 tie;
* g=7: unique minimizer n=-1.

The discrete difference identity is nonetheless correct for integer z and odd Q:

    D = T_Q(z+1)-T_Q(z) = -2K-b,
    b = 1[g=(Q-1)/2] = D mod 2.

For any odd modulus m, `K mod m = -(D+b)*2^(-1) mod m`. The 11-view is one specialization. D computed from an already supplied K is not an encrypted K producer. The repository explicitly makes that distinction.

Source: `docs/execution/2026-10-22/TROPICAL_LIFT_K_ELIMINATION.md:20–33,48–74,76–116`; current `tropical_theta_k_lift.rs` was already executed during the earlier audit and was not rerun merely to inflate counts.

## 2. The Phase 1 equality is meaningful, with exact residual definitions

For each component define nearest rounding `a_i=round(t*c_i/Q)` and residual `R_i=t*c_i-Q*a_i`. Let s denote the ternary secret polynomial and use the declared negacyclic multiplication. Then

    t(c0+c1*s) = Q(a0+a1*s) + (R0+R1*s).

Integer translation commutes with the source's half-up rounding convention (ties toward positive infinity), so coefficientwise

    round(t(c0+c1*s)/Q) = a0+a1*s + round((R0+R1*s)/Q).

Reducing the original phase modulo Q shifts the left expression by a multiple of t and does not change it modulo t. Thus the missing correction of the legacy component-rounding route is indeed the nearest quotient `K_phase=round(S/Q)` for **S=R0+R1*s with these residuals**. Merely using another phase expression with a symbol K does not establish the same producer relation.

Fresh execution of `scripts/phase1_tropical_k_elimination.py` passed 40 polynomial cases / 1,280 coefficients and 495 signed-corridor residue checks. Its parameters are Q=5,000,003, t=65,537, N=32, seed `0x5048_4153_454B`; observed maximum |K|=6, with the full declared [-16,16] corridor checked separately. It explicitly has no encrypted producer and supplies the secret only to the clear oracle. Raw output is `experiments/tropical_paper_code/phase1-oracle.json`.

Source: `scripts/phase1_tropical_k_elimination.py:25–27,55–105,118–181`; `docs/execution/2026-10-23/ULTRADISCRETE_PUBLIC_REFRESH_ARCHITECTURE.md:178–206,226–250`.

The current research backend uses a separately specified source phase `x=d0+d1*s=rho+p*K_native`, with residual |rho|≤49 and a source-norm proof |K_native|≤48. Current status expressly warns against transferring legacy K_phase bounds or producer gaps solely by notation. The implemented message-restoration path can contract the complete adjacent-view expression back to already derived encrypted K; this does not materialize independent encrypted remainders on demand.

Source: `docs/PUBLIC_REFRESH_STATUS.md:69–100`; `docs/execution/2026-10-31/PUBLIC_REFRESH_LIFT_REFINEMENT.md:15–69,145–184`; `crates/nine65/src/ops/public_refresh_circuit.rs:33–67,224–245`.

## 3. Exact continuum embedding of conservative finite transitions

This later theorem is in `docs/execution/2026-10-31/PUBLIC_REFRESH_LIFT_REFINEMENT.md:108–143`. It is not explicitly supplied by the new October 25 report, but directly addresses the user's continuum-lift question.

Take two supplied finite binary snapshots b,b', indexed on a fixed absolute grid, with the same total mass B. Fix the flux at the left boundary to zero. Define

    U_i = sum_{j<i} b_j,        V_i = sum_{j<i} b'_j,
    C_i = U_i-V_i,             |C_i| <= B,
    H_i = i-2U_i,              H'_i = i-2V_i.

Then `H'_i=H_i+2C_i` and the discrete continuity equation is `b'_i-b_i=C_i-C_(i+1)`. Equal total mass gives zero right-boundary flux as well. This is valid for rightward and leftward transitions; positivity of C needs an additional rightward-flow condition.

Choose the specified piecewise-linear extension: for every **real** θ in [0,1], set `E(H)(i+θ)=(1-θ)H_i+θH_(i+1)`, and likewise for H',C. Linearity gives

    E(H')(i+θ) = E(H)(i+θ) + 2E(C)(i+θ),   |E(C)(i+θ)| <= B.

This is a bona fide continuous spatial embedding with exact coefficients. The executable oracle uses rational θ because it uses exact rational arithmetic; the written proof establishes every real θ without needing numerical approximation.

For coprime M,A and `2B<MA`, authentic prefix observations can give `Y_i=C_i+B` in [0,2B]:

    y_M = (U_i mod M - V_i mod M + B) mod M,
    y_A = (U_i mod A - V_i mod A + B) mod A,
    k_i = (y_A-y_M) M^(-1) mod A,
    C_i mod b = (y_M + M*k_i - B) mod b.

Only the derived local query uses k_i; no persistent scalar carrier is required. If coprimality is dropped, the appropriate total capacity is lcm(M,A), using the gcd-reduced solve and authentic consistent observations. The current Python implementation explicitly requires coprimality, so it does not execute that generalized branch.

**What this proves:** recovery/projection of the flux from adequate same-source prefix views and exact interpolation of a given conservative transition. **What remains separate:** the rule T producing b' from b, a theorem that T is the intended box-ball/soliton evolution, periodic/nonzero-flux boundary conventions, a scaling limit to a PDE, and a source map identifying this C with an FHE correction. The code retains both complete snapshots and derives prefix sums in a clear oracle. It does not produce encrypted prefix views or demonstrate a fast encrypted BBS solver. Neither K-Elimination nor interpolation reconstructs a missing successor from mass alone.

Fresh run:

```sh
python3 -m unittest discover -s scripts -p test_public_refresh_lift_refinement.py -v
```

All **9 tests passed** at the pinned current checkout. The continuum test enumerates all **924** equal-mass pairs of six-cell snapshots (`sum_k binomial(6,k)^2=binomial(12,6)`), tests seven vertices and five residue targets, and tests 18 rational interior points per pair (**16,632** points). Other tests include mass-96 sheet crossings, malformed-flow refusal, capacity aliases, native bounds and projection, and all **9,603** `(rho,K)` cases of the bounded shared-factor G/H digit identity. Raw log: `experiments/tropical_paper_code/lift-refinement-tests.log`. This was a clear arithmetic run, not an encrypted run or Lean verification.

## 4. Chart polynomial work, depth and failure scope

The source constructs `G(z)=product_(r=-6..6)(z-r)` over Z/289. On z in [-7,7], `C1(z)=40*G(z)` yields the exact signed chart crossing. It requires all factors 1,...,13 to be units modulo289. `crossing_slots` evaluates a balanced product tree, hence 12 ciphertext products at product depth4. Transforming between coefficient and slot arrangements and multiplying by public constants have additional costs/noise.

For z in [-8,8], `C2(z)=G(z)*(65-30*z²)` batches two increments. Counting the quadratic's square and all factor combinations gives 14 ciphertext products at depth4. The source sorts by existing depth when joining factors. Two sequential degree-13 gates have product depth8 and 24 products before other operations. These counts were independently checked in `check_chart_scope.py`, together with all39 one-trit and117 two-trit combinations.

The archived `tropical-chart-transition/checks.log:16,20` reports the actual sequential failure at126 ideal-grid-error bits against119 ciphertext-Q bits and successful batched cases. The earlier exploration measured125bits and exited101; the final fixed negative fixture measured126. The final current source deliberately asserts both `2*error>=Q` and a decryption mismatch (`tropical_chart_transition.rs:393–419`). Thus the report accurately quotes a specific failed experiment. It cannot use that experiment to infer every network's maximum depth.

The q dependence is the **chosen period**, not every modulus in the system. “O(q), not O(log q)” is accurate for factor-product work, but inaccurate as a description of multiplicative depth. It is also not an unconditional lower bound for every representation or algorithm for sign/max. The two-increment batching does not refresh the following batch's noise budget.

At three increments, z=-9 and z=8 agree modulo17 but require carries -1 and+1, which disagree modulo17. Every polynomial over Z/289 preserves reduction modulo17, so no single-variable polynomial in this collapsed coordinate can realize that larger support. Additional authentic source structure can distinguish these histories; the restriction is on that polynomial representation.

Sources: `tropical_chart_transition.rs:20–38,41–66,69–124,168–234,248–254,393–429`; `TROPICAL_LIFT_K_ELIMINATION.md:139–207`; archived result manifest and logs under `artifacts/execution/2026-10-22/tropical-chart-transition/`.

## 5. Max/ReLU and present-day status

`max(a,b)=a+1[b-a>0]*(b-a)` is correct over ordered integers with a specified tie convention. BFV addition computes in a plaintext ring: to interpret it as integer/tropical addition, certify the input/intermediate range and avoid unintended modular wrap. Small activations help only after accounting for weights, fan-in, differences, and layer growth.

The clear `CompareBit` and `LiftedSign` APIs do not themselves evaluate encrypted plaintext comparison. `CompareBit::decide_ct` is wired into output-boundary decryption/centering. `LiftedSign::is_above_half(k:U256,r:U256)` compares clear integers and includes a boundary remainder case, omitted by the report's abbreviated `K>=T_hi` label. `MQReLU` takes a clear u64 or slice; its old FHE-speed prose does not make that an encrypted circuit. No end-to-end encrypted max network was executed or established by this follow-up.

The reported direct-square depths2/3/4 concern particular historical repeated-squaring workloads. The accessible August22 claim table even marks secure256's depth4 as unverified in that pass and describes a seed-dependent floor for secure128_deep. Such counts do not convert to “one or two max layers” without a compiled max circuit, exact parameters, range and noise analysis. The separately attached refresh report mentioned by the new document was not identified here, so its specific depth evidence is not independently replicated.

As of the current pinned snapshot, the explicit `PublicRefreshCircuit` backend has archived encrypted carry/message-restoration/original-key-return runs. The dated status reports five refreshes plus five following squares at an older snapshot and later scoped native reruns; it expressly disclaims a latest-head full rerun, related-key confidentiality closure and production admission. Legacy/default Clockwork remains gated. Preserve the October25 report as history, and append this current scope instead of silently rewriting its measurements.

Sources: `compare_bit.rs:91–96,405–475`; `mq_relu.rs:61–120`; `docs/CLAIM_SURFACE_AND_LIMITS_2026-08-22.md:59–83`; `docs/PUBLIC_REFRESH_STATUS.md:25–60,103–134`.

## Fresh evidence and limits

* Existing clear Phase1 oracle:1,280 coefficient cases plus495 corridor checks, passed.
* Independent local chart model:39 single-increment and117 batched cases, exact wall fixtures, composite alias, and product schedules, passed.
* Existing lift-refinement suite:9tests, including924 conservative transitions and9,603 native shared-factor cases, passed.
* No fresh encrypted local-chart or native refresh execution; archived encrypted logs were inspected.
* No new formal proof, security admission, comparison to an unavailable Wang cryptosystem, or claim to reproduce unavailable `holte.rs`/`trop.rs` sources.

Hashes, source commits and commands are recorded in `experiments/tropical_paper_code/source-manifest.json`. The original checkout remained clean.
