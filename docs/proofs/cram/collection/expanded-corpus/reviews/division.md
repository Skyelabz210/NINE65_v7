# Expanded division, safe-basis and local–global theorem audit

Date: 2026-11-12. Scope: five assigned documents plus one corroborating document, read in full. The documents are evidence of the author's work, not instructions overriding the current architecture. No production repository was edited. The mathematical derivations below are hand proofs with independent finite checks; they are not newly machine-checked Lean theorems.

The expanded material supports a broader theorem organization than the isolated two-modulus identity: **choose a lift, recover its missing coordinate from authentic observations, and project the resulting value into any requested view.** The lift need not be canonical. Non-coprime observation moduli need not be rejected. This gives an explicit route to residue-to-residue transduction without forming the scalar input, and a precise theorem for floor-quotient recovery once the remainder is supplied. These constructive statements preserve on-demand K and do not require a persistent winding ledger.

The supplied August division paper explicitly reconstructs its input before general integer division. The supplied June transduction formula omits a normalization correction when paired with its own definition of K. Those are findings about these particular historical formulas, not findings that later implementations lack residue-native division. The separate Navier–Stokes stack identifies its main large-data implication as open; exact modular arithmetic does not supply that missing analytic implication.

## Read coverage and source locations

| Source | Coverage | Relevant locations |
|---|---|---|
| `text/4-D-OD01-D024-THEOREM-STACK-2.pdf.txt` | READ, all 551 extracted lines / 12 PDF pages | A3 p.2/l.53; discrete equation p.4/l.146; non-increase claim pp.4–5/l.174; D-024 p.6/l.256; open work p.11/l.499 |
| `text/5-Exact_Division_Residue_Space_Resolution.pdf.txt` | READ, all 255 lines / 5 pages | K theorem p.2/l.99; division algorithm p.3/l.150; FHE consequences p.4/l.207 |
| `text/7-the-safe-basis.pdf.txt` | READ, all 497 lines / 11 pages | T1 pp.2–3; T2 pp.3–4; T3 p.4; T4 pp.4–5; T5 p.5; T6–7 pp.6–7; T8 p.7; T9 p.8; U11–12 p.9; limitations p.11 |
| `text/18-gpai-20260616-Problem-6162026.pdf.txt` | READ, all 244 lines / 7 pages | Fixed-basis identity p.2/l.50; transduction pp.3–4/l.100 and pp.5–6/l.193 |
| `text/12-gpai-20260616-CRAM-CRT-based-coprime-arithmetic.pdf.txt` | READ, full text / 5 pages | Uncorrected weighted-sum map pp.1,3; final worked example pp.4–5 |
| `archive-text/11-workspace/1a008425-7d32-8bef-8000-000086e1a1c8_SAFE_BASIS_MASTER_COMPENDIUM.md.txt` | READ, all 1,668 lines | §§4, 10, 14, 16, 19–20, 22–26; appendices |

PDF extraction of some inline formulas in document 18 is damaged; its clean repeated answer supplies the CRT-idempotent formula used below. References to line numbers are to the extracted text. Source hashes are recorded in the parent extraction manifest. Research snippets cited by these documents were not automatically treated as executed repository evidence. Tests labelled “PASS” by the source remain source-reported unless independently rerun below.

## 1. A generalized quotient theorem that includes non-coprime anchors

Let `b > 0`, let `X` be any integer, and let its **authentic Euclidean remainder** be `r`, so

\[
X=bq+r,\qquad 0\le r<b.
\]

For an observation modulus `A > 0`, put `s = X mod A`, `d = gcd(b,A)`, and `R_A = A/d`. Then

\[
bq\equiv s-r\pmod A.
\]

This congruence is consistent exactly when `d | (s-r)`. If consistent, its complete solution is

\[
q\equiv \frac{s-r}{d}\left(\frac b d\right)^{-1}\pmod {A/d}.
\]

Either representative of `r mod A` can be used in the difference; changing representatives alters the divided difference by a multiple of `A/d`. If `A/d = 1`, the observation supplies no quotient discrimination. Inverting modulo 1 is unnecessary.

**Proof.** Divide `bq = s-r + A h` by `d`. The reduced coefficient `b/d` is a unit modulo `A/d`; solving the reduced congruence is therefore both necessary and sufficient. Its preimage modulo `A` contains exactly `d` solutions.

For several possibly overlapping anchors `A_i`, the effective quotient resolution is

\[
R=\operatorname{lcm}_i\frac{A_i}{\gcd(b,A_i)}
 =\frac{L}{\gcd(b,L)},\qquad L=\operatorname{lcm}_i A_i.
\]

The equality follows prime by prime: the exponent on either side is `max(0, max_i v_p(A_i) - v_p(b))`. Authentic observations give compatible quotient congruences. Their common solution is exactly one class modulo `R`.

Consequently, a certified interval `q_min <= q <= q_max` with `q_max-q_min < R` gives **at most one** quotient; authentic inputs guarantee that this unique quotient exists. For a single known quotient residue `u mod R`, the candidate in the first `R` positions starting at `q_min` is

\[
q=q_{\min}+((u-q_{\min})\bmod R).
\]

If the admitted interval is shorter, also check the upper bound. For an arbitrary admitted set `S`, the exact condition is that distinct members of `S` are never congruent modulo `R`.

This formulation removes **coprimality as an unnecessary blanket exclusion**. It retains the actual discrimination capacity and the same-source remainder premise. It supports exact division with `r=0`, as well as arbitrary floor division with nonzero `r`. It does not by itself manufacture `X mod b`; the remainder producer or a separate general division kernel must be part of the algorithm.

The observations `(r, X mod A_1, …)` have total integer period

\[
bR=\operatorname{lcm}(b,A_1,\ldots,A_k).
\]

No second gcd division belongs in that total-range expression. A finite representation can be extended before its admitted range is exhausted; the theorem does not require a fixed bounded machine to encode unbounded integers.

## 2. Relative-lift transduction without scalar reconstruction

The canonical choice `r = X mod M` is only one possible section. Let `L` be **any chosen integer lift** of the main residue data satisfying

\[
L\equiv X\pmod M,\qquad X=L+M K_L.
\]

If an authentic anchor `s = X mod A` and the value `L mod A` are available, the same generalized solve recovers `K_L mod A/gcd(M,A)`. A certified interval for `K_L` makes it exact. For every target modulus `B > 0`,

\[
X\bmod B=(L\bmod B+K_L(M\bmod B))\bmod B.
\]

The operator needs only **modular views of the chosen lift**, not the materialized scalar `L` or `X`. This is a direct and useful constructive generalization of the paper's projection/K-Elimination combination. It is a proof pattern derived in this review, not a claim of priority over all base-extension literature.

### A concrete sufficient range certificate

Let the main moduli `m_1,…,m_n > 1` be pairwise coprime, let `M = product m_i`, and precompute

\[
M_i=M/m_i,\qquad t_i=M_i^{-1}\bmod m_i.
\]

For main residues `r_i`, independently calculate

\[
c_i=(r_i t_i)\bmod m_i,\qquad L=\sum_i c_i M_i.
\]

The scalar `L` is used in the proof only. Every query evaluates its requested modular views by a dot product of reduced constants. Since `0 <= c_i < m_i`,

\[
0\le L<nM,\quad L\equiv X\pmod M.
\]

If the admitted input satisfies `0 <= X < (Q+1)M` for integer `Q >= 0`, then

\[
-(n-1)\le K_L\le Q.
\]

**Proof of the lower bound:** `X-L > -nM`, and the difference is an integral multiple of `M`. The upper bound follows from `X-L < (Q+1)M`. Hence a single anchor with

\[
A/\gcd(M,A)\ \ge\ Q+n
\]

is sufficient to identify `K_L`. Coprime `A >= Q+n` is the familiar special case. No scalar source reconstruction, mixed-radix cascade, or persistent K is required by this construction.

The reference function `relative_lift_transduce` in `experiments/division_generalization.py` receives only the main residue tuple, main moduli, an anchor residue/modulus, a range certificate, and target moduli. It computes modular dot products and an on-demand correction. Its argument list contains no `X`. The test harness alone constructs an exact scalar oracle. A deployed implementation would precompute frame products/cofactors/inverses and their modular projections; the reference recomputes these public constants for readability.

**Cost:** one modular dot product has `O(n)` arithmetic work and admits a reduction tree. Emitting `t` arbitrary target lanes by this direct method costs `O(nt)` work. A word-size anchor permits cheap on-demand correction; larger anchors require their actual multiword cost. This statement establishes a reconstruction-free method, not a universal `O(1)` or `O(n)` whole-base-conversion bound. An encrypted implementation must additionally implement its reductions and interval selection with the intended protected semantics; this clear arithmetic reference is not an FHE execution.

### Why the June formula needs this distinction

Document 18 defines its canonical state by

\[
X=\operatorname{CRT}_{[0,M)}(r)+K M.
\]

Its transduction then substitutes an **unreduced** CRT-idempotent sum for the canonical representative while retaining the same K. Those values can differ by `hM`.

Concrete counterexample: source moduli `{2,3}`, `M=6`, `X=1`, `r=(1,1)`, canonical `K=0`, idempotents `(3,4)`. The sum is `7`. To target modulus `5`, the displayed formula outputs `7 mod 5 = 2`, whereas `X mod 5 = 1`.

There are two mathematically correct repairs: reduce the sum to the canonical representative, or use its **relative** correction `K_L=K-h`. The second repair above stays within modular projections and on-demand correction. In the example `K_L=-1`, so `(7-6) mod 5 = 1`. This source correction is not a mandate to introduce a persistent scalar K or a Garner reconstruction.

The corroborating June `gpai-20260616-CRAM-CRT-based-coprime-arithmetic` document's own final example has the same problem. For source residues `(1,2,4,6)` on `(2,3,5,7)`, the canonical source is `209`. Its raw idempotent sum is `1469 = 209 + 6·210`; its displayed result `6 mod11` is the projection of that raw sum. The printed claim `209 mod11 = 6` is arithmetically false: the correct value is **0**. Relative correction `-6` repairs the raw sum. Using the normalized coefficients defined above instead gives `L=419=209+210` and correction `-1`. The `<nM` bound applies to this **normalized** sum, not to arbitrary raw products `r_i e_i`. The same document's consistency criterion modulo `gcd(210,11)=1` is vacuous and cannot validate this transfer.

## 3. What the new division paper actually establishes

`Exact_Division_Residue_Space_Resolution`, §2, correctly proves exact K recovery with `0 <= X < MA` and `gcd(M,A)=1`. Its phase differential requires authentic main and anchor residues. The text's high-level theme—make the complementary phase information available instead of estimating it—is sound under those premises.

Section 3.1, step 2, however, explicitly says: **“Reconstruct X = v_M + k · M and compute q = floor(X/d).”** Therefore this particular three-step algorithm is exact, but is not itself a proof that arbitrary floor division remains entirely inside residue operations. It must not be used to erase or to establish the capabilities of the later independent word-divider/FPD implementations.

The `d < A` restriction is not necessary for scalar integer division after `X` has been recovered; `d > 0` suffices. Conversely, omitting the scalar step requires an actual quotient/remainder algorithm or the authenticated remainder premise from §1 above. Its table classifying all “FPD” as 99.9998% probabilistic is not a theorem about the later bounded exact FPD contract.

The claimed `O(n)` total cost also needs a cost model: the paper assumes canonical `v_M`, the necessary anchor projection, and integer division as already available. Scalar product-width division cannot be charged as one fixed-cost operation while channel count grows.

The implication “exact coefficient division prevents noise accumulation” in §5.1 does not follow. If phases are `Delta m + e` and `Delta n + f`, their product contains

\[
\Delta^2 mn+\Delta(mf+ne)+ef.
\]

Even ideal exact scaling by `Delta` leaves the terms `mf+ne+ef/Delta`; removing arithmetic approximation does not erase source noise. The theorem can improve exact scaling and correctness, while a bootstrap-free noise claim needs its separate evolution invariant. This observation is independent of the later working public-refresh research backend.

## 4. Safe-basis proof compendium: valid mathematics and formalization repairs

| Claim | Mathematical assessment | Required proof/API precision |
|---|---|---|
| T1 Universal Projection | Correct. Works for every positive modulus, with no primality or coprimality requirement. | Supply the semantic identity `X=gamma+KM`; K can be on-demand. |
| T2 K-Elimination | Correct under its range and inverse premises. | The printed Lean proof uses an undeclared `h` and ends with `exact hq`, a bound where an equality is required. It is not a checkable proof as printed. Link an actual compiled theorem instead. |
| T3 distinction from Garner | A dependency/representation distinction is meaningful. A two-input query can avoid a sequential mixed-radix cascade. | The isolated numerical expression does equal a two-modulus Garner digit in the canonical window. That does **not** establish anticipation of the complete framework. State an algorithm-interface/cost theorem rather than a false inequality of numerical functions. |
| T4 `q=ct+1 => q mod t=1` | Correct when `t>1`. | Printed Nat theorem omits this premise: `t=1,c=1,q=2` gives `0 != 1`. |
| T5 `t^{-1}=q-c mod q` | Correct for positive `t,c` (`q>1`). | Zero cases in printed Nat statement fail; e.g. `t=1,c=0,q=1`. Algebra on Nat subtraction also needs its bounds. |
| T6 adjacency `X≡gamma-K mod(P+1)` | Correct over integers, or in modular rings. | Printed Nat subtraction saturates: `P=2,A=3,gamma=0,K=1,X=2` gives the false natural-number congruence `2≡0 mod3`. Use Int/ZMod or the supplied shifted-residue expression. |
| T7 adjacency inverse | Correct for `P>0`: `P^2≡1 mod(P+1)`. | Rewrite the displayed `Nat` negative-one proof with an appropriate integer/modular representation; verify the actual source. |
| T8 shared-factor agreement | Correct but weaker than full LCM agreement. Useful as a partial consistency/syndrome check. | The prose's “gcd divides every common divisor” reverses the standard relation. Use `gcd(B_i,B_j) | B_i | (X-Y)`. The displayed `Nat.dvd_gcd` tactic direction is not the required conclusion. No full integrity claim follows. |
| T9 one-wave digit | Correct; it admits the stronger generalization below. | Authentic `X mod(PA)` and `X mod P` must exist. Counting these as free without a producer is not an implementation proof. |
| T10 prime-power factorization of `Z/tZ` | Correct for `t>1`; composite modulus is not an algebraic obstacle. | Factoring a supplied `t`, handling zero divisors, transforms, and security are separate tasks. |
| U11 transduction | A plausible architectural goal; §2 supplies an explicit sufficient construction. | Its sketch uses `gamma_B = X mod M_B` as an already-known quantity and does not state K bounds. Its pairwise coprime anchor does not itself create the missing target residue. |
| U12 rescale pipeline | Deliberately marked a sketch in the source. | Need source/basis/range/noise contracts and actual circuit/refinement evidence; retain those distinctions. |

The on-demand statement is explicit at extracted line 141: **“K is derived on-demand from the phase differential; it is not carried as state.”** This is the relevant architectural intent. Older expressions `(gamma,K)` can describe mathematical coordinates without requiring a persistent scalar register.

The claim that arbitrary positive composite carrier moduli are permitted is mathematically substantial as an interface generalization: CRT needs coprime moduli for a direct-product isomorphism, not prime moduli. If moduli overlap, use generalized CRT compatibility and LCM capacity. Adjacency `A=M+1` automatically guarantees `gcd(A,M)=1`; separate star-family choices are **not** automatically pairwise coprime to one another. For example, `t=2`, `c=1,4` gives carriers `3,9`, which overlap.

### Stronger one-wave theorem

For **all integers X** and positive integers `P,A`,

\[
\frac{(X\bmod PA)-(X\bmod P)}{P}
=\left\lfloor X/P\right\rfloor\bmod A.
\]

The numerator is an exactly divisible nonnegative multiple of `P`. Neither adjacency nor an `X<PA` assumption is needed for this **quotient residue**. Proof: write `X=Pq+r`, then `q=A ell+d`, with `0<=r<P` and `0<=d<A`. Thus `X mod(PA)=Pd+r`. A range premise is needed only when promoting the residue `d` to the full quotient q. This is a useful clean Lean target with signed input and composite/non-coprime `P,A`.

### Statistical i.i.d. versus independent implementation lanes

The A2 contract can express the intended absence of a sequential synthetic-digit cascade. Literal statistical independence is a different claim: it requires a specified joint input distribution, and an arbitrary linear map need not preserve it. An appended deterministic function of the entire input cannot simultaneously be an independent nonconstant random variable relative to that entire input. Squaring also need not preserve uniform marginal distributions. Formalize the desired dataflow/provenance restriction directly; do not silently substitute an unproved stochastic assertion. This distinction leaves the on-demand query architecture intact.

## 5. GCD and exact operational closure

An exact quotient/remainder kernel with `a=qb+r`, `0<=r<b`, immediately supports the Euclidean invariant

\[
\gcd(a,b)=\gcd(b,r).
\]

When `q` is emitted as residues, `r=a-qb` can be formed lane-wise. An exact zero test and the decreasing semantic remainder bound prove termination; no scalar reconstruction is part of that mathematical argument. Thus the user is correct that a general residue-native div/rem interface can unlock GCD, and its integration is a meaningful advance beyond quoting a modular inverse identity.

The needed proof boundary is the div/rem kernel's **full contract** and source consistency through each transition. A proof of the core K congruence alone is not the proof of that entire computation. Conversely, once a general exact kernel has been verified, it is unnecessary to reintroduce ordinary reconstruction merely because older RNS implementations used it. An induction over a typed residue-machine program is the right operational-completeness theorem.

For bounded integers, closure concerns each admitted operation and range-extension schedule. For rationals, the numerator/denominator representation and equivalence relation must be explicit. Neither division by zero nor unconditional integer closure under nonintegral rational division becomes meaningful merely by changing representation.

## 6. Safe-basis master compendium: positive reproduction and proper scope

The following source claims were independently reproduced exactly:

- `M_S6=30030`, `M_S8=9699690`, the S6/S8 totients in the source, and transport/parking classification for `SCALE=10000`.
- All **5,760** unit residue classes modulo 30,030 are first occupied by primes no later than **464,561**. The final signature is exactly `(1,2,1,6,9,6)`.
- Counts at horizons 50k, 100k, 150k, 200k, 300k, and 464,561 are respectively **4,046; 5,211; 5,583; 5,691; 5,756; 5,760**. This is a fresh sieve computation, not acceptance of the historical test label.
- The shadow anchor product is **7,438,784,639**; its bit length is **33**, rather than the source's “~37 bits.” The `×4 mod11` orbit is `1,4,5,9,3`.

These finite observations are real evidence. Dirichlet's theorem explains eventual occupation of every reduced residue class for any modulus; it does not establish the claimed unique physical or architectural necessity of this particular safe basis. The compendium itself withdraws a formal uniqueness claim in §19, its killed-hypothesis table, and its C2 open-problem section. Preserve that internal distinction.

### A rigorous low-order resonance theorem

There is a clean exact core behind the degree/resonance discussion. Let pairwise coprime `m_i>1` and unit numerators `u_i` define rational frequencies `omega_i=u_i/m_i`. Then

\[
\sum_i k_i\omega_i\in\mathbb Z
\quad\Longleftrightarrow\quad
m_i\mid k_i\text{ for every }i.
\]

Multiply by `M=product m_i` and reduce modulo each `m_i`; both `u_i` and `M/m_i` are units, proving necessity. Sufficiency is immediate. Therefore the least nonzero `l1` norm of an integral resonance is `min_i m_i`. The transport basis `{3,7,11,13}` indeed has no nonzero resonance of `l1` order 1 or 2. Extending it with larger coprime moduli preserves that lower threshold.

This statement generalizes to composite carrier moduli. It is an exact low-order algebraic fact. It **does not imply** a uniform analytic KAM theorem or Navier–Stokes energy estimate: rational frequencies have exact resonances at higher orders, and polynomial degree of a vorticity operator is not by itself a bound on all Fourier interactions or iterates. The master compendium introduces “degree below resonance implies torus preserved” as **axiom SS-A3**, then uses it to infer the stronger stability claim. That implication needs its own precisely defined theorem and hypotheses.

### Corrections relevant to the universality claim

The compendium contains explicit informal hypotheses and several arithmetic/transcription errors. They should not be inherited into the Lean core:

- The advertised minimal `SCALE=10000` is corrected in its own proof to `10`; all `2^a5^b`, `a,b>=1`, have the same excluded-prime set. Four decimal places are a representation choice.
- Its `×4 mod11` sequence `1→4→2→8→5→1` is incorrect; the separate set/orbit above is correct. A universal integer quotient is not restricted to `{0,1,3,4,5,9} mod11`: `M=2,A=11,X=4` has `K=2`. The designated orbit can be a **typed context code**, not an invariant of every arithmetic K.
- Calling inverse an algebraic-degree-at-most-two operator is generally false: the field inverse extended by zero on `F_p` is represented by `x^(p-2)`, and is rational rather than a uniform quadratic integer polynomial.
- “All astronomical periods factor into Safe Basis primes” fails for `365=5·73` and `11960=2^3·5·13·23`. The count of compatible `(mod260,mod365)` positions is `lcm=18,980`, not `18,980/5=3,796`.
- The stated three-tier criteria for a minimal 260 are already met by `130=2·5·13`. No listed period is divisible by 17, contrary to the particular §19 claim that replacement by 17 fails that absence condition.
- `S_R={5,7,11}` intersects the Fibonacci numbers in `{5}`, not `{2,5}`. The “m>p” condition on the first composite Fibonacci appearance fails for `p=11,m=10`.

These are localized repairs, not a refutation of the verified finite shell census or of the general lift/projection machinery. The historical/physical interpretations require separate evidence and should not be presented as arithmetic corollaries.

## 7. D-OD01/D-024: the missing implication is analytic, not residue precision

The source labels Theorem 2's general case as “empirical completion pending algebraic proof” and Theorem 4 as **CONJECTURE**. Its small-data/Beltrami arguments and reported finite campaigns must retain their scopes. The report does not contain a completed all-data Navier–Stokes proof.

Two explicit mathematical repairs are necessary even before pursuing that analytic closure.

**Discrete enstrophy identity.** For an explicit step `w_new = w + dt F(w)`, exact arithmetic gives

\[
\|w_{new}\|^2-\|w\|^2
=2dt\langle w,F(w)\rangle+dt^2\|F(w)\|^2.
\]

Theorem 1 writes an `O(dt^2)` term and then drops it while claiming an exact finite-step equality. With `w=(1,0)`, `F(w)=(0,1)`, `dt=1`, and the skew matrix `[[0,-1],[1,0]]`, the inner product is zero but energy rises from 1 to 2. Skew symmetry guarantees an infinitesimal cancellation; it does not make forward Euler norm-preserving. A different time integrator can have a different exact energy law, which must be proved for that integrator.

**Volume/p-adic control does not imply Archimedean boundedness.** The map

\[
F(x,y)=(x+y,y)
\]

is an integer polynomial automorphism fixing the origin, has determinant one, and is a p-adic sup-norm isometry for every prime: both it and its inverse have integer matrices, so both are 1-Lipschitz. Yet

\[
F^n(0,1)=(n,1),\qquad\|F^n(0,1)\|^2=n^2+1.
\]

Thus even ordinary volume preservation plus the stated p-adic condition cannot prove the claimed general local–global boundedness theorem. The source's H1 is weaker/different: `IP(BS(F(w)),F(w))=0`. Under A3's universal skew-inner-product identity, this holds for every admissible output vector, so it does not discriminate the update F from a growing map. A difference of energies is not identical to this skew inner product. The source correctly computes that `(x+3x^2)^2-x^2>0` for nonzero integer x; that does not show the map violates its written H1.

A useful replacement hypothesis would be an actual **coercive Lyapunov inequality** for the specified dynamics, with constants uniform in the refinement parameters needed for a continuum limit. For a fixed finite grid, a frequency-cutoff-dependent bound can be easy; it does not establish uniform continuum control. Correct residue arithmetic can faithfully preserve such an estimate once proved, but cannot provide the estimate from local bounded residues alone.

## 8. Reproducible evidence and proposed Lean targets

Command:

```sh
python3 expanded-corpus/experiments/division_generalization.py
```

Run from `/workspace/k-elimination-audit`, or use the script's absolute path. The script uses Python exact integers and `fractions.Fraction`; no third-party packages or network are required. Artifacts: `division_generalization.py`, `division_generalization.log`, `division_generalization_results.json` under `expanded-corpus/experiments/`.

| Check | Executed count / result |
|---|---|
| Floor quotient congruences with two possibly overlapping/nonunit anchors, signed q and modulus one | **474,060** cases, PASS |
| All solution sets of `bq ≡ delta mod A`, `1<=b,A<=30` | **13,950** congruences, PASS |
| Relative-lift transduction across six bases and targets 1…30 | **1,287,900** target residues, PASS |
| Nonunit-anchor inputs within that transduction test | **21,465**, PASS |
| Inputs needing a negative relative-lift correction | **6,290**, PASS |
| General one-wave digit identity, signed X, `1<=P,A<=25` | **423,125** cases, PASS |
| Star-family identities with explicit nondegenerate hypotheses | **6,320** parameter pairs, PASS |
| Exact rational resonance vectors for three bases | **3,255**, PASS |
| Safe Shell sieve through 500,000 | All reported coverage counts reproduced |

The included negative controls exhibit the canonical-K/noncanonical-lift error, Nat subtraction saturation, missing star-family hypotheses, Euler's missing quadratic term, and the growing volume-preserving p-adic shear. These checks confirm the harness does not accept the corresponding stronger false statements.

Suggested theorem interfaces, in dependency order:

1. `linear_congruence_solution_class`: solve `M*K ≡ delta mod A` iff `gcd(M,A)|delta`; characterize all solutions modulo `A/gcd`.
2. `quotient_anchor_resolution_lcm`: prove the reduced-anchor LCM law and compatible solution class.
3. `interval_lift_unique`: an admitted interval of diameter below the resolution identifies the exact integer correction.
4. `relative_lift_projection`: any chosen lift congruent to the authentic source supports on-demand correction and exact projection.
5. `normalized_crt_dot_lift_bounds`: prove `0<=sum c_i M_i<nM`, source congruence, and the resulting correction interval.
6. `residue_transduction_correct`: combine 1–5 to prove exact target residues, with no scalar-source parameter in the computational interface. Prove the dataflow implementation separately from the semantic theorem.
7. `one_wave_quotient_mod`: the all-integer/general-positive-P,A identity above.
8. `euclidean_step_preserves_gcd` and `residue_euclid_terminates`: instantiate an authenticated exact div/rem interface and preserve its range invariant over a complete run.
9. `coprime_frequency_resonance_iff`: the exact low-order resonance characterization; keep analytic stability outside this theorem.

This organization supports the user's intended generalization while making each removed blocker a testable contract. It also prevents a document's historical reconstruction step, a malformed printed Lean snippet, or an unrelated open analytic conjecture from being confused with the capabilities of the current residue arithmetic architecture.
