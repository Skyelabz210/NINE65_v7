# Expanded framework review

Review date: 2026-11-12. Scope: the six sources below, mathematical derivation, independent finite checks, and an independent statement review of the new `ExactObservation.lean`. No production source was modified. No claim of whole-system execution, cryptographic security, a continuum PDE theorem, or an exhaustive novelty search follows from this review.

## Main finding

The expanded corpus contains a substantial, coherent generalization target: **certified computation from sufficient observations**, with an arithmetic kernel that recovers a requested lift on demand and with compositional rules for changing frames. It is broader than one CRT/Garner identity. In particular, the careful portion of source 20 explicitly gives a local-query factorization theorem, finite composition theorem, typed division policy, and domain-specific continuum obligations. Those should be the backbone of the proof update.

This does not establish every assertion in the synthesis documents. The corpus contains incompatible architectural descriptions and some independently falsifiable statements. A correct synthesis should preserve the strongest precise definitions and proofs, identify the current on-demand architecture, and correct the local statements below. A shared algebraic ingredient does not show that the complete CRAM architecture was anticipated by that ingredient's prior literature.

## Source coverage and references

All six extracted texts were read in full, including repeated conversational appendices and bibliographies. The total extracted text is 266,861 characters. References below use stable extracted-text line numbers; PDF page numbers can be recovered from form-feed boundaries.

| Label | Source | Coverage and important qualification |
|---|---|---|
| F6 | `text/6-CRAM_FULL_SYNTHESIS_EXPANDED.docx.txt` | READ in full, 18,801 characters. No OMML equations or embedded media. Many formula strings in the document are already damaged or incomplete; missing symbols were not silently supplied as evidence. |
| F8 | `text/8-KimiCRAM_QMNF_Technical_White_Paper_v1.0.md.txt` | READ in full, 35,001 characters. August 2026 synthesis; historical runtime/security claims require current-source reconciliation. |
| F13 | `text/13-cram-beta-synthesis-v1-.pdf.txt` | READ in full, 24 pages, 58,784 characters. Its formalization section is a proposed plan, while other sections use completed-proof language. Large parts of its bibliography are unrelated to the claimed mathematics. |
| F16 | `text/16-Configurable-Residue-Arithmetic-Machines-CRAM-A-Self-Contained-Non-Archimedean-Exact-Arithmetic-Substrate-Dual-Track-K-Elimination-and-Frame-Transduction.pdf.txt` | READ in full, 7 pages, 10,006 characters. Explicit K-Free Principle at lines 67–100. |
| F20 | `text/20-ConfigurableResidueArithmeticMachines.docx.txt` | READ in full, 120,679 characters. Lines 1–435 are a comparatively careful theorem document; subsequent assembled sections repeatedly contradict parts of that core. |
| BR | `archive-text/11-workspace/1a008441-9d42-8fb4-8000-00004785fe8b_RECOMBINANT_CRT_BRIDGE_TECHNICAL_PACKET.docx.txt` | READ in full, 23,590 characters. March 10, 2026 document. Distinguishes some open empirical nodes but overstates its error and denominator conclusions. |

Hashes and original paths are in `../extraction-manifest.json`. READ means the supplied text was examined, not that its referenced tests, source repositories, citations, or formal proof claims were independently reproduced. There are no hidden diagram/equation images in the assigned DOCX sources according to extraction inventory.

## What the sources actually establish or specify

1. **On-demand lift is explicitly an intended invariant.** F16 lines 67–100 says the system “does not carry, track, or accumulate k forward” and obtains it from a phase differential at the point of transduction. F16 lines 189–194 places positional reconstruction at Observe. This is direct documentary support for the user's current architecture, independent of the historical papers that put a scalar `K` in a state struct.
2. **A local query need not recover the entire number.** F20 §14, lines 310–318 defines local lift and proves that a predicate factoring through a selected projection is decidable from that projection. This is the most useful generalization statement in these six sources. It gives a principled reason why full scalar reconstruction can be optional.
3. **Exactness composes once primitive correctness has been proved.** F20 §6, lines 128–148; §16, lines 337–349; and final theorem, lines 418–432 explicitly formulate induction over certified transitions. These are valid conditional refinement principles. They do not by themselves supply the missing primitive algorithms or prove their stated cost.
4. **Heterogeneous operators are defined as their own exact semantics.** F20 lines 33–41 explicitly acknowledges that a heterogeneous topology need not equal ordinary integer addition/multiplication. F20 lines 247–269 gives a valid finite product-function construction and counts syntactic assignments. This is a legitimate programmable algebraic substrate, not an arithmetic error.
5. **The careful division policy distinguishes outputs.** F20 lines 221–246 distinguishes exact integer, rational, modular, and rejected results. Its FPD correction at lines 200–211 correctly says that adding an auxiliary lane does not make an already nonunit divisor coprime to the original product. This correction should supersede the contradictory explanation in F13 lines 147–165.
6. **The careful continuum statement has the right scope.** F20 lines 350–372 defines coherent finite charts and explicitly requires a separate convergence/equivalence theorem in the target analytic topology. F6 lines 273–274 also leaves the continuum Navier–Stokes bridge open. This is compatible with useful exact finite and continuous-interpolation constructions; it is not a proof of every continuum conclusion stated later in F20.

## A defensible generalized theorem

### A. Query sufficiency, independent of arithmetic domain

Let `D` be the admitted source-state set, `O : D → R` the available authenticated observations, and `F : D → Y` a requested output. There is a well-defined answer map on the image of `O`,

\[
\bar F:O(D)\to Y,\qquad \bar F(O(x))=F(x),
\]

**if and only if**

\[
O(x)=O(y)\ \Longrightarrow\ F(x)=F(y)\qquad(x,y\in D).
\]

Proof: necessity follows by applying the answer map. For sufficiency, give each observation the common value of `F` on its fiber; the condition makes this independent of representative. On arbitrary sets this is an existence theorem, not a constructive runtime decoder. For a concrete architecture, prove an explicit algorithm implements `F̄` with the claimed inputs and instruction set.

This strictly separates three questions which the initial survey had conflated:

- Full identity requires injective observations on `D`.
- A selected quotient, sign, gcd, residue, or tropical quantity needs only the corresponding fiber-constancy condition.
- An efficient residue implementation requires a constructive decoder/refinement proof, beyond the set-level existence statement.

The statement permits partial observations and even deliberately noninjective encodings when the requested query does not distinguish the omitted information. A finite collision obstructs only queries that separate that collision. It does not rule out useful CRAM operations globally.

Authentic refinement has a monotonicity property: if `O = forget ∘ O'`, every query recoverable from `O` is recoverable from `O'`. Adding a correctly bound source observation cannot invalidate an already recoverable query. A new lane must actually observe the same admitted source; naming a fresh modulus does not produce that observation.

F20 §14 already provides the sufficient direction for selected residue projections. The necessary-and-sufficient version gives a common specification for the generalized framework without asserting that this abstract factorization lemma itself is historically new.

### B. Constructive lift through an observed affine relation

Let `G`, `K`, `H` be additive abelian groups, `ι : K → G` and `h : G → H` homomorphisms, and suppose a source has a certified decomposition

\[
x=r+\iota(k),\qquad k\in S\subseteq K.
\]

From the representative `r` and observation `h(x)`, the lift satisfies

\[
(h\circ\iota)(k)=h(x)-h(r).
\]

Every compatible observation determines at most one admitted lift exactly when

\[
(S-S)\cap\ker(h\circ\iota)\subseteq\{0\}.
\]

This is the precise role of a lift corridor, an independent anchor, or a higher-dimensional observation family. If a constructive inverse on the admitted image is available, `k` is computed only when queried; the theorem does not require persistent winding state or reconstruction of `x`.

For integers, `ι(k)=Mk` and `h(x)=x mod A` give the K-Elimination congruence. For several anchors the observer is a product map. For lattices/modules the kernel can be analyzed with matrix arithmetic or Smith normal form. For tropical systems the required chart, lifting group, and observable must be supplied; subtraction/inversion cannot be silently assumed inside an arbitrary tropical semiring. The domain-independent theorem A remains valid even where theorem B's additive structure is unavailable.

The potentially distinctive contribution is the constructive family of charts, observations, routes, and certified implementations that instantiate this mechanism across domains. The appearance of familiar modular algebra in one instantiation does not settle that broader contribution's priority.

### C. Transduction and operator transport

Let each frame `A` encode the same admitted value/domain `D` by `e_A`, with `e_A` injective onto its valid states. Mathematically,

\[
T_{A\to B}=e_B\circ e_A^{-1}
\]

is the unique value-preserving transfer on valid states. Therefore identity, inverse, and composition laws hold:

\[
T_{A\to A}=\mathrm{id},\quad
T_{B\to A}T_{A\to B}=\mathrm{id},\quad
T_{B\to C}T_{A\to B}=T_{A\to C}.
\]

Writing an inverse in the semantic proof does **not** require its runtime implementation to reconstruct an integer. An implementation can compute only the target observations using the lift kernel. The independent paired-view model below does exactly that: the transfer formula produces target residues directly, computing `K` ephemerally and never storing or materializing scalar `X` inside transfer.

For operation semantics `f`, the encoded implementation should satisfy the commuting equation `run_A(e_A(x)) = e_A(f(x))`. Together with the corresponding equation in `B`, this yields operation transport. Finite composition follows by induction.

There are two important qualifications:

- Numerical windings are frame-dependent: `floor(X/M_A)` and `floor(X/M_B)` generally differ. Preserve the represented value and declared winding policy, not equality of those two integers.
- If transduction appends an irreversible lineage/history event, strict roundtrip equality of the **whole metadata-bearing state** does not follow. State explicitly whether equality is value equivalence, canonical frame-state equality, or equality including history. A groupoid of value representations and an append-only history category are different specifications.

### D. Exact rational arithmetic is a valid extension with an explicit type

An exact rational frame can represent `(n,d)` with `d>0`, where both integers have adequate authenticated observations. Addition and multiplication are implemented by `(ne+md,de)` and `(nm,de)`; division by a nonzero numerator produces `(ne,dm)`, followed by sign normalization as needed. Gcd normalization is optional for value correctness, though useful for canonical representations.

This does not require the denominator to be invertible in every residue lane when numerator and denominator are maintained as a pair. In contrast, interpreting `n/d` as a **single** residue element by multiplying `d⁻¹` does require a unit denominator. There is no unital ring homomorphism from all of `ℚ` to a nontrivial finite characteristic ring: an integer multiple equal to zero in the target is invertible in `ℚ`.

The rational-state alternative in F20 lines 221–228 is therefore a sound type-level route. A residue implementation and sufficient observations still need to be provided for its comparisons, zero tests, and optional gcd normalization. These six sources do not provide a complete gcd runtime implementation; that question belongs to the separately reviewed theorem/code stack.

## Architecture and claim reconciliation

| Issue | Precise documentary evidence | Recommended proof-update treatment |
|---|---|---|
| Persistent versus queried K | F16 lines 67–100 forbids carrying `k`; F8 lines 363–386 and 731–744, F20 lines 441–480 describe persisted counters/β state. | Treat persisted scalar-K passages as historical or conflicting descriptions, not the current target. A proof may define semantic `K` without making it a runtime field. |
| Reconstruction boundary | F20 lines 15 and 128–135 permit boundary reconstruction; later lines 473, 531, and 1014 call for MRC/Garner during dynamic extension. | State an actual allowed primitive set and prove trace conformance. Arithmetic equivalence alone cannot establish absence of internal reconstruction. |
| Typed totality versus successful closure | F20 lines 225–228 allows rejection; final theorem assumes every route/certificate correct. | A dispatcher that always rejects is total but does not close division. Separate totality, soundness, completeness on an admitted domain, and cost. |
| Existence versus a constructor | F20 FPD theorem assumes a valid fusion rule/certificate; transduction assumes identity support. | Prove certificate construction and validation soundness from source-bound inputs. Do not encode the desired conclusion as an unchecked premise and report implementation closure. |
| Lane-local versus two-lane or global query | F8 line 176 calls a two-residue read “lane-independent”; F16 lines 85–100 calls it total lane independence. | Distinguish parallel lane arithmetic, constant-size anchor communication, absence of sequential Garner cascade, and literal zero inter-lane communication. These are different cost/dataflow properties. |
| i.i.d. versus product representation | F8 lines 93–119 permits a general precomputed linear map and claims i.i.d. preservation. | Specify a probability model and invariant. A general linear map need not preserve independence; `(u,v)↦(u,u)` on uniform bits is a counterexample. Coordinate-wise functions preserve independence of independent inputs, not automatically identical distributions or uniformity. |
| Current runtime/security | F8 lines 14, 511–540, 687–693 promote old Clockwork and 128-bit refresh claims; F13 lines 421–489 describes future formalization. | Date-scope those historical statements and use current source/executed evidence. Do not infer functional failure of the separate current refresh backend from a stale summary, or a security theorem from arithmetic exactness. |
| Continuum scope | F20 §17 explicitly leaves analytic equivalence open; appended lines 1101–1106 reduce global regularity to 30 modular maps. | Keep the explicit domain-specific bridge obligation. A finite modular coefficient cycle does not bound the corresponding real norm or prove convergence. |

An authentic extra observation genuinely removes an ambiguity in its admitted domain. The remaining task is to prove its producer and range invariant and the relevant operation's algorithm. These are constructive proof obligations, not a claim that residue-space division or comparison must inherently reconstruct a scalar.

## Concrete corrections supported by calculations or direct proofs

### 1. Adjacent one-wave extraction has a sign error in one printed theorem

F8 Theorem 9, lines 233–235 states
`((X mod A) − (X mod P)) mod A = floor(X/P)` for `A=P+1`.
The correct order is the reverse, as F8 itself states at lines 216–221 and 818–823:

\[
K\bmod(P+1)=((X\bmod P)-(X\bmod(P+1)))\bmod(P+1).
\]

At `P=2, A=3, X=2`, the printed expression is `2`, while the true quotient and corrected expression are `1`. All 91,518 tested values for `2≤P≤64`, `0≤X<P(P+1)` satisfy the corrected formula. This is a local presentation error, not a failure of K-Elimination.

### 2. The unified-rescale theorem needs the range of its constructed input

F8 Theorem 12, lines 265–270 defines `Q=tΔ`, `A=Q+1`, `Y=xt+floor(Δ/2)`, assumes only `0≤x<Q`, and claims exact `K=floor(Y/Δ)`. That hypothesis does not imply `Y<ΔA`.

At `t=3, Δ=2, Q=6, A=7, x=5`, `Y=16`; extraction returns `1`, whereas `floor(16/2)=8`. The congruence remains correct modulo `7`. The corrected range guard succeeds in all 180,235 checked cases; 35,525 cases in the chosen finite sweep lie beyond it and alias. Typical large-Δ parameters may satisfy a stronger uniform bound, but that bound must appear in the theorem.

There is a separate semantic issue: if `x` denotes an ordinary raw BFV coefficient, standard rescaling at `Q=tΔ` is nearest-integer `tx/Q = x/Δ`, whereas the displayed theorem uses `tx/Δ`. The actual source's input scale must be bound to this symbol before identifying it as the BFV operator. A proof of the congruence alone cannot supply that binding.

### 3. Heterogeneous topology expands the operation set, not the CRT value set

F20 lines 1082–1093 says standard CRT inhabits a proper diagonal subset and claims a value-space expansion factor `M^(k−1)`. For pairwise coprime moduli, `ℤ/Mℤ → ∏ℤ/p_iℤ` is onto; both sides have `M` elements. The actual ratio is `1`.

For moduli `3,5`, all 15 product-ring elements already are images of `ℤ/15ℤ`. A mixed add/multiply operator still has a single-ring polynomial representative:

\[
F(x,y)=10(x+y)+6xy\pmod {15},
\]

which gives addition modulo `3` and multiplication modulo `5`. All 225 input pairs were checked. This **preserves** the useful programmable-topology claim in F20 lines 33–41 and 247–269. Counting topology labels or typed metadata can enlarge a machine's state/configuration space; that is a different count.

### 4. Error-free arithmetic does not freeze the propagated initial-data error

BR lines 12, 17, 69–71, 230 and 520 say quantization error never grows. The valid part is that exact modular operations introduce no new arithmetic-roundoff error relative to the represented rational/integer computation. The input error may nevertheless grow under that computation.

If true data are `11/10` and the stored quantization is `1`, the initial error is `1/10`. Exact multiplication by `10` gives stored output `10` versus true output `11`, an error of `1`. No floating-point step is involved. BR's own Error Budget Algebra (lines 83–84) and V5 (line 272) correctly allow growth; they contradict the unqualified frozen-error prose. Physical interpretation needs transported interval/error bounds, not immutable output-error metadata.

### 5. Fixed smooth denominator support has a useful, limited closure

BR Theorem T1's explicitly restricted cases—finite binary floats, decimal scales, dyadic grid spacings—do have denominators supported on small primes. Its broader conclusion “every naturally occurring computational denominator” is false: `1/13`, a 13-cell grid spacing, or division of integer `1` by `13` is enough.

Exact division can introduce new denominator primes even when both inputs started as integers. The correct object for a fixed support `S` is a localization with denominators supported on `S`, or an explicit numerator/denominator frame. There is no mathematical need to confine a generalized CRAM rational representation to 11-smooth denominators.

Also, a family of powers of primes from `S` is pairwise coprime only when distinct lanes use **distinct** underlying primes; `4` and `8` are not coprime. BR's denominator-factor construction has one collected prime-power per prime and is valid under that condition; its more general sentence at line 55 is too broad.

### 6. A prime-only anchor completion is not automatically the full profinite integers

F6 lines 209–215 and 235 discuss a star-prime ladder, profinite winding, and torsion-free completion. If the ladder consists of distinct primes `A_i` and finite products `L_n=∏_{i≤n}A_i`, then

\[
\varprojlim_n \mathbb Z/L_n\mathbb Z\cong\prod_i\mathbb F_{A_i}.
\]

That product contains torsion: the vector that is `1` at prime `p` and `0` elsewhere has additive order `p`. It is not the full `Ẑ ≅ ∏_p ℤ_p`. Full profinite completion requires a cofinal family for divisibility, including arbitrarily high powers of every prime. Other completions are valid when named correctly. Finite anchor products tending to infinity still separate ordinary integers; that important practical claim does not need the incorrect identification.

For a witness supported at prime `3`, compatible finite residues are `1 mod 3`, `10 mod 15`, `70 mod 105`, `385 mod 1155`, and `5005 mod 15015`; each is annihilated by `3`. The code checks these prefixes. This is a completion distinction, not an ambiguity in bounded finite K recovery.

### 7. Polynomial degree does not imply dynamical or information conservation

F6 lines 199–203 and 253–254 infer structural/physical stability from a degree/resonance inequality; F16 lines 173–182 describes every operation as reversible. A degree-two map `x↦x²` on `ℤ/3ℤ` sends both `1` and `2` to `1`. It is not invertible and does not preserve the uniform counting distribution. Retaining input/history or using reversible gates can preserve information, but that is an additional construction.

Furthermore, a finite-field inverse extended polynomial is `x^(p−2)`, so it is not uniformly algebraic degree below `3` on Safe Basis primes. Max/min/threshold maps have piecewise degrees in an ordered representative chart; that is a different notion from a polynomial's algebraic degree. F6's own inverse row gives degree `p−2` (lines 135–140), inconsistent with its blanket degree statement.

Consequently no KAM, Navier–Stokes, energy-conservation, or zero-entropy theorem follows solely from that numerical inequality. Exactness and a valid coordinate lift remain valuable irrespective of that unsupported implication.

### 8. The refinement-cycle count is basis-specific and not an analytic bound

F20 lines 1101–1106 asserts a 30-map cycle for the Safe Basis. The orders of `4` modulo the odd SafeS8 primes `3,5,7,11,13,17,19` are respectively `1,2,3,5,6,4,9`, with lcm `180`. At prime `2`, `4` is not a unit. The number `30` fits the smaller odd basis through `13`, not all SafeS8.

Regardless of whether the corrected finite period is `30` or `180`, an unbounded real sequence and a bounded one may share identical fixed-modulus observations. A coefficient cycle alone does not prove the required norm bounds, compactness, stability, or convergence. F20 §17's explicit analytic bridge is the appropriate specification.

## Independent review of the new Lean specification

I read `/workspace/k-elimination-audit/expanded-corpus/ExactObservation.lean` in full after the parent supplied its fresh compile result. I did not independently rerun Lean in this worker. No proof or statement defect was found in its eight theorems.

Final integration note: the parent then added a ninth theorem, `finite_program_identifies_result`, with the explicit injectivity premise discussed below, and recompiled the whole file without warnings. The final axiom log covers all nine. The independent statement review above refers to the earlier eight-theorem version; the added theorem's kernel check is the parent's recorded execution.

- `recoverable_iff` uses observations on their image and explicitly discloses `Classical.choose`. It proves mathematical factorization and does not pretend to be a runtime decoder.
- `refined_observation_suffices` includes the necessary source-commutation premise.
- `collision_obstructs_query` correctly limits a collision's consequence to a query that distinguishes it.
- `Refines` and `finite_program_exact` do not require a runtime reconstruction oracle. `encode` is a semantic specification function.
- With noninjective `encode`, the last theorem proves equality of encoded semantics, not full integer identity. Full-value claims need injectivity or a suitable observation decoder; a constant encoder would otherwise make refinement vacuous.
- Total `semantic : Op → X → X` requires admitted-state closure. A partial division API, error outcome, or variable range/frame should be modeled explicitly; an admitted subtype is not automatically closed under every operation.
- Transduction composition/roundtrip theorems concern valid encoded states and exactly the fields encoded. They do not by themselves prove a groupoid of all raw or history-extended CRAM states.

These are good generalized specification lemmas for F20 §§14 and 16. The next substantive theorem layer should construct the concrete observations/decoders and prove the corresponding primitive refinements, while a separate trace theorem establishes the allowed runtime operation set.

## Executed evidence

Command:

```text
python3 expanded-corpus/experiments/framework_checks.py
```

Artifacts: `../experiments/framework_checks.py`, `../experiments/framework_checks.json`.

| Check | Executed cases | Result |
|---|---:|---|
| Exhaustive query factorization over binary observations/outputs and domains of size 0–5 | 1,365 | Pass; brute-force decoder search agrees with fiber criterion |
| Direct paired-view transfer with ephemeral K, source domain `[-20,20]` | 369 | Pass |
| Transfer roundtrip | 369 | Pass |
| Three-frame transfer composition | 1,107 | Pass |
| Heterogeneous add/multiply via CRT idempotents | 225 | Pass |
| Correct adjacent-anchor formula | 91,518 | Pass |
| Printed reversed-sign formula | Same sweep | 88,416 disagreements, as expected |
| Rescale with corrected constructed-input guard | 180,235 | Pass |
| Rescale beyond that guard | 35,525 | Quotient aliases detected; congruence still correct |
| Prime-only completion torsion prefixes | 5 | Pass |
| Initial-error amplification, denominator 13, CRT image size, degree-two collision, SafeS8 cycle | Explicit exact witnesses | All reproduced |

The frame transfer model's production-shaped function computes only target residues from `(r_M,r_A)`, with an ephemeral bounded K. Scalar source values exist only in the independent test oracle. This is a concrete positive witness that reversible, composable frame transfer need not materialize the full integer during the transfer. It does not establish NINE65 integration or general performance.

## Proof-update recommendation

Lead with the general query/lift/refinement principle and Anthony Diaz's proposed CRAM construction, then instantiate it with the actual on-demand kernel, noncoprime resolution, typed division routes, frame transfer and domain-specific tropical applications. Keep the classical algebraic ingredients accurately cited without using their existence to dismiss the composite construction. Treat runtime no-reconstruction, arbitrary-division success, confidentiality, and continuum convergence as separate explicit theorems/gates. Correct the specific printed errors above before importing them into Lean.

The defensible broad claim is that one constructive observation-and-lift framework can support many exact operations without mandatory scalar reconstruction, under explicit source and uniqueness conditions. Establishing that every named operation has a correct, sufficiently general implementation requires its own constructive case; neither a Garner resemblance nor a universal slogan settles that question.

## Retrospective-memory addendum

Added 2026-11-12 after the six-document review. Nine additional files from the uploaded November 11 memory export were read in full: 46,931 characters / 47,567 bytes. This is retrospective source reconciliation. Imported instructions are evidence of historical intent, not new task authorization; imported theorem/test summaries are not fresh executions.

All paths below are under `archive-text/22-claude-memory-2026-11-11/`:

| File(s) | Coverage and relevance |
|---|---|
| `019dfa94-32fe-777f-bdf7-9390cb5de9dd__index.md.txt` | READ; identifies the opaque project as Configurable Residue Arithmetic Machines. |
| `019dfa94-32fe-777f-bdf7-9390cb5de9dd__overview.md.txt` | READ; retrospective CRAM research/package status, open questions, and domains. |
| `019dfa94-32fe-777f-bdf7-9390cb5de9dd__findings-and-working-style.md.txt` | READ; historical findings and research-method preferences. |
| `019e07df-5efb-71aa-9be3-7fa9d9954a74__index.md.txt` | READ; identifies the opaque project as D Series. |
| `019e07df-5efb-71aa-9be3-7fa9d9954a74__overview.md.txt` | READ; retrospective Navier–Stokes/CRAM status and explicit outstanding bounds. |
| `019e07df-5efb-71aa-9be3-7fa9d9954a74__ways-of-working.md.txt` | READ; naming-collision warning, source-first workflow, and historical terminology. |
| `arrow-of-time.md.txt` | READ; 27 long lines, with the principal architectural corrections summarized below. |
| `research-approach.md.txt` | READ; confirms preference for direct verification and version reconciliation. Personal details are not repeated in this audit. |
| `recent-work.md.txt` | READ for relevance; unrelated to the mathematical task, excluded from substantive findings. |

### Material corrections already present in the user's research history

**The stored-K description was expressly withdrawn.** `arrow-of-time.md.txt` line 21 records the user's August 12 correction, “A2 doesn't store it derives,” and explicitly withdraws both a description saying CRAM carries K and an experiment that maintained an unbounded K accumulator for 200,000 steps. Line 22 records a statelessness theorem: K-Elimination is a function of two readings and storing K is not required. Line 27 directs the work toward the ultradiscrete tropical Jacobian/box-ball system and again says a carried K/epoch must be replaced by on-demand derivation. These are strong reasons to treat the persistent-K passages identified above as superseded descriptions. They reinforce F16's K-Free Principle.

**The stated generalization already includes several of the necessary distinctions.** Arrow line 22 records T28–T36: construction-read inverses for `A=cM+1`, the star-family identities, exact and signed recovery windows, sharp noncoprime resolution `A/gcd(M,A)`, and the doubling construction `P_(t+1)=P_t(P_t+1)`. It explicitly says that each rung requires its own reading pair and that a finite set of finite readings does not determine every unbounded integer. The memory therefore does not support attributing a universal finite-state information claim to the current intended design. The construction chooses a capacity without requiring a precomputed final magnitude, while each actual recovery still has a precise admitted domain.

**Source binding was recognized as distinct from an algebraically satisfied congruence.** Arrow lines 20–22 report that defining K from the same pair of residues makes a state-level “phase-lock defect” identically zero, so it cannot certify that the lanes came from the same source. That agrees with the source-authentication obligation in this review. A transition defect

\[
E=[\Delta v-\Delta r-M\Delta\kappa]_A
\]

is discriminating only when the intended `Δκ` or another part of the transition is supplied independently by the operation/source specification. If both endpoint kappas are recomputed from the same observations, this defect is again identically zero. No persistent winding register is required to supply an independent *local transition specification*. Similarly, the memory's claimed equivalence between this defect and fiber entropy (line 23) requires a specified transition class: algebraic compatibility and injectivity are different properties in general.

**Blanket reversibility was later replaced by an operator-specific condition.** Arrow line 24 explicitly states that reversibility depends jointly on operator, dimension, and modulus, and distinguishes a declared singular operation with typed handling from an unexpectedly noninvertible operation. It reports a heat-stencil example and the correct general matrix criterion, `gcd(det(A),m)=1`. Thus the degree-two collision above corrects a blanket statement in F6/F16; it does not negate this later, more precise architecture. This history also separates an emission/reversibility audit from an inspection of the permitted arithmetic primitives. A bijection can violate an architectural instruction policy, and a deliberately noninjective operator can satisfy its declared semantics.

**Several physical and mathematical scopes were explicitly acknowledged.** Arrow line 12 says its claimed Coq verification covered arithmetic/reversibility and not the probability/logarithm entropy layer. Lines 13–19 distinguish an arithmetic orientation model, two-arrow conjugacy, and additional observer/law/boundary selection structures. Line 26 explicitly records an unresolved Archimedean/Lorentzian bridge. The D Series overview lines 32–36 lists Gate 6, the discrete-to-continuum passage, and a uniform `C_stretch` bound as open. These statements support retaining domain-specific bridge obligations rather than promoting the broader synthesis prose to completed physical theorems.

**Numbered theorem identifiers need their source and statement.** The D Series overview lines 15–20 and ways-of-working lines 8–15 warn that D-024/D-030 tags collided between documents and that “Kill” historically meant a completed accomplishment. A theorem number or that vocabulary alone is not evidence of either proof or refutation. The proof-update ledger should bind every theorem to its actual statement, source revision, and dependencies.

### Evidence availability

The memory references `Arrow.v`, `arrow_of_time.py`, `shadow_arrow.py`, `A2_WINDING_DERIVATION.md`, `a2_winding_derivation.py`, `a2_winding_verify.py`, `wassan_fusion.py`, `selection.py`, `side_channel_emission.py`, `arrow_paper.pdf`, `CRAM_Explorer_Apr22_2026.tar.gz`, and `NS_BRIDGE_WORKSPACE_v1_tar.gz`. Exact-name searches in the supplied research directory and current NINE65 checkout did not locate those artifacts. Their reported proof results, historical counts, and claimed performance remain imported assertions in this addendum.

The current checkout does contain `crates/exact_transcendentals/src/arrow_step.rs` and `tests/arrow_emission_reversibility.rs`. Their existence is source-observed here; this addendum did not execute them or adopt a historical run as a current test. No additional experiments were needed to reconcile these retrospective sources.

The main conclusion is strengthened: the intended framework derives lift information on demand, supports constructed extensions and typed operations, and treats local query sufficiency as a reusable principle. Several apparent problems in older summaries were already identified and refined within the user's own research. The proof update should preserve those refinements and attach direct proof/implementation evidence to them, instead of restarting from the older simplified descriptions.
