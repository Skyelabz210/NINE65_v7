# Expanded runtime and archive audit

Reviewed 2026-11-12. Current executable source: `Skyelabz210/NINE65_v7` commit
`88a7bdadbf0e1f8fbfdb2b37e9843101b8db3484`, clean before and after this review.
The original repository was not edited. Experiments use isolated targets and
Rust 1.89.0. This report separates the current implementation from the uploaded
Crate-12 snapshots and from prose describing unidentified code.

## Main finding

The current repository **does implement encrypted unsigned integer division
with quotient, remainder and encrypted zero-divisor status**, including
nonunit divisors. Fresh tests at the reviewed commit passed. An assessment
that says the system has no encrypted shared-factor division API is now
incorrect. The operation has an explicit representation and admission
contract: sealed encrypted bit words, public widths, preserved noise bounds,
and finite circuit capacity. It does not reinterpret the older scalar lane
inverse API as integer division.

The repository also has a general bounded **clear-residue** quotient/remainder
projector retaining the complete basis even for shared-factor divisors, and a
live exact BFV rescaling kernel. These are three different constructions with
different input contracts. They support substantial positive claims without
conflating their proofs or measured costs.

## Current call paths and contracts

| Operation | Current path | Meaning and current evidence | Scalar reconstruction / other coordination |
|---|---|---|---|
| Encrypted integer division | `CramPublicEvaluator::divide_integer` → `CramMainEvaluator::divide_integer` → public Boolean circuit → main-Q operations | For unsigned d>0: n=q*d+r, 0≤r<d; for d=0: (q,r,status)=(0,n,1). Fresh encrypted tests pass. | No evaluator-side plaintext decode. Integer bits are supplied at explicit ingress and remain encrypted. Gates require cross-lane BFV arithmetic; this is not one independent quotient operation per original scalar lane. |
| Live exact BFV scaling | `CramMainEvaluator::multiply` → `ExactMulEvaluator::try_mul_exact_prepared` → centered auxiliary tensor → `ExactScaleRound` → prepared hybrid relinearization | Exact half-up BFV result floor((tX+floor(Q/2))/Q), with coherent auxiliary residues and proved capacity. Fresh scale-round tests pass. | Main-only base extension uses certified rank/half decisions; an exact wide idempotent-sum fallback is possible. No canonical coefficient object or Garner cascade is emitted on this reviewed route. |
| General bounded coefficient floor division | `RecumbentCoefficient::divide_with_rank_projection` → `RankResidueDivider::divide_floor` | Signed X, positive u64 d, authentic inclusive interval of width<P; returns q mod every original lane and r. Shared-factor tests and repeated divisions pass. | No scalar X assembled, but full-width fractional scratch carries equivalent coefficient information. Global rank is necessary in this implementation. It is not a live encrypted-plaintext division adapter. |
| Provisioned divisor-lane drop | `RecumbentCoefficient::drop_main` | Observed remainder and inverses on surviving main/anchor lanes; declared exact/floor/nearest semantics. | No global scalar emission. Removes the used main lane; retained anchors describe the quotient. |
| Legacy component-unit division | `CramPublicEvaluator::exact_divide` → `exact_divide_poly` | Each ciphertext component multiplied by d⁻¹ in every main/anchor lane. | Lane-local and no reconstruction, but not an arbitrary integer quotient API; correctly refuses nonunits. |
| Half-range decision | `CompareBit::decide` / `decide_ct`; `WideCompareBit::decide_ct` | Correct canonical half-modulus bit under supported basis/width bounds. Fresh tests pass. | Fast path is a certified fractional estimate; exact fallback reduces an idempotent sum to canonical X. Fixed-work version is used at the secret-holder decrypt/output boundary. Do not describe that particular fallback as having no reconstruction. |
| GCD | `CRTBigInt::gcd`, scalar `gcd` helpers | Clear bounded Euclidean or binary GCD exists. | `CRTBigInt::gcd` uses `%`; `Rem` obtains reconstructed/cached scalar magnitudes. No public encrypted GCD API found in the examined facades. |

### Encrypted integer division: source and mathematical content

Source references in `/workspace/NINE65_v7`:

- `crates/nine65/src/ops/cram_public.rs:235` creates the separate main-Q integer key domain;
  `:250` implements the public division facade and checks its configuration.
- `crates/nine65/src/ops/cram_main_division.rs:37` seals `EncryptedUint`;
  `:86`/`:107` implement checked ingress and preflight; `:177` evaluates;
  `:259` onward implements **client-side** decoding.
- `crates/nine65/src/ops/integer_division_circuit.rs:136` selects the public
  compiler strategy; `:149` implements finite truth-table compilation;
  `:241` implements restoring division.
- `crates/nine65/src/ops/cram_main.rs:322` sends multiplication through the
  prepared exact evaluator; client decryption begins at `:344`.

The Boolean identities are exact in the admitted plaintext ring on Boolean
inputs: NOT(a)=1−a, AND(a,b)=ab, XOR(a,b)=a+b−2ab, and
SELECT(c,a,b)=b+c(a−b). The borrow generator `(1−a)d` and its propagation term
`(1−XOR(a,d))*borrow` are mutually exclusive. Therefore addition implements
their OR without assuming 2 is invertible. This is why a denominator equal
to plaintext modulus 3 is a valid unsigned word divisor.

For restoring division, after a processed numerator prefix P the invariant
is P=dQ+R with 0≤R<d, for d>0. Appending bit a gives T=2R+a<2d. The encrypted
comparison/subtraction chooses T−d if T≥d and T otherwise, updating Q by the
same Boolean decision. An extra scratch bit prevents overflow. A balanced
Boolean zero test masks the quotient for d=0, leaving remainder n. The
evaluator does not branch on the encrypted zero predicate.

For widths ≤4, one-hot indicators of **public candidate indices** compile a
lower-depth finite table. Scalar division of these public indices is setup
computation, not decoding an encrypted input. Larger words use the quadratic
restoring circuit. Both strategies are checked against integer arithmetic.

Each bit is a BFV ciphertext whose polynomial coefficients are stored in RNS.
Thus the implementation is a bit-word circuit executed by residue-based FHE.
The word layout is explicit at ingress. It is not a proof that the same
algorithm directly divides an arbitrary existing single scalar RNS ciphertext
without supplying its integer lift. Equally, output decryption in the test
oracle is not reconstruction inside evaluator computation: callers can keep
the quotient and remainder words encrypted and compose admitted operations.

The contribution of K-Elimination/FPD to this path is through the exact
rescaling and arithmetic substrate. Restoring binary division and Boolean
table compilation should be identified as such when attributing the integer
quotient algorithm; a working composition does not require claiming that
every ingredient is new.

### Fresh executed evidence at the pinned commit

Command environment:

```text
CARGO_HOME=/workspace/.tooling/cargo
RUSTUP_HOME=/workspace/.tooling/rustup
CARGO_TARGET_DIR=/workspace/k-elimination-audit/expanded-corpus/build-runtime/nine65
CARGO_BUILD_JOBS=2
cargo test --locked -p nine65 --lib --release --no-fail-fast <filter> -- --nocapture
```

These runs use package-default features (`exact_transcendentals_backend`,
`accelerated`, `exact_rational`, `clockwork`, `adaptive-threading`). They do
not enable `architecture-meter`, `allow_insecure`, `slow_tests`,
`reference_ntt`, or Rayon flags. Unit tests compile with `cfg(test)`; their
deterministic key fixtures do not constitute a production randomness test.
`runtime_manifest.json` records the source and artifact hashes, toolchain,
commands, features, and archive staging comparisons.

| Filter | Passed | Failed | Ignored | Evidence |
|---|---:|---:|---:|---|
| `cram_main::division::` | 8 | 0 | 0 | `../experiments/runtime_integer_division.log` |
| `arithmetic::rank_residue_divider::` | 8 | 0 | 0 | `../experiments/runtime_rank_residue_divider.log` |
| `arithmetic::recumbent::` | 15 | 0 | 0 | `../experiments/runtime_recumbent.log` |
| `arithmetic::exact_scale_round::` | 10 | 0 | 0 | `../experiments/runtime_exact_scale_round.log` |
| `arithmetic::compare_bit::` | 11 | 0 | 0 | `../experiments/runtime_compare_bit.log` |

This is **52 targeted passing tests**, not a full repository test run. The
initial filter `ops::cram_main::division::` matched zero tests because the
elaborated module lives below `ops::rns_fhe`. That output is retained in
`runtime_integer_division_initial_zero_matches.log`; it is not counted as
validation. `runtime_lib_test_inventory.log` records test discovery used to
correct the filter.

The eight division tests include:

- Both clear compiler strategies for every input pair for widths 1–5,
  including unequal widths: 7,688 evaluations. The full-u64 restoring
  compiler adds 35 boundary pairs and 128 deterministic random pairs.
- Real encrypted evaluation of all 64 three-bit numerator/denominator pairs.
- Divisor 17 sharing a **ciphertext modulus lane**, using N=2, t=3, an
  eight-prime chain, three independent key-generation seeds, and cases
  31/17, 17/17, 16/17, 31/0. Every output coefficient is checked: 264
  coefficient comparisons. This reduced-ring fixture tests arithmetic, not
  secure parameters.
- Real N=8192 execution with the four `secure_128` worker primes and
  explicit t=3: 14/3 → (4,2,false) and 15/0 → (0,15,true). All coefficients
  of nine output bit ciphertexts per division are checked: **147,456
  coefficient comparisons**. The nonzero denominator shares the plaintext
  modulus. This fresh test is independent of the previously archived native
  refresh run and does not claim to rerun refresh.
- Width/overflow, foreign key and foreign context refusals, history-preserving
  composition, refusal before noise exhaustion, and identical public schedules
  for fresh zero/nonzero divisors.

The kernel tests additionally exercise signed interval endpoints, exact and
inexact division, positive/negative numerators, shared-factor divisors, repeated
division, full u64 target moduli, i128 extrema, alias refusal, exact rounding
ties, and comparison boundary cases. These are Rust execution results;
they do not themselves establish Lean-to-Rust refinement.

The unchanged exact-route source scanner passes on **4 route sources,
2,762 production lines, 19 deny patterns, zero violations**, and its self-test
catches all **16 injected forbidden constructs**. Logs:
`runtime_exact_route_denylist.log` and
`runtime_exact_route_denylist_selftest.log`. This is a scoped structural gate,
not dynamic instrumentation of every call in the repository. The public
facade's single `EliminationFirst` ledger event per word division is an
operation classification, not a measured zero count for every underlying
arithmetic helper.

### Cost and admission

`runtime_word_circuit_counts.rs` loads the unchanged compiler and counts its
actual nodes and ciphertext-product operations:

| Equal operand width | Gates | Ciphertext multiplications |
|---:|---:|---:|
| 1 | 5 | 2 |
| 2 | 38 | 19 |
| 3 | 173 | 79 |
| 4 | 761 | 287 |
| 5 | 203 | 120 |
| 8 | 515 | 312 |
| 16 | 2,051 | 1,264 |
| 32 | 8,195 | 5,088 |
| 64 | 32,771 | 20,416 |

The apparent drop at width 5 is the strategy switch from the lower-depth table
to restoring division; fewer gates do not imply a lower multiplicative depth
or a better noise bound. Width 64 compiler correctness is not width 64 encrypted
admission. Fresh preflight confirms the current original t=65537 named tuples
admit up to 1 tested bit (`secure_128`), 2 (`secure_192`) and 4
(`secure_256`) from fresh inputs, refusing the next tested width. The explicit
t=3, N=8192 tuple admits the executed four-bit operation. Existing input history
can reduce admission further. No noise history is reset to force acceptance.

The fresh eight-test suite took 24.27 seconds after compilation; that is a
suite runtime on a shared host, **not a per-division benchmark**. Previously
reported 2.10–2.53× prepared-key speedups measure multiplication, not this
integer division circuit. There is no evidence here for constant-cost
arbitrary-width division.

### Rank-based general quotient: exact positive theorem

Let pairwise-coprime lane moduli have product P, and authenticate
`lower≤X≤upper` with `upper−lower<P`. Set Y=X−lower, and obtain idempotent
coefficients c_i from its residues. Then

```text
sum_i c_i/m_i = rank + Y/P.
```

For S=2^B>kP, the downward error of `sum floor(S*c_i/m_i)/S` is <1/P.
When Y>0, its fractional part is at least 1/P; when Y=0 all c_i are zero.
Consequently taking the integer part yields the exact global rank. After
projecting X directly to d and every d*m_i, let r=X mod d. Since

```text
X mod (d*m_i) = r + d*(floor(X/d) mod m_i),
```

division by the ordinary positive integer d of this **small target residue
difference** returns every quotient residue, even if gcd(d,m_i)>1. No inverse
of d is used. The proof applies to negative X with Euclidean floor semantics.

This is implemented in `arithmetic/rank_residue_divider.rs:133`, with
projection at `:258`; its constructor certifies the precision and lane
constraints. `RecumbentCoefficient` authenticates interval metadata by checked
clear ingress and propagates bounds through arithmetic. It has no unrestricted
raw-residue constructor, no persistent scalar winding field, and only a
debug-build scalar oracle. Its `division_events` field is DAG history depth,
not K. The full-width accumulator and O(number-of-lanes × word-precision)
rank work must be included in cost accounting. The implementation currently
supports i128 interval endpoints and up to 64 u64 lanes; it does not prove
unbounded representability with finite fixed state.

### GCD and magnitude scope

An exact remainder operation plus zero tests and a decreasing nonnegative
remainder proves Euclid's GCD algorithm by the usual invariant
`gcd(a,b)=gcd(b,a mod b)`. This is a valid corollary to seek in the generalized
proof. It does not require persistent scalar K. To instantiate it as a fully
residue-native API, both the divisor and updated remainder must satisfy the
relevant representation contract at each iteration; the rank API presently
takes a **clear u64 divisor**. An encrypted version additionally needs an
admitted schedule and encrypted control/masking.

The current facades inspected do not expose such a GCD. Searches across
`crates` find clear u64/i128 Euclid/binary GCD helpers and
`exact_transcendentals/src/crt.rs:258::CRTBigInt::gcd`. The latter recurses
through `Rem` at `:429`, whose two operands call `reconstruct()`; its struct
at `:30` caches `value: Option<u128>` and a separate sign. `reconstruct()` at
`:216` returns that cache or executes a sequential CRT recurrence. This
existing helper is not evidence of the user's intended on-demand
residue-native GCD construction. Nor does its existence disprove such a
construction in the enlarged theorem corpus.

Half-range comparison is genuinely implemented. However, `CompareBit`'s
precise current fallback at `compare_bit.rs:252` reduces its wide sum to X
before comparing to ceil(M/2), and `decide_ct` does the same in fixed work.
That implementation belongs to the permitted secret-holder boundary. The
main-only evaluator base extender instead compares its unreduced sum N with
`rank*M+ceil(M/2)` without emitting canonical X. Thus one must identify the
particular consumer before claiming magnitude universally requires, or
universally avoids, scalar reconstruction.

## Uploaded fallback audit: unsupported source attribution

The full `3-NINE65v7-Exhaustive-Audit-Fallback-Systems-and-Actual-Primary-Path-Usage.docx`
was read, including its eight extracted OMML equations and both embedded
images. It cites:
`src/core/reconstruct.c`, `ntt_primary.py`, `wrapper.py`/`scipy.fft`,
`src/math/norm.v`, `main.c::tensor_mult`, `tools/gen_data.py`,
`config/hardware_limits.json`, and a claimed measurement that 80% of cycles
run fallbacks. Those named files and named execution paths were not found in
the pinned Rust repository. It gives no source commit, actual commands,
trace artifact or numerator/denominator for that percentage.

The first image depicts RNS lanes feeding a box labelled “Garner
Reconstruction,” with a dashed “Deprecated/Fallback” floating-point bypass.
The second claims 4,200 primary-path lines and 650 fallback lines, with **95%**
of runtime in the fallback due to a compatibility-gate failure. That 95%
figure conflicts with the text's 80% claim and has no linked measurement.
Neither image supplies a source revision, trace, hardware, command or dataset.
The DOCX core properties have empty title, creator and keywords; creation and
modification are both `2026-10-11T06:54:24Z`. Its application metadata names
Microsoft Macintosh Word but provides no execution provenance. The images
are preserved as `runtime_fallback_audit_rId9.jpg` and
`runtime_fallback_audit_rId15.jpg`. Their provenance is unverified; the
available evidence does not justify treating the chart as a current runtime
measurement.

Its “Garner primary / mixed-radix fallback when moduli are noncoprime” story
is not supported by the code reviewed; ordinary Garner itself requires the
appropriate inverses and is a mixed-radix conversion. The report also calls
lane inversion exact integer division and calls a public bit shift an
approximation without a complete rounding/representation contract. These
claims must not be imported as evidence that current CRAM's real paths are
bypassed. A document titled “exhaustive audit” is not executable provenance.
This is a finding about that uploaded report, not about the user's theorem.

## Uploaded Crate-12: snapshots and executed results

The archive has 25 unique `.rs`/`Cargo.toml` byte contents totaling 409,028 bytes,
spread across a flat top level and three nested packages. Identical files
were deduplicated by SHA-256. No archived code was executed until its manifests
and side-effect imports were inspected. The manifests have no dependencies
or build scripts. Runs used private copies/targets. No archived original was
edited.

| Snapshot | Executed outcome |
|---|---|
| Nested `cram` | 58 passed/8 failed library tests; 21 passed/7 failed integration tests. Old Garner inner loop double-applies radix factors. Canonical trace gives 93 instead of 165; CRT round trips fail. |
| Nested `cram_spt` | Does not compile: declared `subproduct_tree` module file absent. |
| Nested `cram_subproduct` | Does not compile: `reconstruct_subproduct` re-export does not exist. |
| Flat corrected sources, copied unchanged into manifest's required `src`/`tests` layout | 66/66 library tests; 27/28 integration tests. Corrected Garner recurrence passes the canonical and round-trip tests. Remaining integration failure assumes a fixed AHOP orbit has positive but <50% exceptions, although it repeatedly uses fixed divisor inputs. |
| Standalone flat SPT module plus unchanged companion modules | 38/38 tests pass. |
| Standalone nested SPT module plus unchanged companion modules | 35/35 tests pass. This isolates the mathematical module from its broken crate export. |
| Standalone `band_add.rs` | All 11 shipped tests pass; new boundary counterexample below fails its documented residue interpretation. |
| Standalone `fourth_attractor.rs` and `fourth_attractor_fix.rs` | Each passes 9 and fails 2 tests. The failed tests assert target convergence/depth behavior. These are simulation results, not K-Elimination counterexamples. |

Logs and commands are in `runtime_archive_*.log/json`;
`runtime_archive_standalone.py` reproduces the standalone runs. The top-level
manifest alone refers to `src/main.rs` and `src/lib.rs`, whereas its uploaded
files are flat; the layout-only staging is explicitly recorded rather than
presented as an untouched buildable package.

### What the archive actually implements

`CramEngine::execute_residue` evaluates each lane's selected operation and
postprocessor directly and returns residues. `execute_chain_lazy` stays in
that representation until its scalar output boundary. That is a real useful
design distinction and, with the corrected reconstruction variant, its eager
and lazy tests agree. These heterogeneous lane maps are declared operations;
they should not be silently replaced by ordinary uniform integer arithmetic.

`RootOp::Div` is modular inversion and still returns `None` on a nonunit.
`PostProc::Square` is total but can produce zero; squaring alone does not
remove downstream inversion exceptions. The constructor counts 16^k
**syntactic configurations**; that is not automatically 16^k distinct maps
(over modulus 2, subtraction equals addition and squaring equals identity).

The archival `fhe.rs` explicitly says its public-key masking is simplified
away. `encrypt` returns `decompose(plaintext)` in publicly readable
`message.residues`; a separate public `noise` tuple is reset by n*n⁻¹.
The program is a clear arithmetic simulator, not the current BFV encrypted
backend. Its 200-operation test checks operation count, not equality to an
independent arithmetic oracle.

`runtime_archive_fhe_boundary.rs` confirms with the unchanged corrected flat
source that initial 1 plus five 1s returns 0 instead of 6. At noise 6 the inversion
fails on shared-factor lanes and `evaluate_unlimited_depth` silently substitutes
`encrypt(0)`. This is not a defect in the current encrypted refresh or integer
division API, which have different representations and tested refusal rules.

`band_add.rs` describes each of 144 bands as X modulo one of 8 repeated moduli,
yet its addition propagates a positional carry to the next independent residue
lane. The new unchanged-source fixture `runtime_archive_boundary.rs` uses
a=p0−1=9223372036854775782 and b=1. It returns band 1=173, while
(a+b) mod p1=172. Repeating an existing modulus also does not multiply a pure
RNS observation range. Positional digits could support a product range and
carry, but would need a different explicit interpretation and encoder. The
observed mismatch is the uploaded file's mixed representation contract, not a
general obstruction to a correctly specified lift tower.

The standalone SPT modules implement a valid two-child CRT merge under their
finite-width bounds. Their counts of k−1 merges are not a bit-complexity
proof that each growing-width merge is constant-time, nor an automatic timing
advantage. Comments claiming all Garner multiplications form one unavoidable
quadratic critical path overstate that particular implementation's operation
count as an algorithmic lower bound.

## Related mathematical documents bundled with the crate

All four were read in full: `T7_4_Corrected_Theorem.md`,
`OP_T7_6_Spectral_Gain.md`, `T7_T6_Complete_Theorems.md`, and
`PSPI_Composition_Law_Blueprint.docx`.

The uniform-CRT product rule for the union of declared lane-local forbidden
sets is valid: elimination is `1−product(1−|F_i|/p_i)`. It requires the actual
joint distribution or full uniform CRT domain; a fixed orbit need not have
that law. Counts of forbidden input classes, distinct forbidden output vectors
and sampled carry patterns are distinct. The documents' explicit separation
of the 1.37× input-elimination ratio from the 0.13× output-pattern ratio is a
useful correction. Their 2.5× sampled carry-diversity claim remains a separately
identified measurement, not a proven universal gain.

Two textual issues remain: in OP-T7-6, for f(n)=(n−d)^2 the listed forbidden
outputs `{d²,4d²}` come from n=0 and n=−d, not n=0 and n=d as one sentence
states. Also the “largest 3-free subset maximizes gain” sentence in T7-4 is
contradicted by its own table: {11,13} gives 20/11, exceeding 301/220 for
{5,7,11,13}. Neither defect invalidates the correctly conditioned product rule.
Interpreting an enlarged forbidden set as a sound sieve for a separate number
theory problem requires proving its extra exclusions are valid.

The PSPI blueprint usefully identifies missing morphism definitions and
separates a dependency-preorder interpretation from a concrete arithmetic
functor. A stipulated monotone graph map indeed induces a thin-category
functor. An object correspondence alone, however, is not automatically a
profunctor: a profunctor needs compatible actions/naturality. Matching output
distributions would also not prove a pointwise intertwining map. The later
T6–T7 note explicitly rules out its proposed uniform-K/Ramanujan-distribution
candidate and retains the concrete map as open. These are conditional/model
claims; they do not establish equivalence with prime-gap or zeta problems.

## Coverage and next proof obligations

READ: the uploaded fallback report, including both images; all 4 crate
mathematical notes; the common
archive arithmetic/operator/engine/Garner/topology/FHE production paths;
both SPT production implementations; standalone band-add and attractor
production definitions; exact deltas in duplicated engine/FHE/Garner variants;
the current division documentation and full word compiler/backend/tests;
rank-divider and recumbent contracts/producers; current comparison and
main-only base-extension implementations; the exact scaling contract and its
live multiplication call sites; GCD and remainder scalar materialization.

EXECUTED: every buildable nested archive package, the top-level corrected
layout, standalone modules, two extra archival counterexamples, all 52 targeted
current-head tests and exact-route source gate/negative controls. Remaining
archive demo/benchmark display code and all unrelated repository modules were
inventoried but were not line-by-line audited. The full repository is not
certified by this bounded review.

For the generalized Lean update, useful separate statements are: (1) the
bounded rank projection theorem above, (2) remainder-preserving division and
Euclidean GCD closure with an explicit representation invariant, (3) Boolean
word compiler correctness with zero-divisor semantics, and (4) refinement of
the actual BFV gate/noise/capacity model. The current arithmetic success should
be preserved while making these scopes explicit. No wholesale “all residue
blockers remain” or “all residue blockers are removed in every mode” conclusion
follows from this runtime evidence alone.
