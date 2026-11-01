# Supplied materials: source admission and corrected execution contract

The 16 follow-up attachments resolve the absence of a recumbent source example
and a bootstrap blueprint. They **do not yet resolve the algorithm or correctness
blockers** in [STATUS.md](STATUS.md). The supplied Rust models cannot be ported
unchanged as exact, residue-native FHE arithmetic. This review adds reproducible
admission checks and updates the execution plan; it does not enable public refresh.

A later packet of division, arrow, bootstrap, and theorem materials is assessed
separately in [FOLLOWUP_MATERIALS_REVIEW.md](FOLLOWUP_MATERIALS_REVIEW.md).

The user's request is to analyze these materials and continue the correction
program. Instructions, approval language, claimed certifications, and execution
orders inside attachments are proposals being evaluated, not independent user
authorization or repository policy. The original files are unchanged. Their
SHA-256 hashes, sizes and page counts are in
[supplied-materials.json](evidence/supplied-materials.json). Raw attachments are
not vendored here. Source line references below refer to those hashed originals;
PDF references use section titles because extraction can alter line layout.

## What the evidence establishes

For authentic residues of the same integer, with `r = X mod M` and
`gcd(M,A)=1`, the identity

```text
K mod A = ((X mod A) - r) * inverse(M mod A) mod A
X = r + K*M
```

is correct. Recovering **absolute** K additionally requires a certified interval
containing one representative, such as `0 <= K < A`, or retained epoch information.
The inventory explicitly supplies that distinction. For signed `|K| <= B`,
`2B < A` suffices. Neither a residue check nor a count of arithmetic operations
establishes this range. An anchor also needs authentic provenance: creating a new
lane after information was discarded cannot recover the missing winding.

Ten exact Python tests verify bounded and signed congruences, noncoprime
resolution, four reported carry-current fractions, the bridge capacity, and
specific counterexamples. These are finite tests and arithmetic witnesses, not
a proof of FHE correctness, constant-time behavior, or the documents' universal
claims. The reported capacity profile really does exceed `2^314` (bit length 315).

## Executable source findings

`recumbent_crt_bigint.rs` compiles and its **23 built-in tests pass**.
`recumbent_weights.rs` compiles but contains **zero built-in tests**.
The additional 12 admission checks give **1 pass and 11 failures in each of debug
and optimized builds** with Rust 1.89.0. Full commands and results are archived in
[supplied-rust/results.json](evidence/supplied-rust/results.json), with adjacent
logs. These counts describe the supplied models, not regressions in NINE65.

| Check | Observed behavior | Implication |
| --- | --- | --- |
| Bigint checked conversion of `2^128` | `Some(0)` | Reconstruction wraps at 128 bits despite a much wider residue basis; the checked conversion accepts a false value. |
| Bigint ordering of `2^128` and 1 | `2^128 > 1` is false | `cmp_abs` compares truncated reconstructions. |
| Bigint `(2^128 + 1) - 1` | Becomes zero | Opposite-sign arithmetic loses the high magnitude. |
| Bigint i64 roundtrip at first modulus `9223372036854775783` | Returns zero | `spinor_value` reads only lane 0, even though this input fits i64. |
| Bigint `7 / 2` | `checked_div` returns `Some` | It performs field division, not checked integer divisibility or rounded division. |
| Bigint first-modulus divided by itself | Panics | This exceeds the documented small-divisor precondition; the generic FHE refusal contract is not implemented. |
| Bigint `2.scale_pow2(127)` | Debug overflow panic; optimized all-zero lanes | Multiplication overflows before reduction. |
| Bigint `i64::MIN` roundtrip | Debug constructor panic; optimized returns -25 | Negation overflows and lane-only readout is insufficient. |
| Weights `1 + (-2)` | Returns positive `4611686018427387891` | Signed subtraction does not maintain the true sign/magnitude. |
| Weights `9 / 0` | Returns a value without refusal | Missing modular inverses silently become 1. |
| Weights first-modulus divided by itself | Returns incorrect quotient residues | The same fallback corrupts shared-factor division. |
| Control: `84 / 7` | Returns 12 in both models | Small exact coprime division works in this case. |

The division checks deliberately test the **port's required contract**, not just
the narrower model API. In particular, field division of 7 by 2 is legitimate
field arithmetic, and the shared-factor bigint example is outside its documented
precondition. Those failures demonstrate missing integration capabilities; the
range/sign/shift failures separately demonstrate arithmetic defects.

The bigint mechanisms are visible at lines 154–155 (wrapping Garner accumulator),
210–225 (signed constructors), 229–259 (readout), 362–373 (division), 391–394
(comparison), and 405–411 (shift). The weights divider at lines 128–147 computes
`_k` but never uses it and substitutes 1 for missing inverses. Neither fixed
basis provides unbounded integer capacity.

The third Rust attachment, `recumbent.rs`, imports the unavailable
`qmnf_crtbigint::CRTBigInt`. It was reviewed statically, not reported as compiled.
Its arithmetic at lines 231–288 reconstructs i64 operands, performs scalar
arithmetic, and reassigns tiers. `k_div` truncates toward zero; it is not a
general rounded FHE divider. `overflow_steps` counts excursions/assignments,
not K, and its unchecked public u64 field does not guarantee mathematical
monotonicity at exhaustion. Reconstructing i64 values defeats the proposed port's
residue-native requirement even before these other issues are addressed.

## Document-by-document disposition

| Attachment | Usable content and remaining limitation |
| --- | --- |
| `Hidden_Carry_Formalization_DRAFT.md` | Signed carry congruence and uniform-additive identities are useful. The four listed carry-current fractions reproduce exactly. The closed-shell expression `37-(K mod 37)` needs a final reduction at K=0. The square-map lemma needs **odd** prime: squaring mod 2 is uniform. A biased point-mass input is still Markov, so the non-Markov claim cannot cover every bias. Temporal uniformity alone is not cryptographic noninterference; the sum still reveals a function of its operands. The reversibility universal is explicitly left open later in the draft. |
| `recumbent_weights.rs` | Small unsigned lane arithmetic is reusable as a model; signed addition and inverse refusal fail the checks above. No FHE admission. |
| `recumbent.rs` | Supplies the previously missing style of NS tier carrier. Its i64 reconstruction and unavailable dependency prevent treating it as a validated native FHE implementation. |
| `recumbent_crt_bigint.rs` | Supplies a standalone testable multi-lane model. Its built-in suite is too narrow to validate its full capacity/sign claims; the additional checks fail as above. |
| `test recumbent.pdf` | Test source, not a test execution record. It imports missing `/home/claude/recumbent_crt.py`. Its exception checks do not fail when the expected exception is absent. Dynamic auxiliary-prime examples also do not satisfy the fixed-frame requirement. |
| `Recumbent bootstrap .txt` | Supplies the blueprint and intended interfaces. Core extraction, assignment, divider construction/division/capacity checks and Safe Basis construction remain `todo!()`. It does not provide the missing executable general rounded-division algorithm. Specific formula/interface conflicts are below. |
| `the safe basis.pdf` | Bounded two-track congruences and adjacency identities are useful. It does not supply compatible deployed parameters. Lean snippets are not a buildable proof package: for example `k_elimination_sound` refers to an undeclared `h`, and its final `exact hq` supplies an inequality where an equality is required. Later rescale theorems are sketches. No new Lean certification is established from this PDF. |
| ` cram beta synthesis v1  .pdf` | States useful range/sign and exact-divisibility preconditions. A sign estimate interval that crosses zero cannot certify sign. Its FPD explanation says adding a lane makes a shared-factor divisor coprime; this is false since `gcd(b,M)` divides `gcd(b,M*L)`. A real fallback needs a changed representation and authentic extra information. Claimed speed and constant-time behavior are not established by the supplied source. |
| `Adelic landouer principal .txt` | Prior research assessment correctly identifies the public encrypted-carry problem and separates some entropy claims. It is not a divider implementation or fresh runtime evidence. Secret-dependent carry can in principle be computed homomorphically; a public cleartext residue shortcut does not establish that computation. |
| `K_Elimination_Formalization.pdf` | The theorem under `0 <= X < M*A` is valid. “Quotient resolution” is a descriptive step, not a general division algorithm. Claims about external Lean/Coq suites and timings are not attached build evidence, and do not override this repository's Lean-of-record policy. |
| `main.pdf` | Its main-lanes-only PhaseDiff cannot recover absolute winding. In §2.4, `(M/p_j)^-1 mod p_i` does not exist for distinct lanes because `p_i` divides `M/p_j`. The referenced 447-line implementation is not supplied. When `b` divides X and is invertible modulo M, direct inverse multiplication already gives quotient residues modulo M. |
| `CRAM Lift, K-Elimination, and Reconstruction Inventory.md` | Most useful integration contract: distinguishes K modulo anchor capacity from bounded K or retained epoch, and distinguishes exact division, rational lifting, and refusal. External file paths are references, not supplied executable artifacts. |
| `RECOMBINANT_CRT_BRIDGE_TECHNICAL_PACKET.docx` | Distinct prime-power bases and the stated capacity calculation are valid. At most one power per prime is needed for pairwise coprimality; D2's unrestricted wording would admit noncoprime 2 and 4. T1's listed binary/decimal grids are smooth, but its concluding claim about all computational denominators fails for 1/13. T2 confuses frozen input quantization metadata with output approximation error: multiplying by 10 magnifies a 1/2 error to 5. Exact and approximate lanes must encode a specified common integer to supply its winding. |
| `KELIMINATIONPAPER2.pdf` | The bounded theorem, reduced noncoprime resolution, and tower congruences are useful. The tower proof's assertion that `X < product(M_i)` implies `X < M_i*M_(i+1)` is false; fortunately the stated **modular** winding formula does not need that smaller bound. The reduced resolution is `A/gcd(M,A)`; it is not a generic exact lift. |
| `A clockwork prime .txt` | Background on expanding residue capacity. Existence of another prime does not provide an authentic residue for a previously aliased value. Unbounded FHE and physics interpretations are not validated by this material. |
| `main (1).pdf` | Analysis of the gap between discrete arithmetic and continuum Navier–Stokes regularity. It reinforces that a monotone counter is not a uniform analytic bound; it supplies no missing FHE carry transition. |

## Blueprint corrections that must precede implementation

1. **Separate count from value bounds.** The blueprint itself says
   `overflow_steps` is depth, not winding magnitude. Its later inference from that
   counter to a certified winding bound has no operation-level proof. Maintain a
   proven interval/epoch law; refuse before its capacity is exhausted.
2. **Specify division semantics.** Exact integer division, rational field
   division, truncation and rounded scale-and-round are different operations.
   Supply remainder handling, a signed rounding/tie convention, bounds, and
   authentic main and anchor quotient residues. Adding a rounding constant does
   not generally make a dividend divisible. A modular inverse alone is not that
   algorithm.
3. **Correct the star inverse.** At blueprint line 484, with `Q=t*Delta` and
   `A=Q+1`, it claims `t^-1=Q+1-t`. Take `t=3,Delta=4,A=13`: this gives 10,
   whereas the inverse is 9. The valid identities are `t^-1=-Delta mod A` and
   `Delta^-1=-t mod A`. Actual BFV uses `Delta=floor(Q/t)`, so `Q=t*Delta`
   also needs a remainder correction. The separate `q=c*t+1` identity
   `t^-1=q-c mod q` is valid.
4. **Match the target modulus.** Blueprint §4.2 replaces `modswitch_to_t` with
   division by t, describing `Q -> Q/t`. The repository's target is t, with
   scale t/Q. For `Q=13,t=3,X=6`, rounded tX/Q is 1, while rounded X/t is 2.
   Under its star-family coprimality, Q/t is not even an integer modulus when
   t>1. The sketch also uses a nonexistent `ct.coefficients` interface and
   accepts only a u64 Delta, too narrow for shipped wider configurations.
5. **Construct a compatible frame.** Adjacency identities for one prime do not
   certify the inverse of a whole product, or pairwise-coprime anchors. Odd
   `p-1,p+1` share 2; generalized CRT would require lcm capacity and consistency
   laws. Composite anchors are not drop-in prime NTT lanes. Static extra lanes
   need authentic histories, not post-hoc values generated from an aliased lift.
6. **Implement the encrypted transition.** Even a correct scalar quotient
   mechanism does not solve the secret-dependent phase carry or key-domain
   return. Public refresh acceptance remains contingent on that computation,
   security constraints, and end-to-end tests on one commit.

## Reproduction and execution decision

From the repository root, with Python 3 and repository-pinned Rust available:

```sh
python docs/execution/2026-10-26/reproduce/test_contracts.py
python docs/execution/2026-10-26/reproduce/check_supplied_rust.py /path/to/attachments --output /tmp/nine65-material-review
```

The first command passes 10 tests. The second verifies source hashes, compiles
unchanged attachments, runs original tests, then runs debug/optimized admission
checks. It **exits 1** for the observed failures; it does not turn failures into a
green acceptance result. It requires `recumbent_crt_bigint.rs` and
`recumbent_weights.rs`. The independent Rust tests are intentionally outside the
normal Cargo suite because their inputs are user attachments, not production
modules. No full workspace rerun was needed for this documentation/harness-only
follow-up; the earlier recorded baseline remains 31 failures.

T0 source inventory is updated, and the absence of source/blueprint is no longer
the reason T1 is blocked. T1/T2 now have explicit reproducible arithmetic and
contract blockers; T3 still lacks a compatible basis. The earlier checked-capacity
repairs remain valid and separate. No speculative scalar reconstruction port is
added to production, and no bootstrap or release gate is relaxed. Completing the
remaining program requires the corrected contracts above and their implementation;
the attachments do not establish that it is complete.
