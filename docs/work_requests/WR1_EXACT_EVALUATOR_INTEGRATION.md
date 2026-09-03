# WR-1 — Derived-Transient Exact Evaluator Integration

**Status:** DRAFT / T1.4 implementation request

**Audit baseline:** `main` = `d6b85a2b7c163fab879c104925a1ef620a669043` at the WR-1 design pass on 2026-09-03. Rebase onto current `main` before implementation and record the actual BASE/HEAD SHAs in the final evidence section.

## Objective

Integrate the already-landed `MainOnlyBaseExt` and `ExactScaleRound` kernels into a certified ciphertext-ciphertext evaluator multiply route while keeping ciphertexts, public/evaluation keys, service transport, and returned results on the published main base Q only.

Derive every auxiliary residue inside the operation from main-base residues, use it only as transient D3 scratch, zeroize/drop it before return, and fail closed whenever a basis, capacity, range, route, or key-shape proof is missing.

Implement both:

- exact `mul_no_relin` / degree-2 tensor + scale-and-round; and
- exact public `mul` / degree-1 output using the hybrid main-RNS relinearization specified below.

Do not route WR-1 through `DualRNSCiphertext`, persistent anchor lanes, `KElimination`, or the legacy limb-local `exact_rescale`.

## Non-negotiable invariants

1. **Integer-only arithmetic.** No floating-point values, conversions, estimates, or thresholds on any WR-1 correctness path.
2. **WIRE-Q.** Inputs, outputs, public keys, evaluation keys, and serialized ciphertext state contain only the declared main Q lanes. Auxiliary A lanes exist only in transient operation-local scratch.
3. **No canonical coefficient reconstruction in evaluator hot paths.** Do not call `RNSContext::to_int`, `to_u256_level`, `extract_k_rns_level*`, `extract_digit_dual`, or any equivalent helper that materializes the represented coefficient.
4. **No Garner/MRC walk.** Use parallel CRT-idempotent synthesis/rank identities only. Rename the existing `MainOnlyBaseExt` internal/comment label “Garner coefficients” to “CRT idempotent coefficients” or “synthesis coefficients”; the current formula is parallel CRT synthesis and the prohibited term creates a false source-contract violation.
5. **Centered lift before tensor.** Derive the centered main-to-A lift of each input polynomial coefficient before multiplying in A. Extending the already-wrapped mod-Q tensor cannot recover the required pre-reduction integer tensor coefficient.
6. **Exact scale-and-round after tensor.** Apply `ExactScaleRound` independently to d0, d1, and d2 using main and transient-A residues of the same integer coefficient.
7. **Relinearize after scale-and-round.** Feed the canonical post-rescale d2 into the public relinearization route. Preserve the ordering already established by the corrected evaluator flow: tensor -> exact scale-and-round -> relinearize.
8. **Typed refusal.** Every unsupported route, insufficient basis, oversized fallback accumulator, malformed key shape, or missing certificate returns a typed error at the new exact API boundary.
9. **Legacy containment.** Leave the existing fail-closed single-RNS `mul` guard in place until WR-1 is green. Do not weaken it to make the new route reachable.
10. **No bootstrap as WR-1 oracle.** Issue #117 establishes an independent public-refresh correctness defect. Validate WR-1 with direct encrypt/evaluate/decrypt and independent integer oracles. Re-run #117 only after WR-1 passes its own gates.

---

## Findings that the implementation must resolve

### F1 — T1.4 has not been wired

`ExactScaleRound` has its unit/differential tests but no production caller. Its module explicitly leaves evaluator integration to T1.4. Add a real exact evaluator route rather than modifying its standalone oracle tests and calling the track complete.

### F2 — Canonical main-to-A projection is insufficient for tensor construction

`ExactScaleRound::scale_round(x_main, x_aux, ...)` requires `x_main` and `x_aux` to be residues of the same centered tensor coefficient `Xc`.

For each input coefficient, derive the transient residues of the centered lift before tensor multiplication. Do not base-extend a tensor value after it has already wrapped modulo Q.

### F3 — Existing `RNSEvalKey` relinearization violates the WR-1 evaluator contract

The current main-only `relinearize` calls `decompose_rns_poly`, and that helper reconstructs the coefficient with `self.rns.to_int(&rns_coeff)` before global base decomposition.

Do not reuse that decomposition in the WR-1 exact route. Add the hybrid main-RNS gadget specified in §D below.

### F4 — The landed RNS-limb gadget supplies the correct algebraic direction but needs smaller digits

The existing M3 lane-local gadget removes CRT materialization but measures a depth-3 noise limit when full q_i-sized lane residues are used as digits. Preserve its CRT-idempotent structure and split each lane residue into small base-2^10 digits. This keeps runtime decomposition lane-local while reducing the scalar size carried by each evaluation-key error term.

### F5 — `MainOnlyBaseExt` needs an explicit fallback-capacity construction gate

Its exact rank fallback accumulates `N = sum_i c_i M_i`, with `N < kM`, in `U256`. Add a construction-time proof that the complete fallback bound fits the accumulator. Do not rely on `MAX_LANES = 16` as a numeric capacity certificate.

Use an exact integer check equivalent to:

```text
k * M <= 2^256
```

with the strict form required by the implemented accumulator bounds. Prefer checked `U512` construction/comparison so the proof itself cannot overflow. Return a typed construction error when the bound fails.

---

## A — Add centered derived-transient projection

Extend `MainOnlyBaseExt` with a centered projection API. Suggested signature:

```rust
pub fn project_centered(
    &self,
    main_residues: &[u64],
    out_aux: &mut [u64],
) -> Result<CenteredProjectionPath, MainOnlyBaseExtError>
```

or return the existing `RankPath` plus a test-observable half-decision path. Keep production visibility no wider than needed by WR-1.

For main basis `m_i`, `M = product(m_i)`, `M_i = M/m_i`, canonical input residues `x_i`, and CRT-idempotent coefficients

```text
c_i = x_i * inverse(M_i mod m_i) mod m_i
N   = sum_i c_i * M_i
rho = floor(N / M)
```

the canonical representative is in the upper half exactly when

```text
N >= rho*M + ceil(M/2).
```

Use that comparison directly. Do not form `X = N - rho*M` as a canonical coefficient object.

After the existing canonical projection computes `X mod a_j`, derive the centered transient residue as:

```text
lower half:  Xc mod a_j = X mod a_j
upper half:  Xc mod a_j = (X mod a_j - M mod a_j) mod a_j
```

### A1 — Fast/common path

Reuse the existing certified fixed-point rank interval. Extend the interval proof to decide lower/upper half whenever the complete uncertainty interval lies on one side of `M/2`.

### A2 — Exact fallback

When the fixed-point interval touches an integer-rank or half-Q decision boundary, form the already-permitted bounded parallel idempotent sum `N` and compare it with:

```text
rho*M + ceil(M/2)
```

Use fixed-width exact comparison. Do not double `N` if doing so can overflow the U256 accumulator.

### A3 — Required tests

Exercise both common and exact-fallback paths and pin:

- `0`, `1`, `(M-1)/2`, `(M+1)/2`, `M-2`, `M-1`;
- negative centered witnesses represented through canonical main residues;
- exhaustive small bases;
- deterministic production-basis random vectors;
- aux ordering permutations where the API permits them;
- malformed/noncanonical residues;
- fallback-capacity refusal.

The integer oracle `scripts/verify_wr1_transient_exact.py` already pins the underlying identity and a load-bearing witness where canonical `M-1` must become centered `-1` in A.

---

## B — Construct a certified transient-A plan per evaluator configuration

Add a precomputed WR-1 plan to `RNSFHEContext` or to a dedicated exact evaluator object. Construct it once per immutable FHE configuration, not once per coefficient.

Suggested contents:

```text
ExactMulPlan
  main primes
  transient aux primes
  centered main->aux projector
  ExactScaleRound
  NTT engines for transient lanes when polynomial multiplication uses NTT
  hybrid-relin shape/base certificate
  exact capacity certificates
```

Do not store A residues in `RNSCiphertext`, `RNSPublicKey`, `RNSEvalKey`, service session state, or serialized artifacts.

### B1 — Auxiliary selector

Use the existing deterministic NTT-compatible prime catalog numerically as a candidate pool, but instantiate it as WR-1 transient D3 scratch only. Do not construct a `DualRNSContext` and do not attach these primes to public ciphertext state.

Select the shortest prefix satisfying all of:

```text
for every q_i in Q and a_j in A: gcd(q_i, a_j) = 1
for every a_j: (a_j - 1) mod (2N) = 0
A = product(a_j)
A > 2 * (N/4 * t + 1) * Q
```

The exact integer oracle currently certifies these minimum prefix sizes for `t = 65537`:

| Config | N | main Q lanes | minimum transient A lanes | A bits | required bits |
|---|---:|---:|---:|---:|---:|
| `secure_128` | 8192 | 3 | 4 | 125 | 118 |
| `secure_128_deep` | 8192 | 4 | 5 | 157 | 147 |
| `secure_192` | 16384 | 5 | 6 | 188 | 175 |
| `secure_256` | 16384 | 6 | 7 | 220 | 204 |

Recompute these from the live config and candidate pool at construction. Do not hard-code the table as the proof.

### B2 — Scratch ownership

Allocate transient A polynomials inside one multiply call or one reusable evaluator-owned scratch arena that cannot be serialized or observed as ciphertext state. Zeroize before release/reuse according to the WR-1 acceptance contract. Key-generation scratch derived from `s` or `s^2` must use `Zeroize`/`ZeroizeOnDrop` ownership.

---

## C — Exact tensor + scale-and-round route

For each input `RNSCiphertext` component c0/c1:

1. validate structure and canonical main residues;
2. convert from Montgomery/NTT representation only as required by the established RNS polynomial APIs;
3. derive centered A residues coefficientwise with §A;
4. construct transient A polynomial limbs;
5. transform/multiply in each main and A lane using matching negacyclic-ring semantics;
6. build the degree-2 tensor:

```text
d0 = a.c0 * b.c0
d1 = a.c0 * b.c1 + a.c1 * b.c0
d2 = a.c1 * b.c1
```

7. for every coefficient of d0/d1/d2, feed the matching main and A residues into `ExactScaleRound::scale_round`;
8. emit only main-Q residues for e0/e1/e2;
9. zeroize/drop all A scratch.

Expose a testable degree-2 exact route for `mul_no_relin` so the oracle can isolate tensor/scale-round from relinearization.

Do not call the old limb-local `exact_rescale` on this route.

---

## D — Add hybrid main-RNS × base-2^10 public relinearization

Add a new evaluation-key type rather than changing the meaning of `RNSEvalKey` fields.

Suggested shape:

```rust
pub struct RNSHybridGadgetKey {
    pub base_bits: u32,
    pub digits_per_lane: usize,
    pub rlk: Vec<Vec<(RNSPolynomial, RNSPolynomial)>>,
}
```

Flattening is acceptable if lane/digit indexing is explicit and validated.

Use `base_bits = 10` for the first implementation and measure before changing it. The current production q_i lanes need three digits each.

### D1 — Algebra

For post-rescale d2 polynomial `P`, main lane `q_i`, and CRT idempotent `g_i`:

```text
[P]_{q_i} = sum_j delta_{i,j} * B^j
B = 2^10
0 <= delta_{i,j} < B

P = sum_i g_i * [P]_{q_i} mod Q
  = sum_i sum_j delta_{i,j} * (g_i * B^j) mod Q.
```

Generate one relinearization-key encryption of:

```text
g_i * B^j * s^2
```

for each `(i,j)`.

### D2 — Do not materialize `g_i`

Construct the message directly in main-RNS form. The CRT-idempotent image is:

```text
lane h == i: B^j * s^2 mod q_h
lane h != i: 0
```

This removes any need to construct `Q/q_i`, multiply it into a wide `g_i`, or reconstruct a coefficient.

Encrypt this RNS message using the same secure RNG/key-generation discipline as the existing evaluation-key generator.

### D3 — Runtime decomposition

For every coefficient in source main lane `i`, extract its three local base-2^10 digits with shifts/masks on the canonical `u64` lane residue. Create/broadcast the small digit polynomial into the existing RNS polynomial multiplication shape and accumulate against the `(i,j)` key pair.

Do not call `decompose_rns_poly`; its current global path reconstructs coefficients with `RNSContext::to_int`.

### D4 — Relinearization order

Run hybrid relinearization on e2 after exact scale-and-round:

```text
(e0, e1, e2) ->
  c0' = e0 + hybrid_relin_0(e2)
  c1' = e1 + hybrid_relin_1(e2)
```

The returned `RNSCiphertext` remains Q-only.

### D5 — Algebra oracle already pinned

`scripts/verify_wr1_hybrid_relin.py` checks the identity in `Z_q[X]/(X^N+1)` using integer-only arithmetic for all named production main bases. The current gate covers 64 deterministic samples per configuration at a compact ring dimension and produces:

```text
secure_128:      1536 exact coefficient/lane checks
secure_128_deep: 2048 exact coefficient/lane checks
secure_192:      2560 exact coefficient/lane checks
secure_256:      3072 exact coefficient/lane checks
TOTAL:           9216
```

The Rust implementation still must measure RLWE noise and complete the public-key ciphertext/decrypt oracle; the algebra harness does not substitute for those gates.

---

## E — Route/API integration

Add an explicit exact route variant, for example:

```text
MulRoute::DerivedTransientExact
```

and a typed construction/runtime error family.

Prefer additive APIs during WR-1:

```rust
try_mul_no_relin_exact(...) -> Result<ExactTensor3, ExactMulError>
try_mul_exact(...)          -> Result<RNSCiphertext, ExactMulError>
```

Keep the current legacy `RNSFHEContext::mul` fail-closed route guard untouched until the exact route passes WR-1 and WR-2 differential/WIRE-Q closure. After WR-2, dispatch can be consolidated without losing a typed failure boundary.

A selected `DerivedTransientExact` route must have zero legacy limb-local rescale calls.

---

## F — Source-call-graph denylist

Add a deterministic source scanner and a runtime counter/guardrail where practical. On every function reachable from the WR-1 exact evaluator route, require zero calls to:

```text
RNSContext::to_int
to_u256_level
extract_k_rns_level*
extract_digit_dual
k_elim_rescale_dual
k_elim_rescale_manufactured
DualRNSContext / DualRNSCiphertext conversion paths
BaseExt redundant-lane projection
CompareBit::decide_ct
legacy RNSFHEContext::exact_rescale
```

Also fail the exact-route source gate on evaluator-side Garner/MRC terminology or implementation helpers. Permit the bounded `U256`/`U512` parallel idempotent-sum fallback used solely to certify rank/half decisions, provided no canonical coefficient is materialized from it.

Make every counter test non-vacuous: temporarily insert one forbidden call locally, prove the guard fails, revert, then commit only the green form.

---

## G — Acceptance matrix

Complete these gates in order. Do not merge after an earlier row alone passes.

### G1 — Independent integer arithmetic gates

```bash
python3 scripts/verify_wr1_transient_exact.py
python3 scripts/verify_wr1_hybrid_relin.py
```

Expected current evidence:

- derived-transient gate: all four named configurations pass, including centered projection, transient tensor, exact scale-and-round, coprimality/NTT/capacity certificates;
- hybrid-relin algebra gate: 9216 exact checks pass.

### G2 — `MainOnlyBaseExt::project_centered`

- exhaustive small-basis oracle;
- production-basis deterministic random oracle;
- exact half-boundary vectors;
- common path observed;
- exact fallback observed;
- fallback accumulator over-capacity configuration rejected with typed error.

### G3 — Exact `mul_no_relin`

Keep the existing Track-1 failing vectors unchanged and route them through the new exact degree-2 evaluator path. Compare d0/d1/d2 after scale-and-round coefficientwise with an independent bigint/integer oracle.

Include cases where `Delta^2 > Q`, negative centered tensor coefficients, rounding boundaries, and the largest declared operand bounds.

### G4 — Hybrid relinearization

- key-message construction matches `g_i * B^j * s^2` lanewise;
- zero coefficient reconstruction/materialization counters;
- deterministic ciphertext oracle with direct decrypt;
- measured noise before/after relin for every named production config;
- eval-key serialized shape contains main-Q RNS polynomials only;
- malformed lane/digit dimensions rejected.

### G5 — End-to-end public multiply

For each of:

```text
secure_128
secure_128_deep
secure_192
secure_256
```

run direct:

```text
keygen -> encrypt(a), encrypt(b) -> try_mul_exact -> decrypt
```

against exact plaintext multiplication modulo t over deterministic edge vectors plus seeded random vectors.

Do not insert bootstrap/refresh into this gate.

### G6 — Repeated multiplication

Measure exact repeated-square/product depth with no refresh first. Record where noise becomes the limiting condition. A wrong plaintext before the measured noise boundary is a WR-1 failure, not a budget result.

### G7 — WIRE-Q

Prove:

- returned ciphertext has only main Q limbs;
- exact-route public/evaluation key has no auxiliary A fields;
- serialized exact-route ciphertext/key artifacts contain no A residues;
- transient A storage is unreachable from service/wire DTOs;
- scratch is zeroized/dropped before return.

WR-2 will perform the broader differential/WIRE-Q closure after WR-1 lands; WR-1 must still make its own route structurally Q-only.

### G8 — Full Rust gates

Run from a Rust-capable environment:

```bash
cargo fmt --all -- --check
cargo build -p nine65 --release
cargo test -p nine65 --lib --release
cargo test -p nine65 --test residue_space_ciphertext --release
cargo test -p nine65 --test full_system_exercise --release
```

Add targeted WR-1 integration tests and run them explicitly. Record exact command output and pass counts.

GitHub Actions issue #79 is an account/repository execution blocker, so a queued/non-running Actions result does not count as WR-1 validation. Attach local Rust-capable build/test evidence until Actions is restored, then require CI again before release closure.

---

## H — Evidence to record in this PR

Before marking PR #111 ready for review, add one final evidence section containing:

- rebased BASE SHA;
- final HEAD SHA;
- exact `(N, Q-primes, t, A-primes, B, digits-per-lane)` tuple per config;
- capacity inequality values in integer form;
- integer-only oracle outputs;
- targeted Rust test outputs;
- full lib/workspace pass counts;
- source-call-graph denylist output;
- direct public encrypt/mul/decrypt oracle results;
- repeated-multiply/noise traces;
- scratch allocation and zeroization evidence;
- serialized Q-only shape evidence;
- before/after integer timing measurements for tensor, scale-round, relin, and full mul;
- any remaining issue numbers with precise dependency direction.

Do not use percentages derived through floating-point timing/math paths. Store raw integer durations (for example ns) and exact integer ratios where comparisons are required.

---

## I — Dependency boundary

WR-1 supplies the exact evaluator multiply primitive required by the next critical-chain steps. Keep these separate:

```text
WR-1 exact evaluator multiply
  -> WR-2 differential + WIRE-Q closure
  -> public bootstrap replacement
  -> per-ciphertext refresh state
  -> stress/depth closure
```

Issue #117 remains a separate bootstrap/refresh correctness defect. Once WR-1 and WR-2 are green, re-run the #117 minimal reproducer with the new evaluator route to determine which remaining failure belongs solely to the refresh pipeline.

Issue #67 remains under its standing deferral until the production FHE architecture is exact/stable; WR-1 does not change that policy decision.

---

## Merge gate

Keep PR #111 in draft until all G1-G8 gates that can execute in the current environment are green, all Rust-required gates have attached evidence from a Rust-capable environment, and the branch is rebased onto current `main` without weakening any fail-closed boundary.

The two Python scripts establish the arithmetic design and catch regressions. They authorize implementation work; they do not by themselves authorize merge.