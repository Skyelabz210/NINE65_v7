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
A > 2 * (N/2 * t + 1) * Q
```

**Owner decision 2026-09-05 — the operand bound is `N/2`, not the `N/4` originally
written here.** `N/4` bounds a single negacyclic product of centered inputs
(`|coeff| < N*Q^2/4`); `d1 = a0*b1 + a1*b0` is the sum of two such products, so
`|d1| < N*Q^2/2`, and `N/4` under-declares it by exactly one bit. The bound
stays at `N/2` (`x_bound_over_q_sq = N/2`, `s_mult = N/2 * t + 1`). Do not round
the two halves of `d1` separately to fit `N/4`: `round(x) + round(y) !=
round(x + y)`, and that would break the exact BFV rule this track exists to
preserve. The one extra required bit costs zero additional auxiliary lanes on
every shipped configuration (see "Configuration tuples and capacity
certificates" in §H below).

The exact integer oracle currently certifies these minimum prefix sizes for `t = 65537`:

| Config | N | main Q lanes | minimum transient A lanes | A bits | required bits |
|---|---:|---:|---:|---:|---:|
| `secure_128` | 8192 | 3 | 4 | 125 | 118 |
| `secure_128_deep` | 8192 | 4 | 5 | 157 | 147 |
| `secure_192` | 16384 | 5 | 6 | 188 | 175 |
| `secure_256` | 16384 | 6 | 7 | 220 | 204 |

The `required bits` column above is the oracle's `N/4` figure. Under the accepted
`N/2` bound the requirement is one bit higher — 148 for the shipped 4-prime
`secure_128`/`secure_128_deep` tuple, 176 for `secure_192`, 205 for `secure_256` —
and the minimum lane counts are unchanged. The `secure_128` row describes the
retired 3-prime chain; the shipped `secure_128` is the 4-prime tuple, i.e. the
`secure_128_deep` row.

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

**Owner decision 2026-09-05 — `try_decrypt_exact` stays as implemented.** It is
verification-side only: reachable only through `try_exact_evaluator()`, never
from `mul_auto`, `AutoBootstrapEvaluator` or the service layer; it refuses with a
typed error when the main lanes disagree on the scaled plaintext. It is not
constant-time — the `MainOnlyBaseExt` rank fallback is fixed-work, but whether
it is taken depends on the decrypted coefficient — and it does not need to be:
constant-time hardening belongs to the production decrypt paths and the existing
CT roadmap, not to WR-1. Document the restriction; do not harden or otherwise
modify it under this work request.

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

**Owner decision 2026-09-05.** The `N/2` operand bound (§B1) and the
non-constant-time `try_decrypt_exact` (§E) are accepted as recorded. PR #111 may
leave draft once a second independent review of (1) the centered-lift-before-
tensor order and (2) the hybrid gadget relinearization algebra has been
completed and recorded on the PR.

---

## H — Evidence (T1.4/T1.5 implementation pass)

**BASE:** `f841642` (`origin/main` at the time of the rebase — the PR's original
base `d6b85a2`/`4b3c9f6` was 24 commits stale and was rebased away, cleanly:
the four pre-existing WR-1 commits only add documents and scripts).

**Route entry points.** `RNSFHEContext::try_exact_evaluator()` ->
`ExactMulEvaluator::{try_mul_no_relin_exact, try_mul_exact, try_decrypt_exact,
generate_hybrid_gadget_key_with_rng}`, all in
`crates/nine65/src/ops/exact_mul.rs`. `MulRoute::DerivedTransientExact` is
added but never returned by `mul_route()`.

### Configuration tuples and capacity certificates

Printed by `aux_lane_counts_match_the_integer_oracle`, recomputed from the live
config at plan construction (never read from a table):

| config | N | Q lanes | log2(Q) | A lanes | log2(A) | required = log2(2*s_mult*Q) | s_mult | B | digits/lane |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `secure_128` | 8192 | 4 | 119 | 5 | 157 | 148 | 268439553 | 2^10 | [3,3,3,3] |
| `secure_128_deep` | 8192 | 4 | 119 | 5 | 157 | 148 | 268439553 | 2^10 | [3,3,3,3] |
| `secure_192` | 16384 | 5 | 146 | 6 | 188 | 176 | 536879105 | 2^10 | [3,3,3,3,3] |
| `secure_256` | 16384 | 6 | 175 | 7 | 220 | 205 | 536879105 | 2^10 | [3,3,3,3,3,3] |

The A-lane counts equal the integer oracle's certified minimums for the tuples
actually shipped. (The oracle's own `secure_128` row uses the retired 3-prime
chain; the shipped `secure_128` is the 4-prime tuple, i.e. the oracle's
`secure_128_deep` row.)

### Recorded deviation from §B1: operand bound is `N/2`, not `N/4`

`N/4` is the correct bound for a **single** negacyclic product — each output
coefficient sums exactly `N` terms of magnitude at most `((Q-1)/2)^2`. But
`d1 = a.c0*b.c1 + a.c1*b.c0` is the **sum of two** such products, so
`|d1 coeff| < N*Q^2/2` and `N/4` under-declares it by exactly one bit.
`scripts/verify_wr1_transient_exact.py` does not catch this because it verifies
one product and never the `d1` sum.

Rounding the two halves of `d1` separately would not fix it
(`round(x)+round(y) != round(x+y)` breaks the exact BFV rule), so the declared
bound is raised. Cost: one required bit (147->148, 175->176, 204->205) and
**zero** additional auxiliary lanes on every named configuration — pinned by
`aux_lane_counts_match_the_integer_oracle`, which builds both plans and asserts
the lane counts are equal and the requirements differ by exactly 1 bit.

### G1 — integer oracles (unchanged by this pass, re-run post-rebase)

```
$ python3 scripts/verify_wr1_transient_exact.py
secure_128: PASS; aux_lanes=4; aux_bits=125; required_bits=118; checks=20064
secure_128_deep: PASS; aux_lanes=5; aux_bits=157; required_bits=147; checks=20080
secure_192: PASS; aux_lanes=6; aux_bits=188; required_bits=175; checks=20096
secure_256: PASS; aux_lanes=7; aux_bits=220; required_bits=204; checks=20112
WR-1 gate: PASS; exact_checks=80353

$ python3 scripts/verify_wr1_hybrid_relin.py
WR-1 hybrid relin gate: PASS; exact_checks=9216
```

### G2 — `MainOnlyBaseExt::project_centered`

`cargo test -p nine65 --lib --release -- main_only_base_ext exact_scale_round`
-> **17 passed, 0 failed** (13 before this pass). New: exhaustive small-basis
centering with the half decision checked against `X >= ceil(M/2)`; production
4/5/6-lane prefixes against a `U512` ground truth including both half
neighbours and both endpoints, with both rank paths required to execute; the
oracle's load-bearing witness (canonical `M-1` -> centered `-1`); typed
rejection of a non-canonical residue through the centered entry point; and the
F5 fallback-capacity refusal (9 lanes refused, 8 accepted).

### G3-G7 — the route

`cargo test -p nine65 --lib --release -- exact_mul::tests`
-> **23 passed, 0 failed, 0 ignored** in 7.6s.

- **G3** 8640 coefficient/lane checks bit-identical to an independent
  arbitrary-precision oracle (own limb type, own schoolbook multiply/divide,
  own `O(N^2)` convolution; touches no crate arithmetic type), across the
  4/5/6-lane production chains, structural corners, negative centered
  coefficients, the negacyclic fold, and 24 seeded random ciphertext pairs per
  chain. Both rank paths execute *inside the evaluator*: certified 22605,
  fallback 6195.
- **G3 (ties)** 78 exact rounding-tie and neighbour points, reached through the
  real evaluator by placing `x` on `Q*(2j+1)/(2t)`.
- **G3 (invariant 5 non-vacuity)** `oracle_rejects_the_wrapped_tensor_shortcut`
  shows the F2 shortcut disagrees with the exact rescale on most coefficients.
- **G4** gadget-key messages match the CRT-idempotent image lanewise (checked
  against an independent reconstruction, to within the CBD error); relin output
  is within the gadget error bound against the oracle; malformed lane/digit/base
  shapes are typed refusals.
- **G5** `keygen -> encrypt -> try_mul_exact -> decrypt` exact mod `t` on all
  four named configs at their real `N`, plus centered (`m > t/2`) and seeded
  random plaintext pairs. No bootstrap or refresh anywhere (invariant 10).
- **G6** measured exact repeated-square depth with no refresh:
  `secure_128` = 3, `secure_192` = 4, `secure_256` = 5. Each run terminates on a
  *wrong plaintext at the noise limit*, not on a round cap or a typed refusal.
- **G7** the emitted ciphertext is structurally identical to a fresh `encrypt`
  output (same `num_primes`, limb count, ring degree, limb lengths, canonical
  residues, passes `RNSCiphertext::validate`); the gadget key carries only
  main-`Q` `RNSPolynomial`s. Neither `RNSCiphertext` nor `RNSHybridGadgetKey`
  has a `serde` derive, so there is no auxiliary field that *could* be
  serialized.

### §F — source-call-graph denylist

```
$ python3 scripts/check_wr1_exact_route_denylist.py --self-test
WR-1 §F denylist self-test: PASS; 16 injected constructs all detected
$ python3 scripts/check_wr1_exact_route_denylist.py
WR-1 §F denylist: PASS; 3 route sources, 1964 production lines, 19 patterns, 0 violations
```

The self-test injects each forbidden construct into a scratch copy and requires
the scanner to report it, so no pattern can pass vacuously.

`DualRNSContext::canonical_anchor_primes_for_n` is the one permitted mention:
§B1 authorises the catalog as a numeric candidate pool, and the scanner denies
every other `DualRNSContext::` associated function plus every `DualRNS*` type.

### Depth and timing against the existing route

Diagnostic, `--ignored`, same seed and round cap, asserting nothing about the
dual route:

```
DEPTH secure_128: WR-1 exact (main-Q only) = 3; existing mul_dual_public = 3
DEPTH secure_192: WR-1 exact (main-Q only) = 4; existing mul_dual_public = 3
DEPTH secure_256: WR-1 exact (main-Q only) = 5; existing mul_dual_public = 3
```

At least as deep everywhere, and deeper at 192/256 — while carrying no
serialized anchor lane.

Stage timings, medians of five rounds, **raw integer nanoseconds** (§H forbids
percentages computed through floating point, so nothing here divides). Every
timed round also decrypts and asserts the correct plaintext, so no number comes
from a wrong answer. `mul_dual_public` is timed in the same process, back to
back, for scale only:

| config | tensor+scale_round | relin | full mul | decrypt | reference `mul_dual_public` |
|---|---:|---:|---:|---:|---:|
| `secure_128` | 41843247 | 52332363 | 93584269 | 2316632 | 760871942 |
| `secure_192` | 112183516 | 189351583 | 297196030 | 6605101 | 2402361733 |
| `secure_256` | 129493010 | 269598190 | 401779827 | 7908847 | 2734146773 |

Caveat on the absolute scale: this container measures `mul_dual_public` for
`secure_128` at ~761 ms against the ~292 ms recorded in `CLAUDE.md`, so the
machine is loaded relative to that baseline. The two columns were measured in
the same process on the same run, so the comparison between them is meaningful
even though neither absolute figure should be quoted against `CLAUDE.md`'s
performance table.

### Security prerequisites addressed (single-RNS path only)

Both defects were confined to the single-RNS key/encrypt path that the exact
route consumes. The dual-RNS production keygen
(`generate_keys_dual*`) was **already correct** on both counts before this
work — it uses `sample_uniform_dual_poly` and per-lane `signed_to_mod`.

1. **Narrow public/eval-key sampler.** `a` in `generate_keys_with_rng` and
   `generate_eval_key_with_rng` was one `rng.next_u64()` per coefficient fed
   through `RNSPolynomial::from_poly`, confining `a` to `2^64` of the `2^119`
   (`secure_128`) or `2^175` (`secure_256`) values RLWE requires it to range
   over. Replaced with `sample_uniform_main_poly`: rejection sampling uniform on
   `[0, Q)`, one value reduced independently into each lane — the single-RNS
   counterpart of `sample_uniform_dual_poly`. Pinned by
   `single_rns_uniform_sampler_covers_the_whole_main_modulus`, which
   reconstructs each sampled coefficient and requires >99% of them to exceed
   `2^64` (a `u64` draw gives exactly zero).
2. **Cross-lane CBD encoding.** The error used `sample_cbd_rng(rng, eta, q_min)`,
   which returns `q_min + sum` for a negative sample — a representative valid
   modulo *one* prime. `from_poly` then reduced that single value into every
   lane, and because `q_min + sum < q_j` for every other lane the RNS object
   represented the integer `q_min + sum` (about `2^29`) rather than a value in
   `{-eta..eta}`. Consistent across lanes, so it decrypted; it simply spent ~29
   bits of noise budget per coefficient. Now signed-sampled and encoded per lane
   with `signed_to_mod`. `sample_cbd_rng` has no callers left and is deleted.

Still owed, and NOT claimed here: WIRE-Q inspection of every published artifact
beyond this route (WR-2), and an external lattice-estimator run for the exact
shipped tuples.

### Full suites (BASE vs HEAD, same machine, same command)

| suite | BASE `f841642` | this branch | delta |
|---|---|---|---|
| `cargo test -p nine65 --lib --release` | 843 passed / 5 failed / 122 ignored | 870 passed / 5 failed / 124 ignored | +27 passed, +0 failed, +2 ignored |
| `--test residue_space_ciphertext --features allow_insecure` | 8 passed / 1 failed | 8 passed / 1 failed | unchanged |
| `--test full_system_exercise --features allow_insecure` | 30 passed / 1 failed | 30 passed / 1 failed | unchanged |

`cargo build --release --workspace --exclude nine65-python --exclude nine65-wasm`
succeeds; `cargo fmt --all -- --check` is clean.

The +27 is 4 new `MainOnlyBaseExt` tests and 23 new `exact_mul` gates. The +2
ignored are the two opt-in diagnostics
(`exact_vs_dual_public_repeated_square_depth`,
`exact_route_stage_timings_integer_nanoseconds`), which assert nothing about
the dual route.

The 5 lib failures are the known issue #117 / #95 public-refresh regressions
(`auto_bootstrap` x4, `bootstrap::diag_measure_noise_growth`) and are identical
at BASE. The two integration failures
(`ct_multiply_is_order_equivariant_bit_exact`,
`test_rns_multi_modulus_mul_bajard`) are also identical at BASE, with
byte-identical failure output.

### Not done / explicitly out of scope

- `try_decrypt_exact` is **not constant-time**: the `MainOnlyBaseExt` rank
  fallback is fixed-work, but *whether* it is taken depends on the decrypted
  coefficient. Documented on the function. Owner decision 2026-09-05: it stays
  as-is (§E); hardening belongs to the production paths and the CT roadmap, not
  to WR-1.
- No CI evidence: GitHub Actions is blocked by issue #79. All numbers above are
  local.
- WR-2's broader differential/WIRE-Q closure is untouched.
- Issue #95 needs the secret-dependent bootstrap correction term; this route
  does not supply it and does not close #95.