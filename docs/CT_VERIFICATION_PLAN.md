# Constant-Time Verification — Measured Results and CI Posture

**Measurement date:** 2026-08-22
**Status:** Measured. Five open findings (F-5 added on the integration pass), five paths gated as blocking CI.
**Harness:** `crates/nine65/src/security/ct_verification.rs`
**Workflow:** `.github/workflows/ct_verification.yml`

---

## 1. What changed, and why this document was rewritten

Until this measurement the repository had never executed its own constant-time
suite. Every test in `security::ct_verification::constant_time_statistical`
carried `#[ignore]`, the thresholds had been widened from the documented
CV < 5% / t < 5 to CV < 25% / t < 100, and the CI step that appeared to run them
invoked `cargo test` **without** `--ignored` — so it selected zero tests and
reported success. CI ran source-pattern checks (`check_ct_ntt_source.py`,
`verify_constant_time.sh`) and nothing else.

The previous version of this file was a March 2026 integration plan for
`ct-verif` and `timecop`. Neither tool was ever integrated. It also contained a
status table marking `extract_k`, `montgomery_reduce`, `barrett_reduce` and
`detect_sign` as `VERIFIED` under four columns including `dudect` — a claim no
executed measurement supported. That table has been deleted rather than
corrected. The unexecuted tooling roadmap is preserved in
[Appendix A](#appendix-a--unexecuted-tooling-roadmap) and clearly labelled as
such.

What follows is measurement.

---

## 2. Measurement environment — read this before quoting any number

| | |
|---|---|
| CPU | Intel Xeon @ 2.80GHz, 4 vCPU |
| Kind | **Shared cloud container**, co-tenanted, concurrent build agents |
| `scaling_governor` | not exposed to the container |
| Turbo / frequency pinning | not controllable |
| Load average during runs | **1.0 to 22.4** (deliberately including the high end) |
| Timer | `std::time::Instant`, measured floor **21–22 ns** for an empty region |
| Build | `cargo test -p nine65 --lib --release` |

This is a hostile environment for timing measurement and the results below are
qualified accordingly. Where a result is reported as **inconclusive**, that word
is doing real work: it means the harness's own control arm said the machine's
noise floor exceeded the decision threshold, not that the author hedged.

---

## 3. Two families of test, and why only one of them can gate a PR

### (a) Robust-CV tests — 8 tests, diagnostics only

These time one scalar operation per `Instant::now()` pair and report
`robust_cv = 1.4826 * MAD / median`. Three defects were found by running them:

**Defect 1 — the measured calls were being deleted by the optimiser.** The tests
were written as `let _result = ctx.montgomery_pow(base, exp);` with no
`black_box`. Measured medians before the fix:

| operation | median (before `black_box`) |
|---|---|
| `extract_k` | 21 ns |
| `montgomery_reduce` | 21 ns |
| `montgomery_mul` | 21 ns |
| `montgomery_pow` (64-bit ladder) | 21 ns |
| empty measured region (timer floor) | **21 ns** |

A 64-iteration modular exponentiation timing identically to a single modular
multiply, and both timing identically to nothing at all, is not a coincidence.
After adding `black_box` on operands and results the same calls measure 751 ns,
28 ns, 32 ns and 437 ns respectively. Every robust-CV number this file
previously reported was the cost of reading the clock.

**Defect 2 — the CV statistic is quantised below the threshold it is compared
to.** MAD is an integer number of nanoseconds, so `robust_cv` can only take the
values 0, 1.4826/median, 2·1.4826/median, … For a 28 ns median the reachable
values are 0.00%, 5.30%, 10.59% — the 5% pass band has **no representable value
inside it**. Observed directly, on unchanged code, one run apart:

```
run 5: Montgomery reduce: median=29.00ns, MAD=0.00, Robust CV=0.0000%   PASS
run 6: Montgomery reduce: median=28.00ns, MAD=1.00, Robust CV=5.2950%   FAIL
```

The harness derives `CV_RESOLVABLE_MEDIAN_NS = 2 · 1.4826 / 0.05 ≈ 59.3 ns` and
applies the 5% CV band only above it. Every operation that falls below the line
is additionally covered by a batched dudect test in family (b) — coverage moved,
it was not dropped.

**Correction (integration pass).** The first version of that repair returned
`None` unconditionally below the line, which left `test_ct_montgomery_reduce`,
`test_ct_montgomery_mul` and `test_ct_barrett_reduce` reporting `ok` while
asserting **nothing at all** about the operations they name, with nothing in the
test name or the CI job listing saying so. A gate that cannot fail is not a
gate.

Quantisation bounds what those tests can check; it does not reduce it to
nothing. Below the resolution floor the timer can still distinguish "MAD within
one tick" from "MAD of several ticks", so `cv_failure` now asserts
`MAD ≤ MAX_UNRESOLVABLE_MAD_TICKS = 1` there and reports which rule it applied.
Both arms of the `0.0000% / 5.2950%` flip above are MAD ≤ 1, so both now pass
**deterministically** — the instability that motivated not gating these numbers
is fixed at the assertion rather than routed around in CI.

Re-measured after the change: two full runs of all eight family-(a) tests,
16 / 16 exit 0, including a run that reproduced the 5.2950% value verbatim. On
that basis the `diagnostics` job now gates on the assertions instead of
downgrading a nonzero cargo exit to `::warning::` (see §3(a) and the job table).

**Defect 3 — the cross-class t-tests were block-measured.** All samples of class
A were collected, then all of class B, so drift between the blocks is
indistinguishable from a class effect. `test_ct_k_elimination_exact_divide`'s
`d=2 vs d=3` statistic, on identical code across four consecutive runs:

```
t = 14.31 → 2.57 → 15.77 → 58.12
```

Those two assertions (in `test_ct_k_elimination_exact_divide` and
`test_ct_input_class_analysis`) are now **reported but not asserted**, with the
reason inline in the source. Both questions are asserted properly by interleaved
replacements in family (b); one of those replacements found a leak the
block-measured version never saw.

### (b) dudect two-class tests — 10 tests, five of them blocking

Each test compares two input classes with:

1. **Interleaved measurement** — class order randomised per round, so machine
   drift is shared by all streams rather than accruing to one.
2. **Interleaved pool allocation** — the three input pools are built round-robin
   (`a[0], a2[0], b[0], a[1], …`). This was added after `extract_k`'s signal
   flipped SIGN between runs while its control stayed clean, which is the
   signature of a heap-placement confound rather than an operand effect. With
   interleaved allocation the control dropped to 0.19 and the sign became
   consistent.
3. **A control arm** — two independent sample streams from the *same* class,
   giving a per-run measurement of the machine's noise floor.

Verdicts are three-valued:

| control t | signal t | verdict |
|---|---|---|
| < 5 | < 5 | constant-time at this sample size |
| < 5 | ≥ 5 | **timing dependence measured** |
| ≥ 5 | any | **inconclusive** — noise floor exceeds the threshold |

The control arm is what makes these safe to block a PR on: a runner too noisy to
measure raises the control *first*, and the verdict degrades to inconclusive
(pass). Noise costs signal; it does not manufacture a red. No threshold dilution
is required or used — the gate is the documented `t < 5`.

---

## 4. Results

### 4.1 Constant-time by measurement

Threshold t < 5. Ranges are across 5–7 independent runs at load average 1–22.

| Operation | Class contrast | control t | signal t | Verdict |
|---|---|---|---|---|
| `MontgomeryContext::montgomery_pow` | exponent Hamming weight 8 vs 56 | 0.05 – 1.53 | **0.01 – 2.05** | constant-time |
| `MontgomeryContext::montgomery_mul` | 12-bit vs near-modulus operands | 0.16 – 2.65 | **0.04 – 2.78** | constant-time |
| `MontgomeryContext::montgomery_reduce` | 16-bit vs top-bit cofactor | 0.10 – 4.85 | **0.27 – 2.29** | constant-time |
| `BarrettContext::reduce_ct` | 40-bit vs 128-bit dividend | 0.15 – 3.78 | **0.01 – 1.59** | constant-time |
| `RNSFHEContext::mod_switch_down_dual` | positive vs negative centred, **magnitude-matched** | 0.15 – 1.08 | **0.08 – 2.29** | constant-time |

The `montgomery_pow` result is the most valuable positive here. Exponent Hamming
weight is *the* classic modular-exponentiation side channel: a square-and-multiply
loop that skips the multiply on a zero bit runs in time proportional to the
popcount, a ladder does not. Measured at popcount 8 versus 56 over full 64-bit
exponents, `t_signal` never exceeded 2.05. The ladder is real.

The `mod_switch_down_dual` sign result matters because that function contains two
explicit secret-dependent branches (`if rem >= q_last_half`, and
`if v_centered.is_neg && q_mod_p != 0`). With coefficient magnitude held constant
between classes so only the sign differs, no timing dependence is measurable. The
branches are not the leak. The dividend magnitude is — see 4.2.

### 4.2 NOT constant-time by measurement — four findings as first recorded

F-1 has since been closed (§4.8), and the diagnosis recorded below for it —
`__umodti3` — turned out to be the wrong cause. The section is kept as written
so the correction is visible rather than overwritten.

All four have clean control arms (max 2.54), so the machine is not the
explanation.

#### F-1 · `exact_modulus_switch_drop_poly` — magnitude leak, 8–17% · **CLOSED, see §4.8**

`crates/nine65/src/ops/rns_fhe.rs:5110`

| contrast | control t | signal t (6 runs) | medians |
|---|---|---|---|
| all-zero vs uniform residues | 0.12 – 1.06 | **71.9 / 79.5 / 129.6 / 89.8 / 98.7 / 119.3** | 128.6 µs vs 150.1 µs (**+16.7%**) |
| 20-bit vs near-modulus residues | 0.10 – 1.34 | **39.0 / 46.5 / 54.8 / 47.4 / 47.3 / 49.2** | 129.3 µs vs 139.8 µs (**+8.1%**) |

The second contrast is the important one: both classes are non-zero, so this is
not the trivial all-zero special case. It is operand magnitude.

Cause. The kernel is branch-free at source level, but every step is a division
by a runtime modulus on a value derived from the ciphertext:

```rust
let r_k  = dropped[c] % q_i;
let x    = src[c] % q_i;
let diff = (x + q_i - r_k) % q_i;
out[c]   = ((diff as u128 * inv as u128) % q_i as u128) as u64;
```

The last line is a 128-bit remainder by a runtime divisor, which LLVM lowers to
`__umodti3` — a shift/subtract loop whose trip count depends on the operand's bit
length. Branch-free is not the same as constant-time when the instruction itself
is not.

**This is the exact align-and-drop primitive**, `#[allow(dead_code)]` with no
production caller by design (see `docs/MODULUS_SWITCHING.md`). It must not be
wired into a production path until this is addressed.

#### F-2 · `RNSFHEContext::mod_switch_down_dual` — magnitude leak, 3.2×

`crates/nine65/src/ops/rns_fhe.rs:3902`

| contrast | control t | signal t (6 runs) | medians |
|---|---|---|---|
| all-zero vs uniform coefficients | 0.07 – 2.10 | **701.0 / 228.9 / 202.4 / 206.6 / 210.0 / 160.5** | 25.4 ms vs 80.5 ms (**3.17×**) |

This is the largest finding in the file, and it is not a percentage — it is a
factor of three. Cause: `U256::div_mod_u64` is a long division whose work scales
with the magnitude of the reconstructed coefficient. Paired with the
magnitude-matched sign result in 4.1, the diagnosis is precise: the dividend
leaks, the sign does not.

#### F-3 · `KElimination::extract_k` — small but reproducible, ~0.5%

`crates/nine65/src/arithmetic/k_elimination.rs:470`

| contrast | control t | signal t | medians (per 4096-call batch) |
|---|---|---|---|
| 20-bit vs near-cap operands | 0.19 – 2.54 | **4.46 (600 rounds) → 6.80 / 11.42 / 10.52 / 7.84 (2000 rounds)** | 2.4132 ms vs 2.4023 ms |
| *re-measured, integration pass* | 0.07 – 1.17 | 4.35 / 13.63 / 10.20 (2000 rounds) → **18.46 / 20.53 / 29.27 (8000 rounds)** | ~13–15 µs apart |

Effect size ≈ 2.6–3.9 ns on a ~588 ns call (0.45–0.67%). `|t|` grows with round
count, which is the signature of a real effect rather than noise — noise leaves
`|t|` bounded while a real difference grows as √n.

**Two corrections from the integration-pass re-measurement.**

1. **The VERDICT was not stable at 2000 rounds.** One of three runs read
   `t_signal = 4.35` and reported `CONSTANT-TIME`. That matters because this
   test is the subject of the scheduled *inverted* tripwire, which hard-fails on
   a `CONSTANT-TIME` verdict: roughly a third of scheduled runs would have
   raised "the documented leak has been fixed" against an unchanged tree. The
   test's own `#[ignore]` reason said "not a flake", which was not established
   at that round count.

   Fixed by raising the round count for this test alone to
   `DUDECT_EXTRACT_K_ROUNDS = 8000`, where 6 of 6 runs across both counts show
   the effect and the 8000-round runs clear the threshold by 3.7× or better with
   controls two orders of magnitude below it. More power, not a wider threshold.

2. **The SIGN is not stable.** The earlier text said near-cap operands were
   "consistently **faster** in 4 of 5 runs". Re-measured, near-cap was slower in
   some runs and faster in others (the per-run median baseline itself moved by
   ~300 µs as the machine's frequency shifted). Only the *magnitude* of the
   dependence is established; its direction is not.

This contradicts the docstring on `extract_k`, which claims
`operations = 6 (fixed)`, `branches = "none"`. The claim of branch-freedom is
plausible; the claim of fixed cost is not what the clock says, because the u128
arithmetic underneath compiles to compiler-runtime division helpers.

Qualification, stated plainly: the effect is under 1% and this machine is
shared. It is above the noise floor by a wide margin *within* runs and its
direction is stable *across* runs, which is why it is listed as a finding rather
than as inconclusive — but a quiesced, frequency-pinned machine should confirm it
before anyone changes `extract_k` in response.

#### F-4 · The robust-CV suite cannot gate anything

Not a code defect — a harness finding, documented above as Defects 1–3. Recorded
here because it means the repository's *only* prior CT measurement claim rested
on numbers that were the cost of `Instant::now()`.

### 4.3 Measured, under threshold, but not blockable

| Operation | contrast | control t | signal t | note |
|---|---|---|---|---|
| `KElimination::exact_divide` | divisor 2 vs 3, identical operands | 0.28 – 3.03 | 0.76 / 2.54 / 3.24 / **4.32 / 4.89** (2000 rounds) | never crossed 5, but came within 0.11 |
| *re-measured, 8000 rounds* | 0.46 – 1.27 | **8.18 / 6.73 / 4.94** | crosses in 2 of 3 |
| *re-measured, 32000 rounds* | 1.14, then **9.20 / 11.19** | 11.42, then 20.22 / 20.26 | control blew past 5 → `INCONCLUSIVE` ×2 |

**Re-measured on the integration pass, and it is no longer "under threshold".**
`|t|` grows with round count (mean ≈ 3 at 2000, ≈ 6.6 at 8000, 11.4 at the one
clean 32000-round run) while the control stays near zero, and the sign is stable
across every clean run: **divisor 3 is consistently slower than divisor 2** by
~1–3 µs per 4096-call batch. That is the same signature as F-3. This is a real
divisor-dependent timing dependence — promoted from "under threshold" to an
**open finding** (F-5).

It is also **not gateable in either direction today**:

* not in `dudect-blocking`, because it is not constant-time and a passing gate
  would be a coin flip;
* not in the inverted `open-findings` tripwire, because that needs a *stable*
  `TIMING DEPENDENCE MEASURED` verdict and this reads dependence in only 2 of 3
  runs at 8000 rounds;
* not above 8000 rounds on the reference machine at all, because at 32000 the
  **control arm itself** exceeds the threshold (9.20, 11.19) and the harness
  correctly reports `INCONCLUSIVE` — the measurement stops being about the code.

So `DUDECT_DIVISOR_CLASS_ROUNDS = 8000` (the most power this machine can buy
while the control stays clean), and the test is collected in a clearly-labelled
**harness-gated, not verdict-gated** step of the `open-findings` job: the job
asserts the harness ran and produced a verdict, surfaces the verdict as a
warning, and archives it. That is a smaller gate than the others in this file
and it is named as such rather than dressed up. Settling it needs a quiesced,
frequency-pinned runner.

### 4.4 Robust-CV measurements, for the record

With `black_box` in place. "Asserted" reflects the 59.3 ns resolvability rule.

| Test | median | MAD | robust CV | asserted |
|---|---|---|---|---|
| `extract_k` | 732 – 751 ns | 15 – 16 | 3.04 – 3.16% | yes — passes |
| `exact_divide` (per divisor) | 832 – 1072 ns | 18 – 90 | 2.90 – 14.88% | yes — **failed under load** |
| `montgomery_pow` | 437 ns | 1 – 2 | 0.34 – 0.68% | yes — passes |
| `ct_vs_vartime` (CT arm) | 688 – 808 ns | — | 3.49 – 3.68% | yes — passes |
| `input_class_analysis` | 695 – 777 ns | — | 2.99 – 3.63% | yes (median spread) — passes |
| `montgomery_reduce` | 28 – 29 ns | 0 – 1 | 0.00% / 5.30% | CV no (below 59.3 ns) — **MAD ≤ 1 tick asserted instead** |
| `montgomery_mul` | 32 – 33 ns | 0 – 1 | 0.00% / 4.49% | CV no (below 59.3 ns) — **MAD ≤ 1 tick asserted instead** |
| `barrett_reduce` | 32 ns | 0 – 1 | 0.00% / 4.63% | CV no (below 59.3 ns) — **MAD ≤ 1 tick asserted instead** |

`exact_divide`'s CV blowout to 14.88% happened when a concurrent build landed
mid-test and its median shifted 832 → 1072 ns inside a single run. In that same
run every dudect control arm stayed between 0.07 and 2.26 and every dudect
verdict was unchanged. That contrast is the empirical case for the posture in
section 5.

### 4.5 Threat model — do not over-read F-1 and F-2

`exact_modulus_switch_drop_poly` and `mod_switch_down_dual` consume **ciphertext**
residues. Against a server-side adversary who already holds the ciphertext, a
timing dependence on those residues discloses nothing they do not have. These
findings matter for:

* a co-resident attacker on the **client**, where the same code runs over values
  correlated with the plaintext and the key;
* any future caller that routes secret-key material or plaintext-correlated
  intermediates through these functions — which is precisely what wiring the
  exact prime drop into a production BGV path would do.

F-3 (`extract_k`) is the broader exposure: K-Elimination is on the critical path
of the rescale used by the multiply, not an unwired primitive.

---

### 4.6 F-3 answered by construction — measured, not argued

Date: 2026-08-22. Same container, same harness, same session as §4.2.

F-3's cause is not a branch. `KElimination::extract_k` is

```rust
let diff = sub_mod_kelim_ct(v_beta, v_alpha, self.beta_cap); // v_alpha % beta_cap
mul_mod_u128_ct(diff, self.alpha_inv_beta, self.beta_cap)    // a % beta_cap, then 128 rounds
```

and both halves contain a `u128 % u128` by a *runtime* modulus, which lowers to
`__umodti3`. The usual remedy is to rewrite the reduction. The alternative tried
here is to remove it: manufacture the CLASS-R anchor **adjacent** to the CLASS-F
product, `A = M + 1`. Then `M ≡ −1 (mod A)`, so `M⁻¹ ≡ M`, and the extraction
collapses to

```text
    k = (v_α − v_β) mod A
```

`v_α < M < A`, so `v_α` is already reduced and the pre-reduction is *absent*, not
merely cheap. What remains is `wrapping_sub`, a mask, and `wrapping_add`.

Implemented as `arithmetic::k_elimination::AdjacencyKElim`.

**Correctness first.** The shortcut is differential-tested against the general
`KElimination` over the *same* `(M, A)` pair — same anchor, but with `M⁻¹`
obtained by extended Euclid instead of by construction — and both against ground
truth `k = ⌊X/M⌋`:

| check | coverage | result |
|---|---|---|
| exhaustive, `M = 105`, `A = 106` | all 11,130 values of `X < M·A` | shortcut = general = truth |
| random, `KElimConfig::Standard` | 200,000 draws over the 96-bit range | shortcut = general = truth |
| boundary probes | `0, 1, M±1, A±1, capacity−1, k·M, k·M+(M−1)` | shortcut = general = truth |
| `M⁻¹ mod A == M` | Minimal / Standard / Maximum, vs extended Euclid | holds |

**Then timing.** The comparison is only worth reading if both arms were measured
with the same power, so the adjacency sweep is repeated `ADJ_REGION_REPEATS = 340`
times per measured region to bring it to the same duration as the general form's,
and it runs at the same `DUDECT_EXTRACT_K_ROUNDS = 8_000`:

| form | region | rounds | kept | median A | median B | t_control | t_signal | verdict |
|---|---|---|---|---|---|---|---|---|
| general `(v_β − v_α)·M⁻¹ mod A` | 2.40 ms | 8,000 | 21,601/24,000 | 2,403,289 ns | 2,388,188 ns | 0.090 | **25.61** | leaks, +0.63% |
| adjacency `(v_α − v_β) mod A` | 3.22 ms | 8,000 | 21,601/24,000 | 3,221,927 ns | 3,222,676 ns | 0.629 | **1.10** | constant-time |

The general arm *is* the positive control: it establishes that this harness, at
this region size and round count, resolves a 0.63% relative effect at t = 25.6.
The adjacency arm's region is 34% *longer*, so it had at least as much power and
returned t = 1.10. That is a null with a demonstrated ability to see the thing it
did not see — not an underpowered shrug.

Cost, over identical inputs, 400 rounds of 4,096 calls:

| form | ns per call |
|---|---|
| general | 668.31 |
| adjacency | 1.71 |

390×. Worth stating in absolute terms rather than as a ratio: **the adjacency
form's entire per-call cost (1.71 ns) is under half the general form's measured
leak (3.7 ns).** Any timing channel it could carry is bounded above by its own
runtime.

**What it costs.** Capacity. Adjacency forces `A = M + 1`, so the representable
range is `M·(M+1) ≈ M²` — 96 bits for `KElimConfig::Standard`, against 110 bits
for the current 48-bit `M` paired with an independently chosen 62-bit `β`.
Recovering the 14 bits means widening the alpha basis, not hunting a wider
anchor.

**Not adopted.** `AdjacencyKElim` has no production caller. Switching
`KElimConfig` to adjacency anchors changes a cryptographic parameter and the
capacity envelope of every path that reads it; that is an owner decision, and
this section exists so the decision can be made against measurements instead of
against an argument.

### 4.7 The same construction does NOT close F-1 — and here is why

Recorded because it was asserted in the affirmative before it was checked, and
the code says otherwise.

The reasoning that failed: the star family `q = c·t + 1` yields `t⁻¹ mod q = q − c`
by inspection, so a manufactured basis gets its inverses free; therefore F-1's
`(x_i − r_k)·q_k⁻¹ mod q_i` should collapse the same way F-3 did.

It does not, for two independent reasons.

1. **Wrong inverse.** The star identity gives `t⁻¹ mod q` — the *plaintext*
   modulus inverted in a lane. F-1 needs `q_k⁻¹ mod q_i`, a cross-lane inverse
   between two main primes. Adjacency could supply it for one pair (`q_i = q_k+1`
   ⟹ `q_k⁻¹ = q_k`), but lanes cannot be pairwise adjacent to each other.
2. **Wrong cost, and this one is fatal on its own.** `inv` is already hoisted out
   of the per-coefficient loop in `exact_modulus_switch_drop_poly` — one
   `mod_inverse` per lane, amortised over `n` = 1,024–16,384 coefficients.
   Obtaining it for free saves setup, not runtime. The leak is the four divisions
   *inside* the loop, and the construction does not touch them.

F-1's fix is therefore arithmetic, not architectural: eliminate the runtime
division from the inner kernel. See §4.8.

### 4.8 F-1 closed — and the actual defect was not the one recorded

Date: 2026-08-22. Same container as §4.2; the baseline was re-measured on the
day rather than quoted, and reproduced the recorded numbers to within 0.5%
(127,970 / 149,782 ns against the recorded 128,200 / 150,100), so the machine is
the same instrument.

**The recorded diagnosis was right about the symptom and wrong about the cause.**
F-1 was attributed to `__umodti3`. Removing every division from the kernel made
the function twice as fast and left the leak *larger*. The cause was a branch.

#### How it was localised

The kernel was replaced with progressively smaller probes, each measured under
both class contrasts, serially (two dudect tests run concurrently contend for the
CPU and invalidate each other — the first attempt at this made that mistake).

| probe | kernel body | class A | class B | gap | verdict |
|---|---|---|---|---|---|
| P0 | `src[c] ^ dropped[c] ^ inv ^ q` — touches all data, no data-dependent arithmetic | 9,058 | 9,068 | 10 ns | flat, t = 0.67 |
| P1 | two `Barrett::reduce_ct` on `u64` dividends | 43,365 | 43,375 | 10 ns | flat, t = 0.30 |
| P2 | one `Barrett::reduce_ct` on a `u128` product | 32,517 | 32,523 | 6 ns | flat, t = 2.24 |
| P3 | P1 **plus one `Barrett::sub_ct`** | 35,722 | 58,794 | **23,072 ns** | **t = 442** |

P0 is the load-bearing one: it clears the harness, the pools, the allocator and
cache locality of any responsibility. P1 and P2 clear the Barrett reduction. P3
adds a single modular subtraction and the leak appears whole.

`objdump` on the kernel: **16 conditional jumps, 3 `cmov`/`sbb`** — in a function
whose comment said branch-free.

#### The defect

```rust
/// Constant-time modular subtraction
pub fn sub_ct(&self, a: u64, b: u64) -> u64 {
    let diff = a.wrapping_sub(b);
    let borrow = (a < b) as u64;          // <-- lowered to a branch
    let mask = borrow.wrapping_neg();
    diff.wrapping_add(self.q & mask)
}
```

`((a < b) as u64).wrapping_neg()` is the standard branchless-mask idiom and it
carries **no guarantee whatsoever**. LLVM lowered it to a conditional branch, and
a branch's cost depends on its prediction rate, which here is a property of the
secret operands:

| class | `a < b` rate | prediction | measured |
|---|---|---|---|
| all-zero residues | 0% (`0 < 0` never) | perfect | fast |
| uniform residues | ~50% | worst case | slow |
| 20-bit residues | ~50% (independent small draws) | worst case | slowest |
| near-modulus residues | near-deterministic (lane primes differ in size, so the order of `x ≈ q_i` and `r_k ≈ q_k` is fixed) | near-perfect | fast |

That table also explains the sign flip that the first Barrett attempt produced:
under the original divisions the magnitude effect dominated and small residues
were *faster*; once division was removed, branch prediction dominated and small
residues became *slower* than near-modulus ones.

#### The fix, and why the first two attempts did not work

1. Replacing `%` with `BarrettContext::reduce_ct` — 2× faster, leak unchanged
   (the absolute gap stayed at ~21.7 µs while the total halved, which is what
   first suggested the arithmetic was not the culprit).
2. Rewriting the mask as `((a as u128).wrapping_sub(b as u128) >> 127)` — no
   boolean anywhere in the source. Leak unchanged: LLVM recognises the pattern
   as `a < b`, canonicalises it back to an `icmp`, and branches again.
3. Adding `core::hint::black_box` on the extracted borrow bit, so the compiler
   cannot reason about the value and the arithmetic form survives to codegen.
   This one worked.

`black_box` is a hint with no language-level guarantee. It is used here *because
the result is measured*, not in place of measuring.

#### Result

| kernel | contrast | class A | class B | gap | t_signal | t_control | verdict |
|---|---|---|---|---|---|---|---|
| division (baseline) | zero vs uniform | 127,970 | 149,782 | +17.0% | 96.82 | 0.67 | leaks |
| division (baseline) | small vs near-mod | 128,362 | 138,420 | +7.8% | 48.40 | 0.85 | leaks |
| Barrett, branchy mask | zero vs uniform | 62,402 | 84,120 | +34.8% | 175.66 | 2.43 | leaks worse |
| Barrett, branchy mask | small vs near-mod | 99,872 | 62,755 | −37.2% | 185.29 | 0.43 | leaks, flipped |
| **Barrett + barrier** | zero vs uniform | 110,927 | 110,977 | **+0.045%** | **0.96** | 1.16 | **constant-time** |
| **Barrett + barrier** | small vs near-mod | 110,782 | 110,798 | **+0.014%** | **0.45** | 0.11 | **constant-time** |

And it is **13% faster than the original division kernel** (110.9 µs vs 128.0 µs),
so constant-time did not cost throughput here — it bought some.

Correctness is unchanged: `exact_modulus_switch_drop_matches_integer_division_exhaustive`
and the three companion tests pass, and the full `nine65` library suite is
760 passed / 0 failed.

#### The general lesson, and what it costs elsewhere

Four other sites in this workspace use the same `((cond) as T).wrapping_neg()`
mask:

| site | function | status |
|---|---|---|
| `arithmetic/k_elimination.rs:942` | `sub_mod_u128_ct` | **measured branchless** — see below |
| `arithmetic/k_elimination.rs:959` | `add_mod_u128_ct` | reached only through `mul_mod_u128_ct` |
| `arithmetic/kelim_residue_divider.rs:270,277` | duplicates of the above | unmeasured |
| `clockwork-core/src/garner.rs:107` | Garner step | unmeasured; A2-prohibited path |

`sub_mod_u128_ct` is what `AdjacencyKElim::extract_k` (§4.6) reduces to, so its
compiled form decides whether that result stands. The magnitude contrast in §4.6
**cannot see a branch**: it draws `v_α` and `v_β` independently, so `a < b` holds
about half the time in *both* arms, and a conditional with equal taken-rates
across classes is invisible however badly it is compiled.

`test_ct_dudect_adjacency_k_elim_operand_order` supplies the contrast that can
see it. Both classes present the identical multiset of operand values and differ
only in order: class A always passes `(larger, smaller)` so the borrow never
fires; class B randomises the order so a branch would mispredict half the time.

| contrast | class A | class B | gap | t_signal | t_control | verdict |
|---|---|---|---|---|---|---|
| sorted vs randomised order | 3,196,712 | 3,197,193 | 0.015% | **0.45** | 0.90 | constant-time |

So the same idiom compiled branchlessly in `k_elimination.rs` and branchfully in
`barrett.rs`. That is the finding worth keeping: **the idiom is not the
guarantee — the measurement is.** Working code was left alone and the contrast
that can falsify it was added as a permanent test, rather than churning a
primitive that measures clean.

Unmeasured sites stay listed as unmeasured. `kelim_residue_divider.rs` and
`clockwork-core/garner.rs` have no dudect coverage; neither is on a production
ciphertext path today, and both need this contrast before either is put on one.

## 5. CI posture

> **NOTHING BELOW IS CURRENTLY RUNNING. Read this before reading the table.**
>
> Checked against the GitHub API on 2026-08-22. Thirteen workflows are
> registered on `Skyelabz210/NINE65_v7` and all report `state: active`.
> **Twelve of the thirteen have never run once** — `total_count: 0` — and
> `ct_verification.yml`, the workflow this whole section describes, is one of
> them. The single workflow that has ever run is `ci.yml`: 39 runs, of which
> the last ~25 all concluded `failure`; its last run that actually completed
> was 2026-02-25 and it failed; its most recent run (2026-02-27,
> `workflow_dispatch`) has been sitting in `queued` ever since and never
> started. **No workflow of any kind has run in this repository since
> 2026-02-27.**
>
> This is not a trigger misconfiguration. `ct_verification.yml` declares
> `pull_request` with a paths filter covering `barrett.rs`, `k_elimination.rs`,
> `rns_fhe.rs` and `security/**`; PR #49 touches all four and still shows zero
> check runs and zero commit statuses. A commit on `main` records
> "(CI Fix): Reverted multi-platform builds and fuzzing to resolve
> billing/spending limit issues", and `CLAUDE.md` records the Cloud Run
> deployment as "billing paused". Re-enabling Actions is an owner action, not
> a code change, so this document cannot fix it — only stop misreporting it.
>
> **So read the table below as a specification of what these jobs would do,
> not as a record of what is being enforced.** Every measurement quoted
> anywhere in this document was produced by running the tests by hand in a
> session, never by CI. The word "blocking" in the table describes a job's
> configured behaviour; nothing is blocking anything today.
>
> Two consequences worth acting on rather than noting:
>
> 1. The YAML/source correspondence — every `test_ct_*` being named by exactly
>    one job — is now enforced by a unit test,
>    `workflow_correspondence::every_ct_timing_test_is_named_by_the_workflow_and_vice_versa`,
>    rather than by a workflow. `cargo test` runs; the workflow does not.
> 2. A gate that exists only in YAML in this repository is not a gate. When
>    adding one, put the enforceable part where `cargo test` will reach it.

| Job | Trigger | Blocking | Contents | Threshold |
|---|---|---|---|---|
| `verify` | push / PR | yes | source-pattern gates, NTT + Montgomery correctness, harness inventory (18 tests) | n/a |
| `dudect-blocking` | push / PR | **yes** | the 5 operations of §4.1 | **t < 5, undiluted** |
| `open-findings` | weekly cron + dispatch | yes, inverted | the 4 findings of §4.2 | verdict must still be TIMING DEPENDENCE MEASURED |
| `diagnostics` | weekly cron + dispatch | gated on producing measurements **and on their assertions passing** | the 8 robust-CV tests | the `::warning::` downgrade of a nonzero cargo exit is gone; `exact_divide` divisor classes moved out to `open-findings` |

Three points about this arrangement:

**Blocking at the tight threshold, not a diluted one.** The five blocking tests
run at `t < 5`. Their worst observed signal across every run, including runs at
load average 22 on a 4-core box, is 2.78. There is 1.8× headroom, and the
control arm converts any further noise into an inconclusive pass rather than a
false red.

**The known-red tests are a state tripwire, not a shrug.** `open-findings` runs
the four leaking tests and **fails if one of them reports CONSTANT-TIME** —
meaning either the leak was fixed (promote the test, update this document) or the
test stopped measuring what it claims. It also fails if a test emits no verdict
at all, which is what a crash or build break looks like. It accepts INCONCLUSIVE
as no news. There is no `continue-on-error` and no `|| true` in that job; every
exit status is inspected.

**The `#[ignore]` attributes stay, and they are not hiding anything.** All 18
tests remain `#[ignore]`d so that `cargo test --workspace` stays fast and
deterministic; CI opts in explicitly with `--ignored --exact`. The four leaking
tests carry `#[ignore = "OPEN FINDING, not a flake: …"]` reason strings
containing the measured statistics, so the finding is visible in a bare
`cargo test -- --list` without opening this file.

---

## 6. Coverage gaps — what is still not measured

* **NTT / `ntt_fft`** — no timing test. Covered only by the source-pattern gate
  `scripts/check_ct_ntt_source.py`.
* **`encrypt_dual` / `decrypt_dual`** — the Δ·m encode and the centred decode both
  touch plaintext directly and have no timing test. This is the most valuable
  gap remaining, because the secret there is unambiguous.
* **`k_elim_rescale_dual`** (`rns_fhe.rs:3714`) — the production BFV rescale.
  Private, reachable only through a full multiply or the
  `#[cfg(feature = "benchmarks")]` wrapper `bench_k_elim_rescale_dual`, so it is
  not covered here. Its source contains the same `U256` division and
  sign-branching pattern that F-2 measured, so F-2 should be treated as
  suggestive of its behaviour, not as a measurement of it.
* **`exact_rescale`** (`rns_fhe.rs:1632`) — private; contains a data-dependent
  centred-representation branch (`if coeff > q_i_half`). Not measured.
* **Key generation and gadget key-switching** — not measured.
* **Cross-platform** — every number here is one x86-64 Xeon. ARM division
  latency characteristics differ and would need their own baseline.

---

## Appendix A — unexecuted tooling roadmap

Retained from the March 2026 plan. **None of this has been executed.** It is
recorded as a roadmap, not as a status.

* **`ct-verif`** (MIT PLV) — formal CT verification via information-flow
  tracking. Requires manual annotations; Rust support is limited and primarily
  C-focused. Not integrated.
* **`timecop`** (Galois) — symbolic execution over LLVM IR for timing channels.
  Not integrated.
* **`dudect`** — statistical timing analysis. This is the methodology the harness
  in `ct_verification.rs` implements directly, in-tree, rather than by taking the
  dependency. That part of the roadmap is done; sections 3–5 above are its
  output.

The `scripts/verify_constant_time.sh` sketch in the original plan invoked
`ct-verif` and `timecop` binaries that were never installed. The script that
exists in the repository under that name performs source-pattern checks only.

---

## Appendix B — reproducing these numbers

```bash
# Everything, one at a time, with full output:
cargo test -p nine65 --lib --release constant_time_statistical -- \
    --ignored --nocapture --test-threads 1

# Just the blocking gate:
for t in test_ct_dudect_montgomery_pow_exponent_hamming_weight \
         test_ct_dudect_montgomery_reduce_operand_magnitude \
         test_ct_dudect_montgomery_mul_operand_magnitude \
         test_ct_dudect_barrett_reduce_operand_magnitude \
         test_ct_dudect_mod_switch_rescale_sign_classes; do
  cargo test -p nine65 --lib --release -- --ignored --exact --nocapture \
    --test-threads 1 "security::ct_verification::constant_time_statistical::$t"
done
```

On a machine you control, first:

```bash
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo
```

The harness prints the CPU governor, turbo state and its own measured timer
floor at the head of every test, so any archived log carries the conditions it
was produced under.
