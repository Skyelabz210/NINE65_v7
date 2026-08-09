# NINE65 v7 — Performance Baseline

**Date:** 2026-08-09
**Toolchain:** `rustc 1.94.1 (e408947bf 2026-03-25)` / `cargo 1.94.1 (29ea6fb6a 2026-03-24)`, release profile
**Host:** Linux 6.18.5-fc-v20, 4 cores
**Machine-readable companion:** [`baseline.json`](./baseline.json)

---

## 0. Read this first

### 0.1 These are QUICK-PASS numbers

Every criterion target ran with `--warm-up-time 1 --measurement-time 3..5 --sample-size 10`
instead of criterion defaults (3 s warmup / 5 s measurement / 100 samples). They are
good enough to establish order-of-magnitude and to settle the two regression floors.
**A publication run needs criterion defaults on a quiet machine.**

The **depth survey numbers are not criterion-sampled at all**. They are single
deterministic correctness-gated chain runs, so they are exact rather than statistical.

### 0.2 The machine was not quiet

A concurrent modulus-switching quarantine workflow ran `cargo test`/`cargo build`
throughout (observed 276 % CPU; load average 3.3–4.3). Everything here ran under
`nice -n -10`.

Single-threaded numbers are **robust**, by three independent agreements:

| Quantity | Path A | Path B | Agreement |
|---|---|---|---|
| homomorphic multiply (symmetric) | standalone probe 105.017 ms | in-repo `depth_chain` bench 105.58 ms | 0.6 % |
| homomorphic multiply, repeat run | probe run 1 105.017 ms | probe run 2 105.302 ms | 0.3 % |
| depth survey, all three shapes | `tests/depth_and_noise.rs` | `benches/depth_chain.rs` | exact |

**Distrust `throughput/*` and `adaptive_rayon/*`.** They use rayon across all 4 cores
and were genuinely contending for them. Treat every parallel/batch number as a
pessimistic upper bound.

### 0.3 The granularity rule

A single lane modular multiply is **nanoseconds**. A full ciphertext multiply at
N=8192 with relinearization is **milliseconds**. These are ~8.5 orders of magnitude
apart. This document keeps them in separate sections (§1 and §2) and they must never
be averaged, compared, or quoted in the same breath.

### 0.4 What is deliberately *not* reported

No "levels remaining", no "budget consumed", no "noise budget exhausted". Those
measure the **retired** modulus-switching mechanism. This substrate does not switch
moduli: K-Elimination divides the value **exactly**, so the value shrinks and the
basis does not move. Nothing is consumed, so there is nothing to report as consumed.

In place of a level counter, the depth bench asserts the **anti-ladder invariant**:
`(main_lanes, anchor_lanes, ct.level)` must be **constant** across the entire chain.
Measured constant at `(3, 5, 3)` across **2048 consecutive multiplies**.

---

## 1. LANE-LEVEL measurements — NANOSECONDS

**One scalar operation on one residue lane.** Nothing in this section touches a
ciphertext. Never quote any of these as a homomorphic-operation cost.

### 1.1 Modular multiply

| Operation | Time | Parameter set |
|---|---:|---|
| Persistent Montgomery mul | **0.983 ns** | 60-bit prime |
| Persistent Montgomery enter | 0.944 ns | 60-bit prime |
| Persistent Montgomery exit | 0.729 ns | 60-bit prime |
| Barrett `mul_ct`, large operands | **2.779 ns** | q = 998244353 (30-bit), constant-time |
| Barrett `mul_ct`, small operands | 4.156 ns | q = 998244353 |
| Barrett `reduce_ct` (u128 → mod q), small | 2.178 ns | q = 998244353 |
| Barrett `reduce_ct`, large | 2.665 ns | q = 998244353 |
| `sub_mod_u128_ct`, no borrow | 1.933 ns | u128 |
| `sub_mod_u128_ct`, borrow | 1.936 ns | u128 — branch-free, as intended |

> **Sub-nanosecond caveat.** The three Montgomery numbers are **pipelined throughput
> across independent loop iterations**, not dependent-chain latency. 0.983 ns is ~3
> cycles at 3 GHz for three chained 64×64 multiplies. Quote them as throughput or
> not at all.

### 1.2 The constant-time u128 primitives — read the caveat

| Operation | Time | Parameter set |
|---|---:|---|
| `mul_mod_u128_ct`, small | 372.84 ns | 62-bit prime 4611686018427387847 |
| `mul_mod_u128_ct`, large | 393.01 ns | 62-bit prime |
| `KElimination::extract_k`, small / large / edge | 384.75 / 387.03 / 386.45 ns | 62-bit prime |

> **These are NOT single-instruction modmuls.** 393 ns / 128 bits ≈ **3.07 ns per
> bit** is the signature of a bit-serial ~128-round constant-time double-and-add
> loop. This is **~140× the Barrett modmul**. Report as "constant-time u128 modmul
> via bit-serial loop", never as "a modmul". `extract_k` is flat across input class,
> which is exactly what a constant-time primitive should do.

### 1.3 CRAM exact-division lane ops

This is the right place to source the claim "a single lane op is nanoseconds".
Each is one residue pair, rolled through a 2048-entry table so constants cannot fold.

| Operation | Time |
|---|---:|
| `ExactDivider::reconstruct_exact` | **9.548 ns** |
| `exact_divide` (÷5) | **12.647 ns** |
| `divmod` (÷7) | 12.432 ns |
| `scale_and_round` (BFV-like) | 16.177 ns |

### 1.4 Other lane-level

| Operation | Time |
|---|---:|
| MQ-ReLU scalar | 9.457 ns |
| MobiusInt sign detection | 12.761 ns |
| Padé exp / sin / sigmoid (scaled i128) | 77.736 / 90.885 / 88.050 ns |
| `ord_63(2)` / `ord_1000(3)` | 117.38 / 849.82 ns |

### 1.5 Lane-level numbers that are NOT real measurements

| Id | Reported | Why it is invalid |
|---|---:|---|
| `adaptive_rayon/entropy_overhead/measure_ciphertext` | 663.81 ps | **No-op.** ~2 clock cycles cannot scan an N=8192 ciphertext. `measure_entropy_from_ciphertext` has two cfg-gated definitions (`shadow_entropy_monitor.rs:108` and `:134`); the real one needs feature `adaptive-threading`, which is **not** in `default` and **not** in this bench's `required-features = ["parallel"]`. The compiled body is literally `fn(_ct) -> u64 { 0 }`. |
| `nine65_vs_seal_comparison/Quantum Operations/*` | 5.7–7.5 ns | Inline code in the bench file; never calls the library. |
| `nine65_vs_seal_comparison/Polynomial Operations/*` | 0.45–160 µs | Inline code in the bench file; never calls the library. |

The no-op above has a second consequence: the entire `adaptive_vs_static` comparison
ran **with the entropy monitor disabled**, so it is not measuring what its name says.

---

## 2. END-TO-END measurements — MILLISECONDS

**One complete ciphertext operation.** All at `secure_128`: N=8192, t=65537,
main primes `[998244353, 985661441, 754974721]`, 3 main lanes + 5 anchor lanes.

### 2.1 The real CRAM DualRNS / K-Elimination path

Correctness asserted on every run (`dec(E(5)+E(7))=12`, `dec(E(5)*E(7))=35`), so
none of these can be an optimized-away no-op.

| Operation | Median | vs 5 ms |
|---|---:|---|
| `add_dual` (homomorphic addition) | **0.82 ms** | under, 6× margin |
| `decrypt_dual` | **4.13 ms** (bench: 4.40 ms) | under, only ~17 % margin |
| `generate_keys_dual` | 5.27 ms | *not a ciphertext op* |
| `encrypt_dual` | **9.93 ms** | **2× over** |
| `mul_dual_symmetric` (K-Elimination multiply) | **105.6 ms** | **21× over** |
| `mul_dual_public` (**real FHE model**) | **279.1 ms** | **56× over** |

`mul_dual_symmetric_with_s2` (precomputed s²) is 105.58 ms; the plain form is
110.43 ms, so the ~5 ms delta is the cost of recomputing s² per multiply.

### 2.2 Chain cost is flat in depth

| Chain length | Total | Per link |
|---:|---:|---:|
| 1 | 102.22 ms | 102.2 ms |
| 4 | 428.53 ms | 107.1 ms |
| 16 | 1719.8 ms | 107.5 ms |

Per-link cost does not fall as the chain progresses. This is the **timing-side echo
of the anti-ladder invariant**: if the basis shrank as the chain advanced (as it
would under a level ladder), later links would get measurably cheaper. They do not.

### 2.3 Full-polynomial cross-check

`timing/rns_kelim_rescale/k_elim_rescale` = **25.222 ms** for one complete N=8192
DualRNS K-Elimination rescale. A multiply needs a tensor product, several such
rescales, and relinearization — which composes to the measured ~105 ms. Two
independent measurement paths agree, so the 105 ms is not a harness artifact.

### 2.4 The DEPRECATED legacy path — do not quote these as CRAM

| Operation | Time | What it actually is |
|---|---:|---|
| `BFVEncryptor` encrypt | 1.53 ms | single 30-bit q, RNS chain **unused** |
| `BFVDecryptor` decrypt | 0.52 ms | single 30-bit q |
| `BFVEvaluator::mul` | 10.97–11.29 ms | `#[deprecated]` in favour of `mul_dual_symmetric` |

These are the legacy pre-CRAM path: `BFVEncryptor`/`BFVDecryptor` use `config.q`,
which `new_verified()` sets to `primes[0]` — a single 30-bit modulus. Encrypt and
decrypt here *are* sub-5 ms, and it is tempting to use them to rescue the latency
claim. **Do not.** Even on this deprecated fast path the *multiply* misses 5 ms by
~2.2×.

### 2.5 Polynomial layer (microseconds) — the one honest N sweep

| N | Forward NTT | Roundtrip | ns/butterfly |
|---:|---:|---:|---:|
| 1024 | 15.102 µs | 28.624 µs | 2.950 |
| 2048 | 30.894 µs | 62.222 µs | 2.743 |
| 4096 | 70.260 µs | 132.69 µs | 2.859 |
| 8192 | 157.29 µs | 293.14 µs | 2.954 |

Butterfly cost is a flat ~2.7–3.0 ns from N=1024 to N=8192: the NTT scales cleanly
as N log N with no per-butterfly degradation. (`timing/ntt_ct` at N=256 gives
3.625 ns/butterfly — small-N fixed overhead; not the headline.)

`ntt_scaling` is the **only** group in the suite whose N labels are correct (see §5.2).

### 2.6 Batch numbers — NOT per-op latency

`throughput/*` and `adaptive_rayon/*` time **whole batches of B ciphertexts**.
Divide by B before quoting. `throughput/batch_encoding` is **plaintext CRT packing**
with no crypto and no ciphertext at all — never quote it as a ciphertext op.
All of §2.6 is contended and pessimistic.

| Operation | Per-ciphertext |
|---|---:|
| encrypt, sequential | 17.03 ms |
| encrypt, rayon 4 cores | 5.8–8.7 ms (~2.9× speedup) |
| decrypt, sequential | 0.565 ms |
| decrypt, rayon 4 cores | 0.200 ms |

"Adaptive" threading is **2.3–8.2× slower** than static parallel across every id.
Root cause is not threading: `shadow_entropy_monitor.rs:395` has `adaptive_encrypt`
constructing a fresh `NTTEngine::new(q, 8192)` + `BFVEncoder` + `BFVEncryptor`
**per message**, rebuilding twiddle tables for every ciphertext. That is
per-iteration setup cost being attributed to threading strategy.

---

## 3. FLOOR 1 — the sub-5 ms latency claim

### Verdict: **UNSUPPORTED for the operation the claim rests on.**

The project docs claim "sub-5ms homomorphic ops". Measured end-to-end on the real
CRAM path, with correctness asserted:

**Under 5 ms**
- Homomorphic addition: **0.82 ms**. Comfortable.
- Decryption: **4.13 ms**. Under, but by only ~17 %, and the max sample hit 4.78 ms —
  it would cross 5 ms on a loaded machine.

**Over 5 ms**
- Encryption: **9.93 ms** — 2× over.
- Homomorphic multiply, symmetric: **105.6 ms** — **21× over**.
- Homomorphic multiply, public (the actual FHE model): **279.1 ms** — **56× over**.

**Plain statement.** The claim does not survive contact with the homomorphic
multiply. A ct×ct multiply is 105 ms in symmetric mode and 279 ms in the mode that
corresponds to homomorphic evaluation as the term is normally used. Being off by
1–2 orders of magnitude is not a tuning gap that criterion defaults or a quiet
machine would close. The claim is true only if "homomorphic op" is read to mean
addition and decryption — the cheap half of the operation set.

**Evidence quality.** Three independent paths agree within 0.6 % (§0.2), and the
25.2 ms single-rescale measurement composes to the 105 ms multiply (§2.3). This is
not a harness artifact.

---

## 4. FLOOR 2 — multiplicative depth ≥ 200

### Verdict: **MEASURED, and the answer is shape-dependent. The floor is cleared in one chain shape and missed by a factor of 200 in another. A bare "depth ≥ 200" claim for this system is not well-formed.**

A depth benchmark **now exists** — `crates/nine65/benches/depth_chain.rs`, written
for this baseline and registered in `crates/nine65/Cargo.toml`. It was run; the
numbers below are measured, not inherited. Depth is **correctness-gated**: a depth
counts as reached only if `decrypt_dual` returns the expected plaintext, tracked in
the clear. A chain stops at the first wrong decryption.

### 4.1 Results, `secure_128` (N=8192, t=65537, 3 main + 5 anchor lanes)

| Shape | Chain | Max correct depth | Stopped by | ≥ 200? |
|---|---|---:|---|---|
| 1 | `ct ← ct × Enc(1)`, **symmetric** | **2048** | ceiling (not noise) | **MEETS** |
| 2 | `ct ← ct × ct`, symmetric (squaring) | **1** | noise | **BELOW** |
| 3 | `ct ← ct × Enc(1)`, **public mode** | **1** | noise | **BELOW** |

- **Shape 1 = 2048 is a LOWER BOUND.** The chain was still healthy when it hit the
  requested ceiling. The pre-existing `tests/depth_and_noise.rs` measures the noise
  curve on this same chain as growing ~1.2 bits per doubling of depth against a
  72.26-bit budget, and extrapolates exhaustion near depth 2^30.
- **Shapes 2 and 3 are TRUE LIMITS.** Both fail at depth 2 with a wrong decryption.

### 4.2 What this means — the part that must not be flattened

**Depth is a property of the chain shape, not of the scheme.**

Shape 1 clears the floor by 10×. But Shape 1 runs in **symmetric mode**, which
requires the secret key at the evaluator — `mul_dual_symmetric` documents itself as
*"WARNING: This requires the secret key... NOT SECURE for multi-party."* That is not
the FHE threat model; it is computing on your own data.

**Shape 3 is the FHE model** — evaluator holds no secret key, relinearization goes
through the evaluation key — and it reaches **depth 1**. Public-mode relinearization
adds ~29 bits of noise per multiply against a 72-bit budget, which exhausts after
two multiplies. **The deep-depth property of Shape 1 does not transfer to the mode
that matters for homomorphic evaluation.**

So:

- ✅ "NINE65 sustains multiplicative depth ≥ 200" — **true only** for a symmetric
  chain against a fresh low-noise operand, and only with the secret key at the
  evaluator.
- ❌ "NINE65 sustains multiplicative depth ≥ 200 under homomorphic evaluation" —
  **false as measured.** That configuration reaches depth 1.
- ❌ "depth 200 was achieved pre-CRAM, therefore depth 200 holds now" — this is the
  inference this document exists to block. What is verified now is the table in §4.1
  and nothing beyond it.

### 4.3 What *is* solidly established

The **anti-ladder invariant holds**, and this is the strongest positive result here.
Across all three chains, and specifically across **2048 consecutive multiplies** in
Shape 1, the lane shape `(main, anchor, level)` stayed pinned at `(3, 5, 3)`. The
bench asserts this at **every link**, so a reintroduced modulus switch fails the
bench rather than silently corrupting the depth number. Per-link *timing* is flat in
depth (§2.2), which is the independent timing-side confirmation.

The basis does not move. That part of the architecture measures out exactly as
specified.

### 4.4 Provenance — the bench is modelled on known-good passing tests

The encrypt/multiply/decrypt shape was taken from two tests **run green before the
bench was written**:

- `crates/nine65/src/ops/rns_fhe.rs` → `tests::test_secure_128_mul_dual_symmetric`
  — the canonical `secure_128` shape: `generate_keys_dual` → `encrypt_dual` →
  `mul_dual_symmetric` → `decrypt_dual`, asserting `(a*b) % t`. **Verified passing.**
- `crates/nine65/tests/depth_and_noise.rs` → `depth_and_noise_curve_deep_chain` —
  the chain driver and the `generate_keys_dual_full` / `precompute_s_squared` /
  `mul_dual_symmetric_with_s2` shape. **Verified passing** (reached depth 256).

The new bench independently reproduces every number that pre-existing test produces.
It deliberately uses only `decrypt_dual`, never `decrypt_dual_with_diagnostics`
(which is `pub` only under `cfg(any(test, debug_assertions))`), so the depth floor
cannot become unmeasurable because of a `RUSTFLAGS` requirement.

### 4.5 Gap: nothing *enforces* this floor

The bench **reports**; it does not assert (a panicking benchmark is useless). The
existing `tests/depth_and_noise.rs` asserts only `DEPTH_REGRESSION_FLOOR = 32`, and
only on the symmetric shape. **No test in the repo currently enforces depth ≥ 200 on
any shape.** Turning §4.1 into an enforced floor means adding a test with a real
`assert!(max_correct_depth >= 200)` gated on the shape actually being claimed.

Do **not** let `test_stress_budget_depth_200_precision`
(`crates/nine65/tests/bootstrap_integration.rs:1090`) stand in for it. Inspected: it
constructs a bare `NoiseBudget`, loops 200 times consuming `NoiseOpType::**Add**`,
and asserts `500000 - 200000 == 300000`. It touches **no ciphertext**, performs **no
multiply**, and measures the retired "budget consumed" metric class. The only thing
"200" and "depth" have to do with it is the function name.

---

## 5. Bench-suite health

### 5.1 Which benches measure the retired modulus-switching mechanism?

**None of them.**

Grepping every bench source in `crates/nine65/benches/` and `crates/mana/benches/`
for `mod_switch` / `modulus_switch` / `NoiseBudget` / `noise_budget` /
`levels_remaining` returns **no hits** outside the new `depth_chain.rs`, where
`level` appears only inside the anti-ladder assertion (asserting that the level does
**not** move).

The retired-mechanism problem lives in the **test suite** — the ~18 failures being
quarantined in the concurrent workflow — not in the bench suite. **No bench target
needs to be retired on modulus-switching grounds.**

**One near-miss worth stating explicitly:** `timing/rns_kelim_rescale/k_elim_rescale`
has "rescale" in its name, which in classical BFV means modulus switching. It is
**not** that. It benches `k_elim_rescale_dual`, i.e. CRAM exact division: it divides
the value and the basis does not move. It is the *current* mechanism. The retirement
is recorded in-source at `crates/nine65/src/ops/rns_fhe.rs:2773`, where the auto
modulus-switch that used to run at the end of `mul_dual_symmetric` is gone and the
multiply returns at full lane count. **Keep this bench.**

### 5.2 Benches that should be retired or fixed — on other grounds

| Bench | Grounds | Detail |
|---|---|---|
| `fhe_scaling/homo_mul_scaling` | deprecated path + wrong labels | Benches `BFVEvaluator::mul`, `#[deprecated]` in favour of `mul_dual_symmetric`, over a single 30-bit modulus with the RNS chain unused. Re-point at the DualRNS path or remove. |
| `fhe_scaling/encrypt_decrypt_scaling` | deprecated path + wrong labels | Same: `BFVEncryptor`/`BFVDecryptor` on `config.q = primes[0]`. |
| `adaptive_rayon/*` | posture tension | `threading_comparison` is excluded *by design* for benchmarking rayon against MANA, a rejected parallelism approach. `adaptive_rayon` survives that exclusion while benchmarking the same rejected rayon layer, and its `thread_pool_creation` group constructs rayon `ThreadPool`s directly. Flagged, not decided here. |

**The mislabelled-N defect**, confirmed from source (`secure_configs.rs:176–232`)
and corroborated by the data:

| Bench id says | Config used | Actual N |
|---|---|---:|
| `N=2048/128-bit` | `secure_128` | **8192** |
| `N=4096/128-bit-deep` | `secure_128_deep` | **8192** |
| `N=4096/192-bit` | `secure_192` | **16384** |
| `N=8192/256-bit` | `secure_256` | **16384** |

Two of the three "scaling" points are the same ring degree. The data proves it
independently: pairs that should differ 2× in N measure within 3 % of each other
(11.289 vs 10.965 ms; 24.447 vs 25.311 ms). The file's doc comment claiming a sweep
across N=1024…8192 is false.

### 5.3 Benches that produce zero measurements

| Target | Status | Cause |
|---|---|---|
| `mana/lane_ops` | 0 measured | `[[bench]] harness = false` stanza is **commented out** in `crates/mana/Cargo.toml` and `autobenches = false` is not set, so the file is auto-discovered under the libtest harness and criterion's `main()` never runs. Undocumented; one-line fix. **Not applied.** |
| `exact_transcendentals/performance` | 0 measured | **No `[[bench]]` stanza at all**, same auto-discovery result. Reads as an oversight — the crate declares criterion in `[dev-dependencies]` with `html_reports` enabled. **Not applied.** |
| `threading_comparison` | not a target | **Deliberate and documented** at `crates/nine65/Cargo.toml:150-153`, backed by `autobenches = false`. The previously reported "fails to build because rayon is not in dev-dependencies" is a *consequence* of that intentional exclusion, not a bug. Nothing to fix. |

### 5.4 BLOCKING: the SEAL comparison bench cannot reach its FHE groups

`nine65_vs_seal_comparison` is documented as the target for the sub-5 ms claim. **It
can never reach that group.** `criterion_group!` registers
`bench_cyclotomic_operations` (8th) before `bench_fhe_operations` (9th) and
`bench_fhe_key_generation` (10th). The cyclotomic setup calls
`CyclotomicRing::new(4096, 1152921504606584833u64)`, and
`find_primitive_root` (`crates/nine65/src/arithmetic/cyclotomic_phase.rs:31`) is a
**linear scan over the entire field**:

```rust
fn find_primitive_root(n: usize, q: u64) -> u64 {
    let two_n = 2 * n as u64;
    for g in 2..q {                                   // q = 1.15e18
        if Self::pow_mod(g, two_n, q) == 1 { ... }
    }
}
```

Only 4096 of ~1.15e18 field elements have order exactly 8192, so the first
qualifying `g` sits near q/4096 ≈ 2.8e14. Measured scan rate 24.7 M candidates/s
⟹ expected wall time ≈ **1.14e7 s ≈ 132 days**. This is not "slow", it is
unreachable. Criterion filters skip *measurement*, not *setup*, so no filter bypasses
it — a filtered 10-minute run produced zero output.

**7 of ~30 ids are permanently unreachable:** `Cyclotomic Phase`,
`FHE_DualRNS_K-Elimination`, `FHE_KeyGen`.

**Status: mitigated.** The new `depth_chain` bench measures the same multiply
in-repo at 105.58 ms, against the unreachable id's standalone-probe value of
105.017 ms. The cyclotomic scan itself still needs fixing (a primitive root should be
found by factoring q−1, not by scanning), but the FHE numbers are no longer blocked
on it.

---

## 6. Reproducing

```bash
# depth floor (§4) — the survey prints the verdict table
cargo bench -p nine65 --bench depth_chain

#   knobs: NINE65_DEPTH_CHAIN_MAX (default 256), NINE65_DEPTH_CHAIN_SECS (default 900),
#          NINE65_DEPTH_CHAIN_SURVEY=0 to skip the survey and time links only
NINE65_DEPTH_CHAIN_MAX=2048 cargo bench -p nine65 --bench depth_chain -- zzz_match_nothing

# corroborating pre-existing test, incl. the noise curve
RUSTFLAGS="-C debug-assertions=on -C overflow-checks=off" \
  cargo test --release -p nine65 --test depth_and_noise -- --nocapture --test-threads=1

# lane-level (§1)
cargo bench -p nine65 --bench timing --features benchmarks

# quick-pass settings used throughout this baseline
cargo bench -p nine65 --bench <target> -- --warm-up-time 1 --measurement-time 3 --sample-size 10
```

`nine65_vs_seal_comparison` will hang; see §5.4.

---

## 7. Open items

1. **No test enforces depth ≥ 200** on any shape (§4.5). The floor is measured but
   not defended against regression.
2. **Public-mode depth is 1** (§4.2). If depth under homomorphic evaluation is a
   product requirement, this is the gap, and it is a relinearization-noise problem,
   not a depth-ladder problem.
3. **Sub-5 ms latency claim needs restating** (§3) — currently false for multiply by
   21× (symmetric) / 56× (public).
4. `find_primitive_root` linear scan (§5.4) — should factor q−1 instead of scanning.
5. Mislabelled N across `fhe_scaling` (§5.2).
6. Entropy monitor compiles to a no-op under the bench feature set (§1.5), which also
   invalidates the `adaptive_vs_static` comparison.
7. `mana/lane_ops` and `exact_transcendentals/performance` measure nothing (§5.3).
8. Re-run everything with criterion defaults on a quiet machine before publication.
