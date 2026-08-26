# NINE65 vs Microsoft SEAL — Head-to-Head, 2026-08-26

First direct benchmark of NINE65 against an external FHE library. SEAL v4.4.3
built from source on this machine; both libraries measured back-to-back on an
idle box with the same methodology.

**Headline:** at matched parameters NINE65's public multiply is **21× slower**
than SEAL's per ciphertext operation — and **~174,000× slower per plaintext
integer**, because SEAL packs 8192 independent values into one ciphertext and
NINE65's benchmarked path packs one. The second number is the one that matters
for throughput work, and it is not a tuning gap; it is a missing feature
(SIMD slot batching), which NINE65's own `ops/batch.rs` documents as
*"Not yet implemented (planned for v0.3)"*.

---

## 1. Setup

| | |
|---|---|
| Machine | 4 vCPU `Intel(R) Xeon(R) @ 2.10GHz`, 15 GB RAM, shared container |
| Date | 2026-08-26 |
| SEAL | v4.4.3, CMake `Release`, **HEXL off**, no `-march=native` (its default build) |
| NINE65 | commit `d0d998b`, `cargo --release` (lto=fat, cgu=1), default features, no `target-cpu=native` |
| Compilers | g++ 13.3.0 / rustc 1.94.1 |
| Harness | `/home/user/seal-bench/bench.cpp`, `crates/nine65/tests/{op_timings,cram_public_timings}.rs` |

Both sides are **generic optimized builds** — each project's own default. Neither
gets CPU-specific tuning. This CPU does expose AVX512-IFMA, which Intel HEXL
targets; enabling HEXL would move SEAL further ahead, so the numbers below are a
*lower* bound on SEAL, not an upper one.

**Methodology, identical on both sides:** 3 independent runs; each run reports
the median of 5 in-process rounds; every round decrypts and asserts exactness, so
no timing can come from a wrong answer. Tables below are medians of the 3 run
medians. The machine was verified idle (`loadavg < 1`, no `rustc`/`cargo`) before
measuring — an earlier attempt was discarded because a background job was holding
a core.

## 2. Parameter matching

NINE65 `secure_128_deep`: `N=8192`, `t=65537`, `q = [998244353, 985661441,
754974721, 469762049]` → **119 bits**.

SEAL was configured to the same `N` and `t` (65537 ≡ 1 mod 2N, so SEAL batching
is available). One asymmetry had to be handled explicitly rather than hidden:

> **SEAL reserves the last prime of `coeff_modulus` as the key-switching
> "special prime"**, so it is not available for ciphertext data. A 4×30-bit
> chain gives SEAL 120 total bits but only **90 effective**.

So both variants are reported:

| variant | coeff_modulus | total | **effective** | vs NINE65's 119 |
|---|---|---|---|---|
| `SEAL-matched` | 4 × 30 | 120 bits | 90 bits | same *total*, less compute room |
| `SEAL-wide` | 5 × 30 | 150 bits | 120 bits | **same *effective*** ← fairest |

`SEAL-wide` is the like-for-like row. `SEAL-matched` is included so nobody can
claim SEAL was handed a bigger modulus.

## 3. Latency at matched parameters (per ciphertext operation)

| Op | `SEAL-matched` (90-bit) | `SEAL-wide` (120-bit) | **NINE65 `secure_128_deep`** (119-bit) | NINE65 vs SEAL-wide |
|---|---|---|---|---|
| Encrypt | 2.693 ms | 3.266 ms | 5.620 ms | **1.7× slower** |
| Add | 0.081 ms | 0.118 ms | 1.492 ms | **12.6× slower** |
| mul_plain | 0.094 ms | 0.145 ms | 3.576 ms | **24.7× slower** |
| mul (+relin) | 12.10 ms | 15.51 ms | 329.61 ms | **21.3× slower** |
| Decrypt | 0.895 ms | 1.101 ms | 2.040 ms | **1.9× slower** |

NINE65's multiply includes relinearization internally, so it is compared against
SEAL's `multiply` + `relinearize_inplace` — like for like.

Encrypt and decrypt are within ~2×. The gap is concentrated in the **evaluation**
path: add 12.6×, multiply 21×.

## 4. Throughput per plaintext integer — the number that actually matters

SEAL's BFV ciphertext at `N=8192` holds **8192 independent plaintext slots**, and
multiplication is element-wise across all of them. This was verified, not
assumed: `verify_slots.cpp` fills all 8192 slots with distinct values, multiplies,
and checks every slot — **8192/8192 correct, 0 mismatches, 68 bits of noise
budget remaining**.

NINE65's benchmarked API (`encrypt_dual(m: u64, ...)`, which asserts `m < t`)
carries **one integer per ciphertext**.

| Op | SEAL-wide per integer | NINE65 per integer | ratio |
|---|---|---|---|
| Add | 0.0144 µs | 1,492 µs | **~103,600×** |
| mul (+relin) | 1.893 µs | 329,610 µs | **~174,100×** |

This is not a micro-optimization gap. `crates/nine65/src/ops/batch.rs` offers only
*coefficient* batching, where "Homomorphic mul results in polynomial product (not
element-wise!)", and states that SIMD slot batching "Requires `t ≡ 1 (mod 2N)`
— Future enhancement … **Not yet implemented (planned for v0.3)**". The
precondition is already satisfied (`t=65537`, `2N=16384`, `65537 mod 16384 = 1`),
and `batch.rs` contains no `DualRNS` integration, so it is not wired into the
evaluator path at all.

**Closing this one gap is worth ~4 orders of magnitude** on batch workloads — far
more than any constant-factor tuning of the existing path.

## 5. NINE65's manufactured chain (not comparable to SEAL — reported separately)

`manufactured_m2b_insecure` is `N=512`, below SEAL's minimum usable degree for
these moduli, so **no SEAL row exists for it**. It is included because it is where
M2b/M3 live:

| Op | median |
|---|---|
| Encrypt | 0.557 ms |
| Add | 0.066 ms |
| mul_plain | 0.479 ms |
| exact_divide | 0.032 ms |
| mul (general) | 91.49 ms |
| mul (M2b, elimination-first rescale) | 85.87 ms |
| **mul (M3, RNS-limb gadget relin)** | **19.89 ms** |
| Decrypt | 0.287 ms |

**M3 is 4.32× faster than M2b** and 4.60× faster than the general path — the
session's benchmark claim reproduces on an idle machine. Note this is `N=512`
against SEAL's `N=8192`: 16× smaller ring, so it cannot be read across.

## 6. Caveats — read before quoting any number here

1. **The 174,000× is a throughput figure, not a latency figure.** For a single
   scalar multiply with no batching opportunity, SEAL also takes 15.51 ms and the
   honest gap is 21×. The amortization only applies to ≥8192 independent values.
2. **SEAL is under-tuned here on purpose.** HEXL off, no `-march=native`. Both
   would widen the gap.
3. **Two NINE65 harnesses disagree on the same operation.** `op_timings` measures
   `secure_128_deep` public mul at 329.61 ms; `cram_public_timings` measures the
   same call at 491.91 ms. Both are medians of 3 on the same idle machine. The
   likely cause is cache/allocator pressure — `cram_public_timings` performs six
   ops per round including two other multiplies. **The conservative (faster)
   329.61 ms figure is used above**, which favors NINE65. Do not treat either as
   a single canonical number until this is chased down.
4. **Security levels are matched by parameter, not by certificate.** Both sides
   sit at N=8192 with ~120-bit moduli; SEAL enforces `tc128` internally, NINE65's
   own screening claims 128-bit for this config. No independent lattice-estimator
   run was done for this comparison.
5. **This measures throughput/latency only.** It says nothing about NINE65's
   actual differentiators — exact integer arithmetic, the emission ledger, the
   K-Elimination rescale. SEAL does not attempt those properties.

## 7. Reproduce

```bash
# SEAL (build once)
git clone --depth 1 --branch v4.4.3 https://github.com/microsoft/SEAL.git seal-src
cd seal-src && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DSEAL_BUILD_EXAMPLES=OFF -DSEAL_BUILD_TESTS=OFF -DSEAL_BUILD_BENCH=OFF \
  -DSEAL_USE_INTEL_HEXL=OFF -DSEAL_USE_MSGSL=OFF -DSEAL_USE_ZLIB=OFF -DSEAL_USE_ZSTD=OFF \
  -DCMAKE_INSTALL_PREFIX=../seal-install
cmake --build build -j4 && cmake --install build

# harness
g++ -O3 -std=c++17 bench.cpp -I../seal-install/include/SEAL-4.4 \
  -L../seal-install/lib -lseal-4.4 -o bench_generic
./bench_generic --rounds 5 --variant wide

# NINE65
cargo test -p nine65 --test op_timings --release --features allow_insecure -- --ignored --nocapture
cargo test -p nine65 --test cram_public_timings --release --features allow_insecure -- --ignored --nocapture
```

Harness sources: `/home/user/seal-bench/{bench.cpp,verify_slots.cpp,run_all.sh}`.
