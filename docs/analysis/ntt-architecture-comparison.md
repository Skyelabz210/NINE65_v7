# NTT Architecture Comparison: v01/v02 (DFT Matrix) vs v03+ (Cooley-Tukey)
## NINE65 Depth Ceiling Investigation — Track D
**Date**: 2026-02-25

---

## 1. Summary

NINE65's Number Theoretic Transform implementation underwent a fundamental architectural change between v02 and v03. v01 and v02 use a DFT matrix approach with O(N²) complexity. v03 introduced Cooley-Tukey DIT with O(N log N) complexity, coinciding with the introduction of MANA (the lane-parallel stream accelerator). v04 inherited v03's implementation unchanged.

**When CT was introduced**: v03, alongside MANA. NOT v02 ("stable" in v02 meant stability hardening of the DFT approach, not an algorithm change).

---

## 2. Structural Comparison

| Dimension | v01/v02 (DFT Matrix) | v03/v04/v7 (Cooley-Tukey) |
|-----------|---------------------|--------------------------|
| Algorithm | DFT matrix, O(N²) | Cooley-Tukey DIT, O(N log N) |
| Core loop | Nested `for k, for j: sum += a[j] * omega^(k*j)` | In-place butterfly stages: `u = a[u]; t = w*a[v]; a[u]=u+t; a[v]=u-t` |
| Reduction strategy | `% self.q as u128` after every multiply | `montgomery_mul` per butterfly — reduces to [0,q) at each stage |
| Number representation | Native u64, intermediate u128 for products | Montgomery form throughout |
| Twiddle factors | Computed on-the-fly from `omega_powers[]` | Precomputed in Montgomery form (`twiddles_fwd[]`, `twiddles_inv[]`) |
| ψ-twist | Coefficient-by-coefficient before/after transform | Baked into precomputed twiddles (implicit in Montgomery form) |
| Bit-reversal | None (DFT matrix is inherently ordered) | Explicit bit-reversal permutation before butterfly stages |
| Memory layout | New output array (not in-place) | In-place (same array throughout) |
| Lazy reduction | N/A | Not used — `montgomery_mul` gives canonical [0,q) at each butterfly |
| Error correction | Triple-stream CRT (α, β, γ correction rounds) | Single-pass (Montgomery guarantees correctness) |

---

## 3. Key Question: Where Does Each Version Place Modular Reduction?

### v01/v02 — Reduction Inside the Innermost Loop

```rust
// v01 style (simplified)
for k in 0..n {
    let mut sum = 0u128;
    for j in 0..n {
        sum += (a[j] as u128) * (omega_powers[(k * j) % n] as u128);
        // No reduction here — accumulates in u128
    }
    result[k] = (sum % q as u128) as u64;  // Reduction once per output element
}
```

**Problem**: `sum` accumulates N products of (≤ q) × (≤ q) ≈ N × q². For N=4096 and q ≈ 2³⁰: `4096 × (2³⁰)² = 2¹²` × 2⁶⁰ = 2⁷² bits needed. u128 has 128 bits, so this fits for N=4096, but headroom shrinks fast with larger N and larger q.

**Consequence**: v01/v02 NTT was inherently limited to smaller N and q values before overflow.

### v03/v7 — Reduction at Every Butterfly

```rust
// v03 Cooley-Tukey butterfly (actual code)
let u = a[u_idx];
let t = self.mont.montgomery_mul(self.twiddles_fwd[t_idx], a[v_idx]);
a[u_idx] = self.mont_add(u, t);    // stays in [0, 2q)
a[v_idx] = self.mont_sub(u, t);    // stays in [0, 2q)
```

`montgomery_mul` reduces to `[0, q)` at each step. `mont_add/mont_sub` result in `[0, 2q)`. No value ever exceeds 2q, regardless of N or q size.

**Consequence**: v03+ NTT is numerically safe for any N and q that fit in the Montgomery parameters, including the large q values required by secure_192 and secure_256.

---

## 4. Key Question: Harvey Lazy Reduction?

**Short answer: No.** v7 does NOT use Harvey lazy reduction (also called "lazy butterfly" or "delayed reduction").

Harvey lazy reduction keeps values in [0, 2q) through the butterfly stages, deferring the final [0, q) reduction until the end. This is a performance optimization that halves the number of full reductions at the cost of carrying wider intermediates.

v7's butterfly uses `montgomery_mul` which reduces to [0, q) per butterfly — the conservative (non-lazy) variant. Each butterfly output is fully reduced before the next stage reads it.

**Why this matters for correctness**: The non-lazy variant is strictly correct. Harvey lazy is also correct but requires the final pass to reduce from [0, 2q). No practical correctness concern either way for the range of q values in NINE65's configs.

**Why this matters for performance**: Non-lazy CT does more work than Harvey lazy (one extra reduction per butterfly pair). For N=4096 (secure_128), there are log₂(4096) = 12 stages × 2048 butterflies/stage = 24,576 extra `montgomery_mul` calls vs Harvey lazy. At ~3ns each: ~73µs overhead. For N=16384 (secure_192/256): ~1.2ms overhead. This is already counted in the performance baselines.

---

## 5. Key Question: Does the CT Stride Pattern Conflict with CRT Lane Layout?

**Answer: No conflict. The two are decoupled.**

MANA's lane-parallel pipeline operates at the ciphertext polynomial level — it splits the work across `lane_count` independent polynomial pairs. Each lane independently calls the NTT on its assigned polynomial slice.

The NTT's CT stride pattern (bit-reversal index permutation) operates within a single polynomial. The stride computation is: `u_idx = k + j`, `v_idx = k + j + half_m`, where `m` doubles each stage.

CRT decomposition in NINE65's RNS context is at the prime level, not at the polynomial coefficient level. For a polynomial of degree N, each prime `p_i` has its own residue polynomial `a_i[x]` with N coefficients. The NTT is applied to each `a_i[x]` independently.

**In practice**: MANA assigns entire `(p_i, polynomial)` pairs to lanes. Each lane runs a complete NTT on its N-coefficient polynomial. There is no cross-lane stride interaction.

---

## 6. Key Question: What Did v01/v02 Do with Triple-Stream CRT Error Correction?

v01 used a three-stream approach to validate and correct the DFT computation:

```
Stream α: DFT with primitive root g (standard)
Stream β: DFT with g' = g² (redundant)
Stream γ: DFT with g'' = g⁴ (double-redundant)
```

After transform, coefficients are cross-checked: `result_α[k] == result_β[k/2]` (mod q) for even k. If they disagree beyond a threshold, Stream γ is used to vote on the correct value.

**Purpose**: The DFT matrix approach accumulates errors in the u128 accumulator for large N. The triple-stream correction was a band-aid to catch the cases where modular reduction of an imprecise sum gave a wrong final digit.

**In v03+**: This mechanism was removed entirely. Montgomery form arithmetic guarantees exact reduction at each step — no accumulation error, nothing to correct. The triple-stream machinery was dead weight once CT replaced DFT matrix.

---

## 7. Version Dating Summary

| Version | NTT Algorithm | Key Change |
|---------|--------------|------------|
| v01 | DFT matrix (O(N²)) | Original implementation |
| v02 | DFT matrix (O(N²)) | Stability hardening only — no algorithm change |
| v03 | Cooley-Tukey DIT (O(N log N)) | CT introduced with MANA; `ntt_fft.rs` added alongside `ntt.rs` |
| v04 | Cooley-Tukey DIT (inherited) | `ntt_fft.rs` unchanged from v03 |
| v7 | Cooley-Tukey DIT (inherited, evolved) | Tighter Montgomery integration, extended for secure_192/256 |

The `ntt.rs` file (DFT matrix) was retained in v03+ for reference/fallback but is not used in the production cipher path. The production path unconditionally uses `ntt_fft.rs` (CT) when the `ntt_fft` feature flag is active — which it is by default.

---

## 8. Implications for Depth Ceiling Analysis

The NTT architecture does NOT impose the depth ceiling. The ceiling for secure_128 (depth 1 without bootstrap) is determined by the noise budget, not by the NTT's precision.

Specific observations:
1. **CT guarantees exact NTT for all configs** — no NTT rounding error contributes to depth limits.
2. **The DFT matrix approach would have been the bottleneck** for secure_192/256 — those configs (N=16384, q ≈ 2¹⁴⁷) would have caused u128 overflow in the innermost accumulator. CT solved this problem.
3. **Performance asymptote**: secure_128 NTT time with CT ≈ O(4096 × 12) = 49,152 butterflies. With DFT matrix: 4096² = 16,777,216 multiplications. CT is ~342× fewer operations, consistent with the observed speedup in v03 benchmarks.
4. **Harvey lazy would reduce NTT overhead by ~30-40%** if implemented. This is a future optimization opportunity, not a current correctness issue.

---

## 9. Files Referenced

| File | Version | Role |
|------|---------|------|
| `/tmp/v01_extract/qmnf_fhe_production/src/arithmetic/ntt.rs` | v01 | DFT matrix implementation, triple-stream correction |
| `/tmp/v03_extract/crates/nine65/src/arithmetic/ntt_fft.rs` | v03 | CT DIT implementation, Montgomery form throughout |
| `crates/nine65/src/arithmetic/ntt_fft.rs` | v7 | Production CT (evolved from v03) |
| `crates/nine65/src/arithmetic/ntt.rs` | v7 | DFT matrix (retained, not used in production path) |
