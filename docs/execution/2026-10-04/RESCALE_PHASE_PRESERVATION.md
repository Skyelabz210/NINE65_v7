# Canonical phase in dual-RNS rescale

Status: **local arithmetic correction only**. This does not admit a deeper BFV circuit, implement refresh, or replace the legacy dual route with the requested FPD/CRAM transduction route.

For the main modulus `Q=tΔ+r`, `0≤r<t`, K-elimination derives `K` against the **canonical** main representative `v=X mod Q`, so `X=v+KQ`. If `K≥0`, write `K=jΔ+κ`, `0≤κ<Δ`. Then

```text
round(X/Δ) mod Q = κt + round((v+κr)/Δ) mod Q.
```

For `K<0`, write `−K=jΔ+κ` and use `−κt + round((v−κr)/Δ) mod Q`. The removed `jQ` is an integer, so it does not alter the rounding decision. These identities require the same `v` that was used to derive `K`.

The previous implementation centered `v` to `v−Q` when `v>Q/2` but left `K` unchanged. That changed the represented integer from `X` to `X−Q` and the rescale output by approximately `−t`. A direct two-case oracle holds the main residue fixed at `Q−1` and changes only the anchor phase:

| Signed integer identified by both bases | Expected `round(X/Δ) mod Q` | Before | After |
|---|---:|---:|---:|
| `Q−1` (`K=0`) | `t=65537` | `0` | `65537` |
| `−1` (`K=−1`) | `0` | `Q−t` | `0` |

The correction keeps `v` canonical in `k_elim_rescale_dual`. It does not change `mod_switch_down_dual`, whose separate centered modulus-switch semantics intentionally use a centered representative. The regression is `k_elim_rescale_preserves_upper_half_phase` in `rns_fhe.rs`; before/after test logs are in `artifacts/execution/2026-10-04-rescale-phase/logs/`.

The depth-4 issue remains open. On the current GSO repeated-square route, source-bound controls on draft PR #156 still fail at depth 4 after this correction. The zero-fresh-error controls now miss by exactly `+1`: target `−1` decodes as `0`, and target `+1` decodes as `2`. The ordinary encrypted `secure_128` run has a larger error. That remaining difference belongs to the BFV component scale-round/relinearization investigation in #157. A prime-2 parking lane could represent a **proven one-bit correction** per coefficient, but it cannot recover an unconstrained winding or an already lost phase; the correction bit, its range, and its transduction into the ciphertext must be established before use.
