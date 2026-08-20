# Modulus Switching in NINE65: Two Rescales Distinguished

This note records a distinction that is easy to conflate and has caused real
confusion in code review. It reflects the architecture in
A. Diaz, *"Modulus Switching in QMNF: From Exact Division to the Clockwork
Bootstrap"* (Aug 2026), and the actual state of the shipped code.

## The two operations

| | BFV rescale | Exact modulus switch (prime drop) |
|---|---|---|
| Divisor | `Δ = floor(Q/t)` | `q_k` (an RNS prime) |
| Encoding | `Δ·m` (message in high bits) | `m mod t` (message in low bits, BGV-style) |
| Math | `round(X / Δ)` | `(X − r_k)·q_k⁻¹ mod q_i` |
| Exactness | **inexact by necessity** | **exact** |
| Purpose | restore message scale after a multiply | drop one prime from the RNS basis |
| Shipped as | `RNSFHEContext::exact_rescale`, `k_elim_rescale_dual` | `exact_modulus_switch_drop_poly` / `_ct` |

## Why BFV rescale cannot be exact

Under `Δ·m` encoding, a homomorphic multiply produces a value at `Δ²·m²` scale
plus a noise term `e·e`. Restoring the `Δ·m` scale requires dividing by
`Δ = floor(Q/t)`. Two facts make this inexact and unavoidable:

1. `e·e` is not a multiple of `Δ`, so `X / Δ` is not an integer — `round(X/Δ)`
   is required, and the rounding error is intrinsic to BFV message extraction.
2. `Δ = floor(Q/t)` is **not a factor of `Q`**. It does not divide into the RNS
   prime basis at all, so no sequence of exact prime-drops can reproduce it.

For secure_128 (`Q ≈ 2^90`, `t = 65537 ≈ 2^16`): `Δ ≈ 2^74`, while a single RNS
prime `q_k ≈ 2^30`. Dividing by `q_k` in place of `Δ` mis-scales the message by
`≈ 2^44` and destroys decryption. This is why the historically named
`exact_rescale` **rounds** — the name is aspirational, documented as such in
the source, and the rounding is original to the founding commit (949b619), not
a regression.

## Why the prime drop *is* exact

For the align-and-drop operation, `r_k = X mod q_k`, so `X − r_k` is an exact
integer multiple of `q_k`. Hence for every surviving lane `q_i`:

```
    (X mod q_i − r_k) · q_k⁻¹  ≡  floor(X / q_k)   (mod q_i)
```

with no rounding term. This is the K-Elimination phase differential applied to
modulus dropping (treat `q_k` as the "main" modulus `M`, each surviving lane as
an "anchor" `A`). `exact_modulus_switch_drop_poly` implements exactly this and
is pinned by an **exhaustive** differential test against integer division over
the full dual range `[0, M·A)` (see
`crates/nine65/src/ops/rns_fhe.rs`), plus E-X2 coprimality-guard tests that
return a typed `Err` rather than a wrong value.

## Status and the migration it enables

`exact_modulus_switch_drop_*` is a **verified standalone primitive**. It is
deliberately **not** wired into the production multiply: the shipped scheme uses
BFV `Δ·m` encoding, whose rescale must divide by `Δ`, which the prime-drop
cannot do. Turning the prime drop into the production rescale is the
**Clockwork Bootstrap** direction of the paper — a scheme migration to BGV-style
`m mod t` encoding where the message survives a modulus switch (with the extra
BGV correction `≡ r_k·q_k⁻¹ (mod t)` to preserve the value mod `t`), setting
`q_small = t` so the switch collapses into decryption rounding at depth ≈ 1.

That migration touches encode, decrypt, and the multiply's scale-tracking; it is
tracked as separate work. This primitive is the load-bearing piece it will build
on, landed and verified first so the exact-division core is trustworthy before
the encoding changes around it.
