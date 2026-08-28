# T3 — M3: Lane-Local Relinearization (RNS-Limb Gadget)

**Tier: FABLE-TIER.** This embeds non-standard math (a CRT-idempotent
gadget decomposition replacing a base-2^b digit decomposition) directly into
the hot path. Do not hand this to a small/context-limited agent without a
frontier-capable review pass on the design before it lands.

**Status: LANDED, depth-2 scope (2026-08-26).** The design below is
implemented (`DualRNSGadgetKey`, `generate_gadget_key_with_rng`,
`relinearize_rns_limb`, `mul_dual_public_manufactured_gadget`,
`CramPublicEvaluator::mul_manufactured_gadget`), guardrail-pinned (zero
`to_u256_level` calls in the relin step), and depth-2 exact. **Depth 3 is
NOT reliable** — this is the "Escalate-if" condition this card names below,
and it was hit: a 30-seed sweep showed 0/30 failures at depth 1-2 and
18/30 at depth 3, a real noise-budget limit (larger per-lane digits than
the base-2^b scheme, compounding through the tensor product across levels),
not a correctness bug. Tests and public entry points are scoped to depth 2
accordingly. See `docs/CRAM_PUBLIC_MODE.md` M3 and PS-CP-8 for the full
finding. **Remaining work** (not done in this pass): a hybrid gadget (RNS
lane × base-2^b sub-decomposition within each lane) to reduce per-level
noise and reach depth-3 parity — a follow-up design task, not a bug fix.

## Goal

Remove the LAST materializing site in the manufactured multiply path:
`extract_digit_dual` reconstructs the full exact 256-bit tensor coefficient
value (`to_u256_level` + K-Elimination) and then bit-shifts base-`2^b`
digits out of it. Replace it, for manufactured chains only, with an
**RNS-limb gadget**: the "digits" are simply the per-lane residues the
ciphertext already carries — zero extraction, lane-local, G5-derivable
eval-key constants.

## Why this is sound (read before implementing)

CRT reconstruction identity: for coprime `q_1..q_k` with `Q = ∏ q_i`, define
the idempotents `g_i = (Q/q_i) · [(Q/q_i)⁻¹ mod q_i]`. Then for any `P` with
`0 ≤ P < Q`:

```
Σ_i  [P]_{q_i} · g_i  ≡  P   (mod Q)
```

This is the SAME identity `parallel_summation_crt` already uses at runtime
(M2a) — T3's contribution is using it **homomorphically**: instead of
computing this sum in the clear at runtime (materializing `P`), each term
`[P]_{q_i} · g_i` is applied as a **scalar-times-ciphertext** operation
against a PRE-ENCRYPTED `g_i · s²`. The materialization moves into the
eval-key algebra, at keygen time, where it is key material — not runtime
ciphertext state.

## Files (read these anchors, not the whole file)

- `crates/nine65/src/ops/rns_fhe.rs`:
  - `extract_digit_dual` (search for the function definition) — the
    materializing site being removed for the manufactured path. Read its
    doc comment and the `to_u256_level` / `extract_k_rns_level_cached` calls
    inside the coefficient loop; this is what the RNS-limb gadget replaces.
  - `relinearize_dual` (search for the function definition) — the caller;
    note it loops `evk.rlk` by `digit_idx` and calls `extract_digit_dual`
    once per digit, then `dual_poly_mul` against `rlk0`/`rlk1` and
    accumulates. The RNS-limb version has the SAME shape, one iteration per
    MAIN LANE instead of per base-`2^b` digit.
  - `DualRNSEvalKey` (struct definition, ~line 313): `pub rlk: Vec<(DualRNSPoly,
    DualRNSPoly)>`, `pub decomp_base: u64`, `pub num_digits: usize`. The new
    RNS-limb key needs a parallel struct or an added variant — do not repurpose
    `decomp_base`/`num_digits` for a different meaning; that silently breaks any
    code reading them.
  - `generate_keys_dual_full_public_deep_with_rng` /
    `generate_keys_dual_full_with_base_with_rng` — existing keygen entry
    points to model the new `generate_keys_rns_gadget` on (same RNG threading,
    same secret-key-derived `s²` computation).
  - `mul_dual_public_manufactured` — the entry point to wire the new
    relinearization into, behind the same public method
    (`CramPublicEvaluator::mul_manufactured`), for manufactured chains only.
  - `k_elimination.rs` / `params/primes.rs::extended_gcd` — use for deriving
    `(Q/q_i)` and its inverse mod `q_i` at keygen. **Extended Euclid only** —
    house rule, composite moduli are the default, Fermat/`pow(a, m-2, m)`
    inverses silently assume a prime modulus.

## DO NOT

- **Do not keep or reintroduce the base-`2^b` gadget "for smaller noise"
  without measuring first.** The RNS-limb gadget's noise is `q_i`-scaled
  (see the noise estimate below); the manufactured chain's `Δ ≈ 2^92`
  headroom is sized to absorb it, but this is a measured claim to verify
  empirically, not to assume.
- **Do not derive digits by materializing `P`.** That is exactly the site
  being removed. If your implementation calls `to_u256_level` or
  `extract_k_rns_level*` anywhere in the RNS-limb relin path, you have not
  actually eliminated the materialization — stop and re-read the idempotent
  identity above.
- **Do not use Fermat's-little-theorem inverses** (`pow(a, m-2, m)`) for
  `(Q/q_i)⁻¹ mod q_i`. Composite moduli are the default in this codebase;
  Fermat requires prime `q_i` and will silently produce garbage or panic on
  a composite one. Use `extended_gcd` (`params/primes.rs`), same as every
  other inverse in this codebase.
- **Do not replace the existing materializing path.** Non-manufactured
  configs (`secure_128`, `secure_192`, etc.) still use
  `extract_digit_dual`/`relinearize_dual` unchanged. The RNS-limb gadget is
  additive (`generate_keys_rns_gadget` + `relinearize_rns_limb`), gated to
  manufactured chains, not a replacement of the general-purpose path.

## Pseudocode

```
// ── keygen (new) ──────────────────────────────────────────────────────
// For each main lane q_i of the manufactured chain (i = 0..lanes.len()):
//   Q_over_qi        = Q / q_i                       // exact, Q is a manufactured product
//   Q_over_qi_mod_qi = Q_over_qi mod q_i
//   inv              = extended_gcd(Q_over_qi_mod_qi, q_i)  -> (Q/q_i)^{-1} mod q_i
//   g_i              = Q_over_qi * inv                // the CRT idempotent, as a u128/U256
//   rlk_i            = Enc_pk( s^2 * g_i )            // one (c0,c1) pair per MAIN lane
// g_i and its derivation (Q/q_i, extended_gcd) are G5-clean: cached but
// re-derivable from the declared chain at any time.

// ── relin (new) ──────────────────────────────────────────────────────
// Input: poly (the d2 tensor component BEFORE rescale — check whether M3
// relinearizes pre- or post-rescale against the current call site; the
// existing `relinearize_dual` call in `mul_dual_public_manufactured` runs
// on `d2_s` (POST-rescale), so RNS-limb relin should too, for a like-for-
// like swap).
// digits ARE the per-lane residues already held on the ciphertext:
//   d_i = poly.main[i]          // no extraction, no materialization
// (c0', c1') = Σ_i  d_i ⊙ rlk_i[0..1]      // per-lane scalar-poly mult + accumulate
//   ⊙ is a scalar-times-polynomial multiply: each coefficient of d_i (a
//   residue mod q_i, but here read as a plain u64 scalar per NTT slot — NOT
//   reduced through q_i again) times the corresponding rlk polynomial,
//   accumulated across all lanes. This mirrors `relinearize_dual`'s existing
//   per-digit `dual_poly_mul` + `dual_poly_add_assign` loop shape exactly,
//   with "digit index" replaced by "lane index".
```

## Noise estimate (verify empirically, do not just trust this)

```
|relin noise| ≈ Σ_i  q_i * N * |e_rlk|
```

For the manufactured chain (`manufactured_m2b_insecure`: N=512, 3 main
lanes ~2^31 each — get exact values from `FHEConfig::manufactured_m2b_insecure`,
do not hand-copy this document's numbers into code): roughly
`3 * 2^31 * 2^9 * e ≈ 2^42 * e` versus `Δ/2 ≈ 2^92` → margin ≈ `2^49`. This
is a back-of-envelope estimate from the plan, not a measured or proven
bound — the acceptance criteria below require measuring it for real on the
actual chain.

## Steps

1. Add `generate_keys_rns_gadget` (new keygen fn, parallel to existing ones,
   manufactured chains only — typed error otherwise, same pattern as
   `k_elim_rescale_manufactured`'s `t | Q` check).
2. Add `relinearize_rns_limb` (new relin fn, same signature shape as
   `relinearize_dual`).
3. Wire into `mul_dual_public_manufactured` (or a new
   `mul_dual_public_manufactured_v2` if swapping in place risks breaking the
   existing plaintext-agreement test — your call, document which).
4. Add a counter-based guardrail (T2-style, never-vacuous): assert the
   RNS-limb relin path performs ZERO `to_u256_level` / `extract_k_rns_level*`
   calls on a real manufactured multiply — same pattern as
   `cram_public_guardrail_manufactured_multiply_never_calls_garner` in
   `arithmetic/unified_rescale.rs` (a `#[cfg(test)]` `AtomicUsize` counter
   incremented at the top of `to_u256_level`, read before/after).
5. Extend the M2b acceptance suite (`tests/m2b_manufactured_rescale.rs`):
   depth-3 squaring chain must stay exact with the new relin swapped in.
6. Add a proof-sketch entry (`docs/CRAM_PUBLIC_MODE.md`, new PS-CP-n) for
   the RNS-limb gadget's correctness, status SKETCH + WITNESS.

## Commands

```
cargo build -p nine65 --release --features allow_insecure
cargo test -p nine65 --test m2b_manufactured_rescale --release --features allow_insecure
cargo test -p nine65 --lib --release
```

## Acceptance criteria

- Depth-3 manufactured squaring chain (2→4→16→256) stays exact with the new
  relin path.
- New counter guardrail green, and manually verified never-vacuous (flip it
  locally — swap in a call to the old materializing path inside the new
  function — confirm the guardrail goes red, then revert; do not commit the
  flipped form).
- Full lib suite stays green (`cargo test -p nine65 --lib --release`, no
  regression from the current 770-passing baseline).
- Noise margin measured (not assumed) on the real manufactured chain and
  recorded in the new PS-CP-n entry.

## Escalate-if

- The measured noise margin is much smaller than the back-of-envelope
  estimate above (investigate before shipping — do not just widen the
  chain to compensate without understanding why).
- The eval-key size becomes pathological (one `(DualRNSPoly, DualRNSPoly)`
  pair per main lane is small for the manufactured chain's 3-4 lanes, but
  verify before assuming this scales fine to larger configs).
- Swapping the relin path changes WHICH lanes the certificate/shift logic
  in `k_elim_rescale_manufactured` needs to see (e.g. if pre-rescale
  relinearization turns out to be required instead of post-rescale) — that
  is a design decision, not a mechanical swap; stop and get a design review
  rather than guessing.
