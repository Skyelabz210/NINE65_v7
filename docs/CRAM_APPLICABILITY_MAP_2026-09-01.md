# CRAM Applicability Map — where the exact / reversible / IID substrate legitimately applies

**Date:** 2026-09-01
**Branch:** `claude/cram-rlwe-security-gcvt1u`
**Companion to:** `CRAM_RLWE_COEXISTENCE_PLAN_2026-09-01.md`

This maps every point — in NINE65's own pipeline and in standard BFV / BGV /
CKKS — where CRAM's exact-integer, reversible, and i.i.d.-safe machinery applies
**within the nonpublic applicable range**, i.e. without ever putting a
non-wrapped secret-dependent value on the wire.

---

## The one rule that places everything

> Exact / reversible / i.i.d. CRAM applies to **(D1)** all plaintext-space
> structure, **(D2)** everything the secret-holder computes, and **(D3)** the
> *internal compute* of every evaluator operation — as derived, transient
> auxiliary state that is discarded before serialization. It **never** changes
> the on-wire **format** of a secret-dependent published object (public keys,
> evaluation/relin/galois keys, ciphertexts): those stay **single-modulus mod
> `Q`** (D4, forbidden for anchors).

D3 is safe under three mechanical conditions (D3-a/b/c from the plan):
**derived** from the mod-`Q` object, **transient** to one kernel call,
**wrapped output** (serialized result carries only mod-`Q` lanes).

### Capabilities referenced

| | Capability | Home domains |
|---|---|---|
| C1 | Exact K-Elimination / exact division (`k_elimination`, `kelim_residue_divider`, `exact_divider`) | D1, D2, D3 |
| C2 | Non-reconstruction base movement (`base_ext` redundant-lane rank recovery) | D3 |
| C3 | Reversible lane ops (7/8 CramOp bijective; Sqr needs a branch witness) | D1, D2, D3 |
| C4 | i.i.d. / emission audit (`arrow_emission_gate`) — incl. **sampler correctness** | D2 (audit) |
| C5 | Chimera heterogeneous lanes (`exact_transcendentals::chimera`) | D1 |
| C6 | Unified rescale, two exits (`unified_rescale`: `Reraise`=BFV, `ModulusReduced`=BGV) | D3 |
| C7 | StarLift / adjacency winding (`unified_rescale::adjacency_project`, star lanes) | D1, D2, D3 |
| C8 | `compare_bit` constant-time half-modulus decision | D2 |

---

## Map 1 — NINE65 pipeline (grounded in real functions)

| # | Operation (function) | Domain | Applies | Status / action |
|---|---|---|---|---|
| 1 | Key samplers (`sample_uniform_dual_poly`, `sample_cbd_signed_rng`) | D2 | **C4** | **Opportunity, security-positive.** Run the arrow/emission audit on sampler output to certify full-support `a` and correct CBD `e` — the exact class of defect behind the old `a`-confined-to-`[0,2^64)` leak. |
| 2 | Published keys (`DualRNSPublicKey`, `DualRNSFullKeySet`, relin/galois keys) | **D4** | — | **Constraint.** Serialize **main-only**. No anchor. This is the WIRE-Q gate (plan E4). |
| 3 | Encode / batch (`encode_vector`, `decode_vector`) | D1 | **C5, C7, C3** | **Opportunity.** SIMD CRT batching already lives here; chimera heterogeneous slot packing and StarLift winding on *messages* extend it. Plaintext is public — fully exact, no security surface. |
| 4 | Encrypt (`encrypt*`, `encrypt_dual*`) | D2 rand / **D4** out | **C4** | Sampler audit on ephemeral randomness; ciphertext **output stays mod-`Q`**. |
| 5 | Add/Sub/AddPlain/MulPlain/Negate (`add`, `sub`, `add_plain`, `mul_plain`, `negate`) | lane-wise mod `Q` | **C3** | **Already exact.** Reversible lane ops, no anchor needed. |
| 6 | **Multiply** (`mul`, `mul_no_relin`, tensor + scale-by-`t/Q`) | **D3** | **C1, C2, C6** | **Flagship.** Do the tensor + rescale over a **derived, transient** auxiliary base (`base_ext`), compute the `⌊t·(c⊗c′)/Q⌉` quotient **exactly** (`unified_rescale`), emit mod-`Q`. Replaces approximate BEHZ rounding with zero-drift exact — security-neutral. Currently shaped over the *published* anchor (D4); move it derived-transient. |
| 7 | Relinearize (`relinearize`, `relinearize_dual`, `relinearize_rns_limb`) | **D3** arith / **D4** key | **C2** | Exact base-ext of the gadget **decomposition** (derived-transient); relin **key stays mod-`Q`**. |
| 8 | Key-switch / rotation (`key_switch`, `apply_automorphism`, `conjugate`) | **D3** arith / **D4** key | **C2, C3** | Same shape as relin: exact decomposition arithmetic; key material mod-`Q`. |
| 9 | Mod-switch (`mod_switch_ct_down`, `mod_switch_ct_to_level`, `mod_switch_down_dual`) | **D3** | **C6 (`ModulusReduced`), C1, C7** | **Unified primitive.** `unified_rescale`'s BGV exit. |
| 10 | Rescale / drop (`exact_drop_ct`, `exact_divide`, `exact_drop_poly`) | **D3** | **C6 (`Reraise`), C1** | Already routed through `unified_rescale` / `arrow_emission_gate`. Exact computation of a rounded (lossy) result — not lossless. |
| 11 | Decrypt / center / decode (`decrypt`, `decrypt_dual`, `detect_sign`, `decode`) | D2 | **C8, C1, C3** | **Opportunity.** Wire `compare_bit` (currently "not wired") into centered decrypt; exact K-Elim decode. Client/secret-holder side — fully applies. |
| 12 | Bootstrap / refresh (`bootstrap`, `bootstrap_with_ksk`, `symmetric_bootstrap`) | D2/D3 / **D4** key | **C1, C6, C7** | Internal exact steps (winding, rescale) apply; **bootstrap key stays mod-`Q`**. Remains capability-gated per `LINEAGE.md` — no depth claim attached. |
| 13 | Noise budget (`budget`, millibits) | cross | **C4** | Already exact-integer tracking. |

---

## Map 2 — Standard BFV / BGV / CKKS (same rule, standard names)

| Standard op | Domain | Applies | Note |
|---|---|---|---|
| KeyGen | D2 | **C4** | Sampler-support / CBD audit before keys are formed. Keys ship mod-`Q`. |
| Encode / batch (BFV-BGV SIMD; CKKS canonical embedding) | D1 | **C5, C7** (BFV/BGV); C1 (CKKS scale) | Slot packing is already CRT; chimera/StarLift extend BFV/BGV plaintext packing. CKKS embedding is real→ℂ, less chimera-native. |
| Encrypt | D2 rand / **D4** out | **C4** | Ciphertext mod-`Q` (or mod-`Q_ℓ`). |
| Add / Sub | lane-wise | **C3** | Exact already. |
| **Multiply (RNS tensor + scale)** | **D3** | **C1, C2, C6** | **The high-value point in every scheme.** Exact base extension replaces BEHZ/HPS approximate base conversion; exact rescale quotient. Auxiliary base derived-transient, discarded. |
| Relinearize / Key-switch (gadget) | **D3** arith / **D4** key | **C2** | Exact digit decomposition; key mod-`Q`. |
| Rescale (BFV) / Mod-switch (BGV) / Rescale (CKKS) | **D3** | **C6** | `unified_rescale`'s two exits are exactly BFV-rescale (`Reraise`) and BGV-modswitch (`ModulusReduced`) as one primitive. CKKS: exact computation of the (rounded, lossy) limb drop. |
| Decrypt / decode | D2 | **C1, C8** | Centered reduction + CT half-modulus decision. |
| Bootstrap | D2/D3 / **D4** key | **C1, C6, C7** | Internal exactness; keys mod-`Q`. |

---

## The points, ranked by value (where to actually put work)

1. **Multiply kernel — exact base extension + exact rescale quotient (D3).**
   Highest value, applies to NINE65 and all three standard schemes. Turns
   approximate RNS multiplication into zero-drift exact, with **no** security
   change (auxiliary base derived from public ciphertext, discarded before
   serialize). This is CRAM's genuinely publishable FHE contribution.
2. **Mod-switch / rescale unification (D3).** `unified_rescale` already codes
   the two exits; deploy it on the mod-`Q` representation. One primitive covers
   BFV rescale and BGV modulus switch.
3. **Decrypt-side `compare_bit` + exact K-Elim decode (D2).** Client-side,
   fully exact, and gives a constant-time decision path. `compare_bit` exists
   but is unwired.
4. **KeyGen sampler i.i.d. audit (D2).** Security-**positive**: the arrow gate
   catches distribution defects (the `a`-confinement bug class) before they
   ship.
5. **Plaintext chimera / StarLift packing (D1).** Heterogeneous slot packing and
   message-space winding, entirely in public plaintext structure.

## The single constraint that bounds all of the above

Every row that touches a **published, secret-dependent object** (keys,
ciphertexts) keeps that object **single-modulus mod `Q`**. The exact substrate
lives in the *compute*, never in the *wire format*. That is the whole of the
security obligation; within it, C1–C8 apply everywhere marked above at no
security cost, and — at the multiply kernel and the sampler audit — at a
genuine correctness/robustness *gain*.
