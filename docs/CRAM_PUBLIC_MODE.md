# CRAM-Public Mode — Variant Charter

Date: 2026-08-26. Status: M1 landed (this document's commit).

This is the **single working CRAM variant** of the FHE evaluator: a purely
public mode in which evaluation is intended to live entirely in residue
space. It guts NINE65_v7's dual-mode evaluator — v7 chosen over v6 after a
side-by-side survey (v7's `mul_dual_public` carries the relinearize/rescale
ordering fix that capped v6's public depth at 1, the `k_elim_rescale_dual`
anchor-tier fix, the winding reset `canonicalize_dual_anchor`, and all of the
CRAM machinery; v6 contains zero CRAM code and exists only as frozen
snapshots).

Everything here follows the corpus-wide verification policy
(cram-substrate `docs/CLAIM_SCOPE.md`): PROVED means a machine-checked
artifact on disk; otherwise proof sketch. Reconstruction-pathway taxonomy
(R8 direct CRT = boundary-licensed; R9 Garner = retired) and capacity
certificates follow the lift inventory, vendored at cram-substrate
`docs/CRAM_LIFT_INVENTORY.md`. Variant lineage: this is the
**chimera-machine variant** (heterogeneous outputs are residue tuples;
single-integer lifts of chimeras are the retired chimera-1 convention).

## Surface (module `ops/cram_public.rs`)

| Op | Delegates to | Emission class today | Measured by |
|---|---|---|---|
| `add`, `sub` | `add_dual` / `sub_dual` | **LaneLocal** | `cram_public_mode.rs`, i.i.d. probe |
| `add_plain`, `mul_plain`, `negate` | `*_dual` | **LaneLocal** | same |
| `exact_divide` | promoted from test-only code | **LaneLocal**; refuses non-unit divisors with a typed error | same + refusal test |
| `mul` | `mul_dual_public` | **R8 Materialization** (gate-qualified, pinned) | arrow harness — see the qualification section below |
| `encrypt` / `decrypt` | `encrypt_dual_with_rng` / `decrypt_dual` | client-side (cold path; reconstruction permitted there per A2 scope) | — |

The evaluator records every operation in an **emission ledger**
(`EmissionLedger`), so any chain's residue-space status is a printed fact,
not a claim. M4's acceptance criterion is a ledger whose materialization
count is zero.

## Arrow-harness qualification of the multiply (the measuring stick)

Emission classifications are qualified by the arrow test harness, not by
predispositions. Lane coupling per se is not the fault — Universal
Projection reads every lane and is A2-compliant; transduction carries
lane-wise. The faults are what the gates measure: undeclared discard (G1),
a running-value cascade (G2), stored non-derivable state (G5). Measured
verdicts for `mul_dual_public`:

| Probe | Instrument | Verdict |
|---|---|---|
| G2 order-invariance, real implementation | `ct_multiply_is_order_equivariant_bit_exact` (4 config/perm cases, bit-exact) | **PASS** — not a Garner/MRC cascade |
| i.i.d. lane-locality, real implementation | `ct_multiply_is_not_lane_independent_every_lane_moves` | coupled — every lane moves (pinned) |
| G1 discard | Δ-rescale is declared; the noise ledger meters it | **METERED**, not a fault |
| G5 constants | level inverses derived by extended Euclid from the declared chain at construction | derivable |
| Six-gate run on the modeled coupling site (materialize + reproject, parallel-summation CRT) | cram-substrate `python3 -m cram_fhe.audit` §8 | **A2 COMPLIANT** (G1 bijection, G2 order-invariant, G3 factorizes, G5 derived); Garner contrast: G2 FAIL |

Gate-qualified conclusion: the multiply's coupling is an **R8-class direct
materialization** (lift-inventory taxonomy: exact, order-invariant,
boundary-licensed) — not an R9 Garner cascade, and not a synthetic
emission. What remains is the narrower **elimination-first policy** point:
R8 materialization is licensed for boundaries/proofs/tests, and the hot
path should be elimination-first (lane-wise carries / transduction). That
is M2/M3, and it is a policy milestone, not a gate violation.

## Gut manifest

**Kept** (public path, all reachable through `CramPublicEvaluator`):
`generate_keys_dual_full_public_deep_with_rng`, `encrypt_dual_with_rng`,
`decrypt_dual` (client half), `add_dual`, `sub_dual`, `add_plain_dual`,
`mul_plain_dual`, `negate_dual`, `mul_dual_public`,
`canonicalize_dual_anchor` (inside the multiply), the capacity audits, and
the promoted lane-wise exact division.

**Cut** (no entry point on this surface, by construction):
`mul_dual_symmetric`, `mul_dual_symmetric_with_s2`, every `*_with_s2`
variant, the symmetric bootstrap path, the deprecated `mul_dual` alias
(already deleted upstream), and the retired modulus ladder
(`mod_switch_ct_down` / `mod_switch_down_dual`). The evaluator holds no
method that accepts a secret key; the secret key exists only in
`CramClientKeys`, whose sole consumer is `decrypt`.

The underlying `rns_fhe.rs` is not physically deleted in M1 — 689+ lib
tests and the admissibility infrastructure still exercise it. The variant
boundary is the module surface: new CRAM work targets `CramPublicEvaluator`
only.

## Milestones

- **M1 (this commit)** — public-only evaluator + emission ledger + acceptance
  tests: roundtrip battery, i.i.d. probe through the surface, refuse-not-
  corrupt division, depth-3 public squaring chain (2→4→16→256, exact at
  every step on `secure_128_deep`; the v6-era green re-expressed on
  unbounded-depth semantics with public entry points only), and the pinned
  honesty assertion that `mul` is a reconstruction.
- **M2 — lane-local rescale.** Replace `k_elim_rescale_dual`'s
  `to_u256_level` ("Iterative CRT (Garner-style)", `arithmetic/rns.rs`) with
  the manufactured-chain align-and-drop of `arithmetic/unified_rescale.rs`
  (`Q = t·D` star chains; each Δ-lane drop is `(x_i − r_k)·q_k⁻¹ mod q_i` — a
  cross-lane *read*, never a running value: G2-compliant).
- **M3 — lane-local relinearization digits.** Replace `extract_digit_dual`'s
  materialised 256-bit value with per-lane one-wave digit reads (compendium
  Theorem 9 shape).
- **M4 — invert the pins.** When M2+M3 land,
  `ct_multiply_is_not_lane_independent_every_lane_moves` starts failing —
  invert it into a lane-independence assertion (its own instructions), invert
  `multiply_is_recorded_as_a_reconstruction_pinned`, reclassify `mul` as
  LaneLocal, and the ledger's reconstruction count goes to zero.

## Proof sketches (per the standing submission policy)

**PS-CP-1 — Lane-locality of the kept primitives.** *Statement:* `add`,
`sub`, `add_plain`, `mul_plain`, `negate`, `exact_divide` move output lane i
only when input lane i moves. *Sketch:* each is component-wise on the
product ring ∏ Z/pᵢZ × ∏ Z/aⱼZ: per-lane modular add/sub/scalar-mul/negation
are functions of that lane's residue alone; exact division multiplies each
lane by its own reciprocal `d⁻¹ mod p` (extended Euclid per lane, no shared
state). No lane reads another lane's input or output. *Status:* SKETCH +
WITNESS (`lane_local_ops_stay_lane_local_through_the_public_surface`, and
the positive control in `residue_space_ciphertext.rs`).

**PS-CP-2 — Exact division correctness on units.** *Statement:* if
`gcd(d, pᵢ)=1` for every lane and d | X (the carried integer), lane-wise
multiplication by `d⁻¹ mod pᵢ` represents X/d exactly. *Sketch:* reduction
mod pᵢ is a ring homomorphism, so `(X/d) mod pᵢ = (X mod pᵢ)·(d⁻¹ mod pᵢ)`;
this is the K-Div branch of the division-closure dispatcher (T-ODC), whose
shared-factor branch (FPD, aux lane) is exactly what the typed refusal
routes toward. *Status:* SKETCH + WITNESS
(`exact_divide_roundtrip_and_refusal`; T-ODC itself remains a sketch).

**PS-CP-3 — The multiply's coupling is exactly two R8 sites, and it is not
a cascade.** *Statement:* `mul_dual_public` is lane-coupled through
`k_elim_rescale_dual → to_u256_level` and `extract_digit_dual` and through
nothing else, and that coupling is an order-invariant exact materialization
(R8), not a Garner cascade (R9) and not a synthetic emission. *Sketch:* the
tensor product is per-lane NTT (positive control: lane-wise primitives stay
local); the only multi-lane materializations are the two named sites; a
parallel/direct CRT sum is a linear combination of independent per-lane
terms, hence order-invariant and bijective on the torus, with constants
derivable by extended Euclid from the declared chain — every gate the arrow
harness can bring passes, and only the i.i.d. observable records the
coupling. *Status:* SKETCH + WITNESS, gate-qualified (Rust:
`ct_multiply_is_order_equivariant_bit_exact` PASS and the pinned
discriminator; Python: cram-substrate audit §8 A2 COMPLIANT on the modeled
site with the Garner contrast convicted on G2; ledger pin
`multiply_is_recorded_as_a_materialization_pinned`).

**PS-CP-4 — Public-only surface cannot reach a secret-key evaluator op.**
*Statement:* no sequence of `CramPublicEvaluator` calls invokes symmetric
evaluation. *Sketch:* type-level — the evaluator's methods accept only
`CramPublicKeys` (public + eval key) and ciphertexts; `DualRNSSecretKey`
appears in no method signature except `decrypt(client: &CramClientKeys)`,
which delegates to client-side decryption and performs no evaluation.
*Status:* SKETCH (enforced by the compiler; a negative compile-test could
pin it further).

**PS-CP-5 — Depth is not gated by lane count on this surface.** *Statement:*
the depth-3 public chain runs on the same basis at every step. *Sketch:*
the multiply divides by Δ via K-Elimination instead of dropping a lane
(Step-5 ladder retired upstream), so the chain's basis fingerprint is
constant and depth is bounded by noise, not by prime supply. *Status:*
SKETCH + WITNESS (`depth3_public_squaring_chain_reaches_256`;
`full_chain_encrypt_mul_divide_decrypt_leaves_the_basis_byte_identical`).
