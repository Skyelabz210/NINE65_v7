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
a running-value cascade (G2), stored non-derivable state (G5 — a
derivability discipline, not a stored-constant ban: caching is fine when
the derivation is known; believed-hard quantities route to the derivation
tooling — see cram-substrate `docs/A2_GATES.md`, G5 addendum). Measured
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
  honesty assertion that `mul` takes an R8 materialization.
- **M2 — lane-local rescale.**
  - **M2a (landed)** — de-cascade `unified_rescale.rs` itself: its winding
    read and ladder merge called a sequential Garner/MRC (`garner()`) at
    runtime — an R9 mechanism hiding inside the otherwise lane-local
    pipeline, precisely what the lift inventory's ladder policy forbids
    ("must not be silently substituted with a runtime Garner cascade").
    Both call sites now use `parallel_summation_crt` (R8: every term
    independent, no running value), result-identical to the Garner ORACLE
    (`garner` is now `#[cfg(test)]`-only, its licensed role), cross-checked
    over >1000 points and the pre-existing exhaustive suites (21/21 tests).
    Also landed: `rescale_drop_only` — steps 1–2 only (rounding offset +
    align-and-drop), zero materialization of any kind, the fully lane-local
    `ModulusReduced` path exposed for the ct hot loop.
  - **M2b (landed)** — the per-coefficient ct-path rescale,
    `k_elim_rescale_manufactured`, wired into `mul_dual_public_manufactured`
    and the evaluator's `mul_manufactured`. Chain: `Q = t·D1·D2·D3` with
    `t = 65537` itself a main lane and Δ-lanes minted by construction
    (`D = c·t+1`, `c ≡ 0 mod 2N`: `≡ 1 mod t` AND NTT-friendly
    simultaneously; primality screened — the residual Field-Layer
    obligation). Pipeline per coefficient: signed-shift `S = 2N·Q²`
    (anchor-lanes only; `≡ 0` mod every main lane and mod Q) →
    align-and-drop every Δ-lane (cross-lane READS, no running value) →
    direct γ read off the t-lane → winding over a capacity-certified
    4-anchor ladder merged by parallel summation (R8) → `Y'' mod Q`
    canonicalization composed base-plus-lift in fixed-width U256 (the lift
    inventory's normative R4 pathway under the `K < C` certificate). No
    `to_u256_level`, no iterative CRT over the lanes, no Garner. Acceptance:
    10-pair multiply battery exact; **depth-3 public squaring 2→4→16→256
    exact**; plaintext-level agreement with the materializing path
    (`tests/m2b_manufactured_rescale.rs`, 5/5).

    Two findings from the M2b bring-up, recorded so they are not relearned:
    1. **Per-component centering breaks the degree-2 decryption identity**
       (measured): the three tensor components' `t·k̂` winding terms must
       survive the rescale so the s-weighted sum telescopes back to
       `X_total/Δ`; rescale each component to `Y'' mod Q`, do NOT center
       components independently.
    2. **Certificates need proved bounds, not assumed ones**: the
       dual-tracked tensor is the product of UNSIGNED representative
       polynomials (coefficients in `[0,Q)`), so `|d0| ≤ N·Q²` and
       `|d1| ≤ 2N·Q²` — assuming centered inputs under-sizes the bound 2×,
       and the winding then aliases by exactly `t·C`. The recovered offset
       factoring as the ladder capacity `C` to the digit was the diagnostic
       that identified it. This is the lift inventory's capacity-alias
       theorem observed live.
- **T2 — regression guardrail layer (landed).** Five never-vacuous tripwires
  protecting the M2a/M2b non-standard decisions from a lower-tier agent's
  regression to textbook defaults:
  `crates/nine65/tests/cram_public_guardrails.rs` (tripwires 2 and 4,
  public-API-only) plus two in-module tests co-located with the code they
  guard — `cram_public_guardrail_no_centering_regression_measurably_fails`
  in `ops/rns_fhe.rs` (tripwire 1) and
  `cram_public_guardrail_manufactured_multiply_never_calls_garner` in
  `arithmetic/unified_rescale.rs` (tripwire 3). Tripwire 5 (the `Y'' mod Q`
  semantics pin) is the pre-existing
  `manufactured_rescale_matches_ground_truth_on_known_values`, now carrying
  an explicit DO-NOT header. See `docs/roadmap/README.md` for the full
  anti-regression rationale and the task-card handoff this layer protects.
- **M3 — lane-local relinearization digits (landed, depth-2 scope).**
  Replaces `extract_digit_dual`'s materialised 256-bit value with a
  CRT-idempotent RNS-limb gadget: `generate_gadget_key_with_rng` (keygen,
  one `(rlk0_i, rlk1_i)` pair per main lane, keyed by `g_i = (Q/q_i)·[(Q/q_i)⁻¹
  mod q_i]`, derived by extended Euclid) and `relinearize_rns_limb`
  (relin — the "digits" are the ciphertext's own per-lane residues,
  broadcast via ordinary `% p`, no CRT reconstruction). Wired additively
  behind new entry points (`mul_dual_public_manufactured_gadget` /
  `CramPublicEvaluator::mul_manufactured_gadget`); the digit-based path is
  unchanged and still exercised by its own tests. Guardrail-pinned: the
  relin step performs zero `to_u256_level` calls
  (`m3_guardrail_gadget_relin_never_calls_to_u256_level`, T2-style,
  never-vacuous against the digit-based path on the same input).

  **Finding: depth-2 reliable, depth-3 is a measured noise-budget limit,
  not a correctness bug.** A 30-seed sweep of the depth-3 squaring chain
  showed 0/30 failures at depth 1-2 and 18/30 (60%) failures at depth 3,
  every failure first appearing at exactly depth 3, off by a small margin
  (e.g. decrypted 255 instead of 256) — the signature of noise overrunning
  `Δ/2`, not an algebraic error (the CRT-idempotent identity `Σ [P]_{q_i}·g_i
  ≡ P (mod Q)` holds regardless of representation; what differs from the
  digit-based scheme is per-term noise: each RNS-limb "digit" is up to
  `q_i - 1` (~2^31 on this chain) versus the digit-based scheme's `2^16`,
  and that gap compounds through the tensor product's noise growth across
  levels). Tests and the public entry points are scoped to depth 2, matching
  what is measured, not what was estimated. Reaching depth-3 parity is
  escalated future work — likely a hybrid gadget (RNS lane × base-`2^b`
  sub-decomposition within each lane) — not attempted here.
- **M4 — invert the pins.** When M2+M3 land,
  `ct_multiply_is_not_lane_independent_every_lane_moves` starts failing —
  invert it into a lane-independence assertion (its own instructions), invert
  `multiply_is_recorded_as_a_materialization_pinned`, reclassify `mul` as
  LaneLocal, and the ledger's materialization count goes to zero.

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

**PS-CP-6 — Parallel-summation CRT is result-identical to Garner and
cascade-free.** *Statement:* `parallel_summation_crt(residues, mods)` equals
the CRT representative in `[0, M)` for pairwise-coprime `mods`, with every
term computed independently. *Sketch:* the Lagrange basis `E_i = M_i·(M_i⁻¹
mod m_i)` satisfies `E_i ≡ δ_ij (mod m_j)` (Kronecker delta: `m_j | M_i` for
`i ≠ j`; the inverse cancels for `i = j`), so `Σ r_i·E_i ≡ r_j (mod m_j)`
for every `j`, and CRT uniqueness gives the representative after one
reduction mod `M`. The reduced-term form `M_i·((r_i·inv_i) mod m_i)` equals
`r_i·E_i (mod M)` because the difference is a multiple of `M_i·m_i = M`.
No term reads another term — R8, not R9. *Status:* SKETCH + WITNESS
(`parallel_summation_matches_garner_oracle`, >1000 cross-checked points on
4 bases, plus the module's pre-existing exhaustive suites which now run
through the new path).

**PS-CP-7 — Correctness of the M2b elimination-first rescale.**
*Statement:* on a manufactured chain, `k_elim_rescale_manufactured` outputs
residues of `⌊(X + Δ/2)/Δ⌋ mod Q` for every dual-tracked tensor value
`|X| ≤ 2N·Q²`, with the winding read exact under the `4NQ+1 < C` anchor
certificate. *Sketch:* (i) the shift `S = 2NQ²` makes `X'' = X+S ≥ 0` and is
a multiple of `Δ`, so `⌊(X''+Δ/2)/Δ⌋ = ⌊(X+Δ/2)/Δ⌋ + S/Δ` exactly, and
`S/Δ = 2NQt ≡ 0 (mod Q)` erases the shift after the mod-Q reduction;
(ii) each Δ-lane drop is the exact identity `(v_i − r_d)·d⁻¹ ≡ ⌊V/d⌋ (mod
q_i)` and nested floors compose to division by Δ; (iii) `Y'' ≤ 4NQt`, so
`K'' = ⌊Y''/t⌋ ≤ 4NQ < C` — the K-Elimination congruence has one
representative in range (capacity certificate, PS-2/L9); (iv) `Y'' = γ+K·t`
then reduces mod Q in one fixed-width U256 operation. *Status:* SKETCH +
WITNESS (`manufactured_rescale_matches_ground_truth_on_known_values`, a
70-point known-value sweep across every winding regime to `2NQ`, plus the
5-test acceptance suite with the depth-3 chain).

**PS-CP-5 — Depth is not gated by lane count on this surface.** *Statement:*
the depth-3 public chain runs on the same basis at every step. *Sketch:*
the multiply divides by Δ via K-Elimination instead of dropping a lane
(Step-5 ladder retired upstream), so the chain's basis fingerprint is
constant and depth is bounded by noise, not by prime supply. *Status:*
SKETCH + WITNESS (`depth3_public_squaring_chain_reaches_256`;
`full_chain_encrypt_mul_divide_decrypt_leaves_the_basis_byte_identical`).

**PS-CP-8 — Correctness of the M3 RNS-limb relinearization gadget (depth
≤ 2).** *Statement:* `relinearize_rns_limb` correctly recovers `P·s²
(mod Q)` from a manufactured-chain ciphertext component `P` (already
canonical mod `Q`, e.g. the output of `k_elim_rescale_manufactured`), using
only `P`'s own per-lane residues as gadget digits — no CRT reconstruction,
no `to_u256_level`. *Sketch:* for each main lane `q_i`, `g_i = (Q/q_i)·
[(Q/q_i)⁻¹ mod q_i]` is the CRT idempotent (`g_i ≡ 1 mod q_i`, `g_i ≡ 0 mod
q_j` for `j ≠ i` — the main-lane residues of `g_i` are the Kronecker delta
by construction, no computation needed); the CRT reconstruction identity
`Σ_i [P]_{q_i}·g_i ≡ P (mod Q)` holds per coefficient; embedding `g_i·s²`
into the encrypted `rlk0_i = -a_i·s-e_i+g_i·s²` and summing
`Σ_i digit_i(x)·rlk_i(x)` (ring convolution, `digit_i` a scalar constant per
coefficient broadcast into every lane) distributes the scalar `g_i` through
the convolution exactly as the base-`2^b` digit scheme distributes
`decomp_base^i`, since both are per-coefficient scalar constants, not
polynomials — so the identity is the SAME mechanism, only the digit
granularity differs (RNS lane vs. positional base-`2^b`). *Caveat, measured
not assumed:* the larger per-lane digit magnitude (`~q_i`, vs.
`decomp_base` for the base-`2^b` scheme) grows noise faster per level; a
30-seed sweep showed 0/30 failures at depth 1-2 and 18/30 at depth 3 (see
the M3 charter finding above) — this proof sketch's claim is therefore
scoped to depth ≤ 2, not depth 3. *Status:* SKETCH + WITNESS
(`m3_rns_limb_relin_matches_digit_relin_at_plaintext_level`,
`m3_rns_limb_relin_depth2_squaring_chain`,
`m3_gadget_depth2_squaring_chain_through_evaluator`,
`m3_guardrail_gadget_relin_never_calls_to_u256_level`).
