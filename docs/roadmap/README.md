# CRAM-Public Roadmap — Terrain Map

Status as of 2026-08-26: M1, M2a, M2b, and T2 (guardrail layer) are landed.
This directory packages everything remaining — T3 (M3), T4 (M4), T5
(benchmarks), T6 (CI), T7 (breakthrough-recording protocol) — as standalone
task cards a fresh, limited-context agent can execute one at a time.

## Why this exists (read before touching anything)

The owner's standing concern: **a lower-tier agent regresses non-standard
work back to textbook defaults it half-remembers from training.** It already
happened once, in-session, on this exact codebase — a coding pass
"simplified" the M2b rescale to per-component centered reconstruction
(textbook BFV intuition). It matched the spec on cherry-picked known values
and broke the degree-2 decryption identity. Only a guardrail test (built
after the fact) would have caught it before commit.

The defense is now **mechanical, not rhetorical**: every non-standard
decision in this codebase is protected by a pinned, never-vacuous test that
fails loudly if reverted to the textbook default (`crates/nine65/tests/
cram_public_guardrails.rs`, plus two in-module tests — see the table below).
**Do not weaken, delete, or "fix" a failing guardrail without first reading
its doc comment and the charter finding it cites.** A red guardrail after a
change means the change regressed something, not that the guardrail is
stale — investigate before touching it.

## Task tiers

- **FABLE-TIER** (judgment-heavy, regression-prone — a frontier-capable
  agent, not a smaller one): T3 (M3), T4 (M4). These embody non-standard
  math directly.
- **HANDOFF-SAFE** (any competent agent; the guardrails catch mistakes):
  T5 (benchmarks), T6 (CI wiring), T7 (protocol scaffolding, execution
  gated on owner trigger).

## Dependency graph

```
T2 (guardrails, DONE) ──┬──> T3 (M3, FABLE) ──┐
                         └──> T4 (M4, FABLE) ──┴──> T5 (benchmarks) ──> T6 (CI)

T7 (breakthrough protocol) — independent, scaffolding only, no code dependency
```

T3 and T4 can run in either order relative to each other, but T4's ledger
flip (`EliminationFirst`, zero `Materialization` on manufactured chains) is
only fully truthful once T3 removes the relinearization materialization
site — see T4's card for how to sequence around that.

## Standing rules (apply to every card)

1. **Verification policy.** PROVED means a machine-checked artifact on disk
   (`lake build` for Lean, `coqc` for Coq — and even then, only the
   `lean4/KElimination/` tree is the formalization of record; the
   `proofs/coq/` tree is legacy/unmaintained, do not cite it as
   machine-checked). Everything else — including anything in this
   repository's `docs/*.md` — is a PROOF SKETCH regardless of how it reads.
   See cram-substrate `docs/CLAIM_SCOPE.md`.
2. **G5 = derivability discipline, not a stored-constant ban.** Caching a
   value is fine when its derivation is known and re-checkable (extended
   Euclid from a declared chain, a closed-form construction). It fails G5
   only when the derivation is unknown/hard and the value is stored anyway
   with no path back to it. See cram-substrate `docs/A2_GATES.md`, G5
   addendum (owner clarification, 2026-08-26).
3. **Arrow harness is the measuring stick, not predispositions.** Cross-lane
   reads are not automatically a fault — Universal Projection and
   transduction read across lanes by design and are A2-compliant. The
   faults the gates actually measure: undeclared discard (G1), a
   running-value sequential cascade (G2 — this is what convicts Garner/MRC),
   stored non-derivable state (G5). Classify a coupling site by running the
   arrow harness on it, not by assuming coupling = fault.
4. **Variant lineage.** Documents from different points in this corpus's
   history (chimera-1, white-paper, machine variant) are VARIANTS of
   evolving work, not contradictions to reconcile.
5. **Extended Euclid only for inverses.** Never `pow(a, m-2, m)` /
   Fermat's-little-theorem inverses — composite moduli are the default in
   this codebase, and Fermat's method silently requires a prime modulus.
6. **Proof sketches accompany every submission.** New non-standard claims
   get a PS-CP-n entry in `docs/CRAM_PUBLIC_MODE.md`'s proof-sketches
   section (status SKETCH + WITNESS, naming the test). Do not mark anything
   PROVED without the lake/coqc artifact.

## Shorthand glossary

Defined once here; used freely in every card without re-expansion.

| Term | Meaning | Doc pointer |
|---|---|---|
| **M1–M4** | CRAM-public milestones: M1 public-only evaluator, M2a de-cascaded unified rescale, M2b elimination-first ct-path rescale (manufactured chain), M3 lane-local relinearization, M4 re-pin the measured verdicts | `docs/CRAM_PUBLIC_MODE.md` §Milestones |
| **T1–T7** | This roadmap's own task numbering (T1 = this packaging, T2 = guardrails, T3 = M3 impl, T4 = M4 re-pin, T5 = benchmarks, T6 = CI, T7 = breakthrough protocol) | this file |
| **G1–G6** | The six arrow-harness gates: G1 invertibility/discard metering, G2 order-invariance (cascade detector), G3 i.i.d. exact factorization, G4 arrow coherence, G5 derivability, G6 custody | cram-substrate `docs/A2_GATES.md` |
| **A1 / A2** | A1 = zero floating point; A2 = no synthetic emissions in the hot path (NOT "no cross-lane traffic" — see rule 3 above) | cram-substrate `docs/CLAIM_SCOPE.md` |
| **R4 / R8 / R9** | Lift-inventory reconstruction classes: R4 = base-plus-lift under a capacity certificate (normative), R8 = direct/parallel-summation CRT (boundary-licensed, order-invariant, no cascade), R9 = sequential Garner/MRC (retired from runtime, test-oracle only) | cram-substrate `docs/CRAM_LIFT_INVENTORY.md` |
| **γ / K / Δ / C / t-lane** | In the M2b rescale: γ = the direct residue read off the surviving (t) lane, K = the reconstructed winding number, Δ = Q/t exactly, C = the anchor-subset capacity certificate, t-lane = the main lane equal to the plaintext modulus | `docs/CRAM_PUBLIC_MODE.md` §M2b, `k_elim_rescale_manufactured` doc comment in `crates/nine65/src/ops/rns_fhe.rs` |
| **PS-CP-n** | Proof-sketch register entries for the CRAM-public variant | `docs/CRAM_PUBLIC_MODE.md` §Proof sketches |
| **Manufactured chain** | `Q = t·D1·D2·...` with `t` itself a main lane and Δ-lanes minted (not hunted) as `D = c·t+1`, `c ≡ 0 mod 2N`, so `D ≡ 1 mod t` AND NTT-friendly by construction | `crates/nine65/src/params/manufactured.rs`, `FHEConfig::manufactured_m2b_insecure` |

## Guardrail-to-decision map (what T2 actually protects)

| Tripwire | Test | Protects | Textbook trap it pins against |
|---|---|---|---|
| 1 — no centering | `cram_public_guardrail_no_centering_regression_measurably_fails` (`ops/rns_fhe.rs`) | M2b finding #1: `Y'' mod Q` reconstruction, uncentered | "Simplify" the rescale to per-component `round(centered(X mod Q)/Δ)` |
| 2 — unsigned bound | `cram_public_guardrail_unsigned_bound_certificate_must_be_4nq_not_2nq` (`tests/cram_public_guardrails.rs`) | M2b finding #2: certificate `4NQ+1`, tensor is UNSIGNED-representative | "The inputs are surely centered, halve the certificate to `2NQ`" |
| 3 — no Garner | `cram_public_guardrail_manufactured_multiply_never_calls_garner` (`arithmetic/unified_rescale.rs`) | M2a de-cascade: `parallel_summation_crt` (R8) only | Reintroducing a sequential-cascade winding read, or promoting `garner` out of `#[cfg(test)]` |
| 4 — derived inverse | `cram_public_guardrail_derived_inverse_matches_egcd_for_every_delta_lane` (`tests/cram_public_guardrails.rs`) | G5 discipline: `t⁻¹ mod D = D − c` read-off | Caching an inverse table disconnected from its derivation |
| 5 — Y″ mod Q semantics | `manufactured_rescale_matches_ground_truth_on_known_values` (`ops/rns_fhe.rs`, DO-NOT header added) | The reconstruction's ground-truth pin | Same as tripwire 1, from the ground-truth-sweep angle |

Run all of T2 before starting any other card:

```
cargo test -p nine65 --test cram_public_guardrails --release --features allow_insecure
cargo test -p nine65 --lib --release cram_public_guardrail
```

## Cards in this directory

- `T3_M3_RNS_LIMB_RELINEARIZATION.md` — FABLE-TIER
- `T4_M4_REPIN_VERDICTS.md` — FABLE-TIER
- `T5_BENCHMARKS_AND_REPRODUCIBILITY.md` — HANDOFF-SAFE
- `T6_CI_QUALITY_GATES.md` — HANDOFF-SAFE
- `T7_BREAKTHROUGH_RECORDING_PROTOCOL.md` — HANDOFF-SAFE (scaffolding; the
  actual protocol doc + Lean skeletons — execution gated on owner trigger,
  see the card)

## Standing submission policy (applies past this roadmap too)

Every future submission to this branch includes a proof sketch entry
(`docs/CRAM_PUBLIC_MODE.md` §Proof sketches) and, where it changes measured
behavior, a charter milestone update. This is not optional per-card
overhead — it is how the next agent (or the owner) reconstructs what
changed and why without re-reading every diff.
