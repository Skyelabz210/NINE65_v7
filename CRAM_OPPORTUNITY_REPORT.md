# CRAM Opportunity Report

Index of recognized CRAM opportunity instances. **Append-only.** Continue from
the highest `[N]`; never rewrite an existing entry. Sibling of the hygiene
report; action items are mirrored into the relevant crate README in lockstep.

Entry format:
`[N] <FORCED|CANDIDATE> | <trigger> | <path:locus> | why | → node:<key> (authored|pending) | mirrored README`

No Level-2 node is authored yet, so every routing key below is `pending`. Log
only — do not improvise the procedure.

---

## Pass 1 — 2026-08-10 (session `229d9a6e`)

### FORCED — invariant violations

`[1] FORCED | A1 | crates/nine65/src/compiler.rs:118-126 | NoiseModel carries six f64 fields (add/mul/relin/rescale/rotate noise bits, safety_factor); lib.rs:42-43 declares the exemption as "offline/static analysis", but the winding now gives an exact magnitude read, so the exemption is a choice rather than a necessity | → node:a1-defloat (pending) | crates/nine65/README.md`

`[2] FORCED | A1 | crates/nine65/src/ops/sbni.rs:259-290 | f64 chi-square / mean / stddev over noise samples; SBNI is retired ("86'd"), so the resolution is deletion of the module, not defloating it | → node:a1-defloat (pending) | crates/nine65/README.md`

`[3] FORCED | A1 | crates/nine65/src/security/ct_verification.rs:34-48 | f64 median / MAD / t-test thresholds; this is the constant-time layer, declared off-limits, and timing statistics are genuinely real-valued — logged so the site is known and NOT "fixed" | → node:a1-defloat (pending) | crates/nine65/README.md`

`[4] FORCED | A1 | crates/nine65/src/comprehensive_benchmarks.rs:52,82,89,125,134 | f64 wall-clock elapsed; measurement harness, not a compute path | → node:a1-defloat (pending) | crates/nine65/README.md`

`[5] FORCED | hot-path reconstruction | crates/exact_transcendentals/src/transduction.rs:213,224 | garner_reconstruct on the transduction compute path; the sibling call at :156 was already retired with a comment saying so, leaving the retirement half-done | → node:reconstruction-retirement (pending) | crates/exact_transcendentals/README.md`

`[6] FORCED | hot-path reconstruction | crates/exact_transcendentals/src/transduction.rs:330-331 | round-trip identity checked by reconstructing both sides through Garner rather than by comparing transduced Σ; see sibling [5] | → node:transduction-state (pending) | crates/exact_transcendentals/README.md`

`[7] FORCED | hot-path reconstruction | crates/exact_transcendentals/src/composite_division.rs:144,167-176 | mixed_radix_garner() plus mixed-radix compare/subtract to recover sign and magnitude on a division path — positional reconstruction where winding + K-Elimination would do | → node:reconstruction-retirement (pending) | crates/exact_transcendentals/README.md`

`[8] FORCED | hot-path reconstruction | crates/exact_transcendentals/src/cram_pde.rs:127 | ExactState::to_u128 reconstructs via Garner, and safe_basis_io::{add,mul} call it to detect the corridor carry, putting Garner on the arithmetic path; now unblocked — cram_machine::canonical_from gives g = (a+K) mod A with no reconstruction. Asserted as outstanding by cram_gates::p2_* | → node:reconstruction-retirement (pending) | crates/exact_transcendentals/README.md`

`[9] FORCED | A2 / i.i.d. | crates/exact_transcendentals/src/k_elim.rs:150-163 | garner_reconstruct threads one accumulator across lanes; measured in cram_anchor::tests, a fault at lane j damages every downstream partial while the flat anchored lift confines it to one winding. Every caller inherits the coupling — see [5][7][8] | → node:iid-heterogeneous-transduction (pending) | crates/exact_transcendentals/README.md`

### CANDIDATE — route for definitive analysis

`[10] CANDIDATE | CRT utilized | crates/nine65/src/arithmetic/rns.rs | RNS construction carries the whole FHE path; lanes are homogeneous, so safe-basis roles and heterogeneous lane operators are uninstantiated | → node:crt-to-cram-substrate (pending) | crates/nine65/README.md`

`[11] CANDIDATE | CRT utilized | crates/exact_transcendentals/src/crt.rs, crt_torus.rs | classical CRT utilities alongside the residue-native modules; two substrates coexisting | → node:crt-to-cram-substrate (pending) | crates/exact_transcendentals/README.md`

`[12] CANDIDATE | CRT utilized | crates/exact_transcendentals/src/cram_pde.rs | ExactState already carries lanes + winding — the correct shape — but is confined to the PDE module and unused by the FHE path | → node:crt-to-cram-substrate (pending) | crates/exact_transcendentals/README.md`

`[13] CANDIDATE | CRT utilized | crates/nine65/src/cram_ct_wrap.rs | the BFV↔CRAM seam; wrap_default leaves c0_aux: None and lane0_as_i128 fingerprints c0.main[0] only, so the FPD path is present but unreachable | → node:crt-to-cram-substrate (pending) | crates/nine65/README.md`

`[14] CANDIDATE | hot-path reconstruction | crates/cram-core/src/lib.rs:276-317 | the A2 meter exists (crt_reconstructions, mixed_radix_calls, and an == 0 compliance check) but is not wired to the nine65 FHE path, so it measures nothing | → node:reconstruction-retirement (pending) | crates/cram-core/README.md`

`[15] CANDIDATE | sequential ripple | crates/nine65/src/arithmetic/ntt.rs, ntt_fft.rs | the butterfly is a staged cascade with cross-coefficient dependency at every stage — the canonical convert-to-lanewise target; see sibling [17] | → node:sequential-to-heterogeneous (pending) | crates/nine65/README.md`

`[16] CANDIDATE | sequential ripple | crates/nine65/src/arithmetic/barrett.rs, montgomery.rs, persistent_montgomery.rs | reduction machinery whose whole purpose is making a positional cascade cheap; check whether the residue-native path removes the need rather than optimising it | → node:sequential-to-heterogeneous (pending) | crates/nine65/README.md`

`[17] CANDIDATE | NTT presumed necessary | crates/nine65/src/arithmetic/ntt.rs, ntt_fft.rs, cyclotomic_phase.rs | negacyclic convolution assumed to require NTT; audit whether lanewise residue arithmetic removes the requirement entirely, which would also drop the CLASS-F primality constraint on those moduli. Sibling of [15] | → node:ntt-necessity-audit (pending) | crates/nine65/README.md`

`[18] CANDIDATE | NTT presumed necessary | crates/nine65/src/arithmetic/persistent_montgomery.rs, barrett.rs | Montgomery/Barrett persistence is downstream of [17]; if NTT goes, so does most of this. Sibling of [16] | → node:ntt-necessity-audit (pending) | crates/nine65/README.md`

`[19] CANDIDATE | modulus selection | crates/nine65/src/params/primes.rs, secure_configs.rs, production.rs | moduli are selected by NTT compatibility ((p−1) mod 2n == 0) and bit width alone; no prime-family role is assigned — no twin/cousin/sexy/Sophie-Germain classification, no Ramanujan boundary, no mod-4 class, no gap or carry fingerprint | → node:prime-family-engineering (pending) | crates/nine65/README.md`

`[20] CANDIDATE | modulus selection | crates/nine65/src/arithmetic/ntt.rs (primitive-root search), k_elimination.rs | CLASS-F (needs primitive roots) and CLASS-R (needs coprimality only, composites legal) are not distinguished at the selection site, so anchors inherit a primality constraint they do not have. cram_anchor::Anchor::adjacent already demonstrates the CLASS-R case | → node:prime-family-engineering (pending) | crates/nine65/README.md`

`[21] CANDIDATE | exact division / rescale | crates/exact_transcendentals/src/cram_ct.rs:1198,1461,1596,1689,1881 | five rescale variants coexist (scalar, fpd, div_exact, chimera router, kelim) with the router choosing between them at runtime; consolidate onto the gated Fifth Operator | → node:fifth-operator-rescale (pending) | crates/exact_transcendentals/README.md`

`[22] CANDIDATE | exact division / rescale | crates/nine65/src/ops/rns_mul.rs | rescale on the ciphertext multiply path, generic rather than lanewise x_i·d_i⁻¹ mod m_i with a coprimality gate | → node:fifth-operator-rescale (pending) | crates/nine65/README.md`

`[23] CANDIDATE | exact division / rescale | crates/nine65/src/arithmetic/residue_division.rs, exact_divider.rs | two general division paths alongside the seven-chimera catalogue; which chimera each implements is unstated, so a Div-root (modular-only) result and an integer quotient are not distinguished at the type level | → node:fifth-operator-rescale (pending) | crates/nine65/README.md`

`[24] CANDIDATE | exact division / rescale | crates/mana/src/anchor.rs:93,100 | exact_divide(v_alpha, v_beta, divisor) is already a two-anchor exact division — the mechanism nine65 lacks — but mana is disconnected from the FHE path | → node:fifth-operator-rescale (pending) | crates/mana/README.md`

`[25] CANDIDATE | magnitude handling | crates/nine65/src/noise/budget.rs:13-291 | the noise budget is a millibit counter maintained beside the data: consume() debits a static per-op cost and remaining_millibits() never reads a ciphertext. Magnitude is modelled, not measured — the winding measures it | → node:winding-magnitude (pending) | crates/nine65/README.md`

`[26] CANDIDATE | magnitude handling | crates/nine65/src/arithmetic/bounded_rns.rs | range is bought by sizing the modulus product rather than by an orthogonal winding track, so headroom costs lanes | → node:winding-magnitude (pending) | crates/nine65/README.md`

`[27] CANDIDATE | noise/identity by reconstruction | crates/nine65/src/ops/gso_fhe.rs:52-96 | NoiseEstimate is bookkeeping: collapse() sets distance = 0 without touching the ciphertext, add_noise/mul_noise update a scalar beside the data. Identity and noise want homomorphic Σ updates, not a tracker | → node:transduction-state (pending) | crates/nine65/README.md`

`[28] CANDIDATE | general-purpose parallelism | crates/nine65/src/ops/parallel.rs:86,106,120,137,219,237 | six rayon par_iter() work-stealing dispatches over lane- and coefficient-indexed operations, where lane dispatch is deterministic by construction | → node:deterministic-lane-parallelism (pending) | crates/nine65/README.md`

`[29] CANDIDATE | general-purpose parallelism | crates/mana/src/lane.rs:214-248, crates/mana/src/parallel.rs:86-154 | rayon over CRT lanes; the lanes are i.i.d. and statically enumerable, so scheduling nondeterminism buys nothing and costs reproducibility | → node:deterministic-lane-parallelism (pending) | crates/mana/README.md`

`[30] CANDIDATE | general-purpose parallelism | crates/nine65/src/arithmetic/ntt.rs:417-454 | rayon parallel forward/inverse NTT — probabilistic scheduling layered on top of a staged cascade. Siblings [15][17] | → node:deterministic-lane-parallelism (pending) | crates/nine65/README.md`

---

## Not logged, and why

Recorded so a later pass does not re-open them:

- **`exact_transcendentals` is A1-clean.** Every `f32`/`f64` occurrence in
  `cordic.rs`, `agm.rs`, `sqrt.rs`, `binary_splitting.rs`,
  `continued_fraction.rs`, `constants.rs`, `crt_rational.rs` and `lib.rs` sits
  inside a `#[cfg(test)]` item — verified by comparing each hit's line against
  the module's `#[cfg(test)]` boundary, not by reading the comments.
- **Comment-only float mentions:** `crates/mana/src/lib.rs:14`,
  `crates/nine65/src/arithmetic/boundary.rs:22`,
  `crates/nine65/src/lib.rs:42-43`,
  `crates/nine65/src/params/security_estimator.rs:553-554`,
  `crates/nine65/src/bin/nine65_v7_demo.rs:333`. These are claims *about* A1,
  not violations of it.
- **`cram_machine::project`'s Garner fallback is not a hot-path reconstruction.**
  It fires only when a heterogeneous schema has left no winding, it is an
  explicit boundary exit, and it is counted separately by
  `destructive_reads()`. Logged here rather than as an entry because the
  distinction is exactly what the reconstruction-retirement node must preserve.
- **`crates/clockwork-core/src/{garner,key_lifecycle}.rs`** — `reconstruct()`
  there is secret-sharing recombination, not CRT reconstruction. Different
  object, same word.

[31] CANDIDATE | deterministic-lane-parallelism | crates/mana/src/parallel.rs:1-275 | MANA's only parallel dispatch is rayon work-stealing (feature-gated, off by default since the rayon removal) — the "lane-parallel pipeline engine" has no deterministic lane executor; measured sequential baseline on 4 idle cores: mul 310/270/229/224 M coeff-ops/s at LOW(3×1024)/MED(6×4096)/HEAVY(10×16384)/ULTRA(16×32768) | → node:deterministic-lane-parallelism (pending) | crates/mana/README.md

[32] CANDIDATE | crt-to-cram-substrate | crates/mana/src/lane.rs:163-198 | Lane::mul/scalar_mul reduce via `%` division while the same crate's PersistentLane (Montgomery-persistent ⊗, lane.rs:340-540) measures 2.41x faster on a 1000-deep mul chain at N=16384 (54.6ms vs 22.6ms); homogeneous-multiplier stacking exists but ManaStream's lanes do not use it | → node:crt-to-cram-substrate (pending) | crates/mana/README.md

[33] CANDIDATE | reconstruction-retirement | crates/mana/src/anchor.rs:166-207 | AnchorContext::exact_divide_stream bottoms out in compute_partial_crt: per-coefficient partial-CRT summation of BOTH codices inside the accelerator's division path — K-Elimination-shaped API, reconstruction-shaped cost; currently uncalled outside tests, must be audited before any hot-path wiring | → node:reconstruction-retirement (pending) | crates/mana/README.md

[34] CANDIDATE | iid-heterogeneous-transduction | crates/exact_transcendentals/src/transduction.rs (TransductionMap) ⇄ crates/mana/src/stream.rs (ManaStream) | lane-to-lane basis movement without reconstruction exists (i128 scalar path, S6/S8/TRANSPORT_CORE constants) but has no bridge to ManaStream's u64 lane vectors — the missing link for heterogeneous-lane mobility in the accelerator | → node:iid-heterogeneous-transduction (pending) | crates/mana/README.md

[35] CANDIDATE | prime-family-engineering | crates/exact_transcendentals/src/arrow_step.rs (ArrowStep::for_heat) | arrow-emission reversibility MEASURED: heat stencil [1,3,1] at dim=8 folds 10^6 steps exactly; singular one-way lanes = {3, 5, 7} — two of four TRANSPORT_CORE primes cannot run backward under this operator; reversibility is (operator, dim, prime)-dependent, so transport lane selection must gate on det(A) mod p ≠ 0 per deployment, not on basis membership | → node:prime-family-engineering (pending) | crates/exact_transcendentals/README.md
