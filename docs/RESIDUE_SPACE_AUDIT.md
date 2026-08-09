# Residue-Space Audit: rayon/MANA, bootstrap, and the exit map

**Status:** authoritative record of a completed audit pass.
**Date:** 2026-08-09. **Working tree HEAD:** `28e7ce2` (uncommitted changes on top).
**Companion documents:** `docs/LADDER_REMOVAL.md` (the SBNI/auto-mod-switch
retirement — the authoritative source for the noise curve, the depth-2 defect,
and the lane-invariance proof; this document does not repeat those numbers, it
cross-references them) and `docs/RETIRED_MECHANISMS.md` (governing policy on
quarantine vs. deletion).

**Provenance note.** The investigating agent for this pass hit the platform
session limit on its final synthesis step, after all four substantive phases
had already completed and written their results to disk. This document was
written directly from that raw, already-verified output rather than by
re-running the agent — no data below is new; all of it was captured before the
limit hit. Labels follow `LADDER_REMOVAL.md`'s convention:

| Label | Meaning |
|---|---|
| **PROVEN** | Reproducible in this working tree by a command in this document. |
| **REPORTED** | Measured by the investigating agent; not independently re-run here. |
| **ASSUMED** | A reading of the code, not executed as a test. |

---

## 1. Rayon reverted; MANA is not actually wired in

### 1.1 The revert

`rayon` had been added to `crates/nine65/Cargo.toml`'s `[dev-dependencies]` by
an earlier pass to unblock a bench target — the wrong fix, since MANA is
canonical and rayon is deliberately not a default dependency here. **PROVEN**,
reverted:

- Removed `rayon = { workspace = true }` from `[dev-dependencies]`.
- Removed the `threading_comparison` `[[bench]]` stanza and set
  `autobenches = false` (required — Cargo auto-discovers `benches/*.rs`, so
  removing only the stanza would have left it compiling under the default
  harness). Verified via `cargo metadata`: `threading_comparison` is absent from
  the target list; the other five bench targets are unaffected.
- `crates/nine65/benches/threading_comparison.rs` **kept on disk**, not deleted,
  with a header recording why it has no `[[bench]]` entry.

Every other rayon reference in the workspace was inventoried and left as-is
because it is correctly feature-gated (`parallel`/`generic-rayon`, not in any
`default` set) — with one exception: **`crates/nine65-extreme-tests/Cargo.toml`
line 16 has an unconditional, ungated `rayon` dev-dependency that is completely
unused** (zero `par_iter`/`rayon` code references in that crate). Flagged, not
removed — out of this pass's scope (different crate).

### 1.2 MANA is not connected to anything

**REPORTED, and the most notable finding of this section.** MANA
(`crates/mana`, ~2,194 lines, `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`,
zero-float) provides real, usable machinery: `Lane`/`LaneOps`,
`MontgomeryLane`/`PersistentLane` (persistent-domain arithmetic), `ManaStream`,
`KAnchor`/`AnchorContext` (K-Elimination exact division without full O(k²)
reconstruction), and `GsoSwarm`/`QbitAgent` (Glowworm Swarm Optimization over
CRT residues — see `docs/GSO_SWARM_NOTES.md` if a separate audit of that
subsystem is run).

But: `nine65`'s only consumer of MANA is `crates/nine65/src/accelerated.rs`
(304 lines), itself gated behind `feature = "accelerated"`, which is **not** in
`default = ["exact_transcendentals_backend"]`. `AcceleratedFHE` has **zero call
sites anywhere outside its own file** — not in `rns_fhe.rs`, not in any
downstream crate. It compiles cleanly (`cargo check -p nine65 --features
accelerated` → 0 errors) — it is not bit-rotted, it is a self-contained adapter
island that nothing calls.

**Consequence:** with rayon correctly gated off by default and MANA
unreferenced by the hot path, **the default `nine65` build has no active
parallelism at all.** Wiring MANA in for real means writing new call sites in
`rns_fhe.rs`, not flipping a feature flag.

**One thing worth guarding if MANA is ever wired in:** `ManaStream::reconstruct_at()`
(`mana/src/stream.rs:99`) materialises the integer via CRT — the same
winding-destroying reconstruction this whole audit is about. It is currently
used only in MANA's own tests. `accelerated.rs`'s `stream_to_rns` stays
lane-wise and does **not** reconstruct — that half of the adapter is clean.

---

## 2. Bootstrap: quarantined, and confirmed not load-bearing

**PROVEN** (test counts) / **ASSUMED** (call-site reachability, from grep across
the workspace — not exhaustively re-traced here).

145 tests (84 in `crates/nine65/src/`, 61 in `crates/nine65/tests/`) were marked
`#[ignore = "VESTIGIAL: <what this specific test asserts>. …"]`, each reason
tailored rather than copy-pasted. **No test deleted, no file deleted, no
assertion changed, nothing outside `#[cfg(test)]` touched.** Full per-file
breakdown and the complete list of 145 test paths are in the raw workflow
output (`docs/RETIRED_MECHANISMS.md` Part II carries the summarized version)
and are not repeated here.

### 2.1 A baseline correction, caught and self-verified

The brief this pass worked from quoted **728 passed / 9 failed / 19 ignored**
from a stale prebuilt binary in `target/`. The agent did not take that on
faith: it temporarily stripped all 84 of its own `#[ignore]` insertions,
rebuilt from clean, and re-ran — got **728 passed / 4 failed / 19 ignored** —
proving the 9-vs-4 discrepancy predated this phase entirely (it's the SBNI/
ladder work from the concurrent workflow) and that quarantining removed zero
tests from the compiled binary. Then restored its own edits. This is the same
correction independently reached by `LADDER_REMOVAL.md` §3.1 from a different
angle (that document measured **644**/4/103 as its own baseline, after the SBNI
tests had *also* left the tree) — the two numbers agree once you account for
which of the two concurrent passes had landed first. **Current verified state
is `LADDER_REMOVAL.md`'s: 644 passed / 4 failed / 103 ignored, independently
re-run by me just now with an identical result.**

### 2.2 Call-site verdict: not on the critical path, anywhere

`crates/nine65/src/ops/rns_fhe.rs` — encrypt/mul/div/decrypt — **does not call
bootstrap at all**; the only occurrences are three doc comments. No downstream
crate calls it either (`fhe-service`, `nine65-ffi`, `nine65-python`,
`private-feedback-nine65`, `apps/`, `sdks/`: zero call sites; `nine65-wasm`
mentions it only to say the WASM surface doesn't expose it).

The one site worth naming: `AutoBootstrapEvaluator`
(`ops/auto_bootstrap.rs:73-77`, reached from `mul_auto`/`try_add_auto`) is the
only place in `src/` where a multiply can trigger a refresh. Still not the
critical path — it's a wrapper the caller must explicitly construct, and
`RNSFHEContext::mul_dual_public` has no dependency on it in either direction.
It's the one API that needs a deprecation path if bootstrap is ever fully
removed. Worth knowing before leaning on it: `nine65-extreme-tests/src/
bootstrap_adversarial.rs:158` already documents finding Q17 — `AutoBootstrapEvaluator`
produces incorrect plaintexts after ~10 chained multiplications. That's an
independent reason not to treat this fallback as a safety net.

### 2.3 What was deliberately left un-quarantined, and why

The rule applied: quarantine iff removing bootstrap would make the test
uncompilable or meaningless. Left live: `clockwork_cross_validation.rs` (not
about `ClockworkBootstrap` at all — cross-validates Garner vs. K-Elimination,
and is feature-gated off by default anyway; flagged as belonging to a
*reconstruction* retirement pass, a different axis, see §3); 18 tests inside
`bootstrap_integration.rs` that test plain encrypt/decrypt/add/mul and CRT/
`mod_inverse` helpers with no bootstrap dependency (need relocation out of that
file, not quarantine — not done here); error-variant `Display`/`category()`
tests; `keys/bootstrap.rs`'s gcd/CRT tests (use `BOOTSTRAP_PRIMES` as a fixture
only); `compiler.rs::test_depth_50_bootstrap_free`, which asserts the
architecture's own bootstrap-*free* claim.

**Correction to an earlier claim of mine:** `symmetric_bootstrap.rs:945` is
**not** production code — it's inside `#[cfg(test)] mod tests`, in
`test_symmetric_depth_50_no_bootstrap`, which is now itself quarantined. I had
listed it as a live ladder call site; it is inert. The live ladder sites are
exactly the ones `LADDER_REMOVAL.md` §2.4 already removed.

---

## 3. The residue-space exit map

**PROVEN** (file:line, traced) — **verdict: `exits_on_hot_path`**, not "stays
fully in residue space." Six reconstructions found on the ciphertext path; two
judged unavoidable as currently designed, three avoidable with an algorithm
change (not made — out of scope, agreed), one already dead code left over from
the retired ladder.

| # | Site | Kind | Avoidable? | Why |
|---|---|---|---|---|
| 1 | `rns_fhe.rs:3304`, `k_elim_rescale_dual` | `to_u256_level` (Garner-style CRT) | **No** | BFV's `Δ`-rescale is `round(v/Δ)`, inexact by construction — needs magnitude no residue tuple carries. Avoiding it means replacing the algorithm with lane-local BEHZ/HPS fast base conversion, a rewrite, not a fix. |
| 2 | `rns_fhe.rs:3194`/`:3204`, `extract_digit_dual` | `to_u256_level` + explicit `v_m + k·M_level` materialisation, **per digit, per coefficient** (6 digits × 8192 coefficients per multiply at `secure_128`) | **Yes** | Standard BEHZ/HPS RNS digit decomposition (`digit_i = x mod q_i`) is exact and fully lane-local. This code reconstructs the whole integer only to slice base-2¹⁶ digits back out of it. |
| 3 | `rns.rs:1346`, `extract_k_rns_level` | `crt_reconstruct_u256` over the fixed 5-prime anchor | **Yes** | The lane-wise half (`k_rns[i]`) is already residue-native; only the final CRT step leaves it. Downstream only needs `k mod Δ` plus a sign — recoverable without the full integer. Reached from both sites 1 and 2. |
| 4 | `rns_fhe.rs:3442`, `mod_switch_down_dual` | `to_u256_level` | **Dead code** | Inside the just-retired ladder. Reachable in principle from `add_dual`'s alignment path, but that path's `while` loop provably never iterates now that nothing shrinks the basis (see `LADDER_REMOVAL.md` §6.2). Should be deleted with the rest of the ladder. |
| 5 | `rns_fhe.rs:2576`/`:2656`/`:2502`, `decrypt_dual_with_diagnostics` and its variants | `to_int_level` / `to_u256_level` | **No — legitimate boundary** | This is decryption emitting a plaintext into `Z_t`. Only the constant term is reconstructed. This is exactly the "boundary I/O" the `ArchitectureCounters` design already permits (§4). |

Plus **7 further boundary-only exits** (counted, not individually catalogued
here — none on the ciphertext hot path).

**A hypothesis this map raises, worth stating explicitly:** sites #2 and #3 —
the relinearization digit extraction, over the *same* fixed 5-prime anchor
basis whose `capacity_bit_length()` `LADDER_REMOVAL.md` §3.4 clocks at a
constant 110 bits regardless of the main basis size — sit directly upstream of
`k_elim_rescale_dual` (site #1) in the depth-2 chain. That is, the currently
open depth-2 correctness defect and this section's "avoidable" reconstructions
may be the *same* code, not two separate findings. This is exactly what the
concurrent depth-2 investigation (`docs/LADDER_REMOVAL.md` §6.1, tracked
separately) is chasing. If it confirms a capacity overflow at site #2/#3, then
fixing that defect and closing an "avoidable" residue-space exit could be one
change, not two.

---

## 4. The `ArchitectureCounters` design, and what this audit confirms about it

`crates/cram-core/src/lib.rs`'s `ArchitectureCounters` already encodes the
right shape: it forbids `internal_projections`, `crt_reconstructions`,
`scalar_materializations`, `garner_calls`, `mixed_radix_calls`, and permits
`transductions`, `user_io_projections`, `oracle_projections`. Interior exact,
boundary allowed. This audit's exit map (§3) is, in effect, a manual instance
of exactly that classification — and it independently reaches the same
boundary/interior split the counters were designed to enforce, without the
counters actually being wired up to do it (they are not incremented anywhere
in `nine65`, and `nine65` does not depend on `cram-core` — a separate,
already-flagged item).

---

## 5. What this document defers to `LADDER_REMOVAL.md`

To avoid two documents disagreeing on the same numbers, this audit does not
restate: the noise-growth curve shape and rate, the exact-division
`log2(d)`-with-zero-rounding-term result, the lane-count invariance proof
across a 4096-deep chain, or the depth-2 `ct×ct` correctness defect. All of
those are `LADDER_REMOVAL.md`'s findings, independently re-verified by direct
`cargo test` runs against this exact working tree, and are the authoritative
source for that material.

---

## 6. Open items

1. **MANA is disconnected.** If the residue-native parallelism story matters,
   this is not a flag to flip — it needs real call sites written in
   `rns_fhe.rs`, and the `reconstruct_at()` reconstruction in `mana/src/
   stream.rs:99` needs guarding before anything routes through it.
2. **The unconditional, unused `rayon` dev-dependency in
   `nine65-extreme-tests/Cargo.toml:16`** — same defect class as the one fixed
   here, different crate, not touched.
3. **Sites #2 and #3 in the exit map are a real rewrite candidate** (lane-local
   BEHZ/HPS digit decomposition), pending the outcome of the depth-2
   investigation — see the hypothesis in §3.
4. **Site #4 (`mod_switch_down_dual`) is dead code** and should be deleted in
   the same pass that eventually removes the rest of the retired ladder
   definitions (`LADDER_REMOVAL.md` §6.2 lists them; they're currently kept
   alive on purpose as `basis_invariance.rs`'s negative control).
5. **`AutoBootstrapEvaluator` needs a deprecation path**, not a deletion, given
   it has no callers in production but is a public API — and given finding
   Q17, it should not be presented as a safety net in the interim.

---

## 7. The one-line version

Rayon was in the wrong dependency slot and is fixed; MANA — the canonical
parallelism layer — turns out not to be connected to anything in the default
build, which is a real gap, not a false alarm. Bootstrap is quarantined (145
tests, tailored reasons, nothing deleted) and independently confirmed to sit on
no critical path anywhere in the workspace. The ciphertext genuinely stays in
residue space at the boundary (decrypt) and cannot avoid leaving it at BFV's
inexact rescale — but two of the six hot-path reconstructions found are
avoidable rewrites, not requirements, and one of them may turn out to be the
same code as the open depth-2 defect.

---

## 8. GSO-FHE (addendum, 2026-08-09)

Audited on request, same rigor as the SBNI pass. **REJECTED — collapse never
touches the real ciphertext.**

`NoiseEstimate::collapse()` (`ops/gso_fhe.rs:96`) sets `self.distance = 0`.
`GSOSwarm::collapse()` mutates only its own internal `shadow` accumulator. The
real `DualRNSCiphertext` math is delegated straight through to
`RNSFHEContext::mul_dual_symmetric`/`mul_dual_public` — collapse is bookkeeping
beside the ciphertext, not an operation on it. This is the same "budget reset
without real ciphertext refresh" pattern `AUDIT_REMEDIATION_2026-07-13.md`
already ruled inadmissible elsewhere; that remediation never reached this file.
`proofs/coq/GSOFHE.v` formalizes the tracker (trivially bounded, since
`perform_collapse` zeroes `distance` by definition) and separately *asserts*,
unproven, that the tracker corresponds to the real BFV error term — a claim
the Rust does not support. `test_gso_mul_public_depth2` already documents a
known-wrong depth-2 decryption as a `println!` warning, not a failing
assertion. `GSOSwarm::extract_shadow()` is deterministic in `basin_id`
(≈ plaintext mod 1024) and unused everywhere except one test's `println!` — no
current exploit path, since nothing consumes it, but a landmine if it's ever
wired in as the "auxiliary randomness" its own header comment claims it is.

Not on the default multiply path (`rns_fhe.rs` hot-path functions never call
into `GSOFHEContext`), so it cannot corrupt anything the other 644 passing
tests depend on. Per author (this was pulled in from an older, separate body
of work, not written against this codebase and not currently treated as
load-bearing): no code/doc remediation requested at this time. Left as-is;
flagged here so the gap is on record rather than silently known-and-unwritten.

### 8.1 Adversarial verification (2 independent refutation attempts, both failed)

Verifier A read all 1422 lines of `gso_fhe.rs`: `result` is bound *before* the
collapse branch and never re-read after it; `mul_dual_symmetric`/`mul_dual_public`
take `&self` with no interior mutability anywhere in the struct graph; `grep
"swarm\|basin\|GSO" rns_fhe.rs` returns **zero hits** — the file doing the real
ciphertext math has no awareness GSO exists. Verifier B checked the other
angles: no `Rc`/`RefCell`/`Arc`/`Mutex`/`static mut`/`unsafe` (no shared-state
backdoor), `basin_radius` never passed into `mul_dual_*`, no cfg/feature wires
it differently. `git log --all --follow` on `gso_fhe.rs` shows **3 commits**,
collapse wiring unchanged since the initial one — no richer version was ever
present and later stripped.

### 8.2 Cross-repo genealogy (9 prior project attempts searched)

| Repo | GSO present | Connects to real residues |
|---|---|---|
| MYSTIC | docs only — own audit says "Coded: NO" | no (nothing to connect) |
| cram-substrate | absent (README + LICENSE only) | n/a |
| Loki5 | absent (that's GRO, Golden-Ratio Oscillator) | n/a |
| Quantum_Modular_Numeric_Framework | nominal only | comment-level; see below |
| QMNF_System | yes, + independent reinvention | no |
| NINE65-v5-proofstack | yes | no |
| NINE65-v5 | yes | no |
| NINE65-v6-a-Clockwork-Prime | yes | no |
| NINE65_v6_a_Clockwork_Prime | yes | no |

**No version, in any repo, at any point in the history, ever connected
swarm/basin state to real ciphertext residues.** The pattern is byte-identical
across every NINE65 generation: real ciphertext computed first via
`mul_dual_*`, then a heuristic counter zeroed, then a self-contained LCG mix
over golden-angle coordinates that nothing reads.

Two findings worth keeping:

1. **QMNF's `sample_error()`** (`src/fhe/polynomial.rs`) is doc-commented
   "GSO MICRO-SWARM" and its output *does* become real ciphertext noise — but
   the executable code is a plain Knuth LCG with no agent, force, or basin.
   Nominal GSO, not mechanistic. It is also noise *generation* at encrypt
   time, not noise *bounding*. The repo's genuine mechanistic swarm
   (`src/swarm_gso.rs`) only minimizes toy fitness functions (sphere,
   rastrigin) and never sees a ciphertext.
2. **QMNF_System's `fhe_ahop.rs`** ("Attractor-Homomorphic Optimization
   Protocol", tagged `G6-01`) is not an independent reinvention — per the
   author it is the **ancestor**. QMNF_System is the original monolith
   (~1.2M lines) that the NINE65 line was split out of. `AHOPCiphertext`
   carries real `c0`/`c1` plus a `noise_bits` counter and a `basin_id`;
   `apply_attractor_reduction()` multiplies `noise_bits` by a fixed
   0.8/0.9/0.95 constant and never touches `c0`/`c1`.

   Its header states the seed idea verbatim:

   > 1. Map ciphertext space to attractor basin
   > 2. Homomorphic operations = trajectory evolution
   > 3. Noise = distance from attractor
   > 4. Attractor pull naturally reduces noise!

   Steps 1–2 are metaphor; step 3 is an *assumption*; step 4 is the
   conclusion drawn from it. The missing artifact — in AHOP, in every NINE65
   generation after it, in the Coq proof and the Lean port — is always the
   same single piece: a defined map from "distance from attractor" to the
   actual RLWE error term. Every descendant faithfully encodes steps 1, 2 and
   4 and never builds step 3. That is why the disconnect is identical
   everywhere: it was inherited, not re-derived.

   Corroborating the sprawl the split was meant to fix: `AHOP` resolves to at
   least seven different expansions inside QMNF_System alone — *Attractor-
   Homomorphic Optimization Protocol*, *Apollonian Hidden Orbit Problem*
   (the post-quantum primitive in the genealogy skill's lineage table),
   *Adaptive Hierarchical Optimization*, *Arithmetic Homomorphic Operations*,
   plus Field/Ring/Mode variants. One acronym, seven meanings, one repo.

**What this does *not* undermine:** the real noise control was never GSO. In
v6 it was K-Elimination exact rescale plus auto modulus-switching; in v7 it is
K-Elimination exact rescale alone (see `LADDER_REMOVAL.md`). Both operate on
real limbs and are wholly orthogonal to GSO/basin/swarm state. The measured
depth curve in `LADDER_REMOVAL.md` is a property of that real mechanism. GSO
was never load-bearing, so retiring the claim costs no measured capability.
