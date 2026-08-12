# Audit Verification — Master Audit Tarball & Physical Audit Packet

**Date:** 2026-08-12
**Subject:** Independent verification of `NINE65_v7_Master_Audit_Final_v2_2.tar.gz`,
the "Exhaustive Physical Audit" packet, the S8 Time-Crystal analysis, and
`deep_wiring_audit.py` — against the live repository, with selective porting
of the remediations that survived scrutiny.

---

## 1. What was verified (with evidence)

| Claim / artifact | Verdict | Evidence |
| :--- | :--- | :--- |
| Workspace builds clean (release) | **Verified** | `cargo build --release --workspace` exit 0 |
| `deep_wiring_audit.py` A2 projection identity, depth 10,000 | **Verified, with caveat** | Script passes; note it derives the winding `k` from the ground-truth integer each step, so it validates the Universal Projection *identity*, not an independent implementation |
| Proposed anchor primes are prime and NTT-friendly | **Verified** | Deterministic Miller–Rabin (bases 2..37); all satisfy 2^15 | p−1, covering 2n for every n ≤ 16384 |
| 5-anchor basis insufficient for secure_256 ct×ct | **Verified** | required = log2(N) + 2·log2(Q) = 14 + 2·175 = 364 bits > M×A = 175 + 157 = 332 bits |
| secure_192 at full level was also over capacity | **Verified — worse than the packet claimed** | 306 bits required vs 303 bits capacity: 100% utilization. The packet did not mention secure_192 at all |
| Repo suffers "silent overflows" for secure_256 (merge report §2.2) | **Refuted** | The live repo fails **loudly**: `mul_dual_public` returned `Err(InvalidParameter)` via the capacity-drift gate, and `tests/anchor_drift_diagnostics.rs` pinned that behavior. There was no silent corruption |
| Tarball's 7-prime basis "verified" for secure_256 | **Refuted** | 7 anchors give 364/395 = 92% utilization. The repo's boundary gate (`BoundaryDiagnostic::to_result(true)`) hard-errors at ≥ 80% in public mode — unchanged in the tarball. The tarball's own public-mode multiplication could never have succeeded; its audit numbers must have come through the warn-only symmetric path |
| Tarball tested against the full suite | **Doubtful** | Its `dry_run_results.log` shows compilation only, no test executions |

## 2. What was ported (re-derived, not copied)

The tarball's diagnosis — anchor capacity is the secure_256 blocker — was
**correct**. Its fix was insufficient (see above), so the port goes further:

1. **Dimension-keyed anchor basis** (`canonical_anchor_primes_for_n`):
   - n ≤ 8192: the original 5 primes, byte-identical behavior — no extra
     lanes, no perf cost, no k-reconstruction change for the 128-bit tiers.
   - n = 16384: 10 primes (A ≈ 315 bits). secure_256: 74% utilization;
     secure_192: 66% — both below the 80% strict gate with real margin.
     The 3 extra primes beyond the tarball's 7 (3221422081, 3222306817,
     3222372353, 3222568961, 3222962177) were verified prime and
     NTT-compatible before inclusion.
2. **Capped U256 reconstruction + witness lanes** (`extract_k_rns_level`):
   the full 10-prime product exceeds U256's Garner ceiling, so k is
   reconstructed from the first 8 anchors (A_recon ≈ 251 bits; any
   gate-legal k is ≤ ~217 bits), and the remaining lanes are checked as
   **integrity witnesses** under the same signed interpretation consumers
   apply. A k that outgrows reconstruction capacity now panics with a
   diagnostic instead of silently wrapping — this implements the packet's
   "Residue Dissenter" concept in the production K-Elimination path, which
   the tarball's own code did not do (its loud-fail only checked proximity
   to the full product, and its U512 `mod` was a 512-iteration bit loop on
   the per-coefficient hot path).
   `k_elim_rescale_dual`'s sign modulus mirrors the same anchor count, per
   its own invariant comment.
3. **N ≥ 8192 production floor assertion** (`secure_configs.rs`): ported
   as-is; consistent with the already-documented policy and satisfied by
   every current secure tier.
4. **Fixed two pre-existing release-test-build breakages** (not from the
   tarball, surfaced by running the full suite):
   - `tests/noise_profile.rs` failed to compile because the
     `#[cfg(not(any(test, debug_assertions)))]` variant of
     `decrypt_dual_with_diagnostics` was private while the test/debug
     variant was `pub`. Made them consistent; the 11 noise-profile tests pass.
   - `fhe-service`'s test build failed to compile: an un-annotated closure
     error type in `handlers.rs` (decrypt batch handler) and two
     `#[cfg(test)]` session helpers that moved a `FnOnce` closure into two
     call sites. Annotated the error type and changed the helpers to
     `Fn` passed by reference; all 50 fhe-service tests pass.

**New capability unlocked:** `secure_256` (and full-level `secure_192`)
ct×ct multiplication through the strict public-mode gate now succeeds with
exact plaintext recovery (`test_secure_256_mul_succeeds_with_10_anchor_basis`:
Enc(2)×Enc(3) → Dec = 6). Cost: the n = 16384 tiers carry 10 anchor lanes
instead of 5, so their per-op time rises accordingly; n ≤ 8192 tiers are
untouched.

## 3. What was rejected, and why

| Tarball change | Decision | Reason |
| :--- | :--- | :--- |
| Parallel-summation CRT replacing Garner ("A2 No-Garner") | **Rejected** | The claimed constant-time benefit is not delivered by the tarball code: it adds a data-dependent `if ri == 0 { continue; }` branch, drops the live tree's `mod_u64_ct` secret-data path in `reconstruct_value_at_level`, and its bit-by-bit 512-iteration reductions are far slower than Garner on the per-coefficient path. Correctness is equivalent; the live Garner path stays |
| `U512` type | **Not needed** | Introduced by the tarball to hold the wider parallel-summation intermediates. The capped-reconstruction + witness design keeps everything inside the existing U256 with a stronger integrity guarantee |
| Public `U256`/`U512` fields & methods | **Rejected** | Widens the crate API surface for the audit binaries' benefit only |
| Audit binaries (`dpa_simulation.rs`, `transduction_audit.rs`, etc.) | **Not ported** | They depend on the rejected public-U512 API, and several exist to produce the simulation-level claims discussed in §4. Portable on request |
| `mul_plain_cost(scalar, config)` scalar-aware noise cost | **Deferred** | Directionally reasonable (models scalar magnitude in mul-plain noise), but it changes noise accounting that auto-bootstrap thresholds depend on; should land with its own calibration tests |

## 4. Claims that remain unverified (treat as marketing until measured)

- **"~360x energy-efficiency lead over TFHE-rs", "10.87 Ops/Joule"** — no
  measurement methodology in the packet; TFHE-rs comparison normalizes
  unlike workloads. Unverifiable from the artifacts provided.
- **"DPA attacks mathematically impossible", "flat-line power profile"** —
  based on a 500-trace *simulated* Hamming-weight model. A simulation with
  Gaussian noise showing correlation 0.0000 is consistent with an
  insufficient model, not proof of impossibility. Real DPA resistance
  requires hardware traces.
- **"Absolute Thermal Stability"** — no thermal data in the packet.
- **S8 "Time Crystal" self-stabilization** — metaphor, not mechanism. The
  S8 basis is real in the codebase (`exact_transcendentals::transduction::S8_BASIS`)
  and residue-witness integrity checking is a sound idea — now actually
  implemented in `extract_k_rns_level` (§2.2) — but nothing about
  time-translation symmetry breaking follows from CRT arithmetic, and no
  "restoring force" exists: a detected fault is detected, not healed.
- **"100,000-step stress test, 30.7 s"** — plausible for the linear
  recurrence in `deep_wiring_audit.py`-style harnesses, but not reproduced
  here against the Rust ops layer.

## 5. Corrections this pass makes to the audit record

1. The repository never had the "silent overflow" defect the merge report
   leads with; it had a **loud, tested capacity gate**. The real defect was
   narrower: the 5-anchor basis made the gate *correctly* reject secure_256
   (and left secure_192 at 100% utilization).
2. The tarball's 7-prime remediation was insufficient against the
   repository's own strict boundary gates (92% ≥ 80%); 10 primes with
   witness-checked reconstruction is the working configuration.
3. CLAUDE.md's config table is stale: `secure_128` is n = 8192 in code, not
   n = 4096.

---

*This document reports only what was built, run, and measured in this
repository. Claims outside that scope are labeled as such above.*
