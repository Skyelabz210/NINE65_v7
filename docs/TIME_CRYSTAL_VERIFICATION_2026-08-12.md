# Time Crystal / System Integrity — Report Claims Benched

**Date:** 2026-08-12. The "Final System Integrity & Time Crystal Verification
Report" makes measurable claims. This turns each into an executable test
against the **real ciphertext path** (`crates/nine65/tests/time_crystal_verification.rs`,
7 tests, all green). No simulation, no normalization games.

## Claim-by-claim verdict

| Report claim | Verdict | Measured |
| :--- | :--- | :--- |
| Fault Localization 100% (Residue Dissenter isolates corrupted lanes) | **VERIFIED** | 10/10 single-bit anchor faults at secure_256 detected loudly (witness dissent or gate refusal); 0 silent-wrong. Pure witness lanes (8,9 of the 10-anchor basis) dissent on direct corruption 4/4 |
| Substrate Rigidity (non-perturbed lanes keep ground state under 50% corruption) | **VERIFIED** | Fault in one anchor lane leaves every other lane **bit-identical** through lanewise ops; main lanes untouched by an anchor fault. This is the "independent periodic oscillators" property, measured as exact equality |
| 50% substrate corruption survivable | **VERIFIED (as detect-and-refuse)** | Corrupting 5 of 10 anchor lanes is refused loudly 4/4; never slips through as a correct answer. NB: "self-stabilized" = detected and refused, **not** silently healed — see honest framing below |
| Depth-50, 100% correctness | **VERIFIED for the symmetric path** | `mul_dual_symmetric` + K-Elim rescale: **exact decryption to depth 50** at secure_128. Public relin chain: exact to **depth 1 only**. The report conflated the two; both are now pinned |
| Memory footprint ~4.2 MB | **VERIFIED** | secure_256 ciphertext measured at exactly **4.00 MiB** (6 main + 10 anchor lanes × 16384 × 8B × 2 polys). The report's 4.2 MB is one ciphertext, honestly |

## Honest framing (what the report overstates)

1. **"Self-stabilizing / self-healing" is detect-and-refuse, not repair.** The
   Residue Dissenter (witness-lane check in `extract_k_rns_level`, PR #39)
   catches a corrupted lane and fails loudly. It does not reconstruct the
   correct value from the survivors. Rigidity (no cross-lane propagation) +
   loud dissent is a strong integrity property and is fully verified — but it
   is error *detection*, and calling it "self-healing" claims a capability the
   code does not have and this suite does not test for.

2. **"Depth-50" is the symmetric path only.** Verified true there. Public-mode
   relinearized multiplication noise-exhausts almost immediately (depth 1
   exact at secure_128). Any depth claim must name its path.

3. **"Time Crystal" is a metaphor, not a mechanism.** The measured content —
   lane independence (rigidity) and dissent-on-perturbation — is real and
   tested. Nothing about time-translation symmetry breaking follows from CRT
   lane arithmetic; the physics analogy carries no additional verified claim.

4. **Unbenched here (marketing until measured):** "380x per-core lead over
   TFHE-rs" (no methodology, unlike workloads), "zero shadow entropy /
   absolute DPA immunity" (requires hardware traces, not the simulation the
   earlier packet used), "256+ bits of security" (that's the lattice
   estimator's job — see docs/LATTICE_ESTIMATOR_BASELINE, not this suite).

## What is now permanent

`tests/time_crystal_verification.rs` runs in the standard workspace suite.
The integrity properties (fault detection, lane rigidity, depth, footprint)
are regression-locked: if a future change lets a fault pass silently, breaks
lane independence, regresses symmetric depth below 10, or bloats the
ciphertext past ~4 MiB, CI goes red.
