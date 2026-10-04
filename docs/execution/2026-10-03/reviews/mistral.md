# Mistral source review

Reference only: these suggestions are **not accepted task instructions**. Read
[REVIEW_DISPOSITIONS.md](REVIEW_DISPOSITIONS.md) first.

Task-local configuration requested `thinking = "max"` for the installed
`mistral-medium-3.5` alias. The installed Mistral backend maps `max` to the
provider parameter `reasoning_effort = "high"`. Tools and edits were disabled.

### (1) Concrete contradictions and gaps

**Contradictions**
- `prime_power_phase.rs:402–409` enforces `lineage`, `family`, `primes`, `n`, `base` equality, but `PrimePowerLiftedPhase` (docs/PRIME_POWER…:53–54) and `CanonicalLowDigitLift` (same file:347–355) have **private fields and no public constructors**, so callers cannot produce a matching `CanonicalLowDigitLift` to pass the check. **Gap at construction, contradiction at validation.**
- `PUBLIC_FHE_SOLUTION_2026-09-28.md:70` requires **`|ρ| ≤ B ≤ h`** as an essential hypothesis for `h+F(x-h)` to yield a canonical digit; no certificate in `CanonicalLowDigitLift` (347–355) attests this radius bound. **Admission gate missing.**

**Gaps**
- `prime_power_phase.rs:420–432` uses an undocumented `words()` to compare `U512` magnitudes; no definition visible. **Missing prerequisite.**
- `prime_power_phase.rs:417` computes `half_delta` from `q`, but `PrimePowerContractionCertificate` (358–364) already carries `half_delta`; no check that they match. **Metadata not validated against context.**
- `PRIME_POWER_BOOTSTRAP_CONTRACTION.md:66–68` states high/low certificates bound error “relative to the exact `Q/t²` and `Q/t` grids,” yet `PrimePowerContractionCertificate:360–363` exposes `half_delta` and `output_error_bound` without grid identifiers. **Certificate lacks grid binding.**

---

### (2) Five small implementable work tickets

| # | Target | Negative test | Done |
|---|--------|----------------|------|
| 1 | `CanonicalLowDigitLift` constructor | Reject if `lineage`/`family` mismatches the producing phase | Constructor is public and all lineage-checked tests pass |
| 2 | `PrimePowerDigitRemoval::contract` | Reject if certificate’s `half_delta ≠ q/(2 base)` | Every accepted contract call has matching half-deltas |
| 3 | `U512` helpers | `words(x) ≥ 512` returns error | No certificate with ≥512-bit value accepted |
| 4 | Pre-addition overflow gate | Reject if `words(phase.high_error_bound) + words(digit.error_bound) ≥ words(half_delta)` before addition | Contract never overflows output bound |
| 5 | `CanonicalLowDigitLift` radius field | Reject construction if `B` or proven `ρ` bound missing | Every lift carries a validated `rho_bound ≤ B` certificate |

---

### (3) Unknowns

- Exact algorithm or artifact that proves `|ρ| ≤ B` for a specific ciphertext history (PUBLIC_FHE…:74–76).
- Source file defining `words()` used in `prime_power_phase.rs:420,421,428`.
- Whether `floor_scale_difference` (363) is redundant given grid-bound claims or independently auditable.
- How the **operation-history bound** (PUBLIC_FHE…:74–76) is serialized and linked to `CanonicalLowDigitLift`.
- Status of the **multiplication bound** (PRIME_POWER…:6–7) vs **noise certificate lower bound** (PRIME_POWER_LIFT…:11–12); two distinct blockers cited.
