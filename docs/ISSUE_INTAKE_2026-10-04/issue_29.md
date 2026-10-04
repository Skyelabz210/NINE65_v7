# Issue #29: Restore recumbent CRAM bootstrap and exact RNS context metadata after PR #26

- state: open
- labels: bug
- created: 2026-07-13T15:26:48Z  updated: 2026-09-03T16:35:43Z
- url: https://github.com/Skyelabz210/NINE65_v7/issues/29

---

Checked all four defects against current `main` (`43a7d33`) — this one's genuinely mixed, not stale:

- **Defect B (approximate `q_bits`, `q_product == 0` sentinel) — looks resolved.** `RNSFHEContext::try_new` now sets `q_bits = config.rns_product_bit_length()`, which is the exact multi-limb bit length (`limbs_bit_length(&self.rns_product_limbs())`), not summed per-prime widths. The `q_product == 0` overflow sentinel is still used in a couple of places (e.g. `mul_route()`'s `if self.q_product == 0 { return MulRoute::KElimDual }`) but as a conservative fail-toward-K-Elimination default, which matches what this issue itself says was already true ("The route currently fails toward K-Elimination") — the ambiguity this issue flagged as the problem (exact bit length) is fixed.
- **Defect C (`KElimination::capacity()` saturating) — looks resolved.** `capacity()` is now `#[deprecated]` in favor of `try_capacity()`/`capacity_limbs()`/`capacity_bit_length()` (checked/exact alternatives). I haven't independently verified every doc reference to CLASS-R/Garner is gone — that overlaps issue #70 (K-Elimination consolidation), which I dispatched a separate pass to; worth a final check there rather than duplicating it here.
- **Defect A (coefficient reconstruction inside the bootstrap refresh hot path) — still present, confirmed by direct read today.** `ClockworkBootstrap::modswitch_to_t` (`crates/nine65/src/ops/bootstrap.rs:727`) still CRT-reconstructs every coefficient via `crt_reconstruct_n`/U256 CRT helpers before dividing on the number line, exactly as described. This is one of the 21 findings the residue-native scanner (`scripts/check_residue_native_architecture.py`) currently reports in `bootstrap.rs`. It's directly relevant to a new, more specific finding I filed today as issue #117 (public refresh producing a wrong plaintext even on configs the admission predicate calls safe) — I've dispatched a dedicated agent to bisect #117 through exactly these three phases, `modswitch_to_t` included. Recommend tracking Defect A's remediation there rather than reopening a parallel effort against the now-nonexistent `audit/remediate-followup-2026-07-13` branch this issue names.
- **Defect D (manual recovery retry lacks a second budget check in `nine65_bench::run_manual_bootstrap_depth`) — status unverified.** I couldn't find a function by that name anywhere in the current tree (`crates/nine65/src/bin/`, `nine65-extreme-tests`) — it may have been renamed, restructured, or removed since July. Needs a fresh look rather than being carried forward on stale line/function references.

Leaving open given Defect A and D. Suggest narrowing this issue's remaining scope to just those two, since B and C are done.