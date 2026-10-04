# Issue #95: [P0] Replace invalid component-wise BFV bootstrap Phase 1 with a mathematically valid public decryption/encoding transition

- state: open
- labels: (none)
- created: 2026-08-31T09:37:11Z  updated: 2026-09-05T09:59:28Z
- url: https://github.com/Skyelabz210/NINE65_v7/issues/95

---

## Cross-reference: independent empirical confirmation of the same defect (issue #117)

This issue's mathematical derivation (the exact identity showing the dropped `K` correction term, the `Q=17,t=5` scalar counterexample) and the live-trace evidence localizing the first wrong value to `modswitch_to_t` are exactly corroborated by issue #117, filed independently a day later from a different angle: `ops::bootstrap::tests::diag_measure_noise_growth` bypasses only `public_phase1_soundness_gate` to run the three real phases and measure their output directly. It shows `refresh(7)` itself — not merely a subsequent multiply — decrypting to `65536`/`65536`/`40` instead of `7` on `secure_128`/`secure_128_deep`/`secure_192`. A dedicated bisection on #117 confirmed the corruption is 100% isolated to Phase 1 (`modswitch_to_t`); Phases 2 and 3 faithfully propagate the value Phase 1 already got wrong. Both issues are describing the same defect from different directions — this one derives *why* it must be wrong, #117 empirically confirms *that* it is wrong, at production scale, on real keys.

One correction to #117's own framing worth recording here: at the time it was filed, #117 didn't yet have this issue's algebra and described the defect only as "public refresh corrupts plaintext on admitted configs." This issue's exact identity is the actual mathematical root cause; #117 is best read as the reproducible empirical evidence for it, not a separate bug.

## Status of the "Immediate fail-closed requirement" section

Worth confirming explicitly since it's a real, checkable claim: **this requirement is already satisfied on current `main`**. `public_phase1_soundness_gate()` (`crates/nine65/src/ops/bootstrap.rs`) unconditionally returns `Nine65Error::BootstrapFailed`, exactly as this section asks ("production entry points return a typed `BootstrapFailed`"). That's precisely why #117's diagnostic test had to bypass it explicitly (`refresh_bypassing_the_gate`) to observe Phase 1's actual output at all — no normal caller can reach the corrupting path. `SymmetricBootstrap` (trusted-evaluator, holds `sk`) remains unaffected, as this issue already notes.

## What remains open

Route A (homomorphic correction circuit evaluating `K` on encrypted state) or Route B (complete the BGV-style `m mod t` encoding migration per `docs/MODULUS_SWITCHING.md`) — this is genuinely new cryptographic construction, not a bug to trace and patch, and deserves the same caution this session applied to not rushing #117: it was deliberately not attempted blind. Whoever picks this up should start from this issue's own exact-identity derivation (the `K_j = round((R0_j + (R1*s)_j)/Q)` correction) rather than re-deriving it.