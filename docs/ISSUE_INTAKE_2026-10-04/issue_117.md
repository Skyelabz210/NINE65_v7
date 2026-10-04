# Issue #117: [P0] Public refresh corrupts plaintext on configs admitted by supports_public_refresh (secure_128_deep, secure_192)

- state: open
- labels: bug, critical, security
- created: 2026-09-03T16:25:35Z  updated: 2026-09-03T17:24:14Z
- url: https://github.com/Skyelabz210/NINE65_v7/issues/117

---

## Summary

`ops::bootstrap::tests::diag_measure_noise_growth` bypasses only the `public_phase1_soundness_gate` ("Gate 0") to run the three actual refresh phases and directly measure their output — independent of #95, which is about the gate that stops the call before this point. Run against a real Rust toolchain on 2026-09-03 (main `2547cf0`, before #114/#108 merged), the measurement is:

```
config              lanes  headroom  required    admits |   refresh(7)     refresh(7)^2
secure_128              4        71        47      true | 65536 (WRONG)    40018 (WRONG)
secure_128_deep         4        71        47      true | 65536 (WRONG)    40018 (WRONG)
secure_192              5        96        49      true |   40 (WRONG)    40518 (WRONG)
```

("admits" = `supports_public_refresh(config)`, `secure_configs.rs`'s own gate for whether a chain has enough post-refresh `Delta` headroom to carry a refresh.)

This test then hits its own tripwire:

> `secure_128: supports_public_refresh admits this config, but the decryption oracle says a public refresh corrupts it. The gate is admitting a corrupting path — fix the predicate, do not relax this assertion.` (`crates/nine65/src/ops/bootstrap.rs:1685`)

## Why this needs its own issue, distinct from #95

`CLAUDE.md`'s Bootstrap Paths section currently documents this test's output as: refresh decrypts correctly, and only the *subsequent multiply* is wrong, and only for the *refused* configs (`secure_128`, `hardware_opt`) — the entire point being that `secure_128_deep`/`secure_192`/`secure_256` (admitted) don't have this problem. The measurement above contradicts that on two counts:

1. `refresh(7)` itself — not the subsequent multiply — is wrong for all three measured configs.
2. Two of the three are configs the admission gate calls **admitted**, not refused.

So this isn't "public bootstrap is stubbed out" (that's #95, and the gate correctly stops normal callers from reaching this). This is: when the gate is bypassed to actually run the three phases (as any real WR-5C replacement eventually must), the phases themselves currently produce a wrong plaintext, on chains the admission predicate says should be safe to carry a refresh. `secure_256` was not in this test's three-case table and has not been measured.

## Reproduce

```
cargo test --release -p nine65 --lib -- ops::bootstrap::tests::diag_measure_noise_growth --nocapture
```

## Bisection

Confirmed via `git worktree` at `f8fa50a` (the commit immediately before PR #107 merged, i.e. before #107, #99, and #103 all three) that this already fails identically there — not a regression from this September's merge wave.

## Scope

No fix attempted here. This is a discovery/tracking issue only. Full writeup: `docs/PUBLIC_REFRESH_CORRUPTS_ADMITTED_CONFIGS_2026-09-03.md` (merged in #109). Relevant to WR-5A (#116, mask sampling) and WR-5B (#113, security validation exactness) in that both touch the same subsystem, but neither's acceptance criteria currently requires investigating *this* — the phases' arithmetic correctness on admitted configs, independent of sampling uniformity or security-bit accounting. `supports_public_refresh`'s predicate (`post_refresh_required_bits` / `public_refresh_headroom_bits` in `params/secure_configs.rs`) is the first place to look, per the test's own panic message.