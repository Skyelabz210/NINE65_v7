# Issue #130: cargo test --workspace's fail-fast silently skips ~28 nine65 integration test files whenever nine65 --lib has any failure

- state: open
- labels: bug, testing
- created: 2026-09-04T10:19:30Z  updated: 2026-09-04T11:17:04Z
- url: https://github.com/Skyelabz210/NINE65_v7/issues/130

---

## Finding

Found by the agent resolving issue #78 (test tier categorization, PR #129) while actually running the MEDIUM tier (CLAUDE.md's documented `cargo test --release --workspace --exclude nine65-python --exclude nine65-wasm` command) to completion rather than assuming it works.

`cargo test --workspace` builds and runs test binaries in an order where `nine65`'s `--lib` target runs before its ~28 separate `tests/*.rs` integration-test binaries, `nine65-extreme-tests`, and the private-feedback crates. Cargo's default fail-fast-per-binary behavior means: **the moment `nine65 --lib` has any failing test, none of those later targets run at all** — not "run and also reported failing," but never invoked, no output, no exit code contribution.

Since `nine65 --lib` currently has 5 known, tracked, pre-existing failures (issue #117 / `docs/PUBLIC_REFRESH_CORRUPTS_ADMITTED_CONFIGS_2026-09-03.md`), **every `cargo test --workspace` run on current `main` silently skips a large fraction of the test suite**, and has been doing so for as long as those 5 failures have existed (bisected elsewhere to predate this September's merge wave entirely). This was independently observed at least twice before without being named as its own issue: PR #109's test plan noted "cargo test --release --workspace ... stops at the same 5 pre-existing nine65 lib failures... crates/targets after that point in the run order were not separately re-verified," and PR #129 (issue #78) reproduced it explicitly while measuring the MEDIUM test tier.

## Why this matters

This means CLAUDE.md's own documented "Run all tests" command has not actually been exercising the full test suite for some unknown period, and neither has any manual `cargo test --workspace` run anyone has done against a `main` carrying those 5 failures — which, per the bisection in `docs/PUBLIC_REFRESH_CORRUPTS_ADMITTED_CONFIGS_2026-09-03.md`, is essentially the entire current history back to at least `f8fa50a`. Combined with issue #79 (GitHub Actions hasn't executed successfully since 2026-02-27), this means the ~28 nine65 integration test files, `nine65-extreme-tests`, and the private-feedback crates have had **no confirmed passing run on record for an extended period** — not failing, not passing, simply not run, silently.

## Required work

1. Add `--no-fail-fast` to the documented/CI workspace test command (trivial, but changes what "the test suite" reports — every currently-hidden integration-test failure becomes visible at once; expect this to surface new information, not introduce new failures).
2. Once `--no-fail-fast` is in place, actually run the full suite once and record, honestly, what the previously-unexecuted ~28 files + `nine65-extreme-tests` + private-feedback crates currently show — pass, fail, or something worse. Do not assume they pass because nothing else in this session found a reason to doubt them.
3. Decide whether CI (once issue #79 is resolved) should use `--no-fail-fast` by default, or fail-fast only after a full run — worth an explicit decision rather than inheriting Cargo's default silently.
4. Update `CLAUDE.md`'s "Build & Test Commands" section once the correct invocation is settled, since it's currently silently wrong about what it exercises.

## Reproduce

```
cargo test --release --workspace --exclude nine65-python --exclude nine65-wasm
# stops after nine65's --lib target fails; compare against:
cargo test --release --workspace --exclude nine65-python --exclude nine65-wasm --no-fail-fast
```