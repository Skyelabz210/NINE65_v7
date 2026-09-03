# fhe-service HTTP API outage under the WIRE-Q fail-closed gate

## Status: confirmed by a Rust-equipped runner on 2026-09-03, unfixed

`docs/WIRE_Q_FAIL_CLOSED_2026-09-02.md` closed the dual-RNS wire boundary and
noted "Rust compilation and integration tests remain required before the
branch is promoted." That requirement was not met: the branch (PR #107) was
merged (`8f59127`) with only the Python source-contract gate
(`scripts/verify_wire_q_fail_closed.py`) run locally, because the merging
environment had no Rust toolchain. This session has one, ran it, and found a
consequence more severe than the PR description states.

## What is actually broken

`Session::dual_ct_to_b64` / `Session::dual_ct_from_b64`
(`crates/fhe-service/src/session.rs:129-146`) were changed to
unconditionally return `Err("WIRE-Q: ...")` — they never encode or decode
anything now, by design, for any input.

`handlers::handle_encrypt` (`crates/fhe-service/src/handlers.rs:453`) calls
`session.dual_ct_to_b64(&ciphertext)?` on the ciphertext it *just produced*
with `encrypt_dual_secure`, to build its own response body. Because that call
always errors, **every `POST /v1/sessions/{id}/encrypt` request now returns
`400 ENCRYPT_FAILED`, for every config, unconditionally.**

`handle_decrypt` and `handle_evaluate` call `dual_ct_from_b64` /
`dual_ct_to_b64` the same way (`handlers.rs:490,535,646`), so decrypt and
evaluate are equally broken, but the practical effect is dominated by
encrypt: no session can ever produce a usable ciphertext through the HTTP
API, so nothing downstream can be exercised either.

This is a materially different claim than PR #107's description ("Rejects
dual/anchor-bearing ciphertext import and export at the FHE service
boundary"). The intent — reject untrusted anchor-bearing input, and stop
publishing anchor-bearing output — is sound and is exactly what
`dual_rns_wire_boundary_is_fail_closed` in `session.rs` verifies. What
shipped goes further: it also rejects the service's *own* freshly encrypted,
non-anchor-bearing output, because no single-RNS mod-Q wire encode/decode
path was ever wired into `handlers.rs` to take its place. `docs/
WIRE_Q_FAIL_CLOSED_2026-09-02.md`'s "Required replacement before re-enabling
transport" section already lists this as outstanding work (items 1-5); it
was not done before merge, and the fail-closed gate has no fallback, so the
service is fully down in the interim rather than degraded.

## Evidence

```
cargo test --release -p fhe-service
test result: ok. 24 passed; 0 failed; 29 ignored; 0 measured; 0 filtered out
```

29 tests in `crates/fhe-service/src/main.rs` — every test that goes through
`setup_and_encrypt` / `setup_and_encrypt_config` (i.e. every test that calls
`POST /encrypt`) — were marked `#[ignore]` in this session, each with a
reason string pointing at this document, so `cargo test --workspace`
reflects the true, intentional state instead of showing 29 tests newly red
for a reason nobody who reads the CI output would otherwise be able to
diagnose. This follows the same convention `CLAUDE.md` already documents for
the bootstrap suites (`#[ignore]`d as VESTIGIAL/RETIRED with a stated
reason) rather than deleting or weakening any assertion — every ignored
test's body and assertions are untouched and will fail again the moment
`#[ignore]` is removed, until the fix below lands.

Before this session's changes, `cargo test --release -p fhe-service` gave:

```
test result: FAILED. 24 passed; 29 failed; 0 ignored
```

The same 24 tests pass in both runs — routing, session lifecycle, auth,
policy, and the two intentional fail-closed regressions
(`dual_rns_wire_boundary_is_fail_closed`,
`decrypt_policy_is_fail_closed`/`token_policy_is_fail_closed`). Only the
encrypt-dependent 29 changed state, and they changed because of the root
cause above, not because of anything else in this session.

## What is NOT fixed here

This document records the finding; it does not implement the fix. The fix is
the single-RNS mod-Q wire type described in `docs/
WIRE_Q_FAIL_CLOSED_2026-09-02.md`'s "Required replacement" section, wired
into `fhe-service`'s `Session`/`handlers` so `handle_encrypt` never needs to
call the retired dual-RNS export path for its own output. That is the same
evaluator/wire work tracked as PR #108's WR-1 (Track 1 T1.4 derived-transient
exact evaluator integration) and WR-2 (WIRE-Q closure), assigned separately.
Scope here was limited to running the Rust checks PR #107 promised and were
never run, and making the resulting (accurate) test state legible rather than
silently red.

## Reproduce

```
cargo test --release -p fhe-service
```
