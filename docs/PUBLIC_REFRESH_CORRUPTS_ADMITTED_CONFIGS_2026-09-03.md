# Public refresh corrupts plaintext on configs CLAUDE.md lists as admitted

## Status: pre-existing, confirmed by bisection to predate PR #107/#99/#103. Not fixed here.

## What this is not

This is not caused by anything in this session's scope (verifying PR #107's
Rust checks, and PR #104). Bisected by running
`ops::bootstrap::tests::diag_measure_noise_growth` and the four
`ops::auto_bootstrap::tests::repeated_squaring_is_exact_under_auto_refresh_*`
/ `squaring_refresh_costs_exactly_one_bootstrap` tests in a worktree at
`f8fa50a` (the commit immediately before PR #107 merged, i.e. before #107,
#99, and #103 all three): all five already fail there, identically. They are
not new.

## What this is

`ops::bootstrap::tests::diag_measure_noise_growth`
(`crates/nine65/src/ops/bootstrap.rs:1612`) bypasses only the
`public_phase1_soundness_gate` ("Gate 0") to run the three actual refresh
phases and directly measure what they produce, independent of whether the
gate would have refused the call. Current measurement on `main`
(`2547cf0`):

```
config              lanes  headroom  required    admits |   refresh(7)     refresh(7)^2
secure_128              4        71        47      true | 65536 (WRONG)    40018 (WRONG)
secure_128_deep         4        71        47      true | 65536 (WRONG)    40018 (WRONG)
secure_192              5        96        49      true |   40 (WRONG)    40518 (WRONG)
```

("true" here is `supports_public_refresh(config)`, i.e. `secure_configs.rs`'s
own admission gate says these configs' chains have enough post-refresh
`Delta` headroom to carry a refresh.)

`CLAUDE.md`'s Bootstrap Paths section currently states, sourced to this same
test: "the refresh output still decrypts correctly, but the first multiply
after it returns a wrong-but-plausible plaintext (`refresh(7)` squares to
`34037`, not `49`)" for the *refused* configs (`secure_128`,
`hardware_opt`), with the clear implication that admitted configs
(`secure_128_deep`, `secure_192`, `secure_256`) do not have this problem —
that is the entire point of `ensure_public_refresh_supported` refusing
`secure_128`/`hardware_opt` while admitting the other three.

The current measurement contradicts that on two counts:

1. `refresh(7)` itself — not merely the subsequent multiply — is wrong
   (`65536`, `65536`, `40`, none of them `7`) for all three configs
   measured, including the two the table calls admitted
   (`secure_128_deep`, `secure_192`).
2. The panic this test hits is its own designed tripwire for exactly this:
   `secure_128: supports_public_refresh admits this config, but the
   decryption oracle says a public refresh corrupts it. The gate is
   admitting a corrupting path — fix the predicate, do not relax this
   assertion.` (`bootstrap.rs:1685`)

`secure_256` is not in this test's three-case table and was not measured
here.

The four `auto_bootstrap` tests fail for a different, already-tracked
reason: `AutoBootstrapEvaluator::mul_auto` triggers an actual (non-bypassed)
public refresh once the noise ledger crosses its threshold, and that refresh
goes through the real `public_phase1_soundness_gate`, which unconditionally
returns `Nine65Error::BootstrapFailed { reason: "public BFV refresh
disabled: Phase 1 does not yet propagate the secret-dependent displaced
quotient/carry through the CRAM Safe-Root/Lift state" }`. This is the
already-open issue #95 referenced in PR #108 ("current main still returns
typed `BootstrapFailed` from `public_phase1_soundness_gate()`") and tracked
there as WR-5A (`#82`, full-`Q_boot` uniform bootstrap mask sampling) / WR-5B
(`#83`, exact/non-tautological bootstrap security validation).

## Why this is left red rather than `#[ignore]`d

The `fhe-service` tests and the two `light_rns_insecure` smoke tests marked
`#[ignore]` in this session's other changes were ignored because their
*root cause is fully understood, has an explicit design intent, and is
already the documented state of the codebase* (the WIRE-Q wire-boundary
closure). This finding is different: it says a table in `CLAUDE.md` that
represents "admitted for public refresh" as a security/correctness claim is
currently wrong for at least two of the three configs it names, on a test
that already contains its own "do not relax this assertion" tripwire. That
deserves to stay loudly red and get an owner decision, not be quietly
filed away — especially since `supports_public_refresh` gates whether
`ops/bootstrap.rs`'s three refresh paths are reachable at all for these
configs (see `admissibility gate` in `CLAUDE.md`).

## What is not done here

No fix is attempted. This is a discovery note only, scoped to what running
the Rust checks PR #107 asked for actually turned up. The predicate fix the
test's own panic message asks for ("fix the predicate, do not relax this
assertion") is bootstrap-path work, not WIRE-Q wire-boundary or Track 2
CompareBit work, and belongs with whoever owns issue #95 / WR-5A / WR-5B.

## Reproduce

```
cargo test --release -p nine65 --lib -- ops::bootstrap::tests::diag_measure_noise_growth --nocapture
cargo test --release -p nine65 --lib -- ops::auto_bootstrap::tests::repeated_squaring_is_exact_under_auto_refresh_secure_128_deep ops::auto_bootstrap::tests::repeated_squaring_is_exact_under_auto_refresh_secure_192 ops::auto_bootstrap::tests::repeated_squaring_is_exact_under_auto_refresh_secure_256 ops::auto_bootstrap::tests::squaring_refresh_costs_exactly_one_bootstrap
```
