# Bounded arithmetic fuzzing

Use the CI-pinned `nightly-2025-08-04` toolchain and `cargo-fuzz 0.13.2`.
The seeded encrypt/decrypt and homomorphic targets intentionally use
`ShadowHarvester` so failures reproduce from the saved input. They are research
arithmetic fixtures, not production-security tests.

Run these targets in the optimized development profile:

```sh
cargo +nightly-2025-08-04 fuzz run fuzz_encrypt_decrypt --dev -- -max_total_time=60
cargo +nightly-2025-08-04 fuzz run fuzz_homomorphic --dev -- -max_total_time=60
```

`fuzz/Cargo.toml` sets development optimization to level 3, retaining debug
assertions and overflow checks. The same command works for the other three
fuzz targets. AddressSanitizer and libFuzzer coverage remain enabled.

Do not pass `--release` alone to seeded targets: it disables the debug assertions
that distinguish research builds, so the library correctly rejects deterministic
key generation/encryption. The targets reject that configuration at compile
time rather than crashing before testing any arithmetic. Do not weaken the
library's entropy guards or label an optimized research build as a production
release test.

The release refusal boundary is tested separately by
`crates/nine65/tests/native_key_entropy.rs` with no `allow_insecure` feature.
A bounded fuzz pass is smoke coverage, not an exhaustive fuzz campaign.
