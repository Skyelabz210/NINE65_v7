# Native key and encryption entropy boundary

Date: 2026-11-10. Base: `7ada6503634a824e80bc4bcfd6231ad0178d7ed3`.
The results below execute this patch on that base before publication.
Toolchain: Rust/Cargo 1.89.0; binding checks use CPython 3.12.14 and the binding's
locked PyO3 0.28.3. Publication does not broaden the verified scope or establish
production admission.

## Reproduction and repair

The native single-modulus `SecretKey::generate`, `KeySet::generate`,
`PublicKey::generate` and `EvaluationKey::generate` sampled directly from
`ShadowHarvester` without applying the release RNG policy already used by
the RNS APIs. The direct and generic `BFVEncryptor` polynomial encryption
cores had the same omission. Their scalar/seeded wrappers inherited it.

On the base implementation plus the initial integration regression, the release
run reported **5 expected-refusal failures and 2 passing secure controls**:
all four key paths and the direct encryption path accepted deterministic
entropy. This is executable boundary evidence, not a complete security audit.

The patch applies the existing release RNG policy at all four key
constructors and both encryption cores, before sampling. A shared fallible
guard now returns the existing `Nine65Error::ConfigError` variant. Native
`try_encrypt`, `try_encrypt_seeded` and `try_encrypt_with_rng` return this error
instead of panicking on forbidden entropy. Additive `try_encrypt_poly` and
`try_encrypt_poly_with_rng` methods offer the same behavior for polynomials;
infallible wrappers retain their panic-on-error contract. It preserves native
signatures, secure implementations, seeded development behavior, and library
unit-test/KAT behavior. The release-discovered single-modulus arithmetic
fixture now uses secure keys/encryption instead of hiding behind a research
feature. The RNG panic message no longer recommends the forbidden combination
of a release library and `allow_insecure`.

Python's `generate_keyset_seeded` and `encrypt_seeded` now return `ValueError`
in release before calling native code. Development calls retain their prior
Python return types and deterministic behavior. Facade/helper calls inherit
the same policy. The existing seeded pytest suite is documented for development
builds; a separate dependency-free script checks actual release/development
extensions. WASM's already explicit `*_for_test` guards are unchanged.

## Executed verification

All commands run from the repository root unless indicated otherwise.

```sh
cargo test --locked --offline --release -p nine65 \
  --test native_key_entropy --test single_modulus_admission --no-fail-fast
# PASS: 7 entropy tests and 3 arithmetic tests, no ignored or filtered tests.

cargo test --locked --offline -p nine65 --test native_key_entropy --no-fail-fast
# PASS: 4 development tests, including seeded key/ciphertext compatibility.

cargo test --locked --offline -p nine65 --test native_key_entropy \
  --features allow_insecure --no-fail-fast
# PASS: 4 explicit research tests.

cargo test --locked --offline --release -p nine65 --lib --no-fail-fast -- \
  keys::tests ops::encrypt::tests kat::tests
# PASS: 36 existing tests; 1,317 unrelated tests filtered out.

cargo check --locked --offline --release -p nine65 --lib --features allow_insecure
# EXPECTED REFUSAL: exit 101, existing release compile_error for allow_insecure.

cargo fmt --all -- --check
cargo clippy --locked --offline -p nine65 --lib \
  --test native_key_entropy --test single_modulus_admission -- -D warnings
cargo clippy --locked --offline --release -p nine65 \
  --test native_key_entropy --test single_modulus_admission -- -D warnings
# PASS: formatting and focused development/release Clippy.

cargo build --locked --offline --release -p nine65 --lib
rustc --edition=2021 -C opt-level=2 -C panic=abort -C debug-assertions=no \
  -C lto=fat --extern nine65=target/release/libnine65.rlib \
  -L dependency=target/release/deps \
  crates/nine65/tests/fixtures/native_entropy_abort_probe.rs \
  -o /tmp/nine65-native-entropy-abort-probe
/tmp/nine65-native-entropy-abort-probe
# PASS: 5 typed entropy refusals, no consumed samples, then a secure round trip.
# This is a standalone panic=abort executable, not an unwinding test harness.
```

The standalone probe must link with LTO enabled to consume the workspace's
fat-LTO release library. An initial non-LTO linker attempt failed before
execution; the command above then linked and passed.

Separately in `crates/nine65-python`, both locked `cargo build --features python`
and `cargo build --release --features python` passed. The release build initially
needed its absent pinned dependencies fetched from crates.io; no lockfile
changes were required. Against each resulting shared library,
`tests/check_entropy_boundary.py --extension <built-library> --mode <mode>` passed:

- Release: four seeded raw/helper routes raise `ValueError`; two secure round trips.
- Research: four seeded routes succeed; keys and ciphertexts reproduce; secure controls pass.

The binding's `cargo fmt -- --check`, release Clippy with `-D warnings`, and
Python syntax compilation of the changed Python code also passed.

## Compatibility and limits

- Normal release callers that depended on seeded native keys or ciphertexts now
  fail closed. The named fallible single-modulus encryption methods return
  `ConfigError` for policy violations without unwinding. Existing infallible
  constructors/methods still panic, and `panic = "abort"` then terminates.
  Migrate to `try_generate_secure`, `try_encrypt_secure` or
  `try_encrypt_poly_secure` to handle failures. Python handles its two seeded
  entry points as ordinary `ValueError` instead.
- Out-of-range native `try_encrypt*` calls still return their input error before
  sampling. OS-backed APIs and generic encryption with `SecureRng` remain usable.
  Generic `FheRng` sampling is itself infallible, so only the direct secure
  fallible APIs also return OS entropy failures. This is not a claim that all
  malformed inputs or unrelated RNS/bootstrap APIs are panic-free.
- Research builds are not deployment builds. The policy uses the existing
  `cfg(test)`/debug-assertion/feature boundary, not a new type-level firewall.
  Custom `FheRng` implementations report their own `is_secure`; manually supplied
  key fields/polynomials are outside these constructors' guarantees.
- These were focused native and binding checks, not the full workspace suite,
  full Python pytest suite, WASM/FFI build matrix, timing audit, or production
  security review. No frozen evidence, public-refresh gates, or admission claims
  were changed.
