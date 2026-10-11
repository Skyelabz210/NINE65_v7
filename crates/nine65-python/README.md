# nine65-python

Python bindings (via [PyO3](https://pyo3.rs)) for `nine65`, the exact-integer
BFV/DualRNS FHE library at the root of this repository. This crate exposes
NINE65's key generation, encrypt, decrypt, add, and (scalar) multiply
operations to Python: no floating-point arithmetic, and no precision loss
introduced by crossing the FFI boundary itself -- every value crossing that
boundary is checked (see "Integer widths" below), and every operation this
README recommends is covered by a real, passing, exact-equality pytest
assertion against the compiled extension. Ciphertext x ciphertext
multiplication remains present at the Python API boundary for compatibility,
but it is **retired and fail-closed**: `mul()` raises `ValueError` and
returns no ciphertext. See "Known limitations" for the disposition and the
DualRNS route that replaces the historical single-modulus path.

This is a *binding*, not a reimplementation: every operation below calls
straight into the same Rust code path exercised by the crate's own test
suite (`cargo test -p nine65`). It inherits that code's guarantees and its
limits alike -- in particular, **finite multiplicative depth** (see the
repository root `README.md` and `docs/CLAIM_SURFACE_AND_LIMITS_*.md`). This
package does not itself expose the Rust DualRNS ct×ct evaluator or its
leveled-depth budget tracking. The retired single-modulus `mul()` boundary
fails closed rather than returning a ciphertext. Use the Rust DualRNS and
`TrackedEvaluator` surfaces when ct×ct depth accounting is required; they
are not currently exposed to Python.

## Status

Experimental. The crate is intentionally excluded from the main Cargo
workspace (`crates/nine65-python` is in `[workspace] exclude` at the
repository root) because it is a `cdylib` built by `maturin`, not by
`cargo build --workspace` -- see "Why this is excluded from the workspace"
below. **Not published to PyPI.** Build and install it locally as described
here.

## Requirements

- Rust (matching the toolchain used by the rest of the repository) and
  `cargo`.
- Python >= 3.9.
- [`maturin`](https://www.maturin.rs/) >= 1.7, < 2.

```bash
python3 -m venv .venv
. .venv/bin/activate            # or the Windows equivalent
pip install "maturin>=1.7,<2" pytest
```

## Building

From this directory (`crates/nine65-python`):

```bash
# Build the extension and install it into the active virtualenv:
maturin develop --release

# Or produce a wheel without installing it:
maturin build --release
# -> target/wheels/nine65_python-*.whl
```

`maturin develop` (without `--release`) also works and is faster to
iterate with, but debug builds of `nine65` are dramatically slower --
multiplication in particular is O(N log N) per-lane NTT work that release's
`lto = "fat"` optimization matters a lot for. Use `--release` for anything
beyond a quick smoke test.

### Why this is excluded from the workspace

Two independent reasons:

1. **Build shape.** `cargo build --workspace` builds `rlib`/binary targets
   for a fixed host toolchain; `maturin` builds a `cdylib` against a
   specific Python interpreter's ABI and packages it as a wheel. Mixing the
   two into one `cargo build --workspace` invocation buys nothing --
   nobody runs `cargo build --workspace` to get a Python wheel -- and would
   force every contributor building the *Rust* workspace to also have a
   Python toolchain available.
2. **Workspace-inheritance vs. standalone builds.** This crate now declares
   its own empty `[workspace]` table in `Cargo.toml` specifically so that
   `maturin`, which invokes `cargo` rooted at *this* directory, can resolve
   it as a standalone crate. Before that fix, `version.workspace = true` /
   `edition.workspace = true` / `authors.workspace = true` in this crate's
   `Cargo.toml` required the crate to be an actual member of some workspace
   to inherit those fields from -- but this crate is simultaneously listed
   in the root `Cargo.toml`'s `[workspace] exclude`, so it wasn't a member
   of *that* workspace either. Building it standalone (`cd
   crates/nine65-python && cargo build`, which is what a bare `maturin
   build` does before the `[workspace]` fix) failed with `error: current
   package believes it's in a workspace when it's not`. Being its own
   workspace root also means this crate owns its standalone release profile
   instead of inheriting the parent workspace profile.

## Quickstart

```python
import nine65_python as n65

# One-call convenience: build a context for a named production security
# config and generate a fresh keyset for it.
fhe = n65.Nine65.build("secure_128")   # or "secure_192" / "secure_256"

ct_a = fhe.encrypt(6)
ct_b = fhe.encrypt(7)

ct_sum = fhe.add(ct_a, ct_b)            # ciphertext + ciphertext
ct_scaled = fhe.mul_plain(ct_b, 6)      # ciphertext x KNOWN plaintext scalar

assert fhe.decrypt(ct_sum) == 13
assert fhe.decrypt(ct_scaled) == 42
```

`fhe.mul(ct_a, ct_b)` (ciphertext x ciphertext) is intentionally
fail-closed. It raises `ValueError` and produces no ciphertext because the
historical single-modulus `BFVEvaluator::mul` route was retired under
issue #135. The Rust DualRNS multiplication routes remain the supported
ct×ct direction and are not yet bound into this Python surface.

The lower-level API this wraps is available directly too, if you want
explicit control over keys (e.g. to serialize a public key to a different
process, or keep the secret key out of the object doing the encrypting):

```python
import nine65_python as n65

config = n65.SecureConfig.secure_128()
ctx = n65.FHEContext.from_secure_config(config)

keys = ctx.generate_keyset_secure()    # OS CSPRNG -- use this for anything
                                        # that isn't a reproducible test
ct = ctx.encrypt(123, keys.public_key)
assert ctx.decrypt(ct, keys.secret_key) == 123

# Homomorphic ops that do NOT go through relinearize/rescale -- verified
# exact by tests/test_homomorphic.py:
ct2 = ctx.encrypt(7, keys.public_key)
assert ctx.decrypt(ctx.add(ct, ct2), keys.secret_key) == 130
assert ctx.decrypt(ctx.mul_plain(ct2, 6), keys.secret_key) == 42

# Serialize a ciphertext (bincode-encoded) to move it between processes:
blob = ct.to_bytes()
ct_restored = n65.Ciphertext.from_bytes(blob)
assert ctx.decrypt(ct_restored, keys.secret_key) == 123

# Batch operations, useful when encrypting/decrypting many plaintexts at once:
values = list(range(10))
cts = ctx.batch_encrypt(values, keys.public_key)
assert ctx.batch_decrypt(cts, keys.secret_key) == values
```

### Deterministic (seeded) operations -- tests and benchmarks only

`generate_keyset_seeded(seed)` and `encrypt_seeded(value, public_key, seed)`
derive their randomness entirely from `seed`: the same seed always produces
the same keys/ciphertext. This is invaluable for reproducible tests and
benchmarks, and actively dangerous for anything holding real data --
`nine65_python.generate_keypair(ctx, seed=...)` and the plain
`ctx.generate_keyset_secure()` / `ctx.encrypt(...)` methods exist
specifically so the non-seeded, OS-CSPRNG-backed path is the one that reads
as the default choice.

## Known limitations

Found while verifying this binding's round-trip correctness. Both findings
were reproduced directly against `nine65`'s Rust API with no PyO3 or Python
involved, so neither is an FFI-boundary defect. The retired multiplication
route is now covered by a passing refusal test. The near-`t` decode defect
remains open and is the single `xfail(strict=True)` in
`tests/test_known_limitations.py`.

### 1. Ciphertext x ciphertext multiplication (`mul()`) is retired

Issue #135 established that the historical single-modulus
`BFVEvaluator::mul()` route could return a plausible ciphertext decrypting
to the wrong plaintext, including the `1 * 1` case. That route is now
retired and fail-closed in Rust, and the Python boundary mirrors the same
disposition: `FHEContext.mul()` raises `ValueError` and returns no
ciphertext.

The Rust tests that previously had misleading names have also been made
explicit: `test_degree2_mul_multiple_values` and
`test_degree2_mul_without_relinearization` exercise the raw tensor product
with the degree-2 decrypt oracle. They do not claim to cover
relinearization/rescaling.

`mul_plain()` remains available for a known plaintext scalar. For encrypted
ct×ct multiplication, the supported architectural direction is the
multi-lane DualRNS/K-Elimination path, such as
`RNSFHEContext::mul_dual_symmetric()`; that surface is not yet bound to
Python.

### 2. Plaintext values near the modulus don't round-trip through plain encrypt/decrypt either

Separately from (1), and with no multiplication involved at all:
`BFVEncoder::decode()`'s `round(t * c / q) mod t` formula has a real,
*noise-free* bias for the specific `(q, t)` pair every `SecureConfig` this
crate exposes reduces to through this single-modulus path (`q = 998244353`,
`t = 65537`; see `test_config.py`'s
`test_secure_128_192_256_share_the_single_modulus_qt_pair`). `q mod t` is
`50306`, not `0`, so `t * floor(q/t) != q`, and the rounding error grows
with the plaintext value. Reproduced with the formula alone (no encryption):
decoding first disagrees with the original value at `m = 9922`. Encryption
noise eats further into the margin -- empirically, values up to `9000`
round-tripped cleanly over 300 trials across 10 independently generated
keysets, while values near `t` (e.g. `t - 1`) failed consistently, by a
small (single-digit), always-*downward* drift rather than random
corruption (see `test_plaintext_near_modulus_bias_is_directional_not_random`).

`tests/conftest.py`'s `SAFE_MAX = 4000` is a test-fixture guardrail, not a
production theorem or API guarantee. The full-range exactness defect is
tracked in **issue #176**. That issue requires either an exact-integer
full-range encoding/decoding route, using the repository's ExactDelta or
equivalent proven machinery, or a mathematically derived typed refusal
boundary. Empirical cutoffs and floating-point patches are explicitly
insufficient.

## Integer widths: Python ints vs. Rust `u64`

Plaintext values, seeds, and scalar multipliers all cross the FFI boundary
as Rust `u64`. Python integers are arbitrary-precision, so PyO3 performs a
checked conversion at the boundary on every call:

- A value that doesn't fit in `u64` (negative, or `>= 2**64`) raises
  **`OverflowError`** before any Rust code runs -- it never gets truncated
  or wrapped.
- A value that *does* fit in `u64` but is out of range for the operation
  (e.g. `encrypt(value, ...)` with `value >= plaintext_modulus()`) raises
  **`ValueError`** from `nine65`'s own bounds check
  (`BFVEncoder::try_encode`), surfaced through the binding's
  `Nine65Error -> ValueError` mapping.
- `to_bytes()` / `from_bytes()` round-trip ciphertexts, public keys, and
  evaluation keys through `bincode`, exactly, with no coefficient touched
  by anything that could introduce drift (no floats anywhere in this path).

`tests/test_boundary.py` in this crate exercises exactly these edges
(negative, `2**64`, `2**64 - 1`, `plaintext_modulus() - 1`, and the largest
plaintext value the active config accepts) so a regression here -- silent
truncation, a wraparound, an unchecked cast -- fails loudly in CI rather
than showing up as a wrong decryption downstream.

## Running the tests

```bash
maturin develop --release        # build + install into the active venv
pytest crates/nine65-python/tests -v
```

The suite covers: encrypt/decrypt round-trips (seeded and OS-CSPRNG-backed,
across all three named configs), homomorphic add / add_plain / mul_plain
with exact-value assertions, batch encrypt/decrypt, ciphertext/key byte
serialization round-trips, out-of-bounds plaintext rejection, the
integer-width boundary cases described below, a passing fail-closed ct×ct
multiplication refusal test, and the open near-`t` decode limitation as
`xfail(strict=True)`. All of it runs against the real compiled extension;
these are not mocks of the Rust layer. Release evidence should record the
discovered test count from the actual run rather than a hard-coded total.

## What's exposed

| Python | Wraps (Rust) |
|---|---|
| `FHEConfig` | `nine65::params::FHEConfig` (`standard_128`, `high_192`, `large_single`) |
| `SecureConfig` | `nine65::params::secure_configs::SecureConfig` (`secure_128`, `secure_192`, `secure_256`) |
| `FHEContext` | Bundles the NTT engine + encoder for a config; `encrypt`/`decrypt`/`add`/`add_plain`/`mul_plain` live here. `mul` remains as a fail-closed compatibility boundary; `mul_capacity` is historical single-modulus metadata, not permission to use the retired route. |
| `KeySet`, `PublicKey`, `SecretKey`, `EvaluationKey` | `nine65::keys::*` |
| `Ciphertext` | `nine65::ops::Ciphertext` |
| `Nine65` (pure Python, in `__init__.py`) | Convenience facade bundling one `FHEContext` + `KeySet` |
| `context_for`, `generate_keypair` (pure Python) | Named-config lookup and one-line key generation |

Not currently exposed (available on the Rust side, could be added later if
needed): `TrackedEvaluator`/`NoiseBudget` depth accounting, the DualRNS
multi-lane path (`RNSFHEContext`), and any of the three bootstrap/refresh
paths (`bootstrap()`, `bootstrap_with_ksk()`, `AutoBootstrapEvaluator`) --
per the repository root `README.md`/`CLAUDE.md`, none of those paths'
round-trip test suites currently run even on the Rust side, so binding them
to Python is deliberately out of scope until that's resolved upstream.

## Publishing

**Not done, and not attempted by this change.** Publishing to PyPI (even
the test index) is a real, effectively-irreversible, publicly-visible
action that requires credentials this change does not have and authority
this change does not carry. What *is* verified: the package builds cleanly
with `maturin build --release`, installs with `maturin develop --release`,
and the full pytest suite passes against the installed extension. A human
with PyPI publishing authority for this project can take it from there --
typically `maturin publish --repository testpypi` first, then, once that's
been smoke-tested, a real release.
