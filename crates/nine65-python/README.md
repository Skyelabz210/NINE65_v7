# nine65-python

Python bindings (via [PyO3](https://pyo3.rs)) for `nine65`, the exact-integer
BFV/DualRNS FHE library at the root of this repository. This crate exposes
NINE65's key generation, encrypt, decrypt, add, and (scalar) multiply
operations to Python: no floating-point arithmetic, and no precision loss
introduced by crossing the FFI boundary itself -- every value crossing that
boundary is checked (see "Integer widths" below), and every operation this
README recommends is covered by a real, passing, exact-equality pytest
assertion against the compiled extension. Ciphertext x ciphertext
multiplication is also bound (`mul()`) but is currently NOT correct for any
config checked -- read "Known limitations" before reaching for it; this is
a `nine65` core-arithmetic issue found and verified while doing this work,
not an FFI-layer one.

This is a *binding*, not a reimplementation: every operation below calls
straight into the same Rust code path exercised by the crate's own test
suite (`cargo test -p nine65`). It inherits that code's guarantees and its
limits alike -- in particular, **finite multiplicative depth** (see the
repository root `README.md` and `docs/CLAIM_SURFACE_AND_LIMITS_*.md`). This
package does not itself track leveled-depth budgets for you; if you chain
more multiplications than the config's noise budget supports, decryption
will return a wrong plaintext rather than raise an error (the same behavior
`nine65`'s own untracked `BFVEvaluator::mul` has in Rust -- use
`TrackedEvaluator` on the Rust side if you need depth accounting; it is not
currently exposed to Python).

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
   workspace root also means this crate's release profile is no longer the
   parent workspace's `panic = "abort"` (see "Panics cross the FFI boundary
   as `ValueError`, not a process abort" below) -- it uses Rust's normal
   `panic = "unwind"` default, which `std::panic::catch_unwind` in
   `src/lib.rs` depends on.

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

`fhe.mul(ct_a, ct_b)` (ciphertext x ciphertext) also exists and is callable
-- but **read "Known limitations" below before using it**: it does not
currently return correct results for `secure_128` / `secure_192` /
`secure_256`, or for any other config this was checked against. This is a
`nine65` core-arithmetic issue, verified independently of Python, not
something introduced by this quickstart or by the binding.

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

Found while verifying this binding's round-trip correctness (the actual
point of this exercise) -- both reproduced directly against `nine65`'s Rust
API with no PyO3 or Python involved, so neither is an FFI-boundary defect.
Both are exercised from Python in `tests/test_known_limitations.py`, marked
`xfail(strict=True)` so CI shows them as an acknowledged, tracked gap
instead of a silent false claim of correctness or an unexplained red X.

### 1. Ciphertext x ciphertext multiplication (`mul()`) does not work

`FHEContext.mul()` wraps `nine65::ops::BFVEvaluator::mul()` -- the
already-`#[deprecated]` single-modulus ct x ct path (tensor product,
relinearize, rescale). Its Rust doc says it "only works when `Δ² ≤ Q`" and
recommends `RNSFHEContext::mul_dual_symmetric()` instead. That capacity
bound is real and is exposed here as `mul_capacity()` -- but it turned out
not to be the binding constraint: **every case checked came back wrong,
including the simplest possible one, `1 * 1`**, which is trivially within
every tested config's `mul_capacity()`. Checked directly in Rust (no PyO3):
`SecureConfig::secure_128()` (n=8192) and, at n=1024, `light_mul_insecure`,
`light_insecure`, and `SecureConfig::test_fast_insecure()` -- all wrong,
every time.

This appears to have gone unnoticed because none of `nine65`'s own passing
`#[test]`s actually exercise this function with a real assertion on the
decrypted result:

- `test_homomorphic_mul_with_relin` and `test_ct_mul_multiple_values`
  (names that read as if they cover exactly this) both construct a
  `BFVEvaluator` *with* an eval key, but then call `mul_no_relin()` +
  `decrypt_degree2()` -- bypassing relinearize/rescale (and the eval key)
  entirely.
- `test_homomorphic_mul_diagnostic` does call `mul()`, but only prints a
  `[FAIL]`/`[OK]` diagnosis line for a human to read; it asserts nothing
  about the actual result.

**Until this is fixed upstream in `nine65`, do not rely on `mul()`'s
output for anything.** `mul_plain()` (ciphertext x a *known* plaintext
scalar -- verified exact by `tests/test_homomorphic.py`) is the safe
alternative wherever the multiplier isn't itself encrypted. This binding
still exposes `mul()` faithfully rather than hiding it -- disabling
existing bound functionality based on this change's own risk judgment
would be a policy call outside its mandate to expose, not redesign, the
underlying crate -- but every doc comment on it says this plainly (see
`src/lib.rs`).

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

`tests/conftest.py`'s `SAFE_MAX = 4000` keeps the rest of this suite's
correctness assertions comfortably inside the verified-safe range so they
aren't flaky against an edge that shifts slightly by key. If you need the
full plaintext range `[0, t)` to round-trip exactly, this single-modulus
path is not yet the right tool -- `nine65` has the machinery to do this
correctly (`params::exact_params::ExactDelta`, and the DualRNS/K-Elimination
stack generally), but it isn't what this simple encode/decode path uses,
and rewiring this binding onto that stack is out of scope for this change
(see "What's exposed" below).

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

## Panics cross the FFI boundary as `ValueError`, not a process abort

`FHEContext.mul()` wraps the underlying multiplication in
`std::panic::catch_unwind` and converts any internal panic into a Python
`ValueError` rather than letting it unwind into (and crash) the Python
interpreter. This only works because this crate's release profile uses
Rust's default `panic = "unwind"` -- see "Why this is excluded from the
workspace" above for why that's true here even though the main workspace's
`[profile.release]` sets `panic = "abort"`.

## Running the tests

```bash
maturin develop --release        # build + install into the active venv
pytest crates/nine65-python/tests -v
```

The suite covers: encrypt/decrypt round-trips (seeded and OS-CSPRNG-backed,
across all three named configs), homomorphic add / add_plain / mul_plain
with exact-value assertions, batch encrypt/decrypt, ciphertext/key byte
serialization round-trips (both "decrypts correctly" and "bytes are
byte-identical after a round trip"), out-of-bounds plaintext rejection, the
integer-width boundary cases described below, and the two known limitations
above (as `xfail(strict=True)`, so they read as understood-and-tracked, not
silently passing or mysteriously red). All of it runs against the real
compiled extension -- these are not mocks of the Rust layer. Expect
`75 passed, 2 xfailed`.

## What's exposed

| Python | Wraps (Rust) |
|---|---|
| `FHEConfig` | `nine65::params::FHEConfig` (`standard_128`, `high_192`, `large_single`) |
| `SecureConfig` | `nine65::params::secure_configs::SecureConfig` (`secure_128`, `secure_192`, `secure_256`) |
| `FHEContext` | Bundles the NTT engine + encoder for a config; `encrypt`/`decrypt`/`add`/`add_plain`/`mul_plain` (all verified exact) and `mul`/`mul_capacity` (ciphertext x ciphertext -- see "Known limitations") live here |
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
