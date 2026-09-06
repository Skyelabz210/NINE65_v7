"""Known, tracked correctness limitations -- found while verifying this
crate's FFI boundary, reproduced here from Python, and marked
`xfail(strict=True)` so they show up in CI as an acknowledged, understood
gap rather than either a mysterious red failure or a silent false claim of
correctness.

`strict=True` means: if either of these ever unexpectedly starts
*passing*, pytest reports that as a failure too. That is deliberate -- an
unexpected pass here means the underlying `nine65` bug was fixed, and this
file (plus README.md "Known limitations" and the doc comments in
src/lib.rs) needs updating, not that the test was wrong to have existed.

Both issues below were verified to originate in `nine65` core, not in this
crate's PyO3 bindings: reproduced directly against `nine65::ops::*` in plain
Rust, with no PyO3 or Python involved at all (see the doc comment on
`FHEContext.mul()` in src/lib.rs and the `conftest.py` header for the
reproduction each is based on).
"""

from __future__ import annotations

import pytest

import nine65_python as n65


@pytest.mark.xfail(
    strict=True,
    reason=(
        "BFVEvaluator::mul() (the deprecated single-modulus ct x ct path "
        "this binding's FHEContext.mul() wraps) returns a wrong plaintext "
        "for every case checked, including the most trivial one (1 * 1), "
        "for every SecureConfig this crate exposes. This is NOT the "
        "documented 'Delta^2 <= Q' capacity limit (1*1 is trivially within "
        "it) -- it reproduces in plain Rust with no PyO3/Python involved. "
        "See src/lib.rs FHEContext.mul() doc and README.md 'Known "
        "limitations'."
    ),
)
def test_ciphertext_times_ciphertext_multiplication_is_currently_broken() -> None:
    fhe = n65.Nine65.build("secure_128", seed=1)
    ct_a = fhe.encrypt(1)
    ct_b = fhe.encrypt(1)
    product = fhe.mul(ct_a, ct_b)
    # This is the simplest possible ct x ct case: 1 * 1 = 1, well within
    # mul_capacity()'s max_product bound. It still comes back wrong.
    assert fhe.decrypt(product) == 1


@pytest.mark.xfail(
    strict=True,
    reason=(
        "BFVEncoder::decode()'s round(t*c/q) formula has a real, "
        "deterministic (noise-free) bias for the (q, t) pair every "
        "SecureConfig this crate exposes reduces to through this "
        "single-modulus path: q mod t != 0, so t*floor(q/t) != q, and the "
        "rounding error grows with the plaintext value. Values near t "
        "(such as t - 1) do not round-trip. See conftest.py SAFE_MAX for "
        "the measured safe range and README.md 'Known limitations'."
    ),
)
def test_plaintext_near_modulus_does_not_roundtrip(
    ctx_128: n65.FHEContext, keys_128: n65.KeySet
) -> None:
    t = ctx_128.plaintext_modulus()
    value = t - 1
    ct = ctx_128.encrypt_seeded(value, keys_128.public_key, seed=1)
    assert ctx_128.decrypt(ct, keys_128.secret_key) == value


def test_plaintext_near_modulus_bias_is_directional_not_random(
    ctx_128: n65.FHEContext, keys_128: n65.KeySet
) -> None:
    """Not xfail: this one documents the SHAPE of the bug (a small,
    consistent downward drift, not wild/random corruption), which is what
    lets `test_encrypt_decrypt.py` trust the well-inside-the-safe-range
    values it actually asserts on. If this ever starts failing, the bias
    has changed character and SAFE_MAX may need re-measuring, not just the
    xfail above."""
    t = ctx_128.plaintext_modulus()
    value = t - 1
    got_values = set()
    for seed in range(10):
        ct = ctx_128.encrypt_seeded(value, keys_128.public_key, seed=seed)
        got_values.add(ctx_128.decrypt(ct, keys_128.secret_key))

    assert value not in got_values
    # The observed drift is small (a handful of units) and always downward,
    # not an arbitrary/high-magnitude value -- consistent with a rounding
    # bias rather than, say, noise overflow wrapping around the whole ring.
    for got in got_values:
        assert 0 <= value - got <= 10
