"""Known limitations of this binding.

`FHEContext.mul()` is retired (#135): it raises `ValueError` and returns
no ciphertext. The decode bias for plaintexts near `t` is still open and
stays `xfail(strict=True)`.
"""

from __future__ import annotations

import pytest

import nine65_python as n65


def test_ciphertext_times_ciphertext_multiplication_is_refused() -> None:
    fhe = n65.Nine65.build("secure_128", seed=1)
    ct_a = fhe.encrypt(1)
    ct_b = fhe.encrypt(1)
    with pytest.raises(ValueError, match="#135"):
        fhe.mul(ct_a, ct_b)


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
