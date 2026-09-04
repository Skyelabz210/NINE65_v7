"""The pure-Python `Nine65` facade and its helper functions
(`python/nine65_python/__init__.py`) -- not the raw PyO3 bindings directly."""

from __future__ import annotations

import pytest

import nine65_python as n65


def test_build_seeded_is_reproducible() -> None:
    fhe_a = n65.Nine65.build("secure_128", seed=123)
    fhe_b = n65.Nine65.build("secure_128", seed=123)

    ct = fhe_a.context.encrypt_seeded(9, fhe_a.keys.public_key, seed=1)
    ct2 = fhe_b.context.encrypt_seeded(9, fhe_b.keys.public_key, seed=1)
    assert ct.to_bytes() == ct2.to_bytes()


def test_build_default_uses_secure_128() -> None:
    fhe = n65.Nine65.build()
    assert fhe.context.name() == "secure_128"


def test_build_rejects_unknown_config_name() -> None:
    with pytest.raises(ValueError):
        n65.Nine65.build("secure_64")


def test_facade_roundtrip(fhe_128: "n65.Nine65") -> None:
    for value in (0, 1, 42, 1000):
        ct = fhe_128.encrypt(value)
        assert fhe_128.decrypt(ct) == value


def test_facade_mul_capacity_delegates_to_context(fhe_128: "n65.Nine65") -> None:
    assert fhe_128.mul_capacity() == fhe_128.context.mul_capacity()


def test_facade_holds_independent_state_per_instance() -> None:
    fhe_a = n65.Nine65.build("secure_128", seed=1)
    fhe_b = n65.Nine65.build("secure_128", seed=2)
    ct = fhe_a.encrypt(123)
    # fhe_b's secret key is unrelated to fhe_a's -- decrypting fhe_a's
    # ciphertext under fhe_b must not recover the plaintext.
    assert fhe_b.decrypt(ct) != 123
    assert fhe_a.decrypt(ct) == 123
