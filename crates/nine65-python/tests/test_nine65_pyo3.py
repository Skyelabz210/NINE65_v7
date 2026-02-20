"""
PyO3 binding tests for nine65_python.

Run with:
pytest -q crates/nine65-python/tests/test_nine65_pyo3.py
"""

import pytest

from nine65_python import SecureConfig, FHEContext


def build_context():
    cfg = SecureConfig.secure_128()
    return FHEContext.from_secure_config(cfg)


def test_encrypt_decrypt_seeded_roundtrip():
    ctx = build_context()
    keys = ctx.generate_keyset_seeded(42)
    ct = ctx.encrypt_seeded(123, keys.public_key, 7)
    assert ctx.decrypt(ct, keys.secret_key) == 123


def test_encrypt_decrypt_secure_roundtrip():
    ctx = build_context()
    keys = ctx.generate_keyset_secure()
    ct = ctx.encrypt(77, keys.public_key)
    assert ctx.decrypt(ct, keys.secret_key) == 77


def test_out_of_bounds_rejected():
    ctx = build_context()
    keys = ctx.generate_keyset_seeded(1)
    too_big = ctx.plaintext_modulus()
    with pytest.raises(ValueError):
        ctx.encrypt_seeded(too_big, keys.public_key, 9)


def test_batch_encrypt_decrypt():
    ctx = build_context()
    keys = ctx.generate_keyset_seeded(99)
    values = list(range(10))
    cts = ctx.batch_encrypt(values, keys.public_key)
    decrypted = ctx.batch_decrypt(cts, keys.secret_key)
    assert decrypted == values


def test_ciphertext_bytes_roundtrip():
    ctx = build_context()
    keys = ctx.generate_keyset_seeded(3)
    ct = ctx.encrypt_seeded(55, keys.public_key, 11)
    blob = ct.to_bytes()
    ct2 = type(ct).from_bytes(blob)
    assert ctx.decrypt(ct2, keys.secret_key) == 55
