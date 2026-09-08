"""Byte serialization round-trips (`to_bytes()` / `from_bytes()`).

These go through `bincode` on the Rust side (see src/lib.rs) with no
floating point anywhere in the path, so a round trip through bytes should
reproduce the exact original value bit-for-bit -- verified here by checking
both that decryption still gives the right plaintext AND that the raw bytes
themselves are byte-identical before/after the round trip.
"""

from __future__ import annotations

import nine65_python as n65


def test_ciphertext_bytes_roundtrip_preserves_bytes_and_plaintext(
    ctx_128: n65.FHEContext, keys_128: n65.KeySet
) -> None:
    ct = ctx_128.encrypt_seeded(3133, keys_128.public_key, seed=11)
    blob = ct.to_bytes()
    assert isinstance(blob, bytes)
    assert len(blob) > 0

    ct2 = n65.Ciphertext.from_bytes(blob)
    assert ct2.to_bytes() == blob  # byte-identical, not just "close"
    assert ctx_128.decrypt(ct2, keys_128.secret_key) == 3133


def test_public_key_bytes_roundtrip(ctx_128: n65.FHEContext, keys_128: n65.KeySet) -> None:
    blob = keys_128.public_key.to_bytes()
    pk2 = n65.PublicKey.from_bytes(blob)
    assert pk2.to_bytes() == blob

    # A ciphertext encrypted under the round-tripped public key must still
    # decrypt correctly under the original secret key -- proves the
    # deserialized key is functionally identical, not just structurally.
    ct = ctx_128.encrypt_seeded(2024, pk2, seed=4)
    assert ctx_128.decrypt(ct, keys_128.secret_key) == 2024


def test_evaluation_key_bytes_roundtrip(ctx_128: n65.FHEContext, keys_128: n65.KeySet) -> None:
    blob = keys_128.evaluation_key.to_bytes()
    ek2 = n65.EvaluationKey.from_bytes(blob)
    assert ek2.to_bytes() == blob


def test_different_ciphertexts_have_different_bytes(
    ctx_128: n65.FHEContext, keys_128: n65.KeySet
) -> None:
    ct_a = ctx_128.encrypt_seeded(1, keys_128.public_key, seed=1)
    ct_b = ctx_128.encrypt_seeded(2, keys_128.public_key, seed=1)
    assert ct_a.to_bytes() != ct_b.to_bytes()


def test_ciphertext_from_bytes_rejects_garbage() -> None:
    import pytest

    with pytest.raises(ValueError):
        n65.Ciphertext.from_bytes(b"not a valid bincode ciphertext")
