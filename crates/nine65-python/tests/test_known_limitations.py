"""Known limitations of this binding.

`FHEContext.mul()` is retired (#135): it raises `ValueError` and returns
no ciphertext. Full-range scalar encoding uses the repaired rational scale.
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


def test_plaintext_near_modulus_roundtrips(
    ctx_128: n65.FHEContext, keys_128: n65.KeySet
) -> None:
    t = ctx_128.plaintext_modulus()
    value = t - 1
    ct = ctx_128.encrypt_seeded(value, keys_128.public_key, seed=1)
    assert ctx_128.decrypt(ct, keys_128.secret_key) == value


@pytest.mark.parametrize("position", [0, 1, 32768, 59905, 65536])
def test_plaintext_full_range_samples_remain_exact_across_seeds(
    ctx_128: n65.FHEContext, keys_128: n65.KeySet, position: int
) -> None:
    """The old floor-Delta drift must not return at the middle or upper edge."""
    for seed in range(10):
        ct = ctx_128.encrypt_seeded(position, keys_128.public_key, seed=seed)
        assert ctx_128.decrypt(ct, keys_128.secret_key) == position
