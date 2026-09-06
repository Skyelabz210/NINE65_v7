"""Encrypt/decrypt round-trip correctness.

Covers both randomness sources (`encrypt_seeded` and OS-CSPRNG-backed
`encrypt`), multiple configs, the documented "safe zone" plaintext range
(see conftest.py), and batch encrypt/decrypt. Every assertion here is an
exact equality -- no tolerance, no "close enough": BFV over an integer
plaintext modulus has no reason to lose precision within its documented
range, and this suite exists specifically to catch it if it ever does.
"""

from __future__ import annotations

import pytest

import nine65_python as n65

from conftest import SAFE_MAX, KEY_SEED

SAFE_VALUES = [0, 1, 2, 41, 100, 999, 1000, 2718, SAFE_MAX]


@pytest.mark.parametrize("value", SAFE_VALUES)
def test_seeded_roundtrip(ctx_128: n65.FHEContext, keys_128: n65.KeySet, value: int) -> None:
    ct = ctx_128.encrypt_seeded(value, keys_128.public_key, seed=value + 1)
    assert ctx_128.decrypt(ct, keys_128.secret_key) == value


@pytest.mark.parametrize("value", [0, 1, 2, 500, SAFE_MAX])
def test_secure_rng_roundtrip(ctx_128: n65.FHEContext, keys_128: n65.KeySet, value: int) -> None:
    # OS-CSPRNG-backed encryption -- the path actually recommended for
    # anything that isn't a reproducible test (see README.md "Quickstart").
    ct = ctx_128.encrypt(value, keys_128.public_key)
    assert ctx_128.decrypt(ct, keys_128.secret_key) == value


def test_different_seeds_give_different_ciphertexts_but_same_plaintext(
    ctx_128: n65.FHEContext, keys_128: n65.KeySet
) -> None:
    value = 1234
    ct_a = ctx_128.encrypt_seeded(value, keys_128.public_key, seed=1)
    ct_b = ctx_128.encrypt_seeded(value, keys_128.public_key, seed=2)
    assert ct_a.to_bytes() != ct_b.to_bytes()  # IND-CPA-style randomization
    assert ctx_128.decrypt(ct_a, keys_128.secret_key) == value
    assert ctx_128.decrypt(ct_b, keys_128.secret_key) == value


def test_same_seed_is_deterministic(ctx_128: n65.FHEContext, keys_128: n65.KeySet) -> None:
    ct_a = ctx_128.encrypt_seeded(777, keys_128.public_key, seed=99)
    ct_b = ctx_128.encrypt_seeded(777, keys_128.public_key, seed=99)
    assert ct_a.to_bytes() == ct_b.to_bytes()


@pytest.mark.parametrize("config_name", ["secure_192", "secure_256"])
def test_roundtrip_on_other_named_configs(config_name: str) -> None:
    # secure_192 / secure_256 use larger N (16384) than secure_128 (8192);
    # a single representative value each is enough to confirm the binding
    # wiring works there too without inflating suite runtime (mul()-class
    # ops are not exercised here, only encrypt/decrypt).
    fhe = n65.Nine65.build(config_name, seed=KEY_SEED)
    for value in (0, 1, 500):
        ct = fhe.encrypt(value)
        assert fhe.decrypt(ct) == value


def test_out_of_bounds_message_rejected(ctx_128: n65.FHEContext, keys_128: n65.KeySet) -> None:
    t = ctx_128.plaintext_modulus()
    with pytest.raises(ValueError):
        ctx_128.encrypt_seeded(t, keys_128.public_key, seed=1)
    with pytest.raises(ValueError):
        ctx_128.encrypt(t, keys_128.public_key)


def test_batch_encrypt_decrypt_matches_values(ctx_128: n65.FHEContext, keys_128: n65.KeySet) -> None:
    values = list(range(0, 200, 7)) + [SAFE_MAX]
    cts = ctx_128.batch_encrypt(values, keys_128.public_key)
    assert len(cts) == len(values)
    decrypted = ctx_128.batch_decrypt(cts, keys_128.secret_key)
    assert decrypted == values


def test_batch_encrypt_decrypt_empty(ctx_128: n65.FHEContext, keys_128: n65.KeySet) -> None:
    assert ctx_128.batch_encrypt([], keys_128.public_key) == []
    assert ctx_128.batch_decrypt([], keys_128.secret_key) == []


def test_wrong_secret_key_does_not_recover_the_plaintext(ctx_128: n65.FHEContext) -> None:
    keys_a = ctx_128.generate_keyset_seeded(1)
    keys_b = ctx_128.generate_keyset_seeded(2)
    ct = ctx_128.encrypt_seeded(4242, keys_a.public_key, seed=3)
    # Decrypting under an unrelated secret key must not (even accidentally)
    # recover the original plaintext -- if it does, something is very wrong
    # with key separation.
    assert ctx_128.decrypt(ct, keys_b.secret_key) != 4242


def test_generate_keypair_helper_seeded_matches_context_method(ctx_128: n65.FHEContext) -> None:
    keys_helper = n65.generate_keypair(ctx_128, seed=KEY_SEED)
    keys_direct = ctx_128.generate_keyset_seeded(KEY_SEED)
    ct = ctx_128.encrypt_seeded(9, keys_helper.public_key, seed=1)
    assert ctx_128.decrypt(ct, keys_direct.secret_key) == 9


def test_generate_keypair_helper_secure_path_works(ctx_128: n65.FHEContext) -> None:
    keys = n65.generate_keypair(ctx_128)  # no seed -> OS CSPRNG path
    ct = ctx_128.encrypt(55, keys.public_key)
    assert ctx_128.decrypt(ct, keys.secret_key) == 55
