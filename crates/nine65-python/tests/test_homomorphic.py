"""Homomorphic operations that do NOT go through relinearize/rescale:
`add` (ciphertext + ciphertext), `add_plain`, and `mul_plain` (ciphertext x
plaintext scalar). All three are verified exact here.

Ciphertext x ciphertext multiplication (`mul()`) is deliberately NOT tested
for correctness in this file -- see `test_known_limitations.py` and
README.md "Known limitations" for why: it does not currently produce
correct results at all, for any config this suite could construct.
"""

from __future__ import annotations

import pytest

import nine65_python as n65

from conftest import SAFE_MAX


def test_add_matches_sum(ctx_128: n65.FHEContext, keys_128: n65.KeySet) -> None:
    for a, b in [(0, 0), (1, 1), (6, 7), (100, 250), (1000, 2000)]:
        ct_a = ctx_128.encrypt_seeded(a, keys_128.public_key, seed=a + 1)
        ct_b = ctx_128.encrypt_seeded(b, keys_128.public_key, seed=b + 2)
        ct_sum = ctx_128.add(ct_a, ct_b)
        assert ctx_128.decrypt(ct_sum, keys_128.secret_key) == a + b


def test_add_is_commutative(ctx_128: n65.FHEContext, keys_128: n65.KeySet) -> None:
    ct_a = ctx_128.encrypt_seeded(17, keys_128.public_key, seed=17)
    ct_b = ctx_128.encrypt_seeded(25, keys_128.public_key, seed=25)
    ab = ctx_128.decrypt(ctx_128.add(ct_a, ct_b), keys_128.secret_key)
    ba = ctx_128.decrypt(ctx_128.add(ct_b, ct_a), keys_128.secret_key)
    assert ab == ba == 42


def test_add_plain_matches_sum(ctx_128: n65.FHEContext, keys_128: n65.KeySet) -> None:
    for a, b in [(0, 0), (1, 1), (6, 7), (100, 250)]:
        ct = ctx_128.encrypt_seeded(a, keys_128.public_key, seed=a + 10)
        ct_sum = ctx_128.add_plain(ct, b)
        assert ctx_128.decrypt(ct_sum, keys_128.secret_key) == a + b


def test_add_plain_rejects_value_at_or_above_plaintext_modulus(
    ctx_128: n65.FHEContext, keys_128: n65.KeySet
) -> None:
    t = ctx_128.plaintext_modulus()
    ct = ctx_128.encrypt_seeded(0, keys_128.public_key, seed=1)
    with pytest.raises(ValueError):
        ctx_128.add_plain(ct, t)


@pytest.mark.parametrize(
    "value,scalar",
    [
        (0, 5),
        (1, 1),
        (6, 7),
        (100, 3),
        (7, 6),
        (SAFE_MAX, 1),
    ],
)
def test_mul_plain_matches_product(
    ctx_128: n65.FHEContext, keys_128: n65.KeySet, value: int, scalar: int
) -> None:
    # mul_plain is a raw scalar multiply (see its Rust doc: "Values >= t are
    # valid here"), so it is NOT subject to the ciphertext x ciphertext
    # mul_capacity() bound. Keep the *product* within the documented safe
    # decode range (SAFE_MAX) so this test isn't entangled with the separate
    # large-plaintext rounding bias covered in test_known_limitations.py.
    assert value * scalar <= SAFE_MAX
    ct = ctx_128.encrypt_seeded(value, keys_128.public_key, seed=value + scalar + 1)
    ct_scaled = ctx_128.mul_plain(ct, scalar)
    assert ctx_128.decrypt(ct_scaled, keys_128.secret_key) == value * scalar


def test_mul_plain_by_zero(ctx_128: n65.FHEContext, keys_128: n65.KeySet) -> None:
    ct = ctx_128.encrypt_seeded(999, keys_128.public_key, seed=5)
    ct_zero = ctx_128.mul_plain(ct, 0)
    assert ctx_128.decrypt(ct_zero, keys_128.secret_key) == 0


def test_facade_add_and_mul_plain(fhe_128: "n65.Nine65") -> None:
    ct_a = fhe_128.encrypt(6)
    ct_b = fhe_128.encrypt(7)
    assert fhe_128.decrypt(fhe_128.add(ct_a, ct_b)) == 13
    assert fhe_128.decrypt(fhe_128.mul_plain(ct_b, 6)) == 42
    assert fhe_128.decrypt(fhe_128.add_plain(ct_a, 100)) == 106


def test_mul_capacity_reports_a_small_bound_for_secure_128(ctx_128: n65.FHEContext) -> None:
    supported, max_product = ctx_128.mul_capacity()
    assert isinstance(supported, bool)
    assert isinstance(max_product, int)
    # Documented in lib.rs / README.md: all three SecureConfig names share
    # the same (q, t) through this single-modulus path, giving a tiny
    # max_product. This test pins the number down so a silent change in the
    # prime tables is caught here rather than as a confusing mul() failure
    # somewhere else.
    assert max_product == 4
