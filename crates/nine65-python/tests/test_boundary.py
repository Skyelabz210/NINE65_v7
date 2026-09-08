"""Integer-width boundary behavior at the Python-int <-> Rust-u64 FFI edge.

Python integers are arbitrary-precision; every plaintext value, seed, and
scalar multiplier crossing into Rust here is declared `u64`. PyO3 performs a
checked conversion on every such call -- this file pins down exactly what
happens at each edge instead of assuming it: a negative value or a value
that doesn't fit in 64 bits must be rejected with `OverflowError` *before*
any Rust code runs (never silently truncated, wrapped, or reinterpreted),
and a value that fits `u64` but violates a domain rule (e.g. `>= t`) must
raise `ValueError` from `nine65`'s own bounds check instead.
"""

from __future__ import annotations

import pytest

import nine65_python as n65

U64_MAX = 2**64 - 1


def test_negative_plaintext_raises_overflow_error(
    ctx_128: n65.FHEContext, keys_128: n65.KeySet
) -> None:
    with pytest.raises(OverflowError):
        ctx_128.encrypt(-1, keys_128.public_key)


def test_plaintext_beyond_u64_raises_overflow_error(
    ctx_128: n65.FHEContext, keys_128: n65.KeySet
) -> None:
    with pytest.raises(OverflowError):
        ctx_128.encrypt(2**64, keys_128.public_key)
    with pytest.raises(OverflowError):
        ctx_128.encrypt(2**128, keys_128.public_key)


def test_plaintext_at_u64_max_fits_the_ffi_conversion_but_fails_domain_check(
    ctx_128: n65.FHEContext, keys_128: n65.KeySet
) -> None:
    # U64_MAX fits in a u64 (the FFI boundary conversion itself succeeds),
    # so this must fail with nine65's *own* ValueError (message out of
    # bounds) rather than an OverflowError from the conversion layer -- if
    # this ever raised OverflowError instead, it would mean the conversion
    # boundary and the domain-bounds check had been conflated somewhere.
    with pytest.raises(ValueError) as exc_info:
        ctx_128.encrypt(U64_MAX, keys_128.public_key)
    assert "OverflowError" not in type(exc_info.value).__name__


def test_negative_seed_raises_overflow_error(
    ctx_128: n65.FHEContext, keys_128: n65.KeySet
) -> None:
    with pytest.raises(OverflowError):
        ctx_128.encrypt_seeded(1, keys_128.public_key, seed=-1)
    with pytest.raises(OverflowError):
        ctx_128.generate_keyset_seeded(-1)


def test_seed_at_u64_max_is_accepted_and_deterministic(ctx_128: n65.FHEContext) -> None:
    # The seed itself has no domain restriction (unlike a plaintext value),
    # so U64_MAX must be accepted, not rejected -- and produce the exact
    # same output on repeated calls.
    keys = ctx_128.generate_keyset_seeded(U64_MAX)
    ct_a = ctx_128.encrypt_seeded(3, keys.public_key, seed=U64_MAX)
    ct_b = ctx_128.encrypt_seeded(3, keys.public_key, seed=U64_MAX)
    assert ct_a.to_bytes() == ct_b.to_bytes()
    assert ctx_128.decrypt(ct_a, keys.secret_key) == 3


def test_plaintext_modulus_boundary_exact(
    ctx_128: n65.FHEContext, keys_128: n65.KeySet
) -> None:
    t = ctx_128.plaintext_modulus()
    # t - 1 is the largest *declared-valid* plaintext (the bound check is
    # `m >= t`). Whether it actually round-trips correctly is a SEPARATE
    # question -- see test_known_limitations.py; this test only checks the
    # bound check itself, using a value from well inside the verified-safe
    # decode range so the two concerns don't get entangled.
    safe_large = min(t - 1, 4000)
    ct = ctx_128.encrypt_seeded(safe_large, keys_128.public_key, seed=1)
    assert ctx_128.decrypt(ct, keys_128.secret_key) == safe_large

    with pytest.raises(ValueError):
        ctx_128.encrypt_seeded(t, keys_128.public_key, seed=1)
    with pytest.raises(ValueError):
        ctx_128.encrypt_seeded(t + 1, keys_128.public_key, seed=1)


def test_mul_plain_scalar_accepts_full_u64_range_but_rejects_overflow(
    ctx_128: n65.FHEContext, keys_128: n65.KeySet
) -> None:
    # mul_plain's scalar is documented (Rust side) as a raw multiplier, not
    # bounded by t -- but it is still a u64 at the FFI boundary.
    ct = ctx_128.encrypt_seeded(0, keys_128.public_key, seed=1)
    ctx_128.mul_plain(ct, U64_MAX)  # must not raise
    with pytest.raises(OverflowError):
        ctx_128.mul_plain(ct, -1)
    with pytest.raises(OverflowError):
        ctx_128.mul_plain(ct, 2**64)


def test_batch_encrypt_rejects_out_of_range_element(
    ctx_128: n65.FHEContext, keys_128: n65.KeySet
) -> None:
    t = ctx_128.plaintext_modulus()
    with pytest.raises(ValueError):
        ctx_128.batch_encrypt([0, 1, t], keys_128.public_key)


def test_batch_encrypt_rejects_overflowing_element(
    ctx_128: n65.FHEContext, keys_128: n65.KeySet
) -> None:
    with pytest.raises(OverflowError):
        ctx_128.batch_encrypt([0, -1], keys_128.public_key)
