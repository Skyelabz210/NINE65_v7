"""Shared fixtures and constants for the nine65_python test suite.

Every test here runs against the real compiled extension (`maturin develop
--release` must have been run first -- see README.md "Running the tests").
Nothing in this suite mocks the Rust layer.
"""

from __future__ import annotations

import pytest

import nine65_python as n65

# Fixed seed used wherever a test wants reproducible (not necessarily secure)
# key material -- see `nine65_python.generate_keypair`'s docstring for why
# this is fine for tests and wrong for anything holding real data.
KEY_SEED = 42

# --- The "safe zone" for plaintext values with the single-modulus contexts
# this crate currently binds ------------------------------------------------
#
# `SecureConfig.secure_128()` / `.secure_192()` / `.secure_256()` all reduce,
# through `FHEContext.from_secure_config`, to the *same* single ciphertext
# modulus (the first RNS prime, 998244353) and the same plaintext modulus
# (65537) -- the additional anchor lanes that give those configs their named
# security level aren't used by this single-modulus BFV path at all.
#
# For that (q, t) pair, `BFVEncoder::decode()`'s `round(t*c/q) mod t`
# formula has a real, deterministic, noise-free bias that grows with the
# plaintext value: `q mod t` is not `0` (998244353 mod 65537 == 50306), so
# `t * floor(q/t)` is not exactly `q`, and the rounding error compounds
# proportionally to the plaintext value. Reproduced directly against the
# Rust formula (no encryption, no noise, no Python) it first flips the
# decoded value at m == 9922. Encryption noise consumes some of the
# remaining margin: measured empirically over 10 independently generated
# keysets x 5 seeds x several plaintexts (300 trials), m <= 9000 round-tripped
# with zero failures, while values approaching `t` (e.g. `t - 1`) failed
# 200/200 trials by a consistent few units -- see `test_known_limitations.py`
# for the reproduction and README.md "Known limitations" for the writeup.
#
# SAFE_MAX is set with a healthy margin under the measured 9000-clean /
# 9922-theoretical boundary specifically so correctness tests here are not
# flaky close to an edge that depends on encryption noise (which varies by
# key and by seed).
SAFE_MAX = 4000


@pytest.fixture(scope="session")
def ctx_128() -> n65.FHEContext:
    return n65.context_for("secure_128")


@pytest.fixture(scope="session")
def ctx_192() -> n65.FHEContext:
    return n65.context_for("secure_192")


@pytest.fixture(scope="session")
def ctx_256() -> n65.FHEContext:
    return n65.context_for("secure_256")


@pytest.fixture(scope="session")
def keys_128(ctx_128: n65.FHEContext):
    """Deterministic keyset for secure_128 -- reused across tests in this
    session for speed (n=8192 key generation is not free); tests that
    specifically need to exercise OS-CSPRNG key generation build their own
    short-lived keyset instead of using this fixture."""
    return ctx_128.generate_keyset_seeded(KEY_SEED)


@pytest.fixture(scope="session")
def fhe_128() -> "n65.Nine65":
    """A ready-to-use `Nine65` facade (context + deterministic keyset) for
    secure_128, session-scoped for the same reason as `keys_128`."""
    return n65.Nine65.build("secure_128", seed=KEY_SEED)
