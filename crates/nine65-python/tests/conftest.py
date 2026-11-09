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

# Moderate values for arithmetic fixtures keep their products and scalar
# multiples within a predictable single-modulus noise envelope. This is not
# a plaintext admission limit: fresh encryption now round-trips the complete
# [0,t) domain using nearest q*m/t encoding. Full-range edge/seed regressions
# live in test_known_limitations.py. The binding's single-modulus path still
# does not inherit the multi-lane named profile's security level or ct*ct API.
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
