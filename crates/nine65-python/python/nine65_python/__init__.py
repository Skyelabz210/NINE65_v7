"""Python bindings for NINE65 -- an exact-integer BFV/DualRNS FHE library.

This package wraps the compiled PyO3 extension (``nine65_python._nine65_python``,
built from ``crates/nine65-python/src/lib.rs``) with a few pure-Python
conveniences: named-config lookup by string, one-call key generation, and a
small ``Nine65`` facade that bundles a context with a keyset so single-party
demos and tests don't have to thread ``public_key``/``secret_key``/
``evaluation_key`` through every call by hand.

Everything here is a thin wrapper. The actual arithmetic -- encoding,
encryption, homomorphic add/mul, decryption -- all happens in Rust; nothing
in this file touches ciphertext coefficients. See ``README.md`` in this
directory for a quickstart and ``tests/`` for round-trip-correctness examples
covering encrypt/decrypt, add, mul (ciphertext x ciphertext), batch
operations, serialization, and integer-width boundary behavior at the
Python-int <-> Rust-u64 FFI edge.

Security note: this crate is a *binding*, not a new implementation. It
inherits every property (and every limitation) of the underlying `nine65`
crate documented at the repository root -- in particular, the finite
multiplicative depth and the screening caveats on the security levels named
by ``SecureConfig``. Read the repository's top-level README and
``docs/CLAIM_SURFACE_AND_LIMITS_*.md`` before using this for anything beyond
experimentation.
"""

from __future__ import annotations

from typing import Optional

from ._nine65_python import (
    Ciphertext,
    EvaluationKey,
    FHEConfig,
    FHEContext,
    KeySet,
    PublicKey,
    SecretKey,
    SecureConfig,
)

__all__ = [
    "Ciphertext",
    "EvaluationKey",
    "FHEConfig",
    "FHEContext",
    "KeySet",
    "PublicKey",
    "SecretKey",
    "SecureConfig",
    "Nine65",
    "context_for",
    "generate_keypair",
    "SECURE_CONFIG_NAMES",
]

__version__ = "0.1.0"

# Named constructors on `SecureConfig`, keyed by the same strings the Rust
# side uses as `SecureConfig.name()` / `FHEConfig.name()`, so a caller can go
# from a config name (e.g. round-tripped through logs or a CLI flag) straight
# to a context without an if/elif ladder of their own.
SECURE_CONFIG_NAMES = {
    "secure_128": SecureConfig.secure_128,
    "secure_192": SecureConfig.secure_192,
    "secure_256": SecureConfig.secure_256,
}


def context_for(name: str) -> FHEContext:
    """Build an :class:`FHEContext` from one of the named production security
    configs (``"secure_128"``, ``"secure_192"``, ``"secure_256"``).

    Raises ``ValueError`` for any other name -- this deliberately does not
    fall back to a test/insecure config, so a typo can't silently downgrade
    security.
    """
    try:
        ctor = SECURE_CONFIG_NAMES[name]
    except KeyError as exc:
        raise ValueError(
            f"unknown secure config {name!r}; expected one of "
            f"{sorted(SECURE_CONFIG_NAMES)}"
        ) from exc
    return FHEContext.from_secure_config(ctor())


def generate_keypair(context: FHEContext, *, seed: Optional[int] = None) -> KeySet:
    """Generate a :class:`KeySet` (public key, secret key, evaluation key) for
    ``context``.

    With ``seed`` omitted (the default), key material comes from the OS
    CSPRNG via ``generate_keyset_secure()`` -- use this path for anything
    that isn't a reproducible test or benchmark. Passing ``seed`` switches to
    ``generate_keyset_seeded()``, which derives an entirely deterministic
    keyset from the seed; the same seed always yields the same keys, which is
    exactly what you want for a repeatable test fixture and exactly what you
    do not want for anything holding real data.
    """
    if seed is None:
        return context.generate_keyset_secure()
    return context.generate_keyset_seeded(seed)


class Nine65:
    """A small single-party convenience facade over :class:`FHEContext`.

    Bundles a context with one keyset so you can call ``encrypt``/``decrypt``/
    ``add``/``mul``/... without passing keys to every call. This is a
    demo/prototyping convenience, not a new security boundary: the secret key
    lives in this object exactly as it would in your own code holding the raw
    ``FHEContext`` + ``KeySet`` pair.

    Example
    -------
    >>> import nine65_python as n65
    >>> fhe = n65.Nine65.build("secure_128", seed=42)   # doctest: +SKIP
    >>> ct_a = fhe.encrypt(6)                            # doctest: +SKIP
    >>> ct_b = fhe.encrypt(7)                            # doctest: +SKIP
    >>> fhe.decrypt(fhe.add(ct_a, ct_b))                 # doctest: +SKIP
    13
    >>> fhe.decrypt(fhe.mul_plain(ct_b, 6))              # doctest: +SKIP
    42

    ``mul()`` (ciphertext x ciphertext) is also available on this facade
    but is NOT demonstrated here -- see its docstring and README.md "Known
    limitations" before reaching for it.
    """

    __slots__ = ("context", "keys")

    def __init__(self, context: FHEContext, keys: KeySet):
        self.context = context
        self.keys = keys

    @classmethod
    def build(cls, config_name: str = "secure_128", *, seed: Optional[int] = None) -> "Nine65":
        """Construct a context for ``config_name`` and generate a keyset for
        it in one call. See :func:`context_for` and :func:`generate_keypair`
        for what each half does."""
        context = context_for(config_name)
        keys = generate_keypair(context, seed=seed)
        return cls(context, keys)

    def encrypt(self, value: int) -> Ciphertext:
        return self.context.encrypt(value, self.keys.public_key)

    def decrypt(self, ciphertext: Ciphertext) -> int:
        return self.context.decrypt(ciphertext, self.keys.secret_key)

    def add(self, ct1: Ciphertext, ct2: Ciphertext) -> Ciphertext:
        return self.context.add(ct1, ct2)

    def add_plain(self, ciphertext: Ciphertext, value: int) -> Ciphertext:
        return self.context.add_plain(ciphertext, value)

    def mul_plain(self, ciphertext: Ciphertext, value: int) -> Ciphertext:
        return self.context.mul_plain(ciphertext, value)

    def mul(self, ct1: Ciphertext, ct2: Ciphertext) -> Ciphertext:
        """Ciphertext x ciphertext multiplication.

        **Currently broken for every config this was checked against --
        see README.md "Known limitations" before using this.** It is not
        merely bounded by ``mul_capacity()``: even the simplest possible
        case, ``1 * 1``, decrypts to the wrong value. This was verified in
        plain Rust with no PyO3/Python involved, so it is a `nine65`
        core-arithmetic issue, not something this facade or the FFI
        boundary introduces. Prefer ``mul_plain()`` (ciphertext x a known
        plaintext scalar), which is verified exact.
        """
        return self.context.mul(ct1, ct2, self.keys.evaluation_key)

    def mul_capacity(self) -> tuple:
        """See ``FHEContext.mul_capacity()``: a necessary-but-not-sufficient
        bound on ``mul()`` correctness -- see ``mul()``'s own docstring for
        the more severe issue this number does not capture."""
        return self.context.mul_capacity()
