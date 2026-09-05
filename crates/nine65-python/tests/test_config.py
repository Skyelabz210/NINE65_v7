"""Config accessors: `SecureConfig`, `FHEConfig`, and the pure-Python
`context_for` / `SECURE_CONFIG_NAMES` helpers built on top of them."""

from __future__ import annotations

import pytest

import nine65_python as n65


@pytest.mark.parametrize("name", ["secure_128", "secure_192", "secure_256"])
def test_secure_config_named_constructors(name: str) -> None:
    ctor = n65.SECURE_CONFIG_NAMES[name]
    cfg = ctor()
    assert isinstance(cfg, n65.SecureConfig)
    assert cfg.is_production_safe() is True


@pytest.mark.parametrize("name", ["secure_128", "secure_192", "secure_256"])
def test_context_for_builds_a_working_context(name: str) -> None:
    ctx = n65.context_for(name)
    assert ctx.name() == name
    assert ctx.degree() > 0
    assert ctx.plaintext_modulus() > 0
    assert ctx.ciphertext_modulus() > 0


def test_context_for_rejects_unknown_name() -> None:
    with pytest.raises(ValueError):
        n65.context_for("not_a_real_config")


def test_context_for_does_not_fall_back_to_insecure() -> None:
    # A typo should raise, not silently hand back some other (possibly
    # weaker) config.
    with pytest.raises(ValueError):
        n65.context_for("secure_128 ")  # trailing space -- not a real key


def test_secure_config_security_bit_accessors_are_consistent(ctx_128: n65.FHEContext) -> None:
    cfg = n65.SecureConfig.secure_128()
    # classical >= hybrid >= quantum is the expected ordering for these
    # models (each strictly-or-equally more permissive to the attacker).
    assert cfg.classical_security() >= cfg.hybrid_security() >= cfg.quantum_security()
    assert cfg.he_standard_compliant() in (True, False)


def test_secure_config_to_config_matches_context(ctx_128: n65.FHEContext) -> None:
    cfg = n65.SecureConfig.secure_128()
    fhe_cfg = cfg.to_config()
    assert fhe_cfg.degree() == ctx_128.degree()
    assert fhe_cfg.plaintext_modulus() == ctx_128.plaintext_modulus()
    assert fhe_cfg.ciphertext_modulus() == ctx_128.ciphertext_modulus()


def test_secure_128_192_256_share_the_single_modulus_qt_pair() -> None:
    # Documented in conftest.py / README.md "Known limitations": all three
    # named configs reduce to the *same* (q, t) through this single-modulus
    # binding, because only the first RNS prime participates in it. This
    # test pins that fact down so a future change to the prime tables (which
    # would change the safe plaintext range this suite relies on) is caught
    # here instead of showing up as a mysterious failure elsewhere.
    ctxs = [n65.context_for(name) for name in ("secure_128", "secure_192", "secure_256")]
    q_values = {c.ciphertext_modulus() for c in ctxs}
    t_values = {c.plaintext_modulus() for c in ctxs}
    assert len(q_values) == 1
    assert len(t_values) == 1


def test_fhe_context_config_roundtrip(ctx_128: n65.FHEContext) -> None:
    cfg = ctx_128.config()
    assert cfg.degree() == ctx_128.degree()
    assert cfg.plaintext_modulus() == ctx_128.plaintext_modulus()
    assert cfg.ciphertext_modulus() == ctx_128.ciphertext_modulus()
    assert cfg.name() == ctx_128.name()
