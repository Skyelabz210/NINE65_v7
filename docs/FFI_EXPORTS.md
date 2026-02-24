# NINE65 Python FFI Exports

This document defines the canonical export surface for the `nine65-python` PyO3 bindings.

## Module: `nine65_python`

### Configuration
- `FHEConfig.standard_128()`
- `FHEConfig.high_192()`
- `FHEConfig.large_single()`
- `SecureConfig.secure_128()`
- `SecureConfig.secure_192()`
- `SecureConfig.secure_256()`
- `SecureConfig.test_fast_insecure()`

Config accessors:
- `name()`
- `degree()`
- `plaintext_modulus()`
- `ciphertext_modulus()`
- `security_bits()`
- `eta()`
- `SecureConfig.is_production_safe()`
- `SecureConfig.to_config()`

### Core Types
- `FHEContext`
- `KeySet`
- `PublicKey`
- `SecretKey`
- `EvaluationKey`
- `Ciphertext`

### FHEContext Methods
- `generate_keyset_secure()`
- `generate_keyset_seeded(seed: int)`
- `encrypt(value: int, public_key: PublicKey)`
- `encrypt_seeded(value: int, public_key: PublicKey, seed: int)`
- `decrypt(ciphertext: Ciphertext, secret_key: SecretKey)`
- `add(ct1: Ciphertext, ct2: Ciphertext)`
- `add_plain(ct: Ciphertext, value: int)`
- `mul_plain(ct: Ciphertext, value: int)`
- `mul(ct1: Ciphertext, ct2: Ciphertext, eval_key: EvaluationKey)`
- `batch_encrypt(values: List[int], public_key: PublicKey)`
- `batch_decrypt(ciphertexts: List[Ciphertext], secret_key: SecretKey)`

### Serialization Helpers
- `PublicKey.to_bytes()` / `PublicKey.from_bytes()`
- `EvaluationKey.to_bytes()` / `EvaluationKey.from_bytes()`
- `Ciphertext.to_bytes()` / `Ciphertext.from_bytes()`

## Tests
- `crates/nine65-python/tests/test_nine65_pyo3.py`
- `crates/nine65-python/tests/improved_pyo3_tests_reference.py` (reference only)
