# private-feedback-nine65

Public-evaluator NINE65 adapter for `private-feedback-core`.

The adapter accepts a validated structured feedback signal and a `DualRNSPublicKey`, encrypts the eight fixed slots, and supports slot-wise homomorphic aggregation through `RNSFHEContext::add_dual`.

Its public API intentionally contains:

- no secret-key field;
- no decryption method;
- no raw response text;
- no Garner reconstruction;
- no mixed-radix conversion;
- no internal number-line projection;
- no floating-point arithmetic.

The test module uses a test-only insecure parameter profile to exercise a complete encrypt → DualRNS add → decrypt oracle round trip. The decrypt operation exists only in the test harness to verify correctness; it is not exposed by `EncryptedFeedback`.

Production applications select an independently evidenced secure parameter tuple and keep the secret key in the client, tenant key service, HSM/TEE, or other owner-controlled boundary defined by `docs/SECURITY_MODE_MATRIX.md`.
