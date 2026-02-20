# fhe-service

Rust HTTP service that exposes the FHE boundary for the telemetry gateway.

Implemented endpoints:
- `GET /healthz` - Health check and active session count
- `GET /v1/version` - Service version and supported configurations
- `GET /v1/metrics` - Prometheus metrics endpoint
- `POST /v1/sessions` - Create a new FHE session with key generation
- `GET /v1/sessions/{id}` - Get session information and noise budget
- `DELETE /v1/sessions/{id}` - Destroy a session and zeroize key material
- `POST /v1/sessions/{id}/encrypt` - Encrypt values to ciphertexts
- `POST /v1/sessions/{id}/decrypt` - Decrypt ciphertexts to values
- `POST /v1/sessions/{id}/evaluate` - Perform homomorphic operations (add, sub, negate, mul, add_plain, mul_plain)

Notes:
- Sessions hold server-side encryption keys and track noise budget
- Key material never leaves the server; only ciphertexts travel over the wire
- Supports secure configurations: secure_128, secure_192, secure_256
- Automatic session cleanup with TTL-based reaper

Security Model:
- This service provides IND-CPA (indistinguishability under chosen-plaintext attack) security
- The decryption endpoint functions as a decryption oracle by design and should NOT be exposed to untrusted clients in production without additional application-layer authentication
- The service does NOT provide CCA (chosen-ciphertext attack) security protections such as noise flooding or OAEP-style message encoding
- For symmetric-mode usage (single server with known key), IND-CPA security is sufficient
- For multi-party or asymmetric usage scenarios, additional security measures are required

Run locally:
```bash
cargo run -p fhe-service --release
```
