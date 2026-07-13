# fhe-service

Rust HTTP service exposing an internal, server-key-holder FHE boundary.

Implemented endpoints:

- `GET /healthz`
- `GET /v1/version`
- `GET /v1/metrics`
- `POST /v1/sessions`
- `GET /v1/sessions/{id}`
- `DELETE /v1/sessions/{id}`
- `POST /v1/sessions/{id}/encrypt`
- `POST /v1/sessions/{id}/evaluate`
- `POST /v1/sessions/{id}/decrypt` — operator-only and disabled by default

## Decryption policy

Production builds conceal the decrypt endpoint unless all conditions hold:

```bash
export FHE_ENABLE_DECRYPT=1
export FHE_DECRYPT_TOKEN='<operator secret>'
```

The caller must also provide:

```text
x-fhe-decrypt-token: <operator secret>
```

Token comparison is constant-time. This gate is defense in depth and does not replace mTLS, workload identity, tenant authorization, or network isolation.

## Security boundary

- Sessions hold server-side keys and track an exact integer noise budget.
- The service is an internal `ServiceOperator` mode, not consumer-side key ownership.
- The service targets IND-CPA evaluation semantics; it does not become IND-CCA secure merely because the decrypt route is gated.
- Public evaluator applications should keep the secret key in the client, owner-controlled key service, HSM/TEE, or device boundary and should not use this process as a public decryption service.
- Session cleanup destroys stored key material through the configured zeroization path.

See `docs/SECURITY_MODE_MATRIX.md` for the complete mode contract.

## Run locally

Evaluation-only default:

```bash
cargo run -p fhe-service --release
```

Explicit operator decryption mode:

```bash
FHE_ENABLE_DECRYPT=1 \
FHE_DECRYPT_TOKEN='<operator secret>' \
cargo run -p fhe-service --release
```
