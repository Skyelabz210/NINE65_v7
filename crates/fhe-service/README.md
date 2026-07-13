# fhe-service

Rust HTTP service exposing an internal, server-key-holder FHE boundary.

## Endpoints

Public liveness/version routes:

- `GET /healthz`
- `GET /v1/version`

Protected tenant routes:

- `POST /v1/sessions`
- `GET /v1/sessions/{id}`
- `DELETE /v1/sessions/{id}`
- `POST /v1/sessions/{id}/encrypt`
- `POST /v1/sessions/{id}/evaluate`
- `POST /v1/sessions/{id}/decrypt` — additionally gated and disabled by default

Operator route:

- `GET /v1/metrics`

## Base authentication and tenant isolation

Every protected request requires:

```text
x-fhe-api-token: <service API secret>
x-fhe-tenant-id: <bounded tenant identifier>
```

The server is configured with:

```bash
export FHE_API_TOKEN='<service API secret>'
```

The tenant identifier is limited to 64 ASCII alphanumeric, hyphen, underscore, or period characters. Each session is bound to its authenticated tenant at creation. A missing session and a cross-tenant session lookup return the same response.

API token comparison hashes both values to fixed-length SHA-256 digests before constant-time comparison.

## Rate limiting

Protected requests are limited per tenant in exact integer one-minute windows. The default is 120 requests per minute and can be changed with:

```bash
export FHE_RATE_LIMIT_PER_MINUTE=120
```

Connection count, session count, payload size, response size, and session TTL remain independently bounded.

## Operator metrics

Metrics require the base API/tenant headers plus:

```text
x-fhe-operator-token: <operator secret>
```

configured by:

```bash
export FHE_OPERATOR_TOKEN='<operator secret>'
```

Without the operator capability, the metrics route is concealed.

## Decryption policy

Production builds conceal the decrypt endpoint unless all conditions hold:

```bash
export FHE_ENABLE_DECRYPT=1
export FHE_DECRYPT_TOKEN='<decrypt operator secret>'
```

and the caller supplies:

```text
x-fhe-decrypt-token: <decrypt operator secret>
```

The request must also pass the base API and tenant checks. This is defense in depth and does not replace mTLS, workload identity, tenant authorization, or network isolation.

## Audit events

Protected-route audit records contain:

- exact integer Unix timestamp;
- truncated SHA-256 tenant tag rather than the tenant identifier;
- operation class;
- HTTP status.

They do not include plaintext, ciphertext, session IDs, keys, or request bodies.

## Security boundary

- The service binds to `127.0.0.1:8080` by default.
- Sessions hold server-side keys and exact integer noise state.
- Session store lock poisoning fails closed rather than reusing potentially inconsistent cryptographic state.
- The service is an internal `ServiceOperator` mode, not consumer-side key ownership.
- The service targets IND-CPA evaluation semantics; authentication does not make the construction IND-CCA secure.
- Public evaluator applications should keep the secret key in the client, owner-controlled key service, HSM/TEE, or device boundary.
- Session cleanup removes expired tenant sessions and invokes configured key zeroization paths when values are dropped.

See `docs/SECURITY_MODE_MATRIX.md` for the complete mode contract.

## Run locally

Evaluation-only operator service:

```bash
FHE_API_TOKEN='<service API secret>' \
FHE_OPERATOR_TOKEN='<operator secret>' \
cargo run -p fhe-service --release
```

Explicit operator decryption mode:

```bash
FHE_API_TOKEN='<service API secret>' \
FHE_OPERATOR_TOKEN='<operator secret>' \
FHE_ENABLE_DECRYPT=1 \
FHE_DECRYPT_TOKEN='<decrypt operator secret>' \
cargo run -p fhe-service --release
```
