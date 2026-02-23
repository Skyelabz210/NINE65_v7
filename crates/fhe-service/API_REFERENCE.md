# FHE Service API Reference

HTTP microservice for session-based BFV homomorphic encryption using the DualRNS pipeline with 5-anchor K-Elimination for correct ct×ct multiplication. Key material never leaves the server; only opaque ciphertexts travel over the wire.

## Quick Start

```bash
# Start the service
./bin/fhe-service

# Create a session, encrypt two values, add them, decrypt the result
SID=$(curl -s -X POST http://127.0.0.1:8080/v1/sessions \
  -d '{"config":"secure_128"}' | jq -r .session_id)

ENC=$(curl -s -X POST http://127.0.0.1:8080/v1/sessions/$SID/encrypt \
  -d '{"values":[42,17]}')

CT_A=$(echo $ENC | jq -r .ciphertexts[0])
CT_B=$(echo $ENC | jq -r .ciphertexts[1])

CT_SUM=$(curl -s -X POST http://127.0.0.1:8080/v1/sessions/$SID/evaluate \
  -d "{\"operations\":[{\"op\":\"add\",\"inputs\":[\"$CT_A\",\"$CT_B\"]}]}" \
  | jq -r .results[0])

curl -s -X POST http://127.0.0.1:8080/v1/sessions/$SID/decrypt \
  -d "{\"ciphertexts\":[\"$CT_SUM\"]}" | jq .values
# → [59]
```

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `FHE_SERVICE_HOST` | `127.0.0.1` | Bind address |
| `FHE_SERVICE_PORT` | `8080` | Bind port |
| `FHE_MAX_SESSIONS` | `64` | Maximum concurrent sessions |
| `FHE_MAX_CONNECTIONS` | `256` | Maximum concurrent TCP connections |
| `FHE_SESSION_TTL` | `3600` | Session time-to-live (seconds) |

## Endpoints

### GET /healthz

Health check.

**Response** `200`:
```json
{
  "status": "ok",
  "service": "fhe-service",
  "active_sessions": 2,
  "timestamp_unix": 1740268800
}
```

### GET /v1/version

Service version and supported configurations.

**Response** `200`:
```json
{
  "service": "fhe-service",
  "version": "0.1.0",
  "supported_configs": ["secure_128", "secure_192", "secure_256"]
}
```

### GET /v1/metrics

Prometheus-format metrics.

**Response** `200` (text/plain):
```
fhe_requests_total 142
fhe_requests_failed_total 3
fhe_active_sessions 2
fhe_uptime_seconds 3600
```

---

### POST /v1/sessions

Create an FHE session. Generates key material server-side.

**Request**:
```json
{
  "config": "secure_128"
}
```

Supported configs:

| Config | n | log2(Q) | t | Security |
|--------|---|---------|---|----------|
| `secure_128` | 4096 | ~90 | 65537 | 128-bit |
| `secure_192` | 16384 | ~145 | 65537 | 192-bit |
| `secure_256` | 16384 | ~174 | 65537 | 256-bit |

**Response** `201`:
```json
{
  "session_id": "a1b2c3d4e5f6...",
  "config": "secure_128",
  "params": {
    "n": 4096,
    "log_q": 90,
    "t": 65537,
    "security_bits": 128
  },
  "noise_budget_estimate_millibits": 62000
}
```

**Errors**: `400 INVALID_PAYLOAD`, `429 MAX_SESSIONS`

### GET /v1/sessions/{id}

Get session info.

**Response** `200`:
```json
{
  "session_id": "a1b2c3d4e5f6...",
  "config": "secure_128",
  "noise_budget_estimate_millibits": 46000,
  "operation_count": 5,
  "created_at": 1740268800
}
```

**Errors**: `404 SESSION_NOT_FOUND`

### DELETE /v1/sessions/{id}

Destroy a session and its key material.

**Response** `200`:
```json
{"deleted": true}
```

---

### POST /v1/sessions/{id}/encrypt

Encrypt plaintext values. Each value must be `< t` (65537).

**Ciphertext format**: Ciphertexts are DualRNS-encoded, containing both main RNS limbs and 5 anchor limbs for K-Elimination. They are larger than single-modulus ciphertexts (up to ~4MB for `secure_256`).

**Request**:
```json
{
  "values": [42, 17, 100]
}
```

**Limits**: Max 1024 values per request.

**Response** `200`:
```json
{
  "ciphertexts": [
    "<base64-encoded bincode ciphertext>",
    "<base64-encoded bincode ciphertext>",
    "<base64-encoded bincode ciphertext>"
  ],
  "noise_budget_estimate_millibits": 54000
}
```

**Errors**: `400 INVALID_PAYLOAD`, `400 ENCRYPT_FAILED` (noise exhausted or value >= t), `404 SESSION_NOT_FOUND`

### POST /v1/sessions/{id}/decrypt

Decrypt ciphertexts back to plaintext values.

**Request**:
```json
{
  "ciphertexts": ["<base64-encoded bincode ciphertext>"]
}
```

**Limits**: Max 1024 ciphertexts, max 4MB per ciphertext, max 64MB total request allocation.

**Response** `200`:
```json
{
  "values": [42],
  "noise_budget_estimate_millibits": 54000
}
```

**Errors**: `400 INVALID_PAYLOAD`, `400 DECRYPT_FAILED`, `404 SESSION_NOT_FOUND`

---

### POST /v1/sessions/{id}/evaluate

Execute homomorphic operations on ciphertexts.

**Request**:
```json
{
  "operations": [
    {
      "op": "add",
      "inputs": ["<base64_ct_a>", "<base64_ct_b>"]
    },
    {
      "op": "mul_plain",
      "inputs": ["<base64_ct>"],
      "scalar": 7
    }
  ]
}
```

**Limits**: Max 256 operations per request, max 4 inputs per operation, max 4MB per ciphertext input, max 64MB total request allocation.

**Supported Operations**:

| op | inputs | scalar | Description | Noise cost |
|----|--------|--------|-------------|------------|
| `add` | 2 ciphertexts | - | ct + ct | 1000 mb |
| `sub` | 2 ciphertexts | - | ct - ct | 1000 mb |
| `negate` | 1 ciphertext | - | -ct | 1000 mb |
| `add_plain` | 1 ciphertext | required, < t | ct + scalar | 100 mb |
| `mul_plain` | 1 ciphertext | required, < t | ct * scalar | ~17000 mb |
| `mul` | 2 ciphertexts | - | ct × ct (DualRNS K-Elimination) | ~30000 mb |

The `mul` (ct×ct) operation uses the DualRNS pipeline with 5-anchor K-Elimination for exact rescaling. This produces correct results on all configurations. Note that `secure_128` has limited noise budget — a single ct×ct mul consumes most of it, leaving room only for `mul_plain` or direct decrypt afterward.

**Response** `200`:
```json
{
  "results": ["<base64_ct_result_1>", "<base64_ct_result_2>"],
  "noise_budget_estimate_millibits": 31000,
  "operation_count": 7
}
```

Each result corresponds positionally to the input operation. Results are opaque ciphertexts that can be passed back to subsequent evaluate or decrypt calls.

**Errors**: `400 INVALID_PAYLOAD`, `400 EVALUATE_FAILED` (noise exhausted, wrong input count, unknown op), `404 SESSION_NOT_FOUND`, `413 PAYLOAD_TOO_LARGE`

---

## Noise Budget

Every session starts with a noise budget (in millibits, where 1000 = 1 bit). Each operation consumes budget. When budget is exhausted, further operations are rejected.

The budget functions as a **Kiosk Architecture** safety mechanism: sessions are self-limiting computation units that prevent unbounded resource consumption and ensure ciphertext integrity.

| Config | Initial budget | Approximate capacity |
|--------|---------------|---------------------|
| `secure_128` | ~62000 mb | ~7 encryptions, or ~60 additions, or ~3 mul_plain |
| `secure_192` | ~100000 mb | ~10 encryptions, or ~100 additions |
| `secure_256` | ~120000 mb | ~12 encryptions, or ~120 additions |

Budget is tracked per-session. Create a new session for fresh budget.

## Chaining Operations

Evaluate results can be fed back into subsequent evaluate calls:

```bash
# Encrypt a=5, b=3, c=2
ENC=$(curl -s -X POST .../encrypt -d '{"values":[5,3,2]}')
CT_A=$(echo $ENC | jq -r .ciphertexts[0])
CT_B=$(echo $ENC | jq -r .ciphertexts[1])
CT_C=$(echo $ENC | jq -r .ciphertexts[2])

# Compute (a + b) in one call
EVAL1=$(curl -s -X POST .../evaluate \
  -d "{\"operations\":[{\"op\":\"add\",\"inputs\":[\"$CT_A\",\"$CT_B\"]}]}")
CT_SUM=$(echo $EVAL1 | jq -r .results[0])

# Then compute (a + b) * c in a second call
EVAL2=$(curl -s -X POST .../evaluate \
  -d "{\"operations\":[{\"op\":\"mul\",\"inputs\":[\"$CT_SUM\",\"$CT_C\"]}]}")
CT_PRODUCT=$(echo $EVAL2 | jq -r .results[0])

# Decrypt: should be (5+3)*2 = 16
curl -s -X POST .../decrypt \
  -d "{\"ciphertexts\":[\"$CT_PRODUCT\"]}" | jq .values
# → [16]
```

Multiple operations can also be batched in a single evaluate call. Operations execute sequentially; each result is available for subsequent operations in the same batch via its position in the results array.

## Error Response Format

All errors follow a consistent format:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "human-readable description"
  }
}
```

Error messages are intentionally generic to prevent information leakage (no plaintext values, moduli, or internal state are revealed in error responses).

## Security Notes

- Key material (secret key, evaluation key) never leaves the server
- Ciphertexts are opaque base64-encoded bincode blobs — not human-readable
- Error messages are uniform to prevent oracle attacks
- Session TTL and max-session limits prevent resource exhaustion
- Connection limits (503 SERVICE_BUSY) prevent DoS
- Request body size is bounded (max 10MB per request)
- Panics in handlers are caught and returned as 500 without leaking state
