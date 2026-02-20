# NINE65 Full-Stack Architecture Pack (Option 1)

Date: 2026-02-09
Owner: Full-stack architecture track
NINE65 status: PRE-PRODUCTION (do not deploy to production until documented security gaps are closed)
Default FHE config: `SecureConfig::secure_192()`

## 0. Scope, Assumptions, and Product Goal

Primary goal: deliver privacy-preserving biometric telemetry analytics where sensitive features remain encrypted end-to-end during transport, storage, and computation.

Assumptions used for this pack:
- Product domain: remote patient monitoring and early risk scoring for regulated healthcare tenants.
- User groups: patient/device users, clinician operators, tenant admins, internal SRE/compliance teams.
- Platform stack: Next.js frontend + Node API gateway + Rust FHE service + Postgres/Prisma + AWS managed infrastructure.

Business outcomes:
- Reduce privacy risk by keeping biometric features ciphertext-only in shared services.
- Provide near-real-time risk insights without exposing raw signals.
- Enable HIPAA + GDPR baseline controls from first release.

Success metrics:
- P95 ingestion accept latency <= 120 ms.
- P95 FHE evaluation latency <= 250 ms for reference workload.
- Evaluation success rate >= 99.5%.
- Minimum post-evaluation noise budget >= 20 bits.
- Zero plaintext biometric payloads in gateway/application logs.

## 1. Product Threat Model

High-value assets:
- FHE secret keys and key metadata.
- Tenant PII mapping records.
- Encrypted telemetry payloads and result ciphertexts.
- Model definitions and policy constraints.

Adversaries and abuse paths:
- External attacker attempting replay, injection, or metadata harvesting.
- Compromised device SDK sending malformed or adversarial payloads.
- Insider with excessive IAM privileges querying restricted stores.
- Third-party compromise in logging/observability pipeline.

Trust-boundary principles:
- Device-side encryption with active public key before network transit.
- Node gateway processes ciphertext and metadata only.
- Secret keys remain in Rust FHE service boundary/HSM references only.
- Decryption runs in restricted zone under policy gating and full audit logging.

Non-goals for v1:
- No plaintext raw biometric persistence for analytics convenience.
- No direct PII joins in dashboards or ad hoc analyst queries.
- No deployment claim of production readiness while NINE65 v5 is pre-production.

## 2. Architecture Diagram with FHE Boundary

```text
                              Public / Edge Zone
+-----------------------+     +-------------------------------------+
| Device SDK            | --> | Node API Gateway                    |
| - capture features    | TLS | - OIDC/JWT auth                     |
| - local preprocess    |     | - schema + idempotency validation   |
| - encrypt with PK     |     | - stream publish / batch fallback   |
+-----------------------+     +------------------+------------------+
                                                 |
                                                 | ciphertext + metadata only
                                                 v
                                Restricted Compute Zone (FHE boundary)
                                +-------------------------------------+
                                | Rust FHE Service (NINE65 v5)        |
                                | - GET /v1/fhe/public-key            |
                                | - POST /v1/fhe/evaluate             |
                                | - noise budget enforcement           |
                                | - metrics + version endpoints        |
                                +------------------+------------------+
                                                 |
                                                 | result ciphertext + eval metadata
                                                 v
                             Highly Restricted Decryption / Policy Zone
+---------------------+      +-------------------------------------+     +----------------------+
| Stream + Batch Bus  | ---> | Result Policy Service              | --> | Product Analytics DB |
| Kinesis/MSK + S3    |      | - policy-gated decrypt requests    |     | derived scores only  |
+---------------------+      | - minimum-necessary plaintext only  |     +----------------------+
                             +------------------+------------------+
                                                 |
                                                 v
                                         +----------------+
                                         | PII Vault DB   |
                                         | strict RBAC    |
                                         | immutable audit|
                                         +----------------+
```

FHE boundary rules:
- Allowed inside boundary: key handling, ciphertext evaluation, noise accounting.
- Allowed outside boundary: auth, routing, rate limits, idempotency, stream orchestration.
- Prohibited outside boundary: secret key material and plaintext biometric payload processing.

## 3. API Contract (Gateway + FHE Service)

Transport and auth baseline:
- External ingress: HTTPS (TLS 1.2+) + OIDC/OAuth JWT.
- Internal service calls: mTLS + short-lived service tokens.
- Every mutating request carries `Idempotency-Key`.

### 3.1 `GET /v1/fhe/public-key`
Purpose: provide the active public key for client/device-side encryption.

Response 200:
```json
{
  "key_id": "fhekey_2026_02",
  "algorithm": "BFV",
  "config": "SecureConfig::secure_192()",
  "public_key_b64": "<base64>",
  "created_at": "2026-02-09T00:00:00Z",
  "expires_at": "2026-03-10T00:00:00Z",
  "status": "active"
}
```

### 3.2 `POST /v1/telemetry/events`
Purpose: ingest encrypted telemetry events (real-time path).

Headers:
- `Authorization: Bearer <jwt>`
- `Idempotency-Key: <uuid>`
- `X-Key-Id: fhekey_2026_02`

Request:
```json
{
  "event_id": "8dbf87cb-b2d1-4791-bce4-b919cd4f16f4",
  "tenant_id": "tenant_a",
  "subject_id": "subj_pseudo_001",
  "device_id": "dev_44A",
  "captured_at": "2026-02-09T12:30:01Z",
  "signal_type": "hrv",
  "sequence_no": 120034,
  "ciphertext_payload_b64": "<base64>",
  "key_id": "fhekey_2026_02",
  "model_version": "risk-v3.2.1",
  "metadata": {
    "firmware": "1.8.0",
    "sampling_hz": 250,
    "region": "us-east-1"
  }
}
```

Response 202:
```json
{
  "status": "accepted",
  "event_id": "8dbf87cb-b2d1-4791-bce4-b919cd4f16f4",
  "ingest_id": "ing_7f5e00",
  "received_at": "2026-02-09T12:30:02Z"
}
```

### 3.3 `POST /v1/fhe/evaluate`
Purpose: execute homomorphic model operation in Rust service.

Request:
```json
{
  "request_id": "eval_66f7f7",
  "tenant_id": "tenant_a",
  "key_id": "fhekey_2026_02",
  "model_version": "risk-v3.2.1",
  "operation": "risk_score",
  "ciphertexts": ["<base64_ct_1>", "<base64_ct_2>"],
  "policy": {
    "max_depth": 12,
    "min_noise_budget_bits": 20
  }
}
```

Response 200:
```json
{
  "request_id": "eval_66f7f7",
  "status": "completed",
  "result_ciphertext_b64": "<base64>",
  "noise_budget_bits": 27,
  "latency_ms": 84,
  "model_version": "risk-v3.2.1"
}
```

### 3.4 `GET /v1/fhe/metrics`
Purpose: expose Prometheus-compatible operational metrics in restricted network.

Response 200 (example):
```text
fhe_eval_latency_ms_bucket{le="50"} 1289
fhe_eval_noise_budget_bits_avg 27.3
telemetry_ingest_lag_seconds 1.4
idempotency_conflicts_total 5
```

### 3.5 Error model
Canonical error payload:
```json
{
  "error": {
    "code": "INVALID_PAYLOAD",
    "message": "signal_type is unsupported",
    "request_id": "req_f92ab4",
    "retryable": false
  }
}
```

Standard codes:
- `INVALID_PAYLOAD` (400)
- `UNAUTHORIZED` (401)
- `FORBIDDEN` (403)
- `NOT_FOUND` (404)
- `CONFLICT_IDEMPOTENCY` (409)
- `NOISE_BUDGET_EXCEEDED` (422)
- `RATE_LIMITED` (429)
- `INTERNAL_ERROR` (500)
- `UPSTREAM_UNAVAILABLE` (503)

## 4. Data Schema and Event Flow

### 4.1 Data classification map

| Class | Examples | Storage rule | Access rule |
|---|---|---|---|
| Strict PII/PHI | name, DOB, contact info, legal identifiers | `pii_identity_map` only | break-glass + audited RBAC |
| Sensitive telemetry | encrypted biometric features | `telemetry_events` ciphertext-only | service-to-service only |
| Derived analytics | risk score, trend grade, alert status | `analytics_results` | tenant-scoped least privilege |
| Operational metadata | firmware, timings, queue status | logs/metrics with redaction | no direct identifiers |

### 4.2 Canonical relational schema

`telemetry_events`
- `id` uuid pk
- `tenant_id` text indexed
- `event_id` uuid unique per tenant
- `subject_id` text pseudonymized indexed
- `device_id` text
- `captured_at` timestamptz
- `received_at` timestamptz
- `sequence_no` bigint
- `signal_type` text
- `ciphertext_payload` bytea
- `key_id` text
- `model_version` text
- `metadata` jsonb

`evaluation_jobs`
- `id` uuid pk
- `request_id` text unique
- `tenant_id` text indexed
- `event_ref` uuid nullable
- `operation` text
- `status` text (queued|running|completed|failed)
- `noise_budget_bits` int nullable
- `latency_ms` int nullable
- `result_ciphertext` bytea nullable
- `error_code` text nullable
- `created_at` timestamptz
- `updated_at` timestamptz

`fhe_key_versions`
- `key_id` text pk
- `algorithm` text
- `config_name` text
- `public_key` bytea
- `private_key_ref` text (HSM/KMS locator)
- `status` text (active|retiring|retired)
- `created_at` timestamptz
- `activate_at` timestamptz
- `retire_at` timestamptz

`model_registry`
- `model_version` text pk
- `model_hash` text
- `schema_version` text
- `status` text (active|shadow|retired)
- `created_at` timestamptz

`pii_identity_map` (restricted schema)
- `subject_id` text pk
- `tenant_id` text
- `full_name` text
- `dob` date
- `contact_email` text
- `created_at` timestamptz

`audit_log`
- `id` uuid pk
- `actor_id` text
- `actor_type` text (user|service)
- `action` text
- `resource_type` text (pii|telemetry|keys|model)
- `resource_id` text
- `decision` text (allow|deny)
- `reason` text
- `timestamp` timestamptz
- `request_id` text

### 4.3 Event flow (real-time + batch fallback)
1. Device captures telemetry and computes privacy-minimized features.
2. Device requests active public key from `GET /v1/fhe/public-key`.
3. Device encrypts locally and sends event to `POST /v1/telemetry/events`.
4. Gateway validates auth, schema, key status, and idempotency.
5. Gateway writes to streaming bus (Kinesis or MSK).
6. If stream is degraded, gateway stores encrypted payload in S3 replay bucket.
7. FHE service evaluates ciphertext and writes result metadata.
8. Result policy service decrypts only minimum-necessary outputs.
9. Analytics DB stores derived values; PII joins require privileged audited workflow.

### 4.4 Idempotency, ordering, and replay
- Unique `(tenant_id, event_id)` in `telemetry_events`.
- Unique `request_id` in `evaluation_jobs`.
- Re-order by `sequence_no` with `captured_at` tie-breaker.
- Replay jobs dedupe deterministically on tenant + event id.

### 4.5 Key rotation and model versioning
- Default key rotation cadence: every 30 days.
- Emergency rotation path on compromise signal.
- Gateway accepts active and retiring keys during transition window.
- Evaluations record immutable `key_id` + `model_version` for auditability.
- Model artifacts are hash-validated before activation.

## 5. Security and Compliance Checklist (HIPAA + GDPR)

### 5.1 Baseline controls
- [ ] TLS 1.2+ on all external traffic; mTLS on service mesh/internal calls.
- [ ] KMS/HSM-backed key storage and enforced rotation policies.
- [ ] Immutable centralized audit logs with sensitive-field redaction.
- [ ] Strict RBAC, least privilege, and short-lived credentials.
- [ ] Segmented network zones for gateway, FHE compute, and decrypt policy service.
- [ ] Privacy-preserving observability (no raw biometrics in logs/metrics).

### 5.2 HIPAA controls
- [ ] Signed BAA with cloud and subprocessors.
- [ ] Documented administrative/technical safeguards for PHI.
- [ ] Access control + audit trail coverage for all PHI access.
- [ ] Breach response workflow with contractual notification timelines.

### 5.3 GDPR controls
- [ ] Document lawful basis and consent capture per tenant use case.
- [ ] DPIA completed for biometric processing.
- [ ] DSAR workflows: export, correction, deletion, processing restriction.
- [ ] Data residency and cross-border transfer controls documented.

### 5.4 Data retention baseline
- Telemetry ciphertext: 180 days hot, 365 days archive.
- Derived risk outputs: 365 days.
- PII mapping: contract term + legal hold policy.
- Audit logs: 6 years minimum for regulated tenants.
- Backup retention: 35 days rolling, encrypted, regional redundancy.

### 5.5 Breach/key compromise workflow
1. Trigger incident from SIEM/CloudWatch anomaly.
2. Move impacted key to `retiring`, then `retired`.
3. Rotate credentials and publish new active key id.
4. Revoke impacted tokens/sessions and constrain access scopes.
5. Execute legal/compliance notifications.
6. Publish post-incident corrective-action report.

## 6. Performance Baseline Plan

### 6.1 SLO candidates
- P95 `/v1/telemetry/events` accept latency <= 120 ms.
- P95 `/v1/fhe/evaluate` latency <= 250 ms.
- Evaluation success rate >= 99.5%.
- Noise budget floor >= 20 bits.
- Error rate (5xx) <= 0.5% at expected tenant load.

### 6.2 Baseline validation matrix
- Core crypto validation:
  - `cargo test -p nine65 --lib --release`
  - `cargo test --release --exclude nine65-python --exclude nine65-wasm`
- Supporting crates after touched changes:
  - `cargo test -p mana --release`
  - `cargo test -p clockwork-core --release`
  - `cargo test -p nexgen_rational --release`
  - `cargo test -p unhal --release`
- Load/soak checks:
  - stream ingest sustained + burst load
  - FHE evaluate concurrency sweeps (1x, 5x, 10x)
  - S3 replay throughput under outage simulation

### 6.3 Metrics and dashboards
- `fhe_eval_latency_ms` (p50/p95/p99)
- `fhe_eval_noise_budget_bits`
- `telemetry_ingest_lag_seconds`
- `idempotency_conflicts_total`
- `decrypt_requests_total` (policy-approved)
- `authz_denied_total`

## 7. Release Checklist and Operational Runbook

### 7.1 Release checklist
- [ ] Architecture docs include explicit NINE65 v5 pre-production warning.
- [ ] Active runtime config is `SecureConfig::secure_192()`.
- [ ] API compatibility tests pass between gateway and FHE service.
- [ ] Security review verifies IAM scope and secrets handling.
- [ ] Logging review confirms no plaintext biometric leakage.
- [ ] Key rotation and rollback validated in staging.
- [ ] Observability alerts configured for latency/noise/auth anomalies.
- [ ] Canary rollout passes SLO gates before full tenant rollout.
- [ ] Performance + security artifacts archived with release metadata.

### 7.2 Operational runbook
Normal operations:
- Review ingest lag, evaluation latency, noise floor, and error budgets each shift.
- Review denied-access and break-glass audit events daily.

High-latency incident:
1. Inspect queue depth and worker saturation.
2. Shift non-critical workloads and defer replay traffic.
3. Scale FHE workers and confirm SLO recovery.

Noise budget incident:
1. Block model versions below minimum noise threshold.
2. Route to safe fallback profile.
3. Trigger model and parameter review.

Stream outage:
1. Enable encrypted S3 batch fallback ingest.
2. Resume stream path once healthy.
3. Replay from S3 with deterministic idempotent dedupe.

Key compromise:
1. Trigger emergency key rotation and revoke affected scopes.
2. Freeze decrypt operations except approved emergency workflows.
3. Follow breach notification workflow and post-incident audit.

## 8. Frontend UX and Product Dashboard Handoff

UI polish checklist:
- Distinct typography and palette with consistent spacing rhythm.
- Executive KPI cards plus deep technical FHE views.
- Clear loading, empty, and error recovery states.
- WCAG AA contrast, keyboard navigation, and focus visibility.
- Lazy-loaded chart bundles and client performance instrumentation.

Required dashboard modules:
- Privacy posture: PII access attempts, denied actions, redaction coverage.
- FHE health: latency percentiles, noise budget by model version, failure reasons.
- Ingestion quality: event ordering drift, duplicate suppression, stream lag.
- Compliance ops: DSAR SLA tracker, retention window status, incident timeline.

## 9. Delivery Notes

This architecture pack is ready for design and implementation kickoff, with streaming ingestion and batch fallback included by default.

Hard constraint before external production commitments:
- NINE65 v5 remains pre-production and must not be represented as production-ready until security findings are formally closed.
