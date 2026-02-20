# Implementation Backlog (Execution Order)

**Date**: 2026-02-09  
**Source**: `docs/FULLSTACK_FHE_ARCHITECTURE_PACK_2026-02-09.md`  
**Target**: first integrated staging release

## Phase 1: Security-critical foundation

1. Gateway authN/authZ hardening
- Owner: backend platform
- Deliverable: JWT validation, tenant scoping, RBAC policy checks
- Acceptance: unauthorized and cross-tenant requests are rejected in integration tests

2. Key service boundary enforcement
- Owner: cryptography platform
- Deliverable: ensure secret keys never leave Rust FHE service boundary
- Acceptance: static checks and runtime assertions prove Node layer handles ciphertext only

3. Idempotency and replay safety
- Owner: backend platform
- Deliverable: unique constraints and idempotency key handling in ingest path
- Acceptance: duplicate telemetry replay does not create duplicate downstream jobs

4. Audit logging baseline
- Owner: security engineering
- Deliverable: immutable audit log for PII/key/decrypt access
- Acceptance: all privileged actions include actor, request id, decision, and timestamp

## Phase 2: Functional integration

1. Implement OpenAPI endpoints
- Owner: backend platform
- Deliverable: `/healthz`, `/v1/version`, `/v1/fhe/public-key`, `/v1/telemetry/events`, `/v1/fhe/evaluate`, `/v1/metrics`
- Acceptance: contract tests pass against `docs/fullstack/OPENAPI_TELEMETRY_FHE_V1.yaml`

2. Database schema migration
- Owner: data platform
- Deliverable: migrate canonical tables in `docs/fullstack/PRISMA_SCHEMA_TELEMETRY_FHE.prisma`
- Acceptance: migration + rollback verified in staging

3. Stream and batch fallback wiring
- Owner: platform engineering
- Deliverable: Kinesis/MSK real-time pipeline + S3 fallback replay job
- Acceptance: outage simulation shows successful replay with dedupe

4. FHE evaluation policy enforcement
- Owner: cryptography platform
- Deliverable: max depth and minimum noise budget checks in eval path
- Acceptance: requests violating policy return `NOISE_BUDGET_EXCEEDED`

## Phase 3: Observability and operations

1. SLO and dashboard rollout
- Owner: SRE
- Deliverable: latency, error, noise budget, and replay lag dashboards
- Acceptance: alert thresholds verified in synthetic load test

2. Incident runbook drill
- Owner: SRE + security engineering
- Deliverable: execute high-latency and key-compromise tabletop using `docs/fullstack/OPERATIONS_RUNBOOK.md`
- Acceptance: action timings and escalation paths documented and signed off

3. Compliance controls validation
- Owner: compliance + security engineering
- Deliverable: DPIA, DSAR flows, retention enforcement checks
- Acceptance: HIPAA/GDPR checklist fully complete for staging gate

## Phase 4: Frontend and product readiness

1. Privacy posture dashboard
- Owner: frontend platform
- Deliverable: FHE latency, noise health, and audit signal panels
- Acceptance: WCAG AA checks pass and dashboards load under target budget

2. Empty/error/loading state polish
- Owner: frontend platform
- Deliverable: resilient UX for ingest and analytics screens
- Acceptance: UX checklist completion and QA sign-off

3. Canary release and rollback rehearsal
- Owner: release engineering
- Deliverable: staged deployment with measured SLO adherence
- Acceptance: canary success criteria met, rollback tested and documented

## Gate criteria for staging readiness
- Security controls in Phase 1 complete.
- API + DB + stream integration in Phase 2 complete.
- Observability and incident readiness in Phase 3 complete.
- Frontend and canary checks in Phase 4 complete.
