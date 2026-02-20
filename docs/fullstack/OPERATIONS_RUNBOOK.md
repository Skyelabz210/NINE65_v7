# Operations Runbook: Telemetry + NINE65 FHE

**Date**: 2026-02-09  
**Scope**: `gateway-service`, `fhe-service`, `result-service`  
**NINE65 status**: pre-production

## 1. On-call scope
- Keep ingest and evaluation within SLO.
- Protect key material and decrypt boundaries.
- Maintain auditability for PHI/PII access paths.

## 2. Golden signals and SLO targets
- Ingest P95 latency (`/v1/telemetry/events`): <= 120 ms
- Evaluate P95 latency (`/v1/fhe/evaluate`): <= 250 ms
- Evaluation success rate: >= 99.5%
- Min completion noise budget: >= 20 bits
- Error budget burn alert: page when 2-hour burn rate exceeds 2x baseline

## 3. Alert routing and severity
- `SEV-1`: active key compromise, unauthorized decryption, data exfiltration indicators.
- `SEV-2`: prolonged ingest outage, sustained >2x latency SLO breach, stream replay failure.
- `SEV-3`: isolated tenant failures, recoverable backlog growth, intermittent high error bursts.

## 4. Standard dashboards
- API latency and error rates by endpoint and tenant.
- Queue lag and replay backlog depth.
- FHE noise budget distribution by model version.
- AuthZ deny spikes and PII access attempts.
- Decrypt request counts by policy and actor.

## 5. Incident playbooks

## 5.1 High latency (`SEV-2` or `SEV-3`)
1. Verify whether issue is ingress, stream, FHE workers, or downstream storage.
2. Check queue depth and worker saturation.
3. Temporarily reduce non-critical batch workloads.
4. Scale FHE workers and verify CPU/memory headroom.
5. Re-check P95, P99, and noise budget floor.
6. Close incident only after 30 minutes of stable metrics.

## 5.2 Noise budget exhaustion (`SEV-2`)
1. Identify impacted model versions and operations.
2. Enforce safe fallback profile with lower homomorphic depth.
3. Block offending model versions from new requests.
4. Notify model owner and cryptography owner.
5. Record evidence and patch policy thresholds.

## 5.3 Stream outage and replay (`SEV-2`)
1. Switch ingest to encrypted S3 fallback mode.
2. Confirm idempotency checks are active.
3. Restore stream transport path.
4. Replay fallback objects in ordered windows.
5. Monitor duplicate conflicts and replay lag to zero.

## 5.4 Key compromise or unauthorized decrypt (`SEV-1`)
1. Freeze key state (`active` -> `retiring` -> `retired`).
2. Rotate key material and issue new key id.
3. Revoke active service tokens and privileged sessions.
4. Disable decrypt workflows except incident channel.
5. Engage legal/compliance notification path.
6. Publish post-incident report with root cause and corrective actions.

## 6. Change management checklist
- Verify staging canary before production rollout.
- Confirm API backward compatibility on all changed endpoints.
- Confirm no plaintext biometrics in logs/traces.
- Verify audit log coverage for PII and key operations.
- Confirm rollback procedure and owner for each deployment.

## 7. Daily and weekly ops cadence
- Daily:
  - Review ingest/evaluate SLO dashboards.
  - Review audit denies and unusual access attempts.
  - Verify key expiry horizon and pending rotations.
- Weekly:
  - Run replay drill on synthetic ciphertext batches.
  - Validate DSAR export/delete workflow path.
  - Review on-call incident trends and action items.

## 8. Evidence and postmortem templates
- Evidence minimum:
  - timeline (UTC),
  - impacted tenants,
  - request IDs and key IDs,
  - metrics screenshots or exports,
  - containment and recovery actions.
- Postmortem must include:
  - root cause,
  - blast radius,
  - control failures,
  - remediation owners and due dates.
