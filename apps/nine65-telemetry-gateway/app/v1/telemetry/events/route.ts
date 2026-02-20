import { NextResponse } from "next/server";
import type { Prisma } from "@prisma/client";
import { db } from "@/lib/db";
import { fetchFhe } from "@/lib/fhe";
import { errorResponse, makeRequestId, requireBearerAuth } from "@/lib/http";
import { increment } from "@/lib/metrics";
import { TelemetryEventRequestSchema } from "@/lib/telemetry";

function decodeBase64(input: string): Buffer {
  return Buffer.from(input, "base64");
}

function safeJsonParse(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

export const runtime = "nodejs";

export async function POST(request: Request) {
  const authError = requireBearerAuth(request);
  if (authError) {
    increment("ingest_rejected_total");
    return authError;
  }

  const idempotencyKey = request.headers.get("idempotency-key");
  const keyHeader = request.headers.get("x-key-id");
  if (!idempotencyKey) {
    increment("ingest_rejected_total");
    return errorResponse(400, "INVALID_PAYLOAD", "Missing Idempotency-Key header");
  }

  const requestId = makeRequestId();
  const payload = await request.json().catch(() => null);
  const parsed = TelemetryEventRequestSchema.safeParse(payload);

  if (!parsed.success) {
    increment("ingest_rejected_total");
    return errorResponse(400, "INVALID_PAYLOAD", "Malformed telemetry payload", false, requestId);
  }

  const body = parsed.data;

  if (keyHeader && keyHeader !== body.key_id) {
    increment("ingest_rejected_total");
    return errorResponse(
      400,
      "INVALID_PAYLOAD",
      "X-Key-Id header must match key_id in payload",
      false,
      requestId
    );
  }

  const duplicateEvent = await db.telemetryEvent.findUnique({
    where: {
      tenantId_eventId: {
        tenantId: body.tenant_id,
        eventId: body.event_id
      }
    }
  });

  if (duplicateEvent) {
    increment("ingest_conflicts_total");
    return errorResponse(
      409,
      "CONFLICT_IDEMPOTENCY",
      "Duplicate event for tenant",
      false,
      requestId
    );
  }

  const duplicateIdempotency = await db.telemetryEvent.findUnique({
    where: {
      tenantId_idempotencyKey: {
        tenantId: body.tenant_id,
        idempotencyKey
      }
    }
  });

  if (duplicateIdempotency) {
    increment("ingest_conflicts_total");
    return errorResponse(
      409,
      "CONFLICT_IDEMPOTENCY",
      "Idempotency key already used for tenant",
      false,
      requestId
    );
  }

  const createdEvent = await db.telemetryEvent.create({
    data: {
      tenantId: body.tenant_id,
      eventId: body.event_id,
      idempotencyKey,
      subjectId: body.subject_id,
      deviceId: body.device_id,
      capturedAt: new Date(body.captured_at),
      receivedAt: new Date(),
      sequenceNo: BigInt(body.sequence_no),
      signalType: body.signal_type,
      ciphertextPayload: decodeBase64(body.ciphertext_payload_b64),
      keyId: body.key_id,
      modelVersion: body.model_version,
      metadata: body.metadata as Prisma.InputJsonValue
    }
  });

  const evaluateRequest = {
    request_id: makeRequestId(),
    tenant_id: body.tenant_id,
    key_id: body.key_id,
    model_version: body.model_version,
    operation: "risk_score",
    ciphertexts: [body.ciphertext_payload_b64],
    policy: {
      max_depth: 12,
      min_noise_budget_bits: 20
    }
  };

  const evaluationJob = await db.evaluationJob.create({
    data: {
      requestId: evaluateRequest.request_id,
      tenantId: body.tenant_id,
      eventRef: createdEvent.id,
      operation: evaluateRequest.operation,
      status: "queued"
    }
  });

  try {
    const upstream = await fetchFhe("/v1/fhe/evaluate", {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify(evaluateRequest)
    });

    const text = await upstream.text();
    const payloadJson = safeJsonParse(text) as
      | {
          noise_budget_bits?: number;
          latency_ms?: number;
          result_ciphertext_b64?: string;
          error?: { code?: string };
        }
      | null;

    if (!upstream.ok) {
      await db.evaluationJob.update({
        where: { id: evaluationJob.id },
        data: {
          status: "failed",
          errorCode: payloadJson?.error?.code ?? "UPSTREAM_UNAVAILABLE"
        }
      });
      increment("fhe_forward_errors_total");
    } else {
      await db.evaluationJob.update({
        where: { id: evaluationJob.id },
        data: {
          status: "completed",
          noiseBudgetBits: payloadJson?.noise_budget_bits,
          latencyMs: payloadJson?.latency_ms,
          resultCiphertext: payloadJson?.result_ciphertext_b64
            ? decodeBase64(payloadJson.result_ciphertext_b64)
            : null
        }
      });
    }
  } catch {
    await db.evaluationJob.update({
      where: { id: evaluationJob.id },
      data: {
        status: "failed",
        errorCode: "UPSTREAM_UNAVAILABLE"
      }
    });
    increment("fhe_forward_errors_total");
  }

  increment("ingest_accepted_total");

  return NextResponse.json(
    {
      status: "accepted",
      event_id: body.event_id,
      ingest_id: evaluationJob.id,
      received_at: createdEvent.receivedAt.toISOString()
    },
    { status: 202 }
  );
}
