import { NextResponse } from "next/server";
import { fetchFhe } from "@/lib/fhe";
import { errorResponse } from "@/lib/http";
import { FheEvaluateRequestSchema } from "@/lib/telemetry";

export async function POST(request: Request) {
  const internalToken = request.headers.get("x-internal-token");
  if (!internalToken || internalToken !== process.env.INTERNAL_EVAL_TOKEN) {
    return errorResponse(403, "FORBIDDEN", "Missing or invalid internal token");
  }

  const payload = await request.json().catch(() => null);
  const parsed = FheEvaluateRequestSchema.safeParse(payload);
  if (!parsed.success) {
    return errorResponse(400, "INVALID_PAYLOAD", "Malformed evaluate payload");
  }

  try {
    const upstream = await fetchFhe("/v1/fhe/evaluate", {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify(parsed.data)
    });

    const text = await upstream.text();
    const responsePayload = text ? JSON.parse(text) : {};
    return NextResponse.json(responsePayload, { status: upstream.status });
  } catch {
    return errorResponse(503, "UPSTREAM_UNAVAILABLE", "FHE service is unavailable", true);
  }
}
