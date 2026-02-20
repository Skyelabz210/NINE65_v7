import { NextResponse } from "next/server";
import { fetchFhe } from "@/lib/fhe";
import { errorResponse, requireBearerAuth } from "@/lib/http";

export async function GET(request: Request) {
  const authError = requireBearerAuth(request);
  if (authError) {
    return authError;
  }

  try {
    const upstream = await fetchFhe("/v1/fhe/public-key", {
      method: "GET",
      headers: {
        authorization: request.headers.get("authorization") ?? ""
      }
    });

    const text = await upstream.text();
    const payload = text ? JSON.parse(text) : {};

    if (!upstream.ok) {
      return NextResponse.json(payload, { status: upstream.status });
    }

    return NextResponse.json(payload, { status: 200 });
  } catch {
    return errorResponse(503, "UPSTREAM_UNAVAILABLE", "FHE service is unavailable", true);
  }
}
