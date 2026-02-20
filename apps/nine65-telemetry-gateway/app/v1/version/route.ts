import { NextResponse } from "next/server";
import { config } from "@/lib/config";
import { fetchFhe } from "@/lib/fhe";
import { requireBearerAuth } from "@/lib/http";

export async function GET(request: Request) {
  const authError = requireBearerAuth(request);
  if (authError) {
    return authError;
  }

  let fheVersion: unknown = null;
  let fheReachable = false;

  try {
    const upstream = await fetchFhe("/v1/version", {
      method: "GET",
      headers: {
        authorization: request.headers.get("authorization") ?? ""
      }
    });

    fheReachable = upstream.ok;
    if (upstream.ok) {
      fheVersion = await upstream.json();
    }
  } catch {
    fheReachable = false;
  }

  return NextResponse.json({
    service: config.gatewayServiceName,
    version: config.gatewayVersion,
    config: "SecureConfig::secure_192()",
    mode: "pre-production",
    fhe_upstream_reachable: fheReachable,
    fhe_upstream: fheVersion
  });
}
