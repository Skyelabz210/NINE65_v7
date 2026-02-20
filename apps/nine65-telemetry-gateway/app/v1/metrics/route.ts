import { fetchFhe } from "@/lib/fhe";
import { requireBearerAuth } from "@/lib/http";
import { renderGatewayMetrics } from "@/lib/metrics";

export async function GET(request: Request) {
  const authError = requireBearerAuth(request);
  if (authError) {
    return authError;
  }

  let upstreamMetrics = "";
  try {
    const response = await fetchFhe("/v1/metrics", {
      method: "GET",
      headers: {
        authorization: request.headers.get("authorization") ?? ""
      }
    });
    upstreamMetrics = await response.text();
  } catch {
    upstreamMetrics = "# upstream fhe metrics unavailable";
  }

  const body = [
    "# gateway metrics",
    renderGatewayMetrics(),
    "",
    "# fhe service metrics",
    upstreamMetrics
  ].join("\n");

  return new Response(body, {
    status: 200,
    headers: {
      "content-type": "text/plain; version=0.0.4"
    }
  });
}
