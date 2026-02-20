import { NextResponse } from "next/server";

export function makeRequestId(): string {
  return globalThis.crypto?.randomUUID?.() ?? `req_${Date.now()}`;
}

export function errorResponse(
  status: number,
  code: string,
  message: string,
  retryable = false,
  requestId = makeRequestId()
) {
  return NextResponse.json(
    {
      error: {
        code,
        message,
        request_id: requestId,
        retryable
      }
    },
    { status }
  );
}

export function requireBearerAuth(request: Request) {
  const authorization = request.headers.get("authorization");
  if (!authorization || !authorization.startsWith("Bearer ")) {
    return errorResponse(401, "UNAUTHORIZED", "Missing or invalid bearer token");
  }

  return null;
}
