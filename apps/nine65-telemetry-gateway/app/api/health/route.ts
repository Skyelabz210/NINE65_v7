import { NextResponse } from "next/server";

export async function GET() {
  return NextResponse.json(
    {
      status: "ok",
      service: "nine65-telemetry-gateway",
      deprecated: true,
      replacement: "/healthz",
      timestamp: new Date().toISOString()
    },
    { status: 200 }
  );
}
