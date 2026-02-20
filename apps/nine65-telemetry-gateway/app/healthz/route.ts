import { NextResponse } from "next/server";
import { config } from "@/lib/config";

export async function GET() {
  return NextResponse.json({
    status: "ok",
    service: config.gatewayServiceName,
    version: config.gatewayVersion,
    timestamp: new Date().toISOString(),
    mode: "pre-production"
  });
}
