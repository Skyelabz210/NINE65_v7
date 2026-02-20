import { NextResponse } from "next/server";

export async function POST() {
  return NextResponse.json(
    {
      status: "error",
      message: "Deprecated endpoint. Use /v1/telemetry/events instead."
    },
    { status: 410 }
  );
}
