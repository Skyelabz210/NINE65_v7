type GatewayCounter =
  | "ingest_accepted_total"
  | "ingest_rejected_total"
  | "ingest_conflicts_total"
  | "fhe_forward_errors_total";

const counters: Record<GatewayCounter, number> = {
  ingest_accepted_total: 0,
  ingest_rejected_total: 0,
  ingest_conflicts_total: 0,
  fhe_forward_errors_total: 0
};

export function increment(counter: GatewayCounter) {
  counters[counter] += 1;
}

export function renderGatewayMetrics(): string {
  return [
    "# HELP gateway_ingest_accepted_total Accepted telemetry ingest requests",
    "# TYPE gateway_ingest_accepted_total counter",
    `gateway_ingest_accepted_total ${counters.ingest_accepted_total}`,
    "# HELP gateway_ingest_rejected_total Rejected telemetry ingest requests",
    "# TYPE gateway_ingest_rejected_total counter",
    `gateway_ingest_rejected_total ${counters.ingest_rejected_total}`,
    "# HELP gateway_ingest_conflicts_total Duplicate idempotency or event conflicts",
    "# TYPE gateway_ingest_conflicts_total counter",
    `gateway_ingest_conflicts_total ${counters.ingest_conflicts_total}`,
    "# HELP gateway_fhe_forward_errors_total Errors forwarding to FHE service",
    "# TYPE gateway_fhe_forward_errors_total counter",
    `gateway_fhe_forward_errors_total ${counters.fhe_forward_errors_total}`
  ].join("\n");
}
