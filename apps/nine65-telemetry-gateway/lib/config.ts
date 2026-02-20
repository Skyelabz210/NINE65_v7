const DEFAULT_FHE_SERVICE_URL = "http://127.0.0.1:8080";
const DEFAULT_GATEWAY_SERVICE_NAME = "nine65-telemetry-gateway";
const DEFAULT_GATEWAY_VERSION = "0.1.0";
const DEFAULT_INTERNAL_EVAL_TOKEN = "dev-internal-token";

export const config = {
  fheServiceUrl: process.env.FHE_SERVICE_URL ?? DEFAULT_FHE_SERVICE_URL,
  gatewayServiceName:
    process.env.GATEWAY_SERVICE_NAME ?? DEFAULT_GATEWAY_SERVICE_NAME,
  gatewayVersion: process.env.GATEWAY_VERSION ?? DEFAULT_GATEWAY_VERSION,
  internalEvalToken:
    process.env.INTERNAL_EVAL_TOKEN ?? DEFAULT_INTERNAL_EVAL_TOKEN
};
