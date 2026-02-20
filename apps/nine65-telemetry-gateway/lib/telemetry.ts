import { z } from "zod";

export const TelemetryMetadataSchema = z
  .record(z.string(), z.unknown())
  .optional()
  .default({});

export const TelemetryEventRequestSchema = z.object({
  event_id: z.string().uuid(),
  tenant_id: z.string().min(1),
  subject_id: z.string().min(3),
  device_id: z.string().min(3),
  captured_at: z.string().datetime(),
  signal_type: z.string().min(2),
  sequence_no: z.number().int().nonnegative(),
  ciphertext_payload_b64: z.string().min(8),
  key_id: z.string().min(3),
  model_version: z.string().min(1),
  metadata: TelemetryMetadataSchema
});

export type TelemetryEventRequest = z.infer<typeof TelemetryEventRequestSchema>;

export const FheEvaluatePolicySchema = z.object({
  max_depth: z.number().int().positive().max(32),
  min_noise_budget_bits: z.number().int().min(1).max(128)
});

export const FheEvaluateRequestSchema = z.object({
  request_id: z.string().min(3),
  tenant_id: z.string().min(1),
  key_id: z.string().min(3),
  model_version: z.string().min(1),
  operation: z.string().min(2),
  ciphertexts: z.array(z.string().min(8)).min(1),
  policy: FheEvaluatePolicySchema
});

export type FheEvaluateRequest = z.infer<typeof FheEvaluateRequestSchema>;
