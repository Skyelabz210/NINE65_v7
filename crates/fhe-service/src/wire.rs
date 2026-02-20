//! Wire types — serde request/response types for the JSON API.

use serde::{Deserialize, Serialize};

/// Maximum length of any single string field in a request (non-ciphertext).
const MAX_STRING_FIELD_LEN: usize = 1024;

/// Maximum length of a single ciphertext field.
/// N=16384 (secure_256) with 2 polynomials × 16384 × 8 bytes × 4/3 base64 ≈ 350 KB.
const MAX_CIPHERTEXT_FIELD_LEN: usize = 512 * 1024;

/// Maximum total allocation per request to prevent memory amplification attacks.
/// Limits total ciphertext data per request to prevent 512MB+ allocations.
const MAX_REQUEST_ALLOCATION: usize = 64 * 1024 * 1024; // 64 MB per request

// ============================================================================
// Session requests / responses
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateSessionRequest {
    /// Config name: "secure_128", "secure_192", "secure_256"
    pub config: String,
}

#[derive(Debug, Serialize)]
pub struct CreateSessionResponse {
    pub session_id: String,
    pub config: String,
    pub params: SessionParams,
    /// Upper-bound heuristic estimate; actual noise may be lower.
    pub noise_budget_estimate_millibits: i64,
}

#[derive(Debug, Serialize)]
pub struct SessionParams {
    pub n: usize,
    pub log_q: u32,
    pub t: u64,
    pub security_bits: usize,
}

#[derive(Debug, Serialize)]
pub struct SessionInfoResponse {
    pub session_id: String,
    pub config: String,
    /// Upper-bound heuristic estimate; actual noise may be lower.
    pub noise_budget_estimate_millibits: i64,
    pub operation_count: u64,
    pub created_at: u64,
}

// ============================================================================
// Encrypt / Decrypt
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct EncryptRequest {
    /// Values to encrypt (each < t)
    pub values: Vec<u64>,
}

#[derive(Debug, Serialize)]
pub struct EncryptResponse {
    /// Base64-encoded bincode ciphertexts
    pub ciphertexts: Vec<String>,
    /// Upper-bound heuristic estimate; actual noise may be lower.
    pub noise_budget_estimate_millibits: i64,
}

#[derive(Debug, Deserialize)]
pub struct DecryptRequest {
    /// Base64-encoded bincode ciphertexts
    pub ciphertexts: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DecryptResponse {
    pub values: Vec<u64>,
    /// Upper-bound heuristic estimate; actual noise may be lower.
    pub noise_budget_estimate_millibits: i64,
}

// ============================================================================
// Evaluate
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct EvaluateRequest {
    pub operations: Vec<Operation>,
}

#[derive(Debug, Deserialize)]
pub struct Operation {
    /// Operation type: "add", "sub", "negate", "add_plain", "mul_plain", "mul"
    pub op: String,
    /// Base64-encoded ciphertext inputs
    pub inputs: Vec<String>,
    /// Scalar for add_plain / mul_plain
    #[serde(default)]
    pub scalar: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct EvaluateResponse {
    /// Base64-encoded result ciphertexts (one per operation)
    pub results: Vec<String>,
    /// Upper-bound heuristic estimate; actual noise may be lower.
    pub noise_budget_estimate_millibits: i64,
    pub operation_count: u64,
}

// ============================================================================
// Validation
// ============================================================================

impl CreateSessionRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.config.len() > MAX_STRING_FIELD_LEN {
            return Err("config name too long");
        }
        match self.config.as_str() {
            "secure_128" | "secure_192" | "secure_256" => Ok(()),
            _ => Err("unsupported config; use secure_128, secure_192, or secure_256"),
        }
    }
}

impl EncryptRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.values.is_empty() {
            return Err("values must not be empty");
        }
        if self.values.len() > 1024 {
            return Err("too many values (max 1024)");
        }
        Ok(())
    }
}

impl DecryptRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.ciphertexts.is_empty() {
            return Err("ciphertexts must not be empty");
        }
        if self.ciphertexts.len() > 1024 {
            return Err("too many ciphertexts (max 1024)");
        }

        // Check aggregate allocation to prevent memory amplification
        let total_allocation: usize = self.ciphertexts.iter().map(|ct| ct.len()).sum();
        if total_allocation > MAX_REQUEST_ALLOCATION {
            return Err("total request allocation exceeds limit");
        }

        for ct in &self.ciphertexts {
            if ct.len() > MAX_CIPHERTEXT_FIELD_LEN {
                return Err("ciphertext field too large");
            }
        }
        Ok(())
    }
}

impl EvaluateRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.operations.is_empty() {
            return Err("operations must not be empty");
        }
        if self.operations.len() > 256 {
            return Err("too many operations (max 256)");
        }

        // Check aggregate allocation to prevent memory amplification
        let total_allocation: usize = self
            .operations
            .iter()
            .flat_map(|op| &op.inputs)
            .map(|input| input.len())
            .sum();
        if total_allocation > MAX_REQUEST_ALLOCATION {
            return Err("total request allocation exceeds limit");
        }

        for op in &self.operations {
            if op.op.len() > 32 {
                return Err("operation name too long");
            }
            if op.inputs.is_empty() {
                return Err("operation must have at least one input");
            }
            if op.inputs.len() > 4 {
                return Err("operation has too many inputs (max 4)");
            }
            for input in &op.inputs {
                if input.len() > MAX_CIPHERTEXT_FIELD_LEN {
                    return Err("ciphertext input field too large");
                }
            }
        }
        Ok(())
    }
}
