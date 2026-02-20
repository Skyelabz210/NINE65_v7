//! End-to-End SEBV Pipeline
//!
//! Complete integration demonstrating the full Shadow Entropy Behavioral
//! Verification flow from raw behavioral data to encrypted classification.
//!
//! # Pipeline Stages
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                        CLIENT SIDE                                  │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │  1. Behavioral Data → SEBV Entropy Battery → CognitiveEntropyVector │
//! │  2. Entropy Vector → FHE Encryption → N65EncryptedEntropy           │
//! │  3. Shadow Entropy Harvest → ShadowSignature                        │
//! │  4. Send: (EncryptedEntropy, Signature) → Server                    │
//! └─────────────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                        SERVER SIDE                                  │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │  5. Verify Signature (timestamp, nonce, integrity)                  │
//! │  6. Homomorphic Classification (weighted distance)                  │
//! │  7. Return: EncryptedDistances → Client                             │
//! └─────────────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                      CLIENT FINAL                                   │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │  8. Decrypt Distances → ClassificationResult                        │
//! │  9. (Optional) Send aggregate feedback for Q-learning               │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Security Properties
//!
//! - THEOREM FHE1: Server sees only ciphertexts (semantic security)
//! - THEOREM SIG1: Signatures are non-replayable
//! - THEOREM SIG2: Signatures are non-precomputable
//! - THEOREM CE1: Human/bot separation in 4D entropy space

use crate::{
    ClassificationResult,
    entropy::compute_cognitive_entropy_default,
    policy::ClassificationPolicy,
    signature::{SignatureHarvester, ShadowSignature, SignatureVerifier, VerificationResult},
    nine65_fhe::{
        FHEContext, N65EncryptedEntropy, N65EncryptedPolicy,
        N65EncryptedClassification, classify_encrypted, decrypt_and_classify,
    },
    avatar::{SEBVAvatar, CulturalIdentity},
    learning::ClassificationFeedback,
};

/// Client-side SEBV context
pub struct SEBVClient {
    /// FHE context for encryption/decryption
    fhe_ctx: FHEContext,
    /// Signature harvester
    harvester: SignatureHarvester,
    /// User's behavioral avatar
    avatar: SEBVAvatar,
    /// Current session nonce (from server)
    session_nonce: Option<[u8; 16]>,
}

impl SEBVClient {
    /// Create new client
    pub fn new(user_id: u64) -> Self {
        Self {
            fhe_ctx: FHEContext::new(),
            harvester: SignatureHarvester::from_timestamp(),
            avatar: SEBVAvatar::new(user_id),
            session_nonce: None,
        }
    }
    
    /// Create with cultural identity
    pub fn with_culture(user_id: u64, culture: CulturalIdentity) -> Self {
        Self {
            fhe_ctx: FHEContext::new(),
            harvester: SignatureHarvester::from_timestamp(),
            avatar: SEBVAvatar::with_cultural_identity(user_id, culture),
            session_nonce: None,
        }
    }
    
    /// Set session nonce from server
    pub fn set_nonce(&mut self, nonce: [u8; 16]) {
        self.session_nonce = Some(nonce);
    }
    
    /// Set session nonce from u128
    pub fn set_nonce_u128(&mut self, nonce: u128) {
        self.session_nonce = Some(nonce.to_le_bytes());
    }
    
    /// Process behavioral data and create verification request
    ///
    /// Returns encrypted entropy and signature for server verification
    pub fn create_verification_request(
        &mut self,
        behavioral_data: &[i64],
    ) -> Result<VerificationRequest, PipelineError> {
        let nonce = self.session_nonce.ok_or(PipelineError::NoNonce)?;
        
        // Stage 1: Compute cognitive entropy
        // Feed behavioral data into harvester for shadow extraction
        self.harvester.feed_many(behavioral_data);
        let entropy = compute_cognitive_entropy_default(behavioral_data);
        
        // Update avatar with new behavioral data
        self.avatar.update_from_behavior(behavioral_data);
        
        // Stage 2: Encrypt entropy vector
        let encrypted_entropy = N65EncryptedEntropy::encrypt(&entropy, &self.fhe_ctx);
        
        // Stage 3: Generate shadow signature
        // Extract shadow entropy from computation
        let shadow = self.harvester.extract_shadow();
        let signature = ShadowSignature::create(entropy, shadow, nonce);
        
        Ok(VerificationRequest {
            encrypted_entropy,
            signature,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        })
    }
    
    /// Process server response and get classification result
    pub fn process_response(
        &self,
        response: &VerificationResponse,
    ) -> ClassificationResult {
        decrypt_and_classify(
            &response.encrypted_result,
            response.threshold,
            &self.fhe_ctx,
        )
    }
    
    /// Process feedback for learning
    pub fn process_feedback(&mut self, feedback: &[ClassificationFeedback]) {
        self.avatar.process_feedback(feedback);
    }
    
    /// Get current avatar accuracy as permille (1000 = 100%)
    pub fn accuracy_permille(&self) -> u32 {
        self.avatar.accuracy_permille()
    }
    
    /// Get FHE context (for testing)
    pub fn fhe_context(&self) -> &FHEContext {
        &self.fhe_ctx
    }
}

/// Server-side SEBV context
pub struct SEBVServer {
    /// FHE context (public key only in production)
    fhe_ctx: FHEContext,
    /// Encrypted classification policy
    encrypted_policy: N65EncryptedPolicy,
    /// Signature verifier
    verifier: SignatureVerifier,
    /// Current classification threshold
    threshold: i64,
}

impl SEBVServer {
    /// Create new server with default policy
    pub fn new() -> Self {
        let fhe_ctx = FHEContext::new();
        let policy = ClassificationPolicy::sebv_standard();
        let encrypted_policy = N65EncryptedPolicy::encrypt(&policy, &fhe_ctx);
        
        Self {
            fhe_ctx,
            encrypted_policy,
            verifier: SignatureVerifier::new(),
            threshold: policy.threshold,
        }
    }
    
    /// Create with custom policy
    pub fn with_policy(policy: ClassificationPolicy) -> Self {
        let fhe_ctx = FHEContext::new();
        let encrypted_policy = N65EncryptedPolicy::encrypt(&policy, &fhe_ctx);
        let threshold = policy.threshold;
        
        Self {
            fhe_ctx,
            encrypted_policy,
            verifier: SignatureVerifier::new(),
            threshold,
        }
    }
    
    /// Generate session nonce for client
    pub fn generate_nonce(&mut self) -> [u8; 16] {
        // In production, use cryptographic RNG
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u128;
        timestamp.to_le_bytes()
    }
    
    /// Generate session nonce as u128
    pub fn generate_nonce_u128(&mut self) -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u128
    }
    
    /// Process verification request from client
    ///
    /// Performs homomorphic classification on encrypted data.
    /// Server NEVER sees plaintext behavioral data (THEOREM FHE1).
    pub fn process_verification(
        &mut self,
        request: &VerificationRequest,
        expected_nonce: &[u8; 16],
    ) -> Result<VerificationResponse, PipelineError> {
        // Stage 5: Verify signature
        // Check timestamp freshness (within 5 minutes)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        
        if now.saturating_sub(request.timestamp) > 300_000 {
            return Err(PipelineError::SignatureExpired);
        }
        
        // Verify nonce matches
        if &request.signature.nonce != expected_nonce {
            return Err(PipelineError::InvalidNonce);
        }
        
        // Full signature verification
        let verification = self.verifier.verify(&request.signature);
        if verification != VerificationResult::Valid {
            return Err(PipelineError::InvalidSignature);
        }
        
        // Stage 6: Homomorphic classification
        // This is the key privacy-preserving step
        let encrypted_result = classify_encrypted(
            &request.encrypted_entropy,
            &self.encrypted_policy,
            &self.fhe_ctx,
        );
        
        Ok(VerificationResponse {
            encrypted_result,
            threshold: self.threshold,
        })
    }
    
    /// Get classification depth (for monitoring)
    pub fn circuit_depth(&self) -> u32 {
        // Distance computation is depth 2
        // Full classification is depth 7
        7
    }
}

impl Default for SEBVServer {
    fn default() -> Self {
        Self::new()
    }
}

/// Verification request from client to server
pub struct VerificationRequest {
    /// Encrypted entropy vector
    pub encrypted_entropy: N65EncryptedEntropy,
    /// Shadow entropy signature
    pub signature: ShadowSignature,
    /// Request timestamp (ms since epoch)
    pub timestamp: u64,
}

/// Verification response from server to client
#[derive(Debug)]
pub struct VerificationResponse {
    /// Encrypted classification distances
    pub encrypted_result: N65EncryptedClassification,
    /// Classification threshold
    pub threshold: i64,
}

/// Pipeline errors
#[derive(Debug, Clone, PartialEq)]
pub enum PipelineError {
    /// No session nonce set
    NoNonce,
    /// Signature has expired
    SignatureExpired,
    /// Invalid nonce in signature
    InvalidNonce,
    /// Signature verification failed
    InvalidSignature,
    /// FHE operation failed
    FHEError(String),
}

impl std::fmt::Display for PipelineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PipelineError::NoNonce => write!(f, "No session nonce set"),
            PipelineError::SignatureExpired => write!(f, "Signature has expired"),
            PipelineError::InvalidNonce => write!(f, "Invalid nonce in signature"),
            PipelineError::InvalidSignature => write!(f, "Signature verification failed"),
            PipelineError::FHEError(msg) => write!(f, "FHE error: {}", msg),
        }
    }
}

impl std::error::Error for PipelineError {}

/// Complete end-to-end verification
///
/// Demonstrates the full SEBV pipeline from behavioral data to classification.
pub fn verify_behavior(
    behavioral_data: &[i64],
    client: &mut SEBVClient,
    server: &mut SEBVServer,
) -> Result<ClassificationResult, PipelineError> {
    // Server generates nonce
    let nonce = server.generate_nonce();
    client.set_nonce(nonce);
    
    // Client creates verification request
    let request = client.create_verification_request(behavioral_data)?;
    
    // Server processes request (homomorphic classification)
    let response = server.process_verification(&request, &nonce)?;
    
    // Client decrypts result
    Ok(client.process_response(&response))
}

/// Batch verification for multiple behavioral windows
pub fn verify_batch(
    behavioral_windows: &[Vec<i64>],
    client: &mut SEBVClient,
    server: &mut SEBVServer,
) -> Vec<Result<ClassificationResult, PipelineError>> {
    behavioral_windows
        .iter()
        .map(|data| verify_behavior(data, client, server))
        .collect()
}

/// Pipeline statistics
#[derive(Debug, Clone, Default)]
pub struct PipelineStats {
    /// Total verifications performed
    pub total_verifications: u64,
    /// Successful verifications
    pub successful: u64,
    /// Human classifications
    pub humans: u64,
    /// Bot classifications
    pub bots: u64,
    /// Signature failures
    pub signature_failures: u64,
    /// Average latency in microseconds (mock, would need real timing)
    pub avg_latency_us: u64,
}

impl PipelineStats {
    pub fn record_verification(&mut self, result: &Result<ClassificationResult, PipelineError>) {
        self.total_verifications += 1;
        
        match result {
            Ok(ClassificationResult::Human { .. }) => {
                self.successful += 1;
                self.humans += 1;
            }
            Ok(ClassificationResult::Bot { .. }) => {
                self.successful += 1;
                self.bots += 1;
            }
            Err(PipelineError::InvalidSignature) |
            Err(PipelineError::SignatureExpired) |
            Err(PipelineError::InvalidNonce) => {
                self.signature_failures += 1;
            }
            Err(_) => {}
        }
    }
    
    /// Success rate as permille (1000 = 100%)
    pub fn success_rate_permille(&self) -> u32 {
        if self.total_verifications == 0 {
            return 1000;
        }
        (self.successful * 1000 / self.total_verifications) as u32
    }

    /// Human classification rate as permille (1000 = 100%)
    pub fn human_rate_permille(&self) -> u32 {
        if self.successful == 0 {
            return 0;
        }
        (self.humans * 1000 / self.successful) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BotType, ENTROPY_SCALE};
    
    #[test]
    fn test_client_creation() {
        let client = SEBVClient::new(12345);
        assert!(client.session_nonce.is_none());
    }
    
    #[test]
    fn test_server_creation() {
        let server = SEBVServer::new();
        assert_eq!(server.circuit_depth(), 7);
    }
    
    #[test]
    fn test_nonce_generation() {
        let mut server = SEBVServer::new();
        let nonce1 = server.generate_nonce();
        let nonce2 = server.generate_nonce();
        
        // Nonces should be non-zero
        assert_ne!(nonce1, [0u8; 16]);
        assert_ne!(nonce2, [0u8; 16]);
    }
    
    #[test]
    fn test_full_pipeline_human() {
        let mut client = SEBVClient::new(1);
        let mut server = SEBVServer::new();
        
        // Generate human-like behavioral data
        let avatar = SEBVAvatar::new(42);
        let behavioral_data = avatar.generate_synthetic_human_data(200);
        
        let result = verify_behavior(&behavioral_data, &mut client, &mut server);
        
        assert!(result.is_ok(), "Pipeline should succeed, got error: {:?}", result.err());
    }
    
    #[test]
    fn test_full_pipeline_bot_scripted() {
        let mut client = SEBVClient::new(2);
        let mut server = SEBVServer::new();
        
        // Generate scripted bot behavioral data
        let avatar = SEBVAvatar::new(42);
        let behavioral_data = avatar.generate_synthetic_bot_data(200, BotType::Scripted);
        
        let result = verify_behavior(&behavioral_data, &mut client, &mut server);
        
        assert!(result.is_ok(), "Pipeline should succeed");
    }
    
    #[test]
    fn test_expired_signature() {
        let mut client = SEBVClient::new(1);
        let mut server = SEBVServer::new();
        
        let nonce = server.generate_nonce();
        client.set_nonce(nonce);
        
        let behavioral_data: Vec<i64> = (0..100)
            .map(|i| ((i * 17 + 5) % 100) * ENTROPY_SCALE / 100)
            .collect();
        
        let mut request = client.create_verification_request(&behavioral_data).unwrap();
        
        // Backdate the request by 10 minutes
        request.timestamp -= 600_000;
        
        let result = server.process_verification(&request, &nonce);
        assert!(result.is_err());
        match result {
            Err(PipelineError::SignatureExpired) => {}
            _ => panic!("Expected SignatureExpired error"),
        }
    }
    
    #[test]
    fn test_invalid_nonce() {
        let mut client = SEBVClient::new(1);
        let mut server = SEBVServer::new();
        
        let nonce = server.generate_nonce();
        client.set_nonce(nonce);
        
        let behavioral_data: Vec<i64> = (0..100)
            .map(|i| ((i * 17 + 5) % 100) * ENTROPY_SCALE / 100)
            .collect();
        
        let request = client.create_verification_request(&behavioral_data).unwrap();
        
        // Use different nonce for verification
        let mut wrong_nonce = nonce;
        wrong_nonce[0] = wrong_nonce[0].wrapping_add(1);
        let result = server.process_verification(&request, &wrong_nonce);
        assert!(result.is_err());
        match result {
            Err(PipelineError::InvalidNonce) => {}
            _ => panic!("Expected InvalidNonce error"),
        }
    }
    
    #[test]
    fn test_batch_verification() {
        let mut client = SEBVClient::new(1);
        let mut server = SEBVServer::new();
        
        let avatar = SEBVAvatar::new(42);
        let windows: Vec<Vec<i64>> = (0..5)
            .map(|_| avatar.generate_synthetic_human_data(100))
            .collect();
        
        let results = verify_batch(&windows, &mut client, &mut server);
        
        assert_eq!(results.len(), 5);
        assert!(results.iter().all(|r| r.is_ok()));
    }
    
    #[test]
    fn test_pipeline_stats() {
        let mut stats = PipelineStats::default();
        
        stats.record_verification(&Ok(ClassificationResult::Human {
            confidence: 80,
            nearest_distance: 50000,
        }));
        stats.record_verification(&Ok(ClassificationResult::Bot {
            bot_type: BotType::Scripted,
            confidence: 90,
            nearest_distance: 10000,
        }));
        stats.record_verification(&Err(PipelineError::SignatureExpired));
        
        assert_eq!(stats.total_verifications, 3);
        assert_eq!(stats.successful, 2);
        assert_eq!(stats.humans, 1);
        assert_eq!(stats.bots, 1);
        assert_eq!(stats.signature_failures, 1);
        assert!((stats.success_rate() - 0.666).abs() < 0.01);
        assert!((stats.human_rate() - 0.5).abs() < 0.01);
    }
    
    #[test]
    fn test_client_with_culture() {
        let culture = CulturalIdentity::from_normalized(0.8, 0.9, 0.1, 0.05);
        let client = SEBVClient::with_culture(123, culture);
        
        assert!(client.avatar.weights().permutation_weight > 
                client.avatar.weights().sample_weight);
    }
    
    #[test]
    fn test_feedback_integration() {
        let mut client = SEBVClient::new(1);
        
        let feedback = vec![
            ClassificationFeedback {
                was_human: true,
                classified_human: true,
                confidence: 800_000,
            },
            ClassificationFeedback {
                was_human: false,
                classified_human: false,
                confidence: 900_000,
            },
        ];
        
        client.process_feedback(&feedback);
        
        assert!((client.accuracy() - 1.0).abs() < 0.01);
    }
}
