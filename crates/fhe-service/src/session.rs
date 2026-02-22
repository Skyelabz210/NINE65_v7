//! Session management — FHE key material and state per client session.

// nine65 re-exports the correct NTTEngine via its own feature gate.
// With default features (ntt_fft), this is NTTEngineFFT.
use nine65::arithmetic::NTTEngine;

#[cfg(test)]
use nine65::entropy::ShadowHarvester;
use nine65::keys::{EvaluationKey, KeySet, PublicKey, SecretKey};
use nine65::noise::budget::NoiseBudget;
use nine65::ops::encrypt::{BFVEncoder, Ciphertext};
use nine65::params::secure_configs::SecureConfig;
use nine65::params::FHEConfig;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::wire::SessionParams;

/// Maximum sessions before rejecting new ones (configurable via FHE_MAX_SESSIONS env).
pub const DEFAULT_MAX_SESSIONS: usize = 64;

/// Generate a hex session ID via getrandom (32 hex chars = 16 random bytes).
fn generate_session_id() -> Result<String, &'static str> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|_| "entropy unavailable")?;
    let mut hex = String::with_capacity(37); // "sess_" + 32 hex
    hex.push_str("sess_");
    for b in bytes {
        use std::fmt::Write;
        write!(hex, "{:02x}", b).map_err(|_| "session id formatting failed")?;
    }
    Ok(hex)
}

/// Server-side FHE session holding all key material.
///
/// The secret key NEVER leaves the server. Ciphertexts travel over the wire.
pub struct Session {
    pub session_id: String,
    pub config_name: String,
    pub config: FHEConfig,
    pub ntt: NTTEngine,
    pub encoder: BFVEncoder,
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
    pub eval_key: EvaluationKey,
    pub noise_budget: NoiseBudget,
    pub operation_count: u64,
    pub created_at: u64,
    pub last_accessed: u64,
}

impl Session {
    /// Create a new session with full keygen.
    ///
    /// Uses OS CSPRNG for production security.
    pub fn new(config_name: &str) -> Result<Self, &'static str> {
        let secure_config = match config_name {
            "secure_128" => SecureConfig::secure_128(),
            "secure_192" => SecureConfig::secure_192(),
            "secure_256" => SecureConfig::secure_256(),
            _ => return Err("unsupported config"),
        };

        let config = secure_config.into_config();
        let ntt = NTTEngine::new(config.q, config.n);
        let keys = KeySet::try_generate_secure(&config, &ntt)
            .map_err(|_| "secure key generation failed")?;
        let encoder = BFVEncoder::new(&config);
        let noise_budget = NoiseBudget::from_config(&config);

        Ok(Self {
            session_id: generate_session_id()?,
            config_name: config_name.to_owned(),
            config,
            ntt,
            encoder,
            secret_key: keys.secret_key,
            public_key: keys.public_key,
            eval_key: keys.eval_key,
            noise_budget,
            operation_count: 0,
            created_at: crate::unix_now_seconds(),
            last_accessed: crate::unix_now_seconds(),
        })
    }

    /// Create a session using deterministic seed (TESTING ONLY).
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn new_test(config_name: &str, seed: u64) -> Result<Self, &'static str> {
        let secure_config = match config_name {
            "secure_128" => SecureConfig::secure_128(),
            "secure_192" => SecureConfig::secure_192(),
            "secure_256" => SecureConfig::secure_256(),
            _ => return Err("unsupported config"),
        };

        let config = secure_config.into_config();
        let ntt = NTTEngine::new(config.q, config.n);
        let mut harvester = ShadowHarvester::with_seed(seed);
        let keys = KeySet::generate(&config, &ntt, &mut harvester);
        let encoder = BFVEncoder::new(&config);
        let noise_budget = NoiseBudget::from_config(&config);

        Ok(Self {
            session_id: generate_session_id()?,
            config_name: config_name.to_owned(),
            config,
            ntt,
            encoder,
            secret_key: keys.secret_key,
            public_key: keys.public_key,
            eval_key: keys.eval_key,
            noise_budget,
            operation_count: 0,
            created_at: crate::unix_now_seconds(),
            last_accessed: crate::unix_now_seconds(),
        })
    }

    /// Return session params for the wire response.
    pub fn params(&self) -> SessionParams {
        let log_q: u32 = self
            .config
            .primes
            .iter()
            .map(|&p| 64 - p.leading_zeros())
            .sum();
        SessionParams {
            n: self.config.n,
            log_q,
            t: self.config.t,
            security_bits: self.config.security_bits,
        }
    }

    /// Serialize a ciphertext to base64-encoded bincode.
    pub fn ct_to_b64(&self, ct: &Ciphertext) -> Result<String, String> {
        let bytes = ct
            .to_bytes()
            .map_err(|e| format!("bincode serialize: {}", e))?;
        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &bytes,
        ))
    }

    /// Deserialize a ciphertext from base64-encoded bincode with validation.
    pub fn ct_from_b64(&self, b64: &str) -> Result<Ciphertext, String> {
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
            .map_err(|e| format!("base64 decode: {}", e))?;
        Ciphertext::from_bytes_validated(&bytes, self.config.n, self.config.q)
            .map_err(|e| format!("ciphertext validation: {}", e))
    }
}

/// Thread-safe session store.
pub struct SessionStore {
    sessions: RwLock<HashMap<String, Arc<RwLock<Session>>>>,
    max_sessions: usize,
    ttl_seconds: u64,
}

impl SessionStore {
    /// Create a new session store with a default 1-hour TTL.
    pub fn new(max_sessions: usize) -> Self {
        Self::new_with_ttl(max_sessions, 3600)
    }

    /// Create a new session store with custom TTL (time-to-live) for sessions.
    pub fn new_with_ttl(max_sessions: usize, ttl_seconds: u64) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            max_sessions,
            ttl_seconds,
        }
    }

    /// Insert a session. Returns Err if at capacity.
    pub fn insert(&self, session: Session) -> Result<String, &'static str> {
        let mut map = self.sessions.write().unwrap_or_else(|e| e.into_inner());
        if map.len() >= self.max_sessions {
            return Err("max sessions reached");
        }
        let id = session.session_id.clone();
        map.insert(id.clone(), Arc::new(RwLock::new(session)));
        Ok(id)
    }

    /// Execute a closure with read access to a session.
    ///
    /// # Poison Recovery
    /// If the RwLock is poisoned (due to a panic in another thread), this method
    /// recovers by calling `e.into_inner()` to access the underlying data. This is
    /// intentional to maintain service availability, though it may leave sessions
    /// in an inconsistent state. The trade-off prioritizes availability over
    /// consistency in the face of unexpected panics.
    pub fn with_session<F, R>(&self, id: &str, f: F) -> Option<R>
    where
        F: FnOnce(&Session) -> R,
    {
        let map = self.sessions.read().unwrap_or_else(|e| e.into_inner());
        if let Some(session_lock) = map.get(id) {
            let mut session = session_lock.write().unwrap_or_else(|e| e.into_inner()); // Need write lock to update last_accessed
            session.last_accessed = crate::unix_now_seconds();
            Some(f(&session))
        } else {
            None
        }
    }

    /// Execute a closure with write access to a session.
    ///
    /// # Poison Recovery
    /// If the RwLock is poisoned (due to a panic in another thread), this method
    /// recovers by calling `e.into_inner()` to access the underlying data. This is
    /// intentional to maintain service availability, though it may leave sessions
    /// in an inconsistent state. The trade-off prioritizes availability over
    /// consistency in the face of unexpected panics.
    pub fn with_session_mut<F, R>(&self, id: &str, f: F) -> Option<R>
    where
        F: FnOnce(&mut Session) -> R,
    {
        let map = self.sessions.read().unwrap_or_else(|e| e.into_inner());
        if let Some(session_lock) = map.get(id) {
            let mut session = session_lock.write().unwrap_or_else(|e| e.into_inner());
            session.last_accessed = crate::unix_now_seconds();
            Some(f(&mut session))
        } else {
            None
        }
    }

    /// Remove and drop a session (zeroizes keys via Drop).
    pub fn remove(&self, id: &str) -> bool {
        let mut map = self.sessions.write().unwrap_or_else(|e| e.into_inner());
        map.remove(id).is_some()
    }

    /// Remove expired sessions based on TTL
    pub fn reap_expired_sessions(&self) -> usize {
        let current_time = crate::unix_now_seconds();
        let mut map = self.sessions.write().unwrap_or_else(|e| e.into_inner());

        let mut removed_count = 0;
        map.retain(|_, session_arc| {
            let session = session_arc.read().unwrap_or_else(|e| e.into_inner());
            let is_valid = current_time - session.last_accessed <= self.ttl_seconds;
            if !is_valid {
                removed_count += 1;
            }
            is_valid
        });

        removed_count
    }

    /// Get the TTL for sessions (in seconds).
    pub fn ttl_seconds(&self) -> u64 {
        self.ttl_seconds
    }

    /// Count of active sessions.
    pub fn count(&self) -> usize {
        self.sessions
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }
}
