//! Session management — FHE key material and state per tenant session.

#[cfg(test)]
use nine65::entropy::ShadowHarvester;
use nine65::noise::budget::NoiseBudget;
use nine65::ops::rns_fhe::{DualRNSCiphertext, DualRNSFullKeySet, RNSFHEContext};
use nine65::params::secure_configs::SecureConfig;
use nine65::params::FHEConfig;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::wire::SessionParams;

pub const DEFAULT_MAX_SESSIONS: usize = 64;

fn generate_session_id() -> Result<String, &'static str> {
    let mut bytes = [0_u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|_| "entropy unavailable")?;
    let mut hex = String::with_capacity(37);
    hex.push_str("sess_");
    for byte in bytes {
        use std::fmt::Write;
        write!(hex, "{byte:02x}").map_err(|_| "session id formatting failed")?;
    }
    Ok(hex)
}

/// Server-key-holder DualRNS session bound to one authenticated tenant.
pub struct Session {
    pub session_id: String,
    pub tenant_id: String,
    pub config_name: String,
    pub config: FHEConfig,
    pub noise_budget: NoiseBudget,
    pub operation_count: u64,
    pub created_at: u64,
    pub last_accessed: u64,
    pub rns_ctx: RNSFHEContext,
    pub dual_keys: DualRNSFullKeySet,
}

impl Session {
    /// Compatibility constructor for internal/test callers.
    pub fn new(config_name: &str) -> Result<Self, &'static str> {
        Self::new_for_tenant(config_name, "internal")
    }

    /// Create a tenant-bound production session using OS CSPRNG key generation.
    pub fn new_for_tenant(config_name: &str, tenant_id: &str) -> Result<Self, &'static str> {
        if tenant_id.is_empty() {
            return Err("tenant id required");
        }

        let secure_config = match config_name {
            "secure_128" => SecureConfig::secure_128(),
            "secure_192" => SecureConfig::secure_192(),
            "secure_256" => SecureConfig::secure_256(),
            _ => return Err("unsupported config"),
        };

        let config = secure_config.into_config();
        let noise_budget = NoiseBudget::from_config(&config);
        let rns_ctx = RNSFHEContext::try_new(&config).map_err(|_| "RNS context creation failed")?;
        let dual_keys = rns_ctx.generate_keys_dual_full_secure();
        let now = crate::unix_now_seconds();

        Ok(Self {
            session_id: generate_session_id()?,
            tenant_id: tenant_id.to_owned(),
            config_name: config_name.to_owned(),
            config,
            noise_budget,
            operation_count: 0,
            created_at: now,
            last_accessed: now,
            rns_ctx,
            dual_keys,
        })
    }

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
        let noise_budget = NoiseBudget::from_config(&config);
        let rns_ctx = RNSFHEContext::try_new(&config).map_err(|_| "RNS context creation failed")?;
        let mut harvester = ShadowHarvester::with_seed(seed);
        let dual_keys = rns_ctx.generate_keys_dual_full(&mut harvester);
        let now = crate::unix_now_seconds();

        Ok(Self {
            session_id: generate_session_id()?,
            tenant_id: "test".to_string(),
            config_name: config_name.to_owned(),
            config,
            noise_budget,
            operation_count: 0,
            created_at: now,
            last_accessed: now,
            rns_ctx,
            dual_keys,
        })
    }

    pub fn params(&self) -> SessionParams {
        let log_q: u32 = self
            .config
            .primes
            .iter()
            .map(|&prime| 64 - prime.leading_zeros())
            .sum();
        SessionParams {
            n: self.config.n,
            log_q,
            t: self.config.t,
            security_bits: self.config.security_bits,
        }
    }

    pub fn dual_ct_to_b64(&self, ciphertext: &DualRNSCiphertext) -> Result<String, String> {
        let bytes = ciphertext
            .to_bytes()
            .map_err(|error| format!("bincode serialize: {error}"))?;
        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &bytes,
        ))
    }

    pub fn dual_ct_from_b64(&self, encoded: &str) -> Result<DualRNSCiphertext, String> {
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
            .map_err(|error| format!("base64 decode: {error}"))?;
        DualRNSCiphertext::from_bytes_validated(&bytes)
            .map_err(|error| format!("ciphertext validation: {error}"))
    }
}

/// Thread-safe tenant-isolated session store.
pub struct SessionStore {
    sessions: RwLock<HashMap<String, Arc<RwLock<Session>>>>,
    max_sessions: usize,
    ttl_seconds: u64,
}

impl SessionStore {
    pub fn new(max_sessions: usize) -> Self {
        Self::new_with_ttl(max_sessions, 3600)
    }

    pub fn new_with_ttl(max_sessions: usize, ttl_seconds: u64) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            max_sessions,
            ttl_seconds,
        }
    }

    pub fn insert(&self, session: Session) -> Result<String, &'static str> {
        let mut map = self.sessions.write().map_err(|_| "session store poisoned")?;
        if map.len() >= self.max_sessions {
            return Err("max sessions reached");
        }
        let id = session.session_id.clone();
        map.insert(id.clone(), Arc::new(RwLock::new(session)));
        Ok(id)
    }

    /// Read a session only when both random ID and authenticated tenant match.
    /// A mismatch and an absent ID return the same `None` result.
    pub fn with_session_for_tenant<F, R>(&self, id: &str, tenant_id: &str, operation: F) -> Option<R>
    where
        F: FnOnce(&Session) -> R,
    {
        let map = self.sessions.read().ok()?;
        let session_lock = map.get(id)?;
        let mut session = session_lock.write().ok()?;
        if session.tenant_id != tenant_id {
            return None;
        }
        session.last_accessed = crate::unix_now_seconds();
        Some(operation(&session))
    }

    pub fn with_session_mut_for_tenant<F, R>(
        &self,
        id: &str,
        tenant_id: &str,
        operation: F,
    ) -> Option<R>
    where
        F: FnOnce(&mut Session) -> R,
    {
        let map = self.sessions.read().ok()?;
        let session_lock = map.get(id)?;
        let mut session = session_lock.write().ok()?;
        if session.tenant_id != tenant_id {
            return None;
        }
        session.last_accessed = crate::unix_now_seconds();
        Some(operation(&mut session))
    }

    #[cfg(test)]
    pub fn with_session<F, R>(&self, id: &str, operation: F) -> Option<R>
    where
        F: Fn(&Session) -> R,
    {
        self.with_session_for_tenant(id, "test", &operation)
            .or_else(|| self.with_session_for_tenant(id, "internal", &operation))
    }

    #[cfg(test)]
    pub fn with_session_mut<F, R>(&self, id: &str, operation: F) -> Option<R>
    where
        F: Fn(&mut Session) -> R,
    {
        self.with_session_mut_for_tenant(id, "test", &operation)
            .or_else(|| self.with_session_mut_for_tenant(id, "internal", &operation))
    }

    pub fn remove_for_tenant(&self, id: &str, tenant_id: &str) -> bool {
        let Ok(mut map) = self.sessions.write() else {
            return false;
        };
        let Some(session_lock) = map.get(id) else {
            return false;
        };
        let Ok(session) = session_lock.read() else {
            return false;
        };
        if session.tenant_id != tenant_id {
            return false;
        }
        drop(session);
        map.remove(id).is_some()
    }

    #[cfg(test)]
    pub fn remove(&self, id: &str) -> bool {
        self.remove_for_tenant(id, "test") || self.remove_for_tenant(id, "internal")
    }

    pub fn reap_expired_sessions(&self) -> usize {
        let current_time = crate::unix_now_seconds();
        let Ok(mut map) = self.sessions.write() else {
            return 0;
        };

        let mut removed_count = 0;
        map.retain(|_, session_arc| {
            let Ok(session) = session_arc.read() else {
                removed_count += 1;
                return false;
            };
            let age = current_time.saturating_sub(session.last_accessed);
            let keep = age <= self.ttl_seconds;
            if !keep {
                removed_count += 1;
            }
            keep
        });
        removed_count
    }

    pub fn ttl_seconds(&self) -> u64 {
        self.ttl_seconds
    }

    pub fn count(&self) -> usize {
        self.sessions.read().map_or(0, |sessions| sessions.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_mismatch_is_indistinguishable_from_missing_session() {
        let store = SessionStore::new(2);
        let session = Session::new_test("secure_128", 7).expect("test session");
        let id = session.session_id.clone();
        store.insert(session).expect("insert");
        assert!(store.with_session_for_tenant(&id, "other", |_| ()).is_none());
        assert!(
            store
                .with_session_for_tenant("sess_missing", "test", |_| ())
                .is_none()
        );
    }

    #[test]
    fn tenant_bound_delete_rejects_cross_tenant_request() {
        let store = SessionStore::new(2);
        let session = Session::new_test("secure_128", 9).expect("test session");
        let id = session.session_id.clone();
        store.insert(session).expect("insert");
        assert!(!store.remove_for_tenant(&id, "other"));
        assert!(store.remove_for_tenant(&id, "test"));
    }
}
