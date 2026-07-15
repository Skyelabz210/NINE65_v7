#[cfg(feature = "wasm")]
mod wasm_impl {
    use wasm_bindgen::prelude::*;

    use nine65::arithmetic::boundary::{capacity_proximity_bits, CapacityRegion};
    use nine65::errors::Nine65Error;
    use nine65::keys::{EvaluationKey, KeySet, PublicKey, SecretKey};
    use nine65::ops::{BFVDecryptor, BFVEncoder, BFVEncryptor, BFVEvaluator, Ciphertext};
    use nine65::params::secure_configs::SecureConfig;
    use nine65::params::FHEConfig;
    use nine65::prelude::NTTEngine;

    // This crate currently exposes the legacy single-modulus BFV client surface.
    // It does not expose DualRNS, K-Elimination, or automatic bootstrap.
    const WIDE_INTERMEDIATE_CAPACITY_BITS: u32 = 127;
    const WASM_WARN_PCT: u32 = 80;
    const WASM_ERROR_PCT: u32 = 90;

    fn intermediate_bits(cfg: &FHEConfig) -> u32 {
        if cfg.q == 0 || cfg.n == 0 {
            return 0;
        }
        let q_bits = 64 - cfg.q.leading_zeros();
        let n_bits = 64 - (cfg.n as u64).leading_zeros();
        n_bits + 2 * q_bits
    }

    fn validate_config_capacity(cfg: &FHEConfig) -> Result<Option<String>, JsValue> {
        let intermediate = intermediate_bits(cfg);
        let report = capacity_proximity_bits(intermediate, WIDE_INTERMEDIATE_CAPACITY_BITS);

        match report.region {
            CapacityRegion::Critical | CapacityRegion::Warn90 => Err(JsValue::from_str(&format!(
                "NINE65 WASM single-modulus BFV config '{}' (n={}, q={}) requires {} intermediate bits, at or above the {}% boundary of the {}-bit checked wide-integer capacity. Use a smaller supported configuration.",
                cfg.name,
                cfg.n,
                cfg.q,
                intermediate,
                WASM_ERROR_PCT,
                WIDE_INTERMEDIATE_CAPACITY_BITS,
            ))),
            CapacityRegion::Warn80 => Ok(Some(format!(
                "NINE65 WASM warning: config '{}' requires {} intermediate bits ({}% of the {}-bit checked wide-integer capacity).",
                cfg.name,
                intermediate,
                report.utilization_pct,
                WIDE_INTERMEDIATE_CAPACITY_BITS,
            ))),
            CapacityRegion::Safe => Ok(None),
        }
    }

    fn clone_config(cfg: &FHEConfig) -> FHEConfig {
        FHEConfig {
            n: cfg.n,
            primes: cfg.primes.clone(),
            q: cfg.q,
            t: cfg.t,
            eta: cfg.eta,
            security_bits: cfg.security_bits,
            name: cfg.name,
        }
    }

    fn map_err(err: Nine65Error) -> JsValue {
        JsValue::from_str(&err.to_string())
    }

    fn serialize<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, JsValue> {
        bincode::serialize(value).map_err(|error| JsValue::from_str(&error.to_string()))
    }

    fn deserialize<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, JsValue> {
        bincode::deserialize(bytes).map_err(|error| JsValue::from_str(&error.to_string()))
    }

    #[wasm_bindgen]
    pub struct WasmFHEContext {
        config: FHEConfig,
        ntt: NTTEngine,
        encoder: BFVEncoder,
    }

    #[wasm_bindgen]
    impl WasmFHEContext {
        #[wasm_bindgen(constructor)]
        pub fn new(security_bits: u32) -> Result<WasmFHEContext, JsValue> {
            let secure = match security_bits {
                128 => SecureConfig::secure_128(),
                192 => SecureConfig::secure_192(),
                256 => SecureConfig::secure_256(),
                _ => {
                    return Err(JsValue::from_str(
                        "Unsupported security_bits. Use 128, 192, or 256.",
                    ))
                }
            };
            let config = clone_config(&secure.config);
            let _warning = validate_config_capacity(&config)?;
            let ntt = NTTEngine::try_new(config.q, config.n).map_err(map_err)?;
            let encoder = BFVEncoder::new(&config);

            Ok(Self {
                config,
                ntt,
                encoder,
            })
        }

        /// Current browser surface identifier.
        pub fn surface(&self) -> String {
            "single-modulus-bfv-leveled".to_string()
        }

        pub fn supports_dual_rns(&self) -> bool {
            false
        }

        pub fn supports_auto_bootstrap(&self) -> bool {
            false
        }

        /// Format: `safe|pct|bits/capacity`, `warn80|...`, `warn90|...`, or `critical|...`.
        pub fn boundary_report(&self) -> String {
            let intermediate = intermediate_bits(&self.config);
            let report =
                capacity_proximity_bits(intermediate, WIDE_INTERMEDIATE_CAPACITY_BITS);
            let region = match report.region {
                CapacityRegion::Safe => "safe",
                CapacityRegion::Warn80 => "warn80",
                CapacityRegion::Warn90 => "warn90",
                CapacityRegion::Critical => "critical",
            };
            format!(
                "{}|{}|{}/{}",
                region, report.utilization_pct, report.value_bits, report.capacity_bits
            )
        }

        pub fn name(&self) -> String {
            self.config.name.to_string()
        }

        pub fn degree(&self) -> usize {
            self.config.n
        }

        pub fn plaintext_modulus(&self) -> u64 {
            self.config.t
        }

        /// Generate keys with browser OS cryptographic randomness.
        pub fn generate_keyset(&self) -> Result<WasmKeySet, JsValue> {
            let keys = KeySet::try_generate_secure(&self.config, &self.ntt).map_err(map_err)?;
            Ok(WasmKeySet { inner: keys })
        }

        /// Deterministic key generation is available only in debug/test builds.
        pub fn generate_keyset_seeded_for_test(&self, seed: u64) -> Result<WasmKeySet, JsValue> {
            #[cfg(debug_assertions)]
            {
                let mut harvester = nine65::entropy::ShadowHarvester::with_seed(seed);
                let keys = KeySet::generate(&self.config, &self.ntt, &mut harvester);
                Ok(WasmKeySet { inner: keys })
            }
            #[cfg(not(debug_assertions))]
            {
                let _ = seed;
                Err(JsValue::from_str(
                    "deterministic key generation is disabled in release builds",
                ))
            }
        }

        /// Encrypt with browser OS cryptographic randomness.
        pub fn encrypt(
            &self,
            value: u64,
            public_key: &WasmPublicKey,
        ) -> Result<Vec<u8>, JsValue> {
            public_key
                .inner
                .validate(self.config.n, self.config.q)
                .map_err(map_err)?;
            let encryptor =
                BFVEncryptor::new(&public_key.inner, &self.encoder, &self.ntt, self.config.eta);
            let ciphertext = encryptor.try_encrypt_secure(value).map_err(map_err)?;
            serialize(&ciphertext)
        }

        /// Deterministic encryption is available only in debug/test builds.
        pub fn encrypt_seeded_for_test(
            &self,
            value: u64,
            public_key: &WasmPublicKey,
            seed: u64,
        ) -> Result<Vec<u8>, JsValue> {
            #[cfg(debug_assertions)]
            {
                public_key
                    .inner
                    .validate(self.config.n, self.config.q)
                    .map_err(map_err)?;
                let encryptor = BFVEncryptor::new(
                    &public_key.inner,
                    &self.encoder,
                    &self.ntt,
                    self.config.eta,
                );
                let ciphertext = encryptor
                    .try_encrypt_seeded(value, seed)
                    .map_err(map_err)?;
                serialize(&ciphertext)
            }
            #[cfg(not(debug_assertions))]
            {
                let _ = (value, public_key, seed);
                Err(JsValue::from_str(
                    "deterministic encryption is disabled in release builds",
                ))
            }
        }

        pub fn public_key_from_bytes(&self, data: &[u8]) -> Result<WasmPublicKey, JsValue> {
            let key: PublicKey = deserialize(data)?;
            key.validate(self.config.n, self.config.q)
                .map_err(map_err)?;
            Ok(WasmPublicKey { inner: key })
        }

        pub fn evaluation_key_from_bytes(
            &self,
            data: &[u8],
        ) -> Result<WasmEvaluationKey, JsValue> {
            let key: EvaluationKey = deserialize(data)?;
            key.validate(self.config.n, self.config.q)
                .map_err(map_err)?;
            Ok(WasmEvaluationKey { inner: key })
        }

        pub fn decrypt(
            &self,
            ciphertext: &[u8],
            secret_key: &WasmSecretKey,
        ) -> Result<u64, JsValue> {
            let ciphertext = self.decode_ciphertext(ciphertext)?;
            secret_key
                .inner
                .s
                .validate(self.config.n, self.config.q)
                .map_err(map_err)?;
            let decryptor = BFVDecryptor::new(&secret_key.inner, &self.encoder, &self.ntt);
            Ok(decryptor.decrypt(&ciphertext))
        }

        pub fn add(&self, left: &[u8], right: &[u8]) -> Result<Vec<u8>, JsValue> {
            let left = self.decode_ciphertext(left)?;
            let right = self.decode_ciphertext(right)?;
            let evaluator = BFVEvaluator::new(&self.ntt, &self.encoder, None);
            serialize(&evaluator.add(&left, &right))
        }

        pub fn add_plain(&self, ciphertext: &[u8], value: u64) -> Result<Vec<u8>, JsValue> {
            if value >= self.config.t {
                return Err(JsValue::from_str("plaintext value exceeds modulus"));
            }
            let ciphertext = self.decode_ciphertext(ciphertext)?;
            let evaluator = BFVEvaluator::new(&self.ntt, &self.encoder, None);
            serialize(&evaluator.add_plain(&ciphertext, value))
        }

        pub fn mul_plain(&self, ciphertext: &[u8], value: u64) -> Result<Vec<u8>, JsValue> {
            if value >= self.config.t {
                return Err(JsValue::from_str("plaintext value exceeds modulus"));
            }
            let ciphertext = self.decode_ciphertext(ciphertext)?;
            let evaluator = BFVEvaluator::new(&self.ntt, &self.encoder, None);
            serialize(&evaluator.mul_plain(&ciphertext, value))
        }

        /// Leveled single-modulus multiplication. This is not DualRNS auto-bootstrap.
        #[allow(deprecated)]
        pub fn mul(
            &self,
            left: &[u8],
            right: &[u8],
            evaluation_key: &WasmEvaluationKey,
        ) -> Result<Vec<u8>, JsValue> {
            validate_config_capacity(&self.config)?;
            evaluation_key
                .inner
                .validate(self.config.n, self.config.q)
                .map_err(map_err)?;
            let left = self.decode_ciphertext(left)?;
            let right = self.decode_ciphertext(right)?;
            let evaluator =
                BFVEvaluator::new(&self.ntt, &self.encoder, Some(&evaluation_key.inner));
            serialize(&evaluator.mul(&left, &right))
        }
    }

    impl WasmFHEContext {
        fn decode_ciphertext(&self, bytes: &[u8]) -> Result<Ciphertext, JsValue> {
            let ciphertext: Ciphertext = deserialize(bytes)?;
            ciphertext
                .validate(self.config.n, self.config.q)
                .map_err(map_err)?;
            Ok(ciphertext)
        }
    }

    #[wasm_bindgen]
    pub struct WasmKeySet {
        inner: KeySet,
    }

    #[wasm_bindgen]
    impl WasmKeySet {
        pub fn public_key(&self) -> WasmPublicKey {
            WasmPublicKey {
                inner: self.inner.public_key.clone(),
            }
        }

        pub fn secret_key(&self) -> WasmSecretKey {
            WasmSecretKey {
                inner: self.inner.secret_key.clone(),
            }
        }

        pub fn evaluation_key(&self) -> WasmEvaluationKey {
            WasmEvaluationKey {
                inner: self.inner.eval_key.clone(),
            }
        }
    }

    #[wasm_bindgen]
    pub struct WasmPublicKey {
        inner: PublicKey,
    }

    #[wasm_bindgen]
    impl WasmPublicKey {
        pub fn to_bytes(&self) -> Result<Vec<u8>, JsValue> {
            serialize(&self.inner)
        }
    }

    #[wasm_bindgen]
    pub struct WasmSecretKey {
        inner: SecretKey,
    }

    #[wasm_bindgen]
    impl WasmSecretKey {
        pub fn to_bytes(&self) -> Result<Vec<u8>, JsValue> {
            Err(JsValue::from_str("SecretKey export disabled"))
        }
    }

    #[wasm_bindgen]
    pub struct WasmEvaluationKey {
        inner: EvaluationKey,
    }

    #[wasm_bindgen]
    impl WasmEvaluationKey {
        pub fn to_bytes(&self) -> Result<Vec<u8>, JsValue> {
            serialize(&self.inner)
        }
    }
}

#[cfg(feature = "wasm")]
pub use wasm_impl::*;
