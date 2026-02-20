#[cfg(feature = "wasm")]
mod wasm_impl {
    use wasm_bindgen::prelude::*;

    use nine65::entropy::ShadowHarvester;
    use nine65::errors::Nine65Error;
    use nine65::keys::{EvaluationKey, KeySet, PublicKey, SecretKey};
    use nine65::ops::{BFVDecryptor, BFVEncoder, BFVEncryptor, BFVEvaluator, Ciphertext};
    use nine65::params::secure_configs::SecureConfig;
    use nine65::params::FHEConfig;
    use nine65::prelude::NTTEngine;

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
        bincode::serialize(value).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    fn deserialize<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, JsValue> {
        bincode::deserialize(bytes).map_err(|e| JsValue::from_str(&e.to_string()))
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
            let cfg = clone_config(&secure.config);
            let ntt = NTTEngine::new(cfg.q, cfg.n);
            let encoder = BFVEncoder::new(&cfg);
            Ok(WasmFHEContext {
                config: cfg,
                ntt,
                encoder,
            })
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

        pub fn generate_keyset_seeded(&self, seed: u64) -> WasmKeySet {
            let mut harvester = ShadowHarvester::with_seed(seed);
            let keys = KeySet::generate(&self.config, &self.ntt, &mut harvester);
            WasmKeySet { inner: keys }
        }

        pub fn encrypt_seeded(
            &self,
            value: u64,
            public_key: &WasmPublicKey,
            seed: u64,
        ) -> Result<Vec<u8>, JsValue> {
            let encryptor =
                BFVEncryptor::new(&public_key.inner, &self.encoder, &self.ntt, self.config.eta);
            let ct = encryptor.try_encrypt_seeded(value, seed).map_err(map_err)?;
            serialize(&ct)
        }

        pub fn decrypt(
            &self,
            ciphertext: &[u8],
            secret_key: &WasmSecretKey,
        ) -> Result<u64, JsValue> {
            let ct: Ciphertext = deserialize(ciphertext)?;
            let decryptor = BFVDecryptor::new(&secret_key.inner, &self.encoder, &self.ntt);
            Ok(decryptor.decrypt(&ct))
        }

        pub fn add(&self, ct_a: &[u8], ct_b: &[u8]) -> Result<Vec<u8>, JsValue> {
            let a: Ciphertext = deserialize(ct_a)?;
            let b: Ciphertext = deserialize(ct_b)?;
            let evaluator = BFVEvaluator::new(&self.ntt, &self.encoder, None);
            let result = evaluator.add(&a, &b);
            serialize(&result)
        }

        pub fn add_plain(&self, ct: &[u8], value: u64) -> Result<Vec<u8>, JsValue> {
            if value >= self.config.t {
                return Err(JsValue::from_str("plaintext value exceeds modulus"));
            }
            let ciphertext: Ciphertext = deserialize(ct)?;
            let evaluator = BFVEvaluator::new(&self.ntt, &self.encoder, None);
            let result = evaluator.add_plain(&ciphertext, value);
            serialize(&result)
        }

        pub fn mul_plain(&self, ct: &[u8], value: u64) -> Result<Vec<u8>, JsValue> {
            let ciphertext: Ciphertext = deserialize(ct)?;
            let evaluator = BFVEvaluator::new(&self.ntt, &self.encoder, None);
            let result = evaluator.mul_plain(&ciphertext, value);
            serialize(&result)
        }

        #[allow(deprecated)]
        pub fn mul(
            &self,
            ct_a: &[u8],
            ct_b: &[u8],
            eval_key: &WasmEvaluationKey,
        ) -> Result<Vec<u8>, JsValue> {
            let a: Ciphertext = deserialize(ct_a)?;
            let b: Ciphertext = deserialize(ct_b)?;
            let evaluator = BFVEvaluator::new(&self.ntt, &self.encoder, Some(&eval_key.inner));
            let result = evaluator.mul(&a, &b);
            serialize(&result)
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

        pub fn from_bytes(data: &[u8]) -> Result<WasmPublicKey, JsValue> {
            let key: PublicKey = deserialize(data)?;
            Ok(WasmPublicKey { inner: key })
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

        pub fn from_bytes(data: &[u8]) -> Result<WasmEvaluationKey, JsValue> {
            let key: EvaluationKey = deserialize(data)?;
            Ok(WasmEvaluationKey { inner: key })
        }
    }
}

#[cfg(feature = "wasm")]
pub use wasm_impl::*;
