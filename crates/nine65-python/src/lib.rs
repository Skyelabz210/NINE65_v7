use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList};

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

fn nine65_err(err: Nine65Error) -> PyErr {
    PyErr::new::<pyo3::exceptions::PyValueError, _>(err.to_string())
}

#[pyclass(name = "FHEConfig", from_py_object)]
#[derive(Clone)]
pub struct PyFHEConfig {
    inner: FHEConfig,
}

#[pymethods]
impl PyFHEConfig {
    #[staticmethod]
    fn standard_128() -> Self {
        Self {
            inner: FHEConfig::standard_128(),
        }
    }

    #[staticmethod]
    fn high_192() -> Self {
        Self {
            inner: FHEConfig::high_192(),
        }
    }

    #[staticmethod]
    fn large_single() -> Self {
        Self {
            inner: FHEConfig::large_single(),
        }
    }

    #[cfg(any(test, feature = "allow_insecure"))]
    #[staticmethod]
    fn light() -> Self {
        Self {
            inner: FHEConfig::light(),
        }
    }

    fn name(&self) -> &str {
        self.inner.name
    }

    fn degree(&self) -> usize {
        self.inner.n
    }

    fn plaintext_modulus(&self) -> u64 {
        self.inner.t
    }

    fn ciphertext_modulus(&self) -> u64 {
        self.inner.q
    }

    fn security_bits(&self) -> usize {
        self.inner.security_bits
    }

    fn eta(&self) -> usize {
        self.inner.eta
    }
}

#[pyclass(name = "SecureConfig", from_py_object)]
#[derive(Clone)]
pub struct PySecureConfig {
    inner: SecureConfig,
}

#[pymethods]
impl PySecureConfig {
    #[staticmethod]
    fn secure_128() -> Self {
        Self {
            inner: SecureConfig::secure_128(),
        }
    }

    #[staticmethod]
    fn secure_192() -> Self {
        Self {
            inner: SecureConfig::secure_192(),
        }
    }

    #[staticmethod]
    fn secure_256() -> Self {
        Self {
            inner: SecureConfig::secure_256(),
        }
    }

    #[cfg(any(test, debug_assertions))]
    #[staticmethod]
    fn test_fast() -> Self {
        Self {
            inner: SecureConfig::test_fast(),
        }
    }

    fn is_production_safe(&self) -> bool {
        self.inner.is_production_safe()
    }

    fn classical_security(&self) -> u32 {
        self.inner.classical_security
    }

    fn hybrid_security(&self) -> u32 {
        self.inner.hybrid_security
    }

    fn quantum_security(&self) -> u32 {
        self.inner.quantum_security
    }

    fn he_standard_compliant(&self) -> bool {
        self.inner.he_standard_compliant
    }

    fn to_config(&self) -> PyFHEConfig {
        PyFHEConfig {
            inner: clone_config(&self.inner.config),
        }
    }
}

#[pyclass(name = "PublicKey", from_py_object)]
#[derive(Clone)]
pub struct PyPublicKey {
    inner: PublicKey,
}

#[pymethods]
impl PyPublicKey {
    fn __repr__(&self) -> String {
        format!("PublicKey(n={})", self.inner.pk0.coeffs.len())
    }

    fn to_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let data = bincode::serialize(&self.inner)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Ok(PyBytes::new(py, &data))
    }

    #[staticmethod]
    fn from_bytes(data: Bound<'_, PyBytes>) -> PyResult<Self> {
        let key: PublicKey = bincode::deserialize(data.as_bytes())
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Ok(Self { inner: key })
    }
}

#[pyclass(name = "SecretKey", from_py_object)]
#[derive(Clone)]
pub struct PySecretKey {
    inner: SecretKey,
}

#[pymethods]
impl PySecretKey {
    fn __repr__(&self) -> String {
        format!("SecretKey(n={})", self.inner.s.coeffs.len())
    }
}

#[pyclass(name = "EvaluationKey", from_py_object)]
#[derive(Clone)]
pub struct PyEvaluationKey {
    inner: EvaluationKey,
}

#[pymethods]
impl PyEvaluationKey {
    fn __repr__(&self) -> String {
        format!("EvaluationKey(levels={})", self.inner.levels)
    }

    fn to_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let data = bincode::serialize(&self.inner)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Ok(PyBytes::new(py, &data))
    }

    #[staticmethod]
    fn from_bytes(data: Bound<'_, PyBytes>) -> PyResult<Self> {
        let key: EvaluationKey = bincode::deserialize(data.as_bytes())
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Ok(Self { inner: key })
    }
}

#[pyclass(name = "Ciphertext", from_py_object)]
#[derive(Clone)]
pub struct PyCiphertext {
    inner: Ciphertext,
}

#[pymethods]
impl PyCiphertext {
    fn __repr__(&self) -> String {
        format!("Ciphertext(n={})", self.inner.c0.coeffs.len())
    }

    fn to_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let data = bincode::serialize(&self.inner)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Ok(PyBytes::new(py, &data))
    }

    #[staticmethod]
    fn from_bytes(data: Bound<'_, PyBytes>) -> PyResult<Self> {
        let ct: Ciphertext = bincode::deserialize(data.as_bytes())
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Ok(Self { inner: ct })
    }
}

#[pyclass(name = "KeySet")]
pub struct PyKeySet {
    inner: KeySet,
}

#[pymethods]
impl PyKeySet {
    #[getter]
    fn public_key(&self) -> PyPublicKey {
        PyPublicKey {
            inner: self.inner.public_key.clone(),
        }
    }

    #[getter]
    fn secret_key(&self) -> PySecretKey {
        PySecretKey {
            inner: self.inner.secret_key.clone(),
        }
    }

    #[getter]
    fn evaluation_key(&self) -> PyEvaluationKey {
        PyEvaluationKey {
            inner: self.inner.eval_key.clone(),
        }
    }
}

#[pyclass(name = "FHEContext")]
pub struct PyFHEContext {
    config: FHEConfig,
    ntt: NTTEngine,
    encoder: BFVEncoder,
}

#[pymethods]
impl PyFHEContext {
    #[new]
    fn new(config: &PyFHEConfig) -> Self {
        let cfg = clone_config(&config.inner);
        let ntt = NTTEngine::new(cfg.q, cfg.n);
        let encoder = BFVEncoder::new(&cfg);
        Self {
            config: cfg,
            ntt,
            encoder,
        }
    }

    #[staticmethod]
    fn from_secure_config(config: &PySecureConfig) -> Self {
        let cfg = clone_config(&config.inner.config);
        let ntt = NTTEngine::new(cfg.q, cfg.n);
        let encoder = BFVEncoder::new(&cfg);
        Self {
            config: cfg,
            ntt,
            encoder,
        }
    }

    fn config(&self) -> PyFHEConfig {
        PyFHEConfig {
            inner: clone_config(&self.config),
        }
    }

    fn name(&self) -> &str {
        self.config.name
    }

    fn degree(&self) -> usize {
        self.config.n
    }

    fn plaintext_modulus(&self) -> u64 {
        self.config.t
    }

    fn ciphertext_modulus(&self) -> u64 {
        self.config.q
    }

    fn generate_keyset_secure(&self) -> PyKeySet {
        let keys = KeySet::generate_secure(&self.config, &self.ntt);
        PyKeySet { inner: keys }
    }

    fn generate_keyset_seeded(&self, seed: u64) -> PyKeySet {
        let mut harvester = ShadowHarvester::with_seed(seed);
        let keys = KeySet::generate(&self.config, &self.ntt, &mut harvester);
        PyKeySet { inner: keys }
    }

    fn encrypt(&self, value: u64, public_key: &PyPublicKey) -> PyResult<PyCiphertext> {
        let encryptor =
            BFVEncryptor::new(&public_key.inner, &self.encoder, &self.ntt, self.config.eta);
        let ct = encryptor.try_encrypt_secure(value).map_err(nine65_err)?;
        Ok(PyCiphertext { inner: ct })
    }

    fn encrypt_seeded(
        &self,
        value: u64,
        public_key: &PyPublicKey,
        seed: u64,
    ) -> PyResult<PyCiphertext> {
        let encryptor =
            BFVEncryptor::new(&public_key.inner, &self.encoder, &self.ntt, self.config.eta);
        let ct = encryptor
            .try_encrypt_seeded(value, seed)
            .map_err(nine65_err)?;
        Ok(PyCiphertext { inner: ct })
    }

    fn decrypt(&self, ciphertext: &PyCiphertext, secret_key: &PySecretKey) -> u64 {
        let decryptor = BFVDecryptor::new(&secret_key.inner, &self.encoder, &self.ntt);
        decryptor.decrypt(&ciphertext.inner)
    }

    fn add(&self, ct1: &PyCiphertext, ct2: &PyCiphertext) -> PyCiphertext {
        let evaluator = BFVEvaluator::new(&self.ntt, &self.encoder, None);
        PyCiphertext {
            inner: evaluator.add(&ct1.inner, &ct2.inner),
        }
    }

    fn add_plain(&self, ct: &PyCiphertext, value: u64) -> PyResult<PyCiphertext> {
        if value >= self.config.t {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "plaintext value exceeds modulus",
            ));
        }
        let evaluator = BFVEvaluator::new(&self.ntt, &self.encoder, None);
        Ok(PyCiphertext {
            inner: evaluator.add_plain(&ct.inner, value),
        })
    }

    fn mul_plain(&self, ct: &PyCiphertext, value: u64) -> PyCiphertext {
        let evaluator = BFVEvaluator::new(&self.ntt, &self.encoder, None);
        PyCiphertext {
            inner: evaluator.mul_plain(&ct.inner, value),
        }
    }

    #[allow(deprecated)]
    fn mul(
        &self,
        ct1: &PyCiphertext,
        ct2: &PyCiphertext,
        eval_key: &PyEvaluationKey,
    ) -> PyCiphertext {
        let evaluator = BFVEvaluator::new(&self.ntt, &self.encoder, Some(&eval_key.inner));
        PyCiphertext {
            inner: evaluator.mul(&ct1.inner, &ct2.inner),
        }
    }

    fn batch_encrypt(
        &self,
        values: Bound<'_, PyList>,
        public_key: &PyPublicKey,
    ) -> PyResult<Vec<PyCiphertext>> {
        let values: Vec<u64> = values.extract()?;
        let encryptor =
            BFVEncryptor::new(&public_key.inner, &self.encoder, &self.ntt, self.config.eta);
        let mut harvester = ShadowHarvester::with_seed(42);

        values
            .into_iter()
            .map(|value| {
                let ct = encryptor
                    .try_encrypt(value, &mut harvester)
                    .map_err(nine65_err)?;
                Ok(PyCiphertext { inner: ct })
            })
            .collect()
    }

    fn batch_decrypt(
        &self,
        ciphertexts: Bound<'_, PyList>,
        secret_key: &PySecretKey,
    ) -> PyResult<Vec<u64>> {
        let ciphertexts: Vec<PyRef<PyCiphertext>> = ciphertexts.extract()?;
        let decryptor = BFVDecryptor::new(&secret_key.inner, &self.encoder, &self.ntt);
        Ok(ciphertexts
            .iter()
            .map(|ct| decryptor.decrypt(&ct.inner))
            .collect())
    }
}

#[pymodule]
fn nine65_python(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyFHEConfig>()?;
    m.add_class::<PySecureConfig>()?;
    m.add_class::<PyFHEContext>()?;
    m.add_class::<PyKeySet>()?;
    m.add_class::<PyPublicKey>()?;
    m.add_class::<PySecretKey>()?;
    m.add_class::<PyEvaluationKey>()?;
    m.add_class::<PyCiphertext>()?;
    Ok(())
}
