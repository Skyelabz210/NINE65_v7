use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList};

use nine65::arithmetic::boundary::{
    capacity_proximity_bits, post_switch_margin_bits, CapacityRegion,
};
use nine65::entropy::ShadowHarvester;
use nine65::errors::Nine65Error;
use nine65::keys::{EvaluationKey, KeySet, PublicKey, SecretKey};
use nine65::ops::{BFVDecryptor, BFVEncoder, BFVEncryptor, BFVEvaluator, Ciphertext};
use nine65::params::secure_configs::SecureConfig;
use nine65::params::FHEConfig;
use nine65::prelude::NTTEngine;

// ─── PyO3 binding boundary thresholds ─────────────────────────────────────────
//
// These thresholds are MORE CONSERVATIVE than the internal Rust thresholds:
// PyO3 callers get warnings/errors before a Python-opaque Rust panic can occur.
//
// Background: When NINE65 internally promotes u128 → U256 during ct×ct operations
// for large-N configurations, Python callers previously got unhandled panics.
// These checks surface the capacity concern BEFORE the operation is attempted.
//
// The values are in "bit-length percentage":
//   80% means: if the intermediate bit-count is 80% of the anchor capacity bits,
//              emit a Python warning (logged, operation still proceeds).
//   90% means: return a Python ValueError before the operation runs.
const PYBINDING_WARN_PCT: u32 = 80;
const PYBINDING_ERROR_PCT: u32 = 90;

/// Compute intermediate value bit-length for a given config.
///
/// During ct×ct, intermediate values can reach ≈ N × Q² (tensor product bound).
/// Returns log2(N × Q²) = log2(N) + 2 × log2(Q).
fn intermediate_bits_for_config(cfg: &FHEConfig) -> u32 {
    if cfg.q == 0 || cfg.n == 0 {
        return 0;
    }
    let q_bits = 64 - cfg.q.leading_zeros();
    let n_bits = 64 - (cfg.n as u64).leading_zeros();
    n_bits + 2 * q_bits
}

/// Check whether a given config's intermediate values are near the u128 boundary.
///
/// Returns `Ok(None)` if safe, `Ok(Some(warning))` at ≥80%, `Err` at ≥90%.
/// The anchor capacity for the canonical 5-anchor set is 159 bits
/// (measured: 2013265921≈31b + 2281701377≈31b + 2483027969≈32b + 2885681153≈32b + 3221225473≈32b = 158-159 bits).
fn check_config_intermediate_boundary(cfg: &FHEConfig) -> PyResult<Option<String>> {
    // Canonical anchor capacity: 5 primes totaling 159 bits (empirically measured)
    let anchor_capacity_bits: u32 = 159;
    let intermediate = intermediate_bits_for_config(cfg);
    let report = capacity_proximity_bits(intermediate, anchor_capacity_bits);

    match report.region {
        CapacityRegion::Critical => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "FHE config '{}' (n={}, q={}) requires {}-bit intermediate values, \
             which EXCEEDS the {}-bit anchor capacity. \
             ct×ct multiplication will overflow. Use a config with fewer/smaller primes.",
            cfg.name, cfg.n, cfg.q, intermediate, anchor_capacity_bits
        ))),
        CapacityRegion::Warn90 => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "FHE config '{}' (n={}, q={}) requires {}-bit intermediate values, \
             which is {}%+ of the {}-bit anchor capacity (threshold: {}%). \
             ct×ct multiplication is at high risk of anchor overflow. \
             Review anchor prime sizing before proceeding.",
            cfg.name,
            cfg.n,
            cfg.q,
            intermediate,
            PYBINDING_ERROR_PCT,
            anchor_capacity_bits,
            PYBINDING_ERROR_PCT,
        ))),
        CapacityRegion::Warn80 => Ok(Some(format!(
            "PyO3 boundary warning: FHE config '{}' intermediate values ({} bits) \
             are {}% of anchor capacity ({} bits). \
             ct×ct multiplication is approaching the anchor capacity boundary. \
             Monitor operations carefully or increase anchor count.",
            cfg.name, intermediate, report.utilization_pct, anchor_capacity_bits,
        ))),
        CapacityRegion::Safe => Ok(None),
    }
}

/// Check post-switch margin after a hypothetical u128→U256 promotion.
///
/// If `intermediate_bits` is > 128, a U256 promotion occurred. This function
/// checks the headroom in U256 (256-bit capacity) and returns a warning/error
/// if headroom is critically low (< 5%) or marginal (5–15%).
fn check_post_switch_margin_u256(intermediate_bits: u32) -> Option<String> {
    if intermediate_bits <= 128 {
        return None; // No promotion occurred
    }
    let margin = post_switch_margin_bits(intermediate_bits, 256);
    if margin.is_critical {
        Some(format!(
            "PyO3 post-switch CRITICAL: after u128→U256 promotion, \
             intermediate value uses {} of 256 bits ({}% headroom). \
             Next operation likely overflows U256. Anchor set is undersized.",
            intermediate_bits, margin.headroom_pct
        ))
    } else if margin.is_marginal {
        Some(format!(
            "PyO3 post-switch WARNING: after u128→U256 promotion, \
             intermediate value uses {} of 256 bits ({}% headroom — marginal). \
             Consider increasing anchor prime count.",
            intermediate_bits, margin.headroom_pct
        ))
    } else {
        None
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

fn nine65_err(err: Nine65Error) -> PyErr {
    PyErr::new::<pyo3::exceptions::PyValueError, _>(err.to_string())
}

#[pyclass(name = "FHEConfig", from_py_object)]
#[derive(Clone)]
pub struct PyFHEConfig {
    inner: FHEConfig,
}

// `standard_128_insecure` / `high_192_insecure` / `large_single_insecure` /
// `light_insecure` on the `nine65` side are all gated
// `#[cfg(any(test, debug_assertions, feature = "allow_insecure"))]` (and
// `light_insecure` is additionally `#[deprecated]`) -- they're
// test/legacy-only configs, not audited for production. The pymethods below
// must carry the *same* cfg gate as whichever underlying function they call,
// or a plain `--release` build (no `allow_insecure`, no `debug_assertions`)
// fails to compile with "function not found" rather than simply omitting
// the method from the exposed `FHEConfig` class the way it should. Prefer
// `SecureConfig.secure_128()` / `.secure_192()` / `.secure_256()` (never
// gated -- always available) for anything that isn't a reproducible test.
#[pymethods]
impl PyFHEConfig {
    #[cfg(any(test, debug_assertions, feature = "allow_insecure"))]
    #[staticmethod]
    fn standard_128() -> Self {
        Self {
            inner: FHEConfig::standard_128_insecure(),
        }
    }

    #[cfg(any(test, debug_assertions, feature = "allow_insecure"))]
    #[staticmethod]
    fn high_192() -> Self {
        Self {
            inner: FHEConfig::high_192_insecure(),
        }
    }

    #[cfg(any(test, debug_assertions, feature = "allow_insecure"))]
    #[staticmethod]
    fn large_single() -> Self {
        Self {
            inner: FHEConfig::large_single_insecure(),
        }
    }

    #[cfg(any(test, debug_assertions, feature = "allow_insecure"))]
    #[allow(deprecated)]
    #[staticmethod]
    fn light() -> Self {
        Self {
            inner: FHEConfig::light_insecure(),
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

    // Matches `SecureConfig::test_fast_insecure`'s own gate exactly (see the
    // note on `impl PyFHEConfig` above for why this must track the callee).
    #[cfg(any(test, debug_assertions, feature = "allow_insecure"))]
    #[staticmethod]
    fn test_fast() -> Self {
        Self {
            inner: SecureConfig::test_fast_insecure(),
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
    fn new(config: &PyFHEConfig) -> PyResult<Self> {
        let cfg = clone_config(&config.inner);
        // Boundary check: warn or error if this config's intermediate values
        // approach or exceed the anchor capacity.
        if let Some(warning) = check_config_intermediate_boundary(&cfg)? {
            // Warning — log to stderr (Python callers see this via sys.stderr)
            eprintln!("{}", warning);
        }
        // Post-switch margin check for configs that would require U256
        let intermediate = intermediate_bits_for_config(&cfg);
        if let Some(msg) = check_post_switch_margin_u256(intermediate) {
            eprintln!("{}", msg);
        }
        let ntt = NTTEngine::new(cfg.q, cfg.n);
        let encoder = BFVEncoder::new(&cfg);
        Ok(Self {
            config: cfg,
            ntt,
            encoder,
        })
    }

    #[staticmethod]
    fn from_secure_config(config: &PySecureConfig) -> PyResult<Self> {
        let cfg = clone_config(&config.inner.config);
        // Boundary check: surface capacity warnings before any operations run.
        if let Some(warning) = check_config_intermediate_boundary(&cfg)? {
            eprintln!("{}", warning);
        }
        let intermediate = intermediate_bits_for_config(&cfg);
        if let Some(msg) = check_post_switch_margin_u256(intermediate) {
            eprintln!("{}", msg);
        }
        let ntt = NTTEngine::new(cfg.q, cfg.n);
        let encoder = BFVEncoder::new(&cfg);
        Ok(Self {
            config: cfg,
            ntt,
            encoder,
        })
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

    /// Report the exact-correctness envelope of `mul()` for this context.
    ///
    /// Returns `(supported, max_product)`. `mul()` performs an
    /// entirely-in-Rust single-modulus ciphertext x ciphertext tensor
    /// product, relinearize, and rescale (`Δ² → Δ`) -- `nine65`'s own docs
    /// mark this path `#[deprecated]` and note it "only works when
    /// `Δ² ≤ Q`" (see `BFVEvaluator::mul` in `crates/nine65/src/ops/homomorphic.rs`).
    /// `max_product` is the largest plaintext product `a * b` that path can
    /// recover exactly; beyond it, `mul()` still returns *a* ciphertext (no
    /// panic, no error) that decrypts to a wrong-but-plausible value rather
    /// than the true product.
    ///
    /// This binding cannot check `a * b` against `max_product` for you --
    /// `mul()` only ever sees ciphertexts, and decrypting to check would
    /// defeat the point of encrypting. Check it yourself against known
    /// plaintext ranges before relying on a `mul()` result, or use
    /// `mul_plain()` (linear scalar multiply, not subject to this bound)
    /// where the multiplier is a known plaintext rather than a ciphertext.
    ///
    /// For every `SecureConfig` this crate exposes (`secure_128` /
    /// `secure_192` / `secure_256`), `max_product` is small (single digits)
    /// because this single-modulus path only ever uses the *first* RNS
    /// prime -- the additional anchor lanes that give those configs their
    /// named security level don't participate in it. `nine65` recommends
    /// `RNSFHEContext::mul_dual_symmetric()` (the DualRNS multi-lane path)
    /// for real ct×ct depth; that path is not yet bound to Python (see
    /// README.md "What's exposed").
    ///
    /// **This bound is necessary but was found NOT sufficient**: see the
    /// `mul()` doc below for a second, more severe issue that this number
    /// does not capture.
    fn mul_capacity(&self) -> (bool, u64) {
        self.config.supports_single_mod_mul()
    }

    /// Homomorphic multiplication with boundary-safe panic isolation.
    ///
    /// # This path is currently broken -- verified during the FFI/bindings
    /// # work that wired this method up (2026-09), not merely "unproven"
    ///
    /// Calling `nine65::ops::BFVEvaluator::mul()` directly in Rust -- no
    /// PyO3, no Python -- and decrypting the result with the matching
    /// secret key gives a **wrong plaintext for every case tried**,
    /// including the most trivial one (`1 * 1`), across every config
    /// checked: `SecureConfig::secure_128()` (n=8192) and, at n=1024,
    /// `light_mul_insecure`, `light_insecure`, and
    /// `SecureConfig::test_fast_insecure()`. This is a distinct failure
    /// from -- and strictly worse than -- the documented `Δ² ≤ Q` capacity
    /// note on `BFVEvaluator::mul` (`crates/nine65/src/ops/homomorphic.rs`):
    /// that note implies correctness *within* `mul_capacity()`'s bound, but
    /// `1 * 1` is within every one of those configs' bounds and still comes
    /// back wrong.
    ///
    /// This appears to be why: none of `nine65`'s own passing `#[test]`s
    /// actually exercise this exact function with a real decrypted-value
    /// assertion. `test_homomorphic_mul_with_relin` and
    /// `test_ct_mul_multiple_values` -- names that read as if they cover
    /// this -- both construct a `BFVEvaluator` with an eval key but then
    /// call `mul_no_relin()` + `decrypt_degree2()` instead of `mul()`,
    /// bypassing relinearize/rescale entirely. `test_homomorphic_mul_diagnostic`
    /// *does* call `mul()`, but asserts nothing about the result (it only
    /// prints a `[FAIL]`/`[OK]` diagnosis line for a human to read) --
    /// which is exactly the "wrong-but-plausible, no error raised" pattern
    /// this repository's own `CLAUDE.md` already documents for a different
    /// subsystem (the public-refresh `refresh(7) -> 34037` case). This one
    /// was previously undocumented as far as this change found.
    ///
    /// This binding still exposes `mul()` faithfully (it *is* what
    /// `nine65` provides, and gating it here would be a binding-layer
    /// policy call outside this change's mandate to expose, not redesign,
    /// the underlying crate) rather than hiding or silently disabling it.
    /// But do not build anything on this method's output right now --
    /// `mul_plain()` (verified exact; see `tests/`) is the safe alternative
    /// wherever the multiplier is a known plaintext rather than a
    /// ciphertext. See README.md "Known limitations" and
    /// `tests/test_known_limitations.py`, which reproduces this from
    /// Python and is intentionally marked `xfail(strict=True)`: it fails
    /// today, and if it ever unexpectedly *passes*, that's the signal this
    /// note (and the linked nine65 core issue) are stale and should be
    /// revisited, not that the test is wrong.
    ///
    /// Before multiplying, this also checks that intermediate values won't
    /// approach the anchor-capacity boundary tracked by
    /// `arithmetic::boundary` (80%/90% thresholds, a *separate* concern
    /// from either issue above -- it guards against an internal u128
    /// overflow, not against wrong-but-plausible output). If the
    /// configuration is borderline there, a Python warning is printed to
    /// stderr.
    ///
    /// Any internal Rust panic (e.g., from an unexpected capacity overflow) is
    /// caught and converted to a Python ValueError, preventing Python process crash.
    #[allow(deprecated)]
    fn mul(
        &self,
        ct1: &PyCiphertext,
        ct2: &PyCiphertext,
        eval_key: &PyEvaluationKey,
    ) -> PyResult<PyCiphertext> {
        // Pre-operation boundary check
        let intermediate = intermediate_bits_for_config(&self.config);
        let report = capacity_proximity_bits(intermediate, 159u32);
        if report.region >= CapacityRegion::Warn80 {
            let msg = format!(
                "PyO3 mul() boundary: intermediate values ({} bits) are at {}% of \
                 anchor capacity (158 bits). Proceeding, but overflow risk is elevated.",
                intermediate, report.utilization_pct
            );
            eprintln!("{}", msg);
            if report.region >= CapacityRegion::Warn90 {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(msg));
            }
        }

        let evaluator = BFVEvaluator::new(&self.ntt, &self.encoder, Some(&eval_key.inner));
        let ct1_inner = ct1.inner.clone();
        let ct2_inner = ct2.inner.clone();

        // Panic-isolate the multiply: any internal overflow becomes a Python ValueError
        // instead of crashing the Python interpreter.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            evaluator.mul(&ct1_inner, &ct2_inner)
        }))
        .map_err(|_| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "FHE multiplication panicked internally — possible anchor capacity overflow. \
                 This config may require U256 arithmetic. Check anchor prime sizing \
                 or use a smaller N/Q configuration.",
            )
        })?;

        Ok(PyCiphertext { inner: result })
    }

    /// Return a human-readable boundary proximity report for this config.
    ///
    /// Reports whether this configuration's intermediate values are approaching
    /// the anchor capacity boundary. Useful for pre-flight checks in Python code
    /// before running expensive FHE circuits.
    ///
    /// Returns a tuple: (utilization_pct: int, region: str, message: str)
    /// where region is one of "safe", "warn80", "warn90", "critical".
    fn boundary_report(&self) -> (u8, String, String) {
        let intermediate = intermediate_bits_for_config(&self.config);
        let report = capacity_proximity_bits(intermediate, 159u32);
        let region_str = match report.region {
            CapacityRegion::Safe => "safe",
            CapacityRegion::Warn80 => "warn80",
            CapacityRegion::Warn90 => "warn90",
            CapacityRegion::Critical => "critical",
        };
        let message = format!(
            "Config '{}': intermediate values = {} bits, anchor capacity = {} bits, \
             utilization = {}% (region: {})",
            self.config.name,
            report.value_bits,
            report.capacity_bits,
            report.utilization_pct,
            region_str,
        );
        (report.utilization_pct, region_str.to_string(), message)
    }

    fn batch_encrypt(
        &self,
        values: Bound<'_, PyList>,
        public_key: &PyPublicKey,
    ) -> PyResult<Vec<PyCiphertext>> {
        let values: Vec<u64> = values.extract()?;
        let encryptor =
            BFVEncryptor::new(&public_key.inner, &self.encoder, &self.ntt, self.config.eta);

        values
            .into_iter()
            .map(|value| {
                let ct = encryptor.try_encrypt_secure(value).map_err(nine65_err)?;
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

// Named `_nine65_python` (leading underscore) rather than `nine65_python`
// because this is the compiled extension backing the pure-Python package of
// the same name (see `python/nine65_python/__init__.py`, which does
// `from ._nine65_python import *` and layers key-generation helpers and
// friendlier constructors on top). The symbol name here must match the
// last path component of `[tool.maturin] module-name` in `pyproject.toml`
// — Python's import machinery resolves the `PyInit_<name>` entry point by
// that name, not by the crate's `[lib] name`.
#[pymodule]
fn _nine65_python(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
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
