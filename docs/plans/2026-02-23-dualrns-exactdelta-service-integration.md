# DualRNS + ExactDelta Service Integration Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Wire the DualRNS 5-anchor multiplication path and ExactDelta encoding through the fhe-service HTTP API, fixing ct×ct multiplication (currently broken on all configs) and near-t rounding errors.

**Architecture:** Replace the single-modulus BFV pipeline in fhe-service with the full DualRNS pipeline from `RNSFHEContext`. Sessions will generate DualRNS keys, encrypt/decrypt in dual-track form, and use `mul_dual_public()` for correct ct×ct multiplication. ExactDelta provides exact `q/t` encoding to eliminate near-t drift. The HTTP API stays unchanged — same endpoints, same JSON shapes, same base64 ciphertext format. The internal representation changes from `Ciphertext` to `DualRNSCiphertext`.

**Tech Stack:** Rust, nine65 core library (`RNSFHEContext`, `DualRNSFullKeySet`, `DualRNSCiphertext`), serde/bincode serialization, base64 wire encoding.

---

## Background

### Why Single-Modulus Fails

The current fhe-service uses `BFVEvaluator` with a single NTT prime (q = primes[0] ≈ 30 bits). For ct×ct multiplication, the tensor product produces terms of order Δ² ≈ q²/t² which must be rescaled back to Δ ≈ q/t. With a single modulus, this rescaling is lossy — the K-Elimination capacity (~110 bits) is insufficient for the anchor product needed to reconstruct exact values after tensor product on multi-prime configs.

### Why DualRNS Fixes It

`RNSFHEContext` distributes computation across all config primes (Q = product of 3-6 primes, 90-177 bits) plus 5 anchor primes (158 bits). The `mul_dual_public()` function:
1. Computes tensor product in dual-RNS form
2. Uses K-Elimination with 5 anchors for exact rescaling
3. Relinearizes using encrypted evaluation key (public, not symmetric)
4. Returns a correct `DualRNSCiphertext`

### Why ExactDelta Fixes Near-t

Current encoder: `delta = q / t` (integer division, discards remainder). When `m * delta` approaches `q`, modular wrap causes ±1-3 decode errors. `ExactDelta` stores the exact rational q/t and uses `scale_and_round()` for precise encoding, eliminating the drift zone.

---

## Task 1: Add serde derives to DualRNS types

**Files:**
- Modify: `crates/nine65/src/ops/rns_fhe.rs` (lines 214-316)

**Step 1: Add serde + bincode derives to DualRNSPoly**

At line 213 (above `pub struct DualRNSPoly`), add:
```rust
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DualRNSPoly {
```

**Step 2: Add serde + bincode derives to DualRNSCiphertext**

At line 249 (above `pub struct DualRNSCiphertext`), add:
```rust
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DualRNSCiphertext {
```

**Step 3: Verify DualRNSSecretKey, DualRNSPublicKey, DualRNSEvalKey have serde derives**

These should already have `#[cfg_attr(feature = "serde", ...)]` (lines 262, 271, 285). Verify and add if missing. `DualRNSFullKeySet` (line 312) also needs the derive.

**Step 4: Build and test**

Run: `cargo build -p nine65 --release --features serde`
Expected: 0 errors, serde derives compile cleanly.

**Step 5: Commit**

```bash
git add crates/nine65/src/ops/rns_fhe.rs
git commit -m "feat(nine65): add serde derives to DualRNS types for service integration"
```

---

## Task 2: Add missing DualRNS operations to RNSFHEContext

**Files:**
- Modify: `crates/nine65/src/ops/rns_fhe.rs` (after `add_dual` at ~line 2920)

The current `RNSFHEContext` has `add_dual` and `mul_dual_public` but is missing `sub_dual`, `negate_dual`, `add_plain_dual`, and `mul_plain_dual`. These are needed for the service's evaluate handler.

**Step 1: Write tests for the missing operations**

Add to the test module at the bottom of `rns_fhe.rs`:

```rust
#[test]
fn test_sub_dual_basic() {
    let config = FHEConfig::standard_128();
    let ctx = RNSFHEContext::new(&config);
    let mut rng = ShadowHarvester::with_seed(42);
    let keys = ctx.generate_keys_dual_full(&mut rng);
    let ct_a = ctx.encrypt_dual(10, &keys.public_key, &mut rng);
    let ct_b = ctx.encrypt_dual(3, &keys.public_key, &mut rng);
    let ct_sub = ctx.sub_dual(&ct_a, &ct_b);
    let result = ctx.decrypt_dual(&ct_sub, &keys.secret_key);
    assert_eq!(result, 7, "10 - 3 should be 7");
}

#[test]
fn test_negate_dual_basic() {
    let config = FHEConfig::standard_128();
    let ctx = RNSFHEContext::new(&config);
    let mut rng = ShadowHarvester::with_seed(42);
    let keys = ctx.generate_keys_dual_full(&mut rng);
    let ct = ctx.encrypt_dual(10, &keys.public_key, &mut rng);
    let ct_neg = ctx.negate_dual(&ct);
    let result = ctx.decrypt_dual(&ct_neg, &keys.secret_key);
    assert_eq!(result, config.t - 10, "-10 mod t");
}

#[test]
fn test_add_plain_dual_basic() {
    let config = FHEConfig::standard_128();
    let ctx = RNSFHEContext::new(&config);
    let mut rng = ShadowHarvester::with_seed(42);
    let keys = ctx.generate_keys_dual_full(&mut rng);
    let ct = ctx.encrypt_dual(10, &keys.public_key, &mut rng);
    let ct_add = ctx.add_plain_dual(&ct, 5);
    let result = ctx.decrypt_dual(&ct_add, &keys.secret_key);
    assert_eq!(result, 15, "10 + 5 should be 15");
}

#[test]
fn test_mul_plain_dual_basic() {
    let config = FHEConfig::standard_128();
    let ctx = RNSFHEContext::new(&config);
    let mut rng = ShadowHarvester::with_seed(42);
    let keys = ctx.generate_keys_dual_full(&mut rng);
    let ct = ctx.encrypt_dual(7, &keys.public_key, &mut rng);
    let ct_mul = ctx.mul_plain_dual(&ct, 6);
    let result = ctx.decrypt_dual(&ct_mul, &keys.secret_key);
    assert_eq!(result, 42, "7 * 6 should be 42");
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p nine65 --lib --release test_sub_dual_basic test_negate_dual_basic test_add_plain_dual_basic test_mul_plain_dual_basic`
Expected: 4 compile errors (methods don't exist yet).

**Step 3: Implement sub_dual**

Add after `add_dual` (around line 2920):

```rust
/// Subtract two dual-track ciphertexts: ct1 - ct2
pub fn sub_dual(&self, ct1: &DualRNSCiphertext, ct2: &DualRNSCiphertext) -> DualRNSCiphertext {
    let neg = self.negate_dual(ct2);
    self.add_dual(ct1, &neg)
}
```

**Step 4: Implement negate_dual**

```rust
/// Negate a dual-track ciphertext: -ct (mod each prime)
pub fn negate_dual(&self, ct: &DualRNSCiphertext) -> DualRNSCiphertext {
    DualRNSCiphertext {
        c0: self.dual_poly_negate(&ct.c0),
        c1: self.dual_poly_negate(&ct.c1),
        level: ct.level,
    }
}
```

Also add the helper `dual_poly_negate`:
```rust
/// Negate a DualRNSPoly (q_i - coeff for each prime)
fn dual_poly_negate(&self, poly: &DualRNSPoly) -> DualRNSPoly {
    let main: Vec<Vec<u64>> = poly.main.iter().enumerate().map(|(i, limb)| {
        let p = self.dual_rns.main.primes[i];
        limb.iter().map(|&c| if c == 0 { 0 } else { p - c }).collect()
    }).collect();
    let anchor: Vec<Vec<u64>> = poly.anchor.iter().enumerate().map(|(i, limb)| {
        let p = self.dual_rns.anchor.primes[i];
        limb.iter().map(|&c| if c == 0 { 0 } else { p - c }).collect()
    }).collect();
    DualRNSPoly { main, anchor, n: poly.n }
}
```

**Step 5: Implement add_plain_dual**

```rust
/// Add a plaintext scalar to a dual-track ciphertext
pub fn add_plain_dual(&self, ct: &DualRNSCiphertext, scalar: u64) -> DualRNSCiphertext {
    assert!(scalar < self.t, "scalar must be < t");
    // Encode: delta * scalar in each RNS channel
    let encoded = self.encode_scalar_dual(scalar);
    DualRNSCiphertext {
        c0: self.dual_poly_add(&ct.c0, &encoded),
        c1: ct.c1.clone(),
        level: ct.level,
    }
}
```

The `encode_scalar_dual` helper encodes `delta * m` into each RNS limb:
```rust
/// Encode a scalar m as delta*m in dual-RNS form (constant polynomial)
fn encode_scalar_dual(&self, m: u64) -> DualRNSPoly {
    let main: Vec<Vec<u64>> = self.dual_rns.main.primes.iter().map(|&p| {
        let delta_p = (p / self.t) as u128;  // delta mod p
        let encoded = ((delta_p * m as u128) % p as u128) as u64;
        let mut coeffs = vec![0u64; self.n];
        coeffs[0] = encoded;
        coeffs
    }).collect();
    let anchor: Vec<Vec<u64>> = self.dual_rns.anchor.primes.iter().map(|&p| {
        let delta_p = (p / self.t) as u128;
        let encoded = ((delta_p * m as u128) % p as u128) as u64;
        let mut coeffs = vec![0u64; self.n];
        coeffs[0] = encoded;
        coeffs
    }).collect();
    DualRNSPoly { main, anchor, n: self.n }
}
```

Note: For the anchor primes, `delta_p = p / t` is a rough approximation. The exact delta mod each prime should be `(Q/t) mod p_i`. We need to use `compute_delta_rns_overflow_safe` or the existing delta computation in `encrypt_dual`. Check `encrypt_dual` (line 2110+) for how delta is computed per-prime and replicate.

**Step 6: Implement mul_plain_dual**

```rust
/// Multiply a dual-track ciphertext by a plaintext scalar
pub fn mul_plain_dual(&self, ct: &DualRNSCiphertext, scalar: u64) -> DualRNSCiphertext {
    assert!(scalar < self.t, "scalar must be < t");
    let scalar_poly = self.scalar_to_dual_poly(scalar);
    DualRNSCiphertext {
        c0: self.dual_poly_mul(&ct.c0, &scalar_poly),
        c1: self.dual_poly_mul(&ct.c1, &scalar_poly),
        level: ct.level,
    }
}

/// Create a constant DualRNSPoly with value `scalar` (NOT delta-encoded)
fn scalar_to_dual_poly(&self, scalar: u64) -> DualRNSPoly {
    let main: Vec<Vec<u64>> = self.dual_rns.main.primes.iter().map(|&p| {
        let mut coeffs = vec![0u64; self.n];
        coeffs[0] = scalar % p;
        coeffs
    }).collect();
    let anchor: Vec<Vec<u64>> = self.dual_rns.anchor.primes.iter().map(|&p| {
        let mut coeffs = vec![0u64; self.n];
        coeffs[0] = scalar % p;
        coeffs
    }).collect();
    DualRNSPoly { main, anchor, n: self.n }
}
```

**Step 7: Run tests to verify they pass**

Run: `cargo test -p nine65 --lib --release test_sub_dual_basic test_negate_dual_basic test_add_plain_dual_basic test_mul_plain_dual_basic -- --nocapture`
Expected: 4 tests PASS.

**Step 8: Commit**

```bash
git add crates/nine65/src/ops/rns_fhe.rs
git commit -m "feat(nine65): add sub/negate/add_plain/mul_plain dual-track operations"
```

---

## Task 3: Add DualRNSCiphertext serialization helpers

**Files:**
- Modify: `crates/nine65/src/ops/rns_fhe.rs` (add `to_bytes`/`from_bytes` to DualRNSCiphertext)

The service serializes ciphertexts to bincode bytes then base64-encodes them. `DualRNSCiphertext` needs equivalent methods to `Ciphertext::to_bytes()` / `Ciphertext::from_bytes_validated()`.

**Step 1: Write test**

```rust
#[test]
fn test_dual_ct_serialization_roundtrip() {
    let config = FHEConfig::standard_128();
    let ctx = RNSFHEContext::new(&config);
    let mut rng = ShadowHarvester::with_seed(42);
    let keys = ctx.generate_keys_dual_full(&mut rng);
    let ct = ctx.encrypt_dual(42, &keys.public_key, &mut rng);
    let bytes = ct.to_bytes().unwrap();
    let ct2 = DualRNSCiphertext::from_bytes_validated(&bytes, config.n).unwrap();
    let val = ctx.decrypt_dual(&ct2, &keys.secret_key);
    assert_eq!(val, 42);
}
```

**Step 2: Run test to verify it fails**

Expected: compile error (methods don't exist).

**Step 3: Implement serialization**

Add to `impl DualRNSCiphertext` (requires `serde` feature):

```rust
#[cfg(feature = "serde")]
impl DualRNSCiphertext {
    /// Serialize to bincode bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        bincode::serde::encode_to_vec(self, bincode::config::standard())
            .map_err(|e| format!("bincode encode: {}", e))
    }

    /// Deserialize from bincode bytes with validation
    pub fn from_bytes_validated(bytes: &[u8], expected_n: usize) -> Result<Self, String> {
        let (ct, _): (Self, _) = bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map_err(|e| format!("bincode decode: {}", e))?;
        // Validate polynomial degree
        if ct.c0.n != expected_n || ct.c1.n != expected_n {
            return Err(format!("degree mismatch: expected {}, got c0={} c1={}", expected_n, ct.c0.n, ct.c1.n));
        }
        Ok(ct)
    }
}
```

Note: Check bincode version. The service uses `bincode = "1.3"` while nine65 uses `bincode = "2.0"`. The service may need to match nine65's bincode version, or we use a compatible serialization approach. Verify the bincode API works with the version in use and adjust accordingly.

**Step 4: Run test to verify it passes**

Run: `cargo test -p nine65 --lib --release --features serde test_dual_ct_serialization_roundtrip -- --nocapture`
Expected: PASS.

**Step 5: Commit**

```bash
git add crates/nine65/src/ops/rns_fhe.rs
git commit -m "feat(nine65): add bincode serialization for DualRNSCiphertext"
```

---

## Task 4: Update fhe-service Session to hold DualRNS state

**Files:**
- Modify: `crates/fhe-service/Cargo.toml` (no new deps, just verify features)
- Modify: `crates/fhe-service/src/session.rs`

**Step 1: Update session.rs imports**

Add to the imports at the top:

```rust
use nine65::ops::rns_fhe::{RNSFHEContext, DualRNSCiphertext, DualRNSFullKeySet};
```

**Step 2: Add DualRNS fields to Session struct**

```rust
pub struct Session {
    // ... existing fields stay ...
    pub rns_ctx: RNSFHEContext,
    pub dual_keys: DualRNSFullKeySet,
}
```

**Step 3: Update Session::new() to generate DualRNS context and keys**

Inside `Session::new()`, after `let config = secure_config.into_config();`:

```rust
let rns_ctx = RNSFHEContext::try_new(&config)
    .map_err(|_| "RNS context creation failed")?;
let dual_keys = rns_ctx.generate_keys_dual_full_secure();
```

Add these to the `Ok(Self { ... })` block.

**Step 4: Update Session::new_test() similarly**

Inside `new_test()`, after creating the config:
```rust
let rns_ctx = RNSFHEContext::try_new(&config)
    .map_err(|_| "RNS context creation failed")?;
let dual_keys = rns_ctx.generate_keys_dual_full(&mut harvester);
```

**Step 5: Add DualRNS ciphertext serialization helpers to Session**

```rust
/// Serialize a DualRNSCiphertext to base64
pub fn dual_ct_to_b64(&self, ct: &DualRNSCiphertext) -> Result<String, String> {
    let bytes = ct.to_bytes()?;
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &bytes,
    ))
}

/// Deserialize a DualRNSCiphertext from base64 with validation
pub fn dual_ct_from_b64(&self, b64: &str) -> Result<DualRNSCiphertext, String> {
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
        .map_err(|e| format!("base64 decode: {}", e))?;
    DualRNSCiphertext::from_bytes_validated(&bytes, self.config.n)
}
```

**Step 6: Build the service crate**

Run: `cargo build -p fhe-service --release`
Expected: 0 errors. May have warnings about unused old fields — that's fine for now.

**Step 7: Commit**

```bash
git add crates/fhe-service/src/session.rs crates/fhe-service/Cargo.toml
git commit -m "feat(fhe-service): add DualRNS context and keys to Session"
```

---

## Task 5: Switch encrypt handler to DualRNS

**Files:**
- Modify: `crates/fhe-service/src/handlers.rs` (handle_encrypt, ~line 200-267)

**Step 1: Write integration test**

In `crates/fhe-service/src/handlers.rs` (or a test file), add:

```rust
#[cfg(test)]
#[test]
fn test_encrypt_decrypt_dual_roundtrip() {
    let session = Session::new_test("secure_128", 42).unwrap();
    let store = SessionStore::new(10);
    let sid = store.insert(session).unwrap();
    // Test via direct session access
    store.with_session_mut(&sid, |session| {
        let ct = session.rns_ctx.encrypt_dual_secure(42, &session.dual_keys.public_key);
        let b64 = session.dual_ct_to_b64(&ct).unwrap();
        let ct2 = session.dual_ct_from_b64(&b64).unwrap();
        let val = session.rns_ctx.decrypt_dual(&ct2, &session.dual_keys.secret_key);
        assert_eq!(val, 42);
    });
}
```

**Step 2: Update handle_encrypt to use DualRNS path**

Replace the encrypt loop (lines 232-251) with:

```rust
let mut ciphertexts = Vec::with_capacity(req.values.len());
for &v in &req.values {
    if v >= session.config.t {
        return Err("invalid value".to_owned());
    }
    session
        .noise_budget
        .consume(NoiseOpType::Encrypt, NoiseBudget::encrypt_cost(&session.config))
        .map_err(|e| format!("noise exhausted: {}", e))?;
    let ct = session.rns_ctx.encrypt_dual_secure(v, &session.dual_keys.public_key);
    let b64 = session.dual_ct_to_b64(&ct)?;
    ciphertexts.push(b64);
}
```

**Step 3: Update handle_decrypt to use DualRNS path**

Replace the decrypt loop (lines 294-298) with:

```rust
let mut values = Vec::with_capacity(req.ciphertexts.len());
for ct_b64 in &req.ciphertexts {
    let ct = session.dual_ct_from_b64(ct_b64)?;
    let v = session.rns_ctx.decrypt_dual(&ct, &session.dual_keys.secret_key);
    values.push(v);
}
```

**Step 4: Build and run tests**

Run: `cargo test -p fhe-service --release -- --nocapture`
Expected: All existing tests pass (may need updating if they create sessions with old format).

**Step 5: Commit**

```bash
git add crates/fhe-service/src/handlers.rs
git commit -m "feat(fhe-service): switch encrypt/decrypt to DualRNS pipeline"
```

---

## Task 6: Switch evaluate handler to DualRNS

**Files:**
- Modify: `crates/fhe-service/src/handlers.rs` (handle_evaluate, ~line 320-483)

This is the key change — replacing single-modulus `BFVEvaluator` with `RNSFHEContext` operations.

**Step 1: Update ciphertext deserialization in evaluate**

Change `session.ct_from_b64(input_b64)?` to `session.dual_ct_from_b64(input_b64)?` and change the `cts` type to `Vec<DualRNSCiphertext>`.

**Step 2: Replace each operation branch**

```rust
let result_ct = match op.op.as_str() {
    "add" => {
        if cts.len() != 2 { return Err("add requires exactly 2 inputs".to_owned()); }
        session.noise_budget
            .consume(NoiseOpType::Add, NoiseBudget::add_cost())
            .map_err(|e| format!("noise exhausted: {}", e))?;
        session.rns_ctx.add_dual(&cts[0], &cts[1])
    }
    "sub" => {
        if cts.len() != 2 { return Err("sub requires exactly 2 inputs".to_owned()); }
        session.noise_budget
            .consume(NoiseOpType::Add, NoiseBudget::add_cost())
            .map_err(|e| format!("noise exhausted: {}", e))?;
        session.rns_ctx.sub_dual(&cts[0], &cts[1])
    }
    "negate" => {
        if cts.len() != 1 { return Err("negate requires exactly 1 input".to_owned()); }
        session.noise_budget
            .consume(NoiseOpType::Add, NoiseBudget::add_cost())
            .map_err(|e| format!("noise exhausted: {}", e))?;
        session.rns_ctx.negate_dual(&cts[0])
    }
    "add_plain" => {
        if cts.len() != 1 { return Err("add_plain requires exactly 1 input".to_owned()); }
        let scalar = op.scalar.ok_or_else(|| "add_plain requires scalar".to_owned())?;
        if scalar >= session.config.t { return Err("invalid scalar".to_owned()); }
        session.noise_budget
            .consume(NoiseOpType::AddPlain, NoiseBudget::add_plain_cost())
            .map_err(|e| format!("noise exhausted: {}", e))?;
        session.rns_ctx.add_plain_dual(&cts[0], scalar)
    }
    "mul_plain" => {
        if cts.len() != 1 { return Err("mul_plain requires exactly 1 input".to_owned()); }
        let scalar = op.scalar.ok_or_else(|| "mul_plain requires scalar".to_owned())?;
        if scalar >= session.config.t { return Err("invalid scalar".to_owned()); }
        session.noise_budget
            .consume(NoiseOpType::MulPlain, NoiseBudget::mul_plain_cost(&session.config))
            .map_err(|e| format!("noise exhausted: {}", e))?;
        session.rns_ctx.mul_plain_dual(&cts[0], scalar)
    }
    "mul" => {
        if cts.len() != 2 { return Err("mul requires exactly 2 inputs".to_owned()); }
        session.noise_budget
            .consume(NoiseOpType::MulCt, NoiseBudget::mul_ct_cost(&session.config))
            .map_err(|e| format!("noise exhausted: {}", e))?;
        session.noise_budget
            .consume(NoiseOpType::Relin, NoiseBudget::relin_cost(&session.config))
            .map_err(|e| format!("noise exhausted: {}", e))?;
        session.noise_budget
            .consume(NoiseOpType::Rescale, NoiseBudget::rescale_cost(&session.config))
            .map_err(|e| format!("noise exhausted: {}", e))?;
        session.rns_ctx.mul_dual_public(&cts[0], &cts[1], &session.dual_keys.eval_key)
            .map_err(|e| format!("mul failed: {}", e))?
    }
    other => { return Err(format!("unknown operation: {}", other)); }
};
```

**Step 3: Update result serialization**

Change `session.ct_to_b64(&result_ct)?` to `session.dual_ct_to_b64(&result_ct)?`.

**Step 4: Remove the `BFVEvaluator` construction**

Delete the line:
```rust
let evaluator = BFVEvaluator::new(&session.ntt, &session.encoder, Some(&session.eval_key));
```

This is no longer needed since all operations go through `session.rns_ctx`.

**Step 5: Build and run tests**

Run: `cargo test -p fhe-service --release -- --nocapture`
Expected: All tests pass with DualRNS pipeline.

**Step 6: Commit**

```bash
git add crates/fhe-service/src/handlers.rs
git commit -m "feat(fhe-service): switch evaluate handler to DualRNS operations

Fixes ct×ct multiplication on all configs by using mul_dual_public
with 5-anchor K-Elimination for exact rescaling."
```

---

## Task 7: Update API_REFERENCE.md to reflect DualRNS

**Files:**
- Modify: `crates/fhe-service/API_REFERENCE.md` (line 235)

**Step 1: Update the mul operation note**

Replace the "Important" note at line 235 with:

```
**Note**: The `mul` (ct×ct) operation uses the DualRNS K-Elimination path with 5 anchor primes for exact rescaling. This provides correct results on all configurations. Each ct×ct multiplication consumes significant noise budget (~30000 mb for mul + relin, partially offset by rescale gain).
```

**Step 2: Verify no other doc changes needed**

Check that the noise budget table and chaining example are still accurate.

**Step 3: Commit**

```bash
git add crates/fhe-service/API_REFERENCE.md
git commit -m "docs: update API reference to reflect DualRNS ct×ct multiplication"
```

---

## Task 8: Add ExactDelta feature to fhe-service (optional, for near-t fix)

**Files:**
- Modify: `crates/fhe-service/Cargo.toml`
- Modify: `crates/fhe-service/src/session.rs`

**Step 1: Add exact_rational feature flag to fhe-service**

In `crates/fhe-service/Cargo.toml`:
```toml
[features]
default = []
allow_insecure = ["nine65/allow_insecure"]
exact_rational = ["nine65/exact_rational"]
```

**Step 2: Add ExactDelta to Session (feature-gated)**

In session.rs, behind `#[cfg(feature = "exact_rational")]`:

```rust
#[cfg(feature = "exact_rational")]
use nine65::params::exact_params::ExactDelta;

pub struct Session {
    // ... existing fields ...
    #[cfg(feature = "exact_rational")]
    pub exact_delta: ExactDelta,
}
```

In `Session::new()`:
```rust
#[cfg(feature = "exact_rational")]
let exact_delta = ExactDelta::new(config.q, config.t);
```

**Step 3: Use ExactDelta in encode validation**

In the encrypt handler, add a bounds check using ExactDelta before encryption:

```rust
#[cfg(feature = "exact_rational")]
{
    // ExactDelta can detect drift-zone values
    if v > session.config.t.saturating_sub(100) {
        return Err("value in near-t drift zone".to_owned());
    }
}
```

This is a conservative bounds check. The full ExactDelta integration (replacing BFVEncoder's truncated delta) requires deeper changes to the RNSFHEContext encoding path, which is a separate effort.

**Step 4: Build with feature**

Run: `cargo build -p fhe-service --release --features exact_rational`
Expected: Compiles. May need to add `nexgen_rational` as a transitive dependency.

**Step 5: Commit**

```bash
git add crates/fhe-service/Cargo.toml crates/fhe-service/src/session.rs
git commit -m "feat(fhe-service): add exact_rational feature flag with near-t bounds check"
```

---

## Task 9: End-to-end integration test

**Files:**
- Modify: `crates/fhe-service/src/handlers.rs` (test module)

**Step 1: Write ct×ct multiplication test**

```rust
#[test]
fn test_mul_ct_ct_correct_via_dual_rns() {
    let session = Session::new_test("secure_128", 42).unwrap();
    let store = SessionStore::new(10);
    let sid = store.insert(session).unwrap();

    store.with_session_mut(&sid, |session| {
        let ct_a = session.rns_ctx.encrypt_dual_secure(11, &session.dual_keys.public_key);
        let ct_b = session.rns_ctx.encrypt_dual_secure(13, &session.dual_keys.public_key);
        let ct_mul = session.rns_ctx.mul_dual_public(&ct_a, &ct_b, &session.dual_keys.eval_key)
            .expect("mul_dual_public should succeed");
        let result = session.rns_ctx.decrypt_dual(&ct_mul, &session.dual_keys.secret_key);
        assert_eq!(result, 143, "11 * 13 should be 143, got {}", result);
    });
}
```

**Step 2: Write full HTTP-path test**

Test the complete flow: create session → encrypt → mul → decrypt, verifying ct×ct gives correct results through the HTTP handlers. Use the existing test infrastructure if available, or test via direct handler calls.

**Step 3: Run full test suite**

Run: `cargo test -p fhe-service --release -- --nocapture`
Run: `cargo test --workspace --release`
Expected: All tests pass.

**Step 4: Commit**

```bash
git add crates/fhe-service/src/handlers.rs
git commit -m "test(fhe-service): add ct×ct multiplication correctness test via DualRNS"
```

---

## Task 10: Rebuild release tarball

**Step 1: Run full workspace tests**

Run: `cargo test --workspace --release`
Expected: All tests pass (1163+ tests, 0 failures).

**Step 2: Build release binary**

Run: `cargo build -p fhe-service --release`

**Step 3: Rebuild tarball**

Follow the existing release process to create `NINE65_v7-release-x86_64-linux.tar.gz` with the updated binary and docs.

**Step 4: Verify tarball**

Extract and check:
- `docs/API_REFERENCE.md` reflects DualRNS mul
- `bin/fhe-service` binary is updated
- sha256 checksum noted

**Step 5: Commit (if any release scripts changed)**

---

## Summary of Changes

| Component | Before | After |
|-----------|--------|-------|
| Session keygen | Single-modulus KeySet | + RNSFHEContext + DualRNSFullKeySet |
| Encrypt | BFVEncryptor (single prime q) | RNSFHEContext.encrypt_dual_secure (all primes Q) |
| Decrypt | BFVDecryptor (single prime q) | RNSFHEContext.decrypt_dual (all primes Q) |
| Add/Sub/Negate | BFVEvaluator (correct) | RNSFHEContext.{add,sub,negate}_dual (correct) |
| Add/Mul Plain | BFVEvaluator (correct) | RNSFHEContext.{add,mul}_plain_dual (correct) |
| Mul ct×ct | BFVEvaluator.mul_no_relin + relinearize (BROKEN) | RNSFHEContext.mul_dual_public (CORRECT, 5 anchors) |
| Ciphertext wire format | Ciphertext → bincode → base64 | DualRNSCiphertext → bincode → base64 |
| Near-t rounding | Truncated delta, drift zone | Bounds check (Task 8), exact delta path available |
| API | Unchanged | Unchanged (same endpoints, same JSON) |

## Risk Notes

1. **Ciphertext size increase**: DualRNSCiphertext includes anchor limbs (5 extra sets of n coefficients per component). For n=4096, this is ~5×8KB = ~40KB extra per ciphertext. Total ciphertext size roughly doubles. The MAX_RESPONSE_BYTES and estimated_ct_size in handlers.rs will need adjustment.

2. **Keygen time increase**: Generating DualRNSFullKeySet (including eval key with digit decomposition across 8 primes) is slower than single-modulus KeySet. Session creation will take longer.

3. **Backward incompatibility**: Existing ciphertexts (single-modulus format) cannot be decrypted by the new DualRNS path. This is a breaking change for any stored ciphertexts. Since sessions are ephemeral (TTL-based), this is acceptable.

4. **bincode version mismatch**: fhe-service uses bincode 1.3, nine65 uses bincode 2.0. Serialization format differs between versions. Need to align on one version.
