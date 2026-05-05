# NINE65
## Low-Depth Bootstrap FHE for Continuous Privacy-Preserving Computation

<div align="center">

**NINE65 is an integer-only BFV/RNS FHE substrate for high-performance private computation across public-key, symmetric, service, edge, and browser-facing deployment modes.**

It is no longer just the original "v7 Bootstrap Complete" snapshot. The current codebase includes the v8 Shadow Butterfly work, real Clockwork bootstrap integration, symmetric protected refresh, SBNI timing-noise hardening, and CRAM-CT witness wiring over live DualRNS ciphertexts.

[Current Functionality](#current-functionality) | [Modes](#execution-modes) | [Quick Start](#quick-start) | [Architecture](#architecture) | [Build](#build-and-test) | [Security](#security-posture)

</div>

---

## Current Functionality

NINE65 is a modular integer-computation substrate for privacy-preserving systems. Its current role is not to be a generic survey/chatbot product or a single demo of FHE bootstrapping. It is the cryptographic compute layer that can sit under products that need continuous private evaluation, private aggregation, edge execution, or constrained-device privacy infrastructure.

The current implementation provides:

| Capability | Current implementation |
|---|---|
| **Public-key FHE mode** | DualRNS BFV evaluation with `mul_dual_public`, evaluation keys, Clockwork bootstrap, and `AutoBootstrapEvaluator` for continued depth. |
| **Low-depth bootstrap** | Clockwork bootstrap uses exact modulus switching plus plaintext×ciphertext bootstrap work, keeping the refresh circuit at low multiplicative depth. |
| **Circular + non-circular bootstrap paths** | `generate_keys()` / `bootstrap()` for circular mode and `generate_keys_with_ksk()` / `bootstrap_with_ksk()` for KSK non-circular mode. |
| **Symmetric protected refresh** | `SymmetricBootstrap` provides decrypt→re-encrypt refresh for key-holder scenarios, framed by the Three-Lock protection model. |
| **SBNI hardening** | Shadow Butterfly Noise Injection rerandomizes deterministic noise drift from butterfly-derived entropy and is wired into public multiplication paths. |
| **CRAM-CT witness layer** | `cram_ct_wrap` wraps `DualRNSCiphertext` in a phase-locked CRAM witness shell and re-extracts signatures after real BFV ops. |
| **Edge/browser path** | `nine65-wasm` exposes a browser boundary with capacity checks and disabled secret-key export. |
| **Service path** | `fhe-service` exposes session-based encrypt/decrypt/evaluate HTTP endpoints with request limits, metrics, TTL, and validation. |
| **Accelerator path** | `mana` and `unhal` provide lane-parallel and hardware-abstraction infrastructure for CRT/RNS workloads. |
| **Integer-only runtime** | Core cryptographic paths are exact integer arithmetic; the core crate forbids unsafe code. |

The practical system direction is:

```text
continuous private computation
  = exact RNS/BFV arithmetic
  + low-depth bootstrap/refresh
  + public and symmetric modes
  + edge/service/browser deployment surfaces
  + witness/lock metadata for state integrity
```

---

## Execution Modes

### 1. Public-key mode

Use this when an evaluator should compute over ciphertexts without holding the secret key.

```text
client/key-holder: key generation + encryption/decryption
server/evaluator:  add, mul, bootstrap, aggregate, route
```

Public mode uses DualRNS BFV ciphertexts, evaluation keys, and Clockwork bootstrap. `AutoBootstrapEvaluator` automatically refreshes ciphertexts when the tracked budget is exhausted or crosses a trigger threshold.

### 2. Non-circular public mode

Use this when the bootstrap key should be independent from the work key.

```text
work key != boot key
bootstrap phase output is key-switched back to the work key
```

This path uses `generate_keys_with_ksk()` and `bootstrap_with_ksk()`.

### 3. Symmetric protected mode

Use this when the evaluator is also the key holder, or when refresh runs inside a protected key boundary such as an HSM, TEE, local device, private gateway, or controlled edge node.

```text
decrypt under sk -> immediately re-encrypt -> restore fresh noise budget
```

This is not the same security model as public FHE bootstrap. Its purpose is continuous high-performance private computation where the key holder is permitted to perform protected refresh. The code models this as `SymmetricBootstrap`, with Three-Lock framing around the plaintext exposure window.

### 4. Edge / IoT / browser mode

NINE65 includes infrastructure intended for constrained or near-user deployment:

- `nine65-wasm` for browser/JS integration.
- boundary checks before operations that could exceed anchor capacity.
- disabled secret-key export in the WASM API.
- `mana` / `unhal` acceleration paths for CRT-lane execution.
- deterministic CPU-only operation paths for environments where GPU assumptions are not available.

### 5. Service mode

`fhe-service` is a REST-style microservice for session-based FHE operations.

Important boundary: the current service session model keeps key material server-side. For strict consumer-side privacy, prefer client-side or edge-held keys, or use the service as a private key-holder component rather than as a public SaaS trust boundary.

---

## Quick Start

### Public-key auto-bootstrap

```rust
use nine65::entropy::ShadowHarvester;
use nine65::ops::auto_bootstrap::AutoBootstrapEvaluator;
use nine65::ops::bootstrap::ClockworkBootstrap;
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::params::secure_configs::SecureConfig;

let config = SecureConfig::secure_128().into_config();
let ctx = RNSFHEContext::try_new(&config).expect("context");
let boot = ClockworkBootstrap::new(&config).expect("bootstrap");
let mut rng = ShadowHarvester::from_os_seed();

let keys = ctx.generate_keys_dual_full(&mut rng);
let boot_keys = boot.generate_keys(&keys.secret_key, &mut rng).expect("boot keys");

let x = ctx.encrypt_dual(2, &keys.public_key, &mut rng);
let mut acc = ctx.encrypt_dual(1, &keys.public_key, &mut rng);

let mut eval = AutoBootstrapEvaluator::new(
    &ctx,
    &boot,
    &boot_keys.bsk,
    &boot_keys.ksk,
    &keys.eval_key,
    &config,
);

for _ in 0..100 {
    acc = eval.mul_auto(&acc, &x).expect("mul + auto-refresh");
}

let out = ctx.decrypt_dual(&acc, &keys.secret_key);
println!("result mod t = {out}; bootstraps = {}", eval.bootstrap_count);
```

### Non-circular bootstrap

```rust
let boot_keys = boot
    .generate_keys_with_ksk(&keys.secret_key, &mut rng)
    .expect("independent boot key + KSK");

let ct = ctx.encrypt_dual(42, &keys.public_key, &mut rng);
let refreshed = boot
    .bootstrap_with_ksk(&ct, &boot_keys.bsk, &boot_keys.ksk)
    .expect("non-circular refresh");

assert_eq!(ctx.decrypt_dual(&refreshed, &keys.secret_key), 42);
```

### Symmetric protected refresh

```rust
use nine65::ops::symmetric_bootstrap::SymmetricBootstrap;

let mut sym = SymmetricBootstrap::new(&config).expect("symmetric bootstrap");
let ct = ctx.encrypt_dual(42, &keys.public_key, &mut rng);
let refreshed = sym
    .bootstrap(&ct, &keys.secret_key, &keys.public_key, &mut rng)
    .expect("symmetric refresh");

assert_eq!(ctx.decrypt_dual(&refreshed, &keys.secret_key), 42);
```

### CRAM-CT wrapper over real DualRNS ciphertexts

```rust
use nine65::cram_ct_wrap::{cram_add_dual, cram_mul_dual, wrap_dual_rns};

let a = wrap_dual_rns(ctx.encrypt_dual(7, &keys.public_key, &mut rng));
let b = wrap_dual_rns(ctx.encrypt_dual(11, &keys.public_key, &mut rng));

let sum = cram_add_dual(&ctx, a, b).expect("CRAM add witness");
assert_eq!(ctx.decrypt_dual(&sum.base, &keys.secret_key), 18 % ctx.t);
```

---

## Architecture

```text
NINE65_v7/
├── crates/
│   ├── nine65/                  # Core BFV/RNS FHE engine
│   │   └── src/
│   │       ├── arithmetic/      # RNS, K-Elimination, NTT, Montgomery, bounds
│   │       ├── ops/
│   │       │   ├── rns_fhe.rs              # DualRNS BFV operations
│   │       │   ├── bootstrap.rs            # Clockwork public bootstrap
│   │       │   ├── auto_bootstrap.rs       # public-mode auto-refresh evaluator
│   │       │   ├── symmetric_bootstrap.rs  # symmetric protected refresh
│   │       │   ├── sbni.rs                 # Shadow Butterfly Noise Injection
│   │       │   └── gso_fhe.rs              # depth/state management
│   │       ├── cram_ct_wrap.rs  # CRAM-CT witness wrapper over DualRNS ciphertexts
│   │       ├── entropy/         # Shadow entropy, CSPRNG, deterministic RNG
│   │       ├── keys/            # public, secret, eval, BSK, KSK material
│   │       ├── noise/           # integer noise-budget tracking
│   │       ├── security/        # estimator and timing/security utilities
│   │       └── params/          # secure configs and parameter validation
│   ├── exact_transcendentals/   # exact integer transcendental / CRAM vocabulary
│   ├── clockwork-core/          # formal-spec RNS, GRO, bound tracking
│   ├── fhe-service/             # HTTP service boundary
│   ├── mana/                    # lane-parallel CRT/RNS acceleration
│   ├── unhal/                   # hardware abstraction over MANA
│   ├── nine65-wasm/             # browser/edge bindings, excluded from default workspace
│   └── nine65-python/           # Python bindings, excluded from default workspace
├── proofs/coq/                  # Coq proof artifacts
├── lean4/                       # Lean4 proof artifacts
├── docs/                        # audit, benchmark, security, and claim docs
└── scripts/                     # quality gates and benchmark generation
```

---

## Security Posture

NINE65 targets post-quantum privacy-preserving computation using LWE/BFV-style lattice cryptography and exact integer RNS arithmetic.

Core security and correctness themes:

- public-key FHE evaluation without evaluator-side plaintext access;
- low-depth Clockwork bootstrap for continued public-mode computation;
- KSK path for non-circular bootstrap operation;
- symmetric protected refresh for key-holder deployments;
- SBNI timing-noise hardening;
- K-Elimination exact rescaling and anchor/boundary checks;
- zero floating-point in cryptographic runtime paths;
- `#![forbid(unsafe_code)]` in the core crate;
- secret-bearing type hardening and zeroization paths;
- claim registry and benchmark policy to avoid stale public claims.

Security configurations are available through:

```rust
SecureConfig::secure_128()
SecureConfig::secure_192()
SecureConfig::secure_256()
```

Benchmark and security claims should be tied back to the checked artifacts in `docs/CLAIM_REGISTRY.csv`, `docs/BENCHMARK_PROFILE_POLICY.md`, and the dated benchmark/security baselines. Re-run baselines on target hardware before making external performance claims.

---

## Build and Test

```bash
# Build core workspace
cargo build --release --workspace \
  --exclude nine65-python \
  --exclude nine65-wasm \
  --exclude nine65-ffi

# Test core workspace
cargo test --release --workspace \
  --exclude nine65-python \
  --exclude nine65-wasm \
  --exclude nine65-ffi

# Core crate only
cargo test -p nine65 --lib --release

# Bootstrap tests
cargo test -p nine65 --lib --release -- bootstrap
cargo test -p nine65 --lib --release -- symmetric_bootstrap

# Service tests
cargo test -p fhe-service --release

# Constant-time / float / claim hygiene scripts
./scripts/check_no_floats_runtime.sh
./scripts/check_claim_registry.sh
./scripts/verify_constant_time.sh
```

### Feature Flags

| Feature | Purpose |
|---|---|
| `exact_transcendentals_backend` | Default exact integer backend and CRAM-CT vocabulary. |
| `clockwork` | GRO timing gates, bound tracking, key lifecycle integrity. |
| `accelerated` | MANA + UNHAL acceleration path. |
| `parallel` / `generic-rayon` | Explicit Rayon opt-in paths. |
| `shadow-entropy` | CRT shadow entropy and monitoring subsystem. |
| `adaptive-threading` | Entropy-driven adaptive threading. |
| `exact_rational` | NexGen rational bridge. |
| `serde` | JSON/bincode serialization support. |
| `deterministic_rng` | reproducible testing. |
| `allow_insecure` | test-only insecure configs; blocked from production release paths where enforced. |

---

## Deployment Surfaces

| Surface | Purpose | Notes |
|---|---|---|
| Rust crate | library integration | primary path for cryptographic operations. |
| `fhe-service` | HTTP service | session model currently keeps keys server-side. |
| WASM binding | browser/edge | boundary checks and secret-key export disabled. |
| MANA/UNHAL | acceleration / hardware abstraction | CRT-lane and edge/accelerator-oriented infrastructure. |
| Python binding | experimentation | excluded from default workspace. |

---

## Current Positioning

NINE65 should be described as:

```text
A low-depth bootstrap FHE substrate for continuous, high-performance,
privacy-preserving computation across public-key, symmetric, service,
edge, and browser deployment modes.
```

Avoid describing the current project as only:

```text
v7 Bootstrap Complete
```

That phrase captures an older milestone, not the current functional shape of the repository.

---

## License

Proprietary. See `LICENSE`.

---

*NINE65 — modular integer privacy infrastructure by Acidlabz210.*
