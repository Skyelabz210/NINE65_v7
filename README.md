# NINE65
## Exact-Integer DualRNS Privacy Substrate with Low-Depth Refresh

NINE65 is a Rust BFV/DualRNS computation substrate for exact modular privacy-preserving workloads across public-evaluator, KSK-separated, symmetric protected, service-operator, browser, edge, and accelerator deployments.

The repository has moved beyond the historical “v7 Bootstrap Complete” snapshot. The current integration line combines:

- public DualRNS evaluation and relinearization;
- circular and KSK-separated Clockwork bootstrap paths;
- automatic pre-operation refresh;
- symmetric protected decrypt→re-encrypt refresh;
- K-Elimination rescaling with explicit anchor/range state;
- exact large-modulus and noise-budget accounting;
- CRAM residue-native architecture gates;
- service, WASM, MANA, and UNHAL deployment surfaces;
- an evaluator-only private-feedback reference application.

> **Evidence state:** named parameter profiles are candidate tuples until independently attested with the exact estimator input and raw output artifact. Per-number provenance, open discrepancies, and the internal engineering assessment are in `docs/CLAIM_SURFACE_AND_LIMITS_2026-08-22.md`.

## Verified Capability

Measured against a decryption oracle. Everything outside this table is outside
the claim surface.

| Config | N | main lanes | log2(q) | public mul | symmetric mul | public direct-square depth | public refresh |
|---|---|---|---|---|---|---|---|
| `secure_128` | 8192 | 3 | 90 | 158.994 ms (4x5) | 44.371 ms | 2 | **refused in code** |
| `secure_128_deep` | 8192 | 4 | 119 | 207.956 ms | 47.262 ms | 2 | pass |
| `secure_192` | 16384 | 5 | 146 | 564.238 ms | 122.927 ms | 3 | pass |
| `secure_256` | 16384 | 6 | 175 | 520.801 ms | 129.971 ms | 4 | admitted, unexercised |

`secure_128`'s three-lane chain leaves too little `Delta` headroom for a public
refresh: the refresh returns a wrong-but-plausible plaintext (`encrypt(7)` comes
back as `8`) with no error raised anywhere in the pipeline.
`ClockworkBootstrap::bootstrap` and `bootstrap_with_ksk` therefore refuse that
config with a typed `Nine65Error`. The predicate is arithmetic on the chain, not
a name match — see `params::secure_configs::ensure_public_refresh_supported`.
Use `secure_128_deep`, which carries the same 128-bit claim on four lanes, when
the workload needs evaluator-side refresh.

Screened security levels for the shipped tuples, measured by
`params::secure_configs::tests::screened_levels_for_named_configs`:

| config | claimed | Core-SVP | MATZOV | binding |
|---|---|---|---|---|
| `secure_128` | 128 | 259 | 233 | 233 |
| `secure_128_deep` | 128 | 196 | 176 | 176 |
| `secure_192` | 192 | 320 | 288 | 288 |
| `secure_256` | 256 | 267 | **240** | **240** |

Every name clears its own number under Core-SVP, the model the constructor gates
on. `secure_256` falls 16 bits short under MATZOV; read the binding number with
`SecureConfig::screened_security_dual()` rather than inferring it from the
constructor name. These are screening numbers from an integer heuristic, not
lattice-security certificates — see "Parameter and Claim Discipline" below.

### Current limits

- **No unbounded-depth capability.** Measured public direct-square depths are
  2–4. "Unlimited depth", "depth 50", and "bootstrap-free" are on
  `docs/LINEAGE.md`'s deprecation list and are not claimed here.
- **Nonlinear public FHE beyond the direct boundary is not established.** What is
  measured is direct multiply/square chains, not general circuits.
- **`secure_256` public bootstrap is not exercised end to end.** Its chain is
  admitted by the refresh predicate; that is a statement about the chain, not a
  verified roundtrip.
- **No external lattice-estimator attestation** exists for the shipped
  `n = 8192 / 16384` tuples.
- **No public constant-time claim.** Blocked on the CT-NTT/cache gates in
  `docs/CT_NTT_CACHE_ROADMAP.md`.

## Execution Contract

NINE65 applications follow the Recumbent CRAM rule:

```text
ingest once -> remain in residue/ciphertext state -> project only at authorized I/O
```

Production hot paths prohibit:

- internal number-line reconstruction;
- Garner reconstruction;
- mixed-radix conversion;
- hidden scalar materialization;
- floating-point arithmetic.

K-Elimination is used only under its coprimality, exact-divisibility, anchor-capacity, and uniqueness-range preconditions. Shared-factor exact division is rejected until the Fused Piggyback Division production adapter is enabled.

Normative contracts:

- `docs/SECURITY_MODE_MATRIX.md`
- `docs/CRAM_INTEGRATION_CONTRACT.md`
- `docs/ENTROPY_MODEL.md`
- `docs/LINEAGE.md`

## Current Components

| Component | Current role |
|---|---|
| `nine65` | BFV/DualRNS key generation, encryption, decryption, evaluation, K-Elimination, key switching, bootstrap, batching, Galois operations, exact bounds, and noise accounting |
| `cram-core` | canonical residue-native CRAM state, validated basis, topology, anchor state, exact bounds, and prohibited-path counters |
| `clockwork-core` | RNS/GRO/bound-tracking and key-lifecycle support |
| `fhe-service` | internal server-key-holder HTTP boundary; decrypt route disabled by default |
| `nine65-wasm` | browser/device boundary with capacity checks and disabled secret-key export |
| `mana` / `unhal` | lane-parallel acceleration and hardware abstraction |
| `private-feedback-core` | bounded feedback signals, strict-turn next-question selection, safe-basis residues, and lane-wise aggregation |
| `private-feedback-nine65` | public-evaluator encryption and homomorphic slot aggregation with no public decrypt capability |
| Lean 4 | formalization of record for K-Elimination and application-boundary properties |

## Security Modes

### Public evaluator

```text
client/owner: key generation, encryption, authorized decryption
evaluator:    add, multiply, key switch, bootstrap, aggregate
```

The evaluator receives public/evaluation/bootstrap material but no secret key or plaintext projection capability.

### KSK-separated public evaluator

The work key and bootstrap key are distinct. The bootstrap phase returns the ciphertext to the work key through the declared KSK path.

### Symmetric protected

A trusted key-holder boundary performs immediate decrypt→re-encrypt refresh. This mode is appropriate for a local device, HSM, TEE, private edge gateway, or isolated operator. It is not evaluator-blind public FHE.

### Service operator

`fhe-service` owns session keys. It is an internal operator mode, not consumer-side key ownership.

The production decrypt route is concealed unless all of the following are present:

```bash
FHE_ENABLE_DECRYPT=1
FHE_DECRYPT_TOKEN='<operator secret>'
```

and the request supplies:

```text
x-fhe-decrypt-token: <operator secret>
```

The token is hashed to a fixed-size digest before constant-time comparison. mTLS, workload identity, tenant authorization, and network isolation remain required for non-loopback deployment.

### WASM / edge client

The browser or device can own key generation and decryption. Secret-key byte export remains disabled. Browser memory and hardware side channels remain part of the deployment threat model.

## Production-Oriented Example

`secure_128_deep` is the shortest chain that carries a public refresh; the
three-lane `secure_128` is refused on that path (see "Verified Capability").
Check admissibility explicitly rather than assuming a profile supports refresh.

```rust
use nine65::entropy::SecureRng;
use nine65::ops::bootstrap::ClockworkBootstrap;
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::params::secure_configs::{supports_public_refresh, SecureConfig};

// API profile identifier. External named-security use still requires an
// independent exact-tuple estimator artifact.
let config = SecureConfig::secure_128_deep().into_config();
assert!(
    supports_public_refresh(&config),
    "this profile cannot carry an evaluator-side refresh"
);

let context = RNSFHEContext::try_new(&config).expect("valid context");
let bootstrap = ClockworkBootstrap::new(&config).expect("bootstrap context");
let mut secure_rng = SecureRng::new();

let keys = context.generate_keys_dual_full_secure();
let bootstrap_keys = bootstrap
    .generate_keys(&keys.secret_key, &mut secure_rng)
    .expect("bootstrap keys");

// Public evaluation: the evaluator holds only the public and evaluation keys.
let a = context.encrypt_dual_secure(7, &keys.public_key);
let squared = context
    .mul_dual_public(&a, &a, &keys.eval_key)
    .expect("public multiply");

// Evaluator-side refresh. A profile whose chain cannot carry it returns
// Nine65Error::BootstrapConfigMismatch here rather than a wrong plaintext.
let refreshed = bootstrap
    .bootstrap(&squared, &bootstrap_keys.bsk, &bootstrap_keys.ksk)
    .expect("public refresh admitted for this profile");

let result = context.decrypt_dual(&refreshed, &keys.secret_key);
println!("result mod t = {result}");
```

`AutoBootstrapEvaluator::mul_auto` drives the same refresh automatically from the
tracked noise budget. It inherits the admissibility gate above: on a refused
profile the first triggered refresh returns an error instead of continuing. Long
auto-refreshed chains are not part of the verified capability set — the measured
public direct-square depths are 2–4.

A software counter reset is not a bootstrap. The auto evaluator must perform a live ciphertext transition and restore usable post-refresh budget.

## Private-Feedback Reference Path

The initial application path operationalizes short adaptive feedback without treating raw text as the encrypted aggregate:

```text
user answer
  -> local/declared classifier
  -> bounded structured signal
  -> highest-value follow-up class
  -> fixed exact-integer slots
  -> DualRNS encryption
  -> evaluator-only private aggregation
  -> owner-authorized output boundary
```

`private-feedback-core` holds no raw response text. `private-feedback-nine65::EncryptedFeedback` accepts only a public key and exposes no decrypt method or secret-key field.

## Entropy Roles

| Mechanism | Approved use |
|---|---|
| `SecureRng` / OS CSPRNG | key generation, production encryption randomness, bootstrap-key generation, security-critical sampling |
| `ShadowHarvester` | deterministic tests, reproducible diagnostics, explicitly reviewed non-secret streams |

Statistical-test success does not establish cryptographic unpredictability.

SBNI (Shadow Butterfly Noise Injection) was retired 2026-08-09: its only
production call site is gone, and its entropy source was a deterministic,
publicly recomputable function of the operation index — it never delivered
the rerandomization or timing-resistance claims made for it. See
`docs/LADDER_REMOVAL.md` §1 for the record and `docs/RETIRED_MECHANISMS.md`
for the companion retirement of modulus switching and the noise-exhaustion
ladder it was paired with.

## Parameter and Claim Discipline

The in-tree estimator is an integer engineering screen, not an independent certificate. The API names `secure_128`, `secure_128_deep`, `secure_192`, and `secure_256` do not by themselves prove those security levels. Read the screened numbers with `SecureConfig::screened_security_bits()` / `screened_security_dual()` rather than inferring them from a constructor name.

External named-security claims require:

- exact ring dimension;
- ordered main modulus chain;
- anchor configuration;
- plaintext modulus;
- secret and error distributions;
- key-switch decomposition;
- attack model and estimator version;
- raw estimator output;
- exact source commit.

Disagreement is resolved in favor of the lower reproducible result.

Every public claim is indexed through `docs/CLAIM_REGISTRY.csv` and governed by `docs/BENCHMARK_PROFILE_POLICY.md`. Detailed status is recorded in `docs/CLAIM_EVIDENCE_LEDGER.md`.

## Build and Verification

```bash
# Format
cargo fmt --all -- --check

# Core workspace tests
cargo test --release --workspace \
  --exclude nine65-python \
  --exclude nine65-wasm \
  --exclude nine65-ffi

# Application stack
cargo test -p private-feedback-core --release
cargo test -p private-feedback-nine65 --release

# Internal service
cargo test -p fhe-service --release

# WASM boundary
rustup target add wasm32-unknown-unknown
cargo check \
  --manifest-path crates/nine65-wasm/Cargo.toml \
  --target wasm32-unknown-unknown \
  --features wasm

# Exact-integer independent application oracle
python3 scripts/private_feedback_correctness_harness.py

# CRAM architecture and claim gates
python3 scripts/check_residue_native_architecture.py
bash scripts/check_no_floats_runtime.sh
bash scripts/check_claim_registry.sh
bash scripts/check_stale_claims.sh

# Lean formalization of record
cd lean4/KElimination
lake build
bash scripts/axiom_audit.sh
```

## Formal and Side-Channel Status

Lean 4 is the current machine-checked formalization of record. Application-boundary theorems cover evaluator capability separation, default service denial, structured-signal bounds, residue homomorphisms, shared-factor division rejection, ciphertext-shape validity, and the rule that a budget reset alone is not bootstrap.

Constant-time-oriented source paths do not close all hardware leakage channels. Full public constant-time claims remain blocked on the CT-NTT/cache gates in `docs/CT_NTT_CACHE_ROADMAP.md`, including address-trace evidence, compiler/disassembly review, timing experiments, and target-specific deployment assumptions.

## Repository Status

The application-hardening integration is tracked in `docs/APP_PLATFORM_READINESS.md`. Merge and release conditions, open discrepancies, and the internal engineering assessment are in `docs/CLAIM_SURFACE_AND_LIMITS_2026-08-22.md`.

## License

Proprietary. See `LICENSE`.

*NINE65 — modular integer privacy infrastructure by Acidlabz210.*
