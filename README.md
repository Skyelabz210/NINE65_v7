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

Correctness columns are checked against a decryption oracle. Everything outside
this table is outside the claim surface.

| Config | N | main lanes | log2(q) | public mul | symmetric mul | public direct-square depth † | public refresh |
|---|---|---|---|---|---|---|---|
| `secure_128` | 8192 | 3 | 90 | 292.40 ms | 82.07 ms | 2 | **refused in code** |
| `secure_128_deep` | 8192 | 4 | 119 | 408.66 ms | 93.14 ms | 2 | pass |
| `secure_192` | 16384 | 5 | 146 | 1114.12 ms | 247.21 ms | 3 | pass |
| `secure_256` | 16384 | 6 | 175 | 1017.91 ms | 262.96 ms | 4 ‡ | pass ‡ |

† Direct squaring **without** refresh — the last depth that still decrypts
correctly. These depths are seed-sensitive at the boundary, so where a config
has been surveyed the column states the depth that holds on *every* seed, not
the modal one. Only `secure_128_deep` has been surveyed so far (12 seeds,
2026-08-24): 11 reach depth 3 and one fails it by exactly one, so the column
states 2. The other three rows are single-seed measurements and their depths
should be read as provisional in the same way. See §4 of the claim-surface doc.
‡ `secure_256`'s depth is from the correctness-gated benchmark run;
its refresh is covered by the auto-refresh acceptance suite rather than
exercised standalone. Per-number provenance is in
`docs/CLAIM_SURFACE_AND_LIMITS_2026-08-22.md`.

**Timings re-measured 2026-08-23** by `tests/op_timings.rs` — see
[Measured performance](#measured-performance) for the machine, the method, and
why the figures that used to sit in this column were replaced.

`secure_128`'s three-lane chain leaves too little `Delta` headroom for a public
refresh: 42 bits remain after the refresh's worst-case noise deposit against the
47 bits one subsequent multiply needs. Measured by
`ops::bootstrap::tests::diag_measure_noise_growth` — which runs the refresh
phases with the gate bypassed, so the gate is not its own evidence — the refresh
output itself still decrypts to `7`, but squaring it returns a
wrong-but-plausible `34037` instead of `49`, with no error raised anywhere in
the pipeline.
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
- **No external lattice-estimator attestation** exists for the shipped
  `n = 8192 / 16384` tuples. The numbers above are in-tree screening results.
- **No public constant-time claim.** Blocked on the CT-NTT/cache gates in
  `docs/CT_NTT_CACHE_ROADMAP.md`.

## Measured performance

Every figure below was produced by `crates/nine65/tests/op_timings.rs` on
**2026-08-23**, on the machine described under Method. Nothing here is
inherited.

| Config | N | main lanes | Encrypt | Add | Public mul | Symmetric mul | Decrypt |
|---|---|---|---|---|---|---|---|
| `secure_128` | 8192 | 3 | 5.38 ms | 1.405 ms | 292.40 ms | 82.07 ms | 1.83 ms |
| `secure_128_deep` | 8192 | 4 | 6.60 ms | 1.528 ms | 408.66 ms | 93.14 ms | 2.51 ms |
| `secure_192` | 16384 | 5 | 23.09 ms | 5.488 ms | 1114.12 ms | 247.21 ms | 7.51 ms |
| `secure_256` | 16384 | 6 | 22.41 ms | 5.943 ms | 1017.91 ms | 262.96 ms | 7.78 ms |

Reproduce:

```bash
cargo test -p nine65 --test op_timings --release --features allow_insecure \
  -- --ignored --nocapture
```

**Method.** Medians over 5 rounds (3 at N=16384), default features — which
means MANA and UNHAL are active, see below. Every round decrypts both the sum
and the product and asserts exactness, so a timing figure cannot come from a
run that computed the wrong answer. Machine: 4 vCPU shared container, Intel
Xeon 2.80 GHz, load average 1–22 during the runs. Run-to-run spread on
`secure_128` public mul across four separate invocations was 281–302 ms, so
treat the third significant figure as noise.

### Why these replaced the previous figures

The previous table quoted 158.994 ms for `secure_128` public mul; `CLAUDE.md`
quoted 152.13 ms alongside 23.56 ms encrypt, 0.83 ms add and 11.06 ms decrypt.

Rather than guess at the discrepancy, the commit that recorded those numbers —
`364bd6a`, 2026-02-24 — was checked out in a worktree and measured on **this**
machine with an equivalent harness:

| | recorded at `364bd6a` | measured at `364bd6a`, here | verdict |
|---|---|---|---|
| Encrypt | 23.56 ms | 21.96 ms | reproduces |
| Add | 0.83 ms | 0.672 ms | reproduces |
| **Public mul** | **152.13 ms** | **316.54 ms** | **does not reproduce, 2.1× off** |
| Decrypt | 11.06 ms | 10.14 ms | reproduces |

Three of the four reproduce within 20%, stable over three runs. So this machine
is comparable to whatever produced them, and the discrepancy is **not**
hardware. One number was simply wrong, and was already wrong when it was
written: `secure_128` public mul has never measured ~152 ms on this code.

The `158.994 ms` figure was worse — it was introduced during the 2026-08-22
session at `877e227`, into a table with no stated source, and never measured at
all.

### The February figures are not comparable to these, and neither is any
### cross-time comparison keyed on a config name

`secure_128` was **redefined** between February and August:

| | `364bd6a` (2026-02-24) | current |
|---|---|---|
| ring degree | **N = 4096** | **N = 8192** |
| lanes | 3 main | 3 main + 5 anchor = 8 |

The constructor's own comment records why — "Increased from 4096 to maintain
security with larger Q". `add`, `encrypt` and `decrypt` are all O(N × lanes), so
the current `secure_128` does roughly **3.2× the work** of February's under the
same name.

That makes every February-to-now delta meaningless as stated, and an earlier
revision of this section published one anyway — including a claimed "~2× `add`
regression" (0.672 ms → 1.405 ms). **There is no such regression.** Measured
with a tight-loop probe, `add` is 0.207 ms at `364bd6a` and 1.04 ms now, a 5.0×
ratio against a ~3.2× work ratio; the remainder is memory and allocation
scaling, not a defect. The claim has been withdrawn rather than rescaled,
because dividing measurements by an estimated work ratio produces an estimate,
not a measurement.

Two things were checked and eliminated before the shape change was found: the
release profile (`lto = "fat"`, `codegen-units = 1` versus cargo's defaults
measures 1.03 ms against 0.85–1.01 ms at `HEAD` — overlapping, nowhere near
5×), and a `git bisect` across all 274 commits in the range, which converged on
a commit whose tree is a divergent re-import rather than a behavioural change.

What survives, because it was measured at a single commit with a single config:
the `152.13 ms` public-mul figure recorded at `364bd6a` does not reproduce **at
`364bd6a` itself**, where the same N=4096 `secure_128` measures 316.54 ms over
three runs. That figure was wrong when written.

And the session-scope conclusion is unaffected, because it compares two commits
that share a config definition: `b03aa4a` built in a separate worktree measured
301.55 ms for `secure_128` public mul against 281–302 ms at `HEAD`, with every
config matching within noise.

### MANA and UNHAL are the default, and are verified to engage

`nine65`'s default feature set is
`["exact_transcendentals_backend", "accelerated"]`, and `accelerated = ["mana",
"unhal"]`. Rayon is not in any default graph: `unhal` is consumed with
`default-features = false` specifically so its own `parallel` default cannot
pull rayon in behind the acceleration flag.

Declared-by-default is not the same as active, so the dispatch path was traced
end to end: `RNSFHEContext::run_limb_lanes` → `unhal::accelerator::Accelerator::auto()`
→ `mana::executor::run_lanes`. On this machine `available_parallelism` reports
4, `lane_parallel_threshold` is 2, and `secure_128` dispatches 8 lanes (3 main
+ 5 anchor), so the parallel path is taken rather than the sequential fallback.
`accelerated_dual_poly_mul_is_bit_identical_to_sequential_reference` pins that
the accelerated result equals the sequential one bit for bit, so the
accelerator is a wall-clock choice and never a numerical one.

To measure without it: `--no-default-features --features exact_transcendentals_backend`.

### Constant-time status: 9 of 9 blocking gates pass, 2 findings remain open

Re-measured 2026-08-23 with the interleaved two-class dudect harness, run
serially — concurrent timing tests contend for the CPU and invalidate each
other.

| gate | t_signal | t_control | verdict |
|---|---|---|---|
| `montgomery_pow_exponent_hamming_weight` | 1.54 | 0.75 | constant-time |
| `montgomery_reduce_operand_magnitude` | 1.62 | 1.81 | constant-time |
| `montgomery_mul_operand_magnitude` | 1.81 | 0.48 | constant-time |
| `barrett_reduce_operand_magnitude` | 3.37 | 3.09 | constant-time |
| `mod_switch_rescale_sign_classes` | 0.34 | 0.22 | constant-time |
| `exact_prime_drop_fixed_vs_random` | 0.77 | 1.26 | constant-time |
| `exact_prime_drop_small_vs_large_residues` | 0.23 | 1.56 | constant-time |
| `adjacency_k_elim_operand_magnitude` | 1.38 | 0.47 | constant-time |
| `adjacency_k_elim_operand_order` | 1.17 | 0.52 | constant-time |

All nine sit below the `t < 5` threshold with clean control arms. **This is not
a claim that the system is constant-time**, and the two tests that say so are
run on the same schedule rather than hidden:

| open finding | measured | gap |
|---|---|---|
| `mod_switch_down_dual` (F-2) | 18.05 ms vs 53.50 ms, t = 616.3 | **2.96×** |
| `KElimination::extract_k` (F-3) | 2,083,963 ns vs 2,071,605 ns, t = 34.1 | 0.60% |

F-2's cause is `U256::div_mod_u64`, a long division over the reconstructed
coefficient. F-3 has a measured structural answer that is built but not adopted
— see `AdjacencyKElim` and `docs/CT_VERIFICATION_PLAN.md` §4.6. Beyond these,
source-level constant-time paths do not close hardware channels; see
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
profile the first triggered refresh returns an error instead of continuing.

The depths in the capability table are **direct-square depths without refresh**.
How far an auto-refreshed chain extends past them is a separate question, tracked
by the acceptance suite in `ops::auto_bootstrap`, and no unbounded-depth claim
follows from it — see `docs/CLAIM_SURFACE_AND_LIMITS_2026-08-22.md`.

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

`cargo bench` output (`target/criterion/`, used for internal micro-benchmarks such as `barrett_ct`/`ntt_ct`/`k_elimination_ct`, separate from the `op_timings.rs` harness behind the table above) is overwritten by each new run. `scripts/archive_criterion_run.sh` snapshots it to a timestamped, commit-pinned `bench-archive/` directory (gitignored) so a run's raw evidence survives past the next benchmark invocation; see `docs/BENCHMARK_PROFILE_POLICY.md` "Raw Criterion Archival".

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
