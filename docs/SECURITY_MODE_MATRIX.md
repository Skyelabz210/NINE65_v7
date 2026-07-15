# NINE65 Security Mode Matrix

**Status:** Normative application-integration contract  
**Applies to:** NINE65 core, `fhe-service`, WASM/edge clients, and application crates

NINE65 exposes several computational modes with different trust boundaries. Applications must select one mode explicitly. No application may infer security properties from the presence of ciphertext alone.

## Mode matrix

| Mode | Secret-key holder | Encrypts | Evaluates | Decrypts | Evaluator trust | Permitted deployment | Prohibited deployment |
|---|---|---|---|---|---|---|---|
| `PublicEvaluator` | Client, tenant key service, or isolated owner-controlled boundary | Client/owner | Untrusted evaluator | Client/owner only | Untrusted | Consumer privacy, outsourced computation, private aggregation | Server-side decryption endpoint exposed to users |
| `PublicEvaluatorKsk` | Work-key owner and independent boot-key owner/boundary | Client/owner | Untrusted evaluator | Work-key owner | Untrusted | Non-circular bootstrap deployments | Collapsing work and boot key without declaring circular mode |
| `SymmetricProtected` | Same protected node that refreshes | Protected node | Protected node | Protected node | Trusted key-holder boundary | HSM, TEE, local device, private edge gateway | Marketing as evaluator-blind public FHE |
| `ServiceOperator` | `fhe-service` process | Service | Service | Service, only when explicitly enabled | Trusted operator | Internal telemetry, isolated control plane, authenticated tenant processing | Public SaaS decryption oracle or unauthenticated shared session namespace |
| `WasmClientLeveled` | Browser/device process | Browser/device | Browser/device or compatible remote evaluator | Browser/device | Remote evaluator may be untrusted | Current single-modulus BFV client encryption and bounded leveled arithmetic | Claiming DualRNS, K-Elimination, or auto-bootstrap support from the current WASM crate |
| `Experimental` | Declared per experiment | Declared per experiment | Declared per experiment | Declared per experiment | Unspecified until documented | Tests, benchmarks, research branches | Production or external security claims |

## Mandatory mode firewall

Every application integration must declare:

1. `mode` from the table above;
2. the process or device that holds the secret key;
3. whether bootstrap is circular, KSK-separated, symmetric refresh, or unavailable;
4. whether any endpoint can return plaintext;
5. authentication, tenant-isolation, rate, and audit controls;
6. the exact parameter tuple and evidence artifact;
7. the permitted number-line projection boundaries.

A deployment is rejected when any field is omitted.

## Service base authorization

Every protected `fhe-service` request requires:

- `FHE_API_TOKEN` configured by the operator and supplied as `x-fhe-api-token`;
- a bounded `x-fhe-tenant-id` header;
- passage through the per-tenant integer request window.

Sessions are bound to the authenticated tenant at creation. Wrong-tenant and absent-session lookups return the same result. The store fails closed on poisoned synchronization state rather than recovering and reusing potentially inconsistent cryptographic state.

The default tenant limit is 120 protected requests per exact one-minute window, configurable through `FHE_RATE_LIMIT_PER_MINUTE`. Metrics require an additional `FHE_OPERATOR_TOKEN` / `x-fhe-operator-token` capability. Audit events contain a truncated tenant digest, action class, exact integer timestamp, and status only.

## Decryption endpoint policy

`fhe-service` is fail-closed. The `/decrypt` route is disabled in non-test builds unless both conditions hold:

- `FHE_ENABLE_DECRYPT=1` is set by the operator; and
- `FHE_DECRYPT_TOKEN` is configured and supplied as `x-fhe-decrypt-token`.

The decrypt request must also pass the base API and tenant checks. Configured and supplied tokens are hashed to fixed-length SHA-256 digests before constant-time comparison. The service binds to loopback by default. A reverse proxy, mTLS, workload identity, or equivalent operator authentication remains mandatory for any non-loopback deployment. These gates are defense in depth; they do not create IND-CCA security.

## Residue-space contract

For DualRNS modes:

- Ciphertexts remain in DualRNS main and anchor lanes throughout evaluation.
- K-Elimination is the exact rescale/division path where its coprimality and range preconditions hold.
- Fused Piggyback Division is the declared route for shared-factor divisors when integrated.
- Garner reconstruction and mixed-radix conversion are prohibited from production hot paths.
- Number-line projection is permitted only at explicit encryption ingestion, authorized decryption, or boundary I/O.
- Main NTT computation moduli remain CLASS-F prime lanes.
- The current FHE anchor path is CLASS-A: anchor polynomial convolution is field-backed and therefore uses prime NTT-compatible lanes, while K-Elimination extraction itself is CLASS-R and requires coprimality and range validity.
- Ring-only composite anchors are not yet a live fast path in the FHE multiplier.

For the current WASM crate:

- the surface identifier is `single-modulus-bfv-leveled`;
- browser OS CSPRNG backs production key generation and encryption;
- deterministic seeded methods fail in release builds;
- imported public/evaluation keys and every ciphertext are validated against the active context;
- secret-key byte export is disabled;
- `supports_dual_rns()` and `supports_auto_bootstrap()` return false.

## Application release gate

An application may move from prototype to deployment only after:

- the mode firewall test passes;
- base API authentication, tenant isolation, rate limiting, and audit policy are verified;
- `/decrypt` is verified unavailable under the production environment;
- key destruction and session expiry are tested;
- ciphertext deserialization rejects malformed dimensions and limb counts;
- exact parameter evidence is pinned;
- residue-native architecture counters report zero internal reconstruction, scalar materialization, Garner, and mixed-radix activity;
- the application-specific structured-signal tests pass at small, large, and endurance scales;
- any WASM deployment states whether it uses the leveled single-modulus surface or a future separately evidenced DualRNS adapter.
