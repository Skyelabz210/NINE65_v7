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
| `ServiceOperator` | `fhe-service` process | Service | Service | Service, only when explicitly enabled | Trusted operator | Internal telemetry, isolated control plane, operator-only processing | Public SaaS decryption oracle |
| `WasmClient` | Browser/device process | Browser/device | Browser/device or remote evaluator | Browser/device | Remote evaluator may be untrusted | Consumer-side privacy and edge applications | Exporting secret-key bytes or moving decryption to the remote evaluator |
| `Experimental` | Declared per experiment | Declared per experiment | Declared per experiment | Declared per experiment | Unspecified until documented | Tests, benchmarks, research branches | Production or external security claims |

## Mandatory mode firewall

Every application integration must declare:

1. `mode` from the table above;
2. the process or device that holds the secret key;
3. whether bootstrap is circular, KSK-separated, or symmetric refresh;
4. whether any endpoint can return plaintext;
5. authentication and tenant-isolation controls;
6. the exact parameter tuple and evidence artifact;
7. the permitted number-line projection boundaries.

A deployment is rejected when any field is omitted.

## Decryption endpoint policy

`fhe-service` is fail-closed. The `/decrypt` route is disabled in non-test builds unless both conditions hold:

- `FHE_ENABLE_DECRYPT=1` is set by the operator; and
- `FHE_DECRYPT_TOKEN` is configured and supplied as `x-fhe-decrypt-token`.

The service must bind to loopback by default. A reverse proxy, mTLS, workload identity, or equivalent operator authentication remains mandatory for any non-loopback deployment. The token gate is defense in depth; it is not a replacement for transport authentication.

## Residue-space contract

- Ciphertexts remain in DualRNS main and anchor lanes throughout evaluation.
- K-Elimination is the exact rescale/division path where its coprimality and range preconditions hold.
- Fused Piggyback Division is the declared route for shared-factor divisors when integrated.
- Garner reconstruction and mixed-radix conversion are prohibited from production hot paths.
- Number-line projection is permitted only at explicit encryption ingestion, authorized decryption, or boundary I/O.
- NTT computation moduli remain CLASS-F prime lanes.
- Anchor, integrity, and K-Elimination support lanes are CLASS-R and require coprimality rather than primality.

## Application release gate

An application may move from prototype to deployment only after:

- the mode firewall test passes;
- `/decrypt` is verified unavailable under the production environment;
- key destruction and session expiry are tested;
- ciphertext deserialization rejects malformed dimensions and limb counts;
- exact parameter evidence is pinned;
- residue-native architecture counters report zero internal reconstruction, scalar materialization, Garner, and mixed-radix activity;
- the application-specific structured-signal tests pass at small, large, and endurance scales.
