# NINE65 Side-Channel Threat Model

**Revision:** 2026-07-13  
**Scope:** current DualRNS, NTT, Persistent-Montgomery, bootstrap, service, and WASM surfaces.

This document distinguishes source-level hardening from compiler-, microarchitecture-, process-, and physical-side-channel closure. A source implementation may be branchless while still requiring target-specific evidence.

## Protected assets

| Asset | Principal locations | Risk |
|---|---|---|
| Secret key polynomial | `DualRNSSecretKey`, key-holder process/device | Complete plaintext/key compromise |
| Bootstrap and evaluation material | bootstrap/evaluation key types | Scheme- and mode-dependent leakage or misuse |
| Plaintext structured signal | client, authorized decrypt boundary | Application privacy compromise |
| Ciphertext state and noise metadata | evaluator/service | Correctness oracle, traffic correlation, denial of service |
| Operator token/session key | `fhe-service` environment/process | Unauthorized decryption capability |

## Trust boundaries

Security mode is explicit. See `SECURITY_MODE_MATRIX.md`.

- Public evaluators are not granted decrypt or number-line projection capabilities.
- Symmetric protected mode trusts its key-holder boundary.
- `fhe-service` is a server-key-holder mode and is not consumer-side key ownership.
- WASM/device mode keeps the key near the consumer but does not make browser memory physically unreadable.

## T1 — Secret-dependent arithmetic timing

**Attack:** infer secret coefficients or plaintext-dependent intermediates from branches, instruction counts, or data-dependent memory accesses.

**Current controls:**

- Montgomery reduction/add/sub use branchless canonicalization.
- NTT butterfly add/sub/neg route through branchless Montgomery primitives.
- Persistent-Montgomery REDC/add/sub/neg are branchless.
- Persistent exponentiation uses a fixed 64-iteration Montgomery ladder.
- NTT loop bounds, bit-reversal indices, and twiddle indices depend only on public parameters.
- `scripts/check_ct_ntt_source.py` rejects regression to the prior branchy source patterns.

**Status:** source-hardened; compiler/disassembly and hardware evidence pending.

## T2 — Cache and address-trace leakage

**Attack:** recover information through secret-dependent array addresses or cache behavior.

**Current controls:**

- NTT coefficient and twiddle addresses follow a public schedule determined by `N`, stage, block, and offset.
- Sparse coefficient shortcuts are not used in the reviewed FFT butterfly path.
- Key arithmetic loops use public dimensions.

**Residuals:**

- `Vec<u64>` does not itself certify cache-line alignment.
- compiler transformations and target prefetch behavior are not yet evidenced;
- shared-cache, SMT, and co-tenant attacks remain deployment concerns.

**Status:** public schedule established at source level; cache-line and trace evidence pending.

## T3 — Decryption and correctness oracles

**Attack:** submit crafted ciphertexts and distinguish decryption success, failure, plaintext, or noise-exhaustion behavior.

**Current controls:**

- public evaluator mode has no decrypt capability;
- `fhe-service` decrypt routing is concealed by default;
- production decryption requires explicit enablement, configured operator token, and matching request header;
- tokens are hashed to fixed-length SHA-256 digests before constant-time comparison;
- malformed ciphertexts are size- and shape-validated before arithmetic;
- noise accounting fails closed instead of unsigned wraparound.

**Residuals:**

- service token gating is defense in depth, not IND-CCA security;
- mTLS/workload identity, tenant authorization, rate limits, and network isolation remain mandatory;
- response classes and latency require deployment-level oracle testing.

**Status:** default-deny service boundary implemented; CCA-hard construction not claimed.

## T4 — Entropy-source misuse

**Attack:** predict keys or encryption randomness through deterministic or failed entropy sources.

**Current controls:**

- `SecureRng` wraps the OS CSPRNG for key generation and production cryptographic sampling;
- service production key generation uses `generate_keys_dual_full_secure()`;
- `ShadowHarvester` is documented and typed as deterministic/test-oriented;
- OS entropy errors propagate or terminate before security-critical output.

**Residuals:** VM/container cloning, platform CSPRNG failure, and lifecycle/reseed policy remain deployment concerns.

**Status:** source roles separated; environment health evidence required per deployment.

## T5 — retired (SBNI misuse or malformed lane state)

SBNI (Shadow Butterfly Noise Injection) was retired 2026-08-09: `pub mod sbni;`
was removed from `ops/mod.rs`, its one production call site
(`mul_dual_public` Step 3.5) is gone, and nothing in the crate compiles
against it. The threat this entry described — corrupt ciphertext
correctness, index outside live limbs, or infer operation state through
malformed entropy/lane input — has no live attack surface because the
mechanism it targeted no longer exists. See `docs/LADDER_REMOVAL.md` §1 for
the retirement record and `docs/RETIRED_MECHANISMS.md` for the companion
retirement of modulus switching. This entry is kept, marked retired, rather
than silently deleted, per the same non-silent-delete rule
`RETIRED_MECHANISMS.md` applies to quarantined tests.

**Status:** retired; not applicable to the current threat surface.

## T6 — Key lifetime and memory exposure

**Attack:** recover key material from logs, serialization, process memory, crash dumps, swaps, or stale sessions.

**Current controls:**

- secret-bearing core types use zeroization paths;
- key debug output is redacted where implemented;
- WASM secret-key byte export is disabled;
- service sessions have TTL cleanup and deletion;
- core crate forbids unsafe code.

**Residuals:**

- allocator copies and compiler behavior can outlive logical zeroization;
- browser linear memory has platform limitations;
- process dumps, hibernation, swap, and administrator access are deployment concerns.

**Status:** software lifecycle controls present; platform assurance pending.

## T7 — Speculative execution and physical channels

**Attack:** Spectre-class transient execution, power analysis, EM emanation, frequency scaling, or thermal effects.

**Current controls:** none claimed at the universal software level.

Required deployment controls include CPU/microcode policy, process isolation, co-tenancy restrictions, HSM/TEE use where appropriate, disabled untrusted plugins, and target-specific testing.

**Status:** open deployment gate.

## Verification gates

A broad `constant-time` claim requires all of the following for the exact commit, compiler, flags, and target:

1. source reachability inventory;
2. branch/control-flow audit;
3. address-trace audit;
4. compiler IR and disassembly review;
5. fixed-vs-random integer-cycle diagnostics;
6. cache-line/twiddle placement evidence;
7. speculative-execution and process-isolation statement;
8. rerun after compiler, target, or arithmetic changes.

Current approved wording:

> NINE65 contains constant-time-oriented source paths with public NTT address scheduling and branchless coefficient arithmetic. Compiler, cache, and hardware closure remain target-specific verification work.

See `CT_NTT_AUDIT_2026-07-13.md` and `CT_NTT_CACHE_ROADMAP.md`.
