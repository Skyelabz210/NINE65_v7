# NINE65 v6 Side-Channel Threat Model

## Scope

This document covers timing side-channel threats to NINE65's BFV FHE implementation. Other side-channels (power analysis, EM emanation, cache timing) are out of scope for this software-only system.

## Assets Under Protection

| Asset | Location | Criticality |
|-------|----------|-------------|
| Secret key polynomial `s` | `SecretKey.s`, `DualRNSSecretKey.s` | CRITICAL — full key recovery |
| Evaluation key `s^2` info | `EvaluationKey.rlk` | HIGH — leaks s^2, partial key recovery |
| Plaintext message `m` | `BFVEncoder.encode()` output | MEDIUM — application-dependent |
| Noise budget state | `NoiseBudget.remaining_mb` | LOW — aids noise overflow attacks |

## Threat Model

### T1: Timing Side-Channel on Decryption

**Attack**: Observe `BFVDecryptor::decrypt()` timing to learn secret key bits.

**Mechanism**: The inner product `c0 + c1 * s` touches every coefficient of `s`. If `mul` uses early-exit optimizations (skip zero coefficients), timing reveals Hamming weight of `s`.

**Mitigation**:
- `RingPolynomial::mul_ct()` — constant-time polynomial multiplication using NTT (no coefficient-dependent branching)
- `GatedDecryptor` — executes decrypt inside GRO coincidence window (INV-7) for value-independent execution timing
- `SecretKeyPath` trait — compile-time enforcement that secret data uses CT paths

**Status**: IMPLEMENTED (v6)

### T2: Timing Side-Channel on Key Generation

**Attack**: Observe `KeySet::generate_secure()` timing to learn ternary distribution of `s`.

**Mechanism**: Ternary sampling with rejection (`secure_ternary()`) has variable iteration count.

**Mitigation**:
- `GatedKeyGen` — executes keygen inside GRO coincidence window
- Ternary sampling uses rejection from `{0,1,2,3}` → `{-1,0,1}` with 25% rejection rate (bounded, constant-time within window)

**Status**: IMPLEMENTED (v6)

### T3: Noise Budget Oracle (IBM 2025 BFV Key Recovery)

**Attack**: Provoke decryption failures when noise budget is exhausted, use failure/success oracle to recover key.

**Mechanism**: If noise overflow wraps silently (unsigned underflow), ciphertexts decrypt to random values without error, giving attacker a distinguishing oracle.

**Mitigation**:
- `NoiseBudget::consume()` uses `checked_sub()` — returns `Nine65Error::NoiseBudgetExhausted` instead of wrapping
- `TrackedEvaluator` wraps all homomorphic operations with automatic budget checking
- All noise budget operations use millibits (integer-only, no float rounding)

**Status**: IMPLEMENTED (v6, Segment B)

### T4: Entropy Source Failure

**Attack**: Exploit predictable random values if OS CSPRNG fails silently.

**Mechanism**: If `/dev/urandom` returns predictable data (stuck entropy pool, VM clone, container without entropy), all keys and encryption randomness are compromised.

**Mitigation**:
- `entropy_health_check()` — startup and periodic validation of CSPRNG output
- `try_*` methods throughout entropy module — propagate errors instead of panicking
- Two-sample divergence check (32 bytes) catches stuck pools

**Status**: IMPLEMENTED (v6)

### T5: Cache Timing in NTT

**Attack**: Observe NTT memory access patterns to learn polynomial coefficients.

**Mechanism**: NTT butterfly operations access twiddle factors at data-dependent indices. CPU cache line misses leak access patterns.

**Mitigation**:
- NTT twiddle factor tables are precomputed and fully loaded into cache before operations
- Future: full CT-NTT with data-independent memory access patterns

**Status**: PARTIAL (twiddle precomputation implemented; full CT-NTT is future work)

## GRO Timing Gate Architecture

The Golden Ratio Oscillator (GRO) provides timing isolation:

```
Oscillator A: phase += delta_phi_a (each step)
Oscillator B: phase += delta_phi_b (approx phi * delta_phi_a)

Coincidence window: |phase_A - phase_B| < W

Crypto operation executes only during coincidence windows.
External observer sees: operation_time = window_start + constant
```

**Properties** (from Clockwork formal spec):
- T9: Coincidence period = 2^N_acc when delta_phi difference is odd
- T10: Windows are uniformly distributed over the period
- T8: Timing is value-independent within windows

## Residual Risks

1. **Hardware-level cache timing** — not addressed by software CT enforcement
2. **Speculative execution** (Spectre-class) — NTT may be vulnerable on affected CPUs
3. **Compiler optimization** — `volatile` writes in zeroization may be optimized in future compilers
4. **Side-channel in `getrandom`** — OS CSPRNG implementation is trusted

## Verification Checklist

- [x] `mul_ct` used for all secret-key multiplications
- [x] GRO timing gate wraps keygen and decrypt
- [x] Noise budget uses `checked_sub()` (no silent overflow)
- [x] `SecretKeyPath` trait enforces CT at compile time
- [x] Entropy health check available
- [x] `ZeroizeOnDrop` on `SecretKey`
- [x] Circular security validated by test
- [ ] Full CT-NTT implementation (future)
- [ ] Cache line alignment for twiddle tables (future)
