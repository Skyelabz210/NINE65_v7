# Clockwork-Core Formal Specification v1.0

**System**: Clockwork-Core RNS Arithmetic for RLWE FHE
**Version**: 1.0 (integrated into NINE65 v5)
**Date**: 2026-02-05
**Classification**: Integer-Only Exact Arithmetic with Formal Safety Guarantees

---

## Abstract

Clockwork-Core is a formally-specified Residue Number System (RNS) arithmetic library that provides exact integer computation for Ring-LWE fully homomorphic encryption ciphertext coefficients. It delivers five capabilities absent from existing FHE implementations: (1) deterministic bit-width bound tracking that propagates through arithmetic chains, (2) Golden Ratio Oscillator timing isolation for side-channel protection, (3) key share lifecycle management with automatic resharing, (4) Garner mixed-radix decomposition for CRT reconstruction, and (5) triple-redundant integrity checking for memory corruption detection. The entire system contains zero floating-point operations. All arithmetic is exact, all bounds are schedule-based and value-independent, and all security-critical paths are constant-time. The specification comprises 5 axioms, 16 definitions, 8 invariants, and 14 theorems, each mapped to concrete test obligations with exhaustive or statistical verification.

---

## Q1: Mathematical Core

### 1.1 Residue Number System Foundations

**Definition D1 (RNS Basis).** An RNS basis is a tuple **p** = (p_0, ..., p_k) of pairwise coprime moduli with p_i >= 2 for all i. The capacity is M_k = prod(p_i). The pairwise coprimality precondition is enforced at construction time and cannot be relaxed post-construction.

*Implementation*: `clockwork_core::basis::RnsBasis`. Construction validates:
- Non-empty moduli list
- All moduli >= 2 (rejects degenerate 0, 1)
- Pairwise coprimality via extended GCD
- Product fits in u128 (capacity overflow detection)

CRT reconstruction coefficients are precomputed at construction: for each i, coeff_i = (M_k / p_i) * inverse(M_k / p_i mod p_i) mod M_k. This amortizes the O(k^2) inverse computation.

**Definition D2 (Residue Encoding).** For X in Z, the residue encoding is:

    Enc_p(X) = (X mod p_0, X mod p_1, ..., X mod p_k)

*Implementation*: `RnsBasis::encode(x: u128) -> Vec<u64>` for unsigned, `encode_signed(x: i128)` for centered-lift values. Signed encoding uses the identity (x mod p + p) mod p for negative x.

**Definition D3 (CRT Decode).** The CRT reconstruction is the unique X in [0, M_k) satisfying all congruences simultaneously:

    Dec_p(r_0, ..., r_k) = sum_i r_i * coeff_i mod M_k

*Implementation*: `RnsBasis::decode(residues: &[u64]) -> u128`. Uses precomputed CRT coefficients with safe u128 modular multiplication (shift-and-add fallback when a*b might overflow u128).

**Theorem T1 (CRT Bijectivity).** Enc_p is a ring isomorphism from Z_{M_k} to Z_{p_0} x ... x Z_{p_k}. Specifically:

    (i)  Dec_p(Enc_p(X)) = X for all X in [0, M_k)
    (ii) Enc_p(X + Y) = Enc_p(X) + Enc_p(Y) (lane-wise mod p_i)
    (iii) Enc_p(X * Y) = Enc_p(X) * Enc_p(Y) (lane-wise mod p_i)

*Test Obligation CT-01*: Exhaustive round-trip for small basis (M_k = 1001), 1M random samples for medium basis (M_k ~ 67.9 billion). Ring homomorphism verified for addition and multiplication with 100K samples each.

**Definition D4 (Centered Lift).** The centered representative of x mod M_k is:

    Center_{M_k}(x) = x               if x <= floor(M_k / 2)
                     = x - M_k         if x > floor(M_k / 2)

This maps [0, M_k) bijectively to [-floor(M_k/2), floor(M_k/2)]. For even M_k, ties go negative (convention: [-M_k/2, M_k/2 - 1]).

*Implementation*: `RnsBasis::centered_lift(x: u128) -> i128` and `decode_centered()`.

### 1.2 Garner Mixed-Radix Decomposition

**Definition D5 (Garner Digits).** For pairwise coprime **p** = (p_0, ..., p_k), the Garner decomposition of X in [0, M_k) is the unique tuple (d_0, ..., d_k) with d_i in {0, ..., p_i - 1} such that:

    X = d_0 + d_1 * p_0 + d_2 * p_0 * p_1 + ... + d_k * prod_{j<k} p_j

*Implementation*: `clockwork_core::garner::GarnerDigits` with `reconstruct() -> u128`.

**Definition D6 (K-Elimination).** The 2-gear Garner step. Given coprime m, a and residues r = X mod m, s = X mod a:

    k = (s - r) * m^{-1} mod a

Then X = r + k * m (mod m * a), with k in {0, ..., a-1}.

*Implementation*: `k_eliminate(r, s, m, a, m_inv_mod_a) -> u64`. Precomputed inverse m^{-1} mod a avoids repeated inversion.

**Theorem T2 (K-Elimination Correctness).** For coprime m, a with X in [0, m*a):
- (i) k in {0, ..., a-1}
- (ii) r + k*m = X (mod m*a)
- (iii) k is unique

*Test Obligation CT-02*: Exhaustive for [0, 77) with moduli (7, 11). 1M random samples for moduli (251, 509). Constant-time variant verified against standard implementation.

**Constant-Time K-Elimination.** The function `k_eliminate_ct` computes the same result as `k_eliminate` but without secret-dependent branches. The subtraction (s - r mod a) is computed as (s + a - r_mod_a) mod a, which normalizes both the borrow and no-borrow cases identically.

*Implementation*: `clockwork_core::garner::k_eliminate_ct`. Required by INV-7 and T16 for any path touching secret values.

**Full Garner Algorithm.** The iterative Garner decomposition peels off one digit per step:

    d_0 = r_0
    For i = 1, ..., k:
        current = r_i
        For j = 0, ..., i-1:
            current = (current - d_j) * p_j^{-1} mod p_i
        d_i = current

*Implementation*: `garner_decompose()` (standard) and `garner_decompose_ct()` (constant-time).

### 1.3 Bit-Width Bound Tracking

**Definition D7 (Bound).** A bound H is a non-negative integer such that |Center_{M_k}(X)| < 2^H. The bound is NEVER computed from the actual value -- it is always derived from operand bounds using the following update rules:

    Addition:         H(X + Y) <= max(H(X), H(Y)) + 1
    Subtraction:      H(X - Y) <= max(H(X), H(Y)) + 1
    Multiplication:   H(X * Y) <= H(X) + H(Y)
    Negation:         H(-X) = H(X)
    Scalar multiply:  H(c * X) <= H(c) + H(X)
    Dot product:      H(sum w_j * x_j) <= ceil(log2 L) + max_j(H(w_j) + H(x_j))

*Implementation*: `clockwork_core::bound_tracker::Bound`. All update rules use only u32 integer arithmetic. The `from_value(i128)` constructor computes the minimal bound via `128 - abs.leading_zeros()`.

**Theorem T4 (Bound Tracker Soundness).** If all input values satisfy |Center(X)| < 2^{H(X)}, then all values computed by the D7 update rules satisfy |Center(Y)| < 2^{H(Y)}.

*Proof sketch*: For addition, |X + Y| <= |X| + |Y| < 2^{H(X)} + 2^{H(Y)} <= 2 * 2^{max(H(X), H(Y))} = 2^{max+1}. Multiplication: |X * Y| < 2^{H(X)} * 2^{H(Y)} = 2^{H(X)+H(Y)}.

*Test Obligation CT-03*: 100K random GearStack values with 10-bit bound. Verify that after add (bound = 11), mul (bound = 20), and chained ops (bound = 21), `verify_bound()` never reports a violation.

### 1.4 Basis Extension (Promotion)

**Definition D8 (Promotion).** Extending an RNS basis by appending a new coprime modulus p_{k+1}:

    p' = (p_0, ..., p_k, p_{k+1})
    M_{k+1} = M_k * p_{k+1}

A residue vector (r_0, ..., r_k) is promoted by computing r_{k+1} = X mod p_{k+1} and appending it.

*Implementation*: `RnsBasis::extend()` creates new basis, `promote_unchecked()` appends residue, `promote_verified()` reconstructs X and validates the new residue.

**Theorem T3 (Promotion Preserves Representation).** For X in [0, M_k), extending to basis **p'** and demoting back recovers the original:

    Dec_p(Demote(Promote(Enc_p(X)))) = X

*Test Obligation CT-04*: 100K random values, verify promote + demote round-trip.

### 1.5 Decode-to-q Bridge

**Definition D9 (DecodeToQ).** The bridge from Clockwork representation space Z_{M_k} to RLWE ciphertext space Z_q:

    Unsigned: DecQ_p(r_0, ..., r_k) = Dec_p(r_0, ..., r_k) mod q
    Centered: DecQ_p(r_0, ..., r_k) = Center_{M_k}(Dec_p(r_0, ..., r_k)) mod q

*Implementation*: `clockwork_core::decode_to_q::DecodeToQ`. The RLWE modulus q is fixed at construction and NEVER changes (INV-1).

**Theorem T5 (DecQ Round-Trip).** For all c in Z_q, when M_k >= q:

    DecQ_p(Enc_p(c_tilde)) = c

where c_tilde is the canonical lift of c (unsigned: c itself; centered: centered representative).

*Test Obligation CT-05*: Exhaustive for q = 4093 and q = 997 across 5 different basis choices, both unsigned and centered conventions.

---

## Q2: Architecture

### 2.1 GearStack Composite Type

The GearStack is the primary working type: it bundles a value's RNS residues, its bound tracker entry, and a reference to its basis. Every arithmetic operation returns a new GearStack with correctly updated bounds.

*Implementation*: `clockwork_core::gearstack::GearStack`.

**Construction**: `from_value(value: u128, bound_bits: u32, basis: RnsBasis)` encodes the value and checks that the basis capacity satisfies A5: M_k > 2^{H + guard} where guard = 8 bits (DEFAULT_GUARD_BITS).

**Arithmetic**: `add()`, `sub()`, `mul()` perform lane-wise operations on residues and update bounds via D7 rules. Each operation checks capacity sufficiency and returns `GearError::InsufficientCapacity` if the result would overflow.

**Verification**: `verify_bound()` is a DEBUG operation that reconstructs the full value and checks |Center(value)| < 2^{bound}. This is only for test obligation CT-03 -- production code never reconstructs full values.

**Dot Product**: `dot_product(weights, values)` chains multiply-then-add operations. The D7 dot product bound (ceil(log2 L) + max product bound) is tighter than naive chaining.

*Test Obligation CT-06*: 100K random samples verify that lane-wise add and mul on GearStack match ring arithmetic on reconstructed values.

### 2.2 GRO Timing Gate

**Axiom A3 (DDS Precision Bound).** All frequencies from a Direct Digital Synthesis oscillator are rational. Phase increments are integers over a 2^{N_acc} accumulator. No irrational frequency claims are made.

**Definition D13 (GRO Gate).** A pair of DDS oscillators with:
- Phase increments: delta_phi_A, delta_phi_B
- Accumulator width: N_acc bits (range [8, 63])
- Phase at time t: theta_X(t) = t * delta_phi_X mod 2^{N_acc}

*Implementation*: `clockwork_core::gro::GroGate`.

**Definition D14 (Coincidence Window).** A time step t is inside a coincidence window when:

    |theta_A(t) - theta_B(t)| mod 2^{N_acc} < W

where W is the window width parameter and the distance is the circular (folded) distance.

**Definition D15 (Window).** A contiguous interval [start, end) of time steps where D14 holds.

**Golden Ratio Construction.** `GroGate::golden_ratio(n_acc, delta_phi_a, window_width)` computes delta_phi_B = delta_phi_A * F_86 / F_85 using Fibonacci numbers F_85 = 420196140727489673 and F_86 = 679891637638612258. This is pure integer arithmetic. The ratio F_86/F_85 approximates the golden ratio phi with error < 10^{-18}. If the phase increment difference is even, it is nudged by 1 to ensure maximal period (T9).

**Theorem T9 (Coincidence Period).** The coincidence period is:

    T_coinc = 2^{N_acc} / gcd(delta_phi_A - delta_phi_B, 2^{N_acc})

When delta_phi_A - delta_phi_B is odd, gcd = 1, giving the maximal period 2^{N_acc}.

*Test Obligation GT-01*: 100+ random parameter pairs with odd difference, verify period = 2^{N_acc}.

**Theorem T10 (Equidistribution).** Coincidence windows are uniformly distributed across the phase space. That is, dividing one full period into K bins, each bin receives approximately T_windows / K windows.

*Test Obligation GT-02*: 16-bin chi-squared test over one full period of a 16-bit accumulator GRO. Each bin's deviation from expected must be within 50% of the mean.

**Theorem T8 (Timing Isolation).** When key-dependent operations execute only during GRO coincidence windows AND use constant-time implementations, no timing information about secret values leaks through execution time.

**Theorem T16 (GRO-Garner Composition).** The combination of GRO gating (T8) with constant-time K-Elimination (k_eliminate_ct) ensures that no timing side-channel exists for the Garner decomposition of secret values.

### 2.3 Key Share Lifecycle

**Axiom A4 (Memory Zeroing).** Key material is zeroed via volatile writes that prevent compiler dead-store elimination. Implementation uses `core::ptr::write_volatile` followed by a `core::sync::atomic::fence(SeqCst)` to prevent reordering.

**Definition D18 (Key Share Pair).** A pair (s_1, s_2) where s_1 + s_2 = s (mod q). The share s_1 = r (uniform random), s_2 = (s - r) mod q.

*Implementation*: `clockwork_core::key_lifecycle::KeySharePair::split(s, r, q)`.

**Definition D19 (Re-sharing).** Given fresh randomness r':

    s_1' = (s_1 + r') mod q
    s_2' = (s_2 - r') mod q

The re-shared pair (s_1', s_2') satisfies s_1' + s_2' = s_1 + s_2 = s (mod q). Old shares are zeroed on Drop (A4).

*Implementation*: `KeySharePair::reshare(r) -> KeySharePair`.

**Definition D20 (Key Lifecycle State Machine).**

    KEYGEN --[initialize]--> SPLIT --[split complete]--> ACTIVE
    ACTIVE --[reshare]--> ACTIVE
    ACTIVE --[destroy]--> ZEROED

States are represented by `KeyState` enum: {Keygen, Split, Active, Zeroed}. Transitions are enforced at runtime -- calling `reshare()` in Keygen state returns an error, calling `initialize()` twice returns an error.

*Implementation*: `clockwork_core::key_lifecycle::KeyLifecycle`.

**Theorem T11 (Re-sharing Correctness).** For any number of re-sharings with randomness r_1, r_2, ..., r_n:

    s_1^{(n)} + s_2^{(n)} = s (mod q)

*Test Obligation KT-01*: 100K random (s, r_0, r_reshare) triples verify initial split and one reshare. 1000 consecutive reshares on a single key pair verify chain correctness.

**Theorem T12 (Share Independence).** Share s_1 is uniformly distributed in Z_q, independent of s. Knowledge of s_1 alone reveals zero information about s.

*Test Obligation KT-04*: 100K samples with fixed secret, bin s_1 values into 16 bins, chi-squared test (threshold: chi^2 < 50, df = 15).

**Theorem T13 (Forward Secrecy).** Compromise of shares at time T reveals nothing about shares at time T+1 (after resharing with fresh randomness).

**Invariant INV-5 (Secret Never Stored).** The full secret s is NEVER stored in memory alongside the shares during the ACTIVE state. It exists only transiently during KEYGEN -> SPLIT transition and during `reconstruct_for_decrypt()`.

*Test Obligation KT-02*: Verify that after `zero()`, both share_a and share_b read as 0.

*Test Obligation KT-03*: Verify full state machine: Keygen -> Active -> reshare -> Active -> Zeroed, with correct state at each step.

### 2.4 Triple-Redundant Integrity

**Definition D22 (Triple Redundant Storage).** For a value v:

    TR(v) = (v, v, v, CRC32(v))

Three independent copies plus a CRC32 checksum.

*Implementation*: `clockwork_core::integrity::TripleRedundant<T>` where T: Clone + Eq + Debug + AsBytes.

**Definition D23 (Majority Vote).** The MajVote algorithm:

    1. If A = B = C and CRC32(A) matches: AllAgree(A)
    2. If exactly two agree and CRC matches the majority: Recovered(majority, corrupted_id)
    3. Otherwise: Failed (fail-closed)

*Implementation*: `TripleRedundant::read() -> VoteResult<T>`.

**Theorem T14 (Single Corruption Recovery).** If exactly one of the three copies is corrupted, MajVote returns `Recovered` with the correct value.

*Test Obligation IT-01*: Corrupt each of the three copies individually, verify recovery.

**Theorem T15 (Fail-Closed Guarantee).** If two or more copies are corrupted, MajVote returns `Failed`. No further operations execute.

*Test Obligation IT-02*: Corrupt copies A and B simultaneously, verify `Failed`.

*Test Obligation IT-03*: 1M random corruption patterns on two copies, verify detection rate > 99.99%.

---

## Q3: Formal Properties and Security

### 3.1 Axioms

| ID | Statement | Enforcement |
|----|-----------|-------------|
| **A1** | RLWE modulus q is fixed and public | `DecodeToQ::q` is immutable; no setter exists |
| **A2** | RLWE operations over Z_q | Architectural constraint; Clockwork handles Z_{M_k} |
| **A3** | DDS frequencies are rational | Integer phase increments over 2^{N_acc}; Fibonacci approx |
| **A4** | Memory zeroing via volatile writes | `core::ptr::write_volatile` + SeqCst fence in `zero_u64` |
| **A5** | Guard margin: M_k > 2^{H + guard} | Checked at GearStack construction; DEFAULT_GUARD_BITS = 8 |

### 3.2 Invariants

| ID | Guarantee | Enforcement Mechanism |
|----|-----------|----------------------|
| **INV-1** | q is FIXED, immutable | `DecodeToQ` has no setter; q set at construction |
| **INV-2** | Enc o Dec = identity on [0, M_k) | CRT bijectivity (T1); precomputed coefficients |
| **INV-3** | abs(Center(X)) < 2^{H(X)} | D7 update rules; only integer arithmetic |
| **INV-4** | GRO window schedule is deterministic | Phase increments are fixed integers; no randomness |
| **INV-5** | Secret s NEVER stored with shares in ACTIVE | KeyLifecycle state machine; A4 zeroing on transition |
| **INV-6** | Zero floating-point computation | Type system; `#![deny(clippy::float_arithmetic)]` |
| **INV-7** | Operation schedule is value-independent | Bound tracking uses only bounds, never values |
| **INV-8** | Before DecQ: MajVote must succeed | TripleRedundant fail-closed semantics (T15) |

### 3.3 Theorem Summary

| ID | Statement | Test ID | Verification Level |
|----|-----------|---------|-------------------|
| **T1** | CRT bijectivity | CT-01 | Exhaustive (small) + 1M random |
| **T2** | K-Elimination correctness | CT-02 | Exhaustive (small) + 1M random |
| **T3** | Promotion preserves representation | CT-04 | 100K random |
| **T4** | Bound tracker soundness | CT-03 | 100K random with `verify_bound()` |
| **T5** | DecQ round-trip | CT-05 | Exhaustive for q = 4093, 997 |
| **T8** | Timing isolation | Architecture | GRO + CT ops compositional argument |
| **T9** | Coincidence period formula | GT-01 | 100+ parameter configs |
| **T10** | Window equidistribution | GT-02 | Chi-squared, 16 bins, full period |
| **T11** | Re-sharing correctness | KT-01 | 100K random + 1000-chain |
| **T12** | Share independence | KT-04 | Chi-squared, 16 bins, 100K samples |
| **T13** | Forward secrecy | Architecture | Resharing with independent randomness |
| **T14** | Single corruption recovery | IT-01 | All 3 positions |
| **T15** | Fail-closed guarantee | IT-02, IT-03 | 1M random corruption patterns |
| **T16** | GRO-Garner composition | Architecture | CT K-Elim + GRO gating |

### 3.4 Constant-Time Guarantees

Two security invariants govern constant-time behavior:

**SC-1 (No Secret-Dependent Branches).** All arithmetic on secret values uses:
- Modular arithmetic that normalizes both borrow/no-borrow cases identically
- Fixed-width integer operations (u64, u128) with known execution time
- No conditional branches based on secret-derived values

**SC-2 (Schedule-Only Promotion).** Promotion decisions depend only on bounds (public, schedule-determined), never on actual values. This is enforced by INV-7: the bound tracker never inspects the value, only propagates bounds through D7 rules.

### 3.5 Zero Floating-Point Guarantee

The entire Clockwork-Core crate contains zero floating-point operations. This is not merely a convention -- it is architecturally enforced:

1. All arithmetic uses u32, u64, u128, i128 integer types
2. Logarithms are computed as `128 - leading_zeros()` (integer bit-counting)
3. Golden ratio approximation uses Fibonacci ratio F_86/F_85 (integer division)
4. Modular inverses use extended GCD (integer recursion)
5. CRC32 uses bitwise operations (crc32fast)
6. Statistical tests in test code use f64, but this is test-only and does not affect production paths

The sole f64 usage is in test obligation KT-04 (chi-squared computation) and IT-03 (detection rate). These are verification-only and compile exclusively under `#[cfg(test)]`.

---

## Q4: NINE65 Integration

### 4.1 Integration Architecture

Clockwork-Core is integrated into NINE65 v5 as an optional workspace crate behind the `clockwork` feature flag. The integration follows a wrapper pattern: each Clockwork capability is wrapped in a NINE65-specific API that adapts types and provides FHE-oriented defaults.

```
nine65 crate (clockwork feature)
  |
  +-- arithmetic/bounded_rns.rs   -->  wraps Bound (D7)
  +-- security/gro_gate.rs        -->  wraps GroGate (D13-D16)
  +-- security/key_manager.rs     -->  wraps KeyLifecycle (D18-D21)
  +-- security/integrity.rs       -->  uses crc32fast (D22-D23 simplified)
  +-- tests/clockwork_cross_validation.rs
  |
  v
clockwork-core crate
  +-- basis.rs        (D1-D4, D8, T1, T3, T5)
  +-- garner.rs       (D5-D6, T2, T16)
  +-- bound_tracker.rs (D7, T4)
  +-- gearstack.rs    (GearStack composite, CT-03, CT-06)
  +-- decode_to_q.rs  (D9, T5, INV-1)
  +-- gro.rs          (D13-D16, T8-T10, T16, A3)
  +-- key_lifecycle.rs (D18-D21, T11-T13, INV-5, A4)
  +-- integrity.rs    (D22-D23, T14-T15, INV-8)
```

### 4.2 BoundedValue (Bound Tracker Wrapper)

`nine65::arithmetic::BoundedValue` wraps Clockwork's `Bound` with FHE-oriented API:

| Method | D7 Rule | Purpose |
|--------|---------|---------|
| `on_add(other)` | H(X+Y) <= max + 1 | Track ciphertext addition |
| `on_mul(other)` | H(X*Y) <= H(X) + H(Y) | Track ciphertext multiplication |
| `on_rescale(prime_bits)` | H' = H - prime_bits | Track modulus switching (key to bootstrap-free depth) |
| `on_scalar_mul(scalar_bits)` | H(c*X) <= H(c) + H(X) | Track plaintext-ciphertext multiply |
| `would_overflow(capacity)` | H > capacity | Detect overflow before it corrupts |
| `needs_promotion(cap, guard)` | cap < H + guard | Signal need for basis extension |
| `dot_product_bound(terms)` | D7 dot product rule | Track matrix-vector multiply |

The `on_rescale` method is critical for NINE65's bootstrap-free depth strategy: each rescaling drops one RNS prime, reducing both the coefficient size and the bound by that prime's bit-width. This is how GSO-FHE achieves depth-50 without bootstrapping.

### 4.3 TimingGate (GRO Wrapper)

`nine65::security::TimingGate` wraps Clockwork's `GroGate` for FHE key operations:

- `new(n_acc, window_width)` creates a golden-ratio GRO with default parameters
- `from_params(delta_a, delta_b, n_acc, window_width)` allows custom configuration
- `next_window(from, max_search)` finds the next execution window
- `is_maximal_period()` verifies the T9 maximal period property

Key operations (decrypt, keygen, evaluation key generation) should execute only during GRO windows, making timing side-channels impossible even against an adversary who can measure execution time with cycle-level precision.

### 4.4 KeyManager (Key Lifecycle Wrapper)

`nine65::security::KeyManager` wraps Clockwork's `KeyLifecycle`:

- `new(q, reshare_interval)` creates a manager with NINE65's NTT prime as modulus
- `initialize(s, r)` splits the secret key into shares
- `record_operation()` increments the operation counter; returns `true` when resharing is needed
- `reshare(r)` performs D19 re-sharing with fresh randomness
- `reconstruct_for_decrypt()` briefly reconstructs s for decryption (must zero after use)
- `destroy()` transitions to ZEROED state, zeroing all key material

This is a major security upgrade over storing the full secret key in memory for the entire session. With the KeyManager, the full key exists only transiently during decrypt operations.

### 4.5 Integrity Checking

`nine65::security::integrity` provides CRC32 checksums for RNS polynomial limbs:

- `compute_limb_checksum(limb: &[u64]) -> u32` hashes a coefficient vector
- `verify_limb_checksum(limb, expected) -> bool` validates against stored checksum
- `CheckedLimb` bundles data with its checksum for automatic integrity tracking

This catches memory corruption (bit flips, buffer overflows, row hammer) that could silently corrupt FHE computations. The CRC32 computation is hardware-accelerated via the `crc32fast` crate.

### 4.6 Cross-Validation: Garner vs K-Elimination

The integration test suite (`tests/clockwork_cross_validation.rs`) validates that Clockwork's Garner reconstruction produces identical results to NINE65's K-Elimination:

| Test | Scope | Iterations |
|------|-------|------------|
| `garner_matches_kelim_2_modulus` | 2-modulus (251, 509) | 100,000 |
| `garner_matches_crt_decode_multi_modulus` | 5-modulus (17, 31, 61, 127, 251) | 100,000 |
| `garner_ct_matches_standard` | CT vs standard Garner, 4-modulus | 100,000 |
| `exhaustive_small_moduli` | 3-modulus (7, 11, 13), all 1001 values | Exhaustive |
| `centered_lift_consistency` | Centered lift range and congruence | 1001 |

### 4.7 Feature Gating

All Clockwork integration code is behind the `clockwork` feature flag:

```toml
# crates/nine65/Cargo.toml
[features]
clockwork = ["clockwork-core", "crc32fast"]

[dependencies]
clockwork-core = { path = "../clockwork-core", optional = true }
crc32fast = { version = "1.3", optional = true }
```

This ensures:
- Building without `--features clockwork` produces the same binary as before integration
- Clockwork's `unsafe` code (volatile zeroing in key_lifecycle) is isolated in a separate crate, respecting nine65's `#![forbid(unsafe_code)]`
- The `crc32fast` dependency is only pulled when integrity checking is needed

### 4.8 Test Coverage Summary

| Component | Tests | Source |
|-----------|-------|--------|
| clockwork-core (standalone) | 46 | 7 modules with CT-*, GT-*, IT-*, KT-* obligations |
| nine65 bounded_rns | 11 | arithmetic/bounded_rns.rs |
| nine65 gro_gate | 5 | security/gro_gate.rs |
| nine65 key_manager | 6 | security/key_manager.rs |
| nine65 integrity | 8 | security/integrity.rs |
| Cross-validation | 5 | tests/clockwork_cross_validation.rs |
| **Total (clockwork)** | **81** | Formal spec + integration |

---

## Appendix A: Module-to-Specification Traceability

| Source File | Definitions | Theorems | Invariants | Axioms | Test IDs |
|-------------|-------------|----------|------------|--------|----------|
| `basis.rs` | D1, D2, D3, D4, D8 | T1, T3, T5 | INV-2 | -- | CT-01, CT-04 |
| `garner.rs` | D5, D6 | T2, T16 | INV-7 | -- | CT-02 |
| `bound_tracker.rs` | D7 | T4 | INV-3 | -- | CT-03 |
| `gearstack.rs` | (composite) | T1, T4 | INV-2, INV-3 | A5 | CT-03, CT-06 |
| `decode_to_q.rs` | D9 | T5 | INV-1 | A1 | CT-05 |
| `gro.rs` | D13, D14, D15 | T8, T9, T10, T16 | INV-4 | A3 | GT-01, GT-02 |
| `key_lifecycle.rs` | D18, D19, D20 | T11, T12, T13 | INV-5 | A4 | KT-01..KT-04 |
| `integrity.rs` | D22, D23 | T14, T15 | INV-8 | -- | IT-01..IT-04 |

## Appendix B: Build and Test Commands

```bash
# Build clockwork-core standalone
cargo build -p clockwork-core --release

# Run all 46 clockwork-core tests
cargo test -p clockwork-core --release

# Build nine65 with clockwork integration
cargo build -p nine65 --features clockwork --release

# Run nine65 clockwork tests (30 unit + 5 integration)
cargo test -p nine65 --features clockwork --release

# Run cross-validation integration tests
cargo test -p nine65 --test clockwork_cross_validation --features clockwork --release

# Full workspace build and test
cargo test --workspace --release
```

## Appendix C: Notation Reference

| Symbol | Meaning |
|--------|---------|
| **p** = (p_0, ..., p_k) | RNS basis (pairwise coprime moduli) |
| M_k = prod p_i | Basis capacity |
| Enc_p(X) | Residue encoding: (X mod p_0, ..., X mod p_k) |
| Dec_p(r) | CRT reconstruction: unique X in [0, M_k) |
| Center_{M_k}(x) | Centered lift: x if x <= M_k/2, else x - M_k |
| H(X) | Bit-width bound: abs(Center(X)) < 2^H |
| DecQ_p(r) | Decode to Z_q: Dec_p(r) mod q |
| (s_1, s_2) | Key share pair: s_1 + s_2 = s (mod q) |
| theta_X(t) | Phase of oscillator X at time t |
| W | GRO window width (phase accumulator units) |
| N_acc | Phase accumulator bit width |
| TR(v) | Triple-redundant: (v, v, v, CRC32(v)) |
| MajVote | Majority vote with CRC verification |
