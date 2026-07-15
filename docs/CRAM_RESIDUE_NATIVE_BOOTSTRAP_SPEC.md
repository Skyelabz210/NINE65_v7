# CRAM Residue-Native Clockwork Bootstrap Contract

Status: **normative implementation specification for issue #29 / draft PR #30**.

This specification does not describe the current `modswitch_to_t` implementation. The current implementation reconstructs coefficients into `u128` or `U256` and is therefore a reference path only until replaced.

## 1. Arithmetic domains

Let the active CLASS-F main family be

```text
B_ell = (q_0, ..., q_{ell-1}),
Q_ell = product(q_i).
```

Requirements:

- every `q_i` is prime;
- every `q_i` is NTT-compatible for the configured polynomial degree;
- the `q_i` are distinct and pairwise coprime.

Let the CLASS-R anchor family be

```text
A = (a_0, ..., a_{s-1}),
A_cap = product(a_j).
```

Requirements:

- every `a_j > 1`;
- the `a_j` are distinct and pairwise coprime;
- `gcd(a_j, q_i) = 1` for every pair;
- anchor primality is not required;
- anchor capacity must exceed the proved quotient/winding bound.

A coefficient is represented by the coherent state

```text
X = ((x mod q_i)_i, (x mod a_j)_j, level, range_certificate).
```

The ordered factor vectors are canonical. A scalar product is optional metadata only.

## 2. Forbidden production operations

The production refresh path must not materialize the canonical integer representative of a ciphertext coefficient.

The following are forbidden in production bootstrap and its direct callees:

- `crt_reconstruct_n`;
- `crt_reconstruct_u256`;
- Garner reconstruction;
- mixed-radix conversion;
- a `0` or saturated scalar standing for an overflowing product;
- routing, capacity, or noise decisions from summed lane widths;
- conversion of all coefficient residues into one `u128`, `U256`, `BigUint`, or equivalent number-line value.

A reference implementation may reconstruct only under `#[cfg(test)]` and only for equivalence testing.

## 3. Required primitive: bounded residue quotient projection

Define the typed primitive

```text
KDivProject(B_ell, A, D, Y, H) -> (K, R, C)
```

where:

- `D > 0` is the divisor represented by its exact factors/limbs and residues;
- `Y` is a coherent main+anchor residue state;
- `H` is a public bound proving `0 <= y < H * D`;
- `K` is the quotient represented in the output quotient basis;
- `R` is the remainder represented in both main and anchor lanes;
- `C` is a certificate of the equations and bounds below.

The primitive must establish:

```text
y = kD + r,
0 <= r < D,
0 <= k < H.
```

Residue obligations:

```text
for every q_i: y_i = k_i * (D mod q_i) + r_i mod q_i,
for every a_j: y'_j = k'_j * (D mod a_j) + r'_j mod a_j.
```

Uniqueness obligation:

```text
H <= A_cap
```

or an equivalent proved bound in the selected quotient basis. This makes the bounded quotient/winding state unique without reconstructing `y`.

Failure is mandatory when:

- basis shape is inconsistent;
- any required coprimality condition fails;
- `D = 0`;
- the quotient bound is not covered by the anchor capacity;
- the input range certificate is absent or invalid;
- the output equations cannot be certified.

The primitive must return a typed error. It must not fall back to integer reconstruction.

## 4. Phase-1 modulus-switch transduction

For each ciphertext coefficient `x` at level `ell`, the BFV switch is

```text
m_t = floor((t*x + floor(Q_ell/2)) / Q_ell) mod t.
```

Construct the numerator residue state without leaving the lanes:

```text
Y = t*X + HalfQ_ell.
```

For every main lane:

```text
y_i = (t*x_i + floor(Q_ell/2) mod q_i) mod q_i.
```

For every anchor lane:

```text
y'_j = (t*x'_j + floor(Q_ell/2) mod a_j) mod a_j.
```

`Q_ell`, `floor(Q_ell/2)`, and their lane residues are precomputed from exact factor vectors or exact limbs. No scalar `Q_ell` is required.

Because `0 <= x < Q_ell`,

```text
0 <= t*x + floor(Q_ell/2) < (t + 1)*Q_ell.
```

Invoke

```text
KDivProject(B_ell, A, Q_ell, Y, t + 1).
```

The quotient is therefore uniquely bounded by `0 <= k <= t`. The plaintext output is

```text
m_t = k mod t.
```

The implementation may emit `m_t` as a plaintext-lane vector because Phase 2 consumes plaintext coefficients. It may not emit or retain the original coefficient `x` as a reconstructed integer.

## 5. Phase-2 and Phase-3 invariants

Phase 2 must consume only:

- the bounded plaintext coefficients from Phase 1;
- bootstrap-key ciphertexts already represented in boot main+anchor lanes;
- lane-local add/multiply/NTT operations.

Phase 3 must produce a `DualRNSCiphertext` satisfying:

```text
main lane count = work_config.primes.len(),
anchor lane count = canonical anchor count for N,
coefficient length in every lane = N,
level = work_config.primes.len().
```

No phase may silently drop the anchor track.

## 6. Correctness theorem required from the implementation

For every valid work configuration, key set, plaintext `m in [0,t)`, encryption randomness, and ciphertext state satisfying the declared input range:

```text
decrypt_work(bootstrap(encrypt_work(m))) = m.
```

The theorem/test scope must include:

```text
m = 0,
m = 1,
m = t - 1,
representative interior values,
all supported active levels ell >= 2.
```

The test-only reconstruction reference must agree coefficient-wise with the residue-native Phase-1 quotient on public vectors.

## 7. Complexity contract

Let `L = ell + s` be the number of active main and anchor lanes.

Sequential software work:

```text
O(L) per lane-local pass,
O(L log L) only when an explicit product/certificate tree requires it.
```

Parallel hardware depth:

```text
O(1) for fixed configured lane count with dedicated lanes,
or O(log L) with a balanced reduction/certificate tree.
```

The implementation must not describe unbounded-lane scalar work as `O(1)`.

## 8. Required Rust surface

The production implementation must expose an auditable typed boundary similar to:

```rust
pub struct ResidueDivisionCertificate {
    pub quotient_bound: u64,
    pub main_equations_verified: bool,
    pub anchor_equations_verified: bool,
    pub remainder_in_range: bool,
}

pub struct ResidueDivisionResult {
    pub quotient_mod_t: u64,
    pub remainder_main: Vec<u64>,
    pub remainder_anchor: Vec<u64>,
    pub certificate: ResidueDivisionCertificate,
}
```

Exact names may differ, but the information and failure semantics may not be erased.

## 9. Mandatory gates

The branch is not complete until all of the following pass:

1. source gate excludes reconstruction/Garner/mixed-radix from production bootstrap;
2. exact context metadata regression;
3. safe-basis regression;
4. Phase-1 residue-native/reference equivalence on public vectors;
5. bootstrap main/anchor shape regression;
6. exact decryption for zero, one, `t-1`, and interior values;
7. depth-three automatic-refresh run records actual bootstrap calls;
8. 100-trial statistical refresh run has zero failures;
9. formatting and compilation;
10. no floating-point token in load-bearing arithmetic paths.

A passing source gate without runtime correctness is insufficient. A passing runtime test that still reconstructs internally is also insufficient.