# U256 K-Elimination Fix for secure_192/secure_256

## Problem
secure_192 and secure_256 configurations have Q > u128:
- secure_192: Q ≈ 5.855e+43 (146 bits)
- secure_256: Q ≈ 2.252e+61 (204 bits)

This caused panics in:
1. Initialization (Q product overflow)
2. Decrypt scaling
3. K-Elimination rescale
4. Digit extraction for relinearization

## Solution

### Custom U256 Type (rns.rs)
Minimal 256-bit unsigned integer with only operations needed:
- `add`, `sub`, `mul_u64`, `mul_low` (low 256 bits)
- `div_mod_u64`, `mod_u64`, `rem_u256`
- `shr1`, `shl1`, `bitlen`, `get_bit`
- `add_mod`, `sub_mod`, `product_u64s`
- Operator traits: `+`, `-`, `*`, `/`, `%`

### extract_k_rns_level (rns.rs)
Changed signature from `(u128, &[u64], &[u64]) -> u128` to `(U256, &[u64], &[u64]) -> U256`
- Uses U256 throughout for M_level product
- CRT reconstruction via iterative Garner algorithm to U256

### k_elim_rescale_dual (rns_fhe.rs)
Completely rewritten to use U256:
- `m_level = U256::product_u64s(level_primes)`
- `(delta, r) = m_level.div_mod_u64(t)`
- Uses SignedU256 for centered representation
- Uses SignedK256 for signed k interpretation
- `round_div_signed_mod_u256` for exact rounding
- Correct encoding for anchor primes (handles M not divisible by anchor)

### mod_switch_down_dual (rns_fhe.rs)
Rewritten to use U256:
- SignedU256::center for value centering
- Proper signed quotient encoding into both main and anchor RNS

### extract_digit_dual (rns_fhe.rs)
Rewritten to use U256 only (no U512):
- Direct bit extraction from U256 for digit decomposition

### decrypt_dual_with_diagnostics (rns_fhe.rs)
Added overflow detection:
- Falls back to U256 path when `full_value * t` would overflow u128

## Key Helper Types

```rust
struct SignedU256 { mag: U256, is_neg: bool }
struct SignedK256 { magnitude: U256, is_neg: bool }
```

## Test Results

- **431 library tests pass** (100%)
- **17 integration tests pass** (100%)
- secure_192: init ✅, keygen ✅, encrypt/decrypt ✅, multiplication ✅
- secure_256: init ✅, keygen ✅, encrypt/decrypt ✅

## Files Modified

1. `crates/nine65/Cargo.toml` - Removed `uint` crate dependency
2. `crates/nine65/src/arithmetic/rns.rs` - Added custom U256, updated extract_k_rns_level
3. `crates/nine65/src/arithmetic/mod.rs` - Updated exports
4. `crates/nine65/src/ops/rns_fhe.rs` - Updated all U256-dependent paths

## Verification

```bash
cargo test -p nine65 secure_ --no-fail-fast
# 22 passed, 0 failed
```
