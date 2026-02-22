# Clockwork Bootstrap Correctness Contract

Revision: 2026-02-22 (v7 "Bootstrap Complete")

This document extracts the structural invariants enforced by the Clockwork
Bootstrap implementation into a reviewable contract. Each invariant is
annotated with (a) where it is enforced in code, (b) which test covers it,
and (c) the failure mode if violated.

---

## 1. Prime Superset Invariant

**Statement:** Boot primes must be a *strict* superset of work primes.

**Enforcement:** `assert_boot_invariants()` in
`crates/nine65/src/ops/bootstrap.rs` (called by `ClockworkBootstrap::new()`).

**Test:** `test_boot_primes_subset_and_single_drop_prime`,
`test_config_matrix_invariants_128_192_256`.

**Failure mode:** If a work prime is missing from boot primes, Phase 3
modswitch cannot map boot residues back to work residues. Ciphertext
becomes undecryptable.

---

## 2. Single Drop Prime Invariant

**Statement:** Boot primes must contain *exactly one* prime not present in
work primes (the "drop prime"). Phase 3 divides by this prime.

**Enforcement:** `assert_boot_invariants()` — counts extras and rejects != 1.

**Test:** `test_boot_primes_subset_and_single_drop_prime`,
`test_config_matrix_invariants_128_192_256`.

**Failure mode:** Zero extras: no modswitch headroom, Q_boot = Q_work.
Multiple extras: modswitch scaling factor is wrong (divides by only one
prime but Q_boot/Q_work > single prime).

---

## 3. Canonical Anchor Invariant

**Statement:** Boot context anchor primes must match the canonical anchor
list for the polynomial degree N. This prevents silent drift between work
and boot anchor sets.

**Enforcement:** `assert_boot_invariants()` — compares boot anchor primes
against `DualRNSContext::canonical_anchor_primes_for_n(N)`.

**Test:** `test_boot_anchor_primes_match_canonical`,
`test_config_matrix_invariants_128_192_256`.

**Failure mode:** Mismatched anchors cause K-Elimination rescale to compute
wrong correction terms. Post-bootstrap ciphertexts silently accumulate
unbounded noise.

---

## 4. Anchor Recomputation After Prime Drop

**Statement:** After Phase 3 modswitch (boot -> work), anchor limbs must
be recomputed from the new work main limbs via CRT reconstruction, not
copied or zeroed from the boot context.

**Enforcement:** `modswitch_boot_to_work()` explicitly reconstructs each
coefficient from work main limbs and reduces mod each anchor prime.

**Test:** `test_bootstrap_output_anchor_consistency` — verifies that
`anchor[ai][pos] == CRT(main)[pos] mod anchor_prime[ai]` at sampled
coefficient positions.

**Failure mode:** Zero or stale anchors cause K-Elimination to produce
garbage correction values. The next multiplication or rescale silently
corrupts the ciphertext.

---

## 5. Key-Switch Uses Full CRT Reconstruction

**Statement:** In the non-circular path (`bootstrap_with_ksk`), key
switching must CRT-reconstruct c1 coefficients from *all* boot prime limbs
before gadget decomposition.

**Enforcement:** `key_switch()` explicitly reconstructs c1[j] via
`crt_reconstruct_n()` across all boot primes before digit decomposition.

**Test:** `test_config_matrix_roundtrip_secure_128` (exercises
`bootstrap()` which uses the same CRT reconstruction pattern).

**Failure mode:** Decomposing from a single limb captures only ~30 bits of
a ~120-bit coefficient. KSK accumulation becomes wrong; the switched
ciphertext decrypts to garbage.

---

## 6. Non-Circular Ordering: Key-Switch Then ModSwitch

**Statement:** In `bootstrap_with_ksk()`, Phase 3 must apply key switching
*before* modswitch. The key switch operates in boot prime space (where the
KSK was generated). ModSwitch then scales Q_boot -> Q_work.

**Enforcement:** `bootstrap_with_ksk()` calls `key_switch()` then
`modswitch_boot_to_work()` in that order.

**Failure mode:** Reversing the order reduces the ciphertext to work prime
space *before* the KSK can operate, destroying the scale/encoding
invariants that the BFV scheme requires.

---

## 7. u128 CRT Ceiling Guard

**Statement:** All CRT reconstruction paths that compute prime products
must use checked arithmetic. If the product of primes exceeds u128, the
operation must return an explicit error, not silently wrap or saturate.

**Enforcement:**
- `modswitch_to_t()`: `primes.iter().try_fold(1u128, checked_mul)` -> `BootstrapOverflow`
- `modswitch_to_t_verified()`: same pattern
- `modswitch_boot_to_work()`: work-prime product check -> `BootstrapOverflow`
- `key_switch()`: boot-prime product check -> `BootstrapOverflow`
- `RNSContext::new()`: `checked_mul` with 0 sentinel
- `RnsBasis::new()` (clockwork-core): `checked_mul` -> `BasisError::CapacityOverflow`

**Test:** `test_secure_192_bootstrap_detects_u128_overflow`,
`test_secure_256_bootstrap_detects_u128_overflow`.

**Current ceiling:** secure_128 (3 x 30-bit = ~90 bits) fits in u128.
secure_192 (5 x 30-bit = ~150 bits) and secure_256 (7 x 30-bit = ~210 bits)
exceed u128 and are explicitly rejected.

**Path forward:** Feature-gated bigint CRT reconstruction (U256 or
arbitrary precision) for bootstrap paths at 192/256-bit security levels.
The existing `U256` type in `rns.rs` provides a foundation.

---

## 8. Bootstrap Depth Budget

**Statement:** The bootstrap circuit depth is ~1 (Phase 2 uses plaintext x
ciphertext, not ct x ct). Boot prime count is computed as
`max(bootstrap_depth + 2, work_primes + 1)`.

**Enforcement:** `ClockworkBootstrap::new()` rejects configs where
`boot_max_depth < bootstrap_depth`.

**Test:** Implicit in all roundtrip tests (construction would fail).

**Failure mode:** Insufficient boot primes cause Phase 2 noise to exceed
the decryption threshold. Bootstrap output decrypts to wrong plaintext.

---

## Test Coverage Matrix

| Invariant | secure_128 | secure_192 | secure_256 |
|-----------|:----------:|:----------:|:----------:|
| Prime superset + single drop | Roundtrip | Structural | Structural |
| Canonical anchors | Roundtrip | Structural | Structural |
| Anchor recomputation | Sampled check | Structural | Structural |
| CRT reconstruction | Roundtrip | Overflow guard | Overflow guard |
| Key-switch ordering | Roundtrip | N/A (overflow) | N/A (overflow) |
| u128 ceiling | Passes | Caught | Caught |
| Full roundtrip | 7 messages | Blocked (u128) | Blocked (u128) |

"Structural" = `test_config_matrix_invariants_128_192_256` verifies
construction succeeds and invariants hold.

"Overflow guard" = Test verifies bootstrap correctly returns
`BootstrapOverflow` when CRT product exceeds u128.

"Blocked (u128)" = Full roundtrip requires bigint CRT (future work).
