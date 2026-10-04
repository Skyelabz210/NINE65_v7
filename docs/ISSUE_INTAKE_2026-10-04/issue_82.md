# Issue #82: [P0] Fix bootstrap circular public-key mask sampling to be uniform over full Q_boot

- state: open
- labels: (none)
- created: 2026-08-31T07:08:48Z  updated: 2026-09-04T09:14:28Z
- url: https://github.com/Skyelabz210/NINE65_v7/issues/82

---

## Finding

`ClockworkBootstrap::generate_circular_pk` samples each RLWE public-key mask coefficient as:

```rust
let min_prime = min(all boot + anchor primes);
let a_coeffs = (0..n).map(|_| rng.next_u64() % min_prime).collect();
```

and then reduces that same narrow scalar into all main and anchor lanes.

This confines the jointly represented coefficient to `[0, min_prime)` instead of sampling uniformly over the full boot modulus `Q_boot`. It also introduces modulo bias from `% min_prime`.

The main FHE path already contains the corrected design in `RNSFHEContext::sample_uniform_dual_poly`: exact full-width rejection sampling over `[0, M)` followed by reduction of one sampled integer into every main/anchor lane. Its own source comments document why a narrow shared draw is jointly degenerate. The bootstrap PK must use the same invariant.

This is especially sensitive because the bootstrap public key is used to create BSK material that encrypts the working secret key.

## Required fix

1. Extract/reuse one canonical full-width dual-RNS uniform sampler rather than maintaining a second sampling implementation.
2. For each coefficient, rejection-sample an exact integer uniformly in `[0, Q_boot)` using enough `u64` limbs; `Q_boot` currently fits within the existing U256 machinery.
3. Reduce that one accepted integer independently into each main and anchor modulus so both tracks encode the same integer.
4. No `% modulus` shortcut for the source distribution unless an exact rejection correction makes it unbiased.
5. Preserve `SecureRng` enforcement on production key generation.
6. Zeroize temporary secret-bearing/sensitive buffers where applicable.
7. Audit every other RLWE `a` sampler in bootstrap/KSK/Galois/keygen for the same narrow-support pattern.

## Correctness/security regression tests

Add deterministic structural tests that:
- reconstruct sampled coefficients from the main basis and prove values occur above `min_prime`;
- verify every anchor residue equals the reconstructed coefficient modulo its anchor prime;
- verify exact rejection-sampling bounds at the top of `[0,Q_boot)`;
- reject/flag the old sampler in a regression test;
- run bootstrap keygen + refresh roundtrips across all named configs and multiple seeds;
- include the existing zero-secret diagnostic style used to catch narrow-mask leakage in the main FHE sampler, adapted to the bootstrap-key path.

Do not turn a statistical check into a proof claim: the structural support/identity tests are the hard gates.

## Mandatory before/after performance evidence

Before changing the sampler, record integer timings for:
- circular bootstrap key generation,
- `BootstrapKey::generate`,
- one full `bootstrap()` roundtrip,
for `secure_128`, `secure_192`, and `secure_256` with fixed seeded benchmark RNG under `allow_insecure`.

After the fix rerun identical commands on the same machine/toolchain/features and publish integer nanosecond/microsecond medians, allocations if available, and exact roundtrip correctness. Sampling security takes priority over speed; then optimize allocations/batching without narrowing support.

## Completion condition

No production bootstrap RLWE mask may have joint support restricted to one machine word or the smallest modulus. Full-Q sampling and main/anchor identity must be mechanically tested.