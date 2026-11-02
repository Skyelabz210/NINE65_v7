# Native public refresh with a smaller inverse-transform cache

The native N8192 work / N32768 outer-ring research backend already exists.
This increment changes its resource usage so that current execution can fit
the selected 8 GiB environment. The earlier archived five-cycle run peaked
at 8.70 GiB on a different snapshot and host.

## Partition and bounds

The inverse transform has a cyclic dimension C=N/2 and a power-of-two
partition B*G=C. It caches 2B baby ciphertexts and performs
`2B+G-2` Galois calls. When the two optimal power-of-two partitions tie on
that count, the planner now chooses the smaller B.

At native N32768, the former B=128/G=128 partition becomes B=64/G=256:

| Quantity | Previous | Current |
| --- | --- | --- |
| Cached baby ciphertexts | 256 | 128 |
| Galois calls | 382 | 382 |
| Plaintext diagonals | 32768 | 32768 |
| Auxiliary cache coefficient payload | 4697620480 bytes | 2348810240 bytes |
| Cache payload in GiB | 4.375 | 2.1875 |

The exact native payload has two components, four two-chunk primes, nine
three-chunk primes, 32768 coefficients and eight bytes per transformed word.
Allocation overhead and all other circuit memory are additional.

More giant groups require more group finalizations and inverse auxiliary
transforms. Equal Galois count does not imply equal latency. This is a memory
tradeoff, with no measured speedup claim.

The plaintext input-error factor is unchanged. The deterministic switch
deposit is still computed from the actual B and G:
`switch_error * (input_error_factor*B + G-1)`.
The resulting native restoration bound remains 562 bits against the 633-bit
threshold; the next-square source forecast remains radius 48 within support49.
No noise admission threshold or security support predicate was relaxed.

## Executed checks

Six inverse-transform tests pass, including native payload/count arithmetic
and encrypted N128 execution with the new partition. Both main-prime and
auxiliary implementations produce identical ciphertexts for a fixed partition.
All output coefficients are compared with the specified slot-to-coefficient
mapping. Thirty focused public-refresh tests, workspace/all-targets Clippy,
formatting, the architecture scan and panic ratchet pass.

The new ignored native regression is explicitly selected with:

```sh
cargo test --locked --config profile.test.package.nine65.opt-level=2 -j2 \
  -p nine65 --lib \
  ops::public_refresh_native::native_public_refresh_current_single_cycle_with_dependent_square \
  -- --exact --ignored --nocapture --test-threads=1
```

It exercises the real encrypted carry producer, message restoration and
original-key return on all 8192 coefficients, then a dependent full-polynomial
square. The input is already squared before refresh. Checks include the
canonical value-root identity, representation lineage and exact returned
producer-bound equality. The independent plaintext oracle is schoolbook
negacyclic multiplication.

The profile retains debug assertions and uses seeded unit-test randomness.
It is research correctness evidence, not production-key security admission.
The [current status](../../PUBLIC_REFRESH_STATUS.md) describes the correlated
key-security premise and the separately disabled legacy Clockwork API.

## Accepted native result

At source commit `4fc4328d45b3987003b937b322edb8286d4ca682`, the exact
native single-cycle test passes: one refresh and one following square,
16,384 coefficient comparisons, zero failures or ignored results. Runtime
including key setup is 577.66 seconds, excluding compilation. Sampled
process high-water RSS is 6,799,280 KiB (about 6.48 GiB), within the 8 GiB
environment. Memory sampling and binary/source hashes are specified in the
[accepted manifest](native-memory-evidence/manifest.json).

This is a new native execution on the memory-optimized snapshot, including
canonical-root and immutable-return checks. It is one cycle; the older
five-cycle experiment is preserved separately. Different cycle counts, hosts
and snapshots prevent treating their RSS/time values as an isolated benchmark.
