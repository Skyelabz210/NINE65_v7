# CRAM-Public Performance Baseline — 2026-08-26

Measured by `crates/nine65/tests/cram_public_timings.rs`. Medians of 3
independent runs (each run itself takes the median of 5 in-process rounds
per op, per the house `op_timings.rs` pattern). Every round decrypts and
asserts exactness, so no timing here comes from a wrong answer. Commit
base: `23b1afd` (the CRAM-public branch at the point T5 was measured; this
file itself lands in the next commit).

Machine: 4 vCPU, `Intel(R) Xeon(R) Processor @ 2.10GHz` (`nproc` / grep
`model name` `/proc/cpuinfo`), shared container.

Reproduce:

```
cargo test -p nine65 --test cram_public_timings --release --features allow_insecure \
  -- --ignored --nocapture
```

## Config tuples (not names — names get redefined; see CLAUDE.md's
## documented house failure mode)

| Config | N | main lanes | primes | t |
|---|---|---|---|---|
| `manufactured_m2b_insecure` | 512 | 4 | `[65537, 738208769, 1409307649, 2617285633]` (t + 3 minted Δ-lanes) | 65537 |
| `secure_128_deep` | 8192 | 4 | main + 4-lane chain per `SecureConfig::secure_128_deep()` (see `crates/nine65/src/params/secure_configs.rs`) | per config |

## Results (median of 3 runs, ms)

| Config | Encrypt | Add | mul_plain | exact_divide | mul (general) | mul_manufactured (M2b) | mul_manufactured_gadget (M3) | Decrypt |
|---|---|---|---|---|---|---|---|---|
| `manufactured_m2b_insecure` | 0.546 | 0.064 | 0.347 | 0.032 | 88.29 | 74.71 | **19.56** | 0.262 |
| `secure_128_deep` | 6.094 | 1.419 | 3.640 | 0.498 | 426.75 | n/a (not a manufactured chain) | n/a | 2.165 |

**M3's RNS-limb gadget relin (19.56ms) is ~3.8x faster than the digit-based
M2b path (74.71ms)** on the manufactured chain — fewer, larger per-lane
terms (4 lanes) beat many small base-`2^16` digits in wall-clock cost, even
though (per `docs/CRAM_PUBLIC_MODE.md`'s M3 finding) it carries more noise
per level and is therefore only depth-2 safe on this chain, not depth-3.
Speed and noise margin are different axes; this baseline records the
former only.

## Determinism

`cram_public_determinism_bit_identical_across_identical_seeds` (same file):
two independent `CramPublicEvaluator` instances, identical seeds throughout
(keygen, encrypt x2, `mul_manufactured`), asserted byte-identical via a
full ciphertext fingerprint (every main + anchor limb, both components) —
PASSED. This is a hard platform requirement (CLAUDE.md: "Deterministic
execution — bit-identical results across all platforms required"), not
just a nice-to-have; a failure here would be a correctness regression, not
a benchmarking concern.

## Regression rule

Flag a **>25% median regression** against this baseline on a future run,
keyed on the CONFIG TUPLE (n, primes, t), never on the config NAME alone —
`secure_128` was silently redefined once already (N=4096→8192, 3→3+5
lanes) and a name-keyed comparison across that redefinition was
meaningless (see CLAUDE.md's own "Performance Baselines" section for the
full story). The house reproduce-window (run-to-run noise on unchanged
code) is ±20%, so the 25% regression threshold is intentionally a bit
looser than that, to avoid false positives from normal variance.

## Raw per-run figures (for anyone re-deriving the medians above)

| Run | Config | Encrypt | Add | mul_plain | exact_divide | mul (general) | mul_manufactured | mul_manufactured_gadget | Decrypt |
|---|---|---|---|---|---|---|---|---|---|
| 1 | manufactured_m2b_insecure | 0.645 | 0.064 | 0.388 | 0.033 | 91.76 | 75.10 | 19.80 | 0.300 |
| 2 | manufactured_m2b_insecure | 0.536 | 0.061 | 0.330 | 0.031 | 87.84 | 74.71 | 19.56 | 0.220 |
| 3 | manufactured_m2b_insecure | 0.546 | 0.064 | 0.347 | 0.032 | 88.29 | 72.92 | 18.88 | 0.262 |
| 1 | secure_128_deep | 6.094 | 1.377 | 3.401 | 0.498 | 426.75 | n/a | n/a | 2.160 |
| 2 | secure_128_deep | 5.988 | 1.419 | 3.642 | 0.453 | 415.93 | n/a | n/a | 2.165 |
| 3 | secure_128_deep | 6.513 | 1.488 | 3.640 | 0.505 | 432.77 | n/a | n/a | 2.346 |

## Seeds

All fixed in `cram_public_timings.rs`: keygen at seed 4242; per-round
encrypt seeds `9000+i` (operand a) / `9500+i` (operand b) for `i` in
`0..rounds`. Determinism check: keygen seed 555001 (both instances),
encrypt seeds 555002/555003 (both instances) — see the same file.
