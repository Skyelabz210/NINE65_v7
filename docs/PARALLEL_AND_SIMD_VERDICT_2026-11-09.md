# Parallel and SIMD verdict (measured 2026-11-09)

Machine: 2 vCPU Xeon @ 2.1 GHz, AVX-512 (F, DQ, IFMA...), no GPU. Debug assertions on
(`allow_insecure` forbids release library builds). Workload: the real per-multiply lane
work (BFV tensor product, 4 forward + 3 inverse NTT per lane, 8 lanes, n = 8192).

## Current integration scope (2026-11-10)

The timings above and below are historical Claude-branch measurements, not a
rerun of the current-main integration. The native research refresh outer basis
also includes nine 59-bit primes; Ntt32 does not support those lanes and is not
a drop-in refresh accelerator. The prototype remains unwired to production NTT
selection. Current integration adds length and CPU checks before safe dispatch;
see the dated recovery/validation report for executed coverage and limits.

## Threads (`ntt_fft::parallel_strategy_probe`, ignored)
| strategy | speedup vs sequential |
|---|---|
| UNHAL -> MANA scoped threads (current) | 2.09x |
| persistent worker pool (hand-built) | 1.98x |
| rayon `par_iter` | 2.08x |

Two cores, 2.09x: the layer is at the hardware ceiling. A persistent pool or rayon buys
nothing at this granularity (about 3 ms of work per call). More cores are the only lever.

## SIMD (`unhal::ntt_simd32`, bit-exact vs the scalar engine, tests in `ntt_fft::simd32_tests`)
Every named secure_128/192/256 work/anchor prime is 28..32 bits (main 28-30, anchor 31-32), so a 32-bit Montgomery
reduction runs 8 butterflies per `vpmuludq` instruction group, data kept in the plain
domain (twiddles stored as `w * 2^32 mod q`; no to/from-Montgomery pass).
- forward n=8192: scalar kernel ~89 us, AVX-512 ~65-80 us (1.2-1.3x).
- per stage: vector stages ~3.2 us (scalar ~6.9 us); the three tail stages (t = 4, 2, 1)
  still run scalar at ~11 us each and are about half the total.
- Headroom, not yet built: in-register permutes for the t = 4, 2, 1 stages, 32-bit packed
  data (halves memory traffic), radix-4 stage fusion. Estimated 2.5-3x on the transform,
  i.e. roughly a quarter off a public multiply. NTT is about a third of the multiply now.
- IFMA (52-bit) is unnecessary: the primes already fit 32 bits.
- The old note "modular arithmetic doesn't benefit from SIMD" (unhal/Cargo.toml) was wrong.

## GPU
No CUDA device here, so not measured. At n = 8192 with 30-bit primes a single multiply is
~40 ms on CPU and ~1 ms of arithmetic on a datacenter GPU, but launch/transfer cost only
pays off when batching many ciphertexts. That is a design decision, not a drop-in swap.

## Not wired
`ntt_simd32` is not yet called by `NTTEngineFFT`; integration needs the tail stages first.
