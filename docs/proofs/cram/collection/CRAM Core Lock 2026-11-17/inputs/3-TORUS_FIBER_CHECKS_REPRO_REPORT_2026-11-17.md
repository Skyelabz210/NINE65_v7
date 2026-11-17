# Torus-Fiber Checks: Reproduction, Coprimality Audit, and Benchmark Results

**Review date:** 17 November 2026  
**Input:** `/home/ubuntu/upload/torus_fiber_checks(2).zip`  
**Archive SHA-256:** `125112c0de435fa729d65df27cce5f10476b1f6194030020fca434bd37e9fea0`

## Executive result

The attachment’s Rust benchmark names the comparison baseline **Garner** (I interpret “gantber” in the request as Garner). At 128 lanes, its captured output reports **64.11×** for the K/overflow (`alpha`) readout micro-operation and **5.63×** for full reconstruction. I rebuilt and ran the supplied Rust source three times on this sandbox’s ARM Neoverse-N1 host: the 128-lane medians were **39.28×** and **5.81×**, respectively. I then changed only the benchmark’s inverse routine and test moduli so the actual lanes and redundant moduli were composite but pairwise coprime; that run passed its checks and measured **38.42×** for the `alpha` readout and **6.24×** for full reconstruction at 128 lanes.

**The relevant mathematical condition is pairwise coprimality, not primality.** The supplied benchmark’s particular modular-inverse helper uses Fermat’s `a^(p−2) mod p`, which assumes a prime modulus. I replaced that helper with extended Euclid for the composite-modulus run. The CRT/reconstruction identities themselves continued to work, including with composite witness moduli.

The archived 64× figure is therefore a real result in the attached one-run capture, but it is not a machine-independent constant. The 5× full-reconstruction result is reproduced in the same general range. This is a standalone CRT/residue microbenchmark, **not** an end-to-end NINE65 FHE benchmark; I did not modify the NINE65 checkout or integrate the routine into its production call path.

## 1. Evidence universe and reproduction setup

The ZIP has 10 files (five `.txt`, four `.py`, one `.rs`), about 31 KB uncompressed. It contains `exact_checks.py`, `carry_questions.py`, `lunations.py`, `strict_int_audit.py`, `kbench.rs`, and captured outputs. The archive was path-checked and extracted to `/home/ubuntu/torus_fiber_checks_review/`; no archive member was executed until its source had been inspected.

The Python checks were rerun in a task-local virtual environment with Python 3.12.3, SymPy 1.14.0, and NetworkX 3.7. The Rust harness was compiled with the README’s command shape (`rustc -O`) using Rust 1.89.0. The measurement host was Linux AArch64, six vCPUs, Neoverse-N1. Runs were sequential and single-process. The NINE65 checkout remained clean.

The three deterministic Python outputs (`exact_checks`, `carry_questions`, and `lunations`) matched their archived output files byte-for-byte. The Python integer-only AST audit reported zero findings on those three files. A separate token scan found no `f32`/`f64`, floating literals, `.sqrt()`, or `.powf()` in the Rust benchmark. These checks are source-level audits, not a proof about external dependencies or a formal verification record.

## 2. Coprimality, not primality

For lane moduli `m_i`, let `M = ∏m_i` and `M_i = M/m_i`. The CRT construction needs each `M_i` to have an inverse modulo `m_i`; the sufficient and exact condition is `gcd(M_i, m_i) = 1`, which follows when the lane moduli are pairwise coprime. The moduli need not be prime.

Given lane residues `x_i`, the benchmark forms `ξ_i = x_i · M_i⁻¹ mod m_i` and the integer sum `S = Σ ξ_i M_i`. The canonical reconstruction is `x = S − αM`, with `α = (S−x)/M` and `0 ≤ α < k` for `k` lanes. The identity can also be expressed as `α = floor(Σ ξ_i/m_i)`. These are CRT/quotient identities over pairwise-coprime moduli.

For a redundant anchor `A`, the code computes `c = (s−S_A)M⁻¹ mod A`, where `S_A = S mod A` and `s = X mod A`. It obtains `K ≡ α+c (mod A)`. This requires `gcd(M,A)=1`; it does **not** require `A` to be prime. If `α` is not known exactly but only constrained to `0…k−1`, the anchor gives up to `k` candidates for `K`, rather than selecting one by itself. An independent witness modulus `q₂` recovers `α` exactly from its residue when `gcd(M,q₂)=1` and `q₂≥k` (the benchmark uses `q₂>k`); `q₂` also need not be prime.

### Composite-modulus correctness trial

I added an isolated exhaustive probe using lane moduli `[8, 9, 25, 49]`, all composite and pairwise coprime, with composite coprime witness moduli `A=17·19=323` and `q₂=23·29=667`. Modular inverses use Python’s general extended-Euclid implementation (`pow(a, -1, m)`). Results:

- All **88,200** canonical inputs reconstructed exactly with Garner and with the `S−αM` formula.
- All **88,200** composite-`q₂` checks recovered the exact `α` in its expected range.
- All **28,488,600** tested `(x,K)` composite-anchor cases satisfied the `K ≡ α+c (mod A)` identity, with the expected four-candidate boundary when `α` is unknown.
- Failures: **0**.

### Composite-modulus performance trial

I created a separate Rust copy of `kbench.rs`; I did not edit the supplied file. The copied harness builds 130 actual moduli as products of disjoint factors near 2³¹, asserts `gcd(m_i,m_j)=1` for every pair, uses extended Euclid for inverses, and retains the benchmark’s correctness checks against an independent redundant modulus and between full reconstructions. The actual lane/check moduli are composite; the factor-generation routine is only a convenient way to create them. All benchmark sizes (`k=2…128`) reported `PASS` in all three runs.

### Exact source changes in the Rust composite harness

The original file remains unchanged. The separate `reproduction/kbench_coprime.rs` was generated from it by `reproduction/adapt_coprime_bench.py`. The changes are confined to modular inversion, modulus generation/selection, validation, and one descriptive output line:

1. **Replace Fermat inversion with extended Euclid.** Original `kbench.rs` line 8 defines `inv(a,p)` as `powmod(a % p, p - 2, p)`. That is Fermat’s inverse formula and requires a prime modulus (and a nonzero residue). The adapted `inv(a,m)` tracks signed Euclidean coefficients in `i128`, runs the extended-Euclidean recurrence, asserts the final gcd is exactly 1, and returns the normalized Bézout coefficient with `rem_euclid(m)`. Thus the inverse exists exactly when the requested operands are coprime, including for composite `m`. The new `gcd` helper uses Euclid’s algorithm for positive integer gcd checks.
2. **Generate composite moduli, not prime lane moduli.** The old setup selected 132 probable-prime values just below `2^62` and used `primes[..k]`, `primes[k]`, and `primes[k+1]` as the base, redundant, and witness moduli. The adapted setup selects 260 convenient factors below `2^31`, pairs them into 130 products `factors[2*i] * factors[2*i+1]`, and uses that `moduli` vector for all three roles. Each resulting modulus is a composite product and remains about 62 bits wide.
3. **Enforce the actual requirement on the full generated set.** Before benchmarking, nested loops assert `gcd(moduli[i], moduli[j]) == 1` for every distinct pair among all 130 moduli. This covers each chosen base lane and both extra moduli. The harness also keeps `assert!(q2 > k)`, so the witness residue uniquely identifies `α` in its known range `0…k−1`; coprimality with `M` makes `M⁻¹ mod q2` available through the new inverse routine.
4. **Route all setup inverses through the general routine.** Because the existing setup call sites already use `inv`, the replacement applies to Garner’s pairwise inverse table `c[i][j]`, each CRT coefficient inverse `minv[i]`, and the inverses of `M` modulo the redundant moduli (`minv_r` and `minv_q`). Their inputs are units because the pairwise-gcd assertion passed.
5. **Keep the timed arithmetic unchanged.** The Garner digit conversion, `sk_alpha`, full-limb accumulation/subtraction, test-vector checks, pseudo-random source, loop counts, and timers were not rewritten. The modulus/inverse setup remains outside the timed loops, as it was in the original. The measured composite run therefore exercises the same arithmetic routines with composite pairwise-coprime moduli; it does not charge extended-Euclid setup to per-operation latency.

One distinction is intentional: the adapted harness still calls its Miller–Rabin `is_prime` helper to find convenient factors for constructing the composites. It does **not** test or require primality of the actual lane/check moduli; those products are composite, and their pairwise gcds are checked directly. Prime factors are merely a convenient way to make disjoint-factor products whose coprimality is easy to guarantee and verify. The exhaustive Python probe separately uses only composite lane and witness moduli with general modular inverses.

## 3. Benchmark evidence

The archive’s `kbench_output.txt` has one timing capture and no host or Rust-version record. Its 128-lane entries are:

| Operation | Garner | `alpha` method | Ratio |
|---|---:|---:|---:|
| `alpha`/K readout primitive | 87,066 ns | 1,358 ns | 64.11× |
| Full reconstruction | 109,448 ns | 19,451 ns | 5.63× |

Fresh three-run medians from this host:

| Input set | Lanes | Garner primitive (ns) | `alpha` primitive (ns) | Primitive ratio | Garner full (ns) | `alpha` full (ns) | Full ratio |
|---|---:|---:|---:|---:|---:|---:|---:|
| Supplied prime-lane harness | 128 | 293,847 | 7,481 | 39.28× | 317,201 | 54,595 | 5.81× |
| Composite, pairwise-coprime harness | 128 | 320,100 | 8,331 | 38.42× | 343,302 | 55,030 | 6.24× |

The supplied harness’s 128-lane primitive counts are 8,128 modular multiplications in the Garner digit conversion versus 257 in `sk_alpha`; those counts are consistent with the intended quadratic-versus-linear readout work. Full reconstruction also includes wide-limb accumulation/subtraction for the `alpha` path and mixed-radix/Horner assembly for Garner. The setup tables and inverse computation are outside the timed loops; the timing includes each path’s per-call work and allocations. The redundant `x_r` residues consumed by `sk_alpha` are also computed from Garner digits during test-vector setup and reused; their generation cost is excluded from the timed result.

The rerun results support a substantial asymptotic and practical improvement for this operation family. They do not establish an invariant 64× ratio: on the same ARM host and source, the primitive was about 39×. The full reconstruction ratio remained close to sixfold. The archived run may have used a different processor, compiler, or host load; its capture lacks that metadata. Its README itself notes a shared single-core machine and tens-of-percent noise.

This benchmark compares two standalone residue-reconstruction approaches. It does not measure NINE65’s production evaluator, encryption/decryption, ciphertext multiplication, bootstrapping, key generation, parallel lanes, memory pressure at a service boundary, or end-to-end application throughput. The `alpha` method also receives a precomputed redundant-modulus residue that is an extra input lane relative to plain Garner’s `k` base residues. Any integrated comparison should count that extra residue and the cost/availability of preparing it.

## 4. Other archive checks

### Carry and anchor identities (`carry_questions.py`)

The rerun reproduces the saved results:

- 60,060 integer cases for the Hermite floor/boundary-bit identity, the tropical minimizer with its boundary bit, and the quasi-periodicity identity: **0 violations**.
- 20,539 cases for the stated Theorem-5 carry as `floor(r/M+s/M)`: **0 violations**.
- 9,000 CRT samples for `α = floor(Σ ξ_i/m_i)`, the iterated carry sum, and the fractional part `x/M`: **0 violations**.
- 18,000 anchor samples for `K ≡ α+c (mod A)`: **0 violations**; the true `K` was among the candidate set every time.

The fixed-point section samples 20,000 pseudorandom inputs and the first 2,000 positive `x` values for each listed precision. At `t=128`, 3 of those 2,000 small inputs fail; at `t=136`, none of the listed random or small-input trials fail. That table reports sampled evidence, not an exhaustive sweep over a 128-bit domain.

A direct bound explains a sufficient precision. Writing the truncation loss as `E/2ᵗ`, with `0 ≤ E < k`, and using the exact fractional part `x/M`, the floor cannot drop below `α` whenever `x·2ᵗ ≥ kM`. For the included `k=8` example, `M` has 128 bits and `kM` has 131 bits; `t=131` is the least integer satisfying this sufficient inequality. Thus `t=136` is safely above the derived bound but is not established by the sample table as the minimum precision required by the algorithm.

### Exact claims and counterexamples (`exact_checks.py`)

These checks do more than confirm identities; they identify corrections to claims encoded in the test descriptions:

- **Tropical theta:** the unconditional statement `argmin = −K` is false in 20,364 of 48,040 tested cases; 2,160 cases tie. The piecewise boundary form (`−K` below the half boundary, tie at it, `−K−1` above it) matched all 24,040 cases in the separate check. The value formula was true in 27,676/48,040 cases, not all.
- **Ramanujan residue:** for the computed partition values, `p(385m+894) ≡ 0 mod 385` holds for 16/102 entries in the tested range, not all. The tested class `β=369` holds for 103/103 entries; `369` is `24⁻¹ mod 385`.
- **Remainder 23:** for the listed factor set `S₀`, `11960 = 2³·5·13·23`. Across all 170,544 seven-subsets of the 22 primes below 80, the remainder was exactly 23 for 3,060 sets; the selected remainder is not unique in that search. In the interval 10,000–14,000, the exact remainder 23 occurred 30 times.
- **Ollivier–Ricci lane graph:** under the script’s stated convention (`α=0`, uniform neighbor measures), the single-lane curvatures were `1/2` for basis `[3]` and `0` for `[4]`, `[5]`, `[7]`, `[11]`, `[13]`. For `[2,3,5,7,11,13]` with degree 11, the lane curvature map was `{2:0, 3:1/11, 5:0, 7:0, 11:0, 13:0}`.

### Lunation arithmetic (`lunations.py`)

The exact integer/rational calculation for `n=405` gives rounded `D=11960`, factorization `2³·5·13·23`, and `11960/405 = 2392/81`. Neighboring entries 398–411 were also recomputed exactly from the source’s chosen rational `29.530589` days. These computations establish the stated arithmetic for that rounded constant; by themselves, they do not establish a separate astronomical or structural interpretation.

## 5. Reproduction commands and artifact map

The accompanying ZIP bundle includes the original ZIP, its extracted source/output files, this report, host metadata, rerun logs, and the standalone composite-modulus probe and benchmark source. It excludes compiled binaries and the virtual environment.

From the extracted bundle root, the deterministic checks can be rerun with:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install sympy networkx
python torus_fiber_checks/exact_checks.py
python torus_fiber_checks/carry_questions.py
python torus_fiber_checks/lunations.py
python torus_fiber_checks/strict_int_audit.py \
  torus_fiber_checks/exact_checks.py \
  torus_fiber_checks/carry_questions.py \
  torus_fiber_checks/lunations.py
rustc -O torus_fiber_checks/kbench.rs -o /tmp/kbench && /tmp/kbench
python reproduction/adapt_coprime_bench.py
rustc -O reproduction/kbench_coprime.rs -o /tmp/kbench-coprime && /tmp/kbench-coprime
python reproduction/coprime_composite_probe.py
```

`reproduction/host_metadata.txt` records the reproduction host/toolchain. `kbench_default_run_1.txt` through `_3.txt` are the supplied prime-lane reruns. `kbench_coprime_run_1.txt` through `_3.txt` are the composite-lane reruns. `coprime_composite_probe_output.txt` records the exhaustive small-ring trial. The original source and output captures remain unchanged under `torus_fiber_checks/`.

## 6. Practical next step for NINE65

If the goal is to adopt this inside NINE65, the next bounded engineering step is to trace one active production reconstruction call from its public caller through its modulus setup and fallback, then benchmark that exact call with identical lane count, limb width, allocation policy, and precomputation accounting. Until that route is traced and tested in NINE65, this result should be described as a promising standalone CRT/reconstruction microbenchmark—not as an active NINE65 FHE speedup.
