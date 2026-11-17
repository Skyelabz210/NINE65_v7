# Torus-Fiber Checks: Reproduction, Coprimality Audit, and Benchmark Results

**Review date:** 17 November 2026  
**Input:** `/home/ubuntu/upload/torus_fiber_checks(2).zip`  
**Archive SHA-256:** `125112c0de435fa729d65df27cce5f10476b1f6194030020fca434bd37e9fea0`

## Executive result

The benchmark compares Garner reconstruction with the redundant-residue `alpha` readout. The first composite performance pass tested only constructed semiprimes; the new v2 pass broadens the corpus to squareful composites, cubes, products with three or four distinct factors, one even modulus, and values above `2^63`. The v2 Rust harness, direct arbitrary-modulus fixture, and exact Python probe passed all checks. At 128 lanes, the three-run median was **50.69×** for the `alpha` readout and **6.32×** for full reconstruction, measured as Garner latency divided by `alpha` latency.

**The relevant mathematical condition is coprimality, not primality or squarefreeness.** The supplied inverse helper used Fermat’s `a^(p−2) mod p`; the composite harness instead uses extended Euclid. The v2 pass also fixes overflow-prone `u64` modular additions/subtractions, makes a failed correctness check terminate before timing, and consumes every reconstructed limb in the timed full-output paths. The exact conditions and remaining harness boundaries are in §2 and §3A.

The archived 64× figure is real for its one-run capture, but is not a machine-independent constant. The v2 timings are a standalone CRT/residue microbenchmark, **not** an end-to-end NINE65 FHE benchmark; the supplied source and NINE65 checkout remain unmodified, and this routine has not been traced into a production FHE call path.

## 1. Evidence universe and reproduction setup

The ZIP has 10 files (five `.txt`, four `.py`, one `.rs`), about 31 KB uncompressed. It contains `exact_checks.py`, `carry_questions.py`, `lunations.py`, `strict_int_audit.py`, `kbench.rs`, and captured outputs. The archive was path-checked and extracted to `/home/ubuntu/torus_fiber_checks_review/`; no archive member was executed until its source had been inspected.

The Python checks were rerun in a task-local virtual environment with Python 3.12.3, SymPy 1.14.0, and NetworkX 3.7. The Rust harness was compiled with the README’s command shape (`rustc -O`) using Rust 1.89.0. The measurement host was Linux AArch64, six vCPUs, Neoverse-N1. Runs were sequential and single-process. The NINE65 checkout remained clean.

The three deterministic Python outputs (`exact_checks`, `carry_questions`, and `lunations`) matched their archived output files byte-for-byte. The Python integer-only AST audit reported zero findings on those three files. A separate token scan found no `f32`/`f64`, floating literals, `.sqrt()`, or `.powf()` in the Rust benchmark. These checks are source-level audits, not a proof about external dependencies or a formal verification record.

## 2. Coprimality, not primality

For lane moduli `m_i`, let `M = ∏m_i` and `M_i = M/m_i`. The CRT construction needs each `M_i` to have an inverse modulo `m_i`; the sufficient and exact condition is `gcd(M_i, m_i) = 1`, which follows when the lane moduli are pairwise coprime. The moduli need not be prime.

Given lane residues `x_i`, the benchmark forms `ξ_i = x_i · M_i⁻¹ mod m_i` and the integer sum `S = Σ ξ_i M_i`. The canonical reconstruction is `x = S − αM`, with `α = (S−x)/M` and `0 ≤ α < k` for `k` lanes. The identity can also be expressed as `α = floor(Σ ξ_i/m_i)`. These are CRT/quotient identities over pairwise-coprime moduli.

For a redundant anchor `A`, the code computes `c = (s−S_A)M⁻¹ mod A`, where `S_A = S mod A` and `s = X mod A`. It obtains `K ≡ α+c (mod A)`. This requires `gcd(M,A)=1`; it does **not** require `A` to be prime. If `α` is not known exactly but only constrained to `0…k−1`, the anchor gives up to `k` candidates for `K`, rather than selecting one by itself. An independent witness modulus `q₂` recovers `α` exactly from its residue when `gcd(M,q₂)=1` and `q₂≥k` (the benchmark uses `q₂>k`); `q₂` also need not be prime.

The residue supplied to the `q₂` readout must correspond to the **canonical** CRT representative `x∈[0,M)`. If instead it is the residue of `X=x+KM`, the same expression returns `α−K (mod q₂)`, not `α`. The anchor returns `K mod A`; exact integer recovery of `K` additionally requires a stated range/representative bound. The lane moduli must be pairwise coprime, while `A` and `q₂` each need only be coprime to `M`; `A` and `q₂` do not themselves need to be coprime to one another.

### Composite-modulus correctness trial

I added an isolated exhaustive probe using lane moduli `[8, 9, 25, 49]`, all composite and pairwise coprime, with composite coprime witness moduli `A=17·19=323` and `q₂=23·29=667`. Modular inverses use Python’s general extended-Euclid implementation (`pow(a, -1, m)`). Results:

- All **88,200** canonical inputs reconstructed exactly with Garner and with the `S−αM` formula.
- All **88,200** composite-`q₂` checks recovered the exact `α` in its expected range.
- All **28,488,600** tested `(x,K)` composite-anchor cases satisfied the `K ≡ α+c (mod A)` identity, with the expected four-candidate boundary when `α` is unknown.
- Failures: **0**.

Scope correction: this earlier small probe already used non-squarefree lane moduli (`8=2³`, `9=3²`, `25=5²`, `49=7²`). The semiprime-only restriction applied to the earlier **large Rust performance corpus**, not to every prior composite test. The new probe adds non-squarefree composite anchors/witnesses, an even lane alongside a three-factor lane, and explicit q₂/anchor boundary semantics.

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

## 3A. Arbitrary-composite audit, fixes, and v2 rerun

### Refined framework conditions

For the Garner/CRT lane set, the required input contract is `k≥1`, lane moduli `m_i>1` that are pairwise coprime, and normalized residues `0≤x_i<m_i`. No lane modulus needs to be prime or squarefree, and a lane residue itself may be zero or a non-unit. For each separate redundant modulus `A` or witness `q₂`, the reconstruction only needs `gcd(M,A)=1` or `gcd(M,q₂)=1`; the two redundant moduli may share factors with each other. Recovering all possible `α∈[0,k)` from `α mod q₂` requires `q₂≥k`. These conditions are mathematical, not a statement that arbitrary non-coprime lane sets work with this Garner inverse-table algorithm.

The earlier `q₂` tests formed their check residue by evaluating Garner digits. The v2 Rust preflight instead assembles the full canonical limb result and independently reduces that integer for `q₂`; the Python probe uses Python’s exact integer representative directly. Both clarify that the witness must be for canonical `x`. If the real system supplies `X=x+KM`, the raw readout is `α−K mod q₂` and must be corrected. The anchor supplies `K mod A`, not an unbounded exact integer `K`.

### Gaps found and corrected

1. **The earlier Rust performance family was narrow.** It benchmarked 130 roughly 62-bit semiprimes. The separate small Python exhaustive probe already covered non-squarefree lane powers; the gap was the large performance corpus and the shapes of its redundant moduli. V2 now includes squares, cubes, products of three/four distinct factors, squareful products, one even composite, and composite check moduli.
2. **The old `u64` modular expressions could overflow.** Terms such as `v[j]+p[j]`, `acc+term`, and `acc+mr−xr` are not safe for every valid `u64` modulus. The benchmark happened to use values below `2^63`, so that limitation was previously untested. V2 replaces them with normalized, overflow-safe `addmod`/`submod` helpers; `mulmod` uses a `u128` product. The new run includes moduli greater than `2^63` and smoke checks at `u64::MAX`.
3. **A failed cross-check was only printed.** V1 could print `FAIL` yet exit successfully and continue timing. V2 asserts the preflight before emitting each timing row, so a correctness failure terminates the process.
4. **The timed full-reconstruction output was under-consumed.** The prior timer XORed only the low limb. V2 hashes every output limb at a fixed width in both full paths, ensuring the entire reconstructed result contributes to the observable sink.
5. **Boundary/provenance cases were implicit.** V2 adds `x=0`, a constructed `α=k−1` vector, normalized-lane assertions, exact q₂ boundary tests, a `q₂<k` non-uniqueness demonstration, and the canonical-versus-shifted residue test. The modular inverse now also checks its Bézout result by verifying `a·a⁻¹≡1 mod m`.

The original archive and first-pass `kbench_coprime.rs` remain unchanged. `kbench_arbitrary_composite.rs` is a separate v2 harness generated from the original source by `adapt_arbitrary_composite_bench.py`. Its default deterministic 130-modulus corpus has 127 varied composite products plus three high-end values: `2·3,037,000,493²` (an even squareful lane above `2^63`) and two distinct odd prime squares above `2^63`. All 130 default values are composites and pairwise coprime; the high odd squares occupy the `mr`/`q₂` slots at `k=128`. The other products exercise semiprime, prime-square, prime-cube, three-factor, four-factor, and `p²q²` patterns. Miller–Rabin is used only to construct that default fixture; the CRT/inverse algorithms do not require primality of their moduli.

V2 also accepts a caller-supplied whitespace- or comma-separated modulus file. For each tested `k`, it validates pairwise coprimality among the first `k` lane moduli and checks each lane against the two following moduli. It does **not** require the anchor and witness to be coprime to each other. The six-value fixture `9 25 49 121 8 4` passed for `k=2` and `k=4`; at `k=4`, the lane moduli are odd and pairwise coprime, `A=8`, `q₂=4=k`, and `gcd(A,q₂)=4`. This is a direct Rust test of arbitrary composite inputs without calling the prime-factor fixture generator. The finite default corpus and this fixture are evidence over tested inputs, not an exhaustive traversal of every `u64` tuple.

The Python `arbitrary_composite_probe.py` passed all of its exact-integer checks:

- **1,801,800** canonical reconstructions/witness checks with lanes `[8,9,25,1001]`, a square anchor `A=289`, and square witness `q₂=361`; all four alpha values occurred.
- **217,800** exhaustive `(x,K)` anchor pairs with `A=121`, including every `K mod A` for every canonical `x` in the test ring.
- **516** q₂-boundary vectors for `k=q₂=4` and `q₂=169>k`, with all `α=0…3`; `A=8` and `q₂=4` share a factor, while each is coprime to `M`.
- Confirmed `q₂<k` is not enough in general: for `k=5,q₂=4`, distinct values `α=0` and `α=4` both read as zero.
- Confirmed the shifted input `X=x+KM` gives `α−K mod q₂`, while the canonical `x` residue gives `α`; rejected all three deliberately invalid inverse requests.
- Passed small exact checks with a `>2^63` even composite lane and with `>2^63` composite witness/anchor values.
- The direct Rust modulus-file fixture `9 25 49 121 8 4` passed both supported sizes (`k=2,4`), including the `q₂=k` boundary and shared factors between `A` and `q₂` at `k=4`.

The optimized Rust v2 harness was compiled with Rust 1.89.0 (`rustc +1.89.0 -O`) and run three times sequentially on the same six-vCPU ARM Neoverse-N1 host. Every tested `k∈{2,4,8,16,32,64,128}` passed before timing. The table gives medians of the three per-run latency values; the ratio is Garner latency divided by `alpha` latency, so values below 1 mean Garner was faster for that row.

| Lanes `k` | Garner alpha/readout (ns) | Alpha readout (ns) | Garner/alpha | Garner full (ns) | Alpha full (ns) | Garner/alpha |
|---:|---:|---:|---:|---:|---:|---:|
| 2 | 46 | 151 | 0.30× | 134 | 268 | 0.50× |
| 4 | 214 | 250 | 0.86× | 319 | 415 | 0.77× |
| 8 | 1,016 | 438 | 2.32× | 1,226 | 780 | 1.57× |
| 16 | 4,424 | 815 | 5.43× | 4,951 | 1,841 | 2.69× |
| 32 | 18,594 | 1,569 | 11.85× | 20,208 | 4,832 | 4.18× |
| 64 | 76,263 | 3,065 | 24.88× | 82,000 | 14,973 | 5.48× |
| 128 | 309,473 | 6,105 | 50.69× | 330,223 | 52,257 | 6.32× |

The v2 median suggests this implementation’s crossover lies between 4 and 8 lanes on this host/workload, and the advantage grows with lane count. Do not treat these as directly interchangeable with the earlier 38.42×/6.24× composite results: v2 changes the modulus distribution, overflow handling, and full-output consumption. Setup tables and inverses remain excluded, `x_r` is supplied to the alpha path as a precomputed canonical-lift residue, and the benchmark still does not count the cost of obtaining that residue. The timing is a steady-state microbenchmark, not an end-to-end application result.

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

The accompanying ZIP bundle includes the original ZIP, its extracted source/output files, this report, host/toolchain metadata, rerun logs, and the first-pass and v2 composite probes/adapters/harnesses. It excludes compiled binaries and the virtual environment.

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
python reproduction/adapt_arbitrary_composite_bench.py
rustc +1.89.0 -O reproduction/kbench_arbitrary_composite.rs -o /tmp/kbench-arbitrary
/tmp/kbench-arbitrary
printf '9 25 49 121 8 4\n' > /tmp/arbitrary-shared-checks.txt
/tmp/kbench-arbitrary /tmp/arbitrary-shared-checks.txt
python reproduction/arbitrary_composite_probe.py
```

`reproduction/host_metadata.txt` records the first-pass provenance; `reproduction/arbitrary_composite_metadata.txt` records the v2 run. `kbench_default_run_1.txt` through `_3.txt` are the supplied prime-lane reruns; `kbench_coprime_run_1.txt` through `_3.txt` are the first composite reruns; `kbench_arbitrary_composite_run_1.txt` through `_3.txt` are the final v2 varied-composite runs. `arbitrary_shared_checks_output.txt` records the direct caller-supplied composite run; the two probe output files record exact Python trials. The original source and output captures remain unchanged under `torus_fiber_checks/`.

## 6. Practical next step for NINE65

If the goal is to adopt this inside NINE65, the next bounded engineering step is to trace one active production reconstruction call from its public caller through its modulus setup and fallback, then benchmark that exact call with identical lane count, limb width, allocation policy, and precomputation accounting. Until that route is traced and tested in NINE65, this result should be described as a promising standalone CRT/reconstruction microbenchmark—not as an active NINE65 FHE speedup.
