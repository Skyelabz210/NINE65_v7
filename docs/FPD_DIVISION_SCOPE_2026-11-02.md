# Prepared-Key FPD in NINE65: BFV Rescaling, Shared-Factor Vectors, and Benchmarks

2026-11-02. Implementation note and review guide; no external attestation.

## Result and scope

The activation branch accelerates the existing main-Q BFV multiplication
route by preparing public hybrid relinearization keys once. Two local release
runs measured a 2.10–2.53× improvement for prepared versus raw-key FPD
multiplication. It also enables exact-rational, Clockwork integrity, and
adaptive-monitor APIs in the default feature set.

**This change does not enable general shared-factor encrypted division.**
`CramPublicEvaluator::exact_divide` still rejects a divisor that is not a unit
on every main and anchor lane. There is no gate-removal diff for that API.
The README's former one-sentence division contract was too broad to describe
the distinct working coefficient kernels and the still-missing adapter.

The title “Exact Shared-Factor Division in Residue Space via Prepared-Key
FPD” would conflate these results if interpreted as an encrypted-division
benchmark. Prepared keys accelerate relinearization during multiplication;
they do not supply the missing quotient information for general division.

## Immutable implementation and performance references

- [Prepared-key evaluator change, `b0ca63d`](https://github.com/Skyelabz210/NINE65_v7/commit/b0ca63d11977407ea478d7e6d03a94de0c90a607):
  raw hybrid keys become `PreparedHybridGadgetKey`; multiplication calls
  `try_mul_exact_prepared` instead of `try_mul_exact`.
- [Features, monitoring fixes and harness, `dde5ea2`](https://github.com/Skyelabz210/NINE65_v7/commit/dde5ea20ecff8198d0eb3353ec038243b42b188f):
  this is the exact measured source commit.
- [Initial evidence archive, `98ca2eb`](https://github.com/Skyelabz210/NINE65_v7/commit/98ca2ebae321d7792439b6a6c9d3cfcbfee3d197):
  raw captures retain their original hashes and measured source reference.
- [Feature inventory and timings](FEATURE_ACTIVATION_2026-11-02.md),
  [run 1](../artifacts/execution/2026-11-02/fpd-stack/run-1.json),
  [run 2](../artifacts/execution/2026-11-02/fpd-stack/run-2.json), and
  [host/build/hash provenance](../artifacts/execution/2026-11-02/fpd-stack/provenance.json).

The public branch is
[`feat/enable-fpd-stack`](https://github.com/Skyelabz210/NINE65_v7/tree/feat/enable-fpd-stack).
Branch publication and a README link are not a merge into `main`.

## Four distinct arithmetic contracts

| API | Exact meaning | Shared-factor status |
| --- | --- | --- |
| `CramMainEvaluator::multiply` / `ExactScaleRound` | BFV tensor rescaling: `Y=floor((t*X+floor(Q/2))/Q)` | Working fixed-divisor kernel; `Q` is noninvertible on every main lane, so coherent auxiliary coordinates are used |
| `CramPublicEvaluator::exact_divide(ct,d)` | Multiply each ciphertext component by `d^-1` on every main and anchor lane | Still rejects nonunits; no general quotient/lift adapter was added |
| `CramCiphertext<()>::cram_rescale_by_scalar_fpd` | Exact division of an S8 coefficient witness, with auxiliary residues, divisibility witnesses and a trusted quotient bound | Works for supported divisors such as 6 and 30; the unit payload is not a BFV ciphertext |
| `RationalBridge` (`exact_rational`) | Exact numerator/denominator arithmetic using `NexGenRat` with bounded `i128` coefficients | Residue conversion computes `num * den^-1 mod p` and panics when the denominator is noninvertible |

`exact_rational` is neither encrypted rational arithmetic nor a fixed-point
representation with scale tracking. It exposes clear exact fractions and
parameter/noise helper APIs. Finite `i128` capacity and the conversion's
invertibility requirement still apply. Its `exact_divide` helper operates on
clear integer arguments, not ciphertexts.

The separate experimental `RankResidueDivider` also has shared-factor floor
division tests. It needs an authentic signed interval and a global CRT-rank
calculation; it is not wired into the service's encrypted division API.

## Why auxiliary information is necessary

On a lane `m` with `g=gcd(d,m)>1`, the equation `d*q+r=X mod m` determines at
most `q mod (m/g)`. For example, `3*q=0 mod 6` admits `q=0,2,4`. A feature
flag or a prepared key cannot select the intended lift from that lane alone.

The live BFV scaler instead receives main and auxiliary residues of the same
bounded tensor coefficient, produced before the main tensor can wrap:

```text
Z = t*X + floor(Q/2)
r = Z mod Q, in [0,Q)
Y = (Z-r)/Q
Y mod a = ((Z mod a)-(r mod a))*inverse(Q,a) mod a
```

Here `gcd(Q,a)=1`. A capacity certificate admits the quotient lift before it
is projected back to the main lanes. Exactness refers to this declared rounded
BFV result, not to the assertion that the original `t*X` is divisible by `Q`.
See the [BFV rescale contract](execution/2026-10-03/FPD_BFV_RESCALE_CONTRACT.md)
for coherence, capacity, signed rounding and the summed-component bound.

## Coefficient-level showcase vectors

Run with a real release library and OS randomness:

```bash
cargo run --locked -p nine65 --release --example cram_public_showcase
```

The showcase checks three separate scopes:

1. **Live BFV coefficient kernel.** Main lanes `[17,97]`, auxiliary lanes
   `[193,257]`, `Q=1649`, `t=3`, and `|X|<=Q^2`. The inputs
   `[-1649,-1100,-550,-275,0,275,550,1100,1649]` produce
   `[-3,-2,-1,-1,0,1,1,2,3]`. For every coefficient it verifies the exact
   equation `Z-r=1649*Y` and both output lane residues. The divisor shares
   factors with both main lanes.
2. **S8 witness kernel.** With `d=6`, quotient bound 1000 and coherent
   auxiliary residues, `[612,-3006,4200,0,66,-12,6] / 6` produces
   `[102,-501,700,0,11,-2,1]`. It checks every output coefficient on all eight
   S8 lanes, including lanes 2 and 3. `gcd(6,S8 product)=6`. The base payload
   is `()`; no encrypted-plaintext quotient is claimed.
3. **Encrypted public evaluator.** Addition, multiplication and the existing
   unit division by 97 are checked by client decryption. Division by a main
   lane prime must still return an error. This is the missing-adapter boundary.

The S8 library's existing FPD tests additionally exercise division by 30,
negative divisors, nondivisible inputs, unsupported factor multiplicity,
missing/malformed auxiliary evidence, insufficient capacity and chained
division. A wrapper's generic base callback is not a verified BFV division
adapter; in the witness tests it intentionally does nothing to an encrypted
payload because there is none.

## Measurements and validation

| Profile | Raw-key FPD multiplication median (ms) | Prepared-key median (ms) | Paired speedup |
| --- | ---: | ---: | ---: |
| `secure_128` | 80.254–86.465 | 37.158–41.219 | 2.10–2.16× |
| `secure_192` | 266.388–281.679 | 110.368–126.448 | 2.23–2.41× |
| `secure_256` | 372.988–374.360 | 147.200–148.209 | 2.53× |

These ranges span two per-run medians, five samples per profile after one
warmup. Each raw/prepared pair uses identical keys and ciphertext inputs and
must match all ciphertext limbs. All 36 correctness trials passed. Runs used
an Intel Xeon Platinum 8573C and Rust 1.89.0 on a shared, unpinned host after
task-owned builds/tests finished. Setup time, prepared-key payload size and
service API timings are separate fields in the captures. No general division
operation or refresh was timed.

The activation snapshot passed 1,201 core tests (139 ignored), 54 release
service tests (27 ignored) and 19 optional parallel-monitor tests. The
follow-up executed 17 `exact_transcendentals` FPD tests and 10
`ExactScaleRound` tests; ignored or filtered tests are not counted as passes.
The showcase and focused tests executed source
[`7cf18cd1cfb21073da4a0f7a4171892a698d97ee`](https://github.com/Skyelabz210/NINE65_v7/commit/7cf18cd1cfb21073da4a0f7a4171892a698d97ee).
The [execution record and log hashes](../artifacts/execution/2026-11-02/division-scope/provenance.json)
identify the exact commands; the [showcase log](../artifacts/execution/2026-11-02/division-scope/showcase.log)
records the expected coefficients and the nonunit rejection. Clippy and
formatting checks passed. The showcase uses `SecureRng` so its encrypted
examples execute under the release library's existing RNG requirements.

## Monitor fixes for independent review

Both fixes originally landed in `dde5ea2`; their history has not been rewritten
because the benchmark refers to that commit. The following patches separate
their hunks and each applies independently to parent `b0ca63d`:

- [Sampling fix](reviews/2026-11-02-fpd/monitor-sampling.patch): callers and
  `measure_entropy_from_ciphertext` both gated the sampling counter, causing
  skipped/stuck sampling. Only the measurement method now advances and gates
  the counter. The regression checks one counter increment per ciphertext and
  a fingerprint from a real sampled ciphertext, allowing parallel completion
  order.
- [Optional-parallel compile fix](reviews/2026-11-02-fpd/monitor-parallel-variable.patch):
  two adaptive calls referred to nonexistent `batch_size` when the parameter
  was named `_batch_size`. Correct both uses. The follow-up also applies
  rustfmt to the affected long assignment.

## What This Does Not Claim

- General shared-factor division of encrypted plaintexts is enabled. The
  public API still rejects it; a conforming bound/coherence/encoding adapter
  and encrypted coefficient tests are outstanding.
- A nonunit acquires a modular inverse, or arbitrary encrypted denominators
  can be divided without a specified quotient/remainder domain.
- The 2.10–2.53× result measures general division, refresh, every enabled
  feature, or an end-to-end application speedup.
- Refresh correctness follows from division. The explicit research refresh
  has separate archived native evidence; legacy Clockwork remains disabled.
  This follow-up does not repair that legacy path or rerun the native cycle.
- Constant-time execution, production security of the full evaluation-key
  graph, a probabilistic decryption-failure bound, or external cryptographic
  attestation. Builder-side tests are not independent validation.

Before claiming general encrypted shared-factor division, specify the lift
and quotient semantics, bind authentic auxiliary information and capacity,
implement the public adapter, check decrypted coefficients on positive and
refusal vectors, and obtain independent review. Publishing this note does not
close those obligations.
