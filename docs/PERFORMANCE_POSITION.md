# NINE65 Performance Position — Honest Assessment

**Date:** 2026-08-09
**Scope:** additive-only review of measurement artifacts already produced under
`benchmarks/records/` (canonical, in-repo) and a supplementary probe under the
scratch directory `scratchpad/n65/records/` (outside the repo). No code was
changed to produce this document. No new numbers were invented.

**Evidence labels used below**, matching the spirit of
`docs/CLAIM_EVIDENCE_LEDGER.md`: **MEASURED** (an experiment ran on this
machine and produced integer-nanosecond samples), **PROJECTED** (arithmetic on
a measured number, not itself an observation), **OPEN** (the artifact needed
to settle the claim does not exist yet).

## Verdict, in one paragraph

Five NINE65 operations are measured on this machine to `fhe-comparison-record-v1`
standard and are internally self-consistent enough to state precisely, with one
serious exception noted below. The constant-time framing is architecturally
real (the `_ct` code is bit-serial and data-independent by construction) but
is currently an **assertion about the code**, not a **demonstrated property**
— no timing-variance experiment has been run to show it. CRT slot batching is
mathematically available on every named production parameter set (proved
below, not just cited) but is **unimplemented**, so the headline 8192x/16384x/
32768x amortization number is a projection off a scalar measurement, not an
observation. The comparison against TFHE is not just under-supported, it is
one the project's own contract text names explicitly as a comparison to
refuse — and no TFHE (or SEAL, or OpenFHE) number exists anywhere in this
repository to compare against regardless. **"Competitors cannot match these
speeds" is not establishable from the artifacts that exist today** — there is
no competitor artifact in this repository, in any schema, at any commit. That
is not a rhetorical hedge; it is the literal state of `benchmarks/comparative/`
and `crates/nine65/benches/nine65_vs_seal_comparison.rs` (see §4).

---

## 1. What is PROVEN by measurement on this machine

Five `fhe-comparison-record-v1` records exist under `benchmarks/records/` for
`secure_128` (N=8192, t=65537, primes `[998244353, 985661441, 754974721]`,
log_q_bits=90, single thread, `release-fat-lto-cgu1`, pinned to core 0):

| Operation | n samples | min ns | median (exact) | p95 (nearest-rank) | max ns | correctness |
|---|---:|---:|---:|---:|---:|---|
| `keygen`   | 40  | 9,275,136   | 18,715,545/2 (9,357,772.5) | 9,752,376   | 10,492,441  | 5/5 |
| `encrypt`  | 40  | 18,999,921  | 19,357,998/1               | 20,397,690  | 22,390,196  | 9/9 |
| `decrypt`  | 40  | 8,360,386   | 17,015,479/2 (8,507,739.5) | 9,336,475   | 10,619,836  | 9/9 |
| `add_ct`   | 100 | 759,830     | 1,613,259/2 (806,629.5)    | 870,003     | 1,017,256   | 6/6 |
| `mul_ct`   | 20  | 212,028,726 | 214,853,118/1              | 219,752,516 | 221,174,315 | 7/7 |

Source: `benchmarks/records/nine65_{keygen,encrypt,decrypt,add_ct,mul_ct}_secure128.json`,
measured by `crates/nine65/examples/comparison_record_probe.rs`, hardware
document `benchmarks/records/hardware.json`
(`hardware_fingerprint = 09fd291610c1ec6ef6d42ba79896772de5fa10e1a4f933384417676527ba3f2d`),
commit `28e7ce2fb5ccf7c8823170603821e08bd8093cce` (working tree dirty from
concurrent, unrelated workflows at measurement time; snapshotted
non-destructively via `git stash create` to `227bd869b53fccd5da8a915627ae41407dd07d81`
so the exact measured source is resolvable — see each record's
`integrity_notes`). 0 correctness failures across all five operations. This
is real, reproducible-in-principle, and honestly labeled.

### 1.1 A discrepancy that must be disclosed, not smoothed over

A second, independent `mul_ct` measurement exists at
`scratchpad/n65/records/nine65_mul_ct_scalar_secure128.json` — **outside this
repository**, produced by a different probe
(`crates/nine65/examples/slot_batching_probe.rs`) calling the identical API
(`RNSFHEContext::mul_dual_symmetric`) on the identical parameter set:

| Field | `benchmarks/records/nine65_mul_ct_secure128.json` | `scratchpad/n65/records/nine65_mul_ct_scalar_secure128.json` |
|---|---|---|
| median_ns | 214,853,118 | 101,863,099 |
| p95_ns | 219,752,516 | 103,561,100 |
| n samples | 20 | 15 |
| hardware CPU string | `Intel(R) Xeon(R) Processor @ 2.80GHz` | `Intel(R) Xeon(R) Processor @ 2.10GHz` |
| `hardware_fingerprint` | `09fd2916...df` | `02329bdb...df` |
| `security_estimator` | named, with numeric output | `"UNAVAILABLE-no-estimator-run-in-this-probe"` |

These two numbers differ by a factor of **~2.11x** for what is claimed to be
the same operation on the same parameters. Two things are worth separating:

- The direction rules out the easy explanation. If this were simply "CPU
  clock speed varies across container placements," the *slower*-clocked
  2.10GHz run should show the *higher* latency. It shows the **lower**
  latency instead (101.9 ms vs 214.9 ms) — backwards from what raw clock
  frequency alone would predict. So the gap is not fully explained by the
  one hardware difference that was captured. Plausible remaining causes,
  none confirmed: scheduling/steal-time noise not visible to `/proc/loadavg`
  on this shared-tenancy container, or the two probes sampling `rns_fhe.rs`
  at different points while other, unrelated workflows were actively editing
  that exact file (git status at measurement time showed it dirty — see the
  concurrency notice this file's own author was given). Both are plausible;
  neither is verified. That is an open item, not a resolved one.
- **Applying the project's own comparability rule to the project's own two
  self-measurements**: `compatibility.hardware_fingerprint` differs
  (`09fd2916...` vs `02329bdb...`) and `compatibility.security_estimator`
  differs (named-with-output vs `UNAVAILABLE`). By the exact rule stated in
  `benchmarks/comparative/README.md` — "two records are ranked only when
  every field in `compatibility` and the `operation` field are identical" —
  **these two NINE65 records are `INCOMPARABLE` to each other**, not merely
  to a competitor. This is the contract working as designed, including
  against its own author. It also means: **neither 101.9 ms nor 214.9 ms
  should be quoted alone as "the" NINE65 `mul_ct` time** until this is
  root-caused. The canonical, in-repo, fully-fingerprinted figure is 214.9 ms
  (`benchmarks/records/nine65_mul_ct_secure128.json`); the 101.9 ms figure is
  real data but sits outside the repository and carries an incomplete
  `compatibility` block. Any external-facing performance claim should use the
  canonical record and note the open discrepancy, not silently pick whichever
  number is more favorable.

For calibration: the task brief's own quoted "measured baseline" for
`mul_dual_symmetric` was ≈105 ms, `add_dual` ≈0.82 ms. The canonical in-repo
`add_ct` figure (806,629.5 ns ≈ 0.81 ms) agrees with that baseline to within
~2%. `mul_ct`, `encrypt`, `decrypt`, and `keygen` do not — they run at
roughly 1.8-2.1x the brief's figures on this run. `add_ct`'s cost is
dominated by RNS-lane addition, not NTT throughput, which is a mechanistically
plausible reason it would be the one operation that is stable across whatever
is causing the other four to move — but that is a hypothesis, not a
verified explanation. It should be checked, not assumed.

### 1.2 What these five records can be compared against today

Per the harness's own comparability rule, they can be safely ranked only
against another `fhe-comparison-record-v1` record that matches every
`compatibility` field: `scheme=BFV-DualRNS`, `plaintext_semantics=scalar-mod-t`,
`target_security_bits=128`, `n=8192`, `log_q_bits=90`, `plaintext_modulus=65537`,
`slots=1`, `refresh_kind=none`, the same `hardware_fingerprint`, `threads=1`,
`build_profile=release-fat-lto-cgu1`, and the same `operation`. In practice
that is: a rerun of the identical probe on the identical container. No such
external record exists yet (see §4). **The five records are proof that NINE65
does what it claims on this parameter set, on this machine, today — they are
not yet proof of standing relative to anything else.**

---

## 2. The constant-time advantage — real construction, unmeasured demonstration

The claim: NINE65's arithmetic layer (`barrett_ct`, `k_elimination_ct`,
`mul_mod_u128_ct`, `ntt_ct`, `sub_mod_u128_ct`) is constant-time by
construction — `mul_mod_u128_ct` is a described ~128-round bit-serial loop at
~3 ns/round, which is why it costs ~385 ns rather than the handful of
nanoseconds a variable-time Barrett/Shoup multiply would take. SEAL and
OpenFHE, in their default configurations, are optimized for throughput and do
not carry that guarantee in their base modular-arithmetic layer.

**Why a slower wall-clock number is not automatically a loss:** if the
comparison is "nanoseconds per multiply," NINE65 loses to a variable-time
implementation on raw throughput almost by definition — data-independent
execution forecloses exactly the input-dependent fast paths (early-exit
comparisons, branchy reduction, table lookups keyed by operand value) that
make variable-time code fast. Comparing that number to a variable-time
library's number as if they were the same product conflates two different
security postures with one performance axis. A fair framing is: NINE65 is
trading a specific, describable amount of throughput for resistance to a
specific, describable class of timing side-channel — that is a different
product, not a slower version of the same product.

**That framing is currently an assertion, not a demonstration, and the
distinction matters for hostile scrutiny.** Nothing in this repository's
benchmark suite currently measures operand-dependent timing variance. The
`_ct` naming convention documents *intent*; it does not, by itself, constitute
evidence that the intent was achieved end-to-end (a single non-constant-time
comparison, branch, or table lookup anywhere in the call graph — including in
code paths this task was not permitted to touch, such as `sbni.rs` or
`rns_fhe.rs` — would break the property while leaving the name and the
docstring unchanged). Nor does this document assert anything specific about
SEAL's or OpenFHE's current source; "mainstream FHE libraries commonly
optimize their base modular arithmetic for throughput rather than
side-channel resistance" is a widely stated premise in the literature, not a
fact this task verified against either library's current codebase. Any public
claim of the form "NINE65 is constant-time where SEAL/OpenFHE are not" should
cite a specific commit and code location in the competitor, not a reputation.

**What would demonstrate it, concretely, without touching the arithmetic:**

1. Define operand classes expected to stress any timing leak differently:
   all-zero limbs, all-`(p-1)` limbs, uniform-random limbs, and a small set of
   structurally adversarial patterns (e.g., operands that would trigger
   worst-case branching in a textbook variable-time Barrett reduction —
   values just below a modulus boundary).
2. For each of `barrett_ct`, `mul_mod_u128_ct`, `ntt_ct`, run enough warm,
   pinned-core, single-thread samples per class to get a stable distribution
   (the existing benchmark harness already produces integer-nanosecond
   samples; no new instrumentation is required, only new operand fixtures).
3. Compare the *distributions* across classes, not just their means — using
   the contract's own preference for integer statistics (e.g., report
   nearest-rank percentiles per class and the spread between classes as an
   integer nanosecond figure, not a t-test p-value). A genuinely
   constant-time implementation should show class-to-class spread on the
   order of measurement noise; a class-dependent shift well outside that
   noise floor would falsify the constant-time claim for that function.
4. Publish that as its own artifact (it is not an `fhe-comparison-record-v1`
   record — it is a new record shape, e.g. `timing-invariance-record-v1`),
   separately from the throughput records, so it can be checked on its own
   terms.
5. Only after that experiment exists does "NINE65 pays X ns for a guarantee
   SEAL/OpenFHE don't give you" become a demonstrated trade rather than a
   named one. This is squarely in the "additive only" lane — new benchmark
   fixtures over existing `_ct` functions, no algorithm changes — and is the
   highest-value next artifact for this specific claim.

---

## 3. Batching — max slots per config, and what is measured vs. projected

**Status: PROJECTED, not measured.** No packed ciphertext has ever been
constructed in this codebase. The number below is arithmetic performed on a
measured scalar latency; it is not an observation of a packed multiply.

### 3.1 The slot count is proved, not merely cited

`t = 65537 = 2^16 + 1` is a Fermat prime; `2N | t - 1 = 65536` for every named
production config, which is exactly the condition under which `X^N + 1`
splits into `N` distinct linear factors mod `t`. This was checked by direct
computation for `secure_128` (N=8192): 3 generates `F_t^*`, and
`psi = 3^((t-1)/2N) mod t = 81` satisfies `psi^16384 = 1` and `psi^8192 = 65536
= -1 (mod t)`, with the 8192 odd powers of `psi` all distinct — i.e.
`Z_t[X]/(X^8192+1) ≅ (F_t)^8192` is a proved isomorphism for this parameter
set, not an inference from the congruence alone. `psi = 81` is the concrete
root of unity an implementation would need.

Max slots per production config, all satisfying `t ≡ 1 (mod 2N)`:

| Config | N | 2N | max slots |
|---|---:|---:|---:|
| `secure_128` / `secure_128_deep` / `hardware_opt` | 8,192 | 16,384 | 8,192 |
| `secure_192` / `secure_256` | 16,384 | 32,768 | 16,384 |
| `ProductionConfig128::high_security` | 32,768 | 65,536 | 32,768 (max possible for t=65537) |

Two named configs are **false positives** for the naive `(t-1) % 2N == 0`
check and are called out explicitly so nobody reaches for them expecting
batching: `large_single_insecure` (t is composite, `257 × 4278255361`, and
neither factor is `≡ 1 (mod 2N)`, so the ring does not split at all — max
slots = 1) and, notably, the config actually **named** `batched_insecure`
(t=257, N=4096; the multiplicative order of 257 mod 8192 is 32, giving at
most 128 slots over a degree-32 extension field, not 4096 linear slots). Both
are reported only; neither was changed, per scope.

### 3.2 The projection

`214,853,118 ns / 8,192 slots ≈ 26,229 ns/slot`, using the canonical in-repo
`mul_ct` median (§1). Using the second, incompletely-fingerprinted measurement
instead gives `101,863,099 / 8,192 ≈ 12,434 ns/slot`. **Both are shown
deliberately, not just the smaller one** — the batching projection inherits
whatever uncertainty exists in the base scalar measurement (§1.1), and until
that ~2.1x discrepancy is resolved, the honest range for the amortized figure
is "roughly 12-26 microseconds per slot, projected," not a single number.

The structural argument for why the projection is plausible in the first
place (not just optimistic) is stronger than a congruence check alone:

- The ciphertext operands `c0`/`c1` that `mul_dual_symmetric` actually
  multiplies are already fully dense — 8,192/8,192 nonzero coefficients in
  every RNS limb — **even when the plaintext is the single scalar 5**, because
  `c1` is uniform-random and `c0 = -(a·s+e) + Delta·m`. Packing the plaintext
  changes *values* inside already-dense polynomials, not the *shape* of the
  computation: no NTT length, no loop bound, and no `k_elim_rescale_dual` `for
  i in 0..self.n` iteration count depends on how many plaintext slots are
  occupied.
- `should_two_stage_rescale` returns `false` unconditionally, so the one
  lane-dropping step (`mod_switch_down_dual`) never runs inside multiply; the
  basis is invariant across the operation regardless of slot occupancy.
- The three K-Elimination rescales that dominate the measured `mul_ct` cost
  are already `for i in 0..self.n` — full-width today, independent of how
  many of those `N` coefficients are meaningful.
- The arithmetic layer is constant-time by construction (§2), which is an
  independent, structural reason latency should not vary with plaintext
  content even before considering the loop-shape argument above.

None of that is a substitute for an actual packed measurement. It is a reason
to expect the projection to be *directionally* right, not a reason to treat
it as measured.

### 3.3 What is concretely missing (report only — not built here)

1. **No plaintext-side NTT.** No `NTTEngine` is ever constructed over the
   plaintext modulus `t` anywhere in the workspace; every construction site
   uses a ciphertext prime. `find_primitive_root` exists
   (`crates/nine65/src/params/primes.rs:178`) and would work — `psi = 81` for
   `secure_128` is now known — but nothing calls it with `t`.
2. **No vector encrypt.** `encrypt_dual` (`crates/nine65/src/ops/rns_fhe.rs:2094`,
   `:2234`, `:2371`) takes `m: u64`. `to_main_rns_u128` /
   `to_anchor_rns_u128` (`rns_fhe.rs:4092`, `:4106`) already accept a
   `&[u64]` slice and already honor indices `1..N-1` — every current caller
   just passes an all-zero vector. **Trap for a future implementer:** index 0
   receives the Delta-scaled value while indices `1..N-1` are only reduced
   mod `p`, not scaled — a vector encoder must pre-scale every coefficient by
   Delta before calling, or slots `1..N-1` decode to zero.
3. **No vector decrypt.** `decrypt_dual_with_diagnostics` and
   `decrypt_dual_u256` both read `inner.main.iter().map(|limb| limb[0])` —
   coefficient 0 only. The noise-margin diagnostic is computed for
   coefficient 0 alone; a packed ciphertext would report a healthy margin for
   one slot while the other 8,191 could be silently corrupt.
4. **Dense-plaintext noise is untested.** Every correctness trial on record —
   in this document's own measurements included — uses a plaintext with
   exactly one nonzero coefficient. BFV multiplication noise grows with the
   plaintext's l1 norm under negacyclic convolution; a fully packed vector has
   a much larger norm than a scalar. Anchor/K-Elimination *capacity* is
   already budgeted for the dense worst case (`N·Q²`, per
   `crates/nine65/src/arithmetic/rns.rs:1022`), but the **decryption noise
   budget** is a different question and is not covered by any existing
   measurement. This is the real risk in the projection, not the arithmetic.
5. **`BatchEncoder` (`crates/nine65/src/ops/batch.rs`) is a different, disconnected
   thing.** It performs coefficient batching (SIMD add/sub only — a multiply
   scrambles the lanes via negacyclic convolution), runs on a single ~30-bit
   prime with `delta = q/t`, and emits a `RingPolynomial` that feeds only the
   single-modulus (non-RNS) `Ciphertext` path. There is no code path from it
   to `DualRNSCiphertext`, whose `Delta = q_product/t` disagrees with
   `BatchEncoder`'s scaling by roughly 2^60. It cannot be reused as-is.
6. **`supports_simd_slots` (`batch.rs:82`) is unsound for composite `t`** — it
   checks `(t-1) % 2N == 0` only, which is necessary but not sufficient
   unless `t` is prime (see `large_single_insecure`, §3.1). Harmless today
   because nothing calls it outside its own test, but it is the natural gate
   for a future implementation and needs a per-prime-factor order check.
7. **Rotations exist but are unwired.** `crates/nine65/src/ops/galois.rs` is a
   complete Galois automorphism / key-switching implementation with zero call
   sites outside its own tests, typed against the single-modulus `Ciphertext`.
   Elementwise packed add/mul does not need it; any cross-slot operation
   (sums, dot products) does.
8. **The comparison harness hardcodes scalar semantics.**
   `scripts/normalize_nine65_bench.py` defaults `--slots` to 1;
   `scripts/cram_compare_results.py` hardcodes `"plaintext_semantics":
   "scalar-mod-t"` and `"slots": 1`. A packed record is a new record class
   under the harness's own rule — it cannot be reported as a faster number in
   the existing series without harness changes.

**Bottom line on batching:** the parameters permit it, the ring algebra
(mul, add, K-Elimination rescale, relinearize) already does full-`N` work
regardless of occupancy, and the amortized-cost argument is structurally
sound — but zero lines of slot-batching code exist, zero packed ciphertexts
have been built, and the noise budget for a dense plaintext has never been
checked. "12-26 microseconds per slot" is a projection with a named
uncertainty range, not a capability NINE65 has today.

---

## 4. The TFHE comparison — currently not available, and the project's own contract says why

The project's comparison contract (`benchmarks/comparative/README.md`)
explicitly lists **"BFV ciphertext multiplication versus TFHE programmable
bootstrapping"** as one of the comparisons it exists to block, alongside
"scalar messages versus packed SIMD throughput" and "N=1024 testing
parameters versus N=4096 production parameters." A "runs neck-and-neck with
TFHE" claim, stated against the measurements in this repository, runs
directly into that rule: NINE65's records are `operation=mul_ct`,
`scheme=BFV-DualRNS`, `refresh_kind=none` — no bootstrap or PBS ever executes
in any of the five records in §1. There is no operation in this repository's
records that is the same *kind of work* as a TFHE programmable bootstrap.

More fundamentally, **there is no TFHE number in this repository at all**, in
any schema, comparable or not:

- `benchmarks/comparative/README.md` itself states the adapter model: "An
  implementation is recorded as `unavailable` until a pinned command is
  supplied. Missing data is never estimated." No TFHE-rs (or SEAL, or
  OpenFHE, or Lattigo) adapter output exists anywhere under `benchmarks/`.
- The one file whose name promises a competitor comparison,
  `crates/nine65/benches/nine65_vs_seal_comparison.rs`, does not call SEAL.
  It benchmarks NINE65's own Montgomery arithmetic and DualRNS FHE
  operations, and its own comment block says what it actually is: *"These
  benchmarks measure core FHE operations that would be compared to SEAL...
  2. Run SEAL with equivalent parameters (see `SEAL_COMPARISON.md`)"* — a
  file that does not exist anywhere in this repository. The benchmark's name
  describes an intended future comparison, not a performed one.

So "neck-and-neck with TFHE" is not merely unsupported by the wrong kind of
record — the raw ingredient (an actual TFHE PBS measurement, on any hardware,
under any methodology) is absent from the codebase. This is not a subtle
gap; it is the literal, checkable state of the two places such a number would
live.

### What would make a defensible cross-scheme statement

BFV ciphertext multiplication and TFHE programmable bootstrapping are not
substitutable operations — a PBS refreshes noise and evaluates a lookup table
in one step; a BFV `mul_ct` does neither. A defensible cross-scheme claim
needs to normalize on something both schemes actually deliver, not on
operation names that happen to be the "flagship" number for each library.
Concretely, it would require:

1. **Matched work-per-operation.** Define the comparison in terms of a
   deliverable (e.g., "cost to homomorphically evaluate one bounded
   comparison and produce a ciphertext with a specified refreshed noise
   budget") and measure the full circuit each scheme needs to deliver it —
   for TFHE that likely includes one or more PBS calls; for BFV it likely
   includes `mul_ct` plus relinearization plus, if the circuit is deep enough
   to need it, an explicit refresh — not a bare `mul_ct` on one side against
   a bare `PBS` on the other.
2. **Matched security target**, established the same way on both sides. This
   repository's `target_security_bits=128` is currently backed by an in-tree
   `LatticeSecurityEstimator` (CoreSVP + MATZOV), explicitly logged in the
   records as "a deterministic internal screening gate, not an independent
   third-party lattice-estimator certificate." A cross-library claim needs
   both sides run through the same named, versioned estimator (e.g. the
   external Albrecht et al. `lattice-estimator`), not each library's own
   internal gate.
3. **Matched, disclosed hardware** — ideally the identical machine for both
   runs, or two runs with published `hardware.json`-equivalent documents and
   fingerprints, given that §1.1 shows this repository's *own* fingerprinting
   already caught a same-task, same-commit hardware discrepancy. Cross-scheme
   claims are more exposed to this failure mode than same-scheme ones, not
   less.
4. **Per-slot / per-useful-output normalization.** TFHE typically processes
   one value per ciphertext but at very fast per-bootstrap latency; BFV with
   slot batching (§3) amortizes a slower operation across many values.
   Comparing raw per-call latency without normalizing to "cost per plaintext
   value processed, at matched security and matched noise-refresh
   obligations" favors whichever scheme's flagship number happens to look
   smaller in isolation, in either direction.
5. **Matched thread count and build profile**, exactly as `compatibility`
   already requires for BFV-vs-BFV comparisons in this repo — there is no
   reason to relax that discipline the moment the comparison crosses scheme
   boundaries; if anything it should tighten, per the contract's own
   emphasis on "differing security estimates" as one of the deliberately
   blocked comparisons.

None of the five are available today. Building them is out of scope for an
additive review — several require running a second library's real
implementation on this hardware, which is new infrastructure, not a
benchmark record.

---

## 5. What is not yet provable, and exactly what would establish it

Restated plainly, per the closing instruction of this review: **"can
competitors match NINE65's speeds" is not establishable from the artifacts
that exist today, in either direction.** It is not that the evidence leans
against the claim — it is that the other side of the comparison does not
exist in this repository at all (§4), and even NINE65's own `mul_ct` number
currently has an internal, unresolved 2.1x discrepancy between two
same-commit measurements (§1.1). A claim built on top of either gap will not
survive someone re-running the numbers.

Concrete, additive next artifacts, in priority order:

1. **Resolve the `mul_ct` discrepancy (§1.1) before quoting any absolute
   NINE65 figure externally.** Re-run `comparison_record_probe` and
   `slot_batching_probe` back-to-back on the same container with `nproc`,
   `/proc/cpuinfo`, and `/proc/loadavg` snapshotted immediately before each
   sample batch, and diff `rns_fhe.rs` against the exact commit/stash used by
   each run to rule out (or confirm) mid-flight edits from concurrent
   workflows as the cause. This is cheap, additive, and directly load-bearing
   for every other number in this document.
2. **A timing-invariance record for the constant-time claim (§2)** — operand
   classes × `{barrett_ct, mul_mod_u128_ct, ntt_ct}`, published as its own
   record shape, showing class-to-class spread at or below noise. This
   converts "constant-time by naming convention" into "constant-time by
   measurement," which is the only version of the claim that survives
   hostile scrutiny.
3. **A dense-plaintext noise trial**, gating the batching amortization claim
   (§3, item 4): encrypt a fully-populated coefficient vector (post-Delta-
   scaling, even without a real CRT encoder — a raw dense polynomial through
   the existing `to_main_rns_u128`/`to_anchor_rns_u128` slice path is enough
   to test the noise question in isolation) and confirm decryption still
   recovers coefficient 0 correctly and within the same margin as the scalar
   case, as a proxy for whether the noise budget survives a full plaintext
   before anyone builds the CRT transform itself.
4. **An actual competitor number, on this hardware, under the existing
   contract schema.** Even a single `fhe-comparison-record-v1` for SEAL or
   TFHE-rs `mul`/`PBS` on a comparable parameter set, run on this same
   container with its own `hardware.json`, would let
   `scripts/cram_compare_results.py` do what it was built to do: mark fields
   comparable or not, automatically, instead of this document doing it by
   hand. Until that exists, every comparative performance claim in this
   project is, by the project's own rule, `INCOMPARABLE` to anything outside
   itself — which is a defensible position to publish (it is what this
   document does), but it is not the same claim as "faster than" or "neck
   and neck with" anything.
5. **The plaintext-side NTT over `t` and vector encrypt/decrypt** (§3.3,
   items 1-3) — the actual missing mathematical and API surface for
   batching. `psi = 81` for `secure_128` is now a known, verified constant;
   implementing against it is future, in-scope, additive work, not part of
   this review.

None of items 2-5 exist yet. Item 1 is the one prerequisite that should
happen before any of the others are trusted.
