# Ladder Removal: retiring SBNI and the per-multiply auto modulus-switch

**Status:** authoritative record of a completed change.
**Date:** 2026-08-09.
**Scope:** `crates/nine65/src/ops/sbni.rs`, `crates/nine65/src/ops/mod.rs`,
the `mod_switch` and rescale code in `crates/nine65/src/ops/rns_fhe.rs`,
and the new measurement file `crates/nine65/tests/depth_and_noise.rs`.

**Companion documents:** `docs/RETIRED_MECHANISMS.md` (the governing policy —
in particular §5, *a silent delete is equally unacceptable*) and
`crates/nine65/tests/basis_invariance.rs` (the standing proof that division
does not move the basis).

---

## 0. How to read this document

Two author decisions drove this change, both explicit, both authorising deletion:

1. **We do not switch moduli.** Classical BFV `rescale` fuses *divide the value*
   with *drop a lane from the basis*, only because inexact division forces you to
   shrink the representation in order to shrink the value. CRAM divides exactly
   (K-Elimination for `gcd(d,M)=1`, Fused Piggyback Division for `gcd(d,M)>1`),
   which unfuses them: divide the coefficients and **the basis does not move**.
   Nothing is consumed, so nothing runs out.
2. **SBNI can be dropped.** Shadow-butterfly noise injection, inherited from the
   `jules/v8-shadow-butterfly` branch, is removed.

Every claim below carries one of three labels. They are not decoration; the
distinction is the point of the document.

| Label | Meaning |
|---|---|
| **PROVEN** | Reproducible in this working tree by a command printed in this document. |
| **REPORTED** | Measured during the change by a probe that is no longer committed, or by a long run whose only surviving evidence is a log file. Cited with its artifact; **not** re-verified here. |
| **ASSUMED** | A reading of the code that has not been executed as a test. |

And one rule applied throughout, stated up front so nothing later reads as
spin: **where a test now passes because code was deleted, this document says so
in those words.** Five tests did not get fixed. They left the crate.

---

## 1. SBNI — what it was, and what dropping it changed

### 1.1 What it was

SBNI lived in `crates/nine65/src/ops/sbni.rs` (253 lines) and had exactly **one**
production call site in the entire workspace: `mul_dual_public` Step 3.5 in
`ops/rns_fhe.rs`.

`inject_dual_in_place` built a single signed coefficient vector
`epsilon_coeffs[k] ∈ [-20, +20]` (`SBNI_BOUND = 20`) from
`blake3(lane_id ‖ tau ‖ q_bfly[k] ‖ gro_tick(lane_id, tau))`, then added that
**same integer polynomial** into every main lane and every anchor lane of a
`DualRNSPoly`. At the call site it was applied to `c0_pre` only; `c1_pre` was
untouched.

Its module doc claimed it "rerandomizes accumulated deterministic noise drift",
delivered "timing side-channel immunity", and "strengthens IND-CPA security".

### 1.2 Why dropping it is safe — three independent arguments

**(a) Structural. ASSUMED (code reading, but mechanical).**
`inject_dual_in_place` performed only `poly.main[i][k] += e mod q` and
`poly.anchor[i][k] += e mod a`. It added no lane, dropped no lane, reordered
nothing, rescaled nothing. It was not a representation transform. Because the
identical integer epsilon was reduced per-lane, the main/anchor pair remained a
consistent representation of one integer polynomial — that is SBNI *declining to
corrupt* an invariant it did not create, not SBNI providing something. No code
anywhere read a value it produced. `generate_injection_poly` and `SBNI_BOUND`
had zero non-test references.

**(b) Numerical. ASSUMED (arithmetic, not executed).**
Step 3.5 ran immediately *before* Step 4's rescale. `k_elim_rescale_dual`
computes `round(v_exact / Δ)` with `Δ = M_level / t`, which is 100+ bits on
`secure_128`. With `|ε| ≤ 20`, `round((v+ε)/Δ)` differs from `round(v/Δ)` only
when `v mod Δ` lands within `ε` of a rounding boundary — probability on the
order of `40 / 2^100`. **SBNI was already, with overwhelming probability, a
no-op on the emitted ciphertext.** Removing it is not merely safe; it is
observationally identical.

**(c) Cryptographic. ASSUMED (code reading).**
The "zero-marginal-cost butterfly entropy" was harvested by running an NTT over
a hardcoded constant — `let dummy_poly = vec![123u64; self.n]` — through fixed
twiddles on `ntt_engines[0]`. That produces the **identical** `q_bfly` shadow
vector on every call, forever. The only varying hash input was `tau`, a plain
monotonic `AtomicU64` starting at 0. No secret key, no RNG, no
ciphertext-dependent material entered the hash, and blake3 was unkeyed.
Therefore epsilon was a deterministic, publicly recomputable function of the
operation index. It masked nothing.

> This last point stands **independently of the removal**. The security claims
> made for SBNI in `README.md`, `docs/ENTROPY_MODEL.md` and
> `docs/SIDE_CHANNEL_THREAT_MODEL.md` were not delivered by the implementation
> that was there. See §6.5 — that documentation debt is **open**.

### 1.3 What dropping it changed

- **On the ciphertext:** nothing observable (argument (b)).
- **On cost:** each `mul_dual_public` no longer performs a full N-point NTT over
  a dummy constant plus a shadow allocation, per multiply, for a value that was
  then rounded away.
- **On the crash:** everything. See §2.
- **On the test suite:** five passing tests left the crate. See §3.2.

### 1.4 The edits

| File | Change |
|---|---|
| `ops/rns_fhe.rs` Step 3.5 | Whole block deleted: `shadows` allocation, the dummy-NTT harvest (both `cfg` arms), the `tau` `fetch_add`, and the `inject_dual_in_place` call. `c0_pre` is no longer `mut`. Replaced by a retirement comment. |
| `ops/rns_fhe.rs` `RNSFHEContext` | `pub sbni_counter: AtomicU64` field removed, and its initializer in `try_new`. |
| `ops/mod.rs` | `pub mod sbni;` replaced by a retirement comment. |
| `ops/sbni.rs` | **Kept on disk**, out of the module tree, header replaced by a `RETIRED MECHANISM` block recording the three arguments above and naming the five tests that went with it. Body untouched. |

`crates/nine65/Cargo.toml:98` still declares `blake3 = "1"`, which is now an
unused dependency — `sbni.rs` was its only consumer. That file is owned by a
concurrent workflow and was deliberately not edited. **Open item, §6.6.**

---

## 2. The auto modulus-switch, and the crash it caused

### 2.1 What it was doing

Three multiply paths ended with the same fused step:

```rust
if level >= 3 { self.mod_switch_ct_down(&ct_result).unwrap_or(ct_result) }
```

at `mul_dual_symmetric`, `mul_dual_symmetric_with_s2`, and `mul_dual_public`
Step 5. The comment above the first one read *"Auto modulus-switch when enough
levels remain (mirrors mul_dual_public)"*.

`mod_switch_ct_down` reconstructs each coefficient, computes
`round(v_centered / q_last)` with an explicit rounding bump, re-encodes into
`num_poly_primes - 1` main lanes, and sets `level: ct.level.saturating_sub(1)`.
That is the classical fused operation in full: an inexact division that pays for
its rounding term with a lane. Every multiply spent a level; depth was bounded
by the prime count; when the chain ran out you had to bootstrap. That is exactly
the ladder author decision (1) says does not exist here.

**A second, quieter ladder was hidden inside the division primitive.**
`k_elim_rescale_dual_two_stage` called `mod_switch_down_dual` *before*
rescaling — a lane drop smuggled into the "exact division" step itself. Its gate
was `should_two_stage_rescale = q_product == 0 && level >= 3 && primes.len() > 5`.
`secure_128` has 3 primes and never tripped it, which is why it was invisible;
any `>5`-prime configuration (`deep_circuit` / `depth3`-style) would have kept
descending per multiply even after the Step-5 sites were deleted.

### 2.2 The out-of-bounds

Two bugs meeting: a producer that shrinks the basis, and a consumer that assumes
it never does.

1. `mul_dual_public` Step 5 returned a ciphertext whose `poly.main` had
   `level - 1` lanes.
2. The **next** multiply reached Step 3.5 and passed `&self.config.primes` — the
   **full**, never-sliced prime list — as `main_moduli` to
   `sbni::inject_dual_in_place`.
3. `sbni.rs:77` iterated `main_moduli.iter().enumerate()` and `sbni.rs:84`
   indexed `poly.main[i]` past its end.

The gate was `level >= 3`, so on a 3-prime `secure_128` config the *first*
multiply descended to 2 and the *second* panicked. That is the depth-2/3 ceiling
that was observed.

### 2.3 Which tests it was breaking

**PROVEN** (six `index out of bounds` panics at `sbni.rs:84:42`, len 2/idx 2 and
len 3/idx 3, all now passing — see §3.3):

- `comprehensive_benchmarks::benchmark_depth_specific_operations_secure_128`
- `comprehensive_benchmarks::benchmark_noise_budget_accuracy`
- `comprehensive_benchmarks::benchmark_noise_growth_secure_128`
- `ops::rns_fhe::tests::test_compare_symmetric_vs_public`
- `ops::rns_fhe::tests::test_public_mode_depth_sweep`
- `ops::rns_fhe::tests::test_tracked_deep_multiplication_chain`

### 2.4 The edits

| Site | Change |
|---|---|
| `mul_dual_symmetric` tail | Auto-switch deleted; returns at full lane count, with a retirement comment. |
| `mul_dual_symmetric_with_s2` tail | Same. |
| `mul_dual_public` Step 5 | Auto-switch deleted; now `Ok(DualRNSCiphertext { c0, c1, level })`. |
| `should_two_stage_rescale` | Now returns `false` unconditionally (parameter renamed `_level`), closing the hidden second ladder. The two-stage function body is retained and still syntactically referenced, so it stays inspectable and raises no `dead_code` warning. |

**Deliberately NOT changed:** the definitions of `mod_switch_down_dual`,
`mod_switch_ct_down`, `mod_switch_ct_to_level` and `mod_switch_eval_key_to_level`
are all still present and still shrink the basis. `basis_invariance.rs` contains
`mod_switch_ladder_is_the_negative_of_this_invariant`, which calls
`mod_switch_ct_down` and **asserts that the basis moves** — it is the negative
control for the whole invariant suite. Deleting or neutering those definitions
would destroy the standing proof of author decision (1). Removing the
multiply-path *call sites* leaves that proof intact.

---

## 3. Before / after

### 3.1 A baseline correction, recorded honestly

The brief for this work quoted a baseline of **728 passed / 9 failed / 19
ignored**. That does not match this working tree. The measured baseline
immediately before the edits was **644 passed / 9 failed / 103 ignored** — a
concurrent workflow had already quarantined roughly 84 further tests. All deltas
below are against the measured baseline, not the quoted one.

### 3.2 Test counts

| | passed | failed | ignored | total |
|---|---|---|---|---|
| **Before** (measured) | 644 | 9 | 103 | 756 |
| **After** (PROVEN, §7) | 644 | 4 | 103 | 751 |

**The identical `644` on both rows is a coincidence, and the arithmetic behind
it matters more than the number.**

```
  644  passes before
-   5  sbni.rs tests, which were PASSING and which left the crate when
       `pub mod sbni;` was removed  ->  NOT repaired, REMOVED
= 639  passes that survive on their own merits
+   6  tests that stopped panicking at sbni.rs:84 and now pass their
       ORIGINAL, UNMODIFIED assertions
-   1  test that this change EXPOSED as failing (§3.4)
= 644  passes after
```

Total count drops `756 -> 751`: exactly the five sbni tests.

### 3.3 Removed, not repaired — the five sbni tests

`test_injection_poly_bounded`, `test_injection_preserves_correctness`,
`test_injection_stochastic`, `test_blake3_uniformity`,
`test_blake3_serial_correlation`. All five were **passing**. The last two sit
*outside* the `mod tests` block as bare module-scope `#[test]` functions, which
makes them easy to overlook when counting.

Per `docs/RETIRED_MECHANISMS.md` §5, they are recorded in the `sbni.rs` header
rather than silently deleted. **They are not evidence of anything any more.** In
particular, `test_injection_preserves_correctness` called
`inject_dual_in_place` on a *fresh* ciphertext where
`poly.main.len() == config.primes.len()`, which is precisely why it never
reproduced the level-mismatch panic that was live in production.

### 3.4 One test newly failing — and it is a real finding

`ops::rns_fhe::tests::test_mul_dual_symmetric_depth2_secure_128_deep`
now fails at `rns_fhe.rs:10540`:

```
assertion `left == right` failed: Depth-2 symmetric: expected 81, got 12606
```

Depth 1 is correct (9). Depth 2 is garbage. **PROVEN.**

Three things about it, in order of increasing seriousness.

**First, the test's own premise was already false.** Its docstring says
*"symmetric mode has NO auto mod-switch (unlike public mode)"*. It did. The
auto-switch at the tail of `mul_dual_symmetric` carried the comment "mirrors
mul_dual_public". The test was green only because of a mechanism its own comment
denies it uses. It was never testing what it claimed to test.

**Second, the removal did not create this defect — it exposed it.** The
auto mod-switch was concealing that `k_elim_rescale_dual` alone does not yet
preserve correctness across two chained ciphertext×ciphertext multiplications
when the basis stays put.

**Third, this is corroborated by an independent, committed, currently-passing
test.** `depth_and_noise_curve_squaring_chain` in
`crates/nine65/tests/depth_and_noise.rs` runs repeated symmetric squaring on
`secure_128` at a fixed basis and records:

```
     0 |     3      5     3 |      8.354 |         - | OK
     1 |     3      5     3 |     28.955 |    20.601 | OK
     2 |     3      5     3 |     89.251 |    60.296 | WRONG got 65302 want 81
  max depth with CORRECT decryption : 1
  stopped by                        : Noise
```

`89.251` bits is `log2(Q)` — the measure is saturated; the error has reached the
full modulus. Same shape in public mode
(`depth_and_noise_curve_public_mode`: correct at depth 1, `got 15 want 5` at
depth 2). **PROVEN, both.**

**REPORTED, not re-verified here:** a temporary probe run during the change (25
`(seed, base)` trials on `secure_128_deep`) found depth-2 symmetric correct
`0/25` without a mod-switch and `25/25` with one manual `mod_switch_ct_down`
after depth 1; and a config sweep found depth-2 `ct×ct` wrong on
`light_rns_exact_insecure` (2 primes), `secure_128` (3 primes) and
`secure_128_deep` (4 primes), in **both** symmetric and public mode. That probe
is not committed. The committed squaring-chain and public-mode tests above cover
the `secure_128` case and are the reproducible evidence.

**The test was left failing and its assertion was left unweakened.** Modulus
switching was not reintroduced to paper over it. It needs an author decision:
either the fixed-basis multiply path is fixed, or the test is retired per
`docs/RETIRED_MECHANISMS.md` — but retiring it would be conceding depth 2, which
is exactly what the residue-native design is meant to deliver. **Open item,
§6.1.**

A **REPORTED** lead for whoever picks this up: `ctx.ke.capacity_bit_length()` is
110 bits and is *constant* across all three configs, because the anchor basis is
a fixed 5 primes (~156 bits). The tensor product before rescale needs roughly
`2·log2(Q) + log2(N)` bits of exact reconstruction — 133 / 193 / 251 bits for the
three configs, all far above 110. Depth 1 nonetheless succeeds, so the rescale is
evidently not doing a naive full-width reconstruction; but the K-Elimination
capacity does not scale with the main basis at all, and that is the first place
to look.

### 3.5 Depth delta

| | depth reached |
|---|---|
| **Before** | hard panic at roughly **2–3** (`sbni.rs:84` out of bounds); nothing beyond was measurable at all |
| **After**, symmetric multiply against a fixed fresh `Enc(1)` | **256** at the committed default cap — stopped by the cap, not by noise (**PROVEN**, §7) |
| **After**, same chain, cap raised via `NINE65_DEPTH_MAX=4096` | **4096** — again stopped by the cap (**REPORTED**; log at `…/scratchpad/deep_run.log`) |
| **After**, symmetric repeated squaring `ct×ct` | **1** (**PROVEN**) |
| **After**, public mode against `Enc(1)`, `t = 65537` | **1** (**PROVEN**) |

The honest summary of that table: the retirement removed a crash and unblocked
measurement. It did not change the underlying BFV noise arithmetic. Useful depth
on this parameter set now ranges from **1 to 4096+ depending entirely on the
circuit**, and the large number comes from a chain whose noise recurrence is
additive by construction (`e_{k+1} ≈ e_k + m·e_one + rounding`) because one
operand is always a fresh `Enc(1)`. It should not be quoted as a general depth
figure.

---

## 4. The noise curve

All figures from `crates/nine65/tests/depth_and_noise.rs`, which uses the
measure the codebase already exposes:
`RNSFHEContext::decrypt_dual_with_diagnostics(ct, sk) -> (decoded, margin)` with
`margin = Δ/2 - |error|`, so `|error| = Δ/2 - margin`, reported as
`1000·log2(|error|)` millibits with integer arithmetic only. `margin < 0` is this
codebase's own exhaustion condition (`try_decrypt_dual` converts exactly that
into `NoiseExhausted`). It is deliberately **not** `NoiseBudget` (a predictive
accounting model, as `bin/cram_exploratory_probe.rs` itself flags) and not
`GSOFHEContext::noise_stats` (a tracker carried alongside the ciphertext rather
than read out of it).

Parameters: `secure_128`, `N = 8192`, main primes
`[998244353, 985661441, 754974721]`, 5 anchor lanes, `t = 65537`,
`log2(Q) = 89.260`, budget `log2(Δ/2) = 72.260` bits.

### 4.1 Shape: BOUNDED GROWTH. Not flat. **PROVEN.**

The noise rises monotonically at every depth. It is not being rounded down to
flat here. What makes it bounded rather than fatal is the *rate*: `log2(noise)`
rises about **1.2 bits per doubling of depth** over `2 -> 256`, i.e. the noise
*magnitude* grows close to linearly in depth, not geometrically.

| depth | 0 | 1 | 2 | 4 | 16 | 64 | 128 | 256 |
|---|---|---|---|---|---|---|---|---|
| noise (bits) | 6.697 | 29.907 | 42.368 | 44.347 | 46.644 | 48.804 | 49.835 | 50.815 |

The first two multiplies cost 23.2 and 12.5 bits; by depth 256 a doubling costs
under one bit. At the cap the measure reads **50.815 bits against a 72.260-bit
budget — 21.4 bits of headroom unspent**, and the run's own extrapolation of the
last octave puts exhaustion near depth `2^30`. The **REPORTED** 4096 run reached
54.854 bits, still 17.4 bits short, and extrapolated to `~2^28.6`.

So: **very large but finite.** The central claim holds in the practical sense
and does **not** hold in the strict "flat / genuinely unbounded" sense. Say the
first, not the second.

### 4.2 Does exact division reduce noise proportionally to the divisor?

**Yes, exactly — and this is the strongest single result in the run. PROVEN.**

Scale a ciphertext by `d` with `mul_plain_dual`, then exact-divide by `d` with
the per-lane K-Elimination reciprocal:

```
      d |        noise |    after x d |    after / d | x d delta | / d delta |   log2 d
      2 |        4.522 |        5.522 |        4.522 |     1.000 |    -1.000 |    1.000
      3 |        7.398 |        8.983 |        7.398 |     1.585 |    -1.585 |    1.581
      5 |        3.697 |        6.019 |        3.697 |     2.322 |    -2.322 |    2.319
      7 |        4.952 |        7.758 |        4.952 |     2.806 |    -2.806 |    2.804
     11 |        8.096 |       11.554 |        8.096 |     3.458 |    -3.458 |    3.456
     23 |        7.781 |       12.303 |        7.781 |     4.522 |    -4.522 |    4.522
     97 |        5.390 |       11.990 |        5.390 |     6.600 |    -6.600 |    6.597
   1009 |        4.522 |       14.501 |        4.522 |     9.979 |    -9.979 |    9.976
   4093 |        6.682 |       18.681 |        6.682 |    11.999 |   -11.999 |   11.994
  16381 |        4.000 |       17.994 |        4.000 |    13.994 |   -13.994 |   13.994

worst deviation of the /d noise delta from -log2(d): 0.005 bits
```

Stronger than proportionality: the raw integer `|error|` after the round trip is
asserted **equal** (`assert_eq`, not approximate) to the pre-scaling value, so
the division introduced no rounding term at all. Lane count, anchor count and
level unchanged throughout.

### 4.3 The precondition that bounds what that buys. **PROVEN.**

`d` must divide the **full underlying integer** `Δ·m + e`, not just the
plaintext. Control measurement — `Enc(12) / 4`, where 4 divides the plaintext but
not the noise:

```
  Enc(12) / 4: noise 5.975 -> 71.260 bits; decrypted 16387 (wanted 3); correct=false
  lanes: main 3 -> 3, anchor 5 -> 5, level 3 -> 3
```

The lane-wise quotient wraps to `(v + kQ)/d`, of order `Q/d`, and the ciphertext
is destroyed. (The lanes still did not move — the basis invariant holds even
while the value is being ruined.)

**Multiplication noise is not of the divisible form.** Therefore exact division
cannot be used to shed accumulated chain noise, and the two-chain comparison
proves it: Chain A (multiply only) and Chain B (multiply, then scale by 97, then
exact-divide by 97 at every depth) have measured noise **identical to 0.000 bits
at every single depth `0..=256`**, and both reach the same depth.

**Exact division is a lossless scale change. It removes exactly the `log2(d)`
bits it just added. It is not a rescale substitute for a multiply chain, and it
bought zero extra depth.**

### 4.4 Two defects found in the existing noise measure — NOT fixed, out of scope

1. `decrypt_dual_with_diagnostics` falls back to `decrypt_dual_u256` and returns
   `margin = 0` **unconditionally** whenever `Q·t ≥ 2^128`. That silently kills
   the measure for every 4-or-more-prime chain at `t = 65537` —
   `secure_128_deep`, `secure_192`, `secure_256`, `deep_circuit_insecure` all
   then report a constant "noise" exactly equal to `log2(Δ/2)` at every depth.
   **That looks like a perfectly flat curve and is in fact no measurement at
   all.** Anyone reading a flat curve off those configs is reading a fallback
   constant. This is why the measurements above use 3 primes.
2. In the negative branch (`full_value > q_half`) the ideal point is computed as
   `Q - decoded·Δ` using `decoded` (which is `t - k`) where it needs the
   magnitude `k`. For any plaintext `≥ t/2` the reported `|error|` is therefore
   `~Q` rather than the true error. Both copies of the function have it. Every
   measurement in `depth_and_noise.rs` keeps the plaintext below `t/2`, and
   `Sample::noise_valid` records the condition explicitly.

---

## 5. Lane count across the deep chain — the anti-ladder invariant

**PROVEN.** Asserted at **every** depth of **every** chain in
`depth_and_noise.rs`, and printed by each run:

```
LANE COUNT CONSTANT over depths 0..=256: main=3 anchor=5 level=3
```

`poly.main.len() == 3`, `poly.anchor.len() == 5`, `ct.level == 3`, unchanged from
depth 0 to depth 256 in the plain chain, the squaring chain, the public chain and
the exact-division chain — and unchanged to depth 4096 in the **REPORTED** long
run. Nothing was consumed anywhere.

This is the depth-side companion to `basis_invariance.rs`, which proves the same
thing under *division* (12 passed / 0 failed, still green — §7).
`depth_and_noise.rs` also carries `DEPTH_REGRESSION_FLOOR = 32`: a depth below
that is treated as a regression of this retirement.

Two things worth stating plainly:

- The invariant held even in the chains that **failed** on correctness — the
  squaring chain reports `main=3 anchor=5 level=3` at depth 2 while decrypting
  `65302` instead of `81`. Lane invariance is a statement about the
  representation, not a certificate of correctness. Do not read one as the
  other.
- The invariant is now true partly because the code that could move the basis in
  the multiply path was deleted. That is the intended change, not an
  independent discovery. The independent evidence that the basis *need not* move
  is `basis_invariance.rs`, which was already green before this work.

---

## 6. What remains

### 6.1 The exposed depth-2 defect — the highest-priority open item

`test_mul_dual_symmetric_depth2_secure_128_deep` is **failing and left
failing**. See §3.4. Depth-2 `ct×ct` at a fixed basis is currently incorrect,
in both symmetric and public mode, on every config tested. The design claim —
exact division unfuses divide-the-value from drop-a-lane, so depth is not
budget-bounded — is correct in principle and is **proven for division**
(`basis_invariance.rs`, 12/12), but it is **not yet realised by the current
multiply-plus-rescale path**. Depth 1 works. Depth 2 does not.

### 6.2 `mod_switch` functions: none uncalled, several unreachable

No `mod_switch` function became syntactically uncalled, so nothing was marked
`#[deprecated]` and no `dead_code` warnings appeared. What changed is
*reachability*:

| Function | Status now |
|---|---|
| `mod_switch_down_dual` | Live definition. Still called from `mod_switch_ct_down`, from `mod_switch_eval_key_to_level`, and from `k_elim_rescale_dual_two_stage`. **Unreachable via the last one** (gate is now `false`). |
| `mod_switch_ct_down` | Live definition, still shrinks the basis. Production callers: only `mod_switch_ct_to_level`'s `while` loop, which **never iterates** now. Real callers are tests: `basis_invariance.rs` (asserts the basis moves — keep), `full_system_exercise.rs`, and `rns_fhe.rs` `test_add_dual_aligns_mixed_levels`. |
| `mod_switch_ct_to_level` | Live, called twice per `add_dual`. **Degenerate:** with nothing descending, both levels are always equal, `target_level == ct.level`, the loop never runs, and it reduces to two full ciphertext clones per addition. Correctness-neutral; a measurable and pointless allocation on the add path. |
| `mod_switch_eval_key_to_level` | Live definition, called from `relinearize_dual`'s `evk_level > poly_level` branch. **That branch is now unreachable** — `d2` keeps the full lane count and the eval key is generated at full level, so `evk_level == poly_level` always. |
| `k_elim_rescale_dual_two_stage` | Retained and still referenced, but **unreachable**: `should_two_stage_rescale` returns `false`. |

**Keep** the `evk_level < poly_level` arm of `relinearize_dual`, which returns
`Nine65Error::RegimeMismatch`. It is a genuine corruption guard — without it
`zip` would silently truncate ciphertext limbs.

**Do not** "simplify away" `ct.level`. It is read at ~46 sites in `rns_fhe.rs`
and used by validation and serialization; `DualRNSCiphertext::validate`'s
`self.level > self.c0.main.len()` check stays satisfied. It is simply now
permanently equal to `config.primes.len()`.

### 6.3 Remaining residue-space exits

1. **`mod_switch_down_dual` / `mod_switch_ct_down` themselves.** Still present,
   still perform the classical fused inexact-divide-and-drop-a-lane. Retained
   *on purpose*: `basis_invariance.rs` needs the retired path to exist and to
   still shrink, because it is the suite's negative control. They are no longer
   reachable from any multiply.
2. **The bootstrap `modswitch_*` family** in `ops/bootstrap.rs` —
   `modswitch_to_t`, `modswitch_to_t_verified`, `modswitch_boot_to_work`, with
   call sites inside the bootstrap paths. Spelled without the underscore, so it
   does **not** appear in a `mod_switch` grep. This is not the per-multiply level
   ladder and is not in the multiply path, but it is the same fused
   divide-and-drop pattern, and `docs/RETIRED_MECHANISMS.md` already quarantines
   bootstrap tests over it. **Out of the scope of this change; listed so the map
   is complete.**
3. **`FHEConfig::max_mod_switch_depth()`** (`params/mod.rs:518`,
   `primes.len().saturating_sub(2)`) and its sole consumer
   `crates/nine65/examples/test_mod_switch.rs`. Pure config arithmetic, touches
   no ciphertext, cannot crash — but it is a **ladder-premise API**: it answers a
   question ("how many levels do I have left?") that this architecture says is
   meaningless. Flagged for retirement, untouched, still compiles.
4. **Orphaned NTT shadow plumbing.** `ntt_inplace_with_shadow` and
   `ntt_with_shadow` still carry a `shadow: &mut Option<Vec<u64>>` parameter that
   existed solely for SBNI; every remaining caller passes `&mut None`, so the
   capture branches are permanently unreachable. **Left alone deliberately.**
   `entropy/crt_shadow.rs` has a *separate* `*_with_shadows` family used by
   `gso_fhe.rs` for a genuinely different purpose; confusing the two would break
   GSO. Handle in a separately-scoped follow-up. Note also that
   `ntt.rs`'s shadow capture pushes one entry per `(k,j)` pair — `n²` entries,
   ~512 MB at `N = 8192` — against a `Vec::with_capacity` sized for `n·log2(n)`.
   That latent OOM under `--features reference_ntt` is now **unreachable**,
   because its only feeder is gone.

### 6.4 The three unrelated broken fixtures — untouched, still failing

All three predate this change, are unrelated to SBNI or modulus switching, and
were deliberately not repaired. **PROVEN** (§7 shows all three still red).

| Test | Failure | Diagnosis |
|---|---|---|
| `noise::budget::tests::exact_delta_size_does_not_sum_lane_widths` | `budget.rs:350`, `assertion left != right failed: left: 4, right: 4` | **Unsatisfiable fixture.** With primes `[5,5]`, `t=2`: it asserts `exact_delta_bit_length == 4`, then asserts `exact_delta_bit_length != summed_lane_widths - t_bits = 6 - 2 = 4`. It asserts `4 == 4` and then `4 != 4`. The *intent* (delta size is not the sum of lane widths) is sound; the fixture chosen to demonstrate it is a case where the two coincide. Needs different primes, not a code fix. |
| `noise::budget::tests::exact_delta_size_handles_products_above_u128` | `budget.rs:126` | **Fixture violates a stated precondition.** `exact_delta_bit_length` asserts `config.t < prime` for every prime; the fixture passes `t = 3` with `2` in the prime vector. The precondition is correct; the fixture is not. |
| `security::tests::test_lwe_params_from_config` | `security/mod.rs:315`, `left: 8192, right: 4096` | **Stale literal.** Asserts `params.n == 4096` with the comment "SecureConfig::secure_128() uses N=4096". `secure_128` was widened to `N = 8192`. The assertion has to follow the config. |

### 6.5 Documentation debt — open, and now urgent

The following all still assert SBNI as a **live security control**:
`README.md:14` and `:170`; `docs/ENTROPY_MODEL.md:46-72`;
`docs/SIDE_CHANNEL_THREAT_MODEL.md:90` and `:97` (threat T5);
`docs/LINEAGE.md:24`; `docs/AUDIT_REPORT_V8.md:31`;
`docs/CLAIM_EVIDENCE_LEDGER.md:87`;
`docs/CRAM_RLWE_SECURITY_ASSESSMENT_2026-06-03.md:88` and `:116-121`.

Two things must be said about this.

- **`docs/ENTROPY_MODEL.md:72` was already false before this change.** It claims
  "SBNI tests cover empty inputs, live-lane shrinkage, coefficient bounds, anchor
  consistency, and decrypt correctness." No such tests ever existed — the five
  that did exist covered none of empty inputs or lane shrinkage. Removing SBNI
  did not make that sentence untrue; it was untrue when written.
- **`CRAM_RLWE_SECURITY_ASSESSMENT` §3.2 "Option B" proposes SBNI as the answer
  to a noise-flooding requirement.** If any downstream security argument leans on
  that, it needs to be **re-derived**, not merely re-pointed. Per §1.2(c), SBNI
  never delivered it: entropy from an NTT of `vec![123u64; n]` through fixed
  twiddles, identical every call, keyed only by a monotonic counter, unkeyed
  hash, no secret and no RNG.

Until these are retired, the documented security posture is provably overstated.

### 6.6 Other open items

- **`blake3 = "1"` (`crates/nine65/Cargo.toml:98`) is now an unused
  dependency.** `sbni.rs` was its only consumer in `crates/nine65/src`. Left in
  place because that file belongs to a concurrent workflow. A `cargo udeps` /
  `deny.toml` / `unused_crate_dependencies` lint may start flagging it. Hand to
  whoever owns `Cargo.toml`.
- **`rns_fhe.rs` `test_add_dual_aligns_mixed_levels` still PASSES**, because it
  manufactures its own level mismatch by calling `mod_switch_ct_down` directly
  and that function was not neutered. It is at risk only if someone later
  disables that path — at which point it needs a disposition, not a silent
  delete.
- **`symmetric_bootstrap.rs` `test_symmetric_depth_50_no_bootstrap`** had a
  break condition that *was* the ladder ("ct descends one level per multiply, so
  their levels diverge… once it can no longer be switched down we have hit the
  level/noise ceiling"). With nothing descending, the alignment is a no-op and
  the premise has evaporated. Already `#[ignore]`d by the concurrent workflow.
- **`crates/exact_transcendentals/src/chimera_division.rs:9`** carries a
  doc-comment reference to "SBNI's lane-count contract". Prose only, no code
  dependency; should be reworded.

### 6.7 Pre-existing compile breakage in three integration targets — not from this work

**PROVEN** by `cargo check -p nine65 --tests`. Three test *targets* do not
compile in this working tree, all from the concurrent workflow's in-flight
renames, none related to SBNI or modulus switching:

- `tests/full_system_exercise.rs` — `FHEConfig::light_insecure` and
  `::he_standard_128_insecure` no longer exist.
- `tests/dual_rns_context_metadata_regression.rs` — `DualRNSContext::{main,anchor}_product_{checked,limbs,bit_length}` missing.
- `tests/rns_context_metadata_regression.rs` — `RNSFHEContext::q_product_{checked,limbs}` missing.

**Consequence for this change:** `full_system_exercise.rs`'s
`test_mod_switch_down` **could not be verified**. It calls `mod_switch_ct_down`,
which was left fully intact and still shrinking, and it already tolerates a
`None` return — so it should pass once that file compiles again. That is an
**ASSUMED**, not a **PROVEN**.

---

## 7. Final measured state

Run at the time of writing, in this working tree.

```
$ cargo test -p nine65 --lib 2>&1 | tail -4

failures:
    noise::budget::tests::exact_delta_size_does_not_sum_lane_widths
    noise::budget::tests::exact_delta_size_handles_products_above_u128
    ops::rns_fhe::tests::test_mul_dual_symmetric_depth2_secure_128_deep
    security::tests::test_lwe_params_from_config

test result: FAILED. 644 passed; 4 failed; 103 ignored; 0 measured; 0 filtered out; finished in 139.59s
```

```
$ cargo test -p nine65 --test basis_invariance 2>&1 | tail -3

test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 19.99s
```

```
$ cargo test -p nine65 --test depth_and_noise 2>&1 | tail -3

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 334.61s
```

Of the four remaining library failures: **three are the pre-existing unrelated
fixtures** of §6.4, and **one is the depth-2 defect this change exposed** (§3.4,
§6.1). No failure is an SBNI out-of-bounds. `cargo check` introduces zero new
warnings — the seven that remain are pre-existing, in `k_elimination.rs`,
`secure_configs.rs`, `auto_bootstrap.rs`, `bootstrap.rs` and
`symmetric_bootstrap.rs`.

### Reproducing the long run

```
RUSTFLAGS="-C debug-assertions=on -C overflow-checks=off" \
NINE65_DEPTH_MAX=4096 NINE65_DEPTH_SECS=1800 \
cargo test --release -p nine65 --test depth_and_noise -- --nocapture --test-threads=1
```

`-C debug-assertions=on` is required in release because
`decrypt_dual_with_diagnostics` is `pub` only under
`cfg(any(test, debug_assertions))`. The committed defaults are
`DEFAULT_MAX_DEPTH = 256` and `DEFAULT_WALL_SECS = 300`, overridable via
`NINE65_DEPTH_MAX` / `NINE65_DEPTH_SECS`.

---

## 8. The one-line version

The auto modulus-switch was deleted from all three multiply paths and from
inside the division primitive, and SBNI was dropped; the crash that capped
multiplication at depth 2–3 is gone, the basis provably does not move across
4096 multiplications, exact division reduces noise by exactly `log2(d)` with no
rounding term — and with the ladder out of the way it is now visible that
depth-2 ciphertext×ciphertext at a fixed basis is not yet correct, which the
ladder had been hiding.
