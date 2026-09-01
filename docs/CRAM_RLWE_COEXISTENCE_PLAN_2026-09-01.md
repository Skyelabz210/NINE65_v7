# CRAM × RLWE Coexistence — Deep Testing & Exploration Plan

**Date:** 2026-09-01
**Branch:** `claude/cram-rlwe-security-gcvt1u`
**Status:** exploration plan (no cryptographic claim is asserted here; each is a
hypothesis with an experiment that can falsify it)

---

## 0. Why this document exists

The dual-track / anchor formulation, as currently shipped, does **not** preserve
RLWE hardness for anything it publishes. This was confirmed both analytically
and empirically (rational-inversion recovers `s` in ~1.75 ms at N=1024 from a
published main+anchor pair). The root cause is proven and sharp:

> RLWE hardness lives entirely in the modular **wrap** of `a·s + e mod Q`
> (the unknown quotient `k = ⌊(a·s+e)/Q⌋` is a one-time pad over ℤ).
> CRAM exact K-Elimination requires the value **not** to wrap
> (`M·A > max|a·s+e|`) so the exact integer is recoverable.
> On a *published, secret-dependent* value these two requirements are the exact
> logical negation of one another.

This plan does **not** try to defeat that theorem. It maps precisely where the
theorem does and does **not** bite, and lays out the experiments that let us
deploy CRAM's real innovations — exact residue-native arithmetic, reversible /
i.i.d.-safe lane compute, zero-drift division — **without** ever placing a
non-wrapped secret-dependent value on the wire.

---

## 1. The coexistence thesis (one invariant)

Everything below follows from a single wire invariant:

> **WIRE-Q.** Any polynomial that is *both* secret-dependent *and* published
> (`pk0`, `c0`, `c1`, `rlk0`, any key-switch / bootstrap key, any ciphertext
> serialized to an untrusted party) may carry residues **only modulo divisors
> of the single security modulus `Q`**. No residue modulo anything coprime to
> `Q` — anchor, shadow-11, syndrome, StarLift anchor, redundant lane — may ever
> appear on such an object.

CRAM exactness is then admissible in exactly three places, because each one
escapes WIRE-Q's premise by breaking either "secret-dependent," "published," or
"non-wrapped":

| Domain | Escapes via | CRAM exactness admissible? |
|---|---|---|
| **D1 — Plaintext space (mod `t`)** | not secret-dependent | **Yes, fully** |
| **D2 — Secret-holder / client side** | not published (inside trust boundary) | **Yes, fully** |
| **D3 — Evaluator kernel, derived+transient** | derivable-from-public + discarded before serialization | **Yes, conditionally** (D3-rules below) |
| **D4 — On the wire, secret-dependent** | escapes nothing | **No — forbidden by WIRE-Q** |

The current architecture fails because the anchor lives in D4. The plan moves
every CRAM innovation into D1/D2/D3 and proves D4 is empty.

---

## 2. The security boundary is a *measurable object*, not a binary

The most important exploratory result to establish first: the break is **not**
gradual and **not** a matter of "how much" anchor you publish. It switches on
**exactly** at the capacity line `M·A > max|a·s+e|` — the same line that makes
K-Elimination exact. Below the line the extra track *itself wraps* and stays a
hard-modulus RLWE sample; above it, total break.

The user's StarLift 36/37 test already shows this at toy scale
(`0 ≤ X < 1332`: exact recovery; `X ≥ 1332`: only `k mod 37`). **Experiment E1**
scales it to production and turns it into a first-class characterization: a
**security cliff curve**, recovery-success vs. published anchor capacity, per
config. This is the empirical spine of the whole plan — it proves the tension is
a hard threshold, which is *why* no "masking" or "partial anchor" compromise can
exist (see E2).

---

## 3. Where each CRAM innovation lands

| CRAM innovation | Domain | Verdict | Rationale |
|---|---|---|---|
| Safe-Basis (30030) slot packing / encoding | D1 | **Deploy** | plaintext structure is public; no `s` involved |
| StarLift 36/37 winding on **messages** | D1 | **Deploy** | operates on plaintext lift, not on `a·s+e` |
| Reversible / i.i.d.-safe lane compute (A2, arrow) | D1/D2/D3 | **Deploy as CT discipline** | side-channel property, orthogonal to RLWE hardness |
| `compare_bit` CT decision kernel | D2 | **Deploy client-side** | used in decrypt/centering, inside trust boundary |
| Exact centered decrypt / K-Elim decode | D2 | **Deploy** | secret holder already knows `s` |
| Exact base-extension (`base_ext.rs`, rank-recovered) | D3 | **Deploy inside mul kernel** | derived from public ct, discarded before serialize |
| Zero-drift exact rescale quotient | D3 | **Deploy inside mul kernel** | computes the *same* rounded ⌊t·x/Q⌉ a bigint gives, drift-free |
| **Anchor track on `pk/ct/rlk`** | D4 | **Forbidden** | publishes non-wrapped `a·s+e`; WIRE-Q violation |
| K-Elimination on the **secret-linear term** at keygen | D4 | **Forbidden** | the anchor's original sin |

The single conceptual correction: CRAM's exact-division / winding machinery has a
legitimate home on the **evaluation-time rescale quotient**
`⌊t·(c⊗c′)/Q⌉` — which is computed from *public ciphertexts* and leaks nothing —
**not** on the **keygen-time secret quotient** in `a·s+e = b + k·Q`, which must
stay hidden. These are different quotients. The bug is attaching exactness to the
second; the opportunity is attaching it to the first.

---

## 4. D3 rules (the delicate domain)

Exact arithmetic inside the evaluator is safe **iff all three** hold. The test
harness must enforce them mechanically:

- **D3-a Derived.** Every coprime-to-`Q` residue used is computed *from* the
  mod-`Q` ciphertext by base extension (`base_ext.rs`), never sampled fresh and
  never carried in from keygen.
- **D3-b Transient.** Auxiliary residues exist only within a single kernel call
  (mul / rescale / relin) and are dropped before the result is returned.
- **D3-c Wrapped output.** The serialized result carries only mod-`Q` lanes.
  A serialization-time assertion (see E4) rejects any coprime-to-`Q` lane.

Standard RNS-BFV multiplication (BEHZ / HPS) already obeys D3-a/b/c with an
*approximate* auxiliary base. CRAM's contribution is to make the base extension
and the rescale quotient **exact and zero-drift** while keeping D3-a/b/c intact.
"Exact rescale" means exact computation of the rounded value — it does **not**
mean skipping the round (skipping the round is the anchor trap again). Rescale
stays intentionally lossy; that loss is a feature, and it is where wire-side
reversibility legitimately ends.

---

## 5. Experiment ladder

Each experiment states a hypothesis, a method against real code, a pass/fail
metric, and what a pass proves. Adversarial experiments (marked ⚔) are designed
to *falsify* a convenient belief, not confirm it.

### Phase A — Characterize the boundary (prove the tension is a hard threshold)

**E1 — Security cliff curve.** *Hypothesis:* recovery success is a step function
of published anchor capacity, stepping at `M·A ≈ max|a·s+e|`.
*Method:* extend the rational-inversion attack to run against `generate_keys_dual_secure()`
public keys for `secure_128_deep / 192 / 256`, sweeping the number of published
anchor lanes 0…10. For each, attempt `s`-recovery and record success rate + max
coefficient residual before rounding. *Metric:* success flips 0→100% within one
lane of the predicted threshold. *Proves:* the break is threshold, not gradual —
foundational for E2.

**E2 ⚔ — Masking does not save a non-wrapped track.** *Hypothesis (to kill):*
"publish the anchor but add independent fresh noise `e′` per track and it's two
harmless RLWE samples." *Method:* construct `(a·s+e mod Q, a·s+e′ mod A)` with
independent CBD `e,e′`; run the attack using the anchor track alone.
*Metric:* if `A > |a·s|`, anchor-alone recovery still succeeds (because
`a·s+e′` doesn't wrap → exact via rational inversion). *Proves:* the only thing
that preserves hardness is *wrap*; no masking / partial-anchor / re-randomization
compromise exists. Closes the door on "clever anchor" proposals permanently.

### Phase B — Establish the RLWE-safe wire baseline

**E3 — Main-only path is genuinely hard.** *Hypothesis:* the existing
`RNSCiphertext` / `encrypt` / `mul` / `decrypt` (mod-`Q`, no anchor) resists the
attack and matches the estimator's screened level. *Method:* run E1's attack
against `RNSPublicKey`; confirm ≈ random-guess recovery (the user's Test 2 showed
33% ≈ ternary chance at N=1024). Cross-check `security_estimator` sees the true
wire modulus. *Metric:* recovery ≈ 1/3 per coefficient; estimator log₂(q) = wire
`Q`. *Proves:* an RLWE-safe deployment already exists in-tree; the task is
*selecting* it, not building it.

**E4 — Executable WIRE-Q gate.** *Hypothesis:* WIRE-Q can be enforced at
compile/serialize time, not by prose. *Method:* introduce a wire type whose
serialization carries only main lanes; add a `#[test]` that serializes every
public object (`pk0`, `c0`, `c1`, `rlk0`) after keygen/encrypt/every homomorphic
op and asserts zero coprime-to-`Q` lanes; wire it into CI. *Metric:* the test
fails loudly on any dual object reaching serialization. *Proves:* the invariant
is machine-checked and cannot silently regress (this is the durable safety net).

### Phase C — Reclaim CRAM exactness inside the kernel (D3)

**E5 — Exact base extension leaks nothing.** *Hypothesis:* `base_ext.rs`'s
redundant-lane rank recovery, used to base-extend a mod-`Q` ciphertext into a
transient auxiliary base, is a deterministic function of public data.
*Method:* prove (and test) that the auxiliary residues are `f(ct mod Q)` with no
fresh entropy; run E1's attack on a ciphertext *plus* its transient auxiliary
residues and confirm no improvement over mod-`Q` alone. *Metric:* recovery rate
unchanged vs. E3. *Proves:* D3-a is real — exactness inside the kernel is free of
security cost.

**E6 — Exact zero-drift multiplication == bigint reference.** *Hypothesis:*
a mul/rescale built on E5 reproduces a `num-bigint` reference BFV multiply
bit-for-bit, with no floating drift, while emitting only mod-`Q` output.
*Method:* implement (or route) `mul` through the derived-transient exact kernel;
differential-test against a bigint oracle over random ct pairs at each config;
assert D3-c on every output. *Metric:* 100% bit-exact vs. oracle; WIRE-Q gate
green on all outputs. *Proves:* CRAM delivers an *exact RNS-BFV multiply* — a
genuine, publishable win — with zero security cost.

**E7 ⚔ — Depth honesty under the safe kernel.** *Hypothesis (to test, not
assume):* with the anchor gone from the wire, achievable multiplicative depth is
the ordinary BFV noise-budget depth (README's measured 2–4), not "exact
unlimited." *Method:* run direct-square depth benchmarks through the E6 kernel;
record decrypt-correct depth per config. *Metric:* report the true number.
*Proves:* prevents the exactness win from being over-read as a depth claim; keeps
`CLAUDE.md`'s depth ledger honest.

### Phase D — Reversible / i.i.d.-safe compute where it belongs

**E8 — CRAM-IID as sampler auditor (RLWE-strengthening).** *Hypothesis:* CRAM's
i.i.d./arrow lens can *audit* that `a` and `e` samplers have full support
(the very property whose earlier violation — `a` confined to `[0,2^64)` — caused
the zero-key decrypt leak). *Method:* apply the A2 / arrow-emission battery to
`sample_uniform_dual_poly` and `sample_cbd_signed_rng` outputs; assert
full-modulus support and expected CBD moments. *Metric:* support = full ring;
no structural emission. *Proves:* CRAM makes RLWE *stronger* here by catching
distribution defects — a constructive, security-positive role.

**E9 — Client-side reversible decode + CT.** *Hypothesis:* the reversible /
i.i.d.-safe substrate and `compare_bit` give a constant-time, drift-free
decrypt/centering entirely inside D2. *Method:* route centered decrypt through
`compare_bit` (client-side); run the CT re-audit (fixed-work fast branch;
scope/close the variable-time fallback per the compare_bit audit). *Metric:*
exact decode on all vectors; documented CT scope. *Proves:* reversibility and CT
have a real home where publishing never happens.

### Phase E — Freeze & document

**E10 — Coexistence conformance suite.** Aggregate E4 (WIRE-Q gate), E6
(exact-mul oracle), E5 (no-leak base-ext), E8 (sampler audit) into one CI job.
Update `CLAUDE.md` and `docs/CLAIM_SURFACE_AND_LIMITS` with the partitioned
claim: *RLWE hardness on the mod-`Q` wire; CRAM exactness in D1/D2/D3; anchor on
the wire retired.*

---

## 6. Design decisions that must be made by the owner (not assumed)

1. **Rescale placement.** Evaluator-side standard rounded rescale (non-interactive,
   noisy, normal FHE) **vs.** client-side exact rescale (interactive protocol).
   The diagram's "private client-side rescaling" silently chooses interactivity;
   confirm which model is intended. Default recommendation: evaluator-side rounded
   rescale (keeps non-interactive FHE), exactness applied only to *computing* the
   rounded value.
2. **Relinearization.** Standard mod-`Q` gadget relin replaces the anchor-based
   relin. Confirm gadget decomposition base.
3. **Multiplication engine.** Route through the existing single-modulus `mul`
   plus the E5/E6 exact base-ext kernel, vs. a fresh BEHZ/HPS implementation.
   The former reuses in-tree assets; the latter is more standard. Recommend the
   former first (lower risk), benchmark, then decide.

None of these are cryptographic-security questions — WIRE-Q secures all three.
They are performance / deployment-model trades.

---

## 7. Sequencing and gates

```
A (E1,E2)  ── prove the threshold, kill masking       [days]
    │
B (E3,E4)  ── safe wire baseline + CI gate            [days]   ◄ ship-blocker gate
    │
C (E5,E6,E7) ── exact kernel, no-leak, honest depth   [1–2 wk]
    │
D (E8,E9)  ── sampler audit + client CT               [1 wk, parallel to C]
    │
E (E10)    ── conformance suite + claim-surface update [days]
```

**Hard gate after Phase B:** nothing ships to any untrusted party until E4 (the
WIRE-Q serialization gate) is green in CI. Everything in C/D is upside on top of
a wire that is already RLWE-safe.

---

## 8. What a success looks like

- A single mod-`Q` wire that the rational-inversion attack cannot beat (E3),
  enforced by CI (E4).
- An **exact, zero-drift RNS-BFV multiply** whose auxiliary machinery is proven
  non-leaking (E5/E6) — CRAM's exactness delivered with no security cost.
- Reversible / i.i.d.-safe compute deployed as a **CT discipline** (D1/D2/D3) and
  as a **sampler auditor** (E8), i.e. security-neutral-to-positive.
- An honest depth ledger (E7) and a partitioned claim surface (E10).
- A permanently closed door on "clever anchor" proposals (E2), so the tension is
  documented as a theorem with a measured threshold, not re-litigated.

The standard this holds to: **never publish a value whose exact integer an
adversary can reconstruct; confine exact reconstruction to where the reconstructor
already holds the secret or the value is public.**
