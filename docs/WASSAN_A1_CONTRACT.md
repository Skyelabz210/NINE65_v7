# WASSAN A1 exactness contract and evidence ledger

Status: **implementation review in progress**. Owner: HackFate / Codex joint execution. Tracking: [#184](https://github.com/Skyelabz210/NINE65_v7/issues/184).

## A1 scope: operational representation

A1 here means that the stated arithmetic invariants are executed by exact integer/residue operations. A proof about a symbolic relationship may mention an irrational constant; that alone does not introduce an irrational-valued operand into an implementation. In particular, `φ = (1 + √5)/2` is irrational, but a code path can implement a rational or integer recurrence describing related structure without ever numerically evaluating `φ`. Each *actual* operational path must be checked before claiming global A1 compliance.

There are **three different WASSAN referents** in the repository family:

| Referent | Operational meaning | A1 status/scope |
| --- | --- | --- |
| [WASSAN HD storage specification](https://github.com/Skyelabz210/HackFate/blob/main/11_wassan_hd_storage.md) | 144 layered CRT positional bands with base `C = 9,699,690`, using exact integer quotient, residue and inter-band carries | No `φ` evaluation appears in its defined band arithmetic; formal claims remain subject to matching executable source |
| `exact_transcendentals::dyn_crt::WassanRing` | A length-`N` coefficient array over `Z/mZ`, with coefficient-wise ring operations and optional positional I/O interpretation | Integer residue arithmetic; the **ring** and **positional integer** operations are distinct |
| `nine65::entropy::WassanNoiseField` | Historical entropy component, removed under [#68](https://github.com/Skyelabz210/NINE65_v7/issues/68) | Retired; do not cite as active execution or reintroduce without security review |

The 144-band storage description chooses `144` for operand-range provisioning. The actively implemented `WassanRing` has runtime `dimension: usize`; **do not equate it with the 144-band storage system or claim the latter's capacity from this API**.

## Ring versus positional arithmetic

Let `m >= 2`, `N >= 1`, and coefficients `0 <= a[i] < m`.

- **Polynomial residue ring:** elements of `(Z/mZ)[X] / (X^N - 1)`. `WassanRing::add` implements `(a[i] + b[i]) mod m` independently at each slot. `negate` and `scalar_mul` have the same coefficient-wise interpretation. These operations are exact in the specified ring.
- **Positional integer view:** `from_u128` encodes `x = Σ a[i] m^i` when representable; `to_u128` decodes when the result fits. This view needs **carries** for integer addition. `WassanRing::try_add_positional` propagates carries and returns `None` if the `N` slots cannot represent the result.
- **Example:** with `m=997`, `N=2`, coefficients for `996 + 1`: ring addition produces coefficient `0` at the low slot, representing the **zero polynomial**; positional integer addition produces digits `[0, 1]`, representing `997`. Both operations are mathematically exact in their **respective algebraic structures**, which must be named at API/harness boundaries.

No scalar reconstruction occurs in the positional carry loop. Only the final comparison-report I/O decodes into `u128`. The `u128` corridor itself is bounded: `None` means extraction or capacity was unavailable, not that a larger value was represented exactly as a `u128`.

## Input validity and fail-closed requirements

- `modulus >= 2` and `dimension > 0`;
- encode only when `0 <= x < modulus^dimension`; `try_from_u128` rejects higher unrepresented digits;
- widened `u128` intermediate for coefficient addition when `modulus` approaches `u64::MAX`;
- positional addition carries through all slots; final carry triggers `None`;
- report `correct=false` whenever the independent checked-integer oracle is unavailable or the carrier cannot represent the result;
- preserve valid-input **polynomial-ring** semantics of the existing `add` API.

## Verification matrix (complete before merging)

1. **Compile and unit correctness**
   - `cargo fmt --all --check`
   - `cargo test -p exact_transcendentals --lib dyn_crt::tests::wassan`
   - `cargo test -p exact_transcendentals --lib cram_harness::tests::wassan`
   - `cargo test -p exact_transcendentals --lib`
   - `cargo test -p exact_transcendentals --no-default-features --lib`
2. **Boundary vector set**: zero, invalid moduli, zero dimension, insufficient single-slot capacity, one carry, repeated carries, full-capacity overflow, `u64::MAX` modulus, `u128::MAX` encoding and decoding, unsupported negative integer chain, checked ground-truth overflow.
3. **Independent oracle**: compare positional results with Python big integers on exhaustive small moduli/dimensions and reproducible seeded large vectors. This oracle must not call Rust arithmetic helpers.
4. **Performance**: before/after on identical host/toolchain/features, raw integer nanosecond timing samples and medians/dispersion; investigate regressions before accepting.
5. **General A1 audit**: grep *owned executable source*, distinguish integers/rationals/symbolic labels/floating arithmetic; separately inspect golden-ratio oscillator, `φ` convergent code, old benchmark/log artifacts, and any user-visible claims. Avoid inferring universal correctness from this focused PR.

## Open issues / disclaimers

- This focused change addresses the live `WassanRing` constructor, ring addition overflow, positional carry API, and integer add-chain harness. It is **not** a proof of whole-repository A1 compliance.
- Polynomial multiplication or exact multi-band WASSAN HD multiplication has **not** been implemented or certified here.
- Performance claims recorded in historic reports remain historical until reproduced.
- A GitHub PR without green CI and recorded host fingerprints is an **implementation candidate**, not completed verification.
