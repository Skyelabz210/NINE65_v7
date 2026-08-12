# 5th-Operator Corpus — Verification & Reconciliation

**Date:** 2026-08-12. All four Python ledgers were executed on this machine
(Python 3.11, exact integer, zero float) and every assertion passed. This
document records the run results, ties the corpus to the CRAM Opportunity
Index, and gates the one A1-violating artifact.

## Run results (this machine)

| Artifact | Result |
| :--- | :--- |
| `star_lift.py` | SL1–SL8 all VERIFIED: star line, {1,13} mod-36 lattice, the lift, anchor-ladder coprimality, K-elim subtract-negate collapse (36⁻¹ ≡ 36 mod 37), anchor hygiene (single anchor = K mod A only), full ladder recovery, 20,000-case general recovery |
| `operator_space_R.py` | OS1–OS8 all VERIFIED: s = 2 + v2(T_{n-1}) exhaustive to n=3000; Pell orbit self-rooting star primes {37, 352837, 34574401}; R operator exhaustive (2,302 checks over 12 lanes); Sqrt period = ord(2) theorem (50 primes); branch-selection-by-winding unique on all 12,285 branch checks; Berkowitz division-free charpoly exact vs brute force, Cayley–Hamilton exact, lane-native on composite moduli {36,77,5929,30030}; σ₁² isolated to 2⁻²⁰ by shift positivity |
| `division_operator_space.py` | DV0/U1/U2/U3 all VERIFIED (10,858 checks): U1 quotient lanes with zero reconstruction + anchor-ladder naming; U2 shared-factor FPD residue-native (no mixed-radix fuse, no integerized dividend); DIV³ identity on 7 prime lanes |
| `grover_exact.py` | G1–G5: 6,130,924 checks, 0 breaks. 2D-collapse pair recurrence == full vector at every index; depth-2000 exact norm at N=2^20; lane-tracked depth-20,000 with bignum cross-check; exact rational optimal stopping k* = 804; A1 tokenizer self-lint clean. Note: run with `cramlab.py` shim (gen_lanes = first-n odd primes) — original module not in the packet |

## Repo-state claims verified

`division_operator_space.py`'s "verified by direct read" claims are accurate
against this repo: `k_elim_divide` (crates/exact_transcendentals/src/k_elim.rs:272)
does bottom out in `garner_reconstruct` (k_elim.rs:150); `fpd` (k_elim.rs:370)
takes the dividend as an integer; `fpd_one_coefficient`
(cram_ct.rs:1390) uses the mixed-radix fuse. The U1/U2 upgrades are the
residue-native replacements, verified to agree with the repo semantics on
every tested case.

## Index reconciliation

- **[33] reconstruction-retirement** — U1/U2 in `division_operator_space.py`
  ARE the Level-2 method for retiring hot-path reconstruction in division
  (quotient stays in lanes; naming is an anchor-ladder read, not basis-wide
  Garner). Node status: method-of-record staged here.
- **[34] iid-heterogeneous-transduction** — `The5thOperator.md` supplies the
  formal layer: transduction packages (Φ, Θ, Π, Ω), well-definedness,
  exactness, signature preservation, reversibility (T-X-WD/EXACT/SIG/REV),
  and the projection non-reversibility theorem (T-X-PROJ) that governs
  winding policy. Node status: formalization staged here; Rust bridge to
  `ManaStream` remains the open engineering item.
- **[35] prime-family-engineering** — `star_lift.py` + `operator_space_R.py`
  + the packet's `prime-family-spacetime` skill supply the star-prime anchor
  ladder discipline and the R-operator lane attributes (s = v2(p−1) twist
  depth). The arrow-reversibility gate from entry [35] composes with these:
  transport lane selection gates on det(A) mod p ≠ 0 AND the lane's family
  attributes.
- **T-X-PROJ ↔ existing code**: the projection non-reversibility theorem is
  the formal statement behind the witness-lane loud-fail added to
  `extract_k_rns_level` (PR #39) — discarding nonzero winding is never
  reversible, so dissent must be an error, not a fallback.

## Gated artifact

`qcram_composite_lib.rs.pending-defloat` — **A1-VIOLATING as received**;
renamed so it cannot be mistaken for landable code. 19 float sites in 4
zones, all integer-expressible:
1. `nilpotent_census`: `(k as f64 / v as f64).log2().ceil()` → exact integer
   ⌈log₂(k/v)⌉ via `(k + v - 1) / v` then bit-length arithmetic.
2. `OracleResult` recall/enrichment + marking threshold → carry exact
   (numerator, denominator) u64 pairs; compare via cross-multiplication.
3. `compute_qcram_cost`: π/4·√m in f64 → scaled-integer isqrt (e.g.
   milli-iterations: `isqrt(m · 10^6) · 785398 / 10^6`), or keep the cost
   model exact-rational.
4. Test assertions comparing f64 rates → integer-count assertions.
The mathematical content (composite-basis recall, nilpotent depth formula,
CRT-parallel Grover cost, 50%/100% projector theorems) is sound and worth
landing after the defloat pass.

## Not vendored

The full `NS_FIFTH_OPERATOR_PACKET_v2` workspace (239 files, 27 crates,
claimed 503 tests) remains outside this repo — it is its own workspace with
its own Cargo root. Its two skills are installed at `.claude/skills/`
(project-level: `cram-operator`, `prime-family-spacetime`). The packet's
u128-corridor audit and NS regularity reports stay in the upload archive
until a decision is made about a monorepo vs. sibling-repo layout.
