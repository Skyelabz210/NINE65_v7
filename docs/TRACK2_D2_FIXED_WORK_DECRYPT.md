# Track 2: Fixed-Work CompareBit Decrypt Integration

**Assigned agent:** Codex  
**Branch:** `codex/track-2-fixed-work-compare-bit-decrypt`  
**Base:** `main@3f8ac37ff655ca735b26fc31b6030e3320ddeab6`  
**Domain:** D2, secret-holder decrypt/output boundary

## Objective

Use the existing residue-determined half-modulus theorem for every single- and
dual-RNS decrypt centering decision, while giving the secret-dependent decision
kernel one fixed operation shape.

## Implemented route

1. `CompareBit::decide_ct` consumes canonical standard-domain main residues.
2. Idempotent coefficients use the existing fixed-work Barrett reducer, avoiding
   secret-dependent `%` and hardware division.
3. The kernel always forms the parallel idempotent sum.
4. It always executes exactly `lane_count - 1` conditional reductions.
5. Each reduction computes both candidates and selects with a full-width mask.
6. `RNSFHEContext` precomputes one immutable kernel for every supported
   main-prime prefix.
7. Single-RNS decrypt converts its Montgomery residues once, obtains the
   CompareBit decision, and uses that bit for centered decoding.
8. Both dual-RNS diagnostic implementations and the U256 decode path use the
   same fixed-work decision.

The parallel accumulator is confined to the D2 output boundary. Evaluator
kernels must continue to use residue-native transduction and may not call this
helper as a reconstruction shortcut.

## U256 comparison correction

The prior `U256::ge_ct` inferred unsigned ordering from bit 127 of a wrapping
`u128` subtraction. That rule fails when an unsigned difference crosses
`2^127`. The repaired implementation propagates borrow through four `u64`
words and derives an all-zero or all-one mask from the final borrow.

Regression coverage includes values immediately below, at, and above every
64-, 128-, 192-, and 256-bit word boundary, plus deterministic wide random
pairs.

## Independent exact oracle

Run:

```text
python3 scripts/verify_compare_bit_ct.py
```

The harness uses integer arithmetic only and independently mirrors:

- four-word borrow propagation;
- Barrett coefficient reduction;
- fixed-count masked reduction;
- the exact half-modulus predicate;
- every value in three small coprime bases;
- boundary and seeded random values on the current secure-128, secure-192, and
  secure-256 main-prime chains;
- source-contract checks for fixed loop count and decrypt wiring.

Current result:

```text
265360 exact checks
100196 U256 ordering
15135 exhaustive small-basis
150021 production-basis
8 source-contract
```

## Constant-work scope

This track closes the centering-bit kernel’s data-dependent early-return and
fallback-loop behavior. The subsequent plaintext projection still uses the
existing reconstruction and rounded-division machinery at the D2 output
boundary. A full-decrypt timing claim requires a separate branchless projection
route plus empirical instruction, disassembly, and two-class timing evidence.

Source shape is a necessary gate. Hardware behavior must still be measured on
each supported architecture before the constant-time claim is promoted.

## Completion gates

- [x] No floating-point arithmetic added.
- [x] No secret-dependent `%` or division in `CompareBit::decide_ct`.
- [x] Fixed `lane_count - 1` conditional-reduction count.
- [x] No secret-dependent early return in the decision kernel.
- [x] Exact unsigned U256 comparison at all word boundaries.
- [x] Single-RNS decrypt uses the fixed-work decision.
- [x] Dual-RNS u128 and U256 decrypt paths use the fixed-work decision.
- [x] Independent Python oracle passes 265360 exact checks.
- [x] Existing no-floating-point production gate passes.
- [x] The residue-native scanner reports zero prohibited constructs in both
      changed Rust production surfaces. Its repository-wide run remains red on
      21 pre-existing findings in untouched `cram_ct.rs` and `bootstrap.rs`.
- [x] Rust formatting and `cargo test -p nine65 --lib arithmetic::compare_bit
      --release` pass in a Rust-equipped runner. Confirmed 2026-09-03 after
      merging this branch forward onto the WIRE-Q fail-closed baseline
      (#107) and Track 1 T1.1-T1.3 (#103): `cargo fmt --all -- --check`
      clean, `arithmetic::compare_bit`: 10 passed, 0 failed, 1 ignored
      (pre-existing benchmark test, unrelated to this track).
- [x] Full `cargo test -p nine65 --lib --release` passes, modulo five
      pre-existing failures confirmed unrelated to this track (bisected to
      predate #107/#99/#103; see
      `docs/PUBLIC_REFRESH_CORRUPTS_ADMITTED_CONFIGS_2026-09-03.md`):
      813 passed, 5 failed (pre-existing), 124 ignored.
- [ ] Disassembly confirms no data-dependent jump in the fixed-work kernel.
- [ ] Integer-recorded two-class timing evidence is collected on x86-64 and
      ARM before promoting the hardware constant-time claim.

## Boundary with issue #95

This is a secret-holder-side centering improvement. It does not expose or
evaluate the secret-dependent public-bootstrap correction. Public bootstrap
remains fail-closed until the separate #95 encrypted-correction or encoding
migration route is complete.
