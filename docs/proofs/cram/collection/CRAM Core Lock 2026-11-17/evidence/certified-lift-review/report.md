# certified_lift and PROOFS.pdf audit — 2026-11-17

## Scope and reproducibility

Reviewed all of `certified_lift/src/lib.rs`, every supplied test and example by source inspection, and all six pages / twenty numbered results of `PROOFS.pdf`. The archive was checked for traversal, links, and special files before extraction. Original uploads were preserved. Only the extracted review copy received a new `tests/review_contract.rs`; no canonical repository was changed.

- Tar SHA-256: `42530547da553ee30ca6bb1403ae59ca49c96eb617399dddcd71e7ff0fb169dc`
- PDF SHA-256: `3ec3c73b212a0d152f070f8995437fc08f9a92eb4676498eb2f9852dbdb79c2a`
- Toolchain: `rustc 1.89.0 (29483883e 2025-08-04)`, x86_64 Linux.
- Locked dependencies: num-bigint 0.4.8, num-traits 0.2.19, num-integer 0.1.47, autocfg 1.5.1.
- Original suite: **19 tests passed**, 0 failed, 0 ignored. Log: `cargo-test-debug.log`. There are no original Rust unit/doc tests beyond these integration tests.
- Independent contract checks: **4 passed in debug and 4 in release**, meaning the tests successfully exposed the stated defects/limitations. Logs: `review-contract-debug.log`, `review-contract-release.log`.
- No Lean/Rust source refinement proof is supplied in this crate. The PDF is handwritten mathematics with reported finite witnesses; those separate witness scripts are not contained in this tar.

Reproduction prefix:

```sh
export PATH=/workspace/.tooling/cargo/bin:$PATH
export CARGO_HOME=/workspace/.tooling/cargo
export RUSTUP_HOME=/workspace/.tooling/rustup
export CARGO_TARGET_DIR=/workspace/scratch/cram-lock-2026-11-17/certified-lift-review/target
cd /workspace/scratch/cram-lock-2026-11-17/certified-lift-review/certified_lift
cargo +1.89.0 test --locked --no-fail-fast
cargo +1.89.0 test --locked --test review_contract -- --nocapture
cargo +1.89.0 test --release --locked --test review_contract -- --nocapture
```

The first command now also includes the added review tests. The archived original-suite log predates their compilation and records the original 19 tests separately.

## What works and can be reused

The code provides an actual executable constructive producer, not just a readout receiving hypothetical residues. A single shell modulus and pairwise-coprime anchors represent an unsigned value with `U < W`, or a signed value with `2U < W`, `W = M * product(anchors)`. Checked arithmetic updates every actual lane before returning the new representation. Signed comparison uses a common nonnegative bias rather than an invalid one-bit parity sign rule.

Composite lanes are supported: constructor pairwise-GCD checks and extended Euclid replace Fermat inversion. `u128` intermediates protect the lane add/multiply/subtract operations at `u64` width. Existing tests exercise adjacent composite pairs, arbitrary coprime composite bases, 127/128-bit windows, signed values, growth, and capacity refusal. Supplied counters confirm a single anchor does not need multi-anchor combination.

`Machine::grow` and `SMachine::grow` derive a temporary quotient from still-valid old observations and project into the new lane before the old frame aliases. This is a useful concrete candidate for the frame-change proof obligation. It does not manufacture a residue after information has been lost. Reserving divisors and preserving live factor certificates through lane selection are coherent specialized mechanisms.

The Shenoy–Kumaresan-style path correctly restricts use by a value-bound certificate: the quotient must fit the regular-anchor product, and the redundant modulus must exceed the possible rank. It falls back to a direct CRT combination of quotient readings when this condition is absent. The original SK equality/route-selection tests passed.

## Blocking findings for admission into locked CRAM

### CL-01 — missing frame identity makes the certificate unsound through public APIs

`Lift` and `SLift` have private fields (`lib.rs:57,62`), but no frame identifier or lifetime tying them to a `Kernel`. Public arithmetic/readout methods accept values from any kernel and do not check lane count, order, moduli, source generation, or the bound against the receiving frame.

Executed counterexample:

1. `Kernel::new(36, &[37]).lift(1000)` gives residues `[28,1]` and bound 1000.
2. Pass that `Lift` to `Kernel::new(35, &[37]).add(foreign, zero)`.
3. The operation succeeds with `[28,1]`, still claiming `U=1000`.
4. In the receiving frame this tuple is **1148**, so the promised `X <= U` is false.

The same public interface accepts a shorter foreign frame and panics at `lib.rs:174` while reading a missing anchor. Both behaviors reproduce in debug and release. This is a concrete Rust API invariant failure, not a failure of K-Elimination algebra. Require frame-bound values and checked mismatch refusal, including stale clones after growth. Private payload fields alone do not establish provenance.

### CL-02 — no named K field, but persistent magnitude is present

There is no persistent payload field named K. Derived K values are temporaries, which is compatible with on-demand winding. However, `Lift.bound: BigUint` is initialized to exactly `x` (`lib.rs:184–187`) and `SLift.bound` to exactly `abs(x)` (`:228`). Unsigned addition and multiplication propagate this scalar exactly when the input bounds are exact (`:189–196`). Consequently an add/multiply-only computation maintains the complete value in an independent BigUint track.

Executed example: lift 100 and 200, multiply, then add 100. Public `.bound()` exposes **20000**, then **20100**, exactly the represented result. `tighten` additionally persists an upper endpoint computed as `K*M + M-1` (`:220–224`). The claim that no function assembles X is too broad under the owner's no-independent-scalar-magnitude contract. This is not merely a harmless renaming issue: the scalar track performs arbitrary-width arithmetic and can supply the exact value over common operation paths.

A repair needs an explicitly authorized bound policy (e.g. public input envelopes with provenance, conservative profile/range certificates, and an audit of whether tightening encodes prohibited payload), not just deleting a field called K. No claim is made that mathematical upper bounds are intrinsically forbidden.

### CL-03 — division is a narrow certified inverse route

`divide` (`:210–216`) requires the divisor to be a unit in **every** lane and requires a matching entry in a tracked constant-factor map. This proves a useful partial exact-division route when its invariant holds. It does not implement Euclidean quotient/remainder, GCD, nonunit division, or general exact divisibility discovery.

Executed: directly loaded 140 divided by 7 returns `UnknownDivisor(7)` despite exact divisibility; division by 2 returns `NotCoprime(2)` in shell 36; even division by 1 returns `UnknownDivisor(1)`. Distinguish an unsupported but valid operation from an arithmetic error. Factor maps appear conservative for their intended constructor/operation history; that observation does not fix CL-01.

### CL-04 — cost and conformance must include actual BigUint operations

`derive_k_lanes` (`:171–180`) directly CRT-combines multiple anchor quotient residues into a full temporary BigUint K; `derive_k_sk` (`:111–123`) also constructs a wide sum before subtracting the rank correction. This is not Garner and is not a persisted K ledger. It is nevertheless wide arithmetic, so a one-subtraction or two-fixed-word-operation cost claim describes only the single-anchor local query. Growth, bounds, multi-anchor combination, allocation, and exact inverse setup have their own costs.

The supplied `skbench.rs` compares two temporary-K assembly routes and consumes only the low limb of their returned BigUint. It is not the same benchmark as a scalar alpha-only primitive or full output-limb consumption in the new arbitrary-composite harness. It was source-reviewed, not timed in this audit.

### CL-05 — growth and refusal semantics require a declared transaction contract

The machine tightens bounds and can grow the frame before a requested arithmetic operation ultimately returns an error. Numeric register values can remain unchanged while representation metadata, frame, counters, and capacity have changed. The locked specification must say whether this is permitted; it is not an atomic no-change refusal by construction. Growth searches descending moduli and respects a finite anchor cap, so it is not an unbounded runtime guarantee.

## PROOFS.pdf: theorem-level disposition

- **T1 CRT; T2 K-Elimination; T2b adjacency; T3 projection; T4 lexicographic order; T6 lane arithmetic/exact unit division:** ordinary proofs are sound under positive-modulus, canonical-remainder, actual-source, divisibility, and stated-range premises. Correctness of these identities is not implementation refinement. T3/T4 describe a carried coordinate; current CRAM can use the same equations with K ghost-only or derived.
- **T5 inverse discipline:** extended Euclid is appropriate. Wording that Fermat `a^(m-2)` equals the inverse *only* for prime m is false. Composite Carmichael modulus **561** is a counterexample: all **320** units satisfy the inverse formula (checked independently). Correct wording: prime-modulus Fermat assumptions cannot justify the formula for arbitrary composites; extended Euclid is uniformly valid for units.
- **T7 lane scheduling:** disjoint coordinate updates commute. This proves schedule independence for that product map, not statistical IID or automatic synchronization of arbitrary coupled lanes.
- **T8/T8b oscillators:** finite-group orders give exact modular recurrence, subject to the stated unit/prime domains. This does not establish physical oscillator synchronization.
- **T9/T10 Safe Basis and shared-factor observations:** correct finite CRT injection/fiber statements. Extra arbitrary-modulus readouts require a source/readout producer; they do not grant inverse division through a nonunit. A bijective identification in a finite lap is not unbounded state capacity.
- **T11 order via components and T11b factor from order:** valid mathematical statements. Lane factorization/order availability and cost remain external inputs; they do not establish fast arbitrary integer factorization.
- **T12 affine folding (numbered theorem 15):** the geometric sum identity is correct. When `a-1` is nonunit modulo m, an inverse does not exist; evaluating the sum directly costs O(N), so the printed fallback does not justify the universal O(log N) algorithm claim. Use division-free paired exponentiation of `(a^N, sum_{j<N} a^j)` or 2x2 affine matrix powering for the correct O(log N) modular-operation route. This is a concrete useful operator candidate.
- **T13 orientation:** lexicographic order and deck translation are sound for the chosen integer orientation; they do not select a physical time arrow. On nonnegative integers the successor is injective, not surjective onto the same set; inverse statements need image/domain restrictions.
- **T14 shadow entropy:** for uniform finite input, `H(X|g(X))=0` iff g is injective, and uniform L-to-one maps lose log2(L) bits. But noninjectivity is not equivalent to breaking a homomorphism: modular quotient maps are homomorphisms and noninjective. Coprime lane packing/fusion can be bijective, so 'fusing lanes' is not synonymous with erasure. Information loss and exact arithmetic must be specified independently.
- **T15 square root:** exponent `(p+1)/4` is valid for nonzero QR input at primes p=3 mod4. On F11*, cubing is an order-four permutation, but it is a square-root function only on quadratic residues. For example cube(2)=8 and 8^2=9 mod11, not2; the domain qualifier matters.
- **T15b Cipolla:** standard valid field-extension proof for the stated odd-prime/QR/nonresidue setup; the `xp*x=x*x` cancellation step uses x nonzero. If zero is included as a QR, handle it separately.
- **T16 transduction:** universal projection gives the desired target residue when r and sufficient K information are authentic. It does not prove the implementation producing that information, source binding, performance, arbitrary square-root branch consistency, or the entire heterogeneous transduction contract.

## Recommendation for the CRAM ledger

Admit this as an **EXECUTED reference prototype and source of reusable kernels**, with CL-01/02 blocking direct conformance promotion. Add its signed-bias comparison, pre-alias projection growth, unit-divisor history certificates, and bounded redundant-anchor route as concrete proof targets. Do not label the crate production-ready, whole-CRAM complete, zero-scalar-magnitude, or Rust-formally-verified. Preserve the PDF as prose mathematics; port the useful corrected statements to the maintained Lean proof stack with their actual premises.
