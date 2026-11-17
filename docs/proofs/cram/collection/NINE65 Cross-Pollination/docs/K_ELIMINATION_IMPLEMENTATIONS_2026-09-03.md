# K-Elimination implementations — one index for all of them

**Resolves:** issue #70 ("[L3] Consolidate duplicate K-Elimination
implementations (or document why both exist)"), per the issue's own
remediation clause ("Consolidate, or document why both exist"). This is the
document-why-both-exist path. Owner guidance on the issue (comment
2026-08-31): *"First determine whether the two K-Elimination implementations
are production-vs-oracle/specialized roles. Prefer clear discoverable
documentation if distinct; do not refactor cryptographic arithmetic solely to
remove duplication."*

**Why this document exists even though every file below already carries its
own "relationship to the production record" doc comment:** those comments
were added piecemeal, file by file, during the 2026-08-19 G1–G24 audit
resolution pass (commit `26401b0`). Each one is individually accurate and
cross-references the production entry point. None of them, individually,
lists the *other* implementations — a reader who finds one has no way to
discover the rest without grepping the whole tree. The 2026-08-30
"Comprehensive Compendium" audit that opened issue #70 re-flagged the
duplication anyway, which is exactly the discoverability gap this index is
meant to close: one place that names every K-Elimination-shaped
implementation in the workspace, what each one is for, and why it is not the
others.

K-Elimination is the two-residue exact winding-number recovery this codebase
is built on: given `X mod M` and `X mod A` for coprime `M, A`, recover the
unique integer `k` such that `X = (X mod M) + k*M`, `0 <= k < A` — see
CLAUDE.md's project overview and `lean4/KElimination/KElimination.lean` for
the formal statement. The formula is four lines of modular arithmetic, cheap
enough that it has been written down independently, for different reasons, in
at least **seven** places in this workspace. This document is the map.

## The one-paragraph answer

There is exactly **one production implementation**:
`DualRNSContext::extract_k_rns_level` in `crates/nine65/src/arithmetic/rns.rs`,
called from the live encrypt/mul/rescale hot path in
`crates/nine65/src/ops/rns_fhe.rs`. Every other implementation listed below is
either (a) a validated *reference* implementation the production path is
differentially tested against, (b) a formal-verification-target
reimplementation that structurally cannot depend on `nine65` (the crate
dependency graph runs the other way), (c) a leaf-crate duplicate forced by the
same dependency-direction constraint, (d) a staged/CRAM engine not yet wired
into the production hot path, or (e) test/analysis code that exercises the
formula but implements no independent production behavior. None of them can
be deleted or merged into `extract_k_rns_level` without either breaking their
own stated purpose or introducing a dependency-graph cycle. Two of them
(`exact_divider.rs`/`exact_coeff.rs`/`ct_mul_exact.rs`) are a real,
previously-undocumented case of avoidable duplication with no live caller —
flagged explicitly in the table below as the one candidate for future
removal, not merging.

## Index

| # | Implementation | Crate | Role | Live production caller? | Formal-proof target | Tests |
|---|---|---|---|---|---|---|
| 1 | `DualRNSContext::extract_k_rns_level` / `extract_k_rns_level_cached` (`arithmetic/rns.rs`) | `nine65` | **Canonical production K-Elimination.** Multi-anchor RNS lane vectors, U256 arithmetic, per-level main-prime subsets, cached inverses. | Yes — `ops/rns_fhe.rs`: `k_elim_rescale_dual`, `extract_digit_dual`, `mul_dual_public`, `mul_dual_symmetric` | No dedicated Lean/Coq file; exercised by `depth2_isolation.rs`, `time_crystal_verification.rs` differential tests | Extensive unit + integration coverage in `rns.rs` and the `tests/` files above |
| 2 | `KElimination` / `AdjacencyKElim` (`arithmetic/k_elimination.rs`) | `nine65` | **Validated, CT-tested, two-modulus reference implementation.** Fixed `(alpha, beta)` scalar split, branchless CT primitives (`sub_mod_u128_ct`, `mul_mod_u128_ct`), the one piece of K-Elimination code with a matching Lean lemma. Backs the legacy single-modulus BFV path (`ops::homomorphic::BFVEvaluator`) and the quarantined Clockwork bootstrap paths. | Yes, but to the *legacy/quarantined* paths, not the live DualRNS hot path | `lean4/KElimination/KElimination.lean`, `lean4/KElimination/Basic.lean` (current formalization of record); legacy `proofs/coq/KElimination.v` (not the verification basis, see CLAUDE.md) | 36 inline tests + `tests/k_elimination_basis_regression.rs` (4) + `crates/nine65-extreme-tests/src/k_elimination_extremes.rs`; target of `nine65::security::ct_verification`'s statistical CT suite |
| 3 | `KElimResidueDivider` (`arithmetic/kelim_residue_divider.rs`) | `nine65` | `BoundedResidueDivider` implementor generalizing the winding lift to the multi-lane "coupled-anchor law" (an anchor *set* folded into one resolution, not per-lane inversion). Built directly on #2's primitives. | **No.** Its own module doc states this explicitly and names a real open conflict with the `BoundedResidueDivider` trait contract (assembling a scalar `X` as an internal step vs. the trait's "may not fall back to full integer reconstruction" rule) that must be resolved before it is wired in. | — | 8 inline tests, including a differential test against #2's `KElimination::extract_k` |
| 4 | `k_eliminate_ct` / `garner_decompose_ct` (`clockwork-core/src/garner.rs`) | `clockwork-core` | **Formal-spec reference implementation** for Clockwork's own Garner/K-Elimination theorems (T2, T16). Reimplements the branchless CT mask pattern locally because `clockwork-core` cannot depend on `nine65` (dependency direction runs `nine65 -> clockwork-core`, not the reverse) — see the module's own "G14 correction" note. | No — this crate is the formal-spec/bound-tracking layer, not the FHE engine | Clockwork Formal Spec §2.1 D5–D6; cross-referenced from `docs/FORMALIZATION_INDEX.md` | 4 inline tests; part of `clockwork-core`'s 46-test suite |
| 5 | K-Elimination engine (`exact_transcendentals/src/k_elim.rs`) | `exact_transcendentals` | **Staged CRAM method-of-record.** Arbitrary-length coprime basis (`&[i128]`), not a fixed two-modulus split; internal primitive for that crate's own CRAM machinery (`cram_anchor`, `cram_machine`, `cram_ops`, `cram_pde`, `crt_torus`, `transduction`). Explicitly documented as the eventual CRAM-architecture migration target, not deleted or merged. | No — `exact_transcendentals` is a dependency-free leaf crate `nine65` depends on, not the reverse; nothing in `nine65`'s live hot path calls into it | — | 26 inline tests; cross-checked against #1 by `nine65`'s own `basis_invariance.rs`, `residue_space_ciphertext.rs`, `noise_profile.rs`, `depth_and_noise.rs` |
| 6 | `KAnchor` (`mana/src/anchor.rs`) | `mana` | **Zero-dependency duplicate** of #2's formula, bit-for-bit identical prime constants (`KElimConfig::Standard`). `mana` is deliberately a zero-dependency leaf crate; `nine65` depends on `mana`, not the reverse, so this file cannot import `nine65`'s implementation without a dependency cycle. | No — `KAnchor`/`AnchorContext` are reachable only through `nine65::accelerated::AcceleratedContext`, which nothing in `nine65`'s own src/tests/benches currently calls | — | 4 inline tests |
| 7 | `k_eliminate` / `k_reconstruct` (`math_utils/src/lib.rs`) | `math_utils` | Intended future single-source-of-truth primitive for QMNF/CRAM/Hydra crates; **not yet adopted by any of them** (no crate in the workspace declares a dependency on `math_utils`). Documented on the module itself as aspirational, not current. | No | — | 11 inline tests |
| — | `KElimParams::compute_k` and friends (`security_proofs/src/k_elimination_attack.rs`) | `security_proofs` | **Not an implementation duplicate.** A standalone cryptanalysis harness that re-derives the formula only to attack it (timing side-channel analysis, inversion-attack search) — its purpose is adversarial analysis of #1/#2's algebraic structure, not providing exact division to any caller. Listed here only so a grep for "K-Elimination" does not mistake it for an eighth production candidate. | No — it is a security-analysis tool | — | 0 `#[test]`-annotated (analysis/report code, exercised via its own binaries) |

## The one genuinely avoidable duplication found while indexing this

`ExactDivider` (`arithmetic/exact_divider.rs`), `ExactContext`/`ExactCoeff`
(`arithmetic/exact_coeff.rs`), and `ExactCiphertext`/`ExactFHEContext`
(`arithmetic/ct_mul_exact.rs`) form a third scalar-pair `(main, anchor)`
K-Elimination chain, structurally close to #2 (`KElimination`) — same shape,
same "Proof File: `ExactCoefficient.v`" claim — but with none of #2's
hardening: `assert!`-based construction instead of a fallible `try_new`,
variable-time `gcd`/`mod_inverse` instead of #2's `_ct` primitives, and no
`Nine65Error` integration. Unlike every implementation in the index above,
this chain carried **no doc comment explaining its relationship to
`KElimination` or to the production path** before this pass — a real
discoverability gap, now closed by a pointer comment in each of the three
files.

Its only non-test caller is `gso_fhe.rs`'s own
`#[cfg(all(test, feature = "shadow-entropy"))] mod arithmetic_benchmarks`
timing comparison; `rns_fhe.rs` references `ct_mul_exact.rs` only in comments
(`"The working solution is in ct_mul_exact.rs with single modulus"`) pointing
at its tests, never at runtime. It has no live production caller today.

This is left in place rather than deleted or merged in this pass, for the
same reason the task guidance for issue #70 asks for: this is
security-critical exact-arithmetic code, and a merge is a decision that
deserves its own reviewed change, not a side effect of a documentation pass.
It is recorded here as the one honest candidate for a future *removal* (not a
merge into `KElimination` — the two have diverging validation behavior that
would need to be reconciled first) if `gso_fhe.rs`'s benchmark comparison and
`ct_mul_exact.rs`'s tests are ever retired.

## Practical guidance

- **Writing new production FHE code?** Call `extract_k_rns_level` /
  `extract_k_rns_level_cached` via `DualRNSContext` (#1). Nothing else in this
  list is wired into the live encrypt/mul/rescale/decrypt path.
- **Writing a scalar reference test, a KAT, or code for the legacy
  single-modulus / quarantined bootstrap paths?** Use `KElimination` (#2) —
  it is the validated, CT-tested, proof-backed one.
- **Extending `BoundedResidueDivider`?** Read `kelim_residue_divider.rs`'s own
  module doc (#3) in full before touching it; it documents an open,
  unresolved conflict with the trait contract, not a subtle detail.
- **Working inside `clockwork-core` or `exact_transcendentals`?** Their
  K-Elimination code (#4, #5) is intentionally local — do not add a
  dependency on `nine65` to "fix" the duplication; that inverts the
  workspace's dependency graph.
- **Auditing for duplication again later?** Start from this table. If a new
  K-Elimination-shaped implementation shows up that isn't in it, that's the
  actual gap — add a row here rather than re-deriving the whole picture.

See also: CLAUDE.md's Repository Structure section, `docs/ARCHITECTURE.md`'s
"K-Elimination Component" section, `docs/FORMALIZATION_INDEX.md` (Lean/Coq
correspondence for #2 and #4).
