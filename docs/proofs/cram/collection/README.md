# K-Elimination research audit

Prepared 12 November 2026, before updating the proof project.

The complete collection is organized through [CRAM_PROOFS_INDEX.md](CRAM_PROOFS_INDEX.md). The [cross-innovation map](CROSS_INNOVATION_MAP.md) connects the checked mathematics to StarLift, shadow11, recumbent arithmetic, rational normalization, transduction, polynomial/lattice queries, native G/H refresh, tropical/continuum charts and coherent anchor towers. Its written deductions and implementation proposals have explicit status labels and an [independent review](cross-innovation-review.md).

Start with [UNIVERSAL_THEOREM.md](UNIVERSAL_THEOREM.md). It gives the universal exact-transport theorem, its constructive ring/integer instances, and the proved one-subtraction/one-multiplication program. The [standalone Lean package](universal-theorem/README.md) freshly compiled 130 declarations. The latest continuation adds 55 declarations proving StarLift, combined-anchor resolution and concrete residue-space divmod/GCD; see [CLOSURE_PROOFS.md](CLOSURE_PROOFS.md).

[EXPANDED_ANALYSIS.md](EXPANDED_ANALYSIS.md) integrates the 22 latest attachments, constructive residue-only division/GCD and polynomial generalization, and current encrypted division tests. [Expanded coverage](expanded-corpus/COVERAGE.md) records the exact scope. The earlier [ANALYSIS.md](ANALYSIS.md) supplies the corrected Nine-Plus Acts, literature and original implementation audit; the [tropical FHE addendum](TROPICAL_FHE_ADDENDUM.md) supplies the exact theta and conservative continuum constructions. [PROOF_UPDATE_SPEC.md](PROOF_UPDATE_SPEC.md) gives the revised formalization order and acceptance criteria.

The central theorem is exact query transport: for observed displacement B and requested displacement C, a unique additive factor on the observation image exists exactly when ker B is contained in ker C. Full lift recovery is a special case; concrete inverse and reduced-congruence programs supply constructive instances. Written domain proofs, source observations, fresh executions, and open questions are labeled separately. The user-specific tropical document has been read; its source gap is closed. The external Wang cryptosystem remains described only by its verified abstract in the retrieved evidence.

The novelty assessment now explicitly separates established arithmetic ingredients from Anthony Diaz's proposed framework, execution method and constructive generalizations. A shared identity or resemblance to one Garner step is not evidence that Garner anticipated the complete contribution. Section6 of the analysis records the claim-level comparison and its limits.

## Frozen sources

* `Skyelabz210/k-elimination-lean4`: `0400092096962e3da45a8e5cbb82185a3c2c38fe`.
* `Skyelabz210/NINE65_v7`: `88a7bdadbf0e1f8fbfdb2b37e9843101b8db3484`.
* First 20 supplied inputs: hashes and sizes in [input-manifest.json](evidence/input-manifest.json).
* Latest 22 supplied inputs, including duplicates and three archives: [expanded input manifest](expanded-corpus/input-manifest.json) and [extraction manifest](expanded-corpus/extraction-manifest.json).

Both original repository checkouts remain unchanged. The included public-root Lean patch is a proposed repair, applied only to a scratch copy. Patched `Basic.lean` compiled; the full repaired root and its axiom queries were not completed. The separate five-module native-refresh arithmetic slice and 130-declaration universal theorem package were freshly checked. The latter includes the nine-theorem `ExactObservation.lean` unchanged. Its [manifest](universal-theorem/verification.json) identifies exactly which generalized and arithmetic statements are now machine checked; remaining domain-specific modules are listed in the theorem report.

## Reproduce the universal theorem package

With the pinned Lean toolchain installed:

```sh
cd universal-theorem
python3 check_proofs.py --lean lean
```

The checker compiles all project modules into a new temporary directory, reuses no project `.olean` file, and audits the axioms of every theorem. It requires no Mathlib. `lake build` also builds this standalone package. Counts include supporting lemmas; the substantive theorem statements and exact scope are in [UNIVERSAL_THEOREM.md](UNIVERSAL_THEOREM.md).

## Expanded independent models and certificate

Run the following standard-library Python scripts from the packet root; each prints its results. The division model also writes its adjacent result file.

```sh
python3 expanded-corpus/experiments/division_generalization.py
python3 expanded-corpus/experiments/portfolio_polynomial.py
python3 expanded-corpus/experiments/framework_checks.py
python3 expanded-corpus/experiments/compendium_residue_divmod_gcd.py
python3 expanded-corpus/experiments/compendium_claim_checks.py
```

With the pinned Lean installed, run `lean +leanprover/lean4:v4.27.0-rc1 expanded-corpus/ExactObservation.lean` through elan, or run the same file with that exact Lean binary. The file prints every theorem's axioms. The existence theorem uses Classical.choice; the other eight have no axioms. This is a mathematical specification certificate, not a production decoder.

Current Rust commands and source hashes are in [runtime.md](expanded-corpus/reviews/runtime.md) and its linked manifest. All 52 targeted current tests passed, including real encrypted integer division. These require the complete pinned NINE65 checkout and dependencies. The bundle does not include that repository or its build artifacts.

## Reproduce the independent models

Python 3.9 or later; standard library only. Run from this directory:

```sh
python3 experiments/verify_claims.py
python3 experiments/corpus_math/check_math.py
python3 experiments/tropical/lattice_observer_checks.py
python3 experiments/tropical_paper_theta.py
python3 experiments/tropical_paper_math/check_paper_math.py
python3 experiments/tropical_paper_code/check_chart_scope.py
```

The first script imports the unmodified supplied historical bootstrap model from `inputs/13-k_elim_bootstrap_corrected.py` to reproduce its counterexamples. This is a clear arithmetic reference, not an encrypted implementation. The corpus model rewrites its adjacent `results.json`. Checked finite domains are recorded in the scripts and report; these counts are not universal proofs or benchmarks.

The newly inspected current repository checkers are copied without changes into `experiments/tropical_source_snapshot/`. Reproduce their clear arithmetic evidence with:

```sh
python3 experiments/tropical_source_snapshot/check_holte_reversibility.py
python3 experiments/tropical_source_snapshot/phase1_tropical_k_elimination.py
python3 -m unittest discover -s experiments/tropical_source_snapshot -p test_public_refresh_lift_refinement.py -v
```

With the pinned Lean4.27.0-rc1 available, the included independent arithmetic proof slice can be checked without Mathlib:

```sh
python3 proof-check/native-refresh-source/check_public_refresh_proofs.py --package proof-check/native-refresh-source --lean lean
```

This fresh five-module build and axiom audit passed. It is separate from the public target repository's failed root build and from verification of encrypted runtime behavior.

## Reproduce the supplied Rust checks

With Rust and Cargo installed:

```sh
cargo test --manifest-path experiments/kelim_build/Cargo.toml --lib --test exhaustive
cargo run --manifest-path experiments/kelim_build/Cargo.toml --bin encoder_demo
cargo test --manifest-path experiments/kelim_build/Cargo.toml --test audit_negative
cargo test --manifest-path experiments/kelim_build/Cargo.toml --release --test audit_negative
```

The crate's original source and tests are unchanged. `tests/audit_negative.rs` is the audit addition. Its passing tests deliberately reproduce finite-range aliasing, a comparison-window limitation, and an intermediate integer overflow. They are evidence of those limitations, not fixes.

The existing NINE65 tropical test requires the complete checkout at the frozen commit; its command and source hashes are in [tropical-bridge.md](evidence/tropical-bridge.md). That checkout and its dependencies are not bundled. The proof build command, parser error, scratch repair, and unavailable cache are recorded in [proof-audit.md](evidence/proof-audit.md).

## Bundle contents and limits

The portable bundle includes reports, the standalone universal proof package and checker, raw execution logs, independent experiment scripts, four copied current arithmetic checkers, the small verified Lean arithmetic slice, supplied Python inputs13/17, the new tropical DOCX and its extraction, the supplied small Rust crate plus audit tests, and the proposed public-repository Lean patch. It excludes toolchain binaries, build outputs, repository clones, the other original attachments, the archived earlier bundle, and bulk literature extracts. The reference list links to the primary literature and identifies abstract-only evidence. Workspace paths in raw logs document where a command was executed; they need not exist on another machine.

`bundle-manifest.json` lists SHA-256 hashes of bundled files. Private memory archives, unrelated portfolio content, build targets and toolchains are excluded. Some findings concern historical examples and must not be transferred to the current NINE65 backend without following its implementation. Fresh encrypted integer division was executed during the preceding corpus phase; this universal-theorem phase adds formal proofs, not new runtime benchmarks. No new full native five-cycle refresh run, full security assessment, definitive novelty determination, or construction-level comparison with Wang's encryption scheme is claimed. Previous packets are preserved under `history/`, including `2026-11-12-before-expanded-corpus/` and `2026-11-12-before-universal-theorem/`.
