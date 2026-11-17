# Proof-source and fresh-build audit

Audit date: 2026-11-12. Scope: the supplied `k-elimination-lean4` repository and proof-relevant attached documents, not a certification of NINE65 runtime or cryptographic security.

## Frozen source and evidence

- Repository: `https://github.com/Skyelabz210/k-elimination-lean4`.
- Commit: `0400092096962e3da45a8e5cbb82185a3c2c38fe`.
- Original checkout: `/workspace/k-elimination-audit/repo`; no edits made by this audit worker.
- Scratch build copy: `/workspace/k-elimination-audit/proof-check/source`.
- Toolchain: `leanprover/lean4:v4.27.0-rc1`, release commit `2fcce7258eeb6e324366bc25f9058293b04b7547`.
- Mathlib lock: `3bdc7047b97538f795b725dc0713c28c0f53ed10`; `lake-manifest.json` in scratch remained byte-identical after dependency checkout.
- There are 27 `theorem` declarations in `KElimination.lean`, three more in `KElimination/Basic.lean`, and 11 Coq `Lemma`/`Theorem`/`Corollary` declarations. Counts are not independent mathematical contributions.

Read in full: both Lean files, Coq source, README, FAQ, extracted attachment 9, attachment 12, attachment 15, attachment 19. Read proof-relevant sections of attachment 3 and compared its appendix/tower claims against attachment 9; attachment 3 is a PDF rendering of substantially the same paper, not an independently verified development. The entire original attachment corpus is not assigned to this worker. Other repositories and all NINE65 runtime integration are outside this worker's audit.

## EXECUTED: current root build is broken before theorem elaboration

The exact pinned source fails:

```text
ELAN_HOME=/workspace/k-elimination-audit/proof-check/elan LEAN_NUM_THREADS=4 \
  /workspace/k-elimination-audit/proof-check/elan/bin/lake --no-cache build
```

Exit status 1. `proof-build.log` records:

```text
error: KElimination.lean:26:0: invalid 'import' command, it must be used in the beginning of the file
```

Cause: the newly added scope clarification starts with `/-!` at line 1. That is a module-documentation command, not an ordinary block comment. It appears before imports at lines 26–29. Moving the module documentation below imports, or changing the leading opener to `/-`, is a small syntactic repair. The correction was applied **only in the isolated scratch copy**, documented in `proof-scratch-repair.log`, so mathematical proof checking can proceed separately from this regression. A successful repaired scratch build would not mean the unchanged pinned source builds.

The independent `KElimination/Basic.lean` also fails on the pinned Lean toolchain (`proof-basic.log`, exit 1):

- Line 22: `omega` cannot establish the fundamental div/mod identity without the relevant equality being supplied.
- Line 33: Lean cannot infer implicit `x` and `y` in the untyped `have h := Nat.div_lt_iff_lt_mul hM`; line 31 then retains an unsolved goal.

The root file does not import `KElimination.Basic`. Thus checking only the root target is insufficient coverage of every Lean file.

A minimal proposed patch is saved at `proof-check/suggested-parser-and-basic.patch`, covering the comment opener and the two Basic proofs. The patched **scratch Basic file was freshly checked successfully** by pinned Lean (exit 0, `proof-basic-scratch.log`; only unused-variable warnings). The full root after the comment change remains unverified because the Mathlib source build was stopped before completion. Original checkout remains untouched.

## SOURCE OBSERVED: what the main soundness theorem actually says

`Soundness.k_elimination_sound` (root Lean lines 265–331) accepts:

1. `cfg : RNSConfig`, with positive natural moduli `M,A` and `Nat.Coprime M A` (lines 62–67);
2. a natural number `X` and `X < M*A`;
3. a natural `M_inv` with an **explicit supplied proof** `(M*M_inv)%A = 1`.

It concludes the exact natural equality

```text
((((X % A) + A - ((X % M) % A)) % A) * M_inv) % A = X / M.
```

This is a correct bounded quotient-recovery statement. The subtraction carefully reduces the main residue modulo A before subtracting, ensuring natural subtraction does not truncate incorrectly. The proof establishes the congruence in `ZMod A`, then uses `X/M<A` to choose the unique natural representative. It does not assert primality of either modulus.

`modular_inverse_exists` (lines 133–157) proves existence of a witness for coprime `M,A` with **A>1**. It uses Mathlib's `ZMod.unitOfCoprime`, not a verified extended-Euclidean implementation. For A=1, the configuration type is inhabited but `(M*M_inv)%1=1` is impossible; the main theorem therefore has no instances at that degenerate anchor. A separate A=1 statement, or a stronger config invariant A>1, would make that boundary explicit.

The following stronger conclusions are absent from the theorem's statement:

- that a runtime reads independently authenticated same-source residues rather than calculating both from a supplied scalar X;
- an implementation that obtains `X mod M` from a vector of smaller residues with a stated operation cost;
- persistent state layout, no carried scalar K, no hidden reconstruction, or concurrency;
- a general integer division dispatcher, non-coprime FPD, signed order, arbitrary anchors, transduction metadata preservation, or anchor-tower closure;
- any ciphertext semantics, encrypted producer-to-consumer path, noise bound, security reduction, leakage theorem, or physical timing claim.

The new scope note and README lines 3–22 acknowledge these distinctions; older assertions elsewhere remain inconsistent with it.

## SOURCE OBSERVED: several names are broader than their conclusions

| Declaration | Actual proposition | Consequence for proof claims |
|---|---|---|
| `key_congruence`, lines 114–117 | Substitution of Euclidean division identity into `%A` | Correct universal algebraic identity; not by itself an extraction algorithm |
| `kElimination_core`, lines 183–194 | `X/M<A` and the congruence | Does not use an inverse or prove the computed quotient equals the true one |
| `kElimination_unique`, lines 197–200 | `(X/M)%A=X/M` under bound | Bounded representative lemma, not a uniqueness theorem for all residue encodings |
| `division_exact`, lines 235–236 | `d divides X -> X%d=0` | No algorithm, no general division proof |
| `division_correct`, lines 239–243 | Ordinary natural quotient/remainder laws | No RNS representation or kernel refinement |
| `k_elimination_complete`, lines 333–341 | `(vM+k*M)/M=k` when `vM<M` | The `_hk:k<A` premise is unused; not operational completeness |
| `detect_coprimality_violation`, lines 353–355 | Rewriting non-coprimality as `gcd≠1` | Logical equivalence, not runtime validation of provenance/range |

## Complexity proof is an assigned model

Lines 247–257 define `k_elimination_complexity k l := k+l` and `mrc_complexity k := k*k`, then prove the arithmetic inequality `k<k*k` when `k>1`. No operational semantics, instruction counter, algorithm implementation, word width, preprocessing, representation conversion, memory cost, hardware depth, or extraction theorem connects those definitions to the actual mechanisms. The proof of this inequality is useful as a model calculation but cannot substantiate an asymptotic implementation comparison. The top-of-file clarification explicitly says so.

The informal historical reconstruction in `docs/K_ELIMINATION_THEOREM.md` lines 145–158 reconstructs both large residues then combines them. Its exact division routine lines 175–185 and 487–524 reconstructs X, divides it, and re-encodes. Those examples conflict with current residue-native execution intent if placed in the compute path. Preserve them as historical examples or declared-boundary routines; do not treat them as proof that the current intended architecture has been implemented.

## Coq cross-validation is strictly weaker than Lean soundness

Read all 173 lines of `coq/K_Elimination.v`. `k_elimination_core` (134–143) proves only the quotient bound plus div/mod substitution; `k_unique` (145–152) proves a bounded modulo identity. There is no coprimality hypothesis, modular inverse, computed phase formula, or proof equating computed K with `X/M`. Thus it independently covers elementary lemmas underlying extraction but **does not cross-validate the full extraction theorem** in a second prover. The source contains 11 proofs and no declared axioms/admitted goals. A current Coq compiler was not found; bundled `.vo` files are historical artifacts, not fresh execution evidence.

README lines 168–175 and attachment 12 lines 191–193 should identify this narrower scope. The source counts 11 Coq results, whereas the README table and technical paper say 10. `0 sorry` also does not mean “no assumptions”: FAQ lines 69–70 are wrong because the theorems have explicit range/inverse premises; proof-assistant foundational axioms must be reported separately from unproved project axioms.

## Concrete false printed formulas

### FAQ purported soundness theorem

FAQ lines 97–100 show an alleged Lean formula subtracting `X%M` directly after adding only one A. The actual source reduces `X%M` modulo A first. Under natural subtraction, the FAQ display is false. With M=5, A=2, X=8, all intended coprimality/range premises hold and `X/M=1`, but `(X%A+A-X%M)` is `0+2-3=0` in Nat, yielding zero. Use the actual source formula or perform subtraction in `Int`/`ZMod`.

### Attachment 9 / PDF3 Appendix A

Extracted attachment 9 lines 413–431 purports to provide sorry-free Lean proofs by `omega` for core, dual and tower formulas. They use `Nat` subtraction, omit necessary hypotheses in core/dual, and are not the source theorem in this repository.

- Core: M=3,A=5,X=5. True quotient is 1; `X%A-X%M=0-2=0` in Nat, so displayed RHS is zero, even though the moduli are coprime and X<MA.
- Dual: M=5,A=3,X=5. True `X/A=1`; displayed natural difference again truncates to zero.
- Tower: its extra coprimality premise does not fix the same subtraction error.

The expressions `(M⁻¹ : ZMod A)` also put the inverse notation around a Nat-typed variable instead of first casting M into ZMod; the intended formal expression should be unambiguous, e.g. `((M : ZMod A)⁻¹).val`. The counterexamples already invalidate the claimed statements under their intended modular-inverse reading. Printed `by omega` does not constitute evidence of compilation. The header “sorry-free” must be replaced by a link to tested source or marked draft.

Attachment 9 §7's pair-observer equation is mathematically valid for arbitrary nonnegative X (no total product bound needed), but its proof says `X<∏M_i` implies `X<M_i*M_{i+1}` “when further residue-constrained” (line 267). That implication is false without additional constraints. For (2,3,5), X=10 is below 30 and above 6. Correct proof: derive the unbounded quotient congruence directly. Do not interpret observers `floor(X/M_i) mod M_{i+1}` as nested quotients `floor(floor(X/M_i)/M_{i+1})`.

The paper correctly says its table returns **modular** k-values (line 292), which should govern its broader prose. Adjacent-pair coprimality and subtraction collapse are sound. The “three logically independent conditions” wording at line 127 is false because adjacency implies coprimality. A prime anchor does not by itself imply coprimality: M=14,A=7 is a counterexample. The resolution table's row `d=M -> resolution 1` is false unless A=M; e.g. M=3,A=6 has d=M and A/d=2.

## Attached broad proof claims need their own missing bridges

Attachment 15 is a prose proof compendium, not Lean source. Its ordinary CRT summation argument is sound. Several later implications do not follow:

1. Lines 137–142 infer zero mutual information of physical power traces from parallel lanes and constant-time execution. A constant-time computation of a secret bit still leaks it under a Hamming-weight leakage model. Independence of scheduling does not imply independence of data-dependent power. No leakage model or masking proof is provided.
2. Lines 156–186 assert any single-lane corruption is detected. Full-range CRT with no independent redundancy maps every residue tuple to a valid integer. For S8, (0,0,...,0) and (1,0,...,0) encode 0 and 4,849,845; both pass reconstruction and re-reduction. If `x` in the claimed check is an independently authenticated true value, detection has an additional witness assumption; if x is reconstructed from the corrupt tuple, all discrepancies are zero.
3. Lines 194–218 infer noise conservation from a symbolic “resonance order” inequality and integer arithmetic. No norm bound relates that order to FHE decryption error. Exact computation of floor division does not imply zero rounding relative to rational division. The displayed inverse of a product also needs an explicit modulus in which it is a unit.
4. Lines 226–241 conflate invertibility of scaled encoding `x -> Δx` (with suitable domain/range) and invertibility of `x -> floor(x/Δ)` on all integers. The latter collapses 0 and 1 for Δ>1. Retaining a remainder or restricting input to Δ-multiples is necessary. Absence of floating point is not absence of truncation.

These are counterexamples to those stated inference steps, not a claim that every NINE65 implementation has those defects.

Attachment 19 has many valid elementary proofs (CRT, Euclidean inverse, bounded K, arbitrary projection given exact r,K, lexicographic order, componentwise scheduling, finite group periods). Its historical “carried identity” should be read as mathematical specification or superseded storage policy, since current intent is on-demand K.

Additional qualifications for attachment 19:

- T5's statement that Fermat inversion works “only when m is prime” is too strong; some composite moduli/bases satisfy it, e.g. Carmichael moduli for all units. The correct implementation rule is that primality is a sufficient general guarantee, while extended Euclid is valid for every unit.
- T12's O(log N) affine iterate is achievable via powering affine maps or doubling a power/geometric-sum pair even if a−1 is a nonunit. “Else the sum directly” in lines 197–198 alone describes an O(N) fallback, not that logarithmic algorithm.
- T14 correctly identifies injectivity with zero conditional input entropy for a full-support finite input. Its assertion that information loss must “break the homomorphism” (lines 233–234) is false: the canonical homomorphism Z/6Z -> Z/3Z is noninjective. Statistical IID, logical reversibility and homomorphism preservation are separate properties.
- T15's cube map on all units mod11 has order four, but it is a square-root selector only on quadratic residues, as the theorem's first sentence already restricts.

## Proposed proof update order

1. Repair the root import-order regression and the unused Basic module; build every Lean source explicitly.
2. Separate universal quotient-congruence, bounded exact recovery, and inverse existence. Add signed integer conventions and A=1 policy.
3. Prove the gcd-reduced congruence and kernel/ambiguity characterization; prove fusion and uniqueness intervals separately.
4. Specify authentic residue observations, provenance/epoch, representation invariants and optional declared reconstruction boundary before implementation refinement.
5. Formalize actual quotient/remainder division and transduction, including refusals, rather than naming ordinary division identities “complete.”
6. Keep complexity definitions as a named abstract model until connected to executable kernels and explicit bit/word/depth accounting.
7. Replace stale README/FAQ/appendix theorem displays with generated statements from the current compiled sources. State the actual axioms and exact Coq overlap.
8. Keep FHE, physical side-channel and continuum claims in separate developments with their own semantics and bridge theorems.

## Build follow-up status

The default Azure Mathlib cache endpoint returned CONNECT 403 for all attempted downloads (`proof-cache.log`). The repetitive failed downloads were stopped. Dependency sources were fetched successfully, and a scratch source build after the comment-only parser repair began successfully compiling dependencies. It was stopped at the parent auditor's request to keep this deliverable focused on research rather than a full Mathlib rebuild. This is not a mathematical proof failure; the exact repository build already has the independently reproduced import-order error. No successful root rebuild or fresh `#print axioms` result is claimed. `proof-check/source/Audit.lean` records the requested axiom queries plus an uncompiled proposed abstract ring-unit extraction lemma and decidable counterexample fixtures. Do not cite the proposed lemma as machine checked.
