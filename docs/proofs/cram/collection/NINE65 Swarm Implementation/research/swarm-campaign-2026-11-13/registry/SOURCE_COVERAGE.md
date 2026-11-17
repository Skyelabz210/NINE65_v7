# Campaign source coverage and recovered mechanisms

Captured 2026-11-13. The registry contains **181 source records**: 42 supplied top-level files, 108 selected extracted artifacts, eight repositories including the Rust Guide, nine freshly read public source excerpts, five scoped private Drive reads, eight primary leads not fetched this campaign, and one unavailable linked chat. All **150 original/member byte hashes match** the prior intake manifests. The source instances remain separate when their bytes are identical.

[sources.jsonl](sources.jsonl) is the canonical source list; [lineage.json](lineage.json) records source pins, concrete reuse candidates and scope boundaries. [corpus_validation.json](corpus_validation.json) records the checks. No historical test count is counted as a fresh campaign result.

## Intake and provenance

The previous intake read coverage was reused after byte-hash verification. This avoids rereading unchanged material and preserves distinctions between full reading, selected mathematical sections, code inspection and executed tests. The source snapshots retain the exact previous manifest records and hashes in [corpus_upload_manifest_snapshot.json](corpus_upload_manifest_snapshot.json).

| Material | Disposition |
|---|---|
| Original 20 supplied items | Every item retained with its individual read scope from `evidence/coverage.md`; items 2, 3 and 8 remain selected-section reads. The tropical DOCX is original item 20. |
| Expanded 22 supplied items | Every item retained with its prior disposition from `expanded-corpus/COVERAGE.md`; duplicates retain references rather than acquire a second independent review. |
| 108 extracted artifacts | All statuses preserved: 59 full extracted-text/identical-prior reads; 49 inventoried resources with scoped code inspection. The latter are not 49 full source reviews. |
| `workspace.zip` | Prior inventory: 34 entries, 19 research documents. Main compendium: 7,998 lines previously read; safe-basis compendium: 1,668 lines previously read. |
| `Crate 12.zip` | Prior inventory: 53 files and 25 unique Rust/manifest contents. Four mathematical documents fully read; production definitions inspected and relevant variants tested previously. Not every demo/benchmark display line was reviewed. |
| Memory archive | Prior inventory and 18 relevant text reads reused. Unrelated private/project material excluded from the campaign's technical conclusions. |
| PDFs and DOCX math | Prior extracted-text coverage retained. This is not a page-by-page visual/OCR audit. Extraction-damaged formulas and unseen embedded objects remain unknown unless the prior review explicitly resolves them. |
| Linked Codex task | `read_thread` is not available in the exposed tools. No task contents are treated as read; the task title is not evidence. |

Original item 19 and expanded items 9/21 are byte-identical. Original item 7 and expanded item 19 are byte-identical. Original item 20 and expanded item 2 are byte-identical. All 42 top-level source instances are still recorded.

The prior full-text reviews, rendered-image exceptions and formula-specific concerns are documented in `/workspace/k-elimination-audit/evidence/coverage.md`, `/workspace/k-elimination-audit/expanded-corpus/COVERAGE.md`, and their linked reviews. Their hashes are in the snapshot. This campaign has not upgraded those historical limits.

## Pinned repository intake

Metadata, branch heads and recursive trees were retrieved through the GitHub connector using the Skyelabz210 account. All eight tree responses reported `truncated=false`. These are complete **tree inventories**, with the source read scope in the next table. No repository-wide build or security audit is claimed by this track.

| Repository | Commit | Tree entries |
|---|---|---:|
| MANA-definitive | `e5a4f236a1ba566ff123ec480d5fc66da6abb04e` | 214 |
| MANA-pages | `3299c9bcdbdf9f1260b29ced3bde87d24e47b195` | 190 |
| NINE65-v5-proofstack | `6b14d5cfa1efa60d61e24f8383d661c51d2ecbdb` | 437 |
| NINE65-v5 | `8051fbe41b5d412340961c81fd799499b7b29651` | 657 |
| NINE65_v7 | `88a7bdadbf0e1f8fbfdb2b37e9843101b8db3484` | 2,927 |
| k-elimination-lean4 | `0400092096962e3da45a8e5cbb82185a3c2c38fe` | 38 |
| qmnf-lean-coq-security-proofs | `1e0acf1d60a894433e9ef902b215b383ce4d1ced` | 302 |
| NINE65-Rust-Guide | `ebe062ce33e196fb79f30138f38665186a0e774e` | 52 |

The research baseline is `d883d24e6a1462c78564e554f42b3dd54044da59`; the source v7 pin remains `88a7bda`. The source Lean pin remains `040009`. A source pin, research snapshot and newly compiled artifact are different objects. Current proof/build outcomes belong to the campaign's verification artifacts, not these metadata observations.

| Repository source actually read this campaign | Lines read | Concrete finding |
|---|---:|---|
| MANA-definitive `crates/nine65/src/ops/gso_fhe.rs` | 1–460, in two excerpts | Noise tracker, illustrative swarm and symmetric/public wrappers are separate mechanisms. Public collapse changes the tracker/swarm after computing the returned ciphertext result. |
| MANA-pages `src/crates/nine65/src/ops/gso_fhe.rs` | 1–190 directly; identical blob established | Git blob `7bffb6db…` equals the definitive file's blob. The inspected definitive ranges therefore describe that identical file; this is not whole-repository identity. |
| NINE65-v5 `crates/exact_transcendentals/lean4/ExactTranscendentals/ExactRational.lean` | 1–220 | Numerator/denominator representation, cross-product equivalence, normalization and a totalized division convention. |
| NINE65-v5-proofstack `lean4/KElimination/KElimination/AHOP/Algebra.lean` | 1–200 | Descartes quadratic form, reflection involution, quadratic preservation and word/orbit structure. |
| QMNF proof repo `lean4/formalization-swarm/18_WASSAN.lean` | 1–220 | 144-coordinate state, direct retrieval and sparse reconstruction. A named constant-time theorem concludes `True`; it is not a cost semantics proof. |
| NINE65-Rust-Guide `docs/gso-fhe.md` | Full returned file, 164 lines | Historical GSO tracker/symmetric API description. Performance and unlimited-depth statements require implementation/mode-specific evidence. |
| NINE65_v7 `KElimination_Universal_Paper.md` | 1–170 | Correct bounded extraction calculation coexists with an unbounded uniqueness statement that omits its needed range hypotheses. |
| Public Lean `KElimination/Basic.lean` | Full returned file, 37 lines | Euclidean decomposition and bounded quotient definitions/statements. Fresh compile results are owned by the formal track. |

[corpus_github_snapshot.json](corpus_github_snapshot.json) retains tree inventory and Git pins. [corpus_github_readings.json](corpus_github_readings.json) retains only the public source ranges above. The registry distinguishes the complete file's Git blob SHA from the SHA-256 of a returned excerpt. The selected files establish mechanisms and scope; they do not certify unrelated modules in the same repository.

## Private primary-source intake

Five primary leads were fetched read-only from the connected `hackfate.ai@gmail.com` Drive. Raw text is retained only outside the repository-ready worktree at `/workspace/k-elimination-audit/private-campaign-sources/corpus_drive_fetches.json`. The portable registry contains metadata, text-snapshot hashes, read ranges and derived findings. The hashes identify connector text, not original DOCX/PDF bytes or a Google Docs revision ID.

| Registry ID | Source / last modified | Exact line scope | Contribution |
|---|---|---:|---|
| `drive-frontiers` | CRT Foundations/Frontiers/Divergence, 2026-03-16 | 105–160 | Heterogeneous lane operators, phase coupling, exceptional sets and explicit unresolved FHE/noise/security questions. Novelty declarations are author claims, not an exhaustive priority finding. |
| `drive-synthesis` | Unified Framework Synthesis, 2026-03-20 | 1–181, complete returned text | RDT, discrete KAM, alternate-gradient, QEC, wavelet, calendar and profinite leads, with implementation/bridge obligations. |
| `drive-nsproof` | NS Regularity Proof Complete, 2026-04-09 | 14–100 | Exact skew-energy identity is useful; the implications to maximum-norm stability and uniform continuum estimates require separate justification. |
| `drive-register` | Major Theorems Register, 2026-05-03 | 1–175 | Claims/scopes/dependencies for K-Elimination, FPD, auxiliary-lane error, winding-energy and skew-advection. A label “Proven” is not a fresh proof check. |
| `drive-blueprint` | 3D NS Build Blueprint, 2026-05-06 | 103–187 | Explicitly narrows delivery to discrete structure/tests; arbitrary-data continuum regularity is OPEN, as are named stretching and Biot–Savart correspondence obligations. |

Eight further primary leads from the skill evidence index are registered as **not fetched this campaign**. The selected lines above do not imply that all five documents were read fully; only the synthesis was. DOCX/native-Doc image formulas were not visually audited. The blueprint's embedded workflow instructions were inspected as source material, not executed as governing instructions.

The date ordering matters: the later blueprint gives a narrower explicit scope than the earlier “complete proof” title. The campaign preserves both records and uses the narrower justified scope until an actual new proof closes the named obligations.

## Recovered contributions and routes back into NINE65

1. **Generalize the AHOP invariant to arbitrary commutative rings.** Write one selected coordinate as `a`, the sum of the others as `s`, and reflect it to `2s−a`. Reflecting twice gives `a`; expansion shows that `Q=(sum k)^2−2 sum(k_j^2)` is unchanged. The proof uses no inverse of 2, so these two identities survive composite characteristic and characteristic 2. This can supply quotient-compatible transition invariants for MAA and transduction. The source's separate noncommutativity and cryptographic hardness claims do not follow from those identities and retain their own hypotheses. This track supplies the algebraic derivation, not a freshly compiled Lean generalization.

2. **Use WASSAN as a structured-query mechanism with explicit fibers.** A 144-coordinate state can answer coordinate queries exactly, and sparse support can be useful for states genuinely restricted to that support. Universal transport supplies the criterion for a smaller observation to answer a chosen query. The source's `True`-valued cost theorem cannot establish execution complexity, and a sparse special case does not establish arbitrary lossless 144:1 compression. The useful next contribution is a source-bound, costed query interface with a declared admissible state class.

3. **Reuse exact rational pairs with a certified division contract.** The v5 representation supports exact arithmetic and equality by cross-products. Its zero-input division convention must be explicit: ordinary field division requires nonzero input, while a totalized API can choose a documented result. This suggests a rational-query extension whose denominator information and range certificates are carried only as needed. The representation alone does not remove gcd, magnitude or information-capacity obligations.

4. **Bind GSO/noise certificates to actual ciphertext transitions.** The historical wrapper's public collapse branch resets tracking metadata without changing the already-computed returned ciphertext. This identifies a precise proof obligation for reuse: a noise-reduction claim must cite a ciphertext transformation and its algebra/security model. Symmetric/trusted computation, public evaluation and research diagnostics remain distinct. The inspected wrapper is not evidence that every underlying multiplication or every later NINE65 refresh route has the same behavior.

5. **Separate exact energy from maximum-norm stability and continuum transfer.** The rational orthogonal matrix `R=[[3/5,−4/5],[4/5,3/5]]` maps `(1,1)` to `(−1/5,7/5)`: squared Euclidean norm stays 2 while maximum norm rises from 1 to 7/5. Thus preserving a quadratic energy does not by itself give a coordinate maximum principle. Preserve the exact skew-energy certificate, then require an independent positive-weight/monotonicity or stability theorem. Likewise, a physical grid energy includes mesh weights; uniform continuum bounds cannot be inferred from an unweighted finite sum without tracking those weights. The later blueprint's explicit OPEN labels support this repair direction. The unavailable NS runtime was not executed in this track.

6. **Repair the old universality statement without losing the valid bounded result.** The pinned v7 paper's Theorem 2.2 omits `k<A` and a representative window for `X`. For example, `M=2, A=3, r=0, k=3` gives the same pair of residues as `X=0` and extracts `k mod A=0`. The valid generalization is query recovery on observation fibers, with integer recovery only after an injective admissible-window certificate. Its one-subtraction/one-multiplication count describes fixed-width local extraction from available authentic readings and a precomputed inverse; obtaining those readings and growing operand bit width have separate costs.

7. **Keep new domain connections typed.** The recovered synthesis proposes code distance, wavelet moments, spectral radius, clean windows, quantum behavior and turbulence links. These names are leads to concrete mappings, not interchangeable meanings of one scalar. For each connection, define its observation, admissible states, target query and kernel/fiber condition; then prove the physical or computational bridge separately. Heterogeneous lane operators and their exceptional sets are particularly concrete finite-state candidates for this process. Independent discovery and formal tracks own the new experiments/proofs that follow.

No conclusion here depends on calling a theorem elementary or on equating algebraic ingredients with the whole contribution. The registry distinguishes reusable mathematics, new generalization candidates, architecture-level integration, executable evidence and unresolved bridges.

## Reproduction and limits

Run `python registry/corpus_build_registry.py` from the campaign directory in this workspace. The generator reads existing intake manifests, rechecks all 150 local source/member hashes, preserves exact dispositions, checks source-ID/parent consistency, and rebuilds the registry/lineage metadata. Its source dependencies are recorded; the portable JSON snapshots remain inspectable when original attachments are unavailable elsewhere. No source program or archived instruction is executed by this generator.

The validation checks the registry's accounting and provenance. It does not prove the contents of the sources, validate all claimed novelty, or replace the campaign's Lean/Rust/Python verification. Re-reading whole repositories, additional Drive leads, repaired PDF formulas, complete Git ancestry and the unavailable linked chat remain explicit unfinished intake scopes.
