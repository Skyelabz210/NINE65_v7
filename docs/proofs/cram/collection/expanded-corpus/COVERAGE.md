# Expanded corpus coverage and provenance

Audit date: 2026-11-12. This intake adds 22 top-level attachments to the earlier 20, with duplicates identified by bytes/SHA-256. The [input manifest](input-manifest.json) records all 22 original paths, sizes and hashes; the [extraction manifest](extraction-manifest.json) records 108 selected extracted files, including 59 text documents. Original attachments were not changed.

READ means the specified source text was actually examined. It does not mean every assertion, citation, historical test, application or referenced external artifact was independently verified. PDF review was of extracted text, with relevant formulas visible in that text; this is not a page-by-page image/OCR audit. Damaged formulas are identified in the detailed reviews. DOCX math and paragraph/table text were extracted; the two images in input 3 were also inspected. Input 10 was visually inspected.

## Top-level intake

| # | File | Coverage / disposition |
|---:|---|---|
| 1 | deep-research-report 6.md | READ in full. Secondary survey, substantially the original pasted text; corrected against sources. See ROOT_NOTES. |
| 2 | Untitled.docx | Byte-identical duplicate of the previously fully reviewed tropical report. Prior read/experiments retained. |
| 3 | NINE65v7 Exhaustive Audit Fallback Systems | READ in full, including eight OMML equations and both images. Paths/measurements do not bind to the pinned checkout. Runtime review. |
| 4 | D-OD01/D024 THEOREM STACK | READ all 12 pages of extracted text. Algebraic and analytic obligations distinguished. Division review. |
| 5 | Exact Division Residue Space Resolution | READ all 5 pages. Its own general-division algorithm explicitly reconstructs. Division review. |
| 6 | CRAM_FULL_SYNTHESIS_EXPANDED | READ in full. Framework review. |
| 7 | the safe basis | READ all 11 pages. On-demand K, projection, composites and printed proof statements reviewed. Division review. |
| 8 | KimiCRAM QMNF Technical White Paper | READ in full. Framework review. |
| 9 | PROOFS.pdf | READ all 6 pages; byte-identical to earlier input 19. Portfolio review and prior evidence. |
| 10 | Untitled.png | VISUALLY INSPECTED: unlabeled black stroke, no readable theorem. |
| 11 | workspace.zip | All 34 entries inventoried; 19 research documents extracted. Detailed document coverage below. Archived control/env files were not executed or adopted as instructions. |
| 12 | gpai CRAM CRT-based coprime arithmetic | READ all 5 pages; duplicate also inside workspace.zip. The worked 209 mod11 example is corrected in the division review. |
| 13 | cram beta synthesis | READ all 24 pages. Framework review. |
| 14 | Crate 12.zip | All 53 files extracted/inventoried. Four mathematics documents fully read; relevant production code and distinct variants inspected and buildable packages tested. Demo/benchmark display code was not all reviewed line by line. Runtime review gives exact scope and failures. |
| 15 | report.pdf | READ all 11 pages. Secondary ECO-PRIME review; not a new division proof. Portfolio review. |
| 16 | Configurable Residue Arithmetic Machines monograph | READ all 7 pages. Explicit K-Free Principle and Observe boundary. Framework review. |
| 17 | Master Portfolio Document 2 | READ all 133 pages of extracted text. No additional K/CRAM/NINE65 theorem found; unrelated personal/commercial content is not incorporated into the technical report or portable packet. |
| 18 | gpai Problem 6162026 | READ all 7 pages. Relative versus canonical lift correction. Division review. |
| 19 | Unit Anchor WhitePaper | Byte-identical duplicate of previously fully reviewed input 7. Prior analysis retained. |
| 20 | ConfigurableResidueArithmeticMachines | READ all 1,131 extracted lines, including appended conversations. Careful §§14/16/17 identified separately from contradictory appendices. Framework review. |
| 21 | PROOFS.pdf | Byte-identical to input 9 and earlier input 19. Same full-text review applies. |
| 22 | claude-memory archive | All entries inventoried; eighteen selected task-related text files fully read. Unrelated personal/project memory excluded. Retrospective claims are leads, not fresh proof/test evidence. ROOT_NOTES and framework addendum. |

## Archive document coverage

`workspace.zip` contains 19 research documents. The exact extracted filenames are in the manifest.

* The main CRAM_COMPENDIUM was fully read: all 7,998 lines / 478,520 characters. [compendium.md](reviews/compendium.md) distinguishes the initial relevant-section pass from the completed 5,219-line continuation and records its additional findings.
* Twelve smaller documents assigned to that review were fully read: the long and short topological-lift treatises; the lift/reconstruction inventory; K-Elimination theorem PDF; eight-slide reconstruction deck; normalized theorem matrix; threaded system documentation; emissions audit; star-CRT scaling analysis; CRAM K-Elimination/lifts inventory; refined paper collection; K-Elimination technical paper.
* SAFE_BASIS_MASTER_COMPENDIUM: all 1,668 lines read and selected finite claims independently reproduced. [Division review](reviews/division.md).
* RECOMBINANT_CRT_BRIDGE_TECHNICAL_PACKET: all text read. [Framework review](reviews/framework.md).
* The 40-page unified 2025-named compendium and 54-page Ultimate v7 compendium: all extracted text read. [Portfolio review](reviews/portfolio.md).
* The remaining two files are byte-identical to top-level inputs 12 and 20, whose full reads apply.

`Crate 12.zip`: the four accompanying theorem documents were fully read. The archive has 25 unique Rust/manifest byte contents across its overlapping snapshots. The [runtime review](reviews/runtime.md) and [runtime manifest](experiments/runtime_manifest.json) distinguish inspected production definitions, unreviewed display/benchmark text, layout-only staging, failing old variants, and unchanged-source test execution. Passing corrected-source tests do not erase archived failures.

The memory selection consists of the six area files named cram-df-forensics, cram-framework-docs, cram-standard-v1, nine65-fhe, qmnf-cram and saros-liouville-test-suite; three files under the named CRAM project; all six files under the two opaque UUID project directories whose indexes identify CRAM and D Series; and the arrow-of-time, research-approach and recent-work topics. No scripts referenced only by those memories were assumed present or run. None of the quoted historical test counts is included in this review's fresh totals.

## Repositories, proofs and executed scope

* Public proof source: `0400092096962e3da45a8e5cbb82185a3c2c38fe`; previous parser/Basic findings and scratch repair retained. Full repaired root was not freshly verified.
* Current NINE65: `88a7bdadbf0e1f8fbfdb2b37e9843101b8db3484`; 52 targeted tests and scoped exact-route guard/negative controls freshly pass. This is not a full-repository test or seven-repository architectural acceptance.
* Native-refresh arithmetic slice: five modules freshly compiled in the preceding phase, preserved separately. This intake did not repeat the expensive native refresh cycle experiment.
* New `ExactObservation.lean`: nine fresh compiled specification theorems, explicit pin, final warning-free log, Classical.choice only in the existence theorem. No Rust refinement or all-domain constructive inverse is inferred.
* Five new independent Python model suites supply the result files cited in EXPANDED_ANALYSIS. Finite enumeration, written proof and Lean proof are explicitly distinguished.
* No publication, push, deployment, external messaging, or original-repository source change was performed.

## Literature scope

The primary/secondary/abstract-only distinctions of the earlier analysis remain in force. This intake additionally examined Hung–Parhami 1994's introduction and relevant operations sections through the author-hosted PDF extraction. Some later formulas were missing in extraction; a full reconstruction of both algorithms is not claimed. The document was used only for the verified statements about division scope, coprimality and processor/time models. No exhaustive historical priority determination is claimed.

## Portable packet scope

The packet includes the research reports, model code/results, checked Lean source/log and selected execution/provenance artifacts. It excludes full private memory archives, the unrelated portfolio, environment files, toolchains and build targets. Absolute source paths in logs document this execution; rerunning current repository tests requires the pinned checkout. SHA-256 hashes identify supplied documents when their original full text is not bundled.
