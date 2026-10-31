# Pinned Hou–Jiang implementation assessment

The missing attack has an openly available authors' implementation. The
publisher's references identify `identitymapping/enhanced_hybrid_attack`.
The assessment driver pins revision
`d60cac04dea5a397b8489cce7171f3fe38b277d8` and verifies SHA-256 hashes of all
24 Python files in its estimator package before importing it. It does not
run the GPU attack or attempt to recover any real secret.

## Exact input and calculation

The source instance is N=8192, Q=983930967448092673, with exactly 48 positive
and 48 negative ternary coefficients at hidden positions. Error is **CBD(3)**,
not the authors' wrapper's default Gaussian with sigma 3.19. The driver uses
the fork's `ND.SparseTernary` and `ND.CenteredBinomial` directly and supplies
unlimited samples as in the earlier assessment. The ring degree is explicitly
8192 and `structure_leverage=True` enables the authors' enhanced attack.

Four searches are required: baseline/enhanced under MATZOV classical and
ADPS16 quantum lattice-reduction cost. Both use GSA, Babai decoding and no
MITM. The quantum-lattice cost model does not establish a fully quantum
hybrid attack assessment. The authors' coarse/fine optimization is preserved;
this is not a proof of global optimality over every attack parameter.

`scripts/cram_hou_jiang_screen.py` runs each search in a separate subprocess,
with a deadline and captured diagnostics. Missing, duplicate, mismatched,
nonfinite, negative, error or timeout results cannot satisfy the complete-run
predicate. Existing output evidence is not overwritten. The source package,
driver and profile driver are hashed in the result. Each worker receives its
own writable temporary directory for the authors' diagnostic NumPy profile;
the model and both pinned source trees remain unchanged.

The Sage image is pinned to
`sagemath/sagemath@sha256:19995db6194f4a4bab18ce9a88556fd15b9ed5e916b4504fefe618a7796ddbdb`.
Runs disable networking, drop capabilities, and limit memory, CPU and PIDs.
The local evidence run mounts an immutable driver snapshot separately from
the writable results directory. The first frozen run failed at the diagnostic
profile write into the read-only working directory; that failure is retained
and is not counted as attack evidence.

## Reproduction

With Sage available and the pinned repository checked out:

```sh
sage -python scripts/cram_hou_jiang_screen.py \
  --source /path/to/enhanced_hybrid_attack \
  --output /new/evidence/assessment.json --timeout 1800 --jobs 2
```

The existing source-assessment workflow has a manually dispatched bounded
job for this run. The ordinary refresh workflow runs the Sage-free driver
regressions. No workflow was remotely dispatched as part of this change.

## Completed native source runs

All four searches completed with finite results and exit status zero:

| Reduction cost model | Baseline log2 work | Enhanced log2 work |
| --- | ---: | ---: |
| MATZOV classical | 258.05009 | 249.72810 |
| ADPS16 quantum lattice reduction | 231.53012 | 223.26653 |

These are the pinned implementation's modeled costs, not certified security
levels. They do not replace lower estimates from other attacks: across the
24 previously completed estimates and these four additional results, the
minimum reported cost remains **161.33894 bits**. This aggregation is not a
security lower bound or a claim that 28 independent attack families were tested.

The [raw assessment](../../../artifacts/execution/2026-10-31/hou-jiang-assessment/assessment.json),
[provenance](../../../artifacts/execution/2026-10-31/hou-jiang-assessment/provenance.json),
native key-free plan, and failed read-only-working-directory run are archived
together. The actual native binary's source-domain fields were checked against
the assessment input. Its key-graph fingerprint is
`85f81c7b08a2eef491729b9a0d472dda28504fce812b28c6d808cd438678d94e`.
All 44 Python checks and both changed workflow YAML files validate. Periodic
Sage stack dumps use the word “Timeout” in diagnostics; the report's status
field and subprocess exit determine whether a search actually timed out.

## Coverage limits and provenance

The ePrint landing page for 2026/366 states **"Corrected Theorem 3.1"** and
dates its latest revision to 2026-08-30. The pinned code was last pushed on
2026-02-23. Correspondence between that code and the corrected theorem is
not established here. Therefore a successful implementation run leaves
`corrected_theorem_3_1_validated`, `quantum_hybrid_coverage_complete`,
`joint_key_security_proven`, and `production_admitted` false. The driver
reports completion of the four implementation runs separately.

The publisher identifies a merged CRYPTO 2026 article combining ePrint
2026/279 and 2026/366. Its abstract reports measured improvements for its
tested parameter sets; those figures are not a universal bound to subtract
from the earlier CRAM estimates. Neither parameter screening nor this run
proves joint/KDM security of W→S→B→W and the self-key relations. The
[public-evaluation reduction](PUBLIC_REFRESH_SECURITY_REDUCTION.md) states
the separate premise needed for confidentiality of the refresh transcript.

Sources read:

* Hou, J., & Jiang, H. (2026). *Careful with the Ring: Enhanced Hybrid Decoding
  Attacks against Module/Ring-LWE*. Cryptology ePrint Archive, 2026/366.
  https://eprint.iacr.org/2026/366 (landing page and revision note).
* Hou, J., Jiang, H., & Ogilvie, T. (2026). *Careful with the Ring! Concrete
  Hardness Gaps Between LWE and MLWE*. CRYPTO 2026.
  https://doi.org/10.1007/978-3-032-35377-1_15 (publisher abstract/references;
  subscription full text was not obtained).
* Authors' pinned implementation and README:
  https://github.com/identitymapping/enhanced_hybrid_attack/tree/d60cac04dea5a397b8489cce7171f3fe38b277d8.
