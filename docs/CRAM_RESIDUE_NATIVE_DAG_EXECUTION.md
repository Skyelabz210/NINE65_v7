# CRAM Residue-Native DAG Execution Ledger

Branch: `cram/residue-native-scale-dag`

Base commit: `f432b2762e4c801b6aa9583e4b5eaf562896c2e5`

## Non-negotiable architecture

Production computation remains in residue space. Number-line projection is restricted to explicit user or protocol output. Test-oracle projection must be isolated from production dependencies.

The production path must contain zero:

- internal projections;
- CRT reconstruction calls;
- scalar materializations;
- Garner calls;
- mixed-radix calls;
- floating-point arithmetic.

CRAM retains heterogeneous lane operators and explicit cross-lane Transduction. It must not collapse into a homogeneous RNS wrapper.

## DAG status

| Node | Work | Status | Gate |
|---|---|---|---|
| N00 | Pin repository base and create execution branch | Complete | Branch is based on recorded main commit |
| N01 | Add production prohibition scanner | Implemented; false-positive handling hardened | Scanner must return zero prohibited executable symbols |
| N02 | Capture benchmark and correctness baseline | Pending runner execution | Raw test and benchmark artifacts committed |
| N03 | Canonical CRAM state | Initial implementation complete | Constructor and architecture-counter tests pass |
| N04 | Basis and residue lanes | Scale tests implemented | Rust runner matrix must pass at 2-64 lanes and 128-65,536 steps |
| N05 | Winding and hidden carry | Type scaffold complete | Exact production update rules and chained oracle tests pending |
| N06 | Shadow and anchor state | Mathematical scale oracle executed | Production witness API remains pending |
| N07 | Bound certificate | Add/multiply rules plus depth tests implemented | Rust adversarial soundness matrix pending |
| N08 | Heterogeneous topology | Initial validated assignment type complete | Transduction-edge graph pending |
| N09-N20 | Arithmetic through bootstrap | Pending | Each node requires correctness before performance |
| N21 | Architecture counters | Implemented in `cram-core` | All prohibited counters must remain zero |
| N22 | Exhaustive and differential correctness | In progress | Independent integer-only harness passes; Rust CI pending |
| N23-N26 | Property, security, fault, and performance gates | Pending | No claims until runner evidence exists |
| N27 | Scale and endurance | In progress | Small, medium, large, and endurance oracle profiles pass |
| N28-N30 | Documentation, release, and merge | Pending | No merge before every gate passes |

## Current scale evidence

The independent integer-only harness completed all four profiles with zero mismatches:

| Profile | Lanes | Steps | Lane operations | Sampled anchor states | Status |
|---|---:|---:|---:|---:|---|
| small | 2, 4, 8 | 128 | 1,792 | 2,048 | PASS |
| medium | 8, 16, 32 | 1,024 | 57,344 | 16,384 | PASS |
| large | 32, 64 | 8,192 | 786,432 | 131,072 | PASS |
| endurance | 64 | 65,536 | 4,194,304 | 1,048,576 | PASS |

Each profile also exhaustively checks 2,905 states across the coprime pairs `(4,9)`, `(8,9)`, `(15,16)`, `(25,49)`, and `(36,37)`. Evidence is stored at `artifacts/N22_N27/correctness_scale_2026-07-13.json`.

This evidence validates the current basis, lane arithmetic, structural state, bound-rule scaffold, and anchor-phase winding formula. It does not yet certify the full Rust FHE path, residue-native Transduction, rescale, key switching, or bootstrap.

## Current implementation files

- `crates/cram-core/Cargo.toml`
- `crates/cram-core/src/lib.rs`
- `crates/cram-core/tests/workload_scales.rs`
- `scripts/check_residue_native_architecture.py`
- `scripts/cram_correctness_harness.py`
- `.github/workflows/cram_residue_native_gates.yml`
- `artifacts/N22_N27/correctness_scale_2026-07-13.json`

## Next execution tranche

1. Obtain GitHub Actions runner evidence and repair compilation or lint findings without weakening gates.
2. Generate N01's complete violation ledger for existing NINE65 residue/FHE paths.
3. Capture N02 same-machine secure and insecure baselines.
4. Split `cram-core/src/lib.rs` into state, basis, lane, winding, shadow, bounds, topology, instrumentation, and errors modules.
5. Implement N05 exact winding update rules and exhaustive small-state tests.
6. Implement N06 production anchor witnesses and K-Elimination tests.
7. Implement N08 Transduction edges without reconstruction, Garner, or mixed-radix machinery.

## Merge rule

This branch remains a draft integration branch. It must not merge into `main` until N29 reports:

```text
internal_projections       = 0
crt_reconstructions        = 0
scalar_materializations    = 0
garner_calls               = 0
mixed_radix_calls          = 0
correctness_failures       = 0
security_gate_failures     = 0
unapproved_regressions     = 0
```
