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
| N01 | Add production prohibition scanner | Implemented, CI verification pending | Scanner returns zero prohibited executable symbols |
| N02 | Capture benchmark and correctness baseline | Pending runner execution | Raw test and benchmark artifacts committed |
| N03 | Canonical CRAM state | Initial implementation complete | Constructor and architecture-counter tests pass |
| N04 | Basis and residue lanes | Initial implementation complete | Exhaustive small-modulus tests required next |
| N05 | Winding and hidden carry | Type scaffold complete | Exact update rules and chained oracle tests pending |
| N06 | Shadow and anchor state | Type scaffold complete | K-Elimination witnesses pending |
| N07 | Bound certificate | Add/multiply rules implemented | Adversarial soundness tests pending |
| N08 | Heterogeneous topology | Initial validated assignment type complete | Transduction-edge graph pending |
| N09-N20 | Arithmetic through bootstrap | Pending | Each node requires correctness before performance |
| N21 | Architecture counters | Implemented in `cram-core` | All prohibited counters must remain zero |
| N22-N30 | Exhaustive, security, performance, scale, release | Pending | No merge before every gate passes |

## Current implementation files

- `crates/cram-core/Cargo.toml`
- `crates/cram-core/src/lib.rs`
- `scripts/check_residue_native_architecture.py`
- `.github/workflows/cram_residue_native_gates.yml`

## Next execution tranche

1. Run the new CI gates and repair compilation or lint findings without weakening them.
2. Generate N01's complete violation ledger for existing NINE65 residue/FHE paths.
3. Capture N02 same-machine secure and insecure baselines.
4. Split `cram-core/src/lib.rs` into state, basis, lane, winding, shadow, bounds, topology, instrumentation, and errors modules.
5. Implement N05 exact winding update rules and exhaustive small-state tests.
6. Implement N06 anchor witnesses and K-Elimination exhaustive tests.
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
