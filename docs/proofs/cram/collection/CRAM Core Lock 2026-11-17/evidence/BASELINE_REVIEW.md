# Standalone CRAM mathematical baseline — 2026-11-17

Status: EXECUTED baseline build and complete transitive axiom audit, followed by theorem-statement inspection. This is not Rust refinement or whole-CRAM acceptance.

## Immutable baseline and command

- Repository: `/workspace/k-elimination-swarm-proof`
- Commit: `dd9c6cfb341ad3747f148c336a015e2b80664e87`
- Branch: `campaign/universal-proof`
- Initial and final status during this audit: only pre-existing untracked `scripts/__pycache__/`; no tracked changes made by this worker.
- No repository-local or `/workspace` AGENTS.md/CLAUDE.md instruction file was found for this proof tree.
- Lean: `leanprover/lean4:v4.27.0-rc1`, Lean commit `2fcce7258eeb6e324366bc25f9058293b04b7547`.
- Mathlib: `3bdc7047b97538f795b725dc0713c28c0f53ed10`.
- Lake manifest SHA256: `4beccaf721d857691e35e3e33cac79a629b92090201058a4160e4e75e35debbc`.

Executed from the repository root:

```sh
python3 scripts/audit_proofs.py \
  --lake /workspace/k-elimination-audit/proof-check/elan/toolchains/leanprover--lean4---v4.27.0-rc1/bin/lake \
  --output /workspace/scratch/cram-lock-2026-11-17/maintained-audit
```

The audit executed `lake --no-cache build` and then compiled a generated complete `#print axioms` query list. Build output ended `Build completed successfully (1185 jobs).` It inventories 20 source files and 223 theorem/lemma declarations. 58 declarations are axiom-free; all others use only the explicitly allowed foundational `propext`, `Classical.choice`, and/or `Quot.sound`. The script rejects admitted proofs and custom axiom/constant/opaque declarations. PASS applies to these inventoried source hashes. Existing local compiled dependency artifacts were available; this is not a clean rebuild of every dependency from source.

Raw output and source-hash inventory are in `maintained-audit/build.log`, `maintained-audit/axioms.log`, and `maintained-audit/verification.json` beneath this directory.

## Existing theorem coverage against the CRAM obligations

| Obligation | Checked baseline statements | Remaining scope |
|---|---|---|
| P1 — representation and Safe Basis | `CoupledAnchors.source_readings_iff`, `main_and_anchor_readings_iff`, `dependent_anchor_resolution`; `ResiduePrimitives.encode_injective_on_window` | No named S6/S8 role/packing implementation proof. Generalized CRT observation equality is proved; a full compatibility/constructor and representation-interface proof remains. |
| P2 — universal query transport | `ExactObservation.recoverable_iff`, `refined_observation_suffices`; `UniversalLift.lift_query_exists_iff`, `target_factor_exists_iff`, `target_factor_unique`, `target_factor_additive`, `constructive_query_correct`; `CostedReadout.ring_is_universal_instance` | General existence uses Classical.choose, does not construct an efficient algorithm. Ring instance is constructive once authentic source/chart readings and sided unit premises hold. |
| P3 — lift and resolution | `IntegerSpecialization.query_exact_signed_window`, `nonunit_query_of_affine_defect`, `nonunit_chart_query_signed_window`; `StarLift.positive_adjacent_congruence`, `negative_adjacent_congruence`, `unit_kernel_equal`; `CoupledAnchors.combined_kernel`, `resolution_eq_lcm_reduced`, `source_period`, `combined_target_iff` | Actual producer binding and finite-word implementation remain. Coupled-anchor law is kernel/capacity mathematics, not an FPD fusion implementation. |
| P4 — sister-tray authenticity | Common-source assumptions are explicit in `UniversalLift.phase_difference` and constructive query theorems; reference-change theorems preserve the declared decomposition | Baseline has no operational sister-tray producer/update machine or source-identity authentication proof. New PhaseBinding work is outside this baseline. |
| P5 — arithmetic | `ResiduePrimitives.ops_correct`, `divmod_correct`, `divmod_zero_refused`, `gcd_correct`; `ResidueAlgorithms.divLoop_correct`, `gcdLoop_correct` | Concrete paired-view state is only two Int residue fields. Increment, nonnegative subtraction, exact comparator and zero test discharge all abstract contracts. Bounded natural divmod/GCD always return `some` on valid inputs (positive divisor for division); no coprimality condition on the divisor. Repeated-subtraction division is constructive, not O(1). Signed division, rational normalization, production Rust and full optimized dispatcher remain. |
| P6 — heterogeneous operators | Ring-level results and `ReflectionInvariant` provide reusable examples | No complete topology-product operator registry or concurrent execution refinement. |
| P7 — transduction | `ExactObservation.transduction_composes`, `transduction_round_trip`; `ReferenceChange.target_invariant_under_reference_change`; target-lane transport in `IntegerSpecialization` | Composition/round-trip hypotheses already assume each transfer preserves the common source. They do not supply actual frame producers, metadata transport, or general algorithm implementations. |
| P8 — capacity/scale | Coupled LCM/GCD law and signed-window uniqueness; `AnchorSaturation.iterate_is_least_sufficient`, `demand_fuel_is_sufficient`, `demand_fuel_is_fixed`, `early_stop_is_least` | Factorization is used only in proofs of the public gcd recurrence, not as runtime input. Constructor gives a least sufficient modulus, not the new source observation. Word overflow, observation acquisition, dynamic frame transactions and inverse-limit execution are not proved. |
| P9 — program execution | `ExactObservation.finite_program_exact`, `finite_program_identifies_result`; `ConsumerTransport.quotient_transition_exists_iff`, `stable_finite_program`; `FutureQuotient.future_is_coarsest`, `quotient_query_correct`, `quotient_step_correct`, `fixed_point_is_future_equivalence` | Abstract finite-word composition assumes total transitions on the same admitted source type. Actual refused operations, dynamic frames, stateful admission, serialization and whole-runtime progress are not covered. Division/GCD have their own nonvacuous `some` progress theorems. |
| P10 — implementation/cost | `CostedReadout.program_counts`, `adjacent_program_counts`, `modular_program_evaluates_to_query` | Expression model counts one subtraction/one multiplication, or adjacent subtraction only, using supplied readings/constants. No Rust/MIR/Aeneas refinement, machine-word bounds, input production cost or hardware timing proof. |

## Baseline's strongest concrete result

`ResiduePrimitives.Frame` stores public moduli and an inverse certificate. `State` stores only `main` and `anchor` residues. The semantic encoder is separate and not called by the runtime division/GCD definitions. `ops_correct` proves the concrete comparator rather than assuming a scalar reconstruction oracle. For natural inputs below `M*A`, the implemented Lean division and Euclidean GCD return the correct encoded results; public capacity supplies sufficient fuel. Thus bounded residue-only division and GCD are already constructive mathematical results in this tree. Extending them to the full CRAM machine and actual Rust execution is a separate obligation, not a reason to discard these proofs.

## Documentation caution

README's new maintained-proof section accurately limits the audited claims, but older later sections still advertise bootstrap-free FHE, historical speed/accuracy contrasts and broad O(k) claims. Those older statements are not conclusions of this audit and should be marked historical/superseded in the canonical CRAM record. A number of declarations prove generic specifications, not the whole system implied by historical prose.
