import KElimination.PublicRefreshReturn
import KElimination.PublicRefreshBounds
import KElimination.PublicRefreshGeometry
import KElimination.PublicRefreshNativeLift
import KElimination.PublicRefreshDigit
import Lean.Util.CollectAxioms
import Lean.Elab.Command

/-! Inspect the elaborated kernel environment, including declarations outside
the expected namespaces. No custom assumption is admitted by this proof slice.
The foundational axioms below are Lean's standard logical foundations, not
assumptions about FHE correctness, noise, or lattice hardness. -/

open Lean in
run_cmd do
  let env ← getEnv
  let modules := #[`KElimination.PublicRefreshReturn,
                   `KElimination.PublicRefreshBounds,
                   `KElimination.PublicRefreshGeometry,
                   `KElimination.PublicRefreshNativeLift,
                   `KElimination.PublicRefreshDigit]
  let foundational := #[`propext, `Quot.sound, `Classical.choice]
  let required := #[
    `KElimination.PublicRefreshReturn.residue_zero_iff,
    `KElimination.PublicRefreshReturn.extracted_pair_eq_returned_pair,
    `KElimination.PublicRefreshReturn.dense_product_return,
    `KElimination.PublicRefreshReturn.dense_boot_product_return,
    `KElimination.PublicRefreshReturn.dense_phase_return,
    `KElimination.PublicRefreshReturn.complementary_term_negacyclic_sign,
    `KElimination.PublicRefreshBounds.odd_half_headroom_iff,
    `KElimination.PublicRefreshBounds.residual_envelope_admission,
    `KElimination.PublicRefreshBounds.nearest_integer_decode,
    `KElimination.PublicRefreshBounds.quadratic_div_envelope,
    `KElimination.PublicRefreshBounds.assembled_return_envelope,
    `KElimination.PublicRefreshBounds.all_cycles_admitted,
    `KElimination.PublicRefreshBounds.Fixture.budget_closed,
    `KElimination.PublicRefreshBounds.Fixture.arbitrary_cycles,
    `KElimination.PublicRefreshGeometry.complete_chart_integer_lower_bound,
    `KElimination.PublicRefreshGeometry.dense_8192_complete_chart_refuses,
    `KElimination.PublicRefreshGeometry.sparse_96_coordinate_99_window,
    `KElimination.PublicRefreshNativeLift.native_source_norm,
    `KElimination.PublicRefreshNativeLift.signed_quotient_radius,
    `KElimination.PublicRefreshNativeLift.signed_quotient_lift_unique,
    `KElimination.PublicRefreshNativeLift.pair_query_exact,
    `KElimination.PublicRefreshNativeLift.pair_query_target_residue,
    `KElimination.PublicRefreshDigit.taylor_remainder,
    `KElimination.PublicRefreshDigit.derivative_evaluation,
    `KElimination.PublicRefreshDigit.rooted_quotient_mod,
    `KElimination.PublicRefreshDigit.canonical_p_square_quotient,
    `KElimination.PublicRefreshDigit.split_digit_correct,
    `KElimination.PublicRefreshDigit.certified_split_digit,
    `KElimination.PublicRefreshDigit.residual_polynomial_correct]
  for name in required do
    match env.find? name with
    | some (.thmInfo _) => pure ()
    | _ => throwError "Missing required public refresh theorem: {name}"
  let mut count := 0
  for (name, info) in env.constants.toList do
    if let some idx := env.getModuleIdxFor? name then
      if modules.contains (env.allImportedModuleNames[idx.toNat]!) then
        match info with
        | .axiomInfo _ => throwError "Unexpected axiom in public refresh module: {name}"
        | .thmInfo _ => count := count + 1
        | _ => pure ()
        -- Definitions and opaque declarations can also contain proof terms.
        -- Check them even if no exported theorem refers to them.
        for dependency in (← collectAxioms name) do
          unless foundational.contains dependency do
            throwError "Unexpected axiom dependency of {name}: {dependency}"
  unless count > 0 do
    throwError "No public refresh theorems found"
  logInfo m!"Public refresh axiom audit OK: {count} theorems; no custom axioms or sorryAx"
