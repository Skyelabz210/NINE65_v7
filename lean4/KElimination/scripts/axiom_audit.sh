#!/usr/bin/env bash
# Inspect every project declaration and its transitive kernel axiom dependencies.
# Run from lean4/KElimination AFTER a fresh `lake build`. No project axiom,
# imported custom axiom, sorryAx or Lean.ofReduceBool is admitted. The allowed
# foundational axioms are Lean's standard logical foundations, not crypto claims.
set -euo pipefail

AUDIT=$(mktemp "${RUNNER_TEMP:-/tmp}/nine65-axiom-audit.XXXXXX.lean")
trap 'rm -f "$AUDIT"' EXIT
{
  find KElimination -name '*.lean' | LC_ALL=C sort | sed 's|\.lean$||; s|/|.|g; s|^|import |'
  echo 'import KElimination'
  echo 'import Lean.Util.CollectAxioms'
  echo 'import Lean.Elab.Command'
  cat <<'LEAN'
open Lean in
run_cmd do
  let env ← getEnv
  let foundational := #[`propext, `Quot.sound, `Classical.choice]
  let mut count := 0
  for (name, info) in env.constants.toList do
    if let some idx := env.getModuleIdxFor? name then
      -- Attribute ownership by source module, not declaration namespace.
      if (`KElimination).isPrefixOf (env.allImportedModuleNames[idx.toNat]!) then
        count := count + 1
        if let .axiomInfo _ := info then
          throwError "Unexpected axiom in KElimination module: {name}"
        -- Check theorem types and proof terms, definitions and opaque values.
        for dependency in (← collectAxioms name) do
          unless foundational.contains dependency do
            throwError "Unexpected axiom dependency of {name}: {dependency}"
  unless count > 0 do
    throwError "No KElimination declarations found"
  logInfo m!"Axiom audit OK: {count} project declarations; no custom axioms or sorryAx"
LEAN
} > "$AUDIT"

lake env lean -DwarningAsError=true "$AUDIT"
