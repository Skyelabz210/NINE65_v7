#!/usr/bin/env bash
# Authoritative axiom audit for the KElimination Lean library.
#
# Inspects the *elaborated kernel environment* (not source text) and fails if any
# KElimination module declares an axiom other than the one documented hardness
# assumption `ahop_hardness`. Because it reads the kernel environment, it is
# immune to the things a source grep cannot see — attributes, comments, or an
# axiom synthesized by a macro.
#
# Run from the package dir (lean4/KElimination) AFTER `lake build`, so the module
# oleans are warm in the page cache (~10s; a cold run is dominated by Mathlib
# olean I/O and can take minutes).
set -euo pipefail

AUDIT="${RUNNER_TEMP:-/tmp}/axiom_audit.lean"
{
  # import every proof module so its declarations enter the environment …
  find KElimination -name '*.lean' | sed 's|\.lean$||; s|/|.|g; s|^|import |'
  echo 'import KElimination'   # … and the root module
  cat <<'LEAN'
open Lean in
run_cmd do
  let env ← getEnv
  let allowed : Name := `KElimination.AHOP.Hardness.ahop_hardness
  let mut bad : Array Name := #[]
  for (name, info) in env.constants.toList do
    if let .axiomInfo _ := info then
      if let some idx := env.getModuleIdxFor? name then
        if (`KElimination).isPrefixOf (env.allImportedModuleNames[idx.toNat]!) then
          unless name == allowed do bad := bad.push name
  unless bad.isEmpty do
    throwError "Unexpected axiom(s) in KElimination modules: {bad}"
  logInfo "Axiom audit OK: only ahop_hardness"
LEAN
} > "$AUDIT"

lake env lean "$AUDIT"
