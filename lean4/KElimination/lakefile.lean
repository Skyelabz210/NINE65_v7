import Lake
open Lake DSL

package «KElimination» where
  version := v!"0.1.0"

require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git"

@[default_target]
lean_lib «KElimination» where
  -- Build the root module AND every KElimination.* submodule, so `lake build`
  -- actually elaborates all proof files. Previously only the near-empty root
  -- module (which imports just Mathlib) was built, so none of the proofs were
  -- ever machine-checked by `lake build` or CI.
  globs := #[.andSubmodules `KElimination]
