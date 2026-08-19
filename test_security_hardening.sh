#!/bin/bash
# Verifies the FHE parameter security hardening surface actually holds:
#   - the crate compiles cleanly with default features
#   - ProductionSafe / SecureConfig invariants (params::secure_configs)
#   - orbital-boundary + HE Standard parameter validation (params::validation)
#   - production parameter tables (params::production)
#
# This is a real gate: `set -euo pipefail` means any failing command aborts
# the script with a non-zero exit immediately. Earlier versions of this
# script piped `cargo check` through `grep ... || echo "No errors..."`,
# which discarded cargo's exit status and made the `||` branch's own zero
# exit the last word regardless of what cargo reported -- the script always
# printed a "PASSED"-shaped summary. That pattern is gone.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

echo "=== Parameter Security Hardening Verification ==="
echo

echo "--- Compiling nine65 (default features) ---"
cargo check -p nine65 --lib

echo
echo "--- ProductionSafe / SecureConfig invariants (params::secure_configs) ---"
cargo test -p nine65 --lib --release params::secure_configs::tests -- --nocapture

echo
echo "--- Orbital boundary + HE Standard parameter validation (params::validation) ---"
cargo test -p nine65 --lib --release params::validation::tests -- --nocapture

echo
echo "--- Production parameter tables (params::production) ---"
cargo test -p nine65 --lib --release params::production::tests -- --nocapture

echo
echo "--- allow_insecure release-build gate (informational, non-fatal) ---"
# CLAUDE.md: "Test configs (allow_insecure) are blocked in release builds --
# never use in production." The enforcement point is a `compile_error!` at
# crates/nine65/src/lib.rs:124-125, gated on
# `not(any(test, debug_assertions))`. It is presently commented out, so this
# check is expected to warn on unmodified `main`. It is kept non-fatal
# (unlike the checks above) because closing it means editing lib.rs, which is
# out of scope for this script; the warning exists so the gap stays visible
# instead of silently regressing further.
if cargo check -p nine65 --lib --release --features allow_insecure >/tmp/nine65_allow_insecure_release_check.log 2>&1; then
  echo "::warning::allow_insecure compiles into a release build (nine65 --release --features allow_insecure succeeded)."
  echo "::warning::The compile_error! gate at crates/nine65/src/lib.rs:124-125 is commented out; uncomment it to close this."
else
  echo "confirmed: allow_insecure is rejected by the release-build compile_error gate"
fi

echo
echo "=== Parameter security hardening verification PASSED ==="
