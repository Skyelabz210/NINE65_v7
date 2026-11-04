# Tooling and proof-review continuation — 2026-11-04

This continues the [hygiene run](HYGIENE_2026-11-04.md). The user explicitly
requested installation of missing tools and rigorous, intuitive written proofs
before further new Lean work. Missing executables are no longer the reason for
any deferred verification in this continuation.

## Environment prepared

Installed official Rust 1.89.0, Cargo 1.89.0, rustfmt and Clippy in isolated
`/workspace/tools/rust/` directories. Installed Elan and the pinned Lean
4.27.0-rc1 compiler/Lake in `/workspace/tools/lean/`. The system C toolchain
and pkg-config are available. The installers did not modify home-directory
shell startup files. Small launchers in the existing user-local PATH expose
`cargo`, `rustc`, `rustfmt`, Clippy, `lean` and `lake` directly without a
root/system-directory install. This workspace also retains the local environment
file `work/verification/env.sh` for explicit selection.
Dependencies were fetched using the existing network/proxy configuration and
`Cargo.lock` remained unchanged.

## Proof work

The [coverage map](../proofs/README.md) separates reused library theorems,
written supplements, finite witnesses and genuinely open obligations.
The [arithmetic derivation](../proofs/REFRESH_ARITHMETIC.md) covers finite G/H
construction and evenness, all-coefficient divisibility, encoding-scale
reinterpretation, the coherent source carry equation and fused restoration.
The [pipeline derivation](../proofs/REFRESH_PIPELINE.md) covers the slot map,
embedded-secret projection, dense-key drop bounds, gadget deposits, exact
BFV tensor rounding, both error-unit conventions, cycle premises and selected
finite-width/authority obligations.

Each argument has explicit hypotheses, intuition, source correspondence and
a second-pass check of boundaries or failed-premise counterexamples. These
are two review passes by the same reviewer, not external cryptographic review.
The arguments do not establish whole-program Rust refinement, correlated-key
confidentiality, a probabilistic failure bound or physical constant-time behavior.
No production/security gate or legacy support predicate was changed.

An additional source-doc correction removes the old `exact_scale_round.rs`
assertion that its kernel was unintegrated and that every BFV tensor needs only
N/4. Its two-product cross component needs N/2, which is what the existing
production plan already enforces. No Rust executable behavior changed.

## Recomputed native plan

The key-free native example was executed at runtime source `a7f8531`:

| Quantity | Result and unit |
| --- | --- |
| Work / outer degree | 8192 / 32768 |
| Work / outer modulus bit length | 119 / 650 |
| Error before slot return | 517 bits, outer ideal-grid phase error |
| Error after slot return | 562 bits, outer ideal-grid phase error |
| Outer half-Delta threshold | 633 bits |
| Final returned bound | 122782933364666, 47 bits, scaled work-ring error |
| Next-square/source residual radius | 48, within planned support 49 |

README, current status and the noise note now distinguish the outer 562-bit
quantity from the final scaled work error. This is a deterministic preflight,
not a new native encrypted run or a security certificate. The older native
five-cycle logs and hashes are unchanged.

## Executed validation

- Workspace formatting and Clippy with warnings denied: passed.
- Existing five-module pinned Lean gate: passed; transitive axiom audit rejects
  custom axioms and `sorryAx` in this slice.
- All ten proof-gate positive/negative controls: passed.
- Focused `allow_insecure` public-refresh library run: 31 passed, 3 ignored.
  This includes native parameter preflight and reduced-ring encrypted
  conformance/root/history checks; it is not a full native refresh rerun.
- Coherent phase/slot tests: 6 passed, including prime/prime-square encoding,
  full negacyclic convolution and encrypted carry-plus-affine restoration.
- Existing lift-refinement Python suite: 9 passed.
- New exact prose witnesses: 77,965 comparisons/cases passed across digit,
  coefficient-divisibility, source identity, return projection, modulus drop
  and full-polynomial multiplication. Includes failed-premise controls.

The standalone release workspace build passed. The complete release workspace
test sweep finished and reported one failed target, `coefficient_slot_gate`:
15 passed, 28 failed, 19 ignored. Across the entire sweep: 2,216 passed,
28 failed, 223 ignored (70 target/doc-test summaries). The release nine65
library target itself passed 1,139 tests with 140 ignored. The failures are
toy N=8/16/32/128/512/1024
contexts refused by the release library's production N>=8192 floor, before
encrypted arithmetic. No production gate was weakened and no failed test was
removed or newly ignored. The full default workspace suite then passed with the existing CI test profile
(nine65 optimization level 2, debug assertions and overflow checks retained):
**2,245 passed, zero failed, 223 ignored**, across 70 target/doc-test summaries.
The coefficient-slot target passed all 43 nonignored tests in that mode.
README and CONTRIBUTING now state that profile.

Default workspace coverage excludes the
independent Python/WASM/FFI bindings, feature-gated integration targets and
ignored tests; no claim of their execution follows from this suite.

## Final retained evidence

The [manifest](../../artifacts/execution/2026-11-04/hygiene-proof-review/manifest.json)
records exact commands, separate pass/fail results, tool versions, source hashes
and artifact hashes. Adjacent raw logs retain both the failed whole-release
sweep and the passing CI-profile sweep. No `Cargo.lock` or Cargo feature/target
metadata changed. The only Rust edit after `a7f8531` is the scaler rustdoc/comment
correction; all executable Rust behavior is unchanged.

Post-edit formatting, workspace/all-target Clippy, local-link checks, all ten
archived documentation hashes, claim/status/security gates, the 20-file
architecture scan and the runtime no-floats gate pass. No new Lean theorem,
full Mathlib rebuild, excluded-binding run or full native five-cycle rerun is
claimed by this continuation. The user-requested new proof work is written
and reviewed before further formalization; existing proof checks stay enabled.
