# Typed public phase refresh, work-key return, and repeated products

This continuation completes polynomial assembly, work-key return and sealed
history re-admission for the conditional small-degree phase-clock construction.
The named-profile Clockwork gate remains closed. Degree-8 arithmetic evidence
does not establish native-degree security or performance.

## Public return construction

For boot degree D*N and work degree N with the same ordered main basis and
plaintext modulus, write X=Y^D and split the boot secret and ciphertext into
D coefficient classes. The phase's class zero is

`c0_0 + c1_0*s0 + X*sum_{r=1}^{D-1}(c1_r*s_{D-r})`.

Client setup emits D hybrid target keys encrypting these boot-secret blocks
under the work secret. Evaluation switches the public c1 blocks, applies the
public X shifts, and adds c0's class zero. It receives neither secret. Dropping
all cross blocks is incorrect; a negative regression demonstrates the loss.

`PhaseClockReturnEvaluator` validates dimensions, ordered basis, plaintext,
eta, ternary setup keys, producer family, embedding degree and storage. It
charges the complete input bound plus every work-ring switch:

`V_return <= V_assembled + t*D*N*eta*(B-1)*sum(digits)`.

`V` is ideal-grid phase error `|t*phase-Q*message|`. The work basis stays fixed;
no anchor limbs are invented. The initial implementation requires identical
work/boot main bases. A different-modulus return needs its own admitted step.

The phase producer now assembles all source coefficients at boot positions
D*j and adds their complete error envelopes. It does not treat their errors
as disjoint. Common setup binds carry controls and return keys into one bundle.
Immutable returned values retain their exact bound and family. Repeat refresh
checks that family, bound and any admitted source-domain receipt before work.

## Immutable source and return admission

`CramMainEvaluator::phase_clock_input` accepts only its own immutable
`CramMainCiphertext`. The plan must match the complete ordered basis, degree,
plaintext and level, and its allowance must cover the existing producer bound.
Main Montgomery limbs are converted coefficient-wise for preprocessing. The
opaque input provides no public raw getter, bound setter, or fresh wrapper.

Client-only setup registers source keys and return targets with the issuing
context/key IDs. A checked input marks an origin receipt only after validating
the registered key and actual clock plan. Conditional raw transduction leaves
that receipt absent, even when it uses a registered key.

Return requires both the boot family and the registered target domain to match
an admitted receipt. The latter check is necessary even if setup randomness
repeats a family nonce. A test deliberately repeats it across clients and
confirms rejection. A successful public return preserves the origin receipt;
`admit_phase_clock_return` checks it and admits the exact returned error bound.
It never substitutes a fresh-encryption bound.

This readmission is scalar-only because the existing main-Q history model is
scalar-only. The conditional full-polynomial test uses a separate observer
and does not acquire a scalar certificate. Context and key setup are trusted
as in the existing prototype; these types do not authenticate arbitrary
externally modified arithmetic tables or establish joint-key security.

## Executed paths

Both fixtures use work degree 8, boot degree 256, plaintext 65537, and the
four-prime 119-bit work modulus. Work and boot secrets are independent.

* The full-polynomial fixture encrypts signed nonconstant coefficients, adds
  public phase stress, refreshes every coefficient, assembles and returns under
  the original work key, and performs actual dependent ciphertext products.
  Two cycles reuse the same precharge. Independent schoolbook convolution
  verifies all plaintext coefficients; an exact phase observer checks the
  emitted envelopes and contraction of the stressed input.
* The history fixture starts from genuine admitted encryption and three
  ciphertext squares. Each cycle enters through the immutable bound, refreshes,
  returns, re-admits the exact producer bound, squares and adds a varying public
  offset. The offset prevents a repeated-square fixed point from making the
  long finite-field plaintext trace trivial. Every cycle checks the client
  plaintext oracle. Debug runs two cycles; optimized runs 100 with one precharge.
* Negative cases cover foreign input/return domains, raw history resets,
  unregistered keys, basis reordering/prefix substitution, understated bounds,
  repeated nonces with a different return target, invalid metadata and oversized
  setup. Repeat refresh preserves admitted receipts and rejects foreign domains.

## CI and remaining native work

The previous tip had no PR workflow runs because newer main workflow edits
made the PR unmergeable. Merge commit 6883834 reconciles those changes, preserves
the debug benchmark required by its deterministic test RNG, and fixes malformed
step joins that had hidden commands. The strict renewal witness and checker
remain present. Focused CI now runs the return and admission regressions in
both profiles, and the architecture scan includes the new production modules.

Named profiles still need an admitted native carry construction. The present
single complete-carry chart requires a coordinate above the source support
bound, whereas dense native support exceeds this practical chart's range.
A dense-to-sparse route needs reviewed source/key-security admission; the
direct precharge also exceeds practical storage at native sizes. Compact
precharge and the common-encoding multi-chart lift remain separate work.
The 100-cycle degree-8 run cannot authorize that gate.

The existing full library/workspace test suite was not rerun in this
continuation. Its previously recorded failures are not reclassified.
The accepted focused run reports **16 passed, 0 failed, 0 ignored** in each
profile. The optimized log records **100 admitted roundtrip/product cycles**
with the same precharge; debug records two. The optimized focused group took
46.61 seconds in this workspace, including the remaining focused regressions.
Workspace/all-targets clippy, formatting, the panic ratchet, all four affected
workflow parses, and the expanded 19-file architecture scan pass.
Source hashes and accepted logs are in `roundtrip-evidence/validation.json`.

Hosted CI at 2eafc90 also passes all Exactness Focused jobs, including the
optimized registered roundtrip, the exact crate/no_std build, carry models,
and basis controls. Fuzz Smoke and residue-native gates pass. The named-profile
renewal job passes its observer/preflight controls and then fails at the native
refresh witness as expected. Other repository gates remain unresolved.

Restoring CI also exposed an audit parser that combined mutually exclusive
anchor-extension branches into a 14-element union. The runtime function emits
7 anchors at the smaller audited degrees and 10 at both 16,384 and 32,768.
The follow-up parser evaluates the restricted branch grammar, cross-checks the
actual Rust function, and preserves the old audit artifact in the history
directory. Eight regression/runtime checks validate the correction; prime,
NTT, distinctness and coprimality checks remain enforced.

Reproduce the focused acceptance run with:

```sh
cargo test -p nine65 --lib phase_clock -- --skip ops::rns_fhe::tropical_phase_clock_tests --nocapture
cargo test -p nine65 --lib --release phase_clock -- --skip ops::rns_fhe::tropical_phase_clock_tests --nocapture
cargo clippy --workspace --all-targets -- -D warnings
bash scripts/check_no_panics.sh ratchet
python3 scripts/check_residue_native_architecture.py
```
