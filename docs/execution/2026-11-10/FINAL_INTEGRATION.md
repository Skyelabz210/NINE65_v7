# Final optimization integration checks

The recovered source snapshot is `3b4466a2030573029ad04e45222cc71374c8ed94`,
with tree `fbfa8322675375af402c4206ce25899a8d49edcb`, identical to checked local
commit `78eddfba9283e501cf5ff43dfcaaa051028b0f64`. It combines research `0986fca`
with main `a6780e9`; earlier scheduler, entropy, depth, Lean, evidence and CI
repairs are retained. The source recovery report records its 106 focused
passes, three ignored tests and feature checks.

Additional interactions passed: 11 scheduler regressions (including 24 squares
and six actual reduced public refreshes), seven release entropy tests, three
release arithmetic tests, ten distribution controls, ten existing parameter
controls, eight audit controls and claim/status/security checks. The scheduler
binary was built from the identical recovered source tree; release checks and
key-free exports ran from the final integration worktree.

The new source-bound distribution and key-graph supplements are under
`artifacts/execution/2026-11-10/final-integration/`. Parameter semantic data is
unchanged. Only the key-publication fingerprint changes in the graph packet;
its audit verifies 659 ciphertexts, 160 return channels and 5,184 finite channel
equalities. These are evidence checks, not a new native encrypted run.
The default distribution checker uses this new supplement. Earlier frozen
packets are untouched. The current modulus ledger changes only its rns.rs
source hash and derived evidence hash; its Rust catalogue cross-check passes.

## Open strict gate

The panic-pattern ratchet remains **failing**, with 79 production `.expect`
patterns against a budget of 77. Three explicit admission refusals were added
in `to_u256_level`, `crt_reconstruct_u256` and `CrtU256Plan::new`; one earlier
NTT FFT constructor expect was removed. The net increase is two. These refuse
unsupported empty or oversized U256 conversions rather than silently truncate.
The panic budget, scanner and runtime refusals have not been changed to make
this gate pass. A separate reviewed API/error-handling or budget decision is
still required. Existing infallible APIs can panic on unsupported inputs.

No full workspace runtime sweep, dense K0 completion, full native refresh,
new timing/constant-time result or production-security admission is claimed.
The integration is published with the strict ratchet failure explicitly open.
