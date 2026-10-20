# Atomic encrypted state and sister-tray updates

Date: 2026-10-20. Baseline: `3198cff3bfb932c90441c27f41d85bb2f0babd8c`.
Scope: the bounded research evaluator, not production S00/S03 acceptance.

## Gap addressed

The preceding one-root experiment could attach consistent dependent views
after an encrypted carry update. It did not plan that update and all retained
views as one operation. A carry/root update could pass its own bound while a
requested sister view overflowed only after the ciphertext work was done.

The evaluator now separates public composition planning from execution.
An advance plan borrows its exact left input and owns its fixed right input,
transition edges, merged support and error bounds. The sister-tray layer
checks the proposed S8 root, 2/11 phase relation and every target layout before
executing any multiplication or emitting a proposed-state view.

The plan is a private, consumed local capability, not caller-supplied metadata.
Commit uses the same inputs, edges and error bounds that were admitted.
The source remains immutable on rejection or cancellation. This is local
same-source/plan consistency, not a cryptographic input-history attestation.
Only the test driver receives a secret key and expected S for independent
post-commit assertions. `prepare_advance` and the consumed plan's `commit`
receive neither a secret key nor a clear expected result.

## Phase and lifetime checks

For every actual planned edge, the gate checks

```text
b_out = (b_left + b_right) mod 2
j11_out = (j11_left + j11_right + floor((b_left+b_right)/2)) mod 11.
```

Here `j11=floor(S/2) mod 11`, not the global BFV refresh carry.
The guard is tested with a deliberately corrupted destination row that must
refuse. The immutable source borrowing prevents substituting a different
parent or changing the ciphertext inputs between planning and execution.
Old tray handles remain valid only for their old source, and cannot be rebound
to the new root/value state, even when the tested plaintext happens not to change.

There is still one S8 root descriptor. The two dependent trays may have
arbitrary positive/shared/repeated moduli within their explicit encoding and
noise limits. No second Safe Basis, ciphertext prime or boot-key family is added.

## Outcome-dependent retry tested

For both carry signs, the first two native encrypted updates retain

```text
tray A = {77,221}
tray B = {1,6,10,8,27,121,385,4199,6,65537}.
```

The third carry/root update alone fits, but the wide-layout proposal does not.
For the negative sign its first failing view is 385, requiring 138 error bits;
for the positive sign it is 4199, requiring 140 bits. The half-scale is 137 bits.
The whole proposal is refused before any of its selector products or output
views are evaluated. The source state and its existing tray handles remain valid.

The test then retries the same encrypted update with

```text
tray A = {6,10,15,21}       period 210
tray B = {1,8,9,11,22,6}   period 792.
```

These views fit at a largest 133-bit error bound. The carry bound still grows
from 86 to 129 bits; changing the layout does not reset or lower the source
state's error certificate. Commit preserves every planned row bound exactly.
The selected third trit is zero in the chosen native fixture, so the actual
S and its 2/11 plaintext observations stay the same while its computation
history and worst-case error change. Reusing the old certificate is not allowed.

The three commits execute 0,9,15 selector products per sign. Rejected proposals
execute none. The following fourth sequential update still refuses at the
original selector-noise gate. Dropping expensive views permits a valid third
step; it does not create another level of ciphertext multiplication depth or
solve the full 8192-term sum.

## Verification and limits

The native run checks all 8192 coefficients of the root, phase and configured
sister outputs after every committed update, for both signs. Prefixes one and
two have 21 outputs each; prefix three has 19. This is 999,424 frame checks,
plus the parent's 49,488 composition/refresh/square checks: 1,048,912 encrypted
coefficient/error checks in total. Existing balanced four-term composition,
sparse near-cut coefficient refresh and its subsequent encrypted square remain
part of the same run.

The fast tests retain the prior 50,004 phase cases and add plan cancellation,
parent mismatch, non-centered terms, foreign input families, invalid/oversized
layouts and malformed transition-edge refusal. The separate clear probe checks
all 54 three-trit assignments across the two native public sign schedules,
and reproduces the per-step bounds, product counts, wide refusal, compact retry
and fourth-update refusal with arbitrary-precision integers.

```sh
python3 scripts/safe_basis_tray_transition_probe.py
cargo test --locked --offline --config 'profile.test.package.nine65.opt-level=2' -j1 -p nine65 --lib sister_tray_ -- --nocapture
cargo test --locked --offline --config 'profile.test.package.nine65.opt-level=2' -j1 -p nine65 --lib precharged_composition_ -- --include-ignored --nocapture
```

Evidence is `safe-basis-tray-transitions.json` and its corresponding test log
under `artifacts/execution/2026-10-19-carry`. Earlier evidence is preserved for
its original source hashes. This patch does not accept S00/S01/S03, implement
the complete heterogeneous operator fabric, authenticate remote provenance,
or enable production public refresh. Those gates, full-sum circuit scaling,
and the key/input-history factory remain open. CI, profiles and linting policy
are unchanged; no lint tool is used.
