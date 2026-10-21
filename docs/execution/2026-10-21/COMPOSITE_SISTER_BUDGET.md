# Composite sister-tray budget control

Scope: the existing bounded native encrypted research evaluator. This is not
a production refresh admission or a change to the ciphertext modulus.

The owner selected **composite sister-tray moduli**, not gadget radices. The
new planner selects the largest composite in an explicit requested interval
whose dependent-view error fits an exact integer cap. One Safe Basis root,
all eight S8 roles, the 2/11 phase relation and the original ciphertext/key
parameters are preserved. Existing requested layouts must also pass; the
planner does not quietly drop them to admit its composite.

## What is controlled

For each public possible-state row r, the native runtime derives its target
residue without reconstructing the selected hidden value:

```text
v_r(m) = (g_r mod m + (K_r mod m)*(Q_work mod m)) mod m
E_view(m) = sum_r v_r(m) * max(E_selector,r, 1)
```

This is the existing conservative coefficient error bound, including the
public-constant case. The planner requires both `E_view <= requested_cap`
and `requested_cap < native_half_scale`. The cap is **per output**, not a
shared pool that can be replenished by adding residue lanes. Choosing a
composite changes the public projection coefficients, so it can change the
view's real certified error without changing the source selector error.

Selection depends only on public possible-state support and its bounds,
never on the decrypted state, sampled measured error or a secret key.
It is performed against the proposed updated state **before** selector
multiplication or output emission. The consumed update plan retains the
same source, edges and bounds through execution.

## Information and boundary checks

This adaptive interface imposes a stronger condition than arbitrary modular
projection: the chosen target must distinguish every row in the admitted
public support. A cheap constant or aliased view is refused. This guarantees
separation only for that finite support, not an arbitrary unbounded integer.
Generic sister views still allow intentional aliases, repeated/shared-factor
moduli and modulus 1; their existing interface is unchanged.

The caller also supplies a minimum and maximum modulus. The current canonical
target-in-plaintext encoding still caps the maximum at 65537. A failed budget
cannot silently lower the minimum. Joint view periods are LCMs, not products
of overlapping moduli, and a period alone is not a separation proof.

The error need not increase with modulus: residues wrap. The planner searches
the entire bounded candidate interval in descending order. For possible
states {1,11} with unit bounds, modulus 6 costs 6, modulus 8 costs 4, and
modulus 9 costs 3. Modulus 10 costs only 2 but aliases the states and is refused.
No prime-only or catalogue-only restriction is imposed on target candidates.

## Native experiment

After the same three encrypted updates used in the previous tray-transition
experiment, search composites in [35,65537]. Preserve the compact retained
layouts `{6,10,15,21}` and `{1,8,9,11,22,6}`, then attach the selected composite
as another dependent view of the same root. All seven support rows must remain
distinct in that selected target.

| Cap as fraction of native half-scale | Negative public schedule | Positive public schedule |
| --- | --- | --- |
| 1/2 | 315 | 300 |
| 1/3 | 194 | 206 |
| 1/4 | 158 = 2*79 | 123 = 3*41 |
| 1/5 | 78 | 93 |
| 1/8 | 45 | 65 |

The quarter-cap selections are actually emitted and decrypted against an
independent client oracle at every one of the 8192 coefficients, together
with the root, phase and retained views. The other eight selections are
native public-bound checks, not additional encrypted emission runs.
For each selected modulus, its exact bound is admitted and one unit less
is refused. At a 1/16 cap neither schedule fits the requested minimum 35;
the source is preserved and no output/work is committed.

The current test matrix and source-bound results are in
[`artifacts/execution/2026-10-21/composite-sister-budget`](../../../artifacts/execution/2026-10-21/composite-sister-budget).
The independent Python probe exhausts 918 small-domain budget cases, proves
maximality over the entire native candidate interval, and compares all ten
native bounds as exact integers when given the encrypted-run log.

## Remaining limit

This makes the sister-view cost tunable; it does **not** reset source error,
remove BFV residual, or add a ciphertext multiplication level. The next
fourth sequential update must still refuse at the original selector-noise
gate. The separate p-squared digit-removal circuit's 131-versus-113-bit
failure is not fixed by this view planner. Full-sum scaling, authenticated
input/key history and complete native refresh remain unresolved.

## Reproduce (no lint)

```sh
python3 scripts/composite_sister_budget_probe.py
cargo test --locked --offline --config 'profile.test.package.nine65.opt-level=2' -j1 -p nine65 --lib sister_tray_ -- --nocapture
cargo test --locked --offline --config 'profile.test.package.nine65.opt-level=2' -j1 -p nine65 --lib precharged_composition_ -- --include-ignored --nocapture
python3 scripts/composite_sister_budget_probe.py --native-log artifacts/execution/2026-10-21/composite-sister-budget/native-tests.log
```
