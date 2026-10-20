# Terminal carry and Safe Basis readouts without a combined selector state

Date: 2026-10-20. Baseline: `7441e7d2a87f6000beecd1c8edd18b2e637d0fee`.
Scope: private research evaluator and sparse coefficient refresh, not production
refresh admission or a reusable full-sum state.

## The gap addressed

Two precharged pairs can each have nine possible sums. For general public
coefficients their combination has 81 distinct sums, exceeding the reference
runtime's 27-state cap even though a final carry calculation can fit its noise
budget. The previous implementation constructs encrypted selectors for the
combined state before projecting its carry and views.

The new terminal route computes the requested readouts directly from the two
input pairs. It does not allocate 81 combined-state ciphertexts or increase
the state cap. A separate, explicit product/output budget bounds its work.
Its result is a `TerminalFrame`, not a `State`; it cannot be supplied to the
existing composition routine as if it retained the hidden remainder state.

## The exact mixed-difference identity

Let x_i and y_j be the one-hot indicators of the left and right pair. For a
public lookup table f_ij, use x_0=1-sum(i>0)x_i and y_0=1-sum(j>0)y_j:

```text
F = f00
  + sum(i>0) (fi0-f00) * x_i
  + sum(j>0) (f0j-f00) * y_j
  + sum(i,j>0) (fij-fi0-f0j+f00) * x_i*y_j.
```

The last coefficient is a mixed finite difference. It supplies the nonlinear
boundary correction; omitting it is not generally valid. Nine indicators on
each side require 8*8=64 selector products. Every requested carry, root lane,
phase coordinate and sister view can reuse those same products with different
public coefficients. Each product is accumulated into the outputs and then
discarded. No selected secret sum or scalar winding is supplied to the evaluator.

The input one-hot property comes from the existing key-holder pair-precharge
producer for a validated ternary source. It is not inferred from arbitrary
ciphertexts or proved by the family tag. Preparation uses an independent boot
secret, the existing five boot primes and plaintext modulus 65537. No new key
family, ciphertext prime or plaintext-modulus conversion is introduced.

Every query describes `sign*(initial+S_left+S_right)`. Public labels are computed
from the two possible `(g,K)` pairs by centered remainder addition and its
crossing. Their winding, all eight S8 residues, and
`j11=floor(S/2) mod11` define a single query frame. Sister moduli are arbitrary
positive values up to the explicit common-encoding limit 65537. They are views
of that frame's value, not additional Safe Bases.

## Admission and error accounting

An immutable consumed plan borrows both exact pair inputs. Before any product
or output ciphertext is evaluated, it checks their private family/source
regime, adjacent and disjoint source indices, encrypted-selector presence,
centered pair labels, query sign/offset/moduli, product and output limits,
input errors, every product error and every requested output error.

For each output its conservative bound is

```text
|f00| + sum(i>0)|fi0-f00|*E_xi + sum(j>0)|f0j-f00|*E_yj
      + sum(i,j>0)|fij-fi0-f0j+f00|*E_product(i,j).
```

The constant term is encoded publicly at the existing delta scale and charged
at most |f00| error. Negative coefficients are charged by magnitude. Replacing
the first indicator using its exact plaintext relation changes the circuit;
it does not assume that encrypted errors cancel or reset the surviving errors.
Execution preserves every planned bound exactly and shares products only
across queries over the same immutable input pair states.

The fast refusal tests include a 63-product budget for a required 64 products,
79 allowed outputs for an 80-output request, wrong family, overlapping source
indices, missing selectors, invalid queries, exhausted input noise and a bundle
whose products fit but whose output bound fails. Refusals and cancellation
perform no selector multiplications. These are private consistency checks, not
production cryptographic input-history authentication.

## Native fixture and follow-up refresh

Let H=floor(Q_work/2). The public coefficients are
`[H-1,H-3,H-9,H-27]`. Each pair has nine distinct possible sums and the full
four-term source has 81. The existing combined-state planner must refuse at
the 28th row before executing a multiplication.

The actual first four source trits are `[1,1,1,1]`; both weighted pair sums are
nonzero. The same two extracted pair states serve four queries:

| Initial offset | Sign | Actual carry | Old exact-grid distance | Fresh bound bits | Square bound bits |
| --- | ---: | ---: | --- | ---: | ---: |
| H | +1 | +2 | H-42 | 89 | 131 |
| H | -1 | -2 | H-42 | 89 | 131 |
| -H+40 | +1 | +1 | H-1 | 88 | 130 |
| -H+40 | -1 | -1 | H-1 | 88 | 130 |

In the H-offset case each sequential pair addition changes the carry:
0 to +1 to +2, or its negative. In the other offset case the two pair windings
alone sum to +2, but the remainder crossing contributes -1, giving +1; the
negative query reverses those signs. For the selected indicators, the mixed
carry coefficient is -1 or +1 in these latter cases. A linear-only readout
would give the wrong carry. This addresses the previous native fixture's
canceling second pair and exercises the nonlinear correction itself.

Each frame includes its carry, eight root lanes, 2/11 coordinate and two
dependent layouts `{6,10,77,221}` and `{1,8,27,121,4199,65537}`. Across these
80 requested outputs the largest error bound uses 105 bits, below the same
137-bit half-scale. There is one intact S8 root per query; the four queries
represent four separate source ciphertext fixtures sharing precharged keys.

For every query the test constructs an actual sparse work-domain ciphertext
at target coefficient j=3. Its four residual coefficients are the signed
public terms and its R0 coefficient is the signed initial offset. The affine
phase alone must decrypt incorrectly; adding the terminal encrypted carry
must agree with an independent source-decryption oracle. A subsequent exact
encrypted square must decode correctly within its bound. The old near-cut
residual is absent from the fresh bound.

The native run checks all 8192 coefficients of 18 input selectors, 80 frame
outputs and 12 affine/refreshed/squared outputs: 901,120 coefficient/error
checks. These are checks across one chosen source and four public queries,
not 901,120 independent encrypted inputs. It performs 64 shared selector
products plus four subsequent ciphertext squares. The clear probe separately
shows that another square would exhaust the current certificate; that refused
extra square is not claimed as a native execution.

## Remaining limits and reproduction

This removes a combined-state storage obstruction for bounded final readout.
The public tables still enumerate possible pairs of input labels, and a
larger general secret sum would require larger inputs or a different circuit.
The terminal frame does not retain encrypted indicators for its 81 joint
states and supplies no general next-step composition interface. Full 8192-term
refresh, compact reusable state, source/history admission and production
S00/S01/S03 acceptance remain open. Noise admission is unchanged.

```sh
python3 scripts/safe_basis_terminal_probe.py
cargo test --locked --offline --config 'profile.test.package.nine65.opt-level=2' -j1 -p nine65 --lib terminal_readout_ -- --include-ignored --nocapture
```

The independent clear probe checks 1,180,980 small readouts and 6,480 native-size
readouts, including negative carries and arbitrary dependent moduli. Its
linear-only negative control fails in 220,899 of the small checks. Native
and targeted regression results are recorded in `safe-basis-terminal-tests.txt`;
exact budgets and source hashes are in `safe-basis-terminal.json`, both under
`artifacts/execution/2026-10-19-carry`. Prior evidence remains historical.
No linting, workflow changes or hosted-CI success claims are included.
