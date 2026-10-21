# Six-term carry from two precharged triple blocks

Date: 2026-10-20. Baseline: `c5bb6a21ee2a174ba047b4ec9a771bf9392f4b3c`.
Scope: private research evaluator and one sparse coefficient refresh. This
does not admit a full refresh or emit a reusable 729-row state.

## Result

The three-pair terminal design failed at the next square because its cubic
lookup reached 175 error bits against a 137-bit half-scale. This experiment
changes the grouping, not the Safe Basis: the key holder precharges one family
of 27 three-trit pattern indicators, and the evaluator projects two adjacent
27-row blocks. Their joint support has 729 possible labels, but the evaluator
does not construct it as a `State`.

The terminal readout is bivariate, so its maximum product budget is
26 x 26 = 676 selector products, one multiplication level. It covers four
offset/sign queries. Each query returns a carry, one S8 root, its 2/11 phase,
and eleven sister-tray residues, for 84 total views. The requested plaintext
moduli are `2,3,5,7,11,13,17,19,6,10,77,221,1,8,27,121,4199,65537,20000`.
Every output preflights below the 137-bit half-scale; the largest is 109 bits,
and each carry bound is 92 bits. A 675-product plan and an 83-output plan are
refused before multiplication. The two positive carry tables use 183 nonzero
mixed terms in union; the full dependent-view frame reserves all 676 products
so the products can be shared across every output.

Exhaustive small-table tests check 91,854 assignments/output pairs. Omitting
the mixed term fails 26,212 checks. The clear production-size probe checks
61,236 lookup cells and predicts a 92-bit six-term refresh error. Its square
bound is 134 bits and admitted, unlike the earlier three-pair grouping.
The next square is refused in preflight at 176 bits versus the 137-bit
half-scale, before any ciphertext multiplication; this certifies one
follow-up square, not a deeper multiplication chain.

## Native encrypted evidence and limitation

The first optimized native run projected and checked both 27-row selectors,
executed all 676 shared products, and checked all 84 views at all 8192
coefficients. It verified that affine-only refresh is wrong, carry-corrected
refresh matches the independent work-domain source oracle, and the refreshed
square decrypts to the expected value. The coefficient/error-check counter
reached 1,155,072, but that run took 1,138.90 seconds and exited nonzero only
at the final instrumentation assertion: the assertion expected the
multiplication counter to include the separately executed square, while the
counter recorded only the 676 terminal products.

After correcting the counter, the native test first passed for the original
uniform all-`+1` source in 1,328.80 seconds. I then changed the first two
adjacent three-trit blocks to distinct patterns, `[1,0,1]` and `[0,1,1]`,
leaving the rest of the source at `+1`. That mixed-source run passed in
1,306.91 seconds. Both clean runs reached 1,155,072 coefficient/error checks;
the mixed-source run verified both selector projections, all 676 shared
terminal products and 84 views, carry-corrected refresh, the follow-up square,
and admission of all 19 sister moduli. The separately executed square is now
included in the multiplication count.

The mixed-source fixture still exercises one fixed vector and two adjacent
patterns, not a randomized family of independent hidden sources. This remains
research-only. Full 8192-term refresh admission, reusable encrypted state,
and production S00/S01/S03 gates remain open.

## Verified commands

```sh
python3 scripts/safe_basis_triple_precharge_probe.py
cargo check --locked --offline -j1 -p nine65 --tests
cargo test --locked --offline -j1 -p nine65 --lib triple_precharge_ -- --nocapture
cargo test --locked --offline -j1 -p nine65 --lib terminal_readout_ -- --nocapture
cargo test --locked --offline -j1 -p nine65 --lib precharged_pairs_ -- --nocapture
cargo test --locked --offline -j1 -p nine65 --lib sister_tray_ -- --nocapture
cargo test --locked --offline --config 'profile.test.package.nine65.opt-level=2' -j1 -p nine65 --lib triple_precharge_native_readouts_refresh_and_square -- --include-ignored --nocapture
```

Detailed bounds and run output are in
`artifacts/execution/2026-10-20-carry/safe-basis-triple-precharge.json` and
`safe-basis-triple-precharge-tests.txt`. No linting or workflow changes were
made.

## Follow-up: all-coefficient carry and one full refresh

After the sparse six-term refresh result, the aligned-frame carry test was
extended from six sampled coefficients to all `N=8192` coefficients for its
zero-offset ciphertext. It uses one independently generated work key and one
boot key, with the old work secret precharged under the boot key. The existing
single S8 root and the work-prime/`t` coordinate views assemble an encrypted
carry polynomial; the oracle independently reconstructs the input residuals
and checks every coefficient. For each of three residual profiles (fresh,
positive injected offset and negative injected offset), the test builds the
affine phase over the whole polynomial, restores the inverse-`N`
preconditioning with a public scalar, adds the encrypted carry, and checks the
refreshed ciphertext at all coefficients. Each profile also has a sampled
carry-only residual-retention check and an affine-only negative control.

The native command
`cargo test --locked --offline -j1 -p nine65 --lib precharged_aligned_frame_encodes_native_carry_and_retains_input_residual -- --nocapture`
passed 49,170 carry/refresh checks: 24,576 carry coefficients and 24,576
refreshed coefficients across the three profiles, plus 18 signed-noise
carry-only checks. There were 24,078 nonzero carries across the three runs,
and all three affine-only controls failed at a nonzero-carry coefficient. The
`precharged_` regression filter passed 6 tests, with 2 expensive tests ignored.
For this four-prime boot tuple, the refreshed error bound is 88 bits on the
fresh profile and at most
`17236625313898582819063915977463` (104 bits) on the injected profiles,
against a half-scale of `68945351303664909702575375964981` (106 bits). All
three refreshed outputs matched the expected constant polynomial `7` at every
coefficient. The carry-only controls still show the old residual; adding the
affine phase and carry produces the tested corrected output.

This establishes one research-only all-coefficient refresh family for one
seeded input/key pair; it is not production S00/S01/S03 admission. Remaining
gates include independent review of the complete error derivation, repeating
across source/key patterns, and a second key epoch. Refreshing the resulting
boot-key ciphertext requires that boot secret precharged under a next boot key
and a fresh carry bound for the dense output ciphertext. Exact source hashes
and test counts are in
`artifacts/execution/2026-10-20-carry/safe-basis-all-coefficient-carry.json`.
