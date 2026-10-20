# Six-term carry from three precharged pair blocks

Date: 2026-10-20. Baseline: `ad276249b8b827868959957919ded3319c96b795`.
Scope: private research evaluator and one sparse coefficient refresh. This does
not admit production refresh or emit a reusable combined state.

## What this advances

The preceding terminal readout combined two precharged pair states. This
experiment reads three pair states directly, without constructing their
729-label product state. A three-dimensional mixed-difference lookup returns
the carry for the six weighted terms. The requested 2/11 phase is computed
from the three pair phases and parity bits using

```text
j_total = j0 + j1 + j2 + j3 + floor((b0+b1+b2+b3)/2)  (mod 11)
```

where `bi` is the corresponding value modulo 2 and `ji=floor(value/2) mod 11`.
Conditioning on the public offset parity, the crossing is a degree-three
Boolean polynomial: three pair products and one triple product. The tests
check negative values and both offset parities.

The public carry table has 83 nonzero three-way differences for the `H` offset
and 65 for the `-H+40` offset, out of 512 possible top-order terms. Its linear
and pair terms are charged too. The two carry offsets share 146 selector
products. Their conservative bounds are 133 and 132 bits against the same
137-bit half-scale. The 2/11 phase uses four parity products and has a 128-bit
bound.

The same single S8 root and the existing dependent layouts produce residue
classes modulo `2,3,5,7,11,13,17,19,6,10,77,221,1,8,27,121,4199,65537`.
For this terminal frame, small-modulus outputs are additive residue
representatives; the tests compare each value modulo its tray modulus. They
are not normalized reusable encrypted state. Their bounds range from 0 to 62
bits. A modulus-20,000 canonical lookup needs the full mixed-difference table
and is refused at 148 bits before any selector multiplication.

## Native result and next boundary

The native fixture uses three independently projected pair states from one
packed source, with all six selected trits equal to `+1`. It verifies carry
`+3` and `+2`, their negatives, the phase class and all listed residue views.
It then applies carry `+3` to a sparse six-term coefficient at work-domain
coefficient 5. The affine-only output is wrong; the corrected output matches
the independent source-decryption oracle at all 8192 coefficients. In total,
425,984 coefficient/error checks pass. The carry products number 146 and the
2/11 phase products number 4.

The corrected refresh output has a 133-bit certified error bound and passes
the native decrypt check. Squaring it is refused before multiplication: the
projected error is 175 bits against a 137-bit half-scale. This isolates the
next target: retain the same precharge storage while reducing the carry
evaluation depth enough to leave room for a square.

The fixture checks one chosen all-positive source, not 425,984 independent
encrypted inputs. Its security call is the repository's in-tree bootstrap
screen, not an external evaluation. The result remains research-only; the
full 8192-term refresh, authenticated source/history admission and production
S00/S01/S03 gates remain open.

## Reproduction

```sh
python3 scripts/safe_basis_three_pair_probe.py
cargo check --locked --offline -j1 -p nine65 --tests
cargo test --locked --offline --config 'profile.test.package.nine65.opt-level=2' -j1 -p nine65 --lib terminal_three_pair_ -- --include-ignored --nocapture
```

The clear oracle exhausts 2,916 small label assignments and records 1,096
cases where omitting the three-way carry term fails. The native log and exact
integer bounds are in `artifacts/execution/2026-10-20-carry/`.
No linting or workflow changes were made.
