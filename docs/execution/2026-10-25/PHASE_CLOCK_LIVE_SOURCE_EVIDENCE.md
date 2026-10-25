# Issue #95: live-source phase-clock evidence

The public refresh gate in `bootstrap.rs` remains closed. These are research
fixtures, not a production bootstrap or a security admission.

## What the evaluator actually receives

For a source ciphertext `(c0,c1)` at `Q_source`, each public component is
split exactly as `p*c_i = Q_source*a_i + R_i`, with centered `R_i`.
For output coefficient `j`, the evaluator forms the public negacyclic
weights from `R1`; the key holder precharges opaque ternary selectors once.
The encrypted clock emits the hidden carry

`K_j = round((R0_j + (R1*s)_j)/Q_source)`.

The evaluator combines that fresh carry with an encrypted affine expression
in the public `a_i`. It receives neither source trits nor client-decoded
plaintexts, phase errors, or carries. A separate test observer checks those
values after evaluation.

## Measured focused results

| Fixture | Degree | Nonzero trits / public selector positions | Carry | Source scaled-residual bits | Refreshed error bits | First square |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Synthetic signed | 1024 | 8 / 8 | -2 | 112 | 46 | Exact |
| Synthetic mixed | 1024 | 16 / 16 | 4 | 112 | 47 | Exact |
| Synthetic decoy cover | 1024 | 8 / 12 | -2 | 112 | 46 | Exact |
| Live RNS source, wrapped slot 0 | 512 | 8 / 12 | -1 | 112 | 44 | Exact |
| Same source, unwrapped slot 511 | 512 | 8 / 12 | 1 | 112 | 44 | Exact |

The live source has a uniform full-width public mask under a separate sparse
source key. Its two stressed coefficients remain BFV-decodable; the stress
term is a public addition to model an evaluated input's large phase error.
The 12-position cover includes four encrypted zero selectors. The same
precharge is reused for both coefficients, whose public residual weights and
negacyclic signs differ. The fixture has `security_bits=0` and a small ring.

## Native capacity and missing proof

For true source weight at most 96 and `V/Q_source <= 1/16`, the signed
99-clock has `twice_window = 4096 + 99*97 = 13699 < 16384` in a doubled
ring. At degree 8192 its window is `2048 + 99*97 = 11651 > 8192`, so that
single-clock geometry refuses. A public cover can contain more than 96
positions while the key-holder-certified *true* weight stays 96; the noise
bound still counts every evaluated cover position.

The present five-lane base-2^10 gadget stores four RNS hybrid keys per
ternary position, with four digits per lane and two full RNS polynomials per
digit. Raw coefficient storage is `6400*N` bytes per position. At degree
16384, a 128-position cover requires **12.5 GiB** before allocation and
protocol overhead; all 8192 positions at degree 8192 require **400 GiB**.
The current machine has about 2.7 GiB RAM, so neither is a native runtime
measurement. Decoy positions do not make the boot key compact.

For a 96-nonzero secret conditional on a public 128-position cover, the
simple support-and-sign count has `log2(binomial(128,96)*2^96) ~= 196.22`
bits. This is **only a counting bound**. It does not establish 128-bit
RLWE/LWE security, key-dependent-message security for the selector columns,
or indistinguishability of their zero and nonzero values. The current in-tree
screen assumes dense ternary secrets and cannot certify this sparse/covered
source. A key-holder-bound weight certificate and independent sparse-secret
attack estimate are required before using the smaller clock window.

The next engineering boundary is the native dense-work-to-sparse-source
switch followed by this clock, with a reviewed key and support policy.
That still must return to the work key, refresh all coefficients, survive
the next product and repeat cycle, and either connect to the single 2/11
Safe-Basis root and common-T sister trays or provide an equally reviewed
CRAM transduction. No result here removes the production fail-closed gate.
