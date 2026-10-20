# Composing encrypted carry states

Date: 2026-10-20. Baseline: `4485bd6d89fdc402de215fccb6a993c4bcbef6ed`.
Scope: a bounded research runtime and sparse coefficient refresh at native
ring degree, not general public refresh.

This experiment replaces the local gate's public starting-remainder argument
with an encrypted state. It also supplies a compact packed precharge producer
and its actual coefficient-extraction operations. It does not assume that
those scalar inputs or their encoding conversions are free.

## State and composition

A public row labels a possible `(g,K)` satisfying `S=g+Q_work*K`. Its encrypted
one-hot selector hides which row is active. Public row labels are alternatives,
not a clear copy or cache of the selected secret winding. The starting row has
the public initial remainder and a public unit selector.

For two encrypted block states, the public transition table applies

```text
c = nearest_Q(g_left + g_right)
g_out = g_left + g_right - Q*c
K_out = K_left + K_right + c
selector_out += selector_left * selector_right.
```

The evaluator evaluates all admitted transitions; it does not learn the active
row. Equal **pairs** `(g_out,K_out)` may be merged by ciphertext addition.
Remainder equality alone is insufficient: states S=0 and S=Q have equal
remainder and different windings and Safe Basis projections.

Appending one secret trit is a special case: construct a three-row state for
the public coefficient times the encrypted trit, then use the same block
composition operation. Both sequential and balanced trees therefore use the
updated encrypted state. The wrong-reset Q=17, r0=8, terms 8 and8 regression
returns one carry, while resetting to r0 for each term returns two.

Every query derives the winding or a root view from this same state. For each
root prime p it uses

```text
S mod p = (g mod p + (K mod p)*(Q_work mod p)) mod p.
```

All eight roles `{2,3,5,7,11,13,17,19}` remain available after every admitted
transition. A root-view ciphertext encodes the **canonical integer residue**
in the common plaintext ring t=65537, rather than switching to an Enc_p
encoding. This interface distinction is explicit; no homomorphic canonical
lift between those encodings is assumed.

## Packed precharge and extraction

The key holder constructs three indicator polynomials, one for each source
coefficient value -1,0,1, and encrypts them under one independent boot secret.
The source test polynomial includes all three trit values and is a chosen
test fixture, not a fresh work-key-distribution experiment.

The polynomials are directly preconditioned by `N^-1=-8 mod65537` before
encryption. A public monomial shift and 13 native Galois trace operations
extract a coefficient's three one-hot indicators as constant plaintexts.
Since `8192*(-8)=1 mod65537`, the resulting plaintext indicators are exact.
The bound includes both their actual encoding error and all key switches:

```text
beta = eta*(2N+1)
E_projected <= N*(beta+8) + (N-1)*E_switch.
```

This is an explicit producer for the scalar selector interface. It uses the
main-Q ciphertext type throughout. No raw coprime RLWE lane or clear
secret-dependent remainder is emitted.

For the five-prime profile, main coefficient storage is 1,966,080 bytes for
the packed precharge and 183,500,800 bytes for shared trace/relinearization
keys, excluding allocation overhead and scratch space. Directly storing
three separate scalar ciphertexts for every source coefficient would require
16,106,127,360 bytes. Packing reduces key storage but does not remove trace
work: extracting every coefficient still requires `3*N*log2(N)` Galois
switches in this reference schedule.

## Admission and limits

The runtime plans transitions, merged-selector errors, carry error, all eight
root-view errors and the public state-count limit **before** executing a
ciphertext multiplication. A refusal leaves the input state intact. The
tests count executed multiplications to verify that rejected transitions do
not perform additional work. Regime mismatch and non-centered input terms
are also refused before evaluation. Family tags here are consistency checks
on private test types, not a cryptographic authentication mechanism.

The following security values are results of the repository's two in-tree
screens at an independently supplied 128-bit target, not external security
certification:

| Boot chain | Product bits | Core-SVP / MATZOV | Decision |
| --- | ---: | --- | --- |
| Four primes | 123 | 190 / 171 | Screen passes; two sequential terms fit |
| Five primes | 154 | 151 / 136 | Screen passes; selected composition profile |
| Six primes | 184 | 127 / 114 | Refused for the native 128-bit target |

The five-prime chain adds 1711276033 to the earlier four boot primes.
The six-prime candidate adds 1224736769 and is not used to generate keys.
Primality, NTT compatibility and coprimality are checked separately.

For the selected public support, three sequential terms fit. Their merged
support sizes are 3,5,7 rows; carry error bounds use 42,86,129 bits and the
largest root-view bounds use 46,90,133 bits. The encoding has a 137-bit
half-scale. A fourth sequential multiplication is refused.

A balanced four-term tree composes two two-term encrypted states instead.
It uses two selector-multiplication levels and nine public support rows. Its
carry and largest root-view bounds use 131 and135 bits respectively and
remain below the same half-scale. This is a bounded-depth improvement, not
permission to add an underscreened modulus. A further tested merge is refused
by the noise certificate.

The small support sizes above come from these public coefficients and valid
row merging. General coefficients may create exponentially many different
states. The configured state limit refuses that growth; it does not establish
a scalable 8192-term representation. The remaining production problem is a
compact state/circuit and complete noise/key/input-history admission for the
full secret sum. This reference runtime remains test-only and no public
refresh entry point is enabled.

The clear probe also budgets an optimistic balanced selector tree, omitting
row-merging and output-projection amplification. In the five-prime profile,
its error bounds use 42,84,126,168 bits at 1,2,4,8 leaves respectively; the
eight-leaf bound is already above the 137-bit half-scale. This particular
8192-leaf reference schedule needs 13 multiplication levels, not the two
currently admitted. This quantifies why merely balancing this construction
or precharging its leaves does not close the full-refresh gap. It is not an
impossibility result for a different compact carry circuit.

## Bounded coefficient refresh and follow-up multiplication

The next check uses that same two-term encrypted carry to correct an actual
sparse work-domain BFV phase. For target coefficient j=1 the constructed
components have only R0[1], R1[1], and R1[0] nonzero, where
R=t*c-Q*nearest(t*c/Q). With the chosen source coefficients s[0]=1 and
s[1]=-1, their sum is S=+3H or -3H, H=floor(Q_work/2). The true source
exact-grid distance is H-1: one integer unit from the decoding cut. These
are constructed near-cut ciphertext components, not a claim about the
distribution of fresh encryptions or arbitrary work keys.

The evaluator computes the public rounded component polynomials, evaluates
their affine phase using an additional encryption of the source polynomial
under the independent boot secret, extracts coefficient 1 by the same
preconditioned trace, and adds the encrypted carry. Its function receives
neither secret key and performs no decryption. The source phase oracle is
used only by the independent assertions. In both signs the uncorrected
affine result is wrong by the carry; the corrected constant plaintext must
match the actual source decode.

The output error certificate includes affine evaluation, preconditioning,
trace switches, and carry evaluation. Its 86-bit bound does not include or
retain the old H-1 residual. Squaring the refreshed coefficient with the
exact BFV multiplier gives a 128-bit bound, below the 137-bit half-scale,
and must decrypt to the squared message. This is a bounded end-to-end
coefficient demonstration, not a full-polynomial bootstrap or an admitted
production source/key/input-lineage factory. The extra encrypted source
polynomial costs 655,360 bytes in the five-prime profile, in addition to the
packed selector and shared evaluation-key storage above.

## Evidence and reproduction

The native probe uses N=8192 and t=65537, four extracted source coefficients,
both carry signs, and root projections at each of three sequential prefixes
and at the four-term balanced result, followed by sparse coefficient refresh
and an encrypted square for each sign. There are 49,488 encrypted
coefficient/error-bound checks: 336 at four decoded positions per composition
output, plus all 8192 coefficients of each uncorrected, refreshed and squared
output for both signs. All
decryption/reconstruction is in independent assertions after the evaluator
has produced its output.

The clear probe exhausts 50,625 small three-trit cases and 64,827 native
boundary cases, checking three prefixes and all eight root views. It also
checks 253,125 small four-trit balanced cases and 19,683 native balanced
cases. Its quadratic-noise ceilings are independently checked using Python
arbitrary-precision multiplication/division.

```sh
python3 scripts/safe_basis_composition_probe.py
cargo test --locked --offline --config 'profile.test.package.nine65.opt-level=2' -j1 -p nine65 --lib precharged_composition_ -- --include-ignored --nocapture
```

The command-scoped optimization speeds native arithmetic. It leaves test
assertions, overflow checks and all scheme gates active and changes no
repository/CI profile. The initial unoptimized exploratory native run was
interrupted for this optimization and is not counted as a passing run.
The inexpensive parameter/security admission test runs by default. The new
expensive native probe runs automatically in the existing `slow_tests` CI
tier, or explicitly with the command above. No existing correctness,
security or admission check is disabled, and no workflow is changed.
New artifacts preserve the earlier source-bound evidence rather than
rewriting historical hashes.
