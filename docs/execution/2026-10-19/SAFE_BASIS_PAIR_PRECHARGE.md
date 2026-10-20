# Pair precharge for bounded hidden-carry composition

Date: 2026-10-20. Baseline: `b0adf341b1c099f45db48785f19d091ce548b213`.
This is research code under `#[cfg(test)]`, not production refresh admission.

## Why pairs

The single-trit producer encrypts three possible values per secret coefficient.
Combining two such inputs spends a ciphertext multiplication level before a
larger carry state can be formed. The pair producer instead encrypts the nine
indicators for `(s[2j],s[2j+1])` during key-holder preparation. It receives the
source secret at preparation time, but does not receive the later ciphertext,
its residual coefficients, or its carry.

Nine packed ciphertexts cover every adjacent pair of the 8192-coefficient
source. Slot j in pattern `(u,v)` contains `-8` exactly when that pair equals
`(u,v)`, and zero otherwise. The upper half of each polynomial is zero.
The same independent boot secret, five boot primes, plaintext modulus 65537,
13 Galois trace keys and relinearization key are used as before.

Since `8192*(-8)=1 mod65537`, trace extraction produces encrypted constant
one-hot indicators. It includes the existing 42-bit projection error bound.
The evaluator can then form a pair state for arbitrary centered public
coefficients a,b and public initial offset r:

```text
S_uv = r + a*u + b*v
K_uv = nearest_Q(S_uv)
g_uv = S_uv - Q*K_uv
```

These are public labels of possible states. The selected pair and carry
remain encrypted. Equal `(g,K)` alternatives merge by ciphertext addition;
their error bounds are added. No ciphertext multiplication is used to form
the first pair state. Foreign family, invalid pair index, non-centered
coefficients, capacity and noise failures are checked before trace work.

The pair state feeds the existing composition planner. All eight Safe Basis
roles and dependent views are derived from the same state. This adds no
second Safe Basis, ciphertext prime or plaintext-modulus conversion.
The common encoding still represents canonical integer residues in t=65537.

## Native test domain and results

The bounded native experiment uses the same N8192, eta3, t65537 and five-prime
154-bit boot chain as the preceding composition experiment. Its two in-tree
security screens must pass the 128-bit target before keys are generated.
No new security certification is claimed.

Let H=floor(Q_work/2). Both signs use initial offset `+/-H` and eight public
terms `+/-[H,-H,H,H,H,H,H,H]`. Four encrypted pair states are projected.
The first four source trits are `[1,-1,-1,1]`; the remaining packed source
contains all nine pair patterns. This is a chosen test fixture, not a random
source-key distribution test.

| Evaluated state | Public rows | Carry bound bits | Largest root bound bits | Result |
| --- | ---: | ---: | ---: | --- |
| Four terms, two precharged pairs | 9 | 89 | 93 | Admitted |
| Six terms, four-term state plus one pair | 13 | 133 | 136 | Admitted |
| Eight terms, two four-term states | 17 | 135 | 138 | Refused |

The four- and six-term results also check the dependent layouts
`{6,10,15,21}` and `{1,8,9,11,22,6}` and the additive 2/11 phase coordinate
`j11=floor(S/2) mod11`. Clear composition tests explicitly include the parity
crossing in its update. Native tests verify their encrypted values and error
bounds. This is the bounded additive relation, not acceptance of the full
heterogeneous operator fabric or production provenance.

The balanced eight-term proposal fails at the root-11 projection before any
of its proposed selector products execute. Both that error and the allowed
half-scale have 137 bits; admission compares their full integers, not their
bit counts. The largest root error is 138 bits. A sequential attempt to add
the fourth pair to the six-term state also refuses, at selector multiplication.
The inputs remain unchanged after either refusal.

## Actual four-term coefficient refresh and follow-up

The native test constructs a sparse work-domain ciphertext with four nonzero
R1 residual coefficients. Its target coefficient is j=3, with
`R0[3]=+/-H` and `R1[3-i]=term[i]` for i=0..3. The four selected secret trits
are all nonzero. Their residual sum is `+/-3H`, giving carry `+/-1` and an
old exact-grid distance H-1, one integer grid unit from the decoding cut.
The second pair's selected weighted sum cancels in this chosen fixture.
All four secret trits participate in the encrypted circuit, but this native
case does not establish correctness across all four-trit assignments; those
assignments are covered by the separate clear oracle.

The existing affine refresh helper now accepts a target coefficient index;
its old coefficient-1 wrapper remains for the earlier regression. Adding
the encrypted four-term carry corrects the wrong affine plaintext. The
fresh error bound uses 89 bits and excludes the old H-1 residual.
A subsequent exact encrypted square has a 131-bit bound and fits within the
same half-scale.
Every coefficient of the uncorrected, corrected and squared outputs is
checked against the independent secret-holder oracle.

The evaluator receives no secret key, decrypted phase, selected clear carry,
or cached actual winding. This remains one sparse coefficient refresh.
It does not refresh an arbitrary dense ciphertext or feed the squared output
through another full refresh.

## Costs and remaining obstruction

The packed pair precharge occupies 5,898,240 coefficient-storage bytes
(5.625 MiB), versus 1,966,080 bytes for the three single-trit ciphertexts.
Shared trace/relinearization keys remain 183,500,800 bytes (175 MiB).
The separate encrypted source polynomial for the affine phase adds 655,360
bytes. These figures exclude allocator overhead, extracted scalar states
and scratch memory. Extracting every pair would require `9*(N/2)*log2(N)`
Galois applications, versus `3*N*log2(N)` for the single-trit reference.
Preparation saves a multiplication level by spending storage and trace work.

The six-term result depends on the tested public coefficient pattern.
For example, coefficients `[1,3,9,27]` already give 81 distinct four-term
possible sums, exceeding the configured 27-state limit. Pair preparation
does not remove the exponential support problem for arbitrary coefficients.

The full 8192-term balanced pair tree still needs 12 multiplication levels,
compared with 13 for single trits. Even ignoring all merging and projection
amplification, the selected bound admits only two levels after extraction;
the third reaches 168 error bits against a 137-bit half-scale. These are
limits of this reference representation and certificate, not an impossibility
theorem for another carry circuit. Reconfiguring trays does not reset noise.

## Reproduction

```sh
python3 scripts/safe_basis_pair_probe.py
cargo test --locked --offline --config 'profile.test.package.nine65.opt-level=2' -j1 -p nine65 --lib precharged_pairs_ -- --include-ignored --nocapture
```

The clear probe checks 34,425 arbitrary small pair assignments and 14,742
native four/six/eight-term assignments. The native run checks all 8192
coefficients of the nine packed indicators, projected block selectors,
carry/root/phase/tray outputs, and refreshed/squared outputs: 1,105,920
coefficient/error checks across one chosen source and both signs. These
are not 1,105,920 independent encrypted source cases.

Evidence is `safe-basis-pairs.json` and `safe-basis-pairs-tests.txt` under
`artifacts/execution/2026-10-19-carry`. Earlier source-bound evidence remains
historical. Production refresh, S00/S01/S03 acceptance, cryptographic source
provenance and the full-sum circuit remain open. No CI or lint policy changes
are part of this experiment.

The next experiment, [terminal readout](SAFE_BASIS_TERMINAL_READOUT.md), computes
carry and frame views for 81 distinct sums without retaining a combined
81-selector state. It also tests non-canceling source pairs and carry +/-2.
