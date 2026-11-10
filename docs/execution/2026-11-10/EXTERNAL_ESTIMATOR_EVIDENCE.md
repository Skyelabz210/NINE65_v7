# Focused external estimator evidence, 2026-11-10

This packet runs selected standalone LWE attack-cost models using third-party
source. It supplies neither an independent reviewer nor an attestation.
Confidentiality of the complete correlated key setup remains unestablished;
external parameter attestation is not obtained. Production admission is closed.
See the [current claim surface](../../PUBLIC_REFRESH_STATUS.md) and
[attestation requirement](../../security/EXTERNAL_PARAMETER_ATTESTATION.md).

The executed NINE65 input source is
`7ada6503634a824e80bc4bcfd6231ad0178d7ed3`. The current key-free Rust review
export and exact sampler/legacy-tuple packet are frozen into the
[combined input](../../../artifacts/execution/2026-11-10/external-estimator/exact-input-packet.json).
Its SHA-256 is
`47e164a1d343f0e8d5a46db6541996ed4e4c628ae161472c121e8dd76afad62c`.
The separate review export hash is
`f1d2ce036ab6e3bf1e2339f4fc09b5425911128367a65a677b6e0fe4ad2f1d18`;
the sampler/legacy packet hash is
`543ecda68277c7d1323b9b4009b2586bc2f81ead970d4d6a7d0c64db1d26fcd4`.
The driver rejects a changed combined input, a changed legacy-packet binding,
or a changed upstream Python source set/digest.

## Tool and runtime

The upstream tool is
[`malb/lattice-estimator`](https://github.com/malb/lattice-estimator/tree/f31b86fe490ab11abb4a69efa13007583791e10a),
revision `f31b86fe490ab11abb4a69efa13007583791e10a`. This retains the existing
`cram_sparse_source_screen.py` upstream pin rather than silently tracking main.
The checkout was clean before import. Every Python file in `estimator/` is
SHA-256 locked in the
[date-specific lock](../../../scripts/security/lattice_estimator_lock_20261110.json).

The Sage runtime is
`sagemath/sagemath@sha256:19995db6194f4a4bab18ce9a88556fd15b9ed5e916b4504fefe618a7796ddbdb`,
with Sage 10.6, Python 3.12.5 and SciPy 1.15.2. The upstream package requires
Python >=3.9 and Sage; `reduction.py` imports SciPy. Its empty Python package
dependency list does not make ordinary Python alone sufficient.

The image was downloaded successfully from the registry using free local
resources. The final container has no network, dropped capabilities, no new
privileges, a read-only root, read-only tool/driver/input mounts, a 4 GiB memory
limit, four CPUs, 256 PIDs, and a 1 GiB temporary filesystem. `DOT_SAGE` and
`XDG_CACHE_HOME` use `/tmp`; the final run preserves the image's `HOME`.
The controller uses four workers and a 45-second deadline per attack, with
independent error/timeout retention. No GPU attack, paid compute, purchase,
remote workflow, external message, merge or push was performed.

The image's shell entrypoint initially flattened a Python `-c` argument and
failed. An explicit Sage entrypoint corrected that. Docker layer creation also
exceeded an initial 60-second client deadline: inspection established a
Created/unstarted container before it was started successfully. A later
pre-start client cancellation removed the initial `HOME` override. These are
preserved in [attempts.json](../../../artifacts/execution/2026-11-10/external-estimator/attempts.json);
none was an approval denial or attack result.

## Exact modeled inputs and scope

There are eight distinct modeled tuples and eleven retained profile/domain
aliases. `secure_128`, `secure_128_deep` and native Work share a tuple;
the two legacy bootstrap 128 labels also share a tuple. The legacy bootstrap
chains are the actual `ClockworkBootstrap::new` prefixes, separately from the
native 13-prime Outer ring. Their gates remain disabled.

| Modeled instance | N | Product-Q bit length | CBD eta | Secret model |
| --- | ---: | ---: | ---: | --- |
| secure_128 / secure_128_deep / native Work | 8192 | 119 | 3 | ideal uniform ternary |
| secure_192 | 16384 | 146 | 4 | ideal uniform ternary |
| secure_256 | 16384 | 175 | 5 | ideal uniform ternary |
| native Source | 8192 | 60 | 3 | exactly 48 positive and 48 negative hidden positions |
| native Outer | 32768 | 650 | 3 | exact uniform ternary |
| legacy bootstrap secure_128 / deep | 8192 | 146 | 3 | ideal uniform ternary |
| legacy bootstrap secure_192 | 16384 | 177 | 4 | ideal uniform ternary |
| legacy bootstrap secure_256 | 16384 | 206 | 5 | ideal uniform ternary |

The dense ideal model is `ND.Uniform(-1,1)`, not Gaussian sigma 3.2.
The named/Work sampler uses word modulo three; relative to ideal ternary its
per-coefficient total variation is `2/(3*2^64)`, with the recorded union upper
bound `2*N/(3*2^64)` for an iid N-vector. The independent legacy boot-key
sampler favors -1 instead of 0 and has the same distance; circular mode
reencodes the original Work coefficients. These small distances are explicit
modeling caveats, not a sampler proof or joint-security conclusion. Outer uses
rejection sampling. Source uses `ND.SparseTernary(48,48,8192)`.
Every error input is `ND.CenteredBinomial(eta)`, variance `eta/2`.

All factorized Q inputs and plaintext moduli are retained as decimal strings.
The upstream LWE API receives scalar Q as the exact product; these runs do not
assess modulus-factorization attacks or the negacyclic ring's extra structure.
`m=infinity` is a modeling relaxation, not a count of independent samples in
the publication graph. Only primal uSVP and the plain dual attack are selected,
each under explicit MATZOV classical and ADPS16 quantum-lattice reduction
cost. Primal uses GSA; dual uses its analytic model. `estimate.rough()` is not
used because it changes the reduction-cost model. These four combinations per
tuple are not exhaustive classical or quantum coverage.

Return material is excluded as a separate iid-key estimate. Its actual samples
use the four-prime Work Q and the embedded Work secret: ambient degree 32768,
effective degree 8192. Treating it as a fresh 13-prime Outer secret would be
incorrect. The seven publication relations, circular/KDM assumptions and
correlated return channels require separate analysis. Successful marginal
estimates cannot establish their confidentiality.

## Results and reproduction

All **32 of 32** selected attack/model tasks returned finite results, with
zero errors and zero timeouts. The controller exited zero; elapsed wall time
including Docker creation was **117.81695 seconds**.

| Modeled instance | MATZOV uSVP | MATZOV dual | ADPS16 quantum-lattice uSVP | ADPS16 quantum-lattice dual |
| --- | ---: | ---: | ---: | ---: |
| secure_128 / deep / native Work | 244.916438 | 247.079704 | 199.280000 | 200.340000 |
| secure_192 | 433.294110 | 436.310002 | 376.300000 | 377.625000 |
| secure_256 | 351.263112 | 353.417199 | 298.920000 | 299.715000 |
| native Source | 497.372109 | 503.806456 | 437.780000 | 440.960000 |
| native Outer | 174.689822 | 175.737879 | 130.645000 | 130.645000 |
| legacy bootstrap secure_128 / deep | 194.098417 | 195.789634 | 151.050000 | 151.580000 |
| legacy bootstrap secure_192 | 347.072776 | 349.528828 | 294.945000 | 295.740000 |
| legacy bootstrap secure_256 | 291.274246 | 293.075968 | 242.210000 | 242.740000 |

Cells are modeled `log2(rop)`, rounded here to six decimals; the raw result and
[selected-cost summary](../../../artifacts/execution/2026-11-10/external-estimator/selected-results-summary.json)
retain the returned values. In this selected quantum-lattice reduction model,
the legacy bootstrap secure_256 tuple's uSVP cost is 242.21, below its owner's
nominal 256 label. This concerns that derived legacy tuple and model; it does
not replace the different named Work tuple's documented 240-bit in-tree
MATZOV screen or turn either tuple into an admitted profile. The native Outer
cost of 130.645 under the two selected quantum-lattice calls likewise supplies
no joint-key or exhaustive 128-bit security conclusion.

The [raw result](../../../artifacts/execution/2026-11-10/external-estimator/focused-results.json)
preserves full cost fields, parameter representations, runtime versions,
per-worker commands/transcripts and every finite/error/timeout status. A
completed focused run means all 32 selected task identities returned finite
outputs; it never means a security lower bound, complete attack coverage,
independent attestation or production admission.

The exact outer command is in
[run-command.json](../../../artifacts/execution/2026-11-10/external-estimator/run-command.json),
with status/elapsed time in `run-status.json`. Its immutable driver, lock and
combined-input snapshot are preserved beside the raw output. Clone and check
out the tool at the locked revision, place the frozen driver/input files at the
mount paths in that command, use a new writable output directory, and run the
recorded argument array. Existing evidence is never overwritten by the driver.
No Cargo target or crypto implementation was modified for these estimates.

The [16 harness controls](../../../artifacts/execution/2026-11-10/external-estimator/harness-controls.json)
pass. They check source/input mutations, missing/duplicate/bogus/nonfinite or
negative result markers, worker failure/timeout transcript retention, alias
deduplication, and exact complete-task coverage. Synthetic control fixtures
are explicitly separate from real estimator outputs. Their exact invocation is
in `supporting-commands.json`; the runnable control script is
[check_external_estimator_20261110.py](../../../scripts/security/check_external_estimator_20261110.py).

The existing Hou–Jiang assessment remains pinned to
`identitymapping/enhanced_hybrid_attack@d60cac04dea5a397b8489cce7171f3fe38b277d8`,
with its separate source lock and four earlier model searches. It was not
rerun in this focused pass. Its corrected-theorem correspondence and complete
quantum-hybrid coverage remain unestablished. The earlier minimum reported
cost of 161.33894 bits is not replaced by a larger value from these two
selected generic-LWE attacks, and neither value certifies the full setup.
