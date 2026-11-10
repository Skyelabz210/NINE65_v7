# Exact parameter and distribution evidence — 2026-11-10

Source: `7ada6503634a824e80bc4bcfd6231ad0178d7ed3`. This packet covers the
shipped named **RNS/DualRNS** paths, their derived legacy Clockwork bootstrap
tuples, and the explicit native `PublicRefreshCircuit` setup. It does not assign
these sampler laws to every other scalar, binding, service, or experimental API
merely because that API accepts a similarly named configuration.

The new [machine-readable export](../../../artifacts/execution/2026-11-10/parameter-distribution/parameter-distributions.json)
adds the exact secret, error and mask distributions missing from the existing
parameter registry. It supplies review inputs; it changes no cryptographic
producer or admission policy. The related
[key-graph packet](PUBLIC_KEY_GRAPH_EVIDENCE.md) records the correlated publication
setup, and the external-estimator track owns attack-model calculations.

## Tuples pinned by executable source

Let `W = [998244353, 985661441, 754974721, 469762049]`. Ordered primes are
significant. The complete decimal products and ordered prime arrays appear in
the export; bit lengths below are `bit_length(product(primes))`, not sums of
per-prime bit lengths.

| Named RNS configuration | N | Ordered ciphertext primes | Exact Q bits | t | η |
| --- | ---: | --- | ---: | ---: | ---: |
| `secure_128` | 8192 | W | 119 | 65537 | 3 |
| `secure_128_deep` | 8192 | W | 119 | 65537 | 3 |
| `secure_192` | 16384 | W, 167772161 | 146 | 65537 | 4 |
| `secure_256` | 16384 | W, 167772161, 595591169 | 175 | 65537 | 5 |

The two 128 labels have identical numerical tuples. These are API labels and
source metadata. In particular, the documented in-tree MATZOV screen for the
`secure_256` work tuple remains 240 bits; this packet provides no independent
security admission.

`ClockworkBootstrap::new` chooses the first
`max(4, work.primes.len()+1)` primes from `BOOTSTRAP_PRIMES`. This yields
different tuples from the native outer ring:

| Legacy bootstrap owner | N | Ordered ciphertext primes | Exact Q bits | t | η |
| --- | ---: | --- | ---: | ---: | ---: |
| `secure_128`, `secure_128_deep` | 8192 | W, 167772161 | 146 | 65537 | 3 |
| `secure_192` | 16384 | W, 167772161, 1811939329 | 177 | 65537 | 4 |
| `secure_256` | 16384 | W, 167772161, 1811939329, 595591169 | 206 | 65537 | 5 |

Legacy circular setup re-encodes the original work secret over the bootstrap
primes. Independent-key setup instead draws a fresh bootstrap secret with a
different modulo-three mapping, described below. These key-generation paths
do not enable the legacy refresh gate. The exporter checks that
`public_phase1_soundness_gate` still returns `BootstrapFailed`.

| Native research domain | N | Exact Q bits | Plaintext modulus / moduli | Secret law |
| --- | ---: | ---: | --- | --- |
| Work | 8192 | 119 | 65537 | word-modulo-three dense ternary |
| Source | 8192 | 60 | 65537 | exactly 48 positive and 48 negative coefficients |
| Outer | 32768 | 650 | 65537 and 4295098369 | exact uniform ternary under SecureRng |
| Return destination | 32768 | 119 | 65537 | original Work secret embedded with stride 4 |

The source uses the first two W primes and gadget base bits 3. The outer
tuple uses W followed by nine explicitly listed 59-bit primes. The return
destination has effective secret degree 8192 and at least 24576 structural zero
coefficients; it is correlated with Work and is not an independent degree-32768
ternary draw. This row is a destination representation, not a fourth
independently generated secret domain. The corresponding source embedding
has stride 1 for this native tuple.

## Exact sampling laws

All distribution statements condition on the OS CSPRNG providing independent
uniform words. A generic `FheRng` trait implementation alone does not establish
that assumption. This packet does not certify entropy quality or the separate
RNG-admission boundary.

For named RNS/DualRNS secrets, native Work, and public-encryption `u`, source
uses `r = rng.next_u64() % 3`, mapped as `0→0`, `1→+1`, `2→−1`. With
`M = 2^64 = 18446744073709551616` and `k = 6148914691236517205`,

```
P(0)  = (k+1)/M = 6148914691236517206 / 18446744073709551616
P(+1) = P(-1)   = 6148914691236517205 / 18446744073709551616
```

The coefficient total-variation distance from exact uniform ternary is
`2/(3·2^64) = 1/27670116110564327424`. A product coupling gives the upper
bound `min(1, n·2/(3·2^64))` for n coefficients. This additive bound alone
does not establish transfer of a 128-bit security claim. The observation is
an exact modeling caveat, not a demonstrated key-recovery attack.

Legacy `generate_independent_boot_sk` maps `0→−1`, `1→0`, `2→+1`. Therefore
its extra unit of probability mass belongs to −1, rather than zero; its
distance from exact uniform ternary is the same. Circular legacy keys inherit
the original work coefficient law instead.

The native Outer secret calls `rng.ternary_vector`; SecureRng rejects the
fourth outcome of a two-bit draw, yielding exactly `1/3` per trit. Source
sampling selects distinct positions uniformly by power-of-two masking and
rejecting repeats, assigning the first 48 accepted positions +1 and the next
48 −1. Its support size is exactly `C(8192,96)·C(96,48)`. Its coefficients
are jointly constrained; a per-coefficient sparse marginal must not replace
this balanced fixed-weight law.

Errors use centered binomial `CBD(η)`, the difference of two sums of η fair
bits. Each coefficient has support `[−η,η]`, zero mean, variance `η/2`, and
`P(e=j)=C(2η,η+j)/2^(2η)`.

| η | PMF numerators in increasing support order | Denominator | Variance |
| ---: | --- | ---: | ---: |
| 3 | 1, 6, 15, 20, 15, 6, 1 | 64 | 3/2 |
| 4 | 1, 8, 28, 56, 70, 56, 28, 8, 1 | 256 | 2 |
| 5 | 1, 10, 45, 120, 210, 252, 210, 120, 45, 10, 1 | 1024 | 5/2 |

The actual standard deviations are `sqrt(η/2)`; substituting a Gaussian with
σ=3.2 would change the model. The separate `params::production` metadata is
outside these constructors and does not override these executed samplers.
RNS key and hybrid-key producers take two one-bit word draws per CBD summand;
the direct phase-bank producer uses SecureRng CBD, taking two bits from each
word. Both have the law above under the stated RNG assumption.

One signed error polynomial is encoded consistently in every RNS lane. Error
residues are correlated representations of that coefficient, not independent
draws per prime. Public-encryption phase error includes products involving the
public-key error, `u`, `e1`, `e2`, and the secret; it is not itself simply a
fresh CBD polynomial. Related-key message targets likewise remain part of the
full security problem.

Single-RNS public/evaluation keys, hybrid target/Galois keys, and the phase
bank use independent unbiased residues in each main-prime lane. Pairwise
coprimality gives uniformity over the product ring. Dual-RNS and legacy
Clockwork public/switch keys instead rejection-sample a canonical integer
uniformly in `[0,Q)` and reduce it into both main and anchor bases, preserving
their correlation. The dual sampler refuses chains whose summed lane widths
exceed 256 bits; native Q650 uses the single-RNS sampler. An old nearby
dual-key comment describing a single 64-bit shared mask is superseded by the
actual call to the full-width sampler.

## Reproduction and controls

Run from the repository root:

```bash
python3 scripts/export_parameter_distribution_evidence.py --check
python3 scripts/test_parameter_distribution_evidence.py
python3 scripts/test_parameter_evidence.py
```

The check compares the complete deterministic export against the current
source-derived result. It verifies every recorded Rust source hash and the
preserved registry hash against Git blobs at the recorded source SHA, then
against the current files. An evidence-only commit can advance HEAD without
invalidating the check; a bound runtime change requires a reviewed export at
its new source commit. Explicit generation for this snapshot is:

```bash
python3 scripts/export_parameter_distribution_evidence.py \
  --source-ref 7ada6503634a824e80bc4bcfd6231ad0178d7ed3
```

The source adapter intentionally recognizes the reviewed constructor and
producer shapes. It is not a Rust parser or a proof of semantic equivalence.
Its hash binding and rejection controls supplement source review. Ten new
tests include exhaustive CBD bit-input checks for η=3,4,5; bounded exact
modulo/rejection/support enumeration; rejection of changed sampler, mask,
embedding and legacy-chain producers; rejection of a corrupted saved law;
and rejection of forged source hashes. The ten pre-existing parameter/depth
evidence controls also pass.

Two existing Rust mask regressions were executed with `--features
allow_insecure`, `--config profile.dev.package.nine65.opt-level=2`, and the
same isolated target directory. Each command selected and passed exactly one
test, with no ignored tests:

```bash
cargo test --locked --offline --config profile.dev.package.nine65.opt-level=2 \
  -p nine65 --features allow_insecure --lib \
  single_rns_uniform_sampler_covers_the_whole_main_modulus -- --nocapture
cargo test --locked --offline --config profile.dev.package.nine65.opt-level=2 \
  -p nine65 --features allow_insecure --lib \
  sampled_mask_anchor_lanes_agree_with_the_main_lanes -- --nocapture
```

Their test runtimes were 0.48 seconds and 1.21 seconds. These deterministic
sampler regressions check full main-modulus coverage and agreement of main
and anchor representations; they are not statistical entropy certification.

The existing Rust named-profile exporter was run with pinned cargo/rustc
1.89.0 and cached dependencies, in an isolated working directory so its fixed
output path could not overwrite historical evidence:

```bash
cd /tmp/nine65-parameter-export
PATH=/workspace/.tooling/rustup/toolchains/1.89.0-x86_64-unknown-linux-gnu/bin:/workspace/.tooling/cargo/bin:$PATH \
CARGO_HOME=/workspace/.tooling/cargo RUSTUP_HOME=/workspace/.tooling/rustup \
CARGO_TARGET_DIR=/tmp/nine65-parameter-target \
cargo run --locked --offline --manifest-path /workspace/NINE65_v7/Cargo.toml \
  -p nine65 --example export_parameter_registry
```

It exited 0, reported 47.63 seconds for the dev build, and printed:

```
wrote artifacts/execution/parameter_registry.json
secure_128: n=8192, lanes=4, exact_Q_bits=119, fingerprint=0xf5d08287c13d81b6
secure_128_deep: n=8192, lanes=4, exact_Q_bits=119, fingerprint=0xf5d08287c13d81b6
secure_192: n=16384, lanes=5, exact_Q_bits=146, fingerprint=0x62972596f3cc51ab
secure_256: n=16384, lanes=6, exact_Q_bits=175, fingerprint=0x5cc15c3e3aae2fd5
```

The fresh registry is byte-identical to the preserved registry:
SHA-256 `5ddb248612358a7f02cfc98118e0b7242e33c60f1766d3148efde96aadfe6138`.
The new distribution export is
SHA-256 `543ecda68277c7d1323b9b4009b2586bc2f81ead970d4d6a7d0c64db1d26fcd4`.
Raw command arguments, exit codes and output logs are retained in the
[run manifest](../../../artifacts/execution/2026-11-10/parameter-distribution/manifest.json).

No encrypted refresh run was performed by this track. No related-key
confidentiality proof, probabilistic failure bound, constant-time result,
external attestation, or production admission follows. No historical raw
artifact was edited. There are no access or installation blockers for these
bounded checks; independent exact-model security assessment remains separate.
