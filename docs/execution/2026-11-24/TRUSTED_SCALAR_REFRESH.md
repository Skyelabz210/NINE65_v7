# Trusted-key scalar refresh

Source commit `102601ba720f9f39c70ecb06c4a99de5d3252418` builds on
`64c1c89b191093dc12cf81b87da5fb1a02c46dc1`. This implements the scalar
and secure-randomness steps of the [November 17 review](https://github.com/Skyelabz210/NINE65_v7/blob/f867ad421ede5665070ce91f2a19ae96e593825d/docs/execution/2026-11-17/REFRESH_MODE_REVIEW.md).

`SymmetricBootstrap::bootstrap_secure` refreshes coefficient zero by decoding
with the local secret key and encrypting under the supplied public key.
`reencrypt_symmetric_secure` uses the secret key for both steps. Both draw
fresh randomness from the OS. The caller must supply the right keys and a
recoverable scalar ciphertext. For a packed input this operation discards the
other plaintext coefficients.

The decoder computes the constant term of the negacyclic product in each
active main lane and reuses the existing centered decode. A negative diagnostic
margin causes refusal. A positive margin can also occur after an input has
crossed into the wrong decoding cell. The original message's recoverability
therefore remains a caller precondition. Raw ciphertext and key types carry
shape and residues and rely on the caller to establish key-family provenance.

The secret-key encryptor previously encoded the message in an anchor lane
using `floor(anchor_prime/t)`. It now computes `Delta = floor(Q_main/t)`
once and uses its residue in every lane. The phase regression independently
computes the decryption product at every coefficient and checks that each lane
contains the same bounded error around that encoding. It then multiplies and
decrypts the returned ciphertext. The [security mode matrix](../../SECURITY_MODE_MATRIX.md)
documents the owning API and key boundary.

## Previously missing evidence

The CRAM collection arrived on main in [137d970](https://github.com/Skyelabz210/NINE65_v7/commit/137d970).
It contains [ANALYSIS.md](../../proofs/cram/collection/ANALYSIS.md),
[CROSS_INNOVATION_MAP.md](../../proofs/cram/collection/CROSS_INNOVATION_MAP.md),
[UNIVERSAL_THEOREM.md](../../proofs/cram/collection/UNIVERSAL_THEOREM.md) and
[verify_claims.py](../../proofs/cram/collection/experiments/verify_claims.py).
Running the verifier passed 1,183,744 quotient-congruence cases, 217,748
bounded recoveries and the historical bootstrap negative controls. For fixed
reference `r` with `X=r+MK`, the theorem identifies when observing `K mod R`
determines `X mod b`. Applying the result to an encrypted operation also
requires a producer for that observation. The original report's
`sym_refresh_lab.py` remains unavailable in the inspected checkout.

## Verification

Pinned Rust 1.89.0 on Linux x86_64. The following tests ran locally.

| Scope | Result |
| --- | --- |
| New scalar decoder | Six tests compare the full-phase decode with the scalar result or expected refusal. Reduced N=64 tests cover every supported level of the 128/192/256 named prime chains. An exhaustive independent oracle covers all 697 phases of a small odd modulus. |
| Trusted refresh | Six new tests cover both OS-random routes, repeated freshness per route, reduced input levels, all-lane phase consistency, subsequent multiplication, malformed inputs, and timed compatibility. The module's two active sampler regressions also pass. Twenty historical tests remain ignored. |
| Adjacent dual decoders | Four pre-existing tests pass for wide and narrow negative-branch margins and U256 behavior. |
| Public leveled | Public-only roundtrips, and exact division with its typed refusal, pass through the public API. |
| Depth | The existing `secure_128` symmetric mul-by-1 sequence succeeds through depth 3 and first decodes incorrectly at 4. |
| Public research and legacy | Eleven scheduler regressions and both legacy Phase-1 refusal regressions pass. Two reduced-ring seeds execute 24 encrypted squares, six refreshes and 192 coefficient comparisons together. |
| Release entropy | Eight native entropy integration tests pass, including a release-linked library's refusal of all three deterministic refresh wrappers before sampling or counting. |

Representative commands, from the repository root:

```sh
cargo test --locked --config profile.test.package.nine65.opt-level=2 -p nine65 --features allow_insecure --lib scalar_ -- --test-threads=1
cargo test --locked --config profile.test.package.nine65.opt-level=2 -p nine65 --features allow_insecure --lib ops::symmetric_bootstrap::tests:: -- --test-threads=1
cargo test --locked --config profile.test.package.nine65.opt-level=2 -p nine65 --features allow_insecure --test time_crystal_verification symmetric_depth_is_finite_and_noise_limited -- --exact
cargo test --locked --config profile.test.package.nine65.opt-level=2 -p nine65 --features allow_insecure --test cram_public_mode public_only_roundtrip_battery -- --exact
cargo test --locked --config profile.test.package.nine65.opt-level=2 -p nine65 --features allow_insecure --test cram_public_mode exact_divide_roundtrip_and_refusal -- --exact
python3 scripts/run_public_refresh_research_gates.py --suite production-boundary
python3 scripts/run_public_refresh_research_gates.py --suite scheduler
cargo test --locked --release -p nine65 --test native_key_entropy
cargo clippy --locked -p nine65 --lib --features allow_insecure -- -D warnings
cargo run --release --locked -p nine65 --example trusted_scalar_refresh_timings
```

The committed-source `scalar_` filter ran 29 passing tests including all
12 new decoder and refresh tests. One historical mask test was ignored.
Strict library Clippy, workspace formatting, and the refresh status self-test
passed. The follow-up to the implementation commit edits the reasons attached
to the 20 historical ignores and records these results.

## Matched-input timings

The [release example](../../../crates/nine65/examples/trusted_scalar_refresh_timings.rs)
uses the default feature set and OS randomness. It generates one key on
`secure_128`, N=8192, t=65537, eta=3, main primes
[998244353, 985661441, 754974721, 469762049]. Each round uses a fresh scalar
ciphertext shared across the two implementations. It alternates measurement
order, checks each decoded scalar, and decrypts both refreshed outputs
outside the timed interval. The reference composes the existing full-product
decoder with secure public-key encryption. Key generation and input generation
are outside the timing. After one warmup, 21 rounds ran in one process on an
AMD EPYC 9V74 cloud host.

| Operation | Full-product median | Checked scalar median |
| --- | ---: | ---: |
| Decode coefficient zero | 2.062 ms | 0.199 ms |
| Decode and re-encrypt with the public key | 31.506 ms | 29.917 ms |

The median end-to-end time decreased by 5.0% on this run. The
[paired samples in nanoseconds](../../../artifacts/execution/2026-11-24/trusted-scalar-refresh/secure_128.csv)
preserve the inputs' public message values and the variability across rounds.
The original report used a different compiler and randomness path. Its
10 ms refresh figure belongs to that setup.
