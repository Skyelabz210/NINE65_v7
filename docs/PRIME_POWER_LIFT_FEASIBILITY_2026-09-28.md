# Canonical lift: complete-circuit feasibility

Snapshot: 2026-09-28, based on `048f79ac771697801e26ebf77e4ee6df33b48281`.
The artifacts also hash the working-tree probe and relevant source files.

## Result

The existing balanced-product canonical section cannot pass its present
noise certificate on any tested four-through-eight-prime chain at `N=8192`
or `N=16384`. A lower bound obtained by dropping positive terms from the
complete certificate is **1,056–1,095 bits**. The largest tested chain has
only **202 bits** of high-encoding half-scale. This remains a statement
about this circuit and certificate, not an impossibility theorem for public
refresh or a necessary lower bound on actual ciphertext error.

The next construction needs a different encrypted digit-removal circuit or
a sharper sound multiplication certificate with enforceable operand
invariants. Extending the existing prime catalog to eight lanes does not
admit this polynomial baseline. Public refresh remains disabled.

## Reproducible evidence

The [Rust probe](../crates/nine65/examples/canonical_lift_feasibility.rs)
calls the real phase, exact-multiply and canonical-lift constructors using
public metadata. It creates no keys or ciphertexts. The
[Python oracle](../scripts/canonical_lift_feasibility.py) independently
calculates the phase bound, projected error and multiplication recurrence
using arbitrary-precision integers. At every reached product node, it also
checks that the production dyadic quadratic ceiling covers the exact
`ceil(N*P*E_A*E_B/Q)` value.

The sweep includes all four public configuration names and every prefix
of `BOOTSTRAP_PRIMES` with four through eight lanes at both ring dimensions.
The hypothetical prefixes use `eta=3` and a 128-bit screen target; the named
configurations retain their actual error widths and security targets.
`secure_128` and `secure_128_deep` are aliases, and their tuple is also the
four-lane `N=8192` candidate. The 14 records contain 12 distinct tuples.

Eight canonical-lift noise refusals agree with the independent calculation.
Six other records stop at a security or exact-arithmetic gate. The oracle
still reports their hypothetical noise schedule separately; those schedules
are not executable admitted plans. The 14 records check 23 quadratic terms.

- [Production probe JSON](../artifacts/bootstrap/canonical_lift_probe_2026-09-28.json)
- [Checked feasibility JSON](../artifacts/bootstrap/canonical_lift_feasibility_2026-09-28.json)

Regenerate from the repository root:

```sh
cargo run --offline -q -p nine65 --features serde \
  --example canonical_lift_feasibility \
  > artifacts/bootstrap/canonical_lift_probe_2026-09-28.json
python3 scripts/canonical_lift_feasibility.py \
  artifacts/bootstrap/canonical_lift_probe_2026-09-28.json \
  --output artifacts/bootstrap/canonical_lift_feasibility_2026-09-28.json
```

Successful oracle execution means the recorded mathematical checks agree;
it does not mean any candidate is admitted for refresh. Each report retains
the production constructor outcome and `complete_refresh_admitted=false`.

## Noise results

Here `P=65537^2`. The first failure column describes the noise recurrence
alone, before considering independent arithmetic and security refusals.
Depth is the depth of the first rejected balanced-product node, not the
complete circuit's 17 levels.

| Tuple | Q bits | Half-scale bits | First noise failure: depth / error bits | Complete certificate lower bound, bits |
| --- | ---: | ---: | ---: | ---: |
| `secure_128`, `secure_128_deep` | 119 | 86 | 1 / 131 | 1,056 |
| `secure_192` | 146 | 113 | 1 / 137 | 1,095 |
| `secure_256` | 175 | 142 | 2 / 197 | 1,095 |
| N=8192, catalog prefix 4 | 119 | 86 | 1 / 131 | 1,056 |
| N=8192, catalog prefix 5 | 146 | 113 | 1 / 131 | 1,056 |
| N=8192, catalog prefix 6 | 177 | 144 | 2 / 189 | 1,056 |
| N=8192, catalog prefix 7 | 206 | 173 | 2 / 189 | 1,056 |
| N=8192, catalog prefix 8 | 235 | 202 | 3 / 247 | 1,056 |
| N=16384, catalog prefix 4 | 119 | 86 | 1 / 136 | 1,094 |
| N=16384, catalog prefix 5 | 146 | 113 | 1 / 136 | 1,094 |
| N=16384, catalog prefix 6 | 177 | 144 | 2 / 196 | 1,094 |
| N=16384, catalog prefix 7 | 206 | 173 | 2 / 196 | 1,094 |
| N=16384, catalog prefix 8 | 235 | 202 | 3 / 256 | 1,094 |

The final complete-circuit lower bound is computed without constructing the
very large quadratic bounds after the first refusal. With projection bound
`E_proj` and linear multiplier

```text
A = (P-1)/2 + P*N*(N/2+1),
```

each balanced product node contributes at least `A*(E_left+E_right)` to
the same mathematical certificate recurrence. A balanced tree with `p`
leaves has `2^(k+1)-p` leaves at depth `k=floor(log2 p)` and
`2*p-2^(k+1)` leaves at depth `k+1`. Taking every leaf bound as `E_proj`
and dropping constant-encoding errors gives

```text
L_product = E_proj*A^k * (2^(k+1)-p + A*(2*p-2^(k+1)))
L_output  = N*(E_proj + L_product).
```

For `p=65537`, this is `E_proj*A^16*(65535+2*A)` before the final addition
and coefficient reassembly. The omitted quadratic, rounding, key-switch
and constant-encoding terms are nonnegative. Arbitrary-precision storage
alone cannot make the present recurrence pass the tested decoding thresholds.

The existing evaluator would perform 536,870,912 ciphertext multiplications
at `N=8192`, or 1,073,741,824 at `N=16384`. The reports record theoretical
Galois counts and key payloads even for refused plans. These are operation
counts and allocation estimates, not measured runtimes or generated keys.

## Independent production gates

At `N=8192`, six through eight catalog primes require 222, 251 and 280 bits
of exact-multiply auxiliary capacity; the available pool has 220 bits.
Their expanded phases also fail the 128-bit in-tree security screen, with
binding results 118, 102 and 89 bits respectively.

At `N=16384`, seven and eight primes reach the scaler's nine-lane fallback
accumulator requirement of 287 bits, above its 256-bit capacity. These
failures occur before canonical-lift noise admission. The six-lane catalog
prefix has an arithmetic plan, but fails its second product level.

The named `secure_256` expanded phase is refused at its declared 256-bit
target because its binding screen is 240 bits. The probe does not lower that
target to reach the lift. These deterministic in-tree screens are not
external lattice-security attestations.

## Next construction gate

A replacement must specify its encrypted nonlinear operation, key
relationship, coefficient transforms, complete error bound and public
resource cost before key generation. Its certificate must cover winding/error
terms or derive an enforceable reason to remove them. Ordinary low-encoding
ciphertexts and public clear-residue division do not supply the canonical
high-encoding digit required by the current contraction kernel.

Actual input operation-history admission and the final output key
relationship remain separate requirements. A complete refresh still needs
encrypted fresh, added, multiplied, relinearized and boundary-noise cases
at every supported level, followed by a public multiplication, under the
[bootstrap correctness contract](BOOTSTRAP_CORRECTNESS_CONTRACT.md).

## Validation

- `cargo test --offline -p nine65 --features allow_insecure --lib public_prime_power_lift`: 4 passed.
- `cargo test --offline -p nine65 --features allow_insecure --test prime_power_phase`: 3 passed, including all 38 encrypted phase cases.
- The probe and Python oracle passed for all 14 records; all 9 recorded source hashes match the working tree.
- The oracle rejects corrupted phase bounds and false production admission; the closed-form bound agrees with 1,028 independently recursive cases.
- `cargo fmt --all -- --check` and whitespace checks passed. Example clippy completed with existing dependency/library warnings.
