# Encrypted unsigned division: public API and admission limits

## Implemented contract

`CramPublicEvaluator::divide_integer` now accepts an encrypted numerator and
an encrypted denominator and returns encrypted quotient, remainder and
divide-by-zero status. `CramMainEvaluator::divide_integer` exposes the same
implementation directly on the service's main-Q arithmetic backend.

For nonzero unsigned denominator `d`, the result satisfies
`n = q*d+r` and `0 <= r < d`. For `d=0`, the defined result is `q=0`, `r=n`,
status `1`; otherwise status is `0`. The evaluator never decrypts or branches
on that predicate. It receives public evaluation material, not the client key.

The operation uses sealed encrypted bit words. The input and output type is
`EncryptedUint`, not a raw `DualRNSCiphertext`. Each bit is a main-Q BFV
ciphertext with its own immutable key-domain identity and noise history.
Ingress accepts an unsigned `u64` and a public width between 1 and 64;
out-of-range values are refused. Quotient and remainder retain the numerator's
width; operand widths can differ. Signed division is outside this contract.

This representation matters: a scalar ciphertext of `n mod t` cannot recover
an arbitrary larger integer `n`. There is no cast that pretends otherwise.
The integer key pair is separate from the old DualRNS scalar key pair. Raw
wire import for integer words is not exposed without Boolean/provenance checks.

## Public usage

```rust
use nine65::ops::cram_public::CramPublicEvaluator;
use nine65::params::SecureConfig;

let mut config = SecureConfig::secure_128().into_config();
config.t = 3; // explicit Boolean-word tuple; N/Q/eta are retained
config.name = "native_integer_words_t3";
let mut evaluator = CramPublicEvaluator::new(&config);
let (public_keys, client) = evaluator.integer_keygen()?;
let numerator = public_keys.encrypt_uint(14, 4)?;
let denominator = public_keys.encrypt_uint(3, 4)?;
let plan = public_keys.plan_integer_division(&numerator, &denominator)?;
let encrypted = evaluator.divide_integer(&numerator, &denominator, &public_keys)?;
let result = client.decrypt_division(&encrypted)?; // client boundary only
assert_eq!((result.quotient, result.remainder, result.divide_by_zero), (4, 2, false));
```

The runnable example uses OS randomness and a real release library:

```bash
cargo run --locked -p nine65 --release --example encrypted_integer_division
```

`plan_integer_division` checks every arithmetic gate before ciphertext
evaluation starts and reports gate count, ciphertext-product count and the
smallest output budget. It reads only widths, public parameters and existing
producer-issued bounds. No bound is reset. Foreign key domains are refused,
including when the nominal parameters match. Failed operations leave inputs
and their histories unchanged.

## Construction and correctness argument

The circuit uses Boolean identities over BFV plaintext arithmetic:

```text
NOT(a) = 1-a
AND(a,b) = a*b
XOR(a,b) = a+b-2*a*b
SELECT(c,a,b) = b+c*(a-b)
```

For two mutually exclusive bits, OR is their sum. In the subtraction circuit,
the borrow generator `(1-a)*d` requires `a!=d`, whereas its propagation term
`(1-XOR(a,d))*borrow` requires `a=d`. Their sum is therefore Boolean. Sealed
ingress and these operations maintain the Boolean invariant modulo every
admitted plaintext modulus, including composite odd moduli.

The general compiler uses restoring binary division. After each processed
numerator prefix `P`, its invariant is `P=d*Q+R`, `0<=R<d` for `d>0`.
For the next bit `a`, form `T=2*R+a`, subtract `d` with an encrypted borrow,
and select `T-d` when no borrow occurred, otherwise `T`. The comparison bit
becomes the next quotient bit. One extra scratch bit prevents overflow.
The encrypted zero predicate is the balanced product of all inverted
denominator bits. Masking quotient bits with its complement produces the
specified zero-divisor result; the remainder already equals the numerator.

For words up to four bits, a finite public truth-table circuit lowers
multiplicative depth. It constructs one-hot selectors from encrypted input
bits and adds the disjoint selectors for each quotient/remainder output bit.
The compiler divides **public candidate indices**, never encrypted input data.
The table has at most 256 input pairs; larger widths use the polynomial-size
restoring circuit. No full integer is reconstructed during evaluation, no
divisor inverse is used, and no clear-input oracle is available to the server.

Each Boolean gate expands into the existing certified main-Q operations.
Ciphertext multiplication uses the prepared-key FPD BFV route. This is an
integer circuit built from FHE operations; it is not a newly invented
shared-factor modular inverse or a scalar FPD adapter for legacy components.

## Executed evidence

Implementation commits are `4f47cad` (compiler), `26f9de5` (encrypted backend),
and `7740e6169199214610e00e9fe30c8d0de28a3e41` (public facade and native
example). The [archived validation manifest](../artifacts/execution/2026-11-02/encrypted-integer-division/manifest.json)
records full source identities, hashes and commands.

At that source snapshot the full core library suite passed **1,209 tests,
139 ignored**; the release service suite passed **54 tests, 27 ignored**.
The encrypted-word construction compile-fail test, minimal-feature build,
Clippy with warnings denied, formatting, integer-only scans and existing
refresh/route architecture checks passed. The service run initially could
not bind loopback sockets inside the network sandbox; with network access
enabled all active service tests passed. Both logs are retained.

- The clear Boolean oracle checks both compilation strategies on every pair
  of 1–5-bit operand widths and values, plus 35 `u64` boundary pairs and 128
  deterministic full-width random pairs. The full-width checks are compiler
  tests, not a claim that 64-bit encrypted division fits current profiles.
- The encrypted three-bit test executes all 64 numerator/denominator pairs,
  including every zero-denominator numerator, with plaintext modulus 3.
- The public API executes `31/17`, `17/17`, `16/17` and `31/0` with **17 in
  the ciphertext modulus chain**, across three key-generation seeds. This
  reduced-ring test uses N=2, t=3 and eight primes; it is correctness evidence,
  not a secure parameter claim. All quotient, remainder and status plaintext
  coefficients are checked: 264 comparisons.
- The native public API test uses N=8192, the four `secure_128` ciphertext
  primes, eta=3 and explicit t=3. It executes `14/3` and `15/0` and checks
  every plaintext coefficient of all nine output bit ciphertexts: **147,456
  comparisons**. Divisor 3 shares the plaintext modulus.
- The release example independently executes `15/3 -> (5,0,0)`,
  `14/3 -> (4,2,0)`, `2/3 -> (0,2,0)` and `15/0 -> (0,15,1)`.
- Refusal tests cover malformed widths, input overflow, foreign key/context,
  and a circuit exceeding its noise budget. Composition tests preserve
  accumulated history and eventually refuse before exhaustion. Public
  schedules and bound metadata match for fresh zero/nonzero denominators.

The native four-bit circuit uses 287 ciphertext multiplications and 761 total
gates. Archived example evaluation was about 18–22 seconds per division on
the task host. These are diagnostic execution times, with overlapping build
activity during part of the run, not an isolated performance comparison.
The earlier 2.10–2.53× prepared-key multiplication result does not measure this
integer operation.

## Admission limits and unresolved scope

The API is available by default, but circuit admission remains finite.
For fresh operands of equal width, the current named tuples with their
original t=65537 admit:

| Tuple | Largest tested admitted width | First tested refusal |
| --- | ---: | ---: |
| `secure_128` / identical `secure_128_deep` | 1 bit | 2 bits |
| `secure_192` | 2 bits | 3 bits |
| `secure_256` | 4 bits | 5 bits |

These rows are preflight evidence, not encrypted runs of every named tuple.
The explicit native t=3 tuple above executes four-bit division with 10,000
displayed millibits left. The five-bit shared-lane test executes in a reduced
ring with a larger chain. Wider operands and prior operation history can
exhaust admission; the implementation does not promise unrestricted 64-bit
encrypted execution, unlimited depth, or transparent automatic refresh.

The legacy `exact_divide(ct, scalar)` retains its component-wise lane-unit
semantics and rejection. Silently changing it to a different quotient
definition would break callers. Its documentation/error now points integer
callers to `divide_integer`. There is still no adapter that recovers an
unstored lift from arbitrary old scalar ciphertexts.

Research refresh has separate archived native correctness evidence;
legacy Clockwork remains disabled. This change neither fixes that legacy
path nor admits the research related-key setup for production. Constant-time
execution, external attestation and a fully functional unbounded-depth system
are not claimed. This closes the absence of an encrypted integer-division API
for admitted words; it does not make every parameter/width combination work.
