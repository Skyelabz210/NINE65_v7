# Public canonical low-digit lift: polynomial baseline

Revision: 2026-09-27. A public ciphertext evaluator now produces the canonical
low digit in the high plaintext encoding when its complete noise plan passes.
Encrypted small-ring tests exercise the producer, contraction, and a subsequent
public multiplication. The current `N=8192`, `t=65537`, four-prime tuple fails
the polynomial multiplication bound and remains unadmitted for refresh.

The [complete-circuit feasibility sweep](PRIME_POWER_LIFT_FEASIBILITY_2026-09-28.md)
now checks all named configurations and four-through-eight-prime catalog
prefixes at both current ring dimensions. A linear-only lower bound on this
baseline's full certificate exceeds every tested decoding threshold; extending
the catalog prefix alone does not admit the circuit. The sweep also records
independent exact-arithmetic and security refusals.

## Exact section and its scope

For prime `p`, define

```text
F(X) = X + product_{a=0}^{p-1}(X-a) mod p^2.
```

Write `x=r+p*k` with `0 <= r < p`. The product vanishes at the integer `r`.
Its derivative at `r` is `product_{a!=r}(r-a) = -1 mod p`, by Wilson's
theorem. Thus `F(r)=r` and `F'(r)=0 mod p`. Taylor expansion modulo `p^2`
gives `F(r+p*k)=r`. The result is the **canonical** representative of the
low digit, rather than an arbitrary integer congruent to it modulo `p`.

Any integer polynomial with this full-domain section property has degree at
least `p`. If its degree were less than `p`, the property at `r` and `r+p`
would force its derivative to vanish at all `p` residues. The derivative
would therefore be the zero polynomial modulo `p`, making the original
polynomial constant modulo `p`. That contradicts its values `F(r)=r`.
Starting from an encrypted variable and public constants, multiplication
depth `d` permits degree at most `2^d`. At `p=65537`, this baseline requires
at least 17 multiplication levels. This is a bound for univariate integer
polynomial sections; it is not an impossibility theorem for other encrypted
mechanisms or additional evaluation-key constructions.

## Coefficient projection without scaling existing noise

Ring multiplication mixes plaintext coefficients. Evaluating `F` directly
on a packed coefficient polynomial would not apply `F` separately to each
coefficient. The baseline instead projects each coefficient to a constant
plaintext using native main-basis Galois keys.

Tracing `X^-j * x` using exponents `N+1, N/2+1, ..., 3` yields `N*x_j`.
Normalizing that ciphertext with centered `N^-1 mod p^2` multiplies its
error by the inverse's magnitude. For the current tuple the inverse is
`-524304`; this would require a 92-bit error bound against an 86-bit
half-scale.

`PrimePowerPhaseEvaluator` avoids that amplification by directly evaluating
one additional encrypted view from the public components:

```text
a0' = (N^-1*a0) mod p^2
a1' = (N^-1*a1) mod p^2
trace_input = Enc_{p^2}(a0' + a1'*s_work mod p^2).
```

The public coefficients are reduced before ciphertext evaluation. Their centered
magnitudes satisfy the original expanded-phase certificate, so this view
has the same 60-bit input-error bound. Its trace recovers `x_j` modulo
`p^2`, with a 73-bit bound and no subsequent inverse multiplication. It is
created with the other views, bound to the same phase lineage and boot-key
family, and exposed only through immutable accessors. It has no auxiliary
wire lanes and does not contain a clear digit or winding.

## Noise admission and the remaining four-prime gate

The native Galois switch uses the exact backend's lane-idempotent gadget
keys. With gadget base `B` and a total of `L` digits, its added error is
bounded by `gamma = eta*N*(B-1)*L`. Repeated trace folds have bound
`N*E_input + (N-1)*gamma`. For the current parameters, `B=1024`, `L=12`,
and `gamma=301694976`.

The polynomial plan admits every factor, balanced product, final addition,
and coefficient reassembly before key generation. For a constant plaintext
operand, write its centered component decryption as

```text
Z = (Q/P)*m + E + Q*K,   P=p^2,   |K_j| <= N/2+1.
```

Exact BFV multiplication contributes both ordinary message/error terms and
`P*(K_A*E_B + K_B*E_A)`. These winding/error terms do not vanish modulo `Q`.
The coefficient error is conservatively bounded by

```text
(E_A+E_B)*((P-1)/2 + P*N*(N/2+1))
  + ceil(P*N*E_A*E_B/Q)
  + ceil((1+N+N^2)/2) + gamma.
```

The implementation bounds the quadratic term using public bit lengths and
checked fixed-width arithmetic. It rejects errors at or above
`floor(floor(Q/P)/2)`. On the present four-prime tuple the first polynomial
multiply already needs a **131-bit** bound, against **86 bits** available.
This is rejection of this baseline's worst-case certificate; it does not
prove every possible four-prime contraction impossible.

Without that rejection, the coefficient-by-coefficient baseline at the
current parameters would perform 106,496 Galois operations and 536,870,912
ciphertext multiplications. Its main evaluation-key payload would contain
11,010,048 64-bit words, about 84 MiB before allocation overhead. The
recursive product uses a logarithmic live stack rather than materializing
all 65,537 factors together. It is a correctness baseline with explicit
admission, not a practical admitted bootstrap for this tuple.

## Verification boundaries

`public_prime_power_lift` covers:

- Exhaustive scalar section identities for bases 3, 5, 17, 31, 101, and 257,
  and the derivative identity at all 65,537 roots for the target base.
- Genuine encrypted canonical lifts for every `x mod p^2` at bases 3, 5,
  and 17 in explicitly insecure `N=8` rings, including every coefficient.
  The producer receives ciphertexts and public keys. Decryption verifies
  outputs and measured errors; it never supplies the digit to the producer.
- Contraction to plaintext `p`, followed by public square/relinearization.
- Full-size `N=8192` Galois permutations and a preconditioned coefficient
  trace, plus malformed secret, exponent, family, and residue refusals.
- Refusal of the current four-prime polynomial plan before generating keys.

The `prime_power_phase` integration test checks the directly preconditioned
view for all 38 existing full-ring input cases, including levels two through
four, evaluated inputs, and both maximum input-error extremes. These tests
do not certify a complete production refresh. Actual input-noise admission,
an admitted encrypted digit-removal circuit, and the final output key
relationship remain required by the
[bootstrap correctness contract](BOOTSTRAP_CORRECTNESS_CONTRACT.md).

```sh
cargo test -p nine65 --features allow_insecure --lib public_prime_power_lift
cargo test -p nine65 --features allow_insecure --test prime_power_phase
```
