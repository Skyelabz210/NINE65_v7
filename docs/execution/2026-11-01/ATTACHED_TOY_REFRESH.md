# Executed attachment: residual-polynomial public refresh

The supplied Rust program works for the tested toy parameters. The exact,
unmodified attachment passes seeds 0 through 31. It checks all 679 permitted
digit inputs and recovers all 16 message coefficients under the original key
and modulus. The degree-13 polynomial is `F(X)=X-G(X)H(X)` modulo 97².

An explicit extension adds the following square that the attachment's final
comment announces but does not execute. It reuses one set of bootstrap,
Galois, relinearization and return keys for five refresh/square cycles per
seed. Across the same 32 seeds, all 160 refreshes and 160 following squares
pass: 5,120 coefficient comparisons against the expected plaintexts. The
square oracle uses separate small-integer schoolbook arithmetic. The first
input's observed error has bit length 32; returned errors have bit lengths
13 through 15. Every tested cycle also asserts observed error contraction.
The largest observed residual is 2, within the declared bound 3.

The [evidence directory](toy-refresh-evidence/validation.json) preserves the
original source, a reviewable extension patch, both runnable binaries, locked
dependencies and all seed transcripts. The extension moves return-key setup
before the cycle loop and generates source relinearization keys there. Secret
keys within the loop are used by the observer checks. This remains a
monolithic reference harness rather than a typed evaluator/client API.

## Algebraic connection

The new Lean theorem
`KElimination.PublicRefreshDigit.residual_polynomial_correct` proves, for
every signed integer K and positive p, that

```text
G(r) = 0 mod p²,  G'(r)H(r) = 1 mod p
    implies
(r+pK) - G(r+pK)H(r+pK) = r mod p².
```

It uses the already proved Taylor and exact-division identities and the
runtime-style indexed derivative certificate. The kernel checks the theorem
without a custom axiom or `sorry`. The proof audit now requires it. All ten
proof-gate controls pass with this extension, bringing the explicit theorem
count in this slice to 51. Earlier 50-theorem evidence remains historical.

This residual form evaluates G and H together at p². The existing native
research backend extracts K using G at p² and H at p, which has different
noise costs. The attachment supports the algebra of that construction; it
does not require replacing the implemented split-encoding backend.

## What this establishes

This is constructive encrypted refresh evidence for N=16, p=97, source
secret weight 4, Q_in=97*2^40 and Q_out=97²*2^900. The source and outer
encoding scales are exact because their plaintext moduli divide Q. Those
manufactured moduli differ from the repository's native RNS tuples.

The residual allowance is an input precondition. Ordinary BFV decryptability
alone does not imply `|eps|<=3` after p² component rounding. With ternary
support H, the component-rounding contribution is bounded by `(H+1)/2`,
in addition to the scaled source error `p²*|e|/Q_in`. The supplied stressed
input fits that corridor, as do the tested following squares. Runtime
observer checks establish these instances; they are not a universal
producer-issued bound for arbitrary histories.

The SplitMix-style RNG, modulo-reduced samples, small dimension, sparse
secret and correlated evaluation-key graph provide no production-security
admission. This run does not prove IID emissions or replace the actual
residue-operation arrow harness. See [current refresh status](../../PUBLIC_REFRESH_STATUS.md)
for the separate native research implementation and its security scope.

Reproduce individual runs from the repository root:

```sh
cargo run --locked --release --manifest-path docs/execution/2026-11-01/toy-refresh-evidence/Cargo.toml --bin original -- 0
cargo run --locked --release --manifest-path docs/execution/2026-11-01/toy-refresh-evidence/Cargo.toml --bin cycles -- 0
python3 scripts/check_public_refresh_proofs.py
python3 scripts/test_public_refresh_proofs.py
```

The standalone manifest keeps the attachment's BigInt dependencies outside
the production workspace. No production arithmetic or support gate changes.
