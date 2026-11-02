# Deterministic closure of the attached toy refresh cycle

The fixed N16/p97 harness now enters every refresh using a computed error
allowance. Its 32-seed execution checks these caps on every source coefficient,
return coefficient and following-square coefficient, across 160 cycles. An
understated return cap of zero is rejected. The observer only compares errors
with the precomputed plan; measured errors never update that plan.

The ledger concerns the [attached toy](ATTACHED_TOY_REFRESH.md). Its formula
derivations and implementation correspondence are reviewed mathematical
obligations, rather than a formal Rust refinement or native-security grant.

## Units and deposits

E bounds coefficient error relative to exact Delta=Q/t encoding. Both toy
moduli are divisible by their plaintext modulus. For canonical base-2^w
gadget digits, each switch deposits at most

`S = N * 8 * (2^w-1) * ceil(bit_length(Q)/w)`.

A centered plaintext multiplier with coefficient L1 norm L multiplies E by
L. A Galois switch adds S. Each complete transform sums all 16 diagonal terms;
the uniform diagonal norm allowance is `16*floor(97²/2)`. The identity Galois
term is conservatively charged a switch too. Adding plaintext deposits zero
error because the encoding scale is exact.

For centered full-polynomial BFV tensor multiplication, the ledger charges

```text
F = N*floor(t/2) + N*t*(N/2+1)
E_product <= (Ea+Eb)*F + ceil(N*t*Ea*Eb/Q)
             + ceil((1+N+N²)/2) + S.
```

The first factor includes full polynomial plaintext norms and both winding
cross terms. The rounding deposit includes c0, c1*s and c2*s²; the final
deposit includes every gadget column. Operand and result headroom are checked
against Q/(2t). The ledger charges all 13 Horner products, both transforms,
and subtraction of the residual polynomial.

Reinterpreting a proved p-multiple from t=p² to t=p preserves E. Component
modulus switching deposits rounding from c0 and all 16 possible outer-secret
coefficients, so the dropped envelope is

`ceil(E_outer * Q_in/Q_out + 17/2)`.

## Resulting caps

| Stage | Bound |
| --- | --- |
| Outer restored coefficient error | 351-bit integer, recorded exactly in plan.json |
| After component modulus switch | 9 |
| After return key switch | 195849 |
| After following full-polynomial square | 5772257706 |
| Next refresh residual radius | 3 |

The last residual is computed as
`floor((2*p²*E + Q_in*(H+1))/(2*Q_in))`, with H=4.
It fits the same radius-3 digit polynomial on every cycle. The initial
stressed input uses its separately derived bound 2833792863. Neither cap is
replaced by a fresh-encryption estimate.

`PublicRefreshBounds.toy_full_polynomial_cycle_budget` checks the concrete
return deposit, following-square corridor and source decoding headroom in
Lean. The earlier admission theorem proves the integer division threshold.
The stage-error derivations above remain separate from these arithmetic
theorems. The proof slice now contains 53 explicit statements.

## Execution and reproduction

[Evidence](toy-cycle-ledger/validation.json) includes the immutable generated
harness, full exact plan, source hashes, kernel result, all 32 transcripts and
the failing understated-bound control. The generator checks the archived
cycle source digest before attaching caps. CI compares regenerated source,
tests the ledger, runs an encrypted five-cycle fixture and requires the
specific negative-control failure.

```sh
python3 scripts/test_toy_refresh_ledger.py
cargo run --locked --release --manifest-path docs/execution/2026-11-01/toy-cycle-ledger/Cargo.toml -- 0
python3 scripts/check_public_refresh_proofs.py
```

This completes a deterministic repeated-cycle bound model and executable
conformance checks for the toy. Full formal correspondence of Rust arithmetic,
general ciphertext-history issuance, and confidentiality of the key graph
remain separate work. The original toy and its historical evidence are retained.
