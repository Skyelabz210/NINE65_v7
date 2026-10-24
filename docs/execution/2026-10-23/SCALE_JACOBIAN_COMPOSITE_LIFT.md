# Scale-Jacobian p-locked lift

This research path now recovers both the carry and bounded residual from one
encrypted scale-difference history. It corrects Phase 1 at the native ring
dimension and survives a dependent square at N=512. It is not yet a public
refresh: the live producer is not connected to the Safe Basis root API, and
the returned ciphertext is not switched back to the work key.

## Tropical scale derivative

For each centered source component residual `R_i`, define the scale chart

```text
b_i(t) = round(t*R_i/Q_source)
d_i    = b_i(p+L) - b_i(p).
```

Combine the `d_i` with the source secret polynomial and the negacyclic sign
rule. If the source phase is `S = R_0 + R_1*s = Q_source*K + g`, the discrete
scale derivative has the form

```text
Delta = L*K + e.
```

Each component's two rounding errors differ by less than one. For secret
weight `H` and admitted phase `|g| <= Q_source/D`, the public integer bound is
`|e| <= ceil(L/D) + H`. This is the piecewise-linear, ultradiscrete chart used
by the experiment; it does not assume a smooth Jacobian.

## Same-history p-lock

The earlier invertible-step trial used `L=19,965`, with
`Delta mod L` as a centered residual tray and modular inverse for K-Elimination.
That producer still needs a diagnostic oracle `Enc_p(e)`. The p-locked branch
uses a different identity: choose `L` divisible by `p`, and encode the one
scale difference under `T=pL`.

```text
Dec_p(Enc_(pL)(Delta))       = round(Delta/L) = K
Dec_p(L * Enc_(pL)(Delta))   = Delta mod p = e mod p.
```

The first view returns `K` because `|e| < L/2`. In the second view, the
plaintext scale cancels and `L*K` vanishes modulo `p`. Both views reuse the
same ciphertext components, RNS basis, output key, and history; no client
residual and no fresh residual encryption enters this p-locked consumer. This
is the useful K-Elimination connection: the tropical quotient and its bounded
remainder are separated by scale-locked sister views.

The working parameters are `p=65,537`, `L=4,999p=327,619,463`,
`T=pL=21,471,196,746,631`, source `D=2^31`, three source RNS lanes, and four
45-bit output NTT primes (`Q` is 180 bits). For H=2 the public residual bound
is 3; for native H=96 it is 97. The native test observed maximum `|e|=14`.
The output chain is an unadmitted correctness fixture (`security_bits=0` in the
test config), not a production parameter set.

## Evidence

In `crates/nine65/tests/research/batched_lift_phase.rs`:

- N=16: same-history residual and carry decode; corrected Phase 1 and a
  dependent square pass.
- N=512: same-history residual and carry decode; corrected Phase 1 passes;
  both a fresh-encryption square control and the corrected-phase square
  decode exactly. The prior smaller-step setting failed only in the corrected
  square, which motivated the larger `L` and tighter `D`.
- N=8192, H=96: every coefficient passes same-history residual and carry
  checks plus corrected Phase 1. The observed residual is 14 against bound
  97; the output noise ledger is 156/159 bits against a 180-bit `Q`. A native
  dependent product and second refresh have not been tested.
- The `L=19,965` comparison remains passing at N=512 and N=8192, but uses the
  diagnostic residual encryption.

These are evaluator-style arithmetic/noise experiments with a test key holder.
They are not yet a public evaluator implementation: the test builds the
scale-difference evaluation material from test-known secret support, and its
client observer decrypts to check the bounds.

## Remaining architecture gap

The one-root Safe Basis exercise in
`crates/nine65/src/ops/safe_basis_sister_tray_tests.rs` still uses symbolic
support rows and a projector that reads their clear remainders. It does not
attach the live `T=pL` scale-difference ciphertext and p-locked views to one
authenticated Root211 history. That integration needs a root capable of
binding the `pL` and `p` views to the identical ciphertext, key, RNS chain,
input commitment, and history, with the public `|e|` certificate carried by
the root rather than supplied by a client.

After that join, the corrected phase still must return to the work key, pass
the native dependent-product/noise check, and survive a second refresh. Until
those gates pass under admitted parameters, the production public-refresh path
remains fail-closed.
