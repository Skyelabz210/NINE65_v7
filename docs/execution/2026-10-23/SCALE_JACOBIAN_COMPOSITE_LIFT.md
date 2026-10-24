# Scale-Jacobian p-locked lift

This research path now recovers the p-locked carry, bounded residual, and a
same-history ciphertext for the quotient winding. A native composite-`pJ`
tray consumer also corrects the residual and survives two dependent products,
but its bounded offset is still supplied by a test oracle. It is not a public
refresh: the live Safe-Basis root has not been joined to the Jacobian history,
and the returned ciphertext is not switched back to the work key. A worst-case
winding bound is now derived for the current ternary output-key and RNS-scale
contract; this is an experiment-side bound, not yet an authenticated production
certificate.

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
  97; the earlier four-prime output noise ledger is 156/159 bits against a
  180-bit `Q`. A dependent product was not run under that earlier tuple; the
  wide-step follow-up below runs native square and cube controls.
- The `L=19,965` comparison remains passing at N=512 and N=8192, but uses the
  diagnostic residual encryption.

These are evaluator-style arithmetic/noise experiments with a test key holder.
They are not yet a public evaluator implementation: the test builds the
scale-difference evaluation material from test-known secret support, and its
client observer decrypts to check the bounds.

## Wide-step same-history winding sibling

The native larger-step test tightens the carry ledger and isolates the
remaining quotient winding. It uses
`M=65,538=p+1`, `L=211*p*M=906,279,584,166`,
`T=pL=59,394,845,107,487,142`, and three 59-bit outer primes (`Q=175` bits).
The exact centered `L`-tray quotient produces a high view whose plaintext is
`e+pJ`; the p-view still returns `e`. A p-locked sibling is made from the
same ciphertext history, then the composite `M` view is used to isolate `J`:

```text
offset B = public residual bound
Dec_p(L * (e+pJ+B))                = e+B mod p
Dec_M((T/M) * (e+pJ+B))            = e+B+pJ mod M
Dec_M(L * (e+pJ+B))                = e+B mod M
subtract the latter from the former M-view -> pJ mod M
p = -1 mod M, so multiply by -1 -> J mod M
```

`B=3` at N=512 and `B=97` at N=8192 keep `e+B` in the nonnegative p
representative. Because `M=p+1`, the p and M encoding scales differ by only
one unit in their moduli; the bounded offset's scale error is below one-half
plaintext unit. The centered inverse is `-1`, which avoids amplifying the
ciphertext noise by the canonical residue `65,537`.

At native N=8192/H=96, all 16,384 coefficients pass the same-history sibling
decode and recover `J` with zero mismatches. The largest observed `|J|` is
115; `M` has centered radius 32,768. The p*M sibling error is 153 bits, and
the ciphertext-only J output error is 165 bits; both are below the 174-bit
`Q/2` decoder capacity. The same run measures carry/corrected Phase 1 at
139/141 bits, square at 167 bits, and the cube after the clear-J correction
control at zero mismatches. The updated tuple passes the repository's 128-bit
security screen. This confirms the p-locked and composite-sister arithmetic
on one history. For the centered component quotient, each coefficient is at
most `Q/(2L)+1/2`; convolution by a ternary output key of degree `n_out` adds
at most `n_out` such terms. BFV decoding therefore gives the public bound
`|J|<=n_out/2+1` when `Q>=L*(n_out+1)`, `B<p`, and
`T>2*p*(n_out/2+1)`. The current native tuple checks these inequalities and
`p+1>2*(n_out/2+1)`, so `J mod (p+1)` uniquely identifies the signed winding
through the full bound. At `n_out=16,384`, this is `|J|<=8,193`, while the
observed maximum is 115. The bound depends on the output key remaining ternary
and on the checked `Q,L,T` inequalities; production must bind those facts to
the ciphertext history and key certificate.

## Remaining architecture gap

The one-root Safe Basis exercise in
`crates/nine65/src/ops/safe_basis_sister_tray_tests.rs` still uses symbolic
support rows and a projector that reads their clear remainders. It does not
attach the live `T=pL` scale-difference ciphertext and p-locked views to one
authenticated Root211 history. That integration needs a root capable of
binding the `pL`, `p`, and `M=p+1` views to the identical ciphertext, key, RNS
chain, input commitment, and history, with public certificates for both
`|e|` and the derived `|J|` bound. Then the root must lift `J mod M` into the
`T` encoding so the carry consumer can subtract `pJ` without a clear
representative. A symbolic endpoint fixture now exercises that scaled
projection, but it still receives clear support rows and is not the live
history-bound producer.

After that join, the corrected phase still must return to the work key, pass
the native dependent-product/noise check, and survive a second refresh. Until
those gates pass under admitted parameters, the production public-refresh path
remains fail-closed.

## Composite `pJ` tray and bounded lift

The next consumer uses one larger composite sister tray to carry the
correction `pJ` itself, avoiding multiplication by `p` after lifting `J`.
Choose `A=517=11*47`, `M1=p+1`, and

```text
M_pJ = A*M1 = 33,883,146
L    = p*M_pJ = 2,220,599,739,402
T    = p*L = p^2*M_pJ = 145,531,445,121,188,874.
```

The centered tray radius is 16,941,572. The native experiment observes
`max |J|=147`, or `p*max|J|=9,633,939`, across 16,384 coefficients, so this
tray carries the observed winding. It cannot carry the full public bound:
`p*8,193=536,944,641`, well beyond its radius. Treat this composite-tray
route as a consumer diagnostic, not the bounded production lift. The same
tray also passes the 128-bit outer-chain screen.

For `X=e+pJ+B`, the same-history high view scaled by `T/M_pJ=p^2` encodes
`e+B+pJ` modulo `M_pJ`. The p-locked `p+1` view already identifies the
bounded offset `e+B`; a Safe-Basis bounded projection must emit that offset
directly at `M_pJ`. Subtraction then gives the bounded centered `pJ` residue.
Since `|pJ|<M_pJ/2`, K-Elimination division by `p^2` lifts the centered signed
integer into `T` exactly. The high correction is `X_T - lift_T(pJ)`.

The medium and native consumer tests currently supply `e+B` with a clear
test oracle to isolate this arithmetic. At N=512 and N=8192, respectively,
the centered `pJ` lift has zero mismatches over 1,024 and 16,384 coefficients.
The corrected residual has 62-bit measured error at both sizes. Its p-view
carry and corrected Phase 1 each have 115-bit and 116-bit measured error;
the dependent square and following product decode exactly at both sizes.
The direct scalar-p control fails in half the slots, demonstrating why the
tray must encode `pJ` before the high lift.

The attempted conversion of `Enc_(p+1)(e+B)` to `M_pJ` with raw
componentwise division fails in 963/1,024 medium slots and
16,197/16,384 native slots. That is the isolated producer gap: the existing
one-root bounded projector can emit `Enc_M_pJ(e+B)` from symbolic support,
and its new composite-target fixture passes at offsets 0, 129, and 258, but
the projector is not yet bound to the live Jacobian ciphertext, its p/p+1/
composite views, or a certified `|J|` envelope.

## Direct-root alternative

The `p+1=65,538` winding tray itself has enough centered capacity for the
derived native bound: its radius is 32,768, greater than
`n_out/2+1=8,193`.
The Safe-Basis fixture now exercises a direct scaled lift from this even-period
tray: given `J mod (p+1)` and the public bound, the root selects the unique
centered `J` and projects `pJ` directly into `T`. Its endpoint checks cover
`J=+-16,386`, plus the observed `+-147` and zero. The endpoint test exceeds
the derived bound and still sign-lifts within the p+1 tray.

The fixture remains symbolic: its support rows contain the clear winding, and
the root projector uses those rows to form the result. The next implementation
step is to connect the live same-history `J mod (p+1)` ciphertext to that
bounded projection without exposing or supplying `J`, certify projection
noise under the native output chain, and subtract the resulting `Enc_T(pJ)`
from the same-history high ciphertext. Then verify the p-view carry, work-key
return, dependent products, and second refresh through the actual producer.

## Full-bound composite `pJ` tray

The tighter bound supports a larger 11-anchored composite tray:
`A=16,390=2*5*11*149`, `M_pJ=A*(p+1)=1,074,167,820`,
`L=p*M_pJ=70,397,736,419,340`, and
`T=p^2*M_pJ=4,613,656,451,714,285,580`. The centered radius is 537,083,909,
which covers `p*8,193=536,944,641` plus the native offset span `2B=258`.
Three 63-bit NTT primes give a 189-bit Q chain; the tuple passes the
repository's 128-bit screen. The N512 and N8192 full-bound consumer/product
tests pass. At native N8192, `max |J|=132`; the full tray has zero K-Elimination
mismatches, corrected residual error is 66 bits, and carry/Phase 1 error is
123 bits. The square and following product both decode exactly. The raw
same-history offset conversion still fails in 16,183 of 16,384 slots, so the
consumer receives `e+B` from a test oracle.

This composite route projects `e+B` into `M_pJ` and subtracts it from the
same-history `e+B+pJ` view before K-Elimination lifting by `p^2`. The offset
projection fixture passes at 0, 129, and 258, but still uses clear symbolic
support rows; the consumer experiment still uses a test oracle for the live
offset. The remaining implementation gate is binding the actual Jacobian
history to that one-root projection with a native noise certificate.
