# Selected BFV rescale: remainder-adjusted fused piggyback division

The owner selects FPD for inexact BFV rescale. The existing residue-native
implementation of the required auxiliary division is `ExactScaleRound`, called
by `ExactMulEvaluator::try_mul_no_relin_exact_observed`. Reuse this route;
preserve its bound, coherent-input and main-Q output contracts. Its module
header's statement that it is not wired is stale.

This selection does not accept the unimplemented Safe Basis/sister integration
or any new encrypted DIV3 noise claim. Inversion belongs to operator lanes on
a phase-locked sister tray; it does not license a sequential scalar decoder.

## Exact result for an inexact division

For a centered tensor coefficient X and the current odd-Q BFV convention:

```text
Z = t*X + floor(Q/2)
r = Z mod Q, canonical in [0,Q)
Y = (Z-r)/Q = floor((t*X + floor(Q/2))/Q)
```

The original scaled value need not be divisible. Subtracting the exact
remainder makes the auxiliary division exact, while the final output retains
the specified mathematical rounding. Negative inputs use floor, not Rust's
truncation toward zero. Do not silently replace this rule with division by
Delta=floor(Q/t), nearest-even, or an exact-integer quotient promise.

For each transient auxiliary operator lane a, gcd(Q,a)=1:

```text
Y mod a = ((Z mod a)-(r mod a))*inverse(Q,a) mod a.
```

The same public Q inverse can be assigned/precomputed for the selected
operator lane. This does not make a nonunit invertible, nor does it remove
the distinct NTT/field requirements of lanes used for polynomial transforms.

`MainOnlyBaseExt` projects the canonical remainder's main residues into the
auxiliary frame using independent CRT-idempotent contributions and certified
rank correction. It emits target residues without a Garner/MRS chain or a
full coefficient X. Every emitted auxiliary residue must describe the same
bounded tensor coefficient as the main frame.

## Lift, capacity and coherent tensor construction

The kernel uses a public shift `S=s_mult*Q` with

```text
|X| <= b*Q^2
s_mult = b*t+1
|Y| <= S
0 <= Y+S <= 2*S
A > 2*s_mult*Q
```

Because Q divides S, projecting Y+S back to main Q emits the same residues as
Y. The strict auxiliary-capacity test remains mandatory. More dependent views
do not enlarge A's independent information by their raw product.

The live evaluator derives centered auxiliary input residues **before**
multiplication. It then computes matching negacyclic tensors in both frames
and applies the rescale to d0, d1 and d2. For centered inputs, the individual
products have the N/4 bound; the two summed products in d1 need N/2. The live
evaluator accounts for the larger bound; the scaler's blanket N/4 documentation
needs correction in F01. Extending a tensor only after its main residues have
wrapped cannot recreate the lost lift.

The raw scaler assumes same-X coherence and the declared bound. Its canonical
residue checks alone do not authenticate them. C01/C02/C06 must distinguish an
internally produced, context-bound component from arbitrary caller arrays or
caller-writable proof booleans.

## Exact division and general shared-factor lanes

Keep exact-integer division as a separate operation with its divisibility
guard. A general inexact FPD entry point needs an explicit positive divisor,
quotient/remainder convention and coherent remainder provenance. For floor,
derive `r=X mod d`; for the declared nearest convention, adjust the numerator
by `floor(d/2)` first and derive that adjusted remainder.

On a lane m sharing factors with d, let g=gcd(d,m). After valid remainder
subtraction, the lane can determine only

```text
q mod (m/g) = (((X mod m)-(r mod m)) mod m)/g
              * inverse(d/g,m/g) mod (m/g).
```

This requires divisibility of the canonical difference by g. If m/g=1, the
partial view is constant0 and requires no inverse. Sufficient coherent
good/auxiliary quotient coordinates and a unique bound must restore the
missing g-fold ambiguity by transduction. The congruence `d*q+r == X mod m`
alone does not select the intended full quotient.

The existing `cram_rescale_by_scalar_fpd` is not the selected BFV kernel: it
fuses a scalar quotient and changes a c0 witness through a generic callback.
The old scalar `k_elim::fpd` also requires exact divisibility. Neither may be
substituted by dropping its guard or passing unrelated auxiliary residues.

## Integration and evidence obligations

* C00 routes the main-only public evaluator through the existing exact tensor
  and remainder-adjusted FPD scaler, preserving the actual emission ledger.
* S03/S05 place inversion instructions and derived views on the admitted
  sister fabric while preserving the authoritative root/source epoch.
* C01/C02/C06 bind rounding, component identity, basis, encoding and the N/2
  bound through validated producers; return typed shape/capacity failures.
* R00 isolates mathematical rounding, encryption error and key-switch error
  in the bound ablation. Exact arithmetic does not erase these terms.
* Validate signed nondivisible values, rounding boundaries, insufficient
  capacity, incoherent arrays and the summed-component bound. Keep the
  no-reconstruction route checks and the arrow/emission refusal gates.

Source: `crates/nine65/src/arithmetic/exact_scale_round.rs:17,225,356,389`,
`crates/nine65/src/arithmetic/main_only_base_ext.rs:21`, and
`crates/nine65/src/ops/exact_mul.rs:769`. Current source has eight scaler unit
tests; this is an inventory, not a claim that they were executed here.
