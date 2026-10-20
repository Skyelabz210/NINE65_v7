# Exact noise-bound contract (draft)

Status: partial mathematical oracle; **no production noise certificate is
admitted**. The FPD integer rounding rule, its auxiliary range condition, and
the exact negacyclic `d1` cross-term bound below are executable. The complete
decrypt-phase recurrence, certificate provenance, and specialist proof review
remain open. `NoiseBudget` millibits are accounting state, not proof that a
particular ciphertext has the represented error.

This draft is scoped to the selected remainder-adjusted FPD path and the
coefficient-norm obligations it exposes. It does not replace
`FPD_BFV_RESCALE_CONTRACT.md`, permit wire export, or authorize refresh.

## Conventions

For each admitted level, let `Q` be the exact product of its ordered main RNS
factors, `t` the plaintext modulus, `Delta=floor(Q/t)`, and
`rho=Q mod t`. `Q` is odd for the selected production tuples. Decode against
the centered plaintext representative in `[-floor(t/2), floor(t/2)]` and the
phase `c0+c1*s (mod Q)`. A public bound must name the level and parameter
tuple; a bit count without its integer norm and context is insufficient.

The candidate norm is the coefficient infinity norm of the *canonical
centered* integer lift. For negacyclic convolution,

```text
||a*b||_inf <= N ||a||_inf ||b||_inf
```

and for a ternary secret with at most `h` nonzero coefficients,
`||s||_1 <= h` and `||s^2||_1 <= h^2`. These deterministic support bounds must
be established by the key and encryption samplers. A sampler failure
probability is a different contract: if any support is probabilistic, the
certificate must include a named lifetime failure budget and composition
rule. The two interpretations cannot be exchanged silently.

The encoding correction is load-bearing:

```text
Q = t*Delta + rho, 0 <= rho < t
Delta*m = (Q/t)*m - (rho/t)*m
```

Thus the phase error relative to the ideal rational scale `Q*m/t` includes
the `rho*m/t` term. Treating `Delta` as `Q/t` omits it.

## Executable FPD integer rule

For a centered integer tensor coefficient `X`, use exactly

```text
Z = t*X + floor(Q/2)
r = Z mod Q                 # canonical 0 <= r < Q, including for X < 0
Y = (Z-r)/Q                 # exact integer quotient, equivalently floor(Z/Q)
```

For odd `Q`, write `tX=kQ+a`, `0<=a<Q`. Then
`Y-k=floor((a+(Q-1)/2)/Q)`, so `|Y-tX/Q| < 1/2`. This is the specified
nearest-integer result for odd `Q`, with negative inputs using mathematical
floor. Exact integer division is a separate operation and must retain its
divisibility check.

The exact remainder identity `Z=QY+r` is independently checked by
`scripts/certified_noise_oracle.py`. Every auxiliary remainder used to derive
an auxiliary quotient must be derived from this same `Z`, `X`, context, and
operation node. Canonical arrays by themselves do not prove that coherence.

If `|X| <= b*Q^2`, define `s_mult=b*t+1`, `S=s_mult*Q`. The conservative
output interval is `|Y|<=S`; therefore `Y+S` is in `[0,2S]`. The independent
auxiliary product must satisfy the strict condition

```text
A > 2*s_mult*Q
```

Equality is insufficient. The oracle tests both sides of this boundary. This
is a capacity statement about the integer lift; it is not a bound on encrypted
phase error.

## Tensor coefficient bound

With every centered input coefficient bounded by `B=(Q-1)/2`, each individual
negacyclic product has coefficient magnitude at most `N*B^2 < N*Q^2/4`.
The BFV cross component is the sum of two products,

```text
d1 = a0*b1 + a1*b0
||d1||_inf <= 2*N*B^2 < N*Q^2/2.
```

The executable toy fixture reaches twice the single-product bound. A bound
that uses `N/4` for this summed component is rejected. This proves only the
integer tensor coefficient range before rescaling; it does not bound the
post-relinearization decrypt phase.

## Candidate certificate semantics; not yet frozen

A future `CertifiedNoiseBound` must be produced by a trusted encryptor or a
checked operation transition, without reading the secret actual error. It
must bind at least the parameter/context fingerprint, ordered basis and
level, key domain and epoch, message encoding, norm and integer unit,
sampler-support policy, operation identifier and parent identifiers, and the
derived integer bound. Imports without an authenticated admitted history stay
uncertified. Public hashes or signatures can bind a claim but cannot make an
unsound recurrence true.

Do not serialize millibits as `CertifiedNoiseBound`: the exact integer upper
bound and its norm/context interpretation are authoritative. A wire version
and canonical encoding must be specified only after the fields and recurrence
are accepted.

## Recurrences still required before admission

The following terms must be derived separately at the actual level and
operation boundary, then composed with checked integer arithmetic:

| Transition | Required inputs and unresolved derivation |
| --- | --- |
| Fresh encryption | Public-key error, encryption error, mask support, secret support, and the `rho*m/t` encoding correction. Bind the sampler support or quantify its failure budget. |
| Add / add-plain | Join both input bounds; add-plain has no noise only under the exact encoded operation and matching context. |
| Scalar / polynomial plaintext multiply | Distinguish coefficientwise constant multiplication from a full negacyclic polynomial product; bind the actual plaintext coefficient norm. |
| Ciphertext multiply | Propagate both input signal and error bounds through all three tensor components, `Delta=floor(Q/t)` correction, FPD rounding residues, and the summed `d1` cross term. Do not use a symmetric one-input shortcut for unequal bounds without proof. |
| Relinearization / key switch | Derive the exact decomposition, digit bounds, evaluation-key error support, secret factors, and additive phase contribution for the implemented key format. |
| Transform / basis change | Show whether each transform is an exact modular permutation or introduces rounding/projection error; bind the basis and level. |
| Modulus switch | Include coefficient rounding residues and their multiplication by the secret, with the actual level transition and signed rounding rule. A level drop cannot be credited without the matching producer. |
| Refresh | Bound input phase perturbation, encrypted digit-removal circuit, bootstrap-key errors, output rounding, and output key relation. The missing encrypted digit-removal proof prevents a reset certificate. |

The existing `NoiseBudget` recurrence is a candidate capacity heuristic. Its
integer arithmetic, margin, and unit tests do not establish these transitions
for an arbitrary `TrackedCiphertext`. In particular, no counter reset,
successful sample decryption, or caller-provided error measurement may issue a
bound.

## Admission gate

This draft does not satisfy C01 acceptance. Before C01 can be marked complete,
an independent specialist review must show that every recurrence dominates
the exact decrypt-phase error on exhaustive small-ring and adversarial
sign/tie domains, that all assumptions are enforced by constructors and key
samplers, and that negative fixtures fail when either the `d1` cross term or
the `rho*m/t` floor-scale correction is removed. Until then C02 certified
history, C03 wire export, and service ciphertext transport remain gated.
