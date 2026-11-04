# Refresh arithmetic: written derivations

Scope and review: [proof coverage](README.md). All polynomial identities below
are over the integers or the explicitly named residue ring. A congruence is not
an equality of canonical integers unless a lift bound is also given. Norms are
coefficient infinity norms. Ring products are negacyclic.

## A1. Constructing the finite G/H certificates

**Statement.** Let p be an odd prime, B >= 1 and 2B < p. Put
S = {-B,...,B}, and let G(X) = product over r in S of (X-r). There is a unique
H in F_p[X] of degree at most 2B with H(r)G'(r) = 1 for every r in S.
It is even. Any integer coefficient lift of these polynomials, with G lifted
modulo p² from the displayed product, satisfies the finite certificates used
by `bounded_digit_circuit::polynomials`.

**Proof.** Distinct elements of S remain distinct modulo p: their nonzero
differences have magnitude at most 2B < p. At a root r,

    G'(r) = product over u in S, u != r, of (r-u).

Every factor is nonzero in the field F_p, so the product is invertible. Write
G_r(X) = G(X)/(X-r). Lagrange interpolation gives the explicit construction

    H(X) = sum over r in S of G_r(X) / G'(r)²   in F_p[X].

Indeed, at u in S all summands other than r=u vanish, and the surviving value
is G_u(u)/G'(u)² = 1/G'(u). Its degree is at most 2B. The difference of two
such interpolants has 2B+1 distinct roots and degree at most 2B; division by
successive linear factors forces that difference to be zero.

Symmetry gives G(-X)=-G(X), hence G'(-X)=G'(X). Thus H(-r)=H(r) at every
root. Uniqueness yields H(-X)=H(X). Since p is odd, comparison of coefficients
makes each odd coefficient zero. This justifies the runtime evenness check.

Finally G(r)=0 as an integer for the displayed product. Replacing coefficients
by their representatives modulo p² preserves G(r)=0 mod p² and preserves
G'(r) mod p. Thus the actual lifted coefficient list has exactly the required
root and inverse-derivative identities. The runtime's synthetic quotient is
G_r modulo p; its inverse-squared weighting matches the formula above. QED.

**Intuition.** G erases the small residual r; its first derivative records how
strongly a displacement by p*K survives. H divides by precisely that slope.

**Existing theorem reused.** Taylor expansion and division by p are already
proved by `PublicRefreshDigit.certified_split_digit`:

    G(r+p*K) = G(r) + p*K*G'(r) + p²*T,
    ((G(r+p*K) mod p²)/p) * H(r+p*K) = K mod p.

For a small signed example, take p=7, B=1, r=-1 and K=-2. Then x=-15,
G=X*(X-1)*(X+1), G(x) mod49=21, and G'(-1)=2. Thus H(-1)=4 mod7,
and `(21/7)*4=12=5 mod7`, the residue of -2. The division is exact before
the final field reduction.

This covers signed K and does not divide by p inside F_p. Division happens on
a certified multiple in Z/p²Z before reduction to F_p.

**Second pass.** If 2B >= p, roots collide and G'(r) need not be invertible.
If p is composite, distinct nonzero differences need not be units. If G(r)
vanishes only modulo p, its quotient contributes an unwanted G(r)/p term.
These are necessary hypotheses, not cosmetic restrictions.

## A2. From slot divisibility to coefficient divisibility

**Statement.** Let N be a power of two, 2N divide p-1, and
R_a = (Z/p^a Z)[X]/(X^N+1), a=1 or 2. Use the same ordering of odd powers of
a primitive 2N-th root for both encodings, with the p² roots reducing to the
p roots. If M in R_2 evaluates to a multiple of p in every slot, then every
coefficient of M is divisible by p. Dividing those coefficients by p gives
Z in R_1 whose slots are the corresponding quotients modulo p.

**Proof.** In F_p a primitive 2N-th root z exists, and z^N=-1. Its N distinct
odd powers are the roots of X^N+1. Distinct root differences are nonzero in
F_p; any lifts of those differences to Z/p²Z are units. A root lift can be
chosen as z_tilde = z^p mod p²: it reduces to z and z_tilde^N=-1 mod p²,
because z^N=-1+p*k and (-1+p*k)^p=-1 mod p² for odd p. Its reduction has
order 2N, so the lifted root also has that order.

The evaluation matrix has Vandermonde determinant equal, up to sign, to the
product of all root differences. This is a unit at both moduli. Evaluation is
therefore invertible at p and p². Reduction modulo p commutes with evaluation.
The assumed slot values reduce to zero; invertibility over F_p forces every
coefficient of M to reduce to zero too.

Choose canonical coefficients M_i=p*Z_i, with 0 <= Z_i < p. For any lifted
root w, evaluation gives M(w)=p*Z(w) mod p². Division on the ideal (p) is
well-defined modulo p: changing a representative by p² changes its quotient
by p. Reducing the divided equality gives the claimed slot values. QED.

**Encoding-scale consequence.** Let Q be the ciphertext modulus and suppose
a ciphertext has ideal-grid phase

    phase = (Q/p²)*M + E  modulo Q.

Using the divisible representative M=p*Z turns the *same phase* into

    phase = (Q/p)*Z + E  modulo Q.

No ciphertext operation, new rounding or new error is introduced. Choosing
another representative changes the phase by an integer multiple of Q.
The bound E must be checked against the new decoding threshold. This is an
identity of rational ideal-grid representatives, not a claim that Q/p² is an
integer. Floor-Delta encryption's discrepancy must already be charged in E.

**Intuition.** The slot transform is an invertible change of coordinates.
All coordinates becoming zero modulo p means the polynomial is zero modulo p,
not just zero at one visible coordinate.

**Source correspondence.** `direct_slot_phase::SlotEncoding` constructs and
checks these roots. `bounded_digit_circuit::evaluate_key` reuses G's ciphertext
under the p context and multiplies by H there. Both contexts share Q, ring,
key and slot order. These are essential coherence premises.

**Second pass.** One vanishing slot is insufficient: X-w vanishes at w but
is not coefficient-wise divisible by p. Over a nonsplit ring, or with a
singular transform, the argument also fails. A quotient of slot residues taken
in an inconsistent order does not prove anything about the actual ciphertext.

## A3. Deriving the native source residual from scaled error

**Statement.** Work coefficient-wise in Z[X]/(X^n+1), with odd Q and p,
a ternary source secret s having H nonzero coefficients, and an integer phase
lift satisfying

    v = p*(c0+c1*s-Q*k) - Q*m,      ||v|| <= V.

For i=0,1 choose coefficient-wise nearest integers A_i to p*c_i/Q and set
R_i=p*c_i-Q*A_i. Choose nearest integers d_i to p*R_i/Q. Define

    A=A0+A1*s,   x=d0+d1*s,   K=m+p*k-A,   rho=x-p*K.

Then

    |rho_j| <= floor((2*p*V + (H+1)*(Q-1))/(2*Q)),
    |x_j| <= (H+1)*floor(p/2),
    m = A+K mod p.

Changing A_i to a congruent representative modulo p does not change the last
message identity. Use the exact nearest lifts for the integer derivation.

**Proof.** Each Q*d_i-p*R_i is an integer of magnitude at most (Q-1)/2:
Q is odd, so nearest rounding cannot land on a half-integer tie. A signed
negacyclic convolution with a weight-H ternary secret therefore bounds

    ||epsilon|| <= (H+1)*(Q-1)/2,
    epsilon = Q*x - p*(R0+R1*s).

Substitute R_i=p*c_i-Q*A_i and the source scaled-error equation:

    Q*x = p²*(c0+c1*s) - p*Q*A + epsilon
        = p*Q*(m+p*k-A) + p*v + epsilon
        = p*Q*K + p*v + epsilon.

Thus Q*rho=p*v+epsilon exactly. The triangle inequality, then integrality,
gives the first bound. Also |R_i| <= (Q-1)/2 implies
|d_i| <= floor(p/2); hence x has at most H+1 signed terms of that magnitude,
giving the second bound. K's definition gives m=A+K mod p. QED.

**Native substitution.** p=65537, H=96 and the admitted V give residual
radius 49. Thus D=97*32768=3,178,496 and

    p*|K_j| <= |x_j|+|rho_j| <= D+49,
    |K_j| <= floor((D+49)/p) = 48.

Both 2D < p² and 2*48 < p. The centered p² lift of x and the signed p lift of
K are unique in their respective intervals. These norm/uniqueness steps
already appear in `PublicRefreshNativeLift.lean`; the new derivation here
explains how the source error supplies rho and the affine correction.

**Intuition.** Rounding each ciphertext component loses a secret-dependent
carry. The coherent phase computes that carry under encryption, and adding
it back repairs the rounded affine message.

**Source correspondence.** `public_refresh_source::source_residual_radius`
uses precisely the displayed rational bound, via integer binary search.
For an admitted V<Q/2, that bound is below (p+H+1)/2. The initial lower
endpoint 0 is feasible and the code's `hi=(p+H+1)/2+1` is strictly above the
floor. The comparison `2*Q*mid <= numerator` is monotone, so each iteration
preserves `lo <= floor(bound) < hi`; termination at `hi=lo+1` returns the exact
floor. P5 checks the relevant wide intermediates.
`direct_slot_phase::evaluate_with_progress` computes both components' affine
and digit projections from the same source residues. Multiplying a component's
residues by p first gives R_i modulo Q; using a canonical rather than centered
R_i only adds Q, hence adds p to its nearest scaled projection. Centering
modulo p removes that difference and yields the same d_i. The affine code
needs only A_i modulo p, not the unreduced nearest integer used in the proof.
Its high and low banks
use the same source key and slot order. The actual phase layout is
`[v,-v]` in both power-five rows (`repeated_antiperiodic`), rather than zero
padding. The other slots therefore carry the same phase coefficients or their
negatives. The symmetric support [-B,B] and norm bounds cover all of them,
which is the all-slots premise needed by A2.

**Second pass.** Signs follow from epsilon=Q*d-p*R, not its negative.
The norm here is H for the already-switched sparse source. Earlier modulus
drops still use the dense work secret's norm, and switch errors still charge
the full polynomial dimension. Substituting H for either would undercount.

## A4. Fused restoration and canonical plaintext equality

A1–A3 show that the carry circuit returns K mod p and the affine circuit
returns A mod p. Addition returns m=A+K mod p coefficient by coefficient.
For the native K in [-48,48], put Y=K+48 in [0,96]. If authentic same-source
views g=Y mod36 and a=Y mod37 are available, write Y=g+36*q with q=floor(Y/36).
Since q is in [0,2] and 36=-1 mod37,

    (g-a) mod37 = q,       g+36*q-48 = K.

Replacing that entire round trip by the already encrypted K preserves the
result. It adds no ciphertext products and requires no encrypted remainder
outputs. Equality modulo p implies equality of canonical representatives in
[0,p); consequently the semantic S8 projections of those representatives
agree too. It does not supply independently encrypted S8 projections.

**Second pass.** A zero congruence defect derived from g and a does not prove
same-source provenance. Nor may views of rho+49 be substituted for views of
K+48. Root authority is a separate API argument, covered in P6.
