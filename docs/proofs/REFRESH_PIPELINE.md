# Refresh pipeline: composition and implementation obligations

Scope and review: [proof coverage](README.md). A1–A4 refer to the
[arithmetic note](REFRESH_ARITHMETIC.md). These are mathematical derivations
and source-correspondence arguments, not a whole-program Rust verification.

## P0. Coherent phase-bank error before the digit circuit

For a key-holder-precharged bank ciphertext, the phase is
`floor(Q/t)*mu + e` modulo Q, with centered plaintext coefficients
|mu_j|<=floor(t/2) and bounded sampler error |e_j|<=eta. Here the preflight
requires Q=1 mod p², so Q=1 mod t for both t=p² and t=p. Consequently

    floor(Q/t)*mu = (Q/t)*mu - mu/t,

and the ideal-grid error is at most eta+1/2 coefficient-wise. This is a
property of this symmetric setup-time precharge; it is not the larger fresh
public-key-encryption envelope. The public evaluator receives no setup secret.

The phase bank computes n source weights, each of magnitude at most
W=floor(p/2), using the common antiperiodic secret layout from A3. Weighting
and summing the bank errors costs at most (eta+1/2)*n*W. Rotations preserve
coefficient infinity norms. With baby count B, the Horner accumulation uses
n/B-1 giant rotations; each adds a switch deposit S from P3b, and those
switch errors are not subsequently multiplied by the public weights.
The final encoded public-vector addition contributes at most 1/2 ideal-grid
error. Thus

    E_phase <= (eta+1/2)*n*W + S*(n/B-1) + 1/2
             <= (eta+1)*n*W + S*(n/B-1) + 1.

Repeated use of the same bank ciphertext can correlate errors; this worst-case
triangle-inequality argument assumes no independence between them.

The right side is exactly the conservative integer expression checked by
`DirectSlotPhaseKey::phase_error_bound`. It applies separately to the high,
low and affine banks. Coherent plaintext relations follow from using the same
source secret, public weights, slot ordering and source history, not from the
error bounds being numerically equal. High and low bank randomness may differ.

**Second pass.** Dropping Q=1 mod t would replace the 1/2 encoding discrepancy
by up to `(Q mod t)/2`; using the same expression then would be unjustified.
Applying public weights after the Horner switches would also require a larger
switch term. Neither premise can be inferred from parameter names alone.

## P1. Slot return is a linear map with an explicit norm bound

**Statement.** Over F_p with the split-ring hypotheses of A2, let E be the
invertible coefficient-to-slot matrix. Let n be the source degree, N the
outer degree, D=N/n, and J the map that takes the first n positive-row input
slots and puts them at polynomial coefficient positions 0,D,...,(n-1)D,
zeroing every other coefficient. The required output slots are L*v, where
L=E*J. Decoding the result gives exactly J*v. This is not E-inverse applied to
all input slots: the selected slot values become polynomial coefficients.

**Proof.** By definition output slots are E*(J*v); invertibility gives
E-inverse*(E*(J*v))=J*v. Any matrix on a cyclic slot row can be written as a
sum of a diagonal matrix times a cyclic rotation: for row i and column j,
choose the unique rotation that moves column j to row i, and assign that
matrix entry to that rotation's i-th diagonal. With two slot rows, first split
into same-row and cross-row blocks; conjugation swaps the rows. This supplies
all four blocks and hence the complete L. Grouping rotations into baby/giant
steps only reassociates the same linear sum. QED.

**Error bound.** For coefficient error e and plaintext diagonal polynomial h,

    ||h*e|| <= ||h||_1 * ||e|| <= N*floor(p/2)*||e||.

The last bound uses N centered coefficients, each of magnitude at most
floor(p/2). Summing at most N diagonals gives F=N²*floor(p/2).
Galois automorphisms permute coefficients with signs, so preserve infinity
norm before their key-switch error. Let S bound each key switch, B the number
of cached babies and G the number of giant groups. A baby chain has at most
B-1 switches plus one conjugation, hence at most B*S error. Diagonal work
amplifies that error by at most F. The Horner giant accumulation contributes
at most (G-1)*S additional error after diagonal multiplication. Therefore

    E_out <= F*E_in + S*(F*B + G-1).

This is the certificate in `public_refresh_slots::PublicSlotReturn::new`.
It is conservative: cancellation may reduce actual error but is not needed.

**Second pass.** Applying a scalar-slot error bound without N would miss the
coefficient convolution norm. Checking one slot does not prove the matrix
identity. The runtime's explicit diagonals, twists, slot ordering and optimized
Montgomery indices must implement L; the proof of the intended matrix alone
does not verify those loops. Existing coefficient-oracle tests are the
implementation evidence, with finite scope.

## P2. Why native dense-key return permits coefficient projection

**Statement.** Let N=D*n and define the ring embedding

    iota: Z[X]/(X^n+1) -> Z[Y]/(Y^N+1),   X -> Y^D.

Define Pi(sum f_j*Y^j)=sum f_(D*j)*X^j. For every outer polynomial f and
work polynomial s,

    Pi(f*iota(s)) = Pi(f)*s,     Pi(iota(s))=s.

Consequently, once key switching has changed the secret to iota(s), projecting
both ciphertext components projects their phase correctly under the work key s.

**Proof.** The embedding respects X^n=-1 because Y^(D*n)=-1. Every outer
polynomial has a unique decomposition

    f(Y) = sum over r=0..D-1 of Y^r * f_r(Y^D),  deg(f_r)<n.

Multiplication by iota(s) stays in the same degree class r modulo D. Reducing
Y^N=-1 preserves that class, since N is divisible by D. Pi selects class zero,
so only f_0*s contributes; its reductions X^n=-1 have exactly the same signs.
This proves both identities. By linearity,

    Pi(c0+c1*iota(s)) = Pi(c0)+Pi(c1)*s.

Selecting coefficients cannot increase the error infinity norm. QED.

**Source correspondence.** `PublicRefreshReturn::generate_with_rng` builds the
return key from the outer secret to `embed(work_secret)`. `evaluate` performs
that key switch first, then projects every D-th coefficient of c0 and c1.
The returned message is in the embedded subring by P1.

**Second pass / counterexample.** Projection is not a ring homomorphism for an
arbitrary outer secret. For D=2, f=Y and secret=Y, Pi(f)=0 but Pi(f*secret)=X.
So projecting before changing to the embedded work secret is invalid. The
complementary-block return theorem for the separate phase-clock construction
must not be substituted for this different native return mechanism.

## P3. Modulus drops and key-switch deposits, with units

Use V for a **scaled source/work phase error**:

    v = t*(phase-Q*k)-Q*m,       ||v|| <= V.

Use E for an **outer ideal-grid error**:

    phase = (Q/t)*m + E  modulo Q.

At the same modulus and message lift V=t*||E||; the source and return plans
must convert those units explicitly.

### P3a. Nearest modulus drop

Let Q=q*Q' for odd q. Independently round both ciphertext components divided
by q. Write the new phase, modulo Q', as old_phase/q + delta0+delta1*s.
Each coefficient rounding error has magnitude at most (q-1)/(2q). A ternary
secret of coefficient l1 norm at most L gives

    ||delta0+delta1*s|| <= (L+1)*(q-1)/(2q) <= (L+1)/2.

Using the same integer message lift gives new scaled error at most

    V' <= ceil(V/q) + ceil(t*(L+1)/2).

The first drop still uses the dense work secret, so L<=n_work, not sparse H.
The native return drops still use the dense boot secret, so L<=N_boot.
Only after source key switching is the sparse norm applicable to A3.
The rounded modular representatives may introduce phase wraps by Q'; these
are absorbed by the new k and do not change the error equation. QED.

### P3b. Gadget key switching

Assume the gadget decomposition exactly reconstructs the target component
modulo Q. Each of d gadget ciphertexts encrypts its prescribed key function
with error bounded by eta. If each decomposition polynomial has coefficients
bounded by b-1 and degree less than N, one product with key error is bounded
by N*(b-1)*eta. Summing all d terms gives ordinary phase error

    S <= N*eta*(b-1)*d,

and scaled error deposit t*S. This uses the full decomposition ring dimension,
regardless of the target secret's sparse norm. It is a deterministic argument
conditional on bounded sampled errors and exact gadget reconstruction. QED.

### P3c. Complete return recurrence

Let E0 be the certified outer error after P1. Begin with V0=t*E0. For every
removed boot prime q_i, in execution order, update

    V_(i+1) = ceil(V_i/q_i) + ceil(t*(N_boot+1)/2).

Then add t*S for the return key switch. P2's projection adds no error.
`ReturnNoisePlan::output_bound` implements these ceilings with checked wide
arithmetic and rejects a result above floor(Q_work/2). Since Q_work is odd,
V<=floor(Q_work/2) implies 2V<Q_work, the strict nearest-decoding condition.

For a canonical coefficient m in [0,t), its scaled phase lies within strictly
less than half Q_work of Q_work*m; nearest decoding recovers m modulo t.
The bound already includes floor-Delta discrepancy and all prior arithmetic
errors; omitting those would invalidate the premise.

**Second pass.** The native **562-bit** quantity is the ideal-grid error after
slot return in the *outer* ring, below its **633-bit** half-Delta threshold.
It is not the final scaled work error. Current key-free preflight gives the
final scaled work bound **122782933364666 (47 bits)** after drops and key
switch, compared against the work modulus **348959453350711275087786864768188417**
(119 bits). Bit lengths are summaries; actual comparisons use full integers.
This is a computed plan, not a measured ciphertext error or encrypted run.

### P3d. Full-polynomial BFV multiplication envelope

Let the ring degree N be even and the secret ternary. For a ciphertext choose
centered c0,c1, so each coefficient has magnitude <Q/2. Write its exact phase as

    phi = (Q/t)*m + Q*k + e = (Q/t)*M + e,   M=m+t*k,

where m is centered modulo odd t and ||e||<Q/(2t). Since
||phi|| < (N+1)*Q/2, coefficient-wise

    |k_j| < (N+1)/2 + (t-1)/(2*t) + 1/(2*t) = (N+2)/2.

The safe integer bound |k_j|<=N/2+1 therefore holds (possibly loose at the
endpoint). It follows that

    ||M||_1 <= F = N*(t-1)/2 + N*t*(N/2+1).

For two ciphertexts a,b form the integer tensors
T0=a0*b0, T1=a0*b1+a1*b0, T2=a1*b1. Exact coefficient rounding produces
U_i=round(t*T_i/Q), with each rounding error delta_i bounded by 1/2.
Before key switching, the phase is

    U0+U1*s+U2*s²
      = (t/Q)*phi_a*phi_b + delta0+delta1*s+delta2*s²
      = (Q/t)*M_a*M_b + M_a*e_b + M_b*e_a
        + (t/Q)*e_a*e_b + delta0+delta1*s+delta2*s².

Here M_a*M_b equals m_a*m_b modulo t, so its extra t-multiple is just a
Q-multiple in the phase. Negacyclic coefficient bounds give

    E_product <= F*(E_a+E_b) + N*t*E_a*E_b/Q
                 + ceil((1+N+N²)/2) + S.

The last term S is the unscaled relinearization deposit from P3b. This is the
mathematical envelope in `bounded_digit_circuit::Noise::multiply`; its
power-of-two quadratic substitute is checked below. In scaled V=t*E units,
the quadratic term becomes N*Va*Vb/Q. For admitted Va,Vb<Q/2 this is at most
(N/2)*min(Va,Vb). This gives the `PolynomialNoise::multiply` expression,
including its t-scaled rounding and switching terms. QED.

**Why the tensor really needs an extended basis.** Centered input bounds give
|T0_j|,|T2_j| <= N*Q²/4, but the two-term T1 needs N*Q²/2. The production
`ExactMulPlan` uses N/2 for every tensor component. For any tensor coefficient
X, let Z=t*X+floor(Q/2) and w=Z modQ in [0,Q). Then

    Y=(Z-w)/Q=floor((t*X+floor(Q/2))/Q).

Because Q is odd and t*X is an integer, this is nearest rounding, including
negative X. In a coprime auxiliary basis, Q has an inverse, giving Y's
residues exactly. With s_mult=(N/2)*t+1 and S0=s_mult*Q, |Y|<=S0.
If the auxiliary product A>2*S0, Y+S0 has a unique representative in [0,A)
and agrees with Y modulo every main prime because S0 is a multiple of Q.
Thus exact rank/base-extension operations yield the intended rounded main
residues. Centered input lifting must happen *before* multiplication: lifting
a tensor already reduced modulo Q would in general round a different integer.

This supplies the mathematical justification for the planner's capacity rule.
It still assumes the code's NTT, rank conversion and exact gadget decomposition
implement their specified ring operations. Those low-level correspondence
obligations cannot be discharged by merely quoting a larger noise margin.

## P4. Composing certificates and the exact cycle premise

Suppose a producer-issued input satisfies the source scaled-error invariant.
Suppose additionally that the executed source drops, gadget operations, phase
banks, G/H circuit and slot map implement their stated arithmetic semantics
and computed error envelopes. Source preparation and A3 give the coherent
phase/radius premises. A1 and A2 recover K; A4 repairs the original plaintext.
P1 puts that plaintext in the embedded work ring. P3's return certificate and
P2 give a decodable work ciphertext encrypting the same canonical plaintext.
This proves conditional correctness of the stage composition. It does not
remove any premise about the implementation of an individual stage.

For error composition, additions use the triangle inequality, plaintext
multiplication uses coefficient l1 norms, and automorphisms preserve infinity
norm apart from switch deposits. Each topologically ordered DAG node therefore
inherits its bound by induction from earlier nodes. The multiplication-node
bound must cover the actual exact BFV rescale/relinearization algorithm;
it is not derived merely from the existence of a polynomial DAG.
P3d derives the mathematical envelope used by
`bounded_digit_circuit::Noise::multiply`. No new complete Rust refinement of
its low-level arithmetic kernels is asserted here.

A useful independent check on its power-of-two quadratic overestimate is:
for nonzero integer a,b,c with bit lengths A,B,C and modulus bit length L,

    a*b*c/Q < 2^(A+B+C-(L-1)).

When the exponent is nonnegative this integer power bounds the ceiling;
when negative the positive fraction is less than one, so ceiling <=1.
This explains the saturating exponent rule. Zero factors need the separate
zero case used by the code; a shift of 1024 or more must be refused.

For repetition, define an admitted set of histories whose source residual
radius is at most B. If the refresh envelope returns V_star for *every* such
history and the full-polynomial square/source-conversion envelope maps V_star
back to a radius at most B, induction admits every finite repetition of that
specific refresh/square pattern. The native executable certificate checks
next radius 48<=49. The inference remains conditional on the stage envelopes
and semantic invariants holding at every step. Five measured native cycles
are finite evidence for one identified snapshot, not proof of arbitrary
circuits or a latest-head native execution. The separate phase-clock
`Fixture.arbitrary_cycles` theorem has its own transition premises.

## P5. Selected finite-width obligations

`PolynomialNoise::new` restricts source/work n<=2^16, odd t<2^32,
eta<2^32 and sum of prime bit lengths<=256. Thus Q<2^256 and admitted V<Q/2
is below 2^255. The source plan also checks positive power-of-two geometry,
so n>=2 is even. Its multiplication factor is

    F = n*(t-1)/2 + n*t*(n/2+1) < 2^65.

For the last inequality, the first term is below 2^47 and the second below
2^63+2^48, whose sum is below 2^64 (and therefore below the stated cap).
Hence (Va+Vb)*F < 2^321. The quadratic substitute
(n/2)*min(Va,Vb) is below 2^270. The sum is below 2^322.
There are at most 8 lanes and at most 64/10 rounded up =7 gadget digits per
lane, so total digits<=56. With base 2^10, the switch deposit
`t*n*eta*(2^10-1)*digits` is below 2^96. Rounding and fresh-error deposits
are also below 2^128. Every intermediate in these displayed U512 expressions
therefore fits 512 bits before admission.

Source gadget base bits lie in [1,16]. Its direct u128 product is bounded by
`t*n*eta*(2^16-1)*digits`, with digits<=8*64=512; it is below 2^105.
The residual numerator `2*t*V+(H+1)*(Q-1)` is below 2^289, since H<=2^16,
and its binary-search comparison `2*mid*Q` fits too. Array payload sizes use
checked usize multiplication. Outer U1024 operations use checked products,
sums and explicit shift guards in the relevant certificate paths.

These arguments concern the named planner expressions. They do not prove
all arithmetic kernels, indexing, casting or unsafe code in the workspace
correct. A current program-level overflow proof remains a separate obligation.

**Second pass.** The operand-admission premise is essential: this bound does
not authorize multiplying arbitrary attacker-supplied U512 values by F.
The sealed source object and the forecast's explicit admission check constrain
the relevant callers. No theorem about the 256-bit work Q is transplanted to
the native 650-bit outer Q.

## P6. Root preservation is a safe-API induction, not attestation

Assume safe external Rust callers and the trusted in-crate implementations of
the sealed constructors. `SourceWorkCiphertext` fields are private; cloning
preserves family/root authority. Encrypt, add and multiply mint a new value
occurrence root from producer lineage. `prepare` clones the existing root and
binds the exact source history. `ReturnedWorkProof` is constructed only by the
crate-private return evaluator and carries that same root capability.
`accept_refresh` checks local family pointer identity, family ID, source
lineage and root pointer identity, then validates the returned bound and
ciphertext shape. Its newly returned object replaces the temporary new root
with the source root before exposure. Thus every accepted refresh preserves
the identical root allocation, while arithmetic produces a new root. QED
under the stated constructor trust boundary, by induction on safe API calls.

The arithmetic assertion that this root still denotes the same canonical
plaintext depends on P4. Pointer equality alone is not an arithmetic proof.
Private fields are not protection against arbitrary changes elsewhere in the
same crate, unsafe memory corruption, or an untrusted remote process. Hashes
are not proofs of remote origin or plaintext equality. A lineage digest is a
public binding identifier, not a stored secret-dependent quotient K. These
limits are compatible with the existing conditional public-evaluation
simulation argument and do not establish its joint-key security premise.
