# Native three-view chart and constraints on its nonlinear readout

The [11-adic ring-section continuation](FROBENIUS_CHART_SECTION.md) now
executes a native nonlinear section and Witt quotient on the actual chart
residue, verifying every coefficient and its Z99 compatibility identity.
It uses a proved auxiliary121->11 encoding change after a public outer-prime
drop. The section is not the coefficientwise canonical integer K; the
plaintext65537 return and full public bootstrap remain open.

The public producer now constructs an encrypted 99/121/143 chart for all8192
source coefficients from one source precharge. The native check preserves
every coefficient and odd zero, and reconstructs all three original view
ciphertexts bit for bit. The new winding coordinate has public bound485;
its producer error bound is47bits in the recorded probe.

The gate domain is also substantially better specified. Exact native input
witnesses rule out a shallow fixed two-view polynomial on the complete
norm-admitted source envelope. A public three-view witness family requires
at least degree33 for a fixed polynomial. The current generic dense-outer
ledger cannot admit that minimum depth at Q241. The nonlinear readout,
return integration and native repeated bootstrap remain open.

## The third tray remains on the 11 anchor

The contexts retain sourceN8192/Q60, outerN16384/Q241, workN8192/Q119 and
p65537. The composites are99=9*11,121=11*11 and143=13*11. A tighter source
phase capQ60/64 gives clock widths10627,12761 and14895, all below16384.
The producer refuses the old Q60/16 allowance for tray143.

For the weighted views Z, the integer chart is

```text
U = -Z99 - 3*Z121 + 5*Z143
D = 9*Z99 - 11*Z121
E = 11*Z121 - 13*Z143

Z99  = 143*U + 16*D + 55*E
Z121 = 117*U + 13*D + 45*E
Z143 =  99*U + 11*D + 38*E.
```

The matrix has determinant1 and an integer inverse. Both periodic residuals
cancel the ideal K and g/Q terms. U retains ideal scale
`32768*(K+g/Q)/14157`. The component period14157 increases U by1 while
leaving D/E unchanged. Thus the periodic state retains its integer winding.
The public cell audit checks757 component triples; the per-component ranges
are U[-5,5], D[-9,9], E[-11,11]. At norm96 this gives the conservative
whole-sum bounds485,873 and1067. The matrix preserves coordinates modulo2,
11 and the dependent composites without dividing by a nonunit.

The `PublicChart` evaluator accepts public contexts, public input components,
a source precharge and its bound, the public source norm and phase cap, and
the integer chart specification. It accepts no source support, client key,
measured phase, clear chart value or hidden sheet. It validates the integer
inverse and each view's window before polynomial work. It combines public
weights before multiplying the common precharge, retaining correlated-error
cancellation. Each output has its own error and integer-range certificate.

The recorded native result is:

| Coordinate | Observed magnitude / public bound | Observed / certified V bits |
| --- | ---: | ---: |
| U | 68 /485 | 38 /47 |
| D | 156 /873 | 39 /49 |
| E | 182 /1067 | 40 /49 |

The complete public producer takes0.876308seconds in that probe, including
public residue preprocessing and three signed polynomial products. It ran
alongside the native witness test; this single timing is not a latency or
peak-memory admission. Setup, client observations, nonlinear readout and
return are separate. Every reconstructed view agrees in every ciphertext
limb, not just after decryption.

## The tighter cap changes the input contract

The dense working-key transform's old Q119/20 example exceeds Q60/64 and is
correctly refused. A Q119/128 example passes. The maximum working V under
the existing deterministic transform envelope is
`5449073146000603104005897005031422`.

The existing reference return ledger still produces a46-bit working bound,
an88-bit following dense polynomial square and a44-bit next prepared-source
bound, below the54-bit source cap. This proves compatibility of the tighter
entry envelope with that reference ledger. It does not execute a nonlinear
three-view gate or a new native refresh. A future service route must enforce
this earlier refresh trigger and authenticate the actual history.

## Valid native inputs constrain a fixed polynomial LUT

For a line parameter t, the client constructs centered source residuals
such that `Z99=Z121=t`, hence `U_pair=t,D_pair=-2t`. The entire native
ciphertext has phase zero outside one coefficient, and that coefficient
has a known bounded g. All phase coefficients and RNS lanes are checked.
The residue preprocessor then verifies the actual hidden lift K.

At capQ60/16, there are125 valid K0 points t=-62..62 and75 points for each
of K1 and K-1 at t=262..336 and t=-336..-262. At capQ60/64, the corresponding
counts are97 and46+46. The native test executes all464 source ciphertexts
across these two domains. They are explicitly ideal CLIENT test fixtures,
not production encryption or an encrypted lift oracle.

Exact interpolation over F65537 gives minimum restriction degrees273 and
187, respectively. A fixed bivariate polynomial F(U,D) restricts to a
univariate polynomial of no greater total degree on this line, so it needs
at least those degrees to cover these inputs. Binary multiplication depth
is therefore at least9 or8 for that gate class. The leading Newton
coefficients are nonzero and all sample evaluations are verified exactly.

These constraints cover an input-independent coefficientwise polynomial
correct on the full bounded source envelope. Membership of the fixtures in
the particular dense-work/source-switch producer image is not proved.
Input-adaptive coefficients, restricted authenticated histories, auxiliary
encrypted inputs and other circuit representations remain outside this
constraint. This is not an impossibility result for CRAM.

## What the third view changes, and what remains

The zero-phase block `(a,a,-2a)`, with `a=floor(70*Q60/32768)`, produces
view increments `(1,1,-1)`. A valid K1 construction gives `(288,288,192)`.
Thus the two-view witness line does not remain a line containing that
nonzero-lift point in the three-view domain. This is a concrete reason to
retain the third encrypted input. It is not a proof of a cheap readout.

There is also a three-view lower constraint. Each view has an isolated
rounding boundary. A three-term zero-sum residual block can create each of
the view increments `(-1,0,0)`, `(0,-1,0)` and `(0,0,-1)`. At most32 such
blocks use96 source terms. This constructs all6545 points of the negative
integer simplex of total degree32 with K0 and g0. The public audit verifies
every residual construction. It does not execute6545 native ciphertexts.

The graded falling-factorial Newton evaluation matrix on that simplex is
triangular, with nonzero diagonal entries `product(alpha_i!) mod65537`.
It is unisolvent for total degree32. A polynomial of that degree vanishing
on the simplex is identically zero, so it cannot return K1 at the valid
nonzero point. A fixed trivariate polynomial on the complete norm envelope
therefore needs at least degree33 and binary multiplication depth6.

Even an optimistic47-bit chart input bound reaches the existing dense-outer
ledger's refusal at the fifth generic multiplication level under Q241.
This omits coefficient/slot transform costs. It identifies a refusal of the
current generic polynomial plan; it is not a lower bound on actual errors
of every possible circuit. A degree33 gate has not been constructed.

The determinant1 coordinate Jacobian preserves information. The nonlinear
step needed for contraction has a different job: it must remove dependence
on the admitted source residual while producing the consuming encoding.
The next investigation is the11-adic Jacobian/Frobenius section on an
explicit coherent auxiliary view. Its result must be distinguished from a
canonical integer lift; no cross-encoding or return may be assumed.

The completed24 configured source attack estimates remain separate from
missing attack-model and joint-key coverage. Authenticated key/domain,
epoch/history and intact S8/Root211 capability integration remain required.
The service refresh gate stays closed. No external backend, additional Safe
Basis root, production modulus change or lint is introduced.

Evidence: `artifacts/execution/2026-10-23/triple-lift-domain/`. The focused
Rust harness passes35 tests and the six Python suites pass40. The direct
harness links the unchanged Cargo-built library with debug assertions and
overflow checks; no package-wide or hosted Rust CI success is claimed.
