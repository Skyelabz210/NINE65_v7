# Commissioned recumbent implementation — 2026-10-27

The NS source is a pattern reference; constructing the FHE implementation is
the engineering task. This continuation repairs the supplied arithmetic and
builds executable coefficient operations instead of requesting a nonexistent
finished FHE artifact.

The user's clarified policy permits reconstruction. It prohibits synthetic
emissions in residue compute, including Garner and mixed-radix conversions.
The previous blanket rejection of all reconstruction identifiers was too broad.
The three source scanners now enforce the clarified default; their historical
reconstruction inventory remains available with `--legacy-reconstruction-audit`.
Capacity, missing-target, floating-point and product-sentinel checks retain their
existing scope. Source scanning is structural evidence, not a mathematical
independence or reversibility proof.

## Implemented arithmetic

`crates/qmnf-crtbigint` imports the supplied CRT substrate and repairs mixed-sign
addition/subtraction, cancellation, canonical zero, signed lane projection,
`i64::MIN`, exact wide reconstruction and capacity refusal. Its private
sign/magnitude fields and checked constructors prevent malformed states.
Reconstruction uses eight limbs and narrow conversions refuse overflow.
The crate remains boundary/reference arithmetic; its magnitude reconstruction
uses the legacy conversion algorithm and is not wired into residue compute.

The original 23 tests pass. Four new signed tests failed before the repair; a
separate wide reconstruction test also reproduced the wrapping defect. All
23 original tests plus 12 added regressions pass in debug and release. The
additional tests include 10,000 signed machine-width pairs, 4,225 small signed
pairs and 24 Python-generated wide vectors. An independent external probe
checked another 12,827 cases against Python integers.

`arithmetic::recumbent` implements immutable `RecumbentCoefficient`,
`PrimaryLane`, `OverflowLane`, basis identity and signed interval metadata.
Checked ingress establishes the lift; addition, subtraction and multiplication
propagate conservative bounds. Intervals must have width less than the full
basis product. Failed bounds or counter increments return typed errors.
The counter is maximum division-event depth along the DAG, not winding
magnitude or a cumulative count across all branches.

`drop_main` implements exact, floor and nearest division by an observed modulus
lane. It reads construction-time inverse tables and updates every surviving
main and anchor residue to the authentic quotient. The remainder is returned.
No scalar numerator is assembled in this path. A debug-only scalar oracle is
captured at already-clear ingress, propagated independently, and checks both
main and anchor provenance. It is compiled out in release.

`divide_with_rank_projection` implements an additional exact bounded operation
for any nonzero `u64` divisor, including shared factors, while retaining every
quotient lane. It derives a global CRT rank with exact integer fractional
arithmetic and projects directly modulo `d*m_i`. It uses neither Garner nor
mixed-radix conversion. Its full-width fractional scratch contains equivalent
numerator information; under the clarified policy this is not automatically a
rejection. Its distribution and reversible output representation still require
their own acceptance evidence.

The combined new arithmetic suite passes 24 tests in debug and 23 in release.
One debug-only corruption test is compiled out in release. Separate 10,000-case
oracles cover observed-lane division, general quotient projection, and the
public wrapper. Independent review checked 5,505 further cases in both profiles.
Current metadata endpoints fit `i128`, and general divisors fit `u64`. The
production BFV Delta is wider, and no raw DualRNS import is admitted by merely
asserting an interval.

Existing CRAM D1/D2 and Agreement-lock reads now use direct weighted CRT rather
than Garner/MRC. Subset lifts remain nonnegative until the complete lift is
centered; the full-S8 midpoint keeps its existing positive-tie convention.
Reconstruction counters report those reads separately from Garner calls.
The FPD direct sum now uses overflow-safe modular products and addition, since
a valid 123-bit fusion product could previously produce a 130-bit intermediate.
Full-width D1/router divisor checks and D2's `i128::MIN` remainder handling also
preserve typed results. Failing-before regressions and independent D1/D2/FPD
oracles cover these changes. The complete `exact_transcendentals` suite now
passes 685 tests in each profile, including ten new CRAM regressions. Independent
review checks 5,226 additional public-API cases in each profile and the corrected
wide-divisor router witness. The no_std library check also passes.

`DualRNSContext` inverse metadata now uses the true main prime-factor product,
including when its legacy scalar snapshot is zero. Scalar K extraction consumes
`main_inv_anchor_checked`; the old scalar field remains an explicitly unavailable
snapshot when the checked field is `None`. Unsigned Euclidean inversion and
overflow-safe modular multiplication cover the complete `u128` range. Anchor,
prefix and combined capacity diagnostics use exact product bit lengths, and
setup bounds refuse overflow instead of saturating. Exact accounting can tighten
existing FHE preflight gates. Nine focused metadata regressions pass in both
profiles, alongside the 47 existing RNS unit tests.

## Driving-digit IID, carry reversibility and arrow diagnostics

The user clarified IID further through the Holte carry process: its driving
digits are independent and uniform, while statistical reversibility is the
Eulerian-weighted detailed-balance property of the induced carry chain. The
carry states can be dependent. Requiring every quotient or anchor coordinate
to remain jointly uniform is a stronger, different property, and is not used
as the user's carry-process acceptance criterion.

The existing `cram_carry` module already implements the transition counts.
The additional Holte integration regressions compare that implementation with
independent bounded-composition formulas and exhaustive small digit tuples.
The [general-arity proof](HOLTE_REVERSIBILITY.md) records the exact corner
identity and an induction establishing the negative gap for every arity at
least four and every base at least two. This is distinct from either a logical
operation's inverse or a production FHE carry circuit.

The added Rust integration target passes eight tests in both profiles, including
12,852 transition-entry checks, 882 low-arity balance equations and all five
supplied factored/Newton rows. The independent exact Python checker covers 144
DP cases, 1,914 big-integer cases and 27 Newton-coefficient rows. The written
induction, rather than that finite grid, establishes the general claim.

`check_centered_chart_order.py` independently verifies all 62 splits of the
six-prime product 30,030, with 1,861,860 state recoveries and 1,861,798 adjacent
ordering checks. It checks the complete sheet occupancies and exact pair-tie
probabilities. One supplied row is corrected: at `Q=143,R=210`, occupancies
`72, 209*143, 71` give `4284066/901800900 = 714011/150300150`. Its dual-anchor
test explicitly assumes the local chart and anchor residue already exist;
this is not an encrypted construction of those inputs.

The supplied arrow suite's G3/G4 checks did not call the operation, and its
lineage check compared supplied data with itself. The repaired
`scripts/a2_arrow_suite.py` audits actual forward/inverse outputs, actual lane
orders, the complete joint distribution, independent semantic expectations,
structural emission observations and separately referenced lineage. Missing
evidence returns `UNVERIFIED`. Its 16 regression tests include false identities,
lossy quotients, schedule dependence, pairwise-independent but jointly-dependent
outputs, and mixed-radix conversion as a structural negative control.

`recumbent_arrow_trace` exercises the actual Rust coefficient API on all 210
inputs in the basis `{2,3,5,7}` and six main-lane orders. The Python driver
replaces the trace's expected field with an independent integer oracle and
compares the restored input with the original. Source-policy evidence is a
separate lexical scan. Lineage covers only this known test fixture; it does
not establish cryptographic custody for ciphertexts.

| Actual operation and declared output | Finite result |
| --- | --- |
| Drop lane 2; retain quotient lanes `{3,5,7}` and remainder modulo 2 | G1–G6 pass on the complete 210-state fixture. |
| General rank division by 2; retain quotient lanes `{2,3,5,7}` plus remainder | Reversible and arithmetically correct; G3 fails joint independence/uniformity. The other finite gates pass. |

The latter diagnostic exposes a real output-domain distinction: the quotient is
restricted to 105 values but is still represented in a 210-state full basis.
It is not jointly uniform on all those output coordinates. This does not
reject the algorithm under the user's distinct driving-digit IID criterion.

For the first operation, the general algebra is `X=d*q+r` with
`0<=q<B`, `0<=r<d` and source capacity `d*B`. The pair `(q,r)` is a bijection
onto that product. Under a uniform complete source domain, its surviving CRT
quotient coordinates and remainder are jointly uniform. Quotient-only output
would discard information.

Reversibility and uniformity alone do not prove absence of synthetic emissions:
mixed-radix digits can also form a bijection of a uniform product. Structural
emission policy therefore remains a separate gate. Finite passes do not assert
universal IID for arbitrary ciphertext distributions.

Reproduce the actual-operation audit:

```sh
mkdir -p /tmp/recumbent-arrow
cargo run -p nine65 --release --example recumbent_arrow_trace -- drop > /tmp/recumbent-arrow/drop-trace.json
cargo run -p nine65 --release --example recumbent_arrow_trace -- rank > /tmp/recumbent-arrow/rank-trace.json
python3 scripts/check_recumbent_arrow.py /tmp/recumbent-arrow
python3 scripts/test_a2_arrow_suite.py
python3 scripts/test_emission_policy_alignment.py
cargo test -p exact_transcendentals --test holte_reversibility
cargo test -p nine65 --test dual_rns_context_metadata_regression
python3 scripts/check_holte_reversibility.py
python3 scripts/check_centered_chart_order.py --output /tmp/chart-order.json
```

The Exactness Focused workflow permanently runs the new arithmetic, metadata,
Holte and bootstrap witnesses in debug and release. Independent Python jobs run
the source-policy, arrow, Holte and centered-chart checks. The actual Rust arrow
trace and reports are uploaded from the release job. These jobs do not depend
on the broader architecture job passing. The arrow wrapper and architecture
scanner share their Garner/MRC patterns, including suffixed spellings.

## Bootstrap regression and remaining integration

Two permanent zero-noise regressions preserve the component-rounding carry
failure: `Q=65,t=3,c0=10,c1=32,s=1`, and the actual shipped secure-128 modulus.
The latter invokes the production component switch and decryptor: the complete
phase decodes to 2, component rounding gives 1, and the required carry is 1.
Both pass in debug and release as negative witnesses. They do not implement
the encrypted carry correction.

The proposed encrypted `max(a,b)` needs an encrypted selector on the certified
difference `a-b`, followed by `b + selector*(a-b)`. The existing clear scalar
ReLU helpers do not supply that selector. The public Clockwork entry point
still invokes `public_phase1_soundness_gate`, which refuses refresh because
the secret-dependent convolution carry is not propagated. Centered-chart
ordering and the Holte proof do not implement either missing ciphertext
operation or establish the claimed bootstrap depth/noise budget.

Workspace clippy with warnings denied and formatting pass. The full affected
nine65 release library run reports **1,013 passed, 4 failed, 138 ignored**.
The four failure names match the original library baseline: the triple-precharge
preflight and three symmetric-depth/zero-noise controls. The current live
depth-four path still fails. No 100-step acceptance claim is made.

The architecture gate now passes across 14 configured production files,
including the RNS kernels used by live rescale. This scoped lexical result is
not a universal implementation or reversibility proof. The capacity contract
remains red for two legacy `q_product` sentinel patterns in `rns_fhe.rs`.
The broader emission/product source scan and the checked-product-only gate pass.
Seventeen scanner regressions also pass, including rejection of real calls and
acceptance of permitted reconstruction or a diagnostic string naming Garner.
The production rescale/bootstrap path and parameter families are unchanged.

Next implementation obligations are wide interval/divisor support, trusted
DualRNS lift ingestion, carry-model checks on the integrated operation, the
encrypted nonlinear carry and key-domain return, and a compatible Safe Basis
construction.
These are development tasks, not requests for another upload. Holte detailed
balance is not inferred from quotient-coordinate marginals. Public refresh
remains disabled until its complete end-to-end acceptance gates pass.
