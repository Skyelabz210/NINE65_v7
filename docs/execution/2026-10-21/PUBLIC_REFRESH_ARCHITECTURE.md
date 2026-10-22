# Public refresh: whole-system diagnosis and solution requirements

Analysis baseline: `main@9800fd1839e85ad92875b3c88812081a5fbb8998`.
Scope: native public BFV refresh, including the preserved Safe Basis / sister
tray substrate. This report supersedes treating the next carry experiment as
the whole solution. It does not supersede the owner's architecture, accept a
task packet, or enable refresh.

## Finding and decision

**A complete, admitted native public refresh has not been obtained.** The
failure is not transport, linting, or an inaccurate CRT quotient. It is the
missing, sufficiently accurate **encrypted nonlinear transformation**, together
with a parameter/key/history contract that supports that transformation and
the next refresh. Exact residue arithmetic is necessary but not sufficient.

There are two distinct routes. The direct carry route computes the missing
decryption carry and must supply it in the consuming circuit's encoding.
The expanded-plaintext route homomorphically evaluates a bounded digit
function instead. It need not explicitly recover every multiplication winding.
Both require a noise budget for the entire encrypted circuit. Combining a
success from one route with a missing producer from the other is not a solution.

The owner-selected primary route is **CRAM-native public refresh**: one Safe
Basis root, phase-locked dependent composite sister trays, a public encrypted
integer carry/digit producer, and a certified return to the work domain. The
expanded-plaintext BFV circuit remains a comparison, not a substitute for
CRAM or an approved implementation plan. No external bootstrap backend is
admitted.

The precharged aligned-frame experiment now computes a ciphertext that
**decodes** to the full hidden carry at all 8192 coefficients and supports one
following square for a fresh input. Its linear CRT assembly also retains a
fractional `g/Q_work` term. Thus it is not yet an encrypted *integer* carry
producer and cannot by itself reset old phase noise. A return-key/basis path
and a repeat-refresh history certificate are separate requirements.
If the return key encrypts the boot secret under the original work secret,
while the precharge encrypts that work secret under the boot secret, a repeated
same-key path also forms a two-key KDM cycle. A lattice parameter screen does
not certify that assumption; admission must either justify it explicitly or
use a key-rotation plan that avoids the cycle.

The native 8192-coefficient follow-up now tests five input histories with a
direct `eta=3` precharge and a public, test-only boot-to-work return:

| History | Certified phase-error bits | Result |
| --- | ---: | --- |
| Fresh work input -> first aligned frame | 75 at boot Q | All coefficients decode; first square admitted |
| First boot square -> work return | 81 at work Q | All coefficients decode to 49 at coefficient zero |
| Returned fresh ciphertext -> second aligned frame | 76 at boot Q | All coefficients decode; second square admitted at 118 bits |
| Returned square -> second aligned frame | 117 at boot Q | All coefficients decode to 49 |
| Square after that second frame | 159 required vs 137 allowed | Correctly refused before execution |

The public return used here switches from the independent boot secret to the
work secret at `Q_boot`, then scales public ciphertext components to `Q_work`.
Its current coefficient-wise wide-integer division is **test-only**, not an
admitted CRAM-native hot path. The more important obstruction is algebraic:
the linear frame's error has a term approximately
`(Q_boot/Q_work) * E_source`; the return scales it back by
`Q_work/Q_boot`. Their composition preserves old error rather than refreshing
it. A genuine solution must homomorphically extract the **integer**
`round(S/Q_work)` (or an equivalent digit map with zero local slope), so the
new phase-error certificate no longer depends on `E_source` after admission.

This is an architectural recommendation, not a claim that the proposed larger
tuple is already secure or implemented. The repository's independent reference
has functional repeated-refresh evidence; it does not establish those properties
for native NINE65. The underlying construction references are
[BFV/BGV bootstrapping](https://eprint.iacr.org/2022/1363),
[bounded-support digit extraction](https://eprint.iacr.org/2024/115), and the
[pinned reference implementation](https://github.com/FeanorTheElf/fheanor/blob/2ba00539204cc03816dd258b57fad94904f54d41/src/bfv/bootstrap.rs).

## 1. What actually connects today

```text
HTTP session
  -> CramMainEvaluator + immutable scalar bound + main-Q transport
  -> exact multiply, then typed refusal when its bound is exhausted
     [no public refresh method on this evaluator]

Legacy AutoBootstrapEvaluator
  -> ClockworkBootstrap
  -> public_phase1_soundness_gate: REFUSED
     [does not call the new expanded-phase/digit-removal route]

Native expanded research route
  public component scaling -> encrypted secret inner product
  -> paired high / low / preconditioned trace views
  -> canonical high-encoding digit producer: native noise refusal
  -> contraction kernel: tested with a secret-derived digit oracle
  -> return-key/modulus/history integration and repeat closure: incomplete

Safe Basis research route
  precharged encrypted coordinates/selectors -> full carry decoding,
  but retained fractional source residual in the phase
  -> root / 2-and-11 coordinates / arbitrary dependent composite views
  -> exact integer extraction + return + repeat closure: incomplete
```

Source boundaries:

| Aspect | Implemented source | Consequence |
| --- | --- | --- |
| Current service | `crates/fhe-service/src/session.rs`, `ops/cram_main.rs`, `ops/wire_q.rs` | Working scalar transport is not a public refresh implementation. The service holds the client key; the library evaluator type itself is separate from the client. |
| Old auto refresh | `ops/auto_bootstrap.rs`, `ops/bootstrap.rs` | A heuristic ledger reset cannot replace the missing circuit. Do not reopen the gate or route certified ciphertexts through mutable legacy wrappers. |
| Expansion | `ops/expanded_phase1.rs`, `ops/expanded_bootstrap.rs`, `keys/expanded_bootstrap.rs` | Public component scaling and encrypted inner product exist. Their output is a noisy expanded plaintext, not the recovered message. |
| Nonlinear producer | `ops/prime_power_digit_lift.rs` | A real public full-domain polynomial producer exists, but refuses the native parameters before key generation. The bounded polynomial compiler is not yet that native admitted producer. |
| Contraction | `ops/prime_power_phase.rs` | Requires a private, lineage-bound `CanonicalLowDigitLift`. Tests that construct it with a secret oracle do not close the producer gap. |
| Safe Basis | `ops/safe_basis_*_tests.rs`, `ops/cram_precharge.rs` | The full-frame evaluator is test-only; key-holder low-noise precharge is a library primitive. Neither is on the service's public refresh path. |
| Exact arithmetic | `ops/exact_mul.rs`, `arithmetic/exact_scale_round.rs`, `arithmetic/main_only_base_ext.rs` | Derived transient lanes preserve the integer tensor. These kernels do not remove encryption noise. |

All abbreviated source paths above are under `crates/nine65/src/`.

## 2. Variable map: do not combine these budgets or key domains

| Variable | Meaning and dependency | What changes it / what it constrains |
| --- | --- | --- |
| `N` | Ring degree; negacyclic convolution length | Noise norms, transform count, arithmetic/key size and security. Changing N also changes the ciphertext/key domain. |
| `p=65537` | Work plaintext modulus | Message space and slot geometry. |
| `t_b=p^2=4295098369` | Expanded plaintext modulus | Retains message plus rounding residual; reduces outer scale and increases multiplication error growth. Not a sister-view modulus. |
| `Q_w`, `q_s`, `Q_b` | Work, sparse-switch, bootstrap ciphertext moduli | Distinct levels and domains. Increasing persistent Q affects security; temporary arithmetic A does not change persistent Q. |
| `Delta_b=floor(Q_b/t_b)`, `r_b=Q_b mod t_b` | Bootstrap encoding scale and its remainder | A floored encoding is not the ideal rational grid; remainder terms belong in the error calculation. |
| `s_w`, `s_s`, `s_b` | Work, temporary sparse, and outer bootstrap secrets | Source rounding uses the secret present at that step; outer encryption uses the bootstrap secret. A return switch closes a key relationship that also needs assessment. |
| `H_in=||s_in||_1` | Secret norm at component rounding | Determines the plaintext residual support. A sparse bootstrap secret alone would not make the earlier dense source rounding sparse. |
| `V` | Bound on `||p*phase-Q*m||`, modulo `pQ` | Must describe actual history **after** the incoming transform and switches. `2V<Q` is the input decoding condition. |
| `rho`, `B` | Expanded plaintext residual and certified support radius | `w=p*m+rho`; `|rho|<=B` is the bounded polynomial's hypothesis, not an observed typical value. |
| `beta`, `E` | Bootstrap-key phase error and outer ciphertext ideal-grid error | Distinct from rho. Polynomial evaluation can fail while rho remains inside its support. |
| `b`, `D`, `eta` | Gadget radix bits, total digits, bounded error-sampler support | Key-switch error bound `E_ks=N*eta*(2^b-1)*D`; does not describe the plaintext carry. |
| `K_dec` | Carry omitted by legacy componentwise decryption rounding | Needs encrypted threshold/quotient evaluation or the alternative expanded-digit construction. |
| `K_mul`, `J` | Integer winding of original components and carry-ciphertext components | Depend on the ciphertext representation and secret, not just its plaintext. They are not interchangeable with K_dec. |
| `nu`, `xi` | Error in first- and second-carry encodings | Even a one-unit error can be amplified beyond the next-operation budget. |
| `R`, `A`, `s_mult` | Tensor rounding bound, transient modulus product, quotient shift multiplier | Control exact arithmetic range and rounding, not lattice security or source history. |
| `m_i`, `E_view` | Sister modulus and its dependent projection error | Tune view cost. Joint periods use LCM for overlapping moduli. Neither adds fresh source capacity. |
| lineage / key epoch | Which input, source, key and operation a result represents | Must survive every transform, switch, correction and contraction. Matching residues alone do not authenticate this relationship. |

The Three Locks / shadow-source goal is a separate protection contract. More
entropy in an outer mask is not a reduction in BFV phase error.

## 3. The original missing carry and its alternative

For nearest integer rounding `n_Q(z)=floor((z+floor(Q/2))/Q)`, define

```text
A_i = n_Q(p*c_i),                 R_i = p*c_i - Q*A_i
K_dec = n_Q(R0 + R1*s)
n_Q(p*(c0+c1*s)) = A0 + A1*s + K_dec.
```

The convolution is negacyclic and the final rounding is coefficientwise.
Rounding the two components and omitting K_dec is not BFV decryption. Keeping
all residues of those independently rounded components does not restore the
discarded secret-dependent quotient.

The expanded route instead computes components at p-squared precision:

```text
a_i = round(p^2*c_i/Q)
w = a0 + a1*s_in = p*m + rho (mod p^2)
B_required = floor(p*V/Q + (H_in+1)*(Q-1)/(2Q)).
```

Dense input at N=8192 requires radius 4096 even for the first fresh-history
fixture. A weight-32 key can reduce it, but only **after actually switching**:

```text
V_ms = floor(q_s*V/Q_w + p*(H_dense+1)*(Q_w-1)/(2Q_w))
V_sw = V_ms + p*E_ks
B_required = floor(p*V_sw/q_s + (H_sparse+1)*(q_s-1)/(2q_s)).
```

With the documented two sparse lanes and 10-bit gadget, the first two scalar
fixtures give B=17. Those fixtures are not certificates after a slot transform.
A live sparse switch, post-transform history and security assessment remain
required. See [the radius contract](../2026-10-03/DIGIT_RADIUS_CONTRACT.md).

For supported rho, construct F with `F(r)=r mod p^2` and `F'(r)=0 mod p`.
Then `F(r+p*m)=r mod p^2`. Use the shifted canonical digit
`h+F(x-h)` for `x=p*m+rho+h`, `h=(p-1)/2`. Subtracting this digit leaves
plaintext divisible by p; reinterpret the grid at plaintext p. **Do not
invert p modulo p^2**: it is not a unit. This is what the contraction API
requires, rather than an ordinary ciphertext of the digit at plaintext p.

This derivative is the precise useful connection to the user's Jacobian
intuition: it cancels a p-adic first-order term on the supported points. It is
not a proof of equivalence to a tropical/ultradiscrete Jacobian construction.
The carry cocycle/piecewise threshold identity is another useful description,
but does not itself implement an encrypted threshold.

## 4. Why the recent correction experiments fail

Use Q=Q_b and t=t_b in this section. For centered component lifts,

```text
C0+C1*s_b = P + Q*K_mul,           P = centered_Q(C0+C1*s_b)
t*(P+Q*K_mul)^2/Q = t*P^2/Q + 2*t*K_mul*P + t*Q*K_mul^2.
```

The last term vanishes modulo Q. The surviving correction is
`W=2*t*K_mul*P`, including the phase error in P, not only its encoded message.
A raw encoding of `K_mul+nu` introduces `2*t*nu*P`. A Delta-scaled carry has
its own component lift `Delta*K_mul+nu+Q*J`. In the compensated adapter,
with `V_phase=P+r_b*K_mul-t*nu`, the extra term is `2*t^2*J*V_phase`.

Fresh native rerun at N=8192, five-prime Q_b (154 bits), half-Delta 121 bits:

| Controlled change | Result | Isolated cause |
| --- | --- | --- |
| Same phase, native mask versus clear `(P,0)` oracle | Square error 95 versus 57 bits | Component winding, not a different message or input error |
| Remove encoded-message part only | Still 95 bits; next square wrong | Correction omitted winding times phase error |
| Full exact raw K oracle | 57 bits; next square correct at 96 bits | Algebra is valid when supplied the exact correction |
| Raw carry with one-unit error | 89 bits; next square wrong at 128 bits | Carry precision requirement |
| Compensated Delta carry, same mask, zero versus sampled CBD error | Both already wrong at 128 bits before key switch | Carry ciphertext's own winding J |
| Fuse key switching | Switch contribution 84 to 20 bits; product still wrong | Key switching is improvable but not the dominant failure |
| Also cancel exact J | Product correct at 78 bits; next square wrong at 122 bits | Separately rounded products amplify rounding |
| Exact J plus one-unit perturbation | Product 121 bits; next square wrong at 153 bits | Second carry requires its own precision proof |
| Single-round clear-phase V oracle | 57 bits; next clear-phase square correct at 58 bits | Positive arithmetic control, not an encrypted implementation |

All sizes here are **measured diagnostics**, not producer-issued upper bounds.
Actual integer comparisons determine correctness; equal bit lengths do not.
The test passes because it checks the controlled successes and expected
failures. It is not a passing end-to-end public refresh test.

A single-round implementation must lift C and B before forming
`F_i=C_i-t*B_i`, square that unwrapped tensor, scale-round once, add the
second-winding correction, and relinearize once. Sending canonical mod-Q
`C-t*B` through ordinary multiply loses the required component lifts.
Its sufficient tensor bound is `(N/2)*(t+1)^2` (77 bits); the shift multiplier
needs 109 bits; the auxiliary threshold needs 263 bits. Nine candidate
transient lanes supply 283 bits, but their reverse-rank accumulator needs 286
bits. Current u64 and U256 interfaces refuse this case correctly.

Widening those kernels would address **one arithmetic obstacle**. It would
not create either public carry producer or make noisy raw J accurate enough.
Consequently it must not be described as the complete refresh fix.

## 5. New whole-circuit checks: optimizing one node is insufficient

The new [reproducible analysis](../../../scripts/public_refresh_architecture.py)
checks polynomial degree and mirrors the current constant-plaintext native
noise recurrence using public integers. It stops on the first refusal, rather
than treating a failed intermediate as an admitted input to the next node.

For B=17 the polynomial has degree 69 even modulo p. This is also the minimum
degree for a polynomial satisfying these support values and slopes: two such
polynomials differ by a multiple of `G^2` over F_p, where
`G=product_(r=-B..B)(X-r)`. Our degree-69 polynomial is the unique remainder
below degree 70. Thus a binary-multiplication polynomial circuit needs at least
seven multiplication layers. B=16 still needs seven; B=32 needs eight.
This is **not** a lower bound against arbitrary non-polynomial refresh methods.

There is an avoidable key-generation cost. Current `ExpandedBootstrapKey`
public-key-encrypts zero, then inserts the source secret, giving
`beta=eta*(2N+1)=49155`. The CRAM-specific key-holder precharge now uses direct
secret-key encryption, `b=Delta*s_in+e-a*s_b` with uniform full-`Q` `a` and
bounded `e`, giving `beta=eta=3`; the evaluator still receives no secret.
This improves the **precharge** error, not the retained source residual or the
missing encrypted integer extraction. The expanded circuit itself has not
been retrofitted with this producer.

Holding the current multiplier and coefficient-trace envelopes fixed:

| Public bound calculation | Projected input bits | First square bits | Second square bits |
| --- | ---: | ---: | ---: |
| Existing bootstrap-key producer | 73 | 131: refused | Not evaluated |
| Prospective low-noise key producer | 59 | 117: fits | 175: refused |

The actual half-Delta is 121 bits. These are **conservative certificate
calculations**, not measured ciphertext errors. A failed upper bound is not
a proof that every sample fails. Nevertheless this exact admission policy
cannot certify the required circuit. Lower-noise keys are useful, but do not
turn this five-prime tuple into a seven-layer bootstrap.

## 6. What one safe basis and composite sister trays can solve

One root is sufficient as the shared source; each dependent tray need not be
a new safe/coprime basis. Preserve the distinction between source factors,
payload/lift capacity, and arbitrary target moduli. The joint period of
overlapping targets is their LCM, not their product.

For the existing 2/11 coordinates,
`b=S mod2`, `j11=((S mod11)-b)*6 mod11`, so `S=b+2*j11 mod22`.
This is phase consistency modulo 22, not K_dec or J. Values S and S+22 share
these coordinates. Larger precharged power coordinates can retain the whole
bounded S; the existing 139-bit representation experiment is relevant.
**Encrypted rank/quotient readout is still a computation**, even when the
representation has enough information.

The composite planner controls `E_view(m)=sum_r (S_r mod m)*E_selector,r`
over the public possible states. It preserves source identity and can reduce
projection cost. It cannot reset the selector errors, supply a missing
8192-term composition, or convert a Delta-scaled target into an accurate raw
phase correction for a different Q/key/operation.

### Dense coefficientwise gate probe (2026-10-22)

`crates/nine65/tests/coefficient_slot_gate.rs` now exercises the missing
coefficient/slot bridge with encrypted toys. At `N=8`, plaintext `17^2`, it
applies (a) the p-adic low-digit section to a dense vector and (b) the
quadratic local ternary carry gate with a different public residual pair at
each coefficient. Both decrypt to the expected value at every coefficient;
the direct ring-square negative control fails, as expected for negacyclic
convolution. These tests use no evaluator secret or digit oracle. The context
is explicitly insecure and the test does not implement the Safe Basis root,
an 8192-term hidden-carry accumulation, contraction, key return, or repeat
refresh.

The prototype expresses each linear transform as a direct sum of
automorphism/diagonal terms. That is useful correctness evidence but not a
viable native transform: the exact N=8192 hybrid-key plan requires 8,191
non-identity Galois keys, with an estimated **47.99 GiB** of key payload
before metadata. The next implementation gate is therefore a structured
coefficient-to-slot / slot-to-coefficient transform with a reviewed key-size
and error certificate. Until that exists, the dense Jacobian gate is only a
toy proof that the scalar map can be vectorized algebraically; it is not a
CRAM refresh implementation.

There are two implementation mismatches to fix before extrapolating:

- The composition prototype's `source_q: i128` accommodates Q_w (119 bits),
  not this Q_b (154 bits). A source-Q change needs a wider admitted coordinate
  type and new source binding; it cannot reuse the old carry certificate.
- Its preconditioner is hardcoded to `-8*N=1 mod65537`, with an assertion
  `8*N+1=t`. At N=32768 and p=65537 the inverse is **-2**, not -8. The one-root
  idea remains valid; this particular prototype is not parameter-generic.

## 7. Complete target architecture and its acceptance conditions

```text
Certified work ciphertext (actual key/domain/history)
  -> slots-to-coefficients, with propagated V
  -> Q-to-q_s modulus switch and work-to-sparse key switch
  -> source-bound p^2 component expansion
  -> low-noise encryption of sparse secret under boot key (keygen material)
  -> coefficients-to-slots, with exact transform/error certificate
  -> native bounded digit DAG, every node admitted
  -> canonical high-digit subtraction and contraction to plaintext p
  -> return modulus/key switch and authenticated output history
  -> multiply -> repeat the complete refresh
```

The Safe Basis root and derived views must participate where the native
arithmetic/transition contract requires them; a regenerated fingerprint is
not that integration. Temporary arithmetic residues stay off the wire.
No stage may decrypt or receive a clear digit/secret-dependent measured error.

Implement and accept in dependency order:

1. **Freeze one complete tuple and arithmetic DAG.** Include actual prime
   lists, all transforms and switches, sampler supports, polynomial coefficients,
   peak integer widths, key sizes and the output-to-next-input inequality.
   Reject infeasible tuples before expensive key generation. The existing
   N=8192 carry-sized five-prime tuple is not admitted for the digit route;
   the tested six-prime continuation fails the recorded 128-bit screen.
2. **Resolve the security-sized context.** N=32768, p=65537, Q around the
   reference's 810-bit direction is a candidate for investigation, not a
   selected secure tuple. Slot geometry remains valid. Assess dense/sparse
   distributions, sample counts and every evaluation-key relationship jointly.
   The [HE standard](https://homomorphicencryption.org/wp-content/uploads/2024/08/Homomorphic-Encryption-Standard-v1.1.pdf)
   does not supply a recommendation for the sparse-key part. An independent
   boot key does not automatically remove cycles once a return key is added.
3. **Implement the selected tuple's native width and transform requirements.**
   Fixed-work rank, sampling, decoding and bound arithmetic must all cover the
   full tuple, not only a 286-bit special case. Current source/boot APIs require
   equal N. An N=32768 profile therefore also needs N=32768 work ciphertexts,
   or a separately constructed/certified ring switch. It cannot silently accept
   existing N=8192 ciphertexts. Preserve their current profile.
4. **Issue live support and circuit certificates.** Sparse switch before
   rounding; outer key noise tracked separately; exact inverse preconditioning;
   SIMD transform implementation and proof; bounded native digit evaluator;
   private source/key/operation-bound canonical digit result. A parameter-only
   allowance and the clear polynomial identity are not input certificates.
5. **Close the refresh loop before service wiring.** Let T be incoming
   transforms/switches, M the supported next multiply, R the entire refresh,
   and B the selected support. Prove both `2*V_out<Q_w` and
   `radius(T(M(R(input))))<=B` for every admitted input. Also admit every
   outer node and the return switch. Test all coefficients through at least
   two refresh/multiply cycles with fresh keys and boundary inputs.
6. **Integrate at the certified main-Q boundary.** Add the new backend to
   `CramMainEvaluator` with preflight refresh and immutable output lineage.
   Preserve wrong-key/epoch/level and over-budget refusals. Only then expose
   it through the service and update claims. Do not unlock legacy Phase 1.

Until steps 1 and 2 have a feasible jointly assessed construction, neither a
deadline nor another positive oracle run makes this a complete solution.
If preserving the present small tuple is mandatory, an alternative public
carry/digit circuit with a proved lower cost is still a research requirement.
This analysis does not prove that no such construction can exist.

## 8. Verification performed for this analysis

- Fresh native opt-in diagnostic: **1 passed, 0 failed, 0 ignored**, 208.91 s.
  This includes deliberate wrong-plaintext controls described above.
- Existing independent radius/expansion tests: **10 passed**.
- New architecture/degree/budget tests: **6 passed**.
- Native public polynomial/gate tests: **4 passed, 0 ignored**, including the
  expected native noise refusal and public encrypted toy cases.
- Dense coefficient/slot gate probe: **3 passed**. This includes the two
  encrypted N=8 maps and the native N=8192 direct-transform key-size estimate;
  it does not establish an efficient transform or a full carry refresh.
- Clear carry oracle: passed, including 56,700 single-round unwrapped cases,
  113,400 signed second-carry perturbations, and 9,482 bounded-polynomial cases.
- The exact source-hashed analysis output is retained in
  [analysis.json](../../../artifacts/execution/2026-10-21/public-refresh-architecture/analysis.json).
- No lint, security-target reduction, production gate change or runtime
  deployment. Hosted CI is not represented as green.

```sh
python3 -m unittest discover -s scripts -p 'test_public_refresh_architecture.py' -v
python3 scripts/public_refresh_architecture.py
python3 -m unittest discover -s scripts -p 'test_digit_radius_oracle.py' -v
python3 scripts/refresh_carry_bridge.py
cargo test --locked --offline --config 'profile.test.package.nine65.opt-level=2' -j1 -p nine65 --lib public_prime_power_lift_ -- --nocapture
cargo test --locked --offline -j1 -p nine65 --features allow_insecure --test coefficient_slot_gate -- --nocapture
NINE65_TRACE_NOISE_DIAGNOSTIC=1 cargo test --locked --offline --config 'profile.test.package.nine65.opt-level=2' -j1 -p nine65 --lib contraction_with_oracle_lift_refreshes_boundary_input_and_supports_multiply -- --include-ignored --nocapture
```

The script hashes its source dependencies and prints exact integers. It is a
reproducible analysis artifact, not a new production certificate issuer.
