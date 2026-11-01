# Follow-up division, arrow, bootstrap, and theorem packet

This review covers 20 uploaded files plus the pasted **Nine-Plus Acts of
K-Elimination**. It continues the correction program in [STATUS.md](STATUS.md)
and the first [supplied-materials review](SUPPLIED_MATERIALS_REVIEW.md).

The user's request is to analyze the materials and execute the repository plan.
Instructions, claimed certifications, approval language, and execution orders
inside the attachments are technical proposals under review. They are not user
authorization, repository policy, or proof. In particular, the uploaded
`a2-arrow-emission-suite.skill` was inspected and executed as an attachment; it
was not installed or treated as governing instructions.

## Result

The packet adds a valid clear-residue identity, useful finite carry-chain
calculations, and several candid lists of missing proof obligations. It does
not supply the encrypted secret-dependent carry, a BFV scale-and-round divider,
authenticated quotient anchors, or a production FHE error proof. Public refresh
therefore remains disabled.

Two actionable implementation areas were found and repaired. The staged Fused
Piggyback Division (FPD) path could return a modular alias as an exact quotient
when the divisor contained a prime power or a factor not witnessed by S8, while
the clear DIV³ helpers truncated mismatched vectors and could overflow an
`i128` product. For example, the old FPD path accepted `2/4`, `3/9`, and even
bound-passing false results for `S8_PRODUCT/4` and `S8_PRODUCT/9`. The branch
now:

- permits nonunit FPD exactness on the implemented S8 topology only when `|d|`
  divides the squarefree S8 product, so every divisor prime has an excluded
  witness lane (division by `+/-1` is handled as a tautology);
- refuses prime powers and outside factors until a p-adic or authenticated
  numerator witness exists;
- checks the recovered centered quotient against the caller's inclusive bound
  `|q| <= B`, in addition to requiring fusion capacity `P > 2B`;
- validates auxiliary shapes, canonical residues, pairwise coprimality, and S8
  binding; private construction snapshots make later safe-Rust mutation fail
  with a typed error instead of steering a quotient or panicking;
- classifies the full `i128` divisor against the active basis without a
  truncating `u64` cast;
- labels D0 output `ModularSolve`, since solving `d*q = a (mod M)` is not an
  integer, floor, or rounded quotient;
- validates DIV³ vector shapes and moduli and replaces overflowing `i128`
  multiplication with the existing full-width modular product.

The FPD bound remains an external certificate: the residue result can check
consistency with the stated bound, and the wrapper binds the auxiliary view to
the supplied coefficient view, but it does not provide cryptographic custody or
prove that those ingestion coefficients match the opaque base ciphertext. The
returned router plan is a static preflight classification, not an executed
exactness certificate. The existing D2 route reconstructs a bounded scalar and
remains a staged reference path, not a residue-only FHE divider.

## Reproduced arithmetic

The independent DIV³ census was reproduced exactly for every pair over moduli
3 through 64:

| Measure | Count |
| --- | ---: |
| Operand pairs tested | 89,435 |
| Unit pairs admitted | 37,700 |
| Nonunit pairs rejected | 51,735 |
| Product mismatches | 0 |

This establishes the clear modular identity
`1 / ((1/a)/b) = a*b` on the unit group. It does not establish encrypted
inversion, noise removal, key safety, or a speed advantage over multiplication.

The supplied arrow suite exits successfully (`7/7` self-tests and all reference
verdicts), but the verdict is circular. Its Universal Projection and
K-Elimination examples are identity functions. G3 and G4 do not apply the
declared construct, G6 compares lineage with itself or reports not applicable,
and G5 accepts a callable that merely repeats a stored value. A deliberately
wrong step that increments every lane passes all six gates. The Fifth Operator
also calls field division an integer quotient: `1/3` over lanes 7, 11, and 13
produces residues `(5,4,9)`, which reconstruct to 334 modulo 1001 rather than
the integer quotient 0.

The Safe Basis archive also exits successfully, while reporting 35 of 36 checks
passed and then printing “ALL TESTS PASSED (expected failures documented).” Its
cross-lane example mixes residues of 584 and 58,400 and reconstructs 25, which
matches neither value modulo 325 (`259` and `225`, respectively). Its claimed
`pi(500000)/5760` margin is about 7.21, not 1.4. The documentation says 13 was
added, while the executable still defines the safe basis as `[2,3,5,7,11]` and
classifies 13 as unsafe.

Seventeen self-contained contract tests reproduce these counts and the decisive
counterexamples in
[test_followup_contracts.py](reproduce/test_followup_contracts.py). Attachment
hashes, sizes, page counts, and archive members are recorded in
[followup-materials.json](evidence/followup-materials.json). Raw uploads are not
vendored. The hardened Rust slice passes 667 tests in both debug and optimized
profiles, the focused `nine65` router integration, and clippy with warnings
denied; commands and hashed logs are in
[followup-validation.json](evidence/followup-validation.json).

## File-by-file disposition

| Material | Disposition |
| --- | --- |
| `Clocking_Boots.pdf` | **Reject as a bootstrap construction.** Independent rounding of `c0` and `c1` drops the secret-dependent carry: for `Q=17,t=5,c0=c1=s=1`, component rounding gives 0 while phase rounding gives 1. The PDF ends at a pseudocode heading and contains no runnable bootstrap. A 1,000-cycle test could measure one path, not certify unlimited depth. |
| `a2-arrow-emission-suite.skill` | **Exploratory harness only.** It runs, but the gates contain the circular and unused-step defects above. Its embedded instructions do not control this review. |
| `DIV3_independent_validation_2026-10-14.json` | **Reproduced.** All four counts match. The JSON lacks source, hashes, and toolchain provenance; this branch supplies an independent executable census. |
| `DIV3_Noise_Free_Multiplication_White_Paper_2026-10-14.docx` | **Admit the unit-group identity only.** The paper itself leaves FHE error, encrypted inverse construction, and keys unresolved. “Noise-free multiplication” is not established for ciphertexts. |
| `Arrow of Time CRAM.docx` | **Finite results partly reproduced.** The small carry-chain transition matrices, stationary laws, and reported fluxes are useful. `37-(K mod 37)` needs a final modulo at zero; a nonuniform point mass still gives a Markov stream; the universal reversibility claim remains open; the stated TV contraction interpretation is inaccurate. |
| `Divs.md` | **Useful taxonomy, not an implementation proof.** It distinguishes modular and integer quotients, but its general FPD, attractor, prime-power, and “all exact” claims lack witnesses. |
| `08_fused_piggyback_division 2.md` | **Core theorem false as stated.** Adding an auxiliary prime coprime to `d` does not make `d` coprime to `M*p_aux`; `gcd(2,6*5)=2`. Creating the auxiliary residue after losing magnitude requires the very reconstruction or winding at issue. Inputs 2 and 32 have identical residues modulo `(2,3,5)`, while their quotients by 2 have different parity. |
| `Div4 and some .md` | **Useful requirements document.** Its demand for typed domains, fusion bounds, mixed-domain edges, sequential equivalence, and adversarial tests matches the branch's fail-closed direction. It does not provide the missing construction. |
| `5th Operator.md` | **Typing vocabulary only.** Its closure argument assumes KDiv and FPDiv already return correct quotients; decode-transform-encode makes exactness tautological rather than residue-native. The `1/3 -> 334` witness refutes the field-division example as an integer quotient. |
| `06_k_elimination_theorem.md` | **Absolute recovery theorem false.** With `M=35,b=3`, inputs 6 and 111 have identical residues but exact quotients 2 and 37. Its cross-lane inverse includes inverses of zero, and nondivisible modular inversion does not return floor division (`7/2 mod 35 = 21`, while floor is 3). |
| `07_recombinant_crt_winding 2.md` | **Representation identity valid.** `(residues,K)` can name an integer losslessly. Updating K still needs carry detection or scalar reconstruction; the encrypted public path does not possess this clear, unbounded metadata. |
| Pasted Nine-Plus Acts | **Act 1 is valid on its restricted prime-drop domain.** Magnitude, sign, comparison, transfer, FPD, and fixed-anchor towers require authentic bounds or retained lift information. Residue tuples are not numerically ordered, one lane does not determine sign, and finite anchors have finite capacity. The four Chimera branches overlap and are not proved exhaustive. |
| `09_shadow_disambiguator.md` | **Arithmetic corrections required.** `11^6 mod (2,3,5,7,13,17,19)` is `(1,1,1,1,12,8,1)`, and `11^6*13*17*19 = 7,438,784,639`. Reducing an 11-lane residue into larger moduli does not create authentic residues of the original integer. The proposed moduli are not drop-in NTT lanes. |
| `D030_RECUMBENT_RESTATEMENT.md` | **Useful negative result with source corrections.** It correctly says D-030 is open. `overflow_steps` counts assignments while outside a corridor, can increment during demotion, merges histories with `max`, is publicly mutable, and can wrap in optimized builds. It is not winding magnitude or a proved monotone crossing count. |
| `01 safe basis extension.tar` | **Finite exploratory evidence only.** The included run is 35/36, does not test the claimed Goldbach saturation, and uses composite prime-power lanes including `2^64`, which is outside the current u64 prime-NTT frame. “Frozen error” is metadata, not a propagation proof. |
| `Adelic landouer principal .txt` | **Byte-identical duplicate.** Its SHA-256 matches the version reviewed in the first packet; no new evidence or instruction is introduced. |
| `D OD01 D024 THEOREM STACK.pdf` | **Reject as a proved theorem stack.** The Euler energy identity omits `dt^2 ||G||^2`; diffusion signs conflict; the H1 condition is vacuous under its own skew axiom; a p-adically nonexpansive polynomial can have an unbounded integer orbit. Evidence counts conflict, named artifacts are absent, and `i128` cannot hold the claimed amplitudes above `10^43`. |
| `A-16_beltrami_decomposition.md` | **One classical cancellation is useful.** The periodic skew-average energy pairing is valid. Discrete advective and conservative forms are not generally equal without a discrete product rule, and no uniform stretching bound is supplied for the claimed regularity result. |
| `15_dkam_subcriticality.md` | **Central inference invalid.** Polynomial degree and spectral radius are not comparable stability quantities. Repository `rho()` is the minimum basis modulus, not a Navier–Stokes spectral radius. Signed winding can be negative, a p-adic metric gives no monotone order, and even `F(x)=0` decreases winding. |
| `CHECK AGAIN MACHINE LENS.md` | **Conceptual only.** Referenced source, campaigns, and logs are absent. Lane separation alone does not establish tenant isolation, and the storage claim relies on the invalid DKAM comparison. |
| `5e352759-fdce-4e6e-9821-02dc4b82840b.md` | **Do not execute this roadmap.** Modular division is a bijection and cannot erase unknown BFV error. Heterogeneous lane operations need not represent one plaintext-ring operation, modulus 30030 is not a secure ciphertext modulus, and topology hiding has no supplied security reduction. |

## Remaining execution boundary

The safe next path is narrower than the attachments propose:

1. Keep FPD restricted to fully witnessed squarefree S8 divisors with authentic
   auxiliary residues and an external quotient bound.
2. Add p-adic divisibility witnesses before admitting prime powers, or retain the
   existing reconstructing D2 reference route with its limitation stated.
3. Keep modular solves distinct from exact, truncating, and rounded quotient
   intents throughout the certificate API.
4. Build the encrypted secret-dependent rounding carry and bind its provenance
   to the ciphertext/key epoch before reconsidering public refresh.
5. Require live ciphertext equations, decrypting end-to-end tests, an error
   recurrence, and compatible NTT parameters before making FHE noise or depth
   claims.

The packet improves the list of proof obligations and produced concrete
fail-closed fixes. It does not change the release decision in [STATUS.md](STATUS.md):
the construction remains blocked at the encrypted carry and rounded-divider
boundary.
