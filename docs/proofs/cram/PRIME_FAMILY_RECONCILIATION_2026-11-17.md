# Prime Family: role-preserving transport and the fixed primary

2026-11-17. This note reconciles the newly supplied Prime Family sources with the owner's current CRAM architecture. It adds written mathematical arguments and implementation obligations, not new Lean declarations or runtime capabilities.

## Read scope and source identity

The complete readable text of **PRIME FAMILIES REFERENCE.md** (238 lines) and **PRIME FAMILY.pdf** (54 pages) was reviewed. The PDF review was divided into pages 1–27 and 28–54, with complete text coverage in each part; the principal transfer passages were cross-reviewed. The preceding review had read selected passages, not the full PDF. This does not claim visual examination of every page, reproduction of every cited experiment, or examination of all 19 underlying documents cited by the compilation.

| Source | SHA-256 | Relationship |
|---|---|---|
| PRIME FAMILIES REFERENCE.md | `1081547cbd801d2d5b8ea00351da77188c8a63b1a3b48bf9935a35fbc589d2da` | Newly supplied reconstructed reference; preserves its VERIFIED/CORPUS/SYNTH distinctions. |
| PRIME FAMILY.pdf | `fe8f56db72e38993888e5a41b1077a97fd6b293e70661c05886f47912e17f1bd` | Byte-identical to the earlier PRIME FAMILY 2 upload; the review coverage is new. |

The other eight attachments in this batch were inventoried and text-extracted. This note does not claim their complete review. Original uploads are not republished here. Page numbers below are physical PDF pages; source labels such as “verified” are historical assertions until tied to inspected proof or execution evidence.

## What the sources change in the architectural interpretation

The PDF, especially pages 1, 4–6 and 21–27, organizes CRAM around **prime roles and family relations**, with composites serving as computational carriers. Coprimality and capacity alone are therefore not a sufficient implementation specification.

The reference's role table distinguishes parking/parity at 2, fabric at 3, surface at 5, bridge at 7, shadow/navigation at 11, and boundary at 13. It describes 2's half-value phase relation and 13's anchor role. These need explicit operator contracts; the prose is not itself an executable update law. Reserving 11 means preserving its designated duties, not assigning a source-independent zero to it.

Reference §6 explicitly describes 17 entering through composite docking, including `143*17=2431`, **without requiring primary-basis extension**. Its broader docking-count and healing claims remain tagged CORPUS; the arithmetic example does not prove them. This passage supports the owner's distinction between an intact primary and other configurations that use its structure.

Accordingly, the selected architecture keeps the primary fixed, uses dependent sisters with arbitrary positive moduli, and preserves declared role/family signatures through their actual source, phase and operation relationships. The historical S6/S8 alternatives, active subsets and independent extension examples do not authorize changing the selected primary during execution. Scalar K remains derived on demand.

## The document's actual transfer principle

PDF page 35 specifies three conditions: a property has a finite signature on the lanes; operations preserve that signature; and encoding and decoding are inverse on the admitted domain. It explicitly qualifies the transfer claim with **“When all three conditions hold.”** Pages 42 and 54 repeat the structural-transfer idea.

A precise version is as follows. Let `D` be a semantic domain and `E` its valid coupled-state representation. Suppose `e:D→E` and `d:E→D` are inverse, and a semantic instruction `F` and implemented instruction `T` satisfy

    T(e(x)) = e(F(x)).

For an invariant `I` of `F`, define `J(s)=I(d(s))`. If `s=e(x)`, then

    J(T(s)) = I(d(T(e(x)))) = I(d(e(F(x)))) = I(F(x)).

Thus `I(x)` implies `J(T(s))`. Initialization and induction give preservation over every finite admitted instruction sequence. The primary basis/configuration can be an immutable component of `E`; its source-dependent readings may evolve. No extension of that primary is required by this argument. The source `x` and decoder can be proof objects, not stored scalar payloads or runtime reconstruction procedures.

For a particular query, a full inverse is unnecessary. With observation `h:D→O` and query `q:D→Q`, exact readout on `im(h)` exists precisely when

    h(x)=h(y) implies q(x)=q(y).

Define the readout at `h(x)` to be `q(x)`; the implication makes it well-defined, and proves uniqueness on the observed image. This is the existing universal query-transport contract. It transports the information actually preserved by the signature; it does not infer other properties from a shared name.

**Automatic inheritance is therefore a reusable theorem after the constructor, operation and signature laws are established.** The remaining work is to instantiate those laws for the real fixed-primary/sister mechanism, including the 2/11 relationship and permitted heterogeneous operators. That work should not be replaced by an independent-anchor architecture.

## A concrete dependent-sister model using the paper's composites

The paper discusses `77=7*11` and `143=11*13` and correctly excludes them as mutually coprime independent carriers. They can nevertheless be dependent views sharing the shadow-11 interface. Define

    E = {(a,b) in Z/77 × Z/143 : a mod 11 = b mod 11}.

There is a ring isomorphism

    Z/1001 ≅ E,    [x] ↦ ([x] mod 77, [x] mod 143),

where `1001=lcm(77,143)`. Equality of the two images means both 77 and 143 divide the difference, hence 1001 divides it, proving injectivity. There are `77*13=1001` compatible pairs, proving surjectivity. Coordinate reduction preserves addition, multiplication and one, so this is a ring isomorphism. It is a written generalized-CRT instance, not a new claim that the live sister mechanism already implements it.

If both views apply the same integer-coefficient polynomial `F`, their reductions modulo 11 remain equal because evaluation commutes with reduction. For heterogeneous operators `T77,T143`, the necessary compatibility obligation is instead

    T77(a) mod 11 = T143(b) mod 11    whenever (a,b) is admitted.

For example, applying identity to one coordinate and `+1` to the other breaks the equality at `(0,0)`. An intended nonzero phase relation can replace equality, but its actual update law must then be proved. Matching prime labels alone is insufficient.

This example leaves the primary untouched. It also does not increase an S6 direct observation's period: `1001` already divides `30030`. Its purpose is dependent carrier structure and operation transport. Higher-power observations can supply additional resolution, provided their authentic producer and compatibility maps are established.

## P-adic refinement and the scope of “no bound”

Pages 32 and 46 give integer-polynomial p-adic non-expansion. Page 34 explicitly distinguishes that local norm statement from an upper bound on ordinary integer magnitude. This is consistent with an extensible compatible family having no fixed global magnitude ceiling.

Non-expansion alone is not the StarLift constructor. The required family law is `a_(n+1) mod p^n = a_n`. For fixed `r` and a readout coefficient `M` with `p∤M`,

    k_n = (a_n-r)*inverse(M,p^n) mod p^n

then commutes with reduction and defines one p-adic winding component. This coefficient need not be the product of the whole primary. The primary remains intact. The actual producer must supply each refinement; repeated copies of the same low-precision residue do not establish it. Finite precision and a fixed global ceiling are different claims.

## Corrections needed before registering inherited properties

These are specific repairs to printed statements, not reasons to discard the role-bearing architecture.

| Source claim | Correct statement and proof consequence |
|---|---|
| PDF pp. 14/31: 11 has a multiplicative orbit of order 110 in the units modulo 121 | 11 is not a unit modulo 121. The unit group has order 110; its acting generator must be a unit. The reference's order-five action by 4 modulo 11 is valid. Its order-five lift modulo 121 is 81, whereas 4 has order 55 there. Fix the action before transferring its types. |
| PDF pp. 22/47: every linear pair `(r,ar+b)` excludes exactly two classes when `a` is a unit modulo prime p | The roots are `0` and `-a⁻¹b`; they are distinct exactly when `p∤b`. For `p∣b` there is only one. Goldbach `(r,n-r)` obeys this same conditional root count. |
| PDF p. 33: p-adic non-expansion preserves the residue tuple unchanged | It preserves the congruence/precision relation, not each numerical coordinate. `F(x)=2x` sends 1 to 2 modulo 3. State evolution must preserve the declared phase relation. |
| PDF pp. 32/46: degree alone bounds fixed points and excludes resonant behavior | A root bound applies to the nonzero polynomial `F(x)-x`. Identity has degree one and fixes the whole field. Additional dynamical hypotheses are required. |
| PDF pp. 31/39: the 121/49 chimera uses both residue rings and quadratic fields interchangeably | `Z/p²` and `F_(p²)` have different characteristics and are not isomorphic rings. A carrier's algebraic type and its transported semantic type must be stated separately. |

The reference also assigns different S1/S5 meanings from the PDF's shadow-uniqueness discussion. Formalization must pin the candidate set, exact predicates and operator domain. Historical carried ledgers (PDF p. 46), Garner paths (pp. 40/43–44) and primary-prime adjoining (p. 47) are superseded for the selected runtime by the owner's current derived-only, fixed-primary requirements.

No application-specific PDE, physical synchronization, historical-intent or cryptographic-security conclusion is imported into CRAM closure by this note. The source itself contains unresolved application dependencies.

## Executed finite checks

The [integer-only probe](clarification-evidence-2026-11-17/dependent_sister_probe.py) was executed from the delivery tree; its [results](clarification-evidence-2026-11-17/dependent_sister_probe_results.json) passed. It enumerated all 11,011 pairs of residues modulo 77 and 143, identified exactly 1,001 compatible pairs, and checked them against the independent integer oracle. All 1,001 compatible inputs preserved the phase relation under `F(x)=x²+3x+7`; a mismatched update was rejected. It also checked the stated unit orders and unique order-five lift, and 334 linear-pair root cases.

Run with `python docs/proofs/cram/clarification-evidence-2026-11-17/dependent_sister_probe.py`. This is reference evidence for the small examples and corrections, not a production observation producer, an infinite-family test or a machine-checked proof.

## Updated closure work

1. Register immutable primary roles and operation-specific capabilities, including the reserved 2/11 duties and each family signature's precise meaning.
2. Define authentic sister constructors and shared-interface/phase maps for arbitrary positive moduli; prove source binding and role preservation.
3. Prove that every admitted joint or heterogeneous operator preserves those maps. Derive automatic invariant inheritance by induction.
4. Prove compatible refinement and the selected StarLift producer recurrence; keep all scalar winding proof-only or query-local.
5. Refine these statements to the actual runtime, including schema, serialization and negative controls. Existing 235-declaration Lean evidence remains unchanged.

See the maintained [core specification](../../../lean4/CRAMUniversal/docs/cram/CORE_SPEC.md), [obligation ledger](../../../lean4/CRAMUniversal/docs/cram/PROOF_OBLIGATIONS.md) and [fixed-primary clarification](FIXED_PRIMARY_SISTER_TRAYS_2026-11-17.md).
