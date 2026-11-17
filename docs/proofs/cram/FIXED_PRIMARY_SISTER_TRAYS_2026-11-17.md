# Architecture clarification: fixed primary, dependent sister trays

2026-11-17. This records the owner's clarification after the initial proof publication at `137d970`. It amends the interpretation of the architecture, not the frozen evidence or the checked Lean statements.

The subsequent [complete Prime Family review](PRIME_FAMILY_RECONCILIATION_2026-11-17.md) supplies the source's role/family emphasis and its conditional property-transfer principle (PDF p. 35). The intended inheritance is structural: composite sisters preserve specified roles and signatures through certified maps and operations. The review also records corrections needed before individual source claims become registered invariants.

## The intended machine

The primary Safe Basis stays intact and fixed. No runtime operation adds, removes or replaces one of its moduli. Roles 2 and 11 remain present, and the designated shadow-11 observation is reserved for disambiguation/phase duties.

Additional sister trays may use arbitrary positive moduli. Their dependence comes from an actual phase/source/operation relation to the primary and other required state. They are not independent replacements for the primary basis. A sister observation need not be a function of the primary snapshot alone.

Depth or precision can grow within the compatible sister system without a fixed global magnitude ceiling. The primary is unchanged. K is queried from observations; it is not maintained as an independent scalar magnitude or winding ledger.

Earlier mathematical examples involving a payload product excluding 11, joint 2/11 coordinates, or independent anchor extension must not be mistaken for instructions to alter the primary tray. A factorization used in a proof does not remove a lane from the machine.

## What automatic inheritance must prove

Let x be the semantic source, a proof variable rather than a stored integer. For the primary B and sisters j, define the joint representation relation by the declared maps:

    Rep(x,b,(s_j)) := b=h_B(x) and, for every j, s_j=h_j(x).

An explicitly richer phase relation may replace these equations where needed. For every admitted instruction F, the real joint update must preserve Rep and leave B unchanged. Cross-tray dependencies are permitted when declared; the proof must not assume independent per-lane updates for operations that need the joint state.

For a primary invariant I_B and claimed sister invariant I_j, prove:

    I_B(b) and R_j(b,s_j) imply I_j(s_j).

Correct initialization and preservation of R_j make this inheritance automatic throughout admitted execution. The remaining work is to establish those premises for the actual producer and operators. Ring-local properties such as units and field structure are separate from transported source invariants; arbitrary sister moduli are not excluded merely because they overlap the primary's factors.

## Unbounded tower formulation

For a p-adic instance with p not dividing M, fixed remainder r and authentic compatible sister readings a_n modulo p^n, define

    k_n = (a_n-r)*inverse(M,p^n) mod p^n.

The inverses and readouts commute with reduction: k_(n+1) mod p^n = k_n. The winding component therefore defines a unique p-adic element. For integer-source observations, it is the embedded integer quotient. This statement has no fixed global bound on the source. A finite precision level is not a ceiling on the whole compatible family.

For fixed-main 36/37 StarLift, the level-one inverse is -1; at precision 37^n the compatible inverse is -sum_(j<n)37^j. An actual constructor must establish its chosen level maps. Merely applying the level-one constant at every precision is not that proof.

Likewise, a declared shadow readout with gcd(M,11)=1 and authentic successive states X_next=X+M*delta recovers delta modulo 11 from the shadow difference, independently of absolute source magnitude. This equation's M is not automatically the full primary product. Nonunit cases retain their reduced query resolution. A sufficient local increment interval or additional sister precision resolves the desired increment. Recovering arithmetic trajectory and authentic instruction provenance are distinct transported queries.

These are written mathematical obligations and derivations. They do not add declarations to the existing 235-declaration Lean audit.

## What the inspected code establishes

- NINE65's `Shadow11Plan` derives and discards a temporary increment; its current callers are tests. The separate `PhaseLock22` is another reference profile. Five focused phase-lock tests passed in the follow-up inspection; they do not execute the complete live sister producer.
- The current `cram_ct` shadow-edge branch compares a target-11 snapshot. Its graph label alone does not prove a relation involving source 2.
- The uploaded `certified_lift` stores exact input magnitude in `Lift.bound` and propagates it through unsigned addition and multiplication. The earlier finding remains specific to that prototype, not a requirement of this intended architecture.
- Upstream DCCMS at `40a76158970c41440ec7e4c10437fa1c2e271d03` contains carried-winding reference structures. The related remaster at `ad0c8380f02b1d0c4f05a3e00726be3bc9680058` describes extensible towers, but relevant producers still use scalar inputs or stored K, and its named sister lock checks basis membership. Those implementations do not yet establish the required derived-only, source-bound transport path.

The next closure target is **primary immutability + authentic dependent observations + preserved phase relations + transfer of each named invariant**. It is not an independent-RNS replacement or a fixed ceiling on the proposed tower.

The [follow-up evidence](clarification-evidence-2026-11-17/) contains the focused Rust execution record, exact-integer continuous/p-adic-prefix probe, and 325-case remaster reference smoke check. These finite checks are scoped evidence; they do not certify the complete live producer or an infinite-limit implementation. Newly supplied source documents and private/internal extracts are not republished with this clarification.
