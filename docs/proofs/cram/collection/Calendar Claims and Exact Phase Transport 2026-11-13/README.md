# Calendar arithmetic, formal transport and the limits of the cosmological passage

The supplied passage combines correct integer identities, useful possible
representations, false statements about those representations, and unverified
historical/physical interpretations. **The Lean proofs do not establish that
the Dresden Codex is an operating system of the universe.** They establish
conditional mathematical transport results. A calendar can indeed be a target
query on a richer state; that does not negate its calendrical use or identify
the richer state with the physical universe.

This audit preserves a constructive result: for the chosen integer periods,
the joint 260/365/584 observation leaves **exactly 23 possible phases modulo
11,960**. An authentic residue modulo 23 resolves them. A new bounded query
constructor and an inverse with a retained 73-lane passed **873,080 complete
observation states**. This computes a modeled phase, not eclipse occurrence.

## 1. What the formal files actually say

`UniversalLift.lean:target_factor_exists_iff` says that an additive target C
factors through an additive observation B on its genuine observation image
exactly when ker(B) is contained in ker(C). `ExactObservation.lean:recoverable_iff`
gives the more general set-theoretic condition: equal observations must imply
equal requested answers. The existence proof uses classical choice; concrete
efficient decoders are separate constructions.

Neither statement asserts that physical reality is an integer, that any
particular manuscript implements the maps, or that an eclipse/deity corresponds
to a CRAM state. These are not variables or established hypotheses in the
formal theorem. The letter B as a basis field in an eight-tuple must also not
be conflated with the linear observation map called B in an interpretation.

**Factorization is not automatically an isomorphism.** For example, observing
X modulo 6 suffices to answer X modulo 3. The transport sends both classes 0
and 3 modulo 6 to 0 modulo 3, so it is not injective. Generally the first
isomorphism theorem identifies K/ker(B) with im(B); kernel inclusion permits
a further target projection. Equality of kernels gives an isomorphism between
the two observation images. Recovery of the entire source requires an
injective observation on the admitted domain.

A fixed finite tuple cannot injectively encode arbitrary unbounded integers.
The source restriction or additional observations in the existing proofs are
substantive. For cyclic integer observations of periods m_i, the kernel is
lcm(m_i) Z. It does not "reset" at one period; the reading returns while the
kernel remains the same subgroup.

The previously checked formal files were inspected, not modified or rebuilt
for this audit. No new Lean declaration, cryptographic security claim or
physical law is asserted here.

## 2. Claim ledger

| Claim in the passage | Audit result |
|---|---|
| A calendar may be a target query on a richer common state | Valid mathematical modeling choice; the actual state and query must be specified |
| The universe is an unbounded integer X | Additional physical postulate, not a consequence of the universal theorem |
| The Codex is the observation kernel / a proved physical CRT realization | Not established; a map, its kernel and a material implementation are different objects |
| Kernel inclusion proves an isomorphism of microscopic and macroscopic reality | False inference; it proves query factorization under stated hypotheses |
| Calendar periods are independent coprime Safe Basis lanes | False as stated; periods overlap and differ from the six-prime basis |
| 260=4*5*13; 365=5*73; 584=8*73; 780=4*3*5*13; 819=7*9*13 | Correct factorizations |
| 260 is the smallest saturated basis for unspecified lower functions | No defined optimization target or proof; many coprime bases have bijective CRT maps |
| 73 being a star prime establishes a physically stable solar anchor | Does not follow; 365 is an integer calendar period approximating the solar year |
| lcm(260,365)=18980 and 5*584=8*365=2920 | Correct integer identities; not exact periods of real planetary motion |
| Calendar Round is the maximum resolution of the whole machine | Only the resolution of the particular 260/365 observation; added data can refine it |
| Long Count advances only when Calendar Round completes | Incorrect: its kin coordinate advances daily |
| Long Count is a cryptographic accumulator | A modern analogy, with no cryptographic security definition or historical evidence supplied |
| Gods are cryptographic/operator states rather than deities | Unverified reassignment; astronomical and calendrical associations do not remove religious meanings |
| 11960 leaves a 23-day residual or is a maximum entropy constant | Unsupported as written; 23 is a prime factor and can be an ambiguity count in a specified observation model |
| The eclipse table cannot be integrated because of factor 23 | False algebraically; enlarge the observation with suitable authentic data |
| The table implements firmware update / winding vanish / entropy reset | Historical and operational hypotheses requiring instructions and state transitions, not established facts |
| The 819-day period is necessarily an operator-topology switch and not astronomical | Unsupported; peer-reviewed work explicitly investigates its planetary commensurations |
| Profinite implies a finite state space | False: a profinite inverse limit can be infinite; the profinite integers are uncountable |
| Continuum/time is an illusion proved by these results | Not established by the mathematics or inspected physical evidence |
| 36/37 alone determines unrestricted 260/365 phases | False without further observations or a valid source window |
| Writing multiple Long Count glyphs proves the no-emission invariant | False inference: mixed-radix positional notation is not an execution trace |
| Exact modular arithmetic proves exact astronomical alignment | False inference: physical models, observations, epoch and errors remain separate premises |

## 3. The calendar lattice that can actually be specified

The listed periods are not mutually coprime:

    gcd(260,365)=5,    gcd(365,584)=73,
    gcd(260,584)=4,    gcd(260,780)=260.

Their individual prime-power factorizations can be combined with generalized
CRT, subject to compatibility on shared factors. For full phase readings,
the joined observation has the following exact resolution:

| Newly included reading | Combined period | Additional resolution factor |
|---|---:|---:|
| X mod 260 | 260 | 260 |
| X mod 365 | 18980 | 73 |
| X mod 584 | 37960 | 2 |
| X mod 780 | 113880 | 3 |
| X mod 819 | 2391480 | 21 |

This is a concrete sense in which the structures can be stacked. For these
five modeled periods a pairwise-coprime prime-power presentation is
{8,9,5,7,13,73}. It differs from the six-prime Safe Basis
{2,3,5,7,11,13}, which has period 30030. Shared periods and powers cannot be
treated as automatically independent information.

The repository's compressed four-head signatures are yet another observation
type: they retain zero/nonzero bits, not these complete phase residues. The
preceding sequence-identification report documents that distinction.

## 4. What 23 means under an explicit source/target choice

For observations determining X modulo P, and target X modulo D, all compatible
sources have the form x_0+jP. Their target values form a coset of the subgroup
generated by P in Z/D. That subgroup has order D/gcd(P,D): the least positive
j satisfying D | jP is D/gcd(P,D).

Take P=lcm(260,365,584)=37960 and D=11960. Then

    D = 8*5*13*23 = 520*23,
    gcd(P,D)=520,
    D/gcd(P,D)=23.

Every old observation fiber therefore leaves exactly 23 possible modeled
eclipse-table phases. Since 23 is coprime to P, adding authentic X mod 23
gives lcm(P,23)=873080, divisible by D, and makes the target exact.
Merely naming the modulus 23 or factoring a period does not supply the new
source reading X mod 23.

The word "23" is not sufficient without its source observation:

| Existing full observation period P | Possible phases modulo 11960 | Least sufficient extra raw X-mod-a channel |
|---:|---:|---:|
| 30030, six-prime Safe Basis | 92 | a=184 |
| 18980, Calendar Round | 46 | a=184 |
| 37960, including the 584 phase | 23 | a=23 |

The least-extra-channel statements are by divisibility, for unrestricted
integer sources and one additional raw residue modulus. In the first two
rows the extra channel must supply the full missing 2^3 power together with
23, so 184=8*23. They are not lower bounds on all possible conditional
encodings. The prior proved gcd-saturation constructor yields respectively
92->184, 46->92->184 and 23->23.

If a uniform probability model is separately imposed on the 23 target
possibilities, their conditional Shannon entropy is log2(23) bits. Without
that distribution one has an ambiguity count, not an entropy value. This
provides no universal thermodynamic constant, no 23-day error, and no inference
that occlusion creates computational randomness.

### Direct residue query and reversible complete frame

The executable `eclipse_phase.py` accepts canonical authentic readings
r=X mod 260, v=X mod 584, w=X mod 23. Compatibility requires v-r divisible
by 4. Set

    e = ((v-r)/4) mod 2,
    u = r+260e,
    q = 5(w-u) mod 23,
    y = u+520q.

Then u=X mod 520 and y=X mod 11960. Proof: write X=r+260k and
v=X-584j. Thus (v-r)/4=65k-146j, whose parity is that of k, so u selects
the correct 520-residue. Since 520*5=1 modulo 23, q is the residual quotient
class needed to select the unique target representative y in [0,11960).

This constructs the requested bounded target residue; it does not reconstruct
unbounded X or maintain a scalar K. Reading authenticity, frame, origin and
epoch remain caller premises. The executable checks only types, canonical
ranges and overlap compatibility.

The complete observation is preserved if t=X mod 73 is retained:

    compatible (r260,v584,w23) <-> (y11960,t73).

Its inverse is

    r260=y mod 260,    w23=y mod 23,
    v584=t+73*((y-t) mod 8).

Both sides identify X modulo 873080. The formulas give inverse maps of the
compatible residue rings and therefore preserve their admitted arithmetic.
All 873080 source states and their roundtrips passed. Roundtrips use those
same states and are not counted as a second independent sample. Five signed
256-bit representatives, seven forward-input refusals and four inverse-input
refusals also passed.

**The output is an idealized table phase.** Whether a real solar eclipse occurs
at that phase is a different query requiring an astronomical model and
observations. A modular-phase test is not an eclipse-prediction experiment.

## 5. Long Count and the actual 13-baktun remainder

The standard positional reading is

    X = 144000*baktun + 7200*katun + 360*tun + 20*uinal + kin.

The Smithsonian converter and the repository's
`dccms_atlas/src/engines/long_count.rs` both give these place values. One day
after a chosen zero origin is 0.0.0.0.1, while floor(X/18980) is still zero.
After one Calendar Round the Long Count offset is 0.2.12.13.0, not a single
increment of its kin register. Full historical date labels also require an
epoch/correlation; these examples are offsets from a mathematical zero.

A Long Count can encode a full count from which any chosen winding is derived.
Its digits are not simply the single winding floor(X/18980). They are
mixed-radix positional coordinates, not independent CRT lanes. Writing a
number in several glyphs is analogous to writing several decimal digits: it
does not demonstrate that an algorithm never materializes that number.

There is nevertheless a relevant exact relationship:

    13*144000 = 1872000 = 98*18980 + 11960.

Thus the ideal 11960 value is the remainder of a 13-baktun span modulo the
Calendar Round. In this identity **11960 is the remainder; 23 is its factor**.
This arithmetic does not by itself identify historical intent or a maximum
entropy principle. No novelty/priority claim is made for the identity.

## 6. Historical evidence and sensitivity to the actual table

The Smithsonian describes Long Count daily counting, its positional places,
the 260/365 interlocking Calendar Round and the approximation of the solar
year by the Haab. That evidence supports both calendrical use and significant
mathematical sophistication. An additional computational interpretation must
be supported alongside, not substituted for, those observations by declaration.

Linden and Bricker (2023) investigate planetary commensurations across twenty
819-day periods. Their abstract explicitly describes the interpretation as
incomplete and open to further research. This does not establish that 819 is
an operator switch, nor justify declaring it unrelated to astronomy.

Justeson and Lowry (2025) distinguish the surviving **11959-day** eclipse table
from a commonly used **11960-day** model. They analyze 69 stations, 405 months,
variable intervals and possible overlapping restarts. Their proposed restart
procedures are historical/astronomical hypotheses with explicit calculations,
not evidence of a CRAM "firmware update." The present query constructor uses
the ideal 11960 modulus. Choosing 11959 as a different target changes the
arithmetic: 11959 is prime and coprime to 37960, so all 11959 target classes
remain possible from that source period alone. The correct model and reading
convention must be identified before interpreting factors as instructions.

The pasted "Shadow Entropy 23" and "From Dresden Codex to Profinite Manifold"
titles were not located as exact titles in the scoped local/Drive searches.
Three related Drive documents were retrieved. The shadow-entropy reference
defines a cryptographic byproduct-entropy concept and explicitly says that
arithmetic extracts rather than creates input entropy. It did not provide
the alleged eclipse/23 maximum-entropy theorem in the inspected text. The
other retrieved documents discuss profinite/adelic structures and modern
frameworks; none supplies the quoted historical/cosmological proof. This
audit does not validate their separate cryptographic or physical assertions.
Full retrieved text remains in the private research workspace, outside this
repository-ready packet. Search scope is not a proof those titled works do
not exist elsewhere.

## 7. Profinite does not mean finite or physically established

The profinite integers are

    Z_hat = inverse_limit_n Z/nZ = product_p Z_p.

Each finite-stage residue ring is finite. The compatible infinite families
form an infinite, uncountable compact space. The ordinary integers embed
injectively and densely in this completion; they do not exhaust it. A finite
residue snapshot, an unbounded integer and a complete profinite element are
different mathematical objects. A nontrivial profinite space is also not
automatically a manifold in the usual real-manifold sense.

Nothing in this construction establishes that physical time is an illusion
or that the universe is a finite automaton. Such a model needs explicit
physical state variables, measurement maps, evolution, units and predictions
that can be tested against alternatives. The formal transport theorem tells
us what follows once those premises are supplied; it does not establish them.

## 8. A testable research statement to retain

> The recognized integer periods admit compatible modular observations and
> exact target-query transfers. Universal K-Elimination characterizes when
> the observations suffice. Concrete extra observations resolve specified
> ambiguities. Whether particular manuscript signs implement those transfers
> is an archaeological hypothesis; whether a physical system obeys a proposed
> modular dynamics is an empirical hypothesis.

A historical operator test should choose a particular sign and page sequence,
freeze a transcription independent of the proposed opcode, identify every
input/anchor and predict held-out outputs. Competing positional/calendar
readings must be scored on the same material. A physical test separately
needs an observational prediction beyond reproducing integer identities or
existing ephemeris outputs. Neither requires abandoning the mathematical
construction when a particular interpretive hypothesis fails.

## Sources and reproduction

* [UniversalLift source](../swarm-campaign-2026-11-13/proofs/UniversalLift.lean):
  `target_factor_exists_iff`, `direct_target_query` and explicit hypotheses.
* [ExactObservation source](../swarm-campaign-2026-11-13/proofs/ExactObservation.lean):
  `recoverable_iff`, `collision_obstructs_query`, source injectivity conditions.
* [Least-anchor theorem](../swarm-campaign-2026-11-13/proofs/mathlib/AnchorSaturation.lean):
  previous formal support for the general least-sufficient-anchor construction.
* [Smithsonian calendar converter and explanation](https://maya.nmai.si.edu/calendar/maya-calendar-converter).
* [Linden and Bricker, 2023](https://www.cambridge.org/core/journals/ancient-mesoamerica/article/abs/maya-819day-count-and-planetary-astronomy/9839C2633BECD1356C94D4079E2580FE):
  abstract and bibliographic context inspected, not the paywalled full article.
* [Justeson and Lowry, 2025](https://www.science.org/doi/10.1126/sciadv.adt9039):
  selected table-design and 11959/11960 passages inspected; not a fresh
  independent epigraphic transcription or astronomical replication.
* [Pinned Long Count implementation](https://github.com/Skyelabz210/dccms/blob/40a76158970c41440ec7e4c10437fa1c2e271d03/dccms_atlas/src/engines/long_count.rs).

Two external searches requested seven result slots; three unique institutional/
scholarly pages were fetched, including a longer second fetch of the eclipse
paper. Four scoped Drive searches led to three related-document fetches.
The exact named source titles remain unverified. A source ledger records
retrieval scope and private text hashes without copying those texts here.

Run `python3 check_claims.py` in this directory (standard library only).
`verification.json` records the final executable hashes, cases and limits.
The original repositories, frozen protocols, previous evidence and security
gates are unchanged. The new constructor is research code; no encrypted
NINE65 run, production integration or physical measurement is reported.
