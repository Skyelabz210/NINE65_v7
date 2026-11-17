# Identify the remembered star sequence before extending its interpretation

The user recalls very large jumps after few steps, a six-point star, possible
twin primes on its sides, a Chinese name resembling I Ching, and four stacked
"calendars" interpreted as lattices. These clues do not yet specify one
mathematical sequence. An optional identification question is pending. The
prior 36/37 -> 72/73 construction remains valid, but is not presumed to be the
particular growing sequence the user remembers.

## Three plausible growth mechanisms

| Candidate | Checked values | What grows |
|---|---|---|
| Ordinary star numbers / their prime subsequence | 1,13,37,73,121,181,... / 13,37,73,181,337,... | S_n=6n(n-1)+1 grows quadratically; selecting prime members introduces gaps |
| "Superstar primes," as defined on the secondary reference below | 661 and 1,750,255,921 | Prime star numbers whose positions in the ordered prime list are themselves star numbers |
| Products of distinct star-prime anchors at fixed shell 36 | 37; 2,701; 488,881; 164,752,897; 71,338,004,401 | The quotient observation period multiplies when a coprime authentic anchor is added |

A fourth candidate relevant to residue moduli is the primorial sequence:
2,6,30,210,2310,30030,510510,9699690,... . The existing six-prime Safe Basis has
product 30030. This is independently defined from the star sequence.

The term "superstar prime" was located on a secondary page, not a definitive
primary historical source. Its two stated examples were independently checked:

    661 = S_11 = the 121st prime,       121 = S_5;
    1,750,255,921 = S_17080
                 = the 86,526,037th prime,
    86,526,037 = S_3798.

Both primalities were verified by complete trial division as well as SymPy;
prime ranks were computed with SymPy 1.14.0 `primepi`. Membership of the two
examples is established by these computations. We did not enumerate every
intermediate candidate to certify the page's assertion that these are the
first two. The user's remembered sequence remains unidentified.

For modulus growth, the anchor-product explanation is directly represented in
the supplied CRAM lift document, section 5.4 and section 6.1: 37 and 73 give
quotient period 2701. Extending with 181,337,433 gives the table above. These
are products, not successive star primes. With fixed shell 36 the full source
period is 36 times the quotient period. Every extra reading must be authentic;
old readings alone do not generate new information. Also only 37 is adjacent
to fixed shell 36: the generic 73/181/... readouts require the appropriate
inverse, rather than automatically inheriting the subtraction-only formula.

## State the twin-prime claim before testing its generality

Several different statements could be meant by "before and after":

* Adjacent integers on either side of an odd prime are even. They cannot be a
  twin-prime pair once those neighbors exceed 2.
* A twin partner to an odd prime differs by 2. Not every ordinary star prime
  has one: 37-2=35=5*7 and 37+2=39=3*13.
* The neighbors of the star shell S_n-1 are S_n-2 and S_n. These sometimes
  form twins, such as 11/13 around 12 and 71/73 around 72. The shell 36 has
  35/37, so the universal statement for all star shells is false.
* Primorial neighbors are not always both prime: 210-1=209=11*19,
  and the user's own basis product satisfies 30030+1=30031=59*509.

The two checked superstar candidates both have a prime at p-2. This observation
does not settle a conjecture confined to that narrower class; the counterexample
37 above concerns ordinary star primes, since 37 does not meet the superstar
definition. Every star number is 1 modulo 12, so p+2 is divisible by 3; any
twin partner of a prime star number must be the lower p-2 member.

For all twin-prime pairs above (3,5), the midpoint is divisible by 6. This is a
necessary sieve condition: otherwise one of the odd neighbors is divisible by
3. It is not sufficient: 35 and 37 flank 36. None of the usable lift identities
requires a twin-prime guarantee.

## The four named structures are actually in the repository

At DCCMS commit `40a76158970c41440ec7e4c10437fa1c2e271d03`,
`dccms_atlas/src/heads.rs` defines `FourCalendarHydra` with:

| Source head | Implemented cycle | Distinct semantics |
|---|---:|---|
| Tzolkin | 260 | First phase projection |
| Haab | 365 | Second phase projection |
| CalendarRound | 18980 | Joint 260/365 period |
| LongCount | 144000 | This implementation truncates its head to one baktun; the historical Long Count is a positional count |

They can be modeled as coupled modular structures. That mathematical model is
compatible with calendrical use; it does not establish that their historical
function was exclusively computational or non-calendrical.

For full phase readings on a shared count, the kernel of the joined observation
is the intersection of the individual kernels:

    intersection_i (m_i Z) = lcm(m_1,...,m_4) Z.

Thus the full-phase period is 136656000. Adding the four cycles in the order
above increases resolution by factors 260,73,1,7200. The Calendar Round adds
no new information once full 260 and 365 readings are already present, though
it can give another useful operator/schema view.

The implemented `four_head_address` does not output those full phase readings.
It compresses each head to six zero/nonzero residue bits; `flat_address` packs
24 bits. There are at most 16777216 such labels, fewer than 136656000 full
phase states. Accordingly that packed signature cannot be an exact inverse
for the entire common phase. Query-specific sufficiency remains possible and
should be tested against the query's fibers. This is an information bound and
source inspection, not a fresh execution of the Rust implementation.

## The likely Chinese name and the geometry distinction

The likely remembered name is **I Ching**, also written **Yijing**, the Book of
Changes. David K. Jordan's UC San Diego exposition describes its hexagrams as
six broken or unbroken lines, assembled from two three-line trigrams, giving
64 configurations. A geometric hexagram is a six-point star; MathWorld uses
that geometric sense for star-number arrangements.

There is also a specifically relevant modern source: the page "The Hexagram"
at iching-hexagrams.com explicitly redraws hexagrams as stars in a circle and
describes the Receptive figure as a six-point star. It combines that drawing
with zodiac and other esoteric correspondences. This is a plausible lead to
the user's remembered picture; it is not evidence of a traditional star-prime
theorem or a historically established connection to the Dresden manuscript.
No mathematical twin-prime proof was identified in the inspected passage.

## Sources and verification scope

1. [MathWorld: Star Number](https://mathworld.wolfram.com/StarNumber.html):
   geometric definition and ordinary sequence.
2. [OEIS A083577](https://oeis.org/A083577): ordinary prime star sequence.
3. [OEIS A002110](https://oeis.org/A002110): primorial definition and sequence.
4. [Star number, secondary page](https://en.wikipedia.org/wiki/Star_number):
   the "superstar" terminology and two example values; specific memberships
   verified computationally here.
5. [Caldwell and Gallot, Mathematics of Computation](https://doi.org/10.1090/S0025-5718-01-01315-1):
   primorial/factorial primality research; inspected the abstract and opening
   discussion, not the entire article's proofs.
6. [David K. Jordan, UC San Diego](https://pages.ucsd.edu/~dkjordan/chin/Baguah.html):
   trigrams, six-line hexagrams and historical terminology.
7. [Modern I Ching star drawings](https://www.iching-hexagrams.com/hexagrams/the-hexagram/):
   a possible visual reference, not mathematical or historical validation.
8. [Pinned DCCMS heads](https://github.com/Skyelabz210/dccms/blob/40a76158970c41440ec7e4c10437fa1c2e271d03/dccms_atlas/src/heads.rs):
   actual four-head definitions and compression path.
9. Supplied `CRAM K-Elimination, Lifts, and Exact Reconstruction`, sections
   5.4/6.1: documentary evidence of multiplicative star-anchor capacity.

Five search calls requested 23 result slots; seven unique web pages were then
fetched, with a second, longer fetch of the UCSD page to inspect its six-line
section. Search result counts are not counts of independently evaluated papers.
No externally retrieved full-page body is included in this packet.

Run `python3 check_candidates.py` with `sympy==1.14.0`. The adjacent
`verification.json` records exact values, factorizations, source hash when the
prior DCCMS snapshot is present, and explicit limits. This adds source
identification and exact finite calculations, not new Lean results or a new
physical/historical test.
