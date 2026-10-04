# R03 public-bootstrap tuple decision: BLOCKED_DESIGN

No complete native public-bootstrap tuple is admitted. The generated
[candidate ledger](../../../artifacts/execution/bootstrap_candidates.json) is
reproducible with `python3 scripts/bootstrap_candidate_search.py --self-test
--output artifacts/execution/bootstrap_candidates.json`. Its self-test executes
nine assertions, including refusal of a corrupted product width and malformed
NTT primes. The script verifies the archived canonical probe and oracle hashes
against current source before using their results. This is a pre-admission
decision, not acceptance of R03: its R02 operation schedule, R01 live input
radius and V00 joint security disposition do not yet exist.

The current four through eight prime NINE65 chains are too small for the
*existing full-domain canonical-lift circuit and its certificate*. In the
ledger, `first_failing_inequality` is chosen in constructor order: exact
arithmetic capacity, then the in-tree security screen, then the first
canonical noise refusal. This ordering does not make one gate cure another.
All fourteen named and catalog-prefix cases are retained, including duplicate
names for the same actual tuple.

| Current tuple or prefix | Exact Q bits | First known refusal |
| --- | ---: | --- |
| `secure_128` and `secure_128_deep`, N=8192 | 119 | Canonical error 131 > 86 half-scale bits at depth 1 |
| `secure_192`, N=16384 | 146 | Canonical error 137 > 113 at depth 1 |
| `secure_256`, N=16384 | 175 | Binding screen 240 < declared 256-bit target |
| N=8192, catalog 4/5 | 119/146 | Canonical error 131 > 86/113 at depth 1 |
| N=8192, catalog 6/7/8 | 177/206/235 | Auxiliary need 222/251/280 > 220 bits |
| N=16384, catalog 4/5/6 | 119/146/177 | Canonical error 136/136/196 > 86/113/144 at depth 1/1/2 |
| N=16384, catalog 7/8 | 206/235 | Fallback accumulator 287 > 256 bits |

These are refusals for the archived canonical circuit; a bounded-digit circuit
may have a different error schedule. More CRAM lanes can increase exact
arithmetic capacity, but cannot by themselves certify a BFV noise margin or a
security target. The canonical sweep estimates 536,870,912 ciphertext
multiplications at N=8192, so key generation for that rejected path would
also be an expensive detour. The ledger retains its theoretical operation,
automorphism and key-payload counts with labels that forbid interpreting them
as measured work.

The independent Fheanor 0.11.9 reference provides valuable **functional-only**
evidence. At N=1024 and exact `log2(Q)` bit length 810, a B=17 run passed
three refresh-and-square rounds. At N=1024/Q=990, B=32 passed three; at
N=8192/Q=990, B=32 passed two and used a measured peak of 1,249,992 KiB.
The separate N=1024, nominal Q≈820, B=32 trial failed its second refresh
with a plaintext mismatch; it has no completed result tuple, so the ledger
does not invent its exact primes or a failing inequality. Successful trials
checked every coefficient each round. Their positive measured noise budgets
are diagnostics, not worst-case input support or a security attestation.

For all completed reference tuples, the ledger independently checks each
64-bit prime, `2N | (q_i-1)`, and `2N | (65537-1)` for degree-one plaintext
slots. It computes `log2(Q)` as the bit length of the integer product, not a
sum of lane widths. It checks run/result hashes, exit success and positive
all-coefficient rounds. Reference run time, peak memory and Galois-key count
are measured metadata; key payload and complete circuit multiplication count
remain unknown until the exact native circuit is frozen. The N=8192/Q=990
demo is far outside the cited 128-bit ternary standard table's ≈202-bit Q
allowance, and its sparse temporary key has no standard-table recommendation.
The N=1024 trials likewise have no joint security disposition. None is a
production candidate.

The proposed N=32768, Q≈810, B=17 direction has valid *plaintext slot
geometry* because `2N=65536` divides `65537-1`. It is not an exact candidate:
no ordered Q-prime list, certified bounded-digit DAG, live radius proof,
return-key error schedule or external assessment has been frozen. The next
admission pass must evaluate each stage of one exact tuple: input history and
radius, transforms, temporary-key switch, nonlinear digit removal,
contraction, return key, one subsequent multiplication and the next refresh.
Each stage needs arithmetic widths, auxiliary NTT supply, error bounds,
required public keys, payload size and operation count. V00 must assess all
key distributions, evaluation-key samples and relationships jointly before
expensive production key generation. Until those prerequisites are available,
the public refresh gate stays closed.

This decision uses the source-bound [canonical feasibility report](../../../docs/PRIME_POWER_LIFT_FEASIBILITY_2026-09-28.md), the [reference route and its
limits](../../../docs/PUBLIC_FHE_SOLUTION_2026-09-28.md), and the preserved
[CRAM architecture contract](PLAN.md). R03 remains `blocked_design`, and M2
cannot be claimed from these artifacts.
