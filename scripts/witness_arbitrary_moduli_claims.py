#!/usr/bin/env python3
"""Witness script: WP_ARBITRARY_MODULI claims, checked by execution.

Checks the load-bearing arithmetic claims of "Arbitrary Moduli in RNS-FHE —
A Formal Proof of Constraint Dissolution" (Diaz, Aug 2026) against actual
integer arithmetic. Exact integers only; no floats, no sampling estimates
where an exhaustive or wide check is available.

Why this exists: the paper ships Lean-shaped snippets labelled "0 sorry",
but section 5.2's own proof body contains `sorry`, several snippets use
Lean 3 syntax or identifiers containing spaces, and two theorem STATEMENTS
are wrong as written. A claim that has been executed beats a claim that has
been labelled. This is the same rule the project's own execution plan states
at Phase 4.4: keep the mathematics, drop the labels.

Exit code 0 iff every claim's *measured* status matches what this script
records below. A future edit to the paper that fixes U3/U6 should flip those
entries here too.

Run:  python3 scripts/witness_arbitrary_moduli_claims.py
"""

from __future__ import annotations

import random
import sys


def inv(a: int, m: int) -> int:
    """Modular inverse via Python's exact integer pow. No floats."""
    return pow(a, -1, m)


failures: list[str] = []
notes: list[str] = []


# ---------------------------------------------------------------------------
# U2 — star family:  q = c*t + 1  =>  q == 1 (mod t)  and  t^-1 mod q == q - c
# Paper section 3.2. VERIFIED: holds, including composite t and composite c.
# ---------------------------------------------------------------------------
def check_u2() -> None:
    held = 0
    for t in [65537, 1024, 12, 100, 3, 2**16]:  # prime AND composite plaintext moduli
        for c in [1, 2, 3, 7, 100, 1001, 99991, 2**20]:
            q = c * t + 1
            if q % t != 1:
                failures.append(f"U2 transparency: q={q} t={t} -> q%t={q % t}, expected 1")
                continue
            try:
                actual = inv(t, q)
            except ValueError:
                failures.append(f"U2: t={t} has no inverse mod q={q}")
                continue
            claim = (q - c) % q
            if claim != actual:
                failures.append(f"U2 free inverse: t={t} c={c} q={q}: q-c={claim} != t^-1={actual}")
            else:
                held += 1
    notes.append(f"U2  star family q=c*t+1, t^-1 = q-c        : {held} cases hold  [HOLDS]")


# ---------------------------------------------------------------------------
# A3 — Universal Projection: X = gamma + K*M  =>  X mod A is a lanewise read
# for EVERY A, with no coprimality or primality precondition.
# Paper section 1.3. VERIFIED: holds.
# ---------------------------------------------------------------------------
def check_a3(trials: int = 50_000) -> None:
    rng = random.Random(20260822)
    bad = 0
    for _ in range(trials):
        gamma = rng.randrange(0, 10**7)
        k = rng.randrange(0, 10**7)
        m = rng.randrange(2, 10**7)
        a = rng.randrange(2, 10**7)  # deliberately NOT coprime-filtered
        x = gamma + k * m
        if x % a != (gamma % a + (k * m) % a) % a:
            bad += 1
    if bad:
        failures.append(f"A3 universal projection: {bad}/{trials} failures")
    notes.append(f"A3  universal projection, arbitrary A      : {trials - bad}/{trials} hold  [HOLDS]")


# ---------------------------------------------------------------------------
# U3 — elastic capacity via adjacency A = P + 1.
# Paper section 4.2 STATES:  X mod A == (gamma + K) mod A
# MEASURED: false in general. Since A = P+1, P == -1 (mod A), so K*P == -K,
# giving (gamma - K). The paper has a sign error.
# ---------------------------------------------------------------------------
def check_u3() -> None:
    as_written_ok = 0
    corrected_ok = 0
    total = 0
    for p in [7, 100, 1001, 998244353, 2**31 - 1]:
        a = p + 1
        for gamma in [0, 1, 5, p - 1]:
            for k in [0, 1, 2, 37, 1000]:
                x = gamma + k * p
                total += 1
                if (gamma + k) % a == x % a:
                    as_written_ok += 1
                if (gamma - k) % a == x % a:
                    corrected_ok += 1
    if corrected_ok != total:
        failures.append(f"U3 corrected form (gamma-K) failed {total - corrected_ok}/{total}")
    if as_written_ok == total:
        failures.append("U3: paper's (gamma+K) unexpectedly held everywhere - recheck this script")
    notes.append(
        f"U3  adjacency read: paper says (gamma + K)  : {as_written_ok}/{total} hold  "
        f"[SIGN ERROR AS WRITTEN]"
    )
    notes.append(f"U3  corrected      (gamma - K)             : {corrected_ok}/{total} hold  [HOLDS]")


# ---------------------------------------------------------------------------
# U6 — adjacency anchor A = P + 1.
# Paper section 7.2 STATES:  (P * A) % P == 1
# MEASURED: that expression is identically 0 -- P*A is a multiple of P by
# construction. The paper's own proof derives (P*P + P) % P = 0 and then
# concludes 1. The intended, TRUE fact is against modulus A, not P:
#   P == -1 (mod A)  =>  P * P == 1 (mod A)  =>  P^-1 mod A == P
# ---------------------------------------------------------------------------
def check_u6() -> None:
    as_written_ok = 0
    corrected_ok = 0
    total = 0
    for p in [7, 100, 1001, 998244353, 2**31 - 1]:
        a = p + 1
        total += 1
        if (p * a) % p == 1:
            as_written_ok += 1
        if (p * p) % a == 1 and inv(p, a) == p:
            corrected_ok += 1
    if corrected_ok != total:
        failures.append(f"U6 corrected form (P^-1 mod A == P) failed {total - corrected_ok}/{total}")
    if as_written_ok != 0:
        failures.append("U6: paper's (P*A)%P==1 unexpectedly held - recheck this script")
    notes.append(
        f"U6  anchor: paper says (P*A) %% P == 1      : {as_written_ok}/{total} hold  "
        f"[FALSE AS WRITTEN - always 0]"
    )
    notes.append(f"U6  corrected: P^-1 mod A == P             : {corrected_ok}/{total} hold  [HOLDS]")


# ---------------------------------------------------------------------------
# U1 consequence worth recording: the star family is what makes Delta exact.
# If Q is MANUFACTURED as t * D, then Delta = Q/t = D exactly, with no floor
# and no rounding term -- which is precisely what the BFV rescale cannot do
# when Q is a product of hunted NTT primes and t does not divide it.
# ---------------------------------------------------------------------------
def check_u1_exact_delta() -> None:
    held = 0
    total = 0
    for t in [65537, 12, 1024]:
        for d in [3, 1001, 2**20 + 1, 998244353]:
            q = t * d
            total += 1
            if q % t == 0 and q // t == d:
                held += 1
            else:
                failures.append(f"U1 exact Delta: Q={q} t={t} d={d}")
    notes.append(f"U1  manufactured Q = t*D => Delta exact    : {held}/{total} hold  [HOLDS]")


def main() -> int:
    check_u2()
    check_a3()
    check_u3()
    check_u6()
    check_u1_exact_delta()

    print("WP_ARBITRARY_MODULI — claims checked by execution")
    print("=" * 70)
    for n in notes:
        print("  " + n)
    print("=" * 70)

    if failures:
        print(f"\n{len(failures)} unexpected result(s):", file=sys.stderr)
        for f in failures:
            print("  " + f, file=sys.stderr)
        return 1

    print(
        "\nSummary: U1(exact-Delta consequence), U2 and A3 hold as stated.\n"
        "U3 and U6 are WRONG AS WRITTEN in the paper and hold only in their\n"
        "corrected forms. Implementing U3 as published would introduce a sign\n"
        "error; implementing U6 as published would assert a false identity.\n"
        "Section 5.2's Lean body contains `sorry` while section 11 claims 0."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
