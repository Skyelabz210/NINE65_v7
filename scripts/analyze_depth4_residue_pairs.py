#!/usr/bin/env python3
"""Test-only independent integer audit of exported depth-4 residue pairs.

The Rust diagnostic exports residues to /tmp. This script never runs in the
FHE path and uses Python integers as an external oracle for the exact signed
lift and the two candidate BFV scale rules.
"""

import json
import sys
from hashlib import sha256
from math import prod

MAIN = [998244353, 985661441, 754974721, 469762049]
ANCHOR = [
    2013265921, 2281701377, 2483027969, 2885681153,
    3221225473, 3221422081, 3222306817,
]
MODULI = MAIN + ANCHOR
Q = prod(MAIN)
P = prod(MODULI)
N = 8192
T = 65537
DELTA = Q // T
WEIGHTS = [(P // m) * pow(P // m, -1, m) % P for m in MODULI]
Q_WEIGHTS = [(Q // m) * pow(Q // m, -1, m) % Q for m in MAIN]


def crt(residues, weights, modulus):
    return sum(r * w for r, w in zip(residues, weights)) % modulus


def round_away_zero(x, divisor):
    q = (abs(x) + divisor // 2) // divisor
    return -q if x < 0 else q


def parse_residues(field):
    return [int(v) for v in field.split(",")]


def negacyclic_coefficient_zero(c1, s):
    return c1[0] * s[0] - sum(c1[i] * s[N - i] for i in range(1, N))


def decode(c0, c1, s):
    phase = (c0[0] + negacyclic_coefficient_zero(c1, s)) % Q
    plaintext = (phase * T + Q // 2) // Q % T
    return plaintext, phase


def analyze(path):
    with open(path, "rb") as raw:
        source_sha256 = sha256(raw.read()).hexdigest()
    # With ternary s and canonical |c_i|<Q, the folded p0 coefficient is at
    # most (N^3+N)Q^2 in magnitude. We allow an extra NQ^2 for p1 and still
    # remain well inside the combined main+anchor signed CRT interval.
    bound = (N ** 3 + 2 * N) * Q * Q
    assert 2 * bound < P, "independent signed CRT lift is not certified"
    records = [[], []]
    secret = []
    with open(path, encoding="utf-8") as stream:
        header = stream.readline().strip()
        assert header.startswith("# n=8192 ") and "expected=65536" in header, header
        declared = dict(field.split("=", 1) for field in header[2:].split())
        rust_decoded = int(declared["decoded"])
        for expected_i, line in enumerate(stream):
            fields = line.strip().split("\t")
            assert len(fields) == 11 and int(fields[0]) == expected_i
            s_main = parse_residues(fields[9])
            s_anchor = parse_residues(fields[10])
            candidates = [z for z in (-1, 0, 1) if all(z % p == r for p, r in zip(MAIN, s_main))]
            assert len(candidates) == 1
            s = candidates[0]
            assert all(s % a == r for a, r in zip(ANCHOR, s_anchor))
            secret.append(s)
            for component in range(2):
                offset = 1 + 2 * component
                input_main = parse_residues(fields[offset])
                input_anchor = parse_residues(fields[offset + 1])
                output_main = parse_residues(fields[5 + 2 * component])
                output_anchor = parse_residues(fields[6 + 2 * component])
                x = crt(input_main + input_anchor, WEIGHTS, P)
                if x > P // 2:
                    x -= P
                assert abs(x) <= bound, (expected_i, component, x.bit_length())
                assert all(x % m == r for m, r in zip(MODULI, input_main + input_anchor))
                delta_y = round_away_zero(x, DELTA) % Q
                bfv_y = (T * x + Q // 2) // Q % Q
                actual = crt(output_main, Q_WEIGHTS, Q)
                assert all(actual % p == r for p, r in zip(MAIN, output_main))
                assert all(actual % a == r for a, r in zip(ANCHOR, output_anchor))
                records[component].append((x, actual, delta_y, bfv_y))
    assert len(secret) == N

    result = {"schema": "nine65-depth4-coefficient-audit-v1", "source": path,
              "source_sha256": source_sha256,
              "rust_decoded": rust_decoded,
              "n": N, "q_bits": Q.bit_length(), "combined_bits": P.bit_length(),
              "signed_bound_bits": bound.bit_length(), "components": []}
    for component, rows in enumerate(records):
        delta_bad = [i for i, (_, actual, d, _) in enumerate(rows) if actual != d]
        bfv_bad = [i for i, (_, actual, _, b) in enumerate(rows) if actual != b]
        delta_vs_bfv = [i for i, (_, _, d, b) in enumerate(rows) if d != b]
        result["components"].append({
            "component": component, "actual_vs_delta_mismatch_count": len(delta_bad),
            "first_actual_vs_delta_mismatch": delta_bad[0] if delta_bad else None,
            "actual_vs_bfv_mismatch_count": len(bfv_bad),
            "first_actual_vs_bfv_mismatch": bfv_bad[0] if bfv_bad else None,
            "delta_vs_bfv_count": len(delta_vs_bfv),
            "first_delta_vs_bfv": delta_vs_bfv[0] if delta_vs_bfv else None,
            "max_input_bits": max(abs(x).bit_length() for x, _, _, _ in rows),
        })
    for label, columns in (
        ("actual", [1, 1]), ("delta_oracle", [2, 2]),
        ("bfv_oracle", [3, 3]), ("bfv_c0_only", [3, 1]),
        ("bfv_c1_only", [1, 3]),
    ):
        c0 = [row[columns[0]] for row in records[0]]
        c1 = [row[columns[1]] for row in records[1]]
        plaintext, phase = decode(c0, c1, secret)
        result[label] = {"plaintext": plaintext, "phase": str(phase)}
    assert result["actual"]["plaintext"] == rust_decoded
    return result


if __name__ == "__main__":
    source = sys.argv[1] if len(sys.argv) > 1 else "/tmp/nine65-depth4-zero-error-residue-pairs.tsv"
    print(json.dumps(analyze(source), indent=2))
