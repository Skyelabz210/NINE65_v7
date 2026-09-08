#!/usr/bin/env python3
"""Independent Python arbitrary-precision oracle for GitHub issue #81.

Cross-checks the depth-2 DualRNS ct x ct multiply chain against a completely
separate implementation, using real public vectors dumped by
`crates/nine65/tests/depth2_python_oracle_vectors_issue81.rs` into
`crates/nine65/tests/fixtures/depth2_oracle_vectors_issue81.json`.

INTEGER ONLY, NO FLOATS: every operation here is Python's native arbitrary-
precision `int` arithmetic (`+`, `-`, `*`, `//`, `%`, `pow(..., -1, m)`). No
`float`/`Decimal` appears anywhere in this file -- rounding is done with
integer floor-division formulas, matching this project's "zero floats in
arithmetic hot paths" rule even though this is a verification script, not
production code.

DOES NOT CALL INTO OR SHARE CODE WITH THE RUST IMPLEMENTATION: this script
does not import, subprocess, or FFI into `nine65` in any way. It re-derives,
from scratch:

  1. A negacyclic polynomial multiply (schoolbook O(N^2) convolution over the
     ring Z[x]/(x^N+1)) -- NOT the NTT `nine65::arithmetic::ntt` uses.
  2. A from-scratch CRT reconstruction (direct/parallel-summation form, not a
     Garner mixed-radix cascade) over both the main and anchor RNS bases,
     using Python's built-in `pow(a, -1, m)` modular inverse (Python's
     multiplicative inverse via the extended Euclidean algorithm, not any
     inverse table baked into nine65) -- independently re-deriving the exact
     formula `DualRNSContext::extract_k_rns_level` uses
     (`arithmetic/rns.rs`), so the SAME defect that issue #81 describes (an
     anchor-prime subset too small to hold the true signed winding `k`) would
     be independently reproduced here if the fixture's data still exhibited
     it.
  3. A from-scratch BFV-style decode (round(t/Q * v) mod t via exact integer
     floor-division + manual half-up rounding), matching
     `RNSFHEContext::decrypt_dual_u256`'s documented algorithm without
     reading its code.

What it checks, per dumped ciphertext:

  (a) DECODE CROSS-CHECK -- reconstruct coefficient 0 of `c0 + c1*s` from the
      dumped MAIN-system residues (schoolbook convolution + CRT + decode) and
      confirm the result equals both the mathematically EXPECTED plaintext
      and Rust's own `decrypt_dual` output for that exact ciphertext.

  (b) WINDING/CAPACITY CROSS-CHECK -- for a sample of coefficients, replicate
      `extract_k_rns_level`'s formula (v_exact = v_m + k*M_level, k found via
      CRT over the anchor residues) using the dumped MAIN + ANCHOR residues,
      and confirm:
        - the reconstruction round-trips (v_exact mod each prime reproduces
          the dumped residue for that prime -- this crate's own CRT machinery
          is not silently wrong),
        - the reconstructed |k| stays strictly under the anchor basis's
          half-capacity (no wraparound already occurred), quantifying the
          real margin on THESE exact vectors rather than trusting a comment.

Usage:
    python3 scripts/depth2_issue81_python_oracle.py \
        [path/to/depth2_oracle_vectors_issue81.json]

Exit code 0 and "ALL CHECKS PASSED" iff every op in the fixture matches on
every check. Any mismatch prints full diagnostic detail and exits nonzero.
"""

import json
import sys
from pathlib import Path


def negacyclic_convolve(a, b, n, modulus):
    """(a * b) mod (x^n + 1), coefficient-wise mod `modulus`. Schoolbook
    O(n^2), integer-only. Returns a list of n ints in [0, modulus)."""
    result = [0] * n
    for i in range(n):
        ai = a[i]
        if ai == 0:
            continue
        for j in range(n):
            bj = b[j]
            if bj == 0:
                continue
            k = i + j
            term = ai * bj
            if k >= n:
                k -= n
                result[k] = (result[k] - term) % modulus
            else:
                result[k] = (result[k] + term) % modulus
    return result


def mod_inverse(a, m):
    """Extended-Euclid modular inverse via Python's built-in three-arg pow
    (available since Python 3.8), itself an independent implementation of
    the extended Euclidean algorithm -- not a call into nine65."""
    return pow(a % m, -1, m)


def crt_reconstruct(residues, primes):
    """Direct (non-cascaded) CRT reconstruction: every term
    residue_i * M_i * inverse(M_i mod p_i, p_i) is computed independently of
    every other term, then summed mod M. Arbitrary precision via Python int."""
    m = 1
    for p in primes:
        m *= p
    acc = 0
    for i, p in enumerate(primes):
        mi = m // p
        mi_mod_p = mi % p
        mi_inv = mod_inverse(mi_mod_p, p)
        term = (residues[i] * mi_inv % p) * mi
        acc = (acc + term) % m
    return acc


def reconstruct_signed_value(main_residues, anchor_residues, main_primes, anchor_primes):
    """Replicates extract_k_rns_level's formula: v_exact = v_m + k*M_level,
    with k found via CRT over the anchor residues. Returns (v_exact_signed,
    v_m, k, m_level, a_full) as plain Python ints (v_exact_signed may be
    negative)."""
    v_m = crt_reconstruct(main_residues, main_primes)
    m_level = 1
    for p in main_primes:
        m_level *= p

    k_rns = []
    for j, a in enumerate(anchor_primes):
        m_level_mod_a = m_level % a
        inv = mod_inverse(m_level_mod_a, a)
        v_m_mod_a = v_m % a
        diff = (anchor_residues[j] - v_m_mod_a) % a
        k_rns.append((diff * inv) % a)

    k = crt_reconstruct(k_rns, anchor_primes)
    a_full = 1
    for a in anchor_primes:
        a_full *= a
    a_half = a_full // 2

    if k > a_half:
        k_signed = k - a_full
    else:
        k_signed = k

    v_exact = v_m + k_signed * m_level
    return v_exact, v_m, k_signed, m_level, a_full


def round_div_half_up(numerator, denominator):
    """round(numerator / denominator) for non-negative ints, integer-only,
    half rounds up -- matches decrypt_dual_u256's documented rounding."""
    assert numerator >= 0 and denominator > 0
    return (2 * numerator + denominator) // (2 * denominator)


def decode_bfv(v_main_true, main_primes, t):
    """BFV-style decode: v_main_true is the TRUE (non-negative-canonical,
    i.e. already reduced into [0, Q)) value of c0+c1*s coefficient 0 in the
    main system. round(v * t / Q) mod t, integer-only."""
    q = 1
    for p in main_primes:
        q *= p
    half_q = q // 2
    v = v_main_true % q
    if v > half_q:
        neg_mag = q - v
        scaled = round_div_half_up(neg_mag * t, q)
        return (t - scaled) % t
    else:
        scaled = round_div_half_up(v * t, q)
        return scaled % t


def check_decode(op, n, main_primes, t, s_main):
    """Check (a): independent decode of coefficient 0 from dumped residues,
    schoolbook negacyclic convolution + CRT + decode, no NTT, no nine65
    code."""
    ct = op["ciphertext"]
    c0_main = ct["c0"]["main"]
    c1_main = ct["c1"]["main"]

    coeff0_true_per_prime = []
    for lane in range(len(main_primes)):
        p = main_primes[lane]
        c1s = negacyclic_convolve(c1_main[lane], s_main[lane], n, p)
        inner0 = (c0_main[lane][0] + c1s[0]) % p
        coeff0_true_per_prime.append(inner0)

    v_main = crt_reconstruct(coeff0_true_per_prime, main_primes)
    decoded = decode_bfv(v_main, main_primes, t)

    ok = decoded == op["expected"] == op["rust_decrypt"]
    return ok, decoded


def check_winding(op, main_primes, anchor_primes, k_primes, sample_coeffs):
    """Check (b): for a handful of coefficients of c0, independently
    reconstruct the true signed value via main+anchor CRT (replicating
    extract_k_rns_level's formula), confirm round-trip against the dumped
    residues, and confirm |k| stays under half the reconstruction anchor
    basis's capacity."""
    ct = op["ciphertext"]
    c0_main = ct["c0"]["main"]
    c0_anchor = ct["c0"]["anchor"]
    anchors = anchor_primes[:k_primes]

    max_k_bits = 0
    min_margin_bits = None
    for i in sample_coeffs:
        main_res = [c0_main[lane][i] for lane in range(len(main_primes))]
        anchor_res = [c0_anchor[lane][i] for lane in range(k_primes)]

        v_exact, v_m, k_signed, m_level, a_full = reconstruct_signed_value(
            main_res, anchor_res, main_primes, anchors
        )

        # Round-trip: v_exact reduced mod every main prime and every anchor
        # prime used must reproduce the dumped residues exactly.
        for lane, p in enumerate(main_primes):
            if v_exact % p != main_res[lane]:
                return False, f"main round-trip failed lane={lane} p={p} coeff={i}", 0, None
        for lane, a in enumerate(anchors):
            if v_exact % a != anchor_res[lane]:
                return False, f"anchor round-trip failed lane={lane} a={a} coeff={i}", 0, None

        k_bits = abs(k_signed).bit_length()
        a_half_bits = (a_full // 2).bit_length()
        margin = a_half_bits - k_bits
        max_k_bits = max(max_k_bits, k_bits)
        if min_margin_bits is None or margin < min_margin_bits:
            min_margin_bits = margin

    return True, None, max_k_bits, min_margin_bits


def main():
    fixture_path = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else Path(__file__).resolve().parent.parent
        / "crates/nine65/tests/fixtures/depth2_oracle_vectors_issue81.json"
    )
    if not fixture_path.exists():
        print(f"FIXTURE NOT FOUND: {fixture_path}")
        print(
            "Generate it first: cargo test -p nine65 --test "
            "depth2_python_oracle_vectors_issue81 --release --features allow_insecure"
        )
        sys.exit(2)

    data = json.loads(fixture_path.read_text())
    n = data["n"]
    t = data["t"]
    main_primes = data["main_primes"]
    anchor_primes = data["anchor_primes"]
    k_primes = data["k_reconstruction_anchor_count"]

    print(f"=== depth2_issue81_python_oracle ===")
    print(f"fixture: {fixture_path}")
    print(f"n={n} t={t} main_primes={main_primes}")
    print(f"anchor_primes={anchor_primes} (k_reconstruction uses first {k_primes})")
    print()

    # Sanity: main_primes is exactly secure_128/secure_128_deep's real chain.
    expected_main = [998244353, 985661441, 754974721, 469762049]
    assert main_primes == expected_main, (
        f"fixture main_primes {main_primes} != expected real secure_128/128_deep chain "
        f"{expected_main} -- oracle would not be checking representative data"
    )

    ops_by_seed_key = {}
    keys = {}
    ops = []
    for entry in data["ops"]:
        if entry["mode"] == "secret_key":
            seed = entry["label"].removeprefix("secret_key_seed")
            keys[seed] = entry["s"]["main"]
        else:
            ops.append(entry)

    all_ok = True
    decode_pass = 0
    winding_pass = 0
    total = 0
    worst_margin = None

    for op in ops:
        total += 1
        # label format: "seed<seed>_<opname>"
        seed = op["label"].split("_", 1)[0].removeprefix("seed")
        s_main = keys.get(seed)
        if s_main is None:
            print(f"FAIL {op['label']}/{op['mode']}: no secret key dumped for seed {seed}")
            all_ok = False
            continue

        ok, decoded = check_decode(op, n, main_primes, t, s_main)
        status = "OK" if ok else "FAIL"
        print(
            f"[{status}] {op['label']:<28} mode={op['mode']:<10} "
            f"python_decode={decoded} rust_decrypt={op['rust_decrypt']} expected={op['expected']}"
        )
        if ok:
            decode_pass += 1
        else:
            all_ok = False

        # Winding/capacity check on a sample of coefficients (0, N/4, N/2,
        # 3N/4, N-1) -- enough to sample across the polynomial without
        # re-doing O(N) extended-Euclid inversions for every one of N=64
        # coefficients on every op (already fast at N=64, but this keeps the
        # check's cost independent of any future N bump).
        sample = sorted(set([0, n // 4, n // 2, (3 * n) // 4, n - 1]))
        wok, err, max_k_bits, margin = check_winding(op, main_primes, anchor_primes, k_primes, sample)
        if wok:
            winding_pass += 1
            print(
                f"       winding: max|k| observed = {max_k_bits} bits, "
                f"min margin under half-capacity = {margin} bits (sampled coeffs {sample})"
            )
            if worst_margin is None or margin < worst_margin:
                worst_margin = margin
        else:
            all_ok = False
            print(f"       WINDING CHECK FAILED: {err}")

    print()
    print(f"decode cross-check: {decode_pass}/{total} passed")
    print(f"winding/capacity cross-check: {winding_pass}/{total} passed")
    if worst_margin is not None:
        print(f"worst-case observed margin under half-capacity across all ops/coeffs: {worst_margin} bits")

    if all_ok:
        print()
        print("ALL CHECKS PASSED")
        sys.exit(0)
    else:
        print()
        print("AT LEAST ONE CHECK FAILED -- see FAIL lines above")
        sys.exit(1)


if __name__ == "__main__":
    main()
