#!/usr/bin/env python3
"""Audit native public-refresh review inputs without generating any keys.

The existing Rust exporter is the input authority. This supplemental audit
recomputes its source-bound fingerprint and records channel/sample accounting
that its aggregate graph does not expose. No security estimate is produced.
"""

import argparse
import hashlib
import itertools
import json
import math
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
BOUND_FILES = [
    "ops/public_refresh_circuit.rs", "ops/public_refresh_source.rs",
    "ops/public_refresh_source_kernels.rs", "ops/direct_slot_phase.rs",
    "ops/public_refresh_slots.rs", "ops/public_refresh_return.rs",
    "ops/rns_fhe.rs", "ops/exact_mul.rs", "ops/rns_galois.rs",
    "entropy/rng_trait.rs", "entropy/secure.rs", "ops/public_refresh_key_graph.rs",
]


def negacyclic(a, b):
    """Exact integer multiplication in Z[X]/(X^len(a)+1)."""
    assert len(a) == len(b)
    out = [0] * len(a)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            index = i + j
            out[index % len(a)] += x * y * (-1 if index >= len(a) else 1)
    return out


def check_embedded_channels():
    # Check a basis of the mask space for every ternary degree-four secret.
    # Bilinearity then extends this finite identity to arbitrary integer masks.
    small_n, stride = 4, 4
    basis_checks = 0
    for work in itertools.product((-1, 0, 1), repeat=small_n):
        embedded = [0] * (small_n * stride)
        embedded[::stride] = work
        for index in range(len(embedded)):
            mask = [0] * len(embedded)
            mask[index] = 1
            product = negacyclic(mask, embedded)
            for channel in range(stride):
                assert product[channel::stride] == negacyclic(mask[channel::stride], work)
            basis_checks += 1
    return {"work_degree": small_n, "stride": stride,
            "ternary_secrets": 3**small_n, "mask_basis_vectors_per_secret": small_n * stride,
            "basis_products_checked": basis_checks, "channel_equalities_checked": basis_checks * stride,
            "scope": "independent finite algebra witness; not native encrypted execution or Rust refinement"}


def has_cycle(relations):
    reach = {name: set() for name in ("Work", "Source", "Outer")}
    for relation in relations:
        if relation["message_secret"] is not None:
            reach[relation["message_secret"]].add(relation["encryption_secret"])
    for k in reach:
        for i in reach:
            if k in reach[i]:
                reach[i].update(reach[k])
    return any(name in targets for name, targets in reach.items())


def audit(packet_path, source_commit=None):
    raw = packet_path.read_bytes()
    packet = json.loads(raw)
    assert packet["schema"] == "nine65-independent-review-inputs-v1"
    assert packet["status"] == "unsigned_review_inputs_not_attestation"
    assert packet["production_admitted"] is False
    domains = {entry["domain"]: entry for entry in packet["native_domains"]}
    assert set(domains) == {"Work", "Source", "Outer"}
    for domain in domains.values():
        domain["primes"] = list(map(int, domain["ordered_primes_decimal"]))
        domain["plaintexts"] = list(map(int, domain["plaintext_moduli_decimal"]))
    work, source, outer = (domains[name] for name in ("Work", "Source", "Outer"))
    assert (work["n"], source["n"], outer["n"]) == (8192, 8192, 32768)
    assert source["primes"] == work["primes"][:2]
    assert outer["primes"][:len(work["primes"])] == work["primes"]
    p = source["plaintexts"][0]
    assert work["plaintexts"] == [p] == source["plaintexts"]
    assert outer["plaintexts"] == [p, p*p]
    assert source["source_weight"] == 96
    assert all(d["cbd_eta"] == 3 for d in domains.values())
    source_base, work_base, outer_base, return_base, phase_baby = 3, 10, 10, 3, 128

    def digits(primes, base):
        return [(q.bit_length() + base - 1) // base for q in primes]

    work_digits = digits(work["primes"], work_base)
    source_digits = digits(source["primes"], source_base)
    outer_digits = digits(outer["primes"], outer_base)
    return_digits = digits(work["primes"], return_base)
    relations = packet["native_relations"]
    counts = [1, sum(work_digits), sum(source_digits), 2*phase_baby,
              sum(outer_digits), 4*sum(outer_digits), sum(return_digits)]
    assert counts == [1, 12, 20, 256, 66, 264, 40]
    assert [r["published_ciphertexts"] for r in relations] == counts
    assert [(r["message_secret"], r["encryption_secret"]) for r in relations] == [
        (None, "Work"), ("Work", "Work"), ("Work", "Source"),
        ("Source", "Outer"), ("Outer", "Outer"), ("Outer", "Outer"), ("Outer", "Work")]

    fingerprint = hashlib.sha256(b"NINE65-public-refresh-key-graph-v1")
    def word(value):
        fingerprint.update(value.to_bytes(8, "little"))
    for domain in (work, source, outer):
        for value in (domain["n"], domain["plaintexts"][-1], domain["cbd_eta"], len(domain["primes"])):
            word(value)
        for q in domain["primes"]:
            word(q)
    for value in (source["source_weight"], source_base, phase_baby):
        word(value)
    for relation in relations:
        purpose = relation["purpose"].encode()
        word(len(purpose))
        fingerprint.update(purpose)
        word(relation["published_ciphertexts"])
    file_hashes = {}
    source_commit = subprocess.check_output(
        ["git", "rev-parse", "--verify", f"{source_commit or 'HEAD'}^{{commit}}"],
        cwd=ROOT, text=True,
    ).strip()
    for relative in BOUND_FILES:
        path = ROOT / "crates/nine65/src" / relative
        digest = hashlib.sha256(path.read_bytes()).digest()
        repo_path = str(path.relative_to(ROOT))
        committed = subprocess.check_output(["git", "show", f"{source_commit}:{repo_path}"], cwd=ROOT)
        assert digest == hashlib.sha256(committed).digest(), f"runtime generator differs from {source_commit}:{repo_path}"
        file_hashes[repo_path] = digest.hex()
        fingerprint.update(digest)
    assert fingerprint.hexdigest() == packet["key_publication_fingerprint"]

    cycle_controls = {
        "full_graph": has_cycle(relations),
        "without_return": has_cycle(relations[:-1]),
        "without_self_relations": has_cycle([r for r in relations if r["message_secret"] != r["encryption_secret"]]),
        "without_return_or_self_relations": has_cycle([r for r in relations[:-1] if r["message_secret"] != r["encryption_secret"]]),
    }
    assert cycle_controls == {"full_graph": True, "without_return": True,
                              "without_self_relations": True, "without_return_or_self_relations": False}
    assert packet["requires_joint_key_review"] is True
    assert packet["return_effective_secret_degree"] == work["n"]
    stride = outer["n"] // work["n"]
    inverse_baby = 1 << (((outer["n"]//2).bit_length()-2)//2)
    inverse_giant = (outer["n"]//2) // inverse_baby
    exponents = [pow(5, outer["n"]//2-phase_baby, 2*outer["n"]),
                 pow(5, inverse_giant, 2*outer["n"]), 5, 2*outer["n"]-1]
    assert exponents == [49665, 31745, 5, 65535]
    for domain in domains.values():
        q_product = math.prod(domain["primes"])
        domain["q_product_decimal"] = str(q_product)
        domain["q_product_bits"] = q_product.bit_length()
        domain["prime_bits"] = [q.bit_length() for q in domain["primes"]]
        del domain["primes"], domain["plaintexts"]
    coefficient_equations = sum(count*n for count, n in zip(counts, [work["n"], work["n"], source["n"], outer["n"], outer["n"], outer["n"], outer["n"]]))
    return {
        "schema": "nine65-public-key-graph-evidence-v1",
        "source_commit": source_commit,
        "runtime_generator_hashes_match_source_commit": True,
        "packet_sha256": hashlib.sha256(raw).hexdigest(),
        "key_publication_fingerprint_recomputed": fingerprint.hexdigest(),
        "bound_source_sha256": file_hashes,
        "native_domains": list(domains.values()),
        "native_relations": relations,
        "gadget_digits_per_lane": {"work_relin_base10": work_digits, "source_switch_base3": source_digits,
                                    "outer_relin_and_each_galois_base10": outer_digits, "return_base3": return_digits},
        "native_galois_exponents": dict(zip(("phase_giant", "inverse_baby", "inverse_giant", "inverse_conjugate"), exponents)),
        "published_ring_ciphertexts": sum(counts),
        "coefficient_equation_count_before_CRT_expansion": coefficient_equations,
        "work_receiver_ring_channels": {"direct_degree8192_rows": counts[0]+counts[1],
                                        "return_outer_rows": counts[-1], "return_channels_per_outer_row": stride,
                                        "return_degree8192_channels": counts[-1]*stride,
                                        "total_degree8192_channels_sharing_W": counts[0]+counts[1]+counts[-1]*stride},
        "cycle_controls": cycle_controls,
        "embedded_channel_witness": check_embedded_channels(),
        "limitations": ["Ciphertext and channel counts are bookkeeping, not independent LWE samples or a security bound.",
                        "CRT lanes share one signed error vector in each ciphertext.",
                        "All gadgets and phase-bank plaintexts are correlated secret-dependent messages.",
                        "Fingerprint covers enumerated source files, not all dependencies, a full build, or remote execution.",
                        "No keys are generated by this audit; encrypted tests need separately identified execution.",
                        "Joint/KDM confidentiality and production admission remain unestablished."],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-commit", help="pin reviewed generator source; defaults to current HEAD for a new audit")
    parser.add_argument("--check", action="store_true", help="verify the existing output without rewriting it; reuse its recorded source commit")
    args = parser.parse_args()
    previous = json.loads(args.output.read_text()) if args.check else None
    if not args.check and args.output.exists():
        parser.error("--output already exists; choose a new artifact or use --check")
    result = audit(args.packet, args.source_commit or (previous["source_commit"] if previous else None))
    if args.check:
        assert result == previous, "audit differs from recorded evidence"
    else:
        with args.output.open("x") as output:
            output.write(json.dumps(result, indent=2) + "\n")
    print(f"PASS: source fingerprint, 659 ciphertexts, cycle controls, 160 return channels; {result['embedded_channel_witness']['channel_equalities_checked']} finite channel equalities")


if __name__ == "__main__":
    main()
