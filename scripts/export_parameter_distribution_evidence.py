#!/usr/bin/env python3
"""Export exact, source-bound RNS parameter/distribution review inputs.

This is a deliberately narrow source adapter with fail-closed anchors, not a
Rust parser, estimator, entropy test, or encrypted execution. Source edits that
change these producers require review and an adapter update.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import math
import pathlib
import re
import subprocess
from fractions import Fraction

ROOT = pathlib.Path(__file__).resolve().parents[1]
# Default validation follows the source-bound main supplement. The original
# 7ada650 packet remains frozen at parameter-distribution/parameter-distributions.json.
OUTPUT = "artifacts/execution/2026-11-10/parameter-security-orchestration/main676-parameter-distributions.json"
RUST = "crates/nine65/src/"
FILES = (
    RUST + "params/secure_configs.rs",
    RUST + "entropy/secure.rs",
    RUST + "entropy/rng_trait.rs",
    RUST + "ops/rns_fhe.rs",
    RUST + "ops/exact_mul.rs",
    RUST + "ops/public_refresh_circuit.rs",
    RUST + "ops/public_refresh_source.rs",
    RUST + "ops/public_refresh_source_plan.rs",
    RUST + "ops/public_refresh_source_kernels.rs",
    RUST + "ops/public_refresh_return.rs",
    RUST + "ops/direct_slot_phase.rs",
    RUST + "ops/rns_galois.rs",
    RUST + "ops/bootstrap.rs",
    RUST + "keys/bootstrap.rs",
)


class EvidenceError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def unique(pattern: str, text: str, label: str) -> re.Match:
    matches = list(re.finditer(pattern, text, re.S))
    require(len(matches) == 1, f"{label}: expected one source match, got {len(matches)}")
    return matches[0]


def integer(expression: str) -> int:
    """Only the positive integer literals/products used in these constructors."""
    node = ast.parse(expression.strip(), mode="eval").body

    def visit(value: ast.AST) -> int:
        if isinstance(value, ast.Constant) and type(value.value) is int:
            return value.value
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Mult):
            return visit(value.left) * visit(value.right)
        raise EvidenceError(f"unsupported integer source expression: {expression}")

    result = visit(node)
    require(result > 0, "parameter must be positive")
    return result


def function(text: str, name: str) -> str:
    """Extract a reviewed function body; brace counting is intentionally narrow."""
    match = unique(r"\bfn " + re.escape(name) + r"(?:<[^\n]*>)?\s*\(", text, name)
    start = text.index("{", match.end())
    depth = 1
    for end in range(start + 1, len(text)):
        depth += (text[end] == "{") - (text[end] == "}")
        if depth == 0:
            return text[start + 1 : end]
    raise EvidenceError(f"{name}: unterminated body")


def anchors(body: str, snippets: tuple[str, ...], label: str) -> None:
    for snippet in snippets:
        require(snippet in body, f"{label}: distribution producer changed: {snippet}")


def rational(value: Fraction) -> dict:
    return {"numerator": str(value.numerator), "denominator": str(value.denominator)}


def cbd(eta: int) -> dict:
    # Vandermonde: P(A-B=k)=C(2 eta,eta+k)/2^(2 eta).
    denominator = 1 << (2 * eta)
    probabilities = [Fraction(math.comb(2 * eta, eta + k), denominator)
                     for k in range(-eta, eta + 1)]
    require(sum(probabilities) == 1, "CBD PMF does not normalize")
    mean = sum(k * p for k, p in zip(range(-eta, eta + 1), probabilities))
    variance = sum(k * k * p for k, p in zip(range(-eta, eta + 1), probabilities))
    require(mean == 0 and variance == Fraction(eta, 2), "CBD moments differ")
    return {"law": "centered_binomial", "eta": eta, "support": [-eta, eta],
            "pmf_numerators": [str(math.comb(2 * eta, eta + k))
                               for k in range(-eta, eta + 1)],
            "pmf_denominator": str(denominator), "mean": rational(mean),
            "variance": rational(variance), "standard_deviation": f"sqrt({eta}/2)",
            "not_a_gaussian_sigma_3_2": True}


def tuple_record(n: int, primes: list[int], t: int, eta: int) -> dict:
    q = math.prod(primes)
    return {"n": n, "ordered_primes_decimal": [str(p) for p in primes],
            "q_decimal": str(q), "q_hex": hex(q), "exact_q_bits": q.bit_length(),
            "t_decimal": str(t), "eta": eta, "error_distribution": f"cbd_{eta}"}


def parse_named(text: str) -> list[dict]:
    entries = []
    for name in ("secure_128", "secure_128_deep", "secure_192", "secure_256"):
        body = function(text, name)
        values = unique(r'Self::new_verified\(\s*([\d_]+),\s*vec!\[([^\]]+)\],'
                        r'\s*([\d_]+),\s*([\d_]+),\s*([\d_]+),\s*"' + name + r'",?\s*\)',
                        body, name + " tuple")
        n, prime_text, t, eta, claim = values.groups()
        entry = tuple_record(integer(n), [integer(p) for p in prime_text.split(",") if p.strip()],
                             integer(t), integer(eta))
        entry.update(name=name, nominal_security_label_bits=integer(claim),
                     secret_distribution="word_mod3_ternary",
                     encryption_u_distribution="word_mod3_ternary")
        entries.append(entry)
    return entries


def parse_native(text: str) -> tuple[list[dict], dict]:
    native = function(text, "native_research")
    configs = {}
    for label in ("work", "high"):
        block = unique(r"let " + label + r" = FHEConfig\s*\{(.*?)\n\s*\};", native, label).group(1)
        get = lambda field: unique(r"\b" + field + r":\s*([^,]+),", block, field).group(1)
        primes = unique(r"primes:\s*vec!\[([^\]]+)\]", block, label + " primes").group(1)
        configs[label] = tuple_record(integer(get("n")),
                                     [integer(p) for p in primes.split(",") if p.strip()],
                                     integer(get("t")), integer(get("eta")))
        require(get("security_bits").strip() == "0", "native security label must remain zero")
    args = unique(r"PublicRefreshSourcePlan::new\(&work,\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+)\)",
                  native, "source tuple").groups()
    source_n, lanes, weight, base = map(integer, args)
    work = dict(configs["work"], domain="Work", secret_distribution="word_mod3_ternary")
    source = tuple_record(source_n, list(map(int, work["ordered_primes_decimal"]))[:lanes],
                          int(work["t_decimal"]), work["eta"])
    source.update(domain="Source", secret_distribution="balanced_sparse_ternary",
                  nonzero_weight=weight, positive_count=weight // 2,
                  negative_count=weight // 2, zero_count=source_n-weight,
                  support_cardinality_decimal=str(math.comb(source_n, weight)
                                                 * math.comb(weight, weight // 2)),
                  work_embedding_stride=source_n // work["n"], gadget_base_bits=base,
                  coefficient_marginals_do_not_imply_independence=True)
    require(source_n % work["n"] == 0 and weight % 2 == 0, "invalid sparse geometry")
    outer = dict(configs["high"], domain="Outer", secret_distribution="uniform_ternary",
                 plaintext_moduli_decimal=[work["t_decimal"], configs["high"]["t_decimal"]])
    returned = tuple_record(outer["n"], list(map(int, work["ordered_primes_decimal"])),
                            int(work["t_decimal"]), work["eta"])
    returned.update(domain="ReturnDestination", secret_distribution="embedded_original_work",
                    effective_secret_degree=work["n"], embedding_stride=outer["n"] // work["n"],
                    fresh_independent_secret=False, structural_zero_count=outer["n"]-work["n"])
    return [work, source, outer, returned], {"source_weight": weight, "base_bits": base}


def parse_legacy(s: dict[str, str], named: list[dict]) -> list[dict]:
    keys = s[RUST + "keys/bootstrap.rs"]
    # Strip comments before parsing the one public ordered prime array.
    uncommented = re.sub(r"//[^\n]*", "", keys)
    array = unique(r"pub const BOOTSTRAP_PRIMES: \[u64; 8\] = \[([^\]]+)\]",
                   uncommented, "legacy prime array").group(1)
    primes = [integer(p) for p in array.split(",") if p.strip()]
    body = function(s[RUST + "ops/bootstrap.rs"].split("impl ClockworkBootstrap", 1)[1], "new")
    anchors(body, ("let bootstrap_depth = 2;", "let min_for_depth = bootstrap_depth + 2;",
                   "let min_for_modswitch = work_config.primes.len() + 1;",
                   "let required = min_for_depth.max(min_for_modswitch);",
                   "BOOTSTRAP_PRIMES[..boot_prime_count].to_vec()", "eta: work_config.eta"),
            "legacy tuple derivation")
    entries = []
    for work in named:
        count = max(4, len(work["ordered_primes_decimal"]) + 1)
        require(count <= len(primes), "legacy chain exceeds source prime array")
        entry = tuple_record(work["n"], primes[:count], int(work["t_decimal"]), work["eta"])
        entry.update(owner_profile=work["name"],
                     circular_secret_distribution="same_original_work_coefficients_reencoded",
                     circular_key_independent_of_work=False,
                     independent_boot_secret_distribution="word_mod3_minus_one_heavy_ternary",
                     bootstrap_key_encryption_u_distribution="word_mod3_ternary",
                     public_and_switch_key_mask="canonical_full_Q_rejection_uniform",
                     key_generation_does_not_enable_refresh=True, legacy_refresh_gate_enabled=False,
                     nominal_security_label_bits=work["nominal_security_label_bits"])
        entries.append(entry)
    return entries


def validate_producers(s: dict[str, str]) -> None:
    get = lambda suffix: s[RUST + suffix]
    rns = get("ops/rns_fhe.rs")
    for name in ("generate_keys_with_rng", "generate_keys_dual_with_rng", "encrypt_with_rng",
                 "encrypt_dual_with_rng"):
        anchors(function(rns, name), ("let r = rng.next_u64() % 3;", "0 => 0", "1 => 1"), name)
    anchors(function(rns, "sample_cbd_signed_rng"),
            ("for _ in 0..eta", "let a = (rng.next_u64() & 1)",
             "let b = (rng.next_u64() & 1)", "sum += a - b"), "RNS CBD")
    anchors(function(rns, "sample_uniform_main_poly"),
            (".primes", "rng.uniform_vector(self.n, prime)"), "main mask")
    anchors(function(rns, "sample_uniform_dual_poly"),
            ("sum_bits <= 256", "if candidate.lt(modulus)", "value.mod_u64(prime)"), "dual mask")
    secure = get("entropy/secure.rs")
    anchors(function(secure, "try_secure_ternary"),
            ("try_secure_u64()? % 4", "if r < 3", "(r as i64) - 1"), "secure ternary")
    anchors(function(secure, "try_secure_cbd"),
            ("for _ in 0..eta", "bits & 1", "(bits >> 1) & 1", "sum += a - b"), "secure CBD")
    anchors(function(secure, "try_secure_u64_bounded"),
            ("u64::MAX - (u64::MAX % bound)", "if val < threshold", "val % bound"), "secure uniform")
    anchors(function(get("ops/public_refresh_source_kernels.rs"), "balanced_secret"),
            ("rng.next_u64() as usize & (ctx.n - 1)", "if trits[index] == 0",
             "if count < weight / 2 { 1 } else { -1 }"), "balanced sparse secret")
    anchors(function(get("ops/public_refresh_source_plan.rs").split("impl PublicRefreshSourcePlan", 1)[1].split("impl PolynomialNoise", 1)[0], "new"),
            ("!source_n.is_power_of_two()", "source_weight % 2 != 0", "source.n = source_n",
             "source.primes.truncate(source_lanes)"), "source derivation")
    anchors(function(get("ops/public_refresh_circuit.rs"), "generate_with_rng"),
            ("rng.ternary_vector(high.n)", "PublicRefreshReturn::generate_with_rng"), "outer secret")
    anchors(function(get("ops/public_refresh_source.rs"), "generate_with_rng"),
            ("work.generate_keys_with_rng(rng)", "balanced_secret(&source, self.source_weight, rng)"),
            "work/source setup")
    anchors(function(get("ops/public_refresh_source.rs"), "encrypt_with_rng"),
            ("ctx.encrypt_with_rng(0, &self.family.public_key, rng)",), "work encryption")
    anchors(function(get("ops/direct_slot_phase.rs"), "encrypt_polynomial"),
            ("ctx.sample_uniform_main_poly(rng)", "rng.cbd_vector(ctx.n, ctx.config.eta)"), "phase bank")
    anchors(function(get("ops/public_refresh_return.rs"), "generate_with_rng"),
            ("reduced_config.n = boot.n", "&client.work_secret_key().s", "work.config.primes.len()"),
            "return embedding")
    # All hybrid key producers delegate to this target-key primitive.
    anchors(function(get("ops/exact_mul.rs"), "generate_hybrid_target_key"),
            ("ctx.sample_uniform_main_poly(rng)", "sample_cbd_signed_rng(rng, ctx.config.eta)"),
            "hybrid key mask/error")
    legacy = get("ops/bootstrap.rs")
    anchors(function(legacy, "generate_independent_boot_sk"),
            ("let r = rng.next_u64() % 3;", "0 => -1i8", "1 => 0i8", "_ => 1i8"),
            "legacy independent secret")
    anchors(function(legacy, "generate_keys"), ("self.lift_sk_to_boot(work_sk)",), "legacy circular secret")
    anchors(function(legacy, "generate_circular_pk"),
            ("sample_uniform_dual_poly(rng, &self.boot_config.primes)",
             "sum += a_bit - b_bit"), "legacy public key")
    anchors(function(legacy, "public_phase1_soundness_gate"),
            ("Err(Nine65Error::BootstrapFailed",), "legacy refresh refusal")
    key_source = get("keys/bootstrap.rs")
    anchors(function(key_source.split("impl BootstrapKey", 1)[1].split("impl KeySwitchKey", 1)[0], "generate"),
            ("boot_ctx.encrypt_dual_with_rng(0, &boot_keys.public_key, rng)",), "legacy bootstrap encryption")
    anchors(function(key_source.split("impl KeySwitchKey", 1)[1], "generate"),
            ("boot_ctx.sample_uniform_dual_poly(rng, &boot_ctx.config.primes)",
             "let eta = boot_ctx.config.eta", "sum += a - b"), "legacy switch key")


def build_evidence(root: pathlib.Path, sources: dict[str, str] | None = None,
                   source_ref: str | None = None) -> dict:
    s = sources if sources is not None else {p: (root / p).read_text() for p in FILES}
    validate_producers(s)
    named = parse_named(s[RUST + "params/secure_configs.rs"])
    domains, _ = parse_native(s[RUST + "ops/public_refresh_circuit.rs"])
    legacy = parse_legacy(s, named)
    registry_path = "artifacts/execution/parameter_registry.json"
    registry = json.loads((root / registry_path).read_text())
    current = {entry["name"]: entry for entry in registry["configurations"]}
    require(set(current) == {entry["name"] for entry in named}, "registry profile names drifted")
    for entry in named:
        old = current[entry["name"]]
        require((old["ring_degree"], old["main_primes"], old["plaintext_modulus"], old["eta"])
                == (entry["n"], list(map(int, entry["ordered_primes_decimal"])),
                    int(entry["t_decimal"]), entry["eta"]), "source/registry tuple mismatch")
    m = 1 << 64
    counts = {-1: m // 3, 0: m // 3 + 1, 1: m // 3}
    tv = sum(abs(Fraction(count, m) - Fraction(1, 3)) for count in counts.values()) / 2
    distributions = {
        "word_mod3_ternary": {"support": [-1, 0, 1],
            "pmf_numerators": [str(counts[k]) for k in (-1, 0, 1)], "pmf_denominator": str(m),
            "total_variation_from_uniform_per_coefficient": rational(tv),
            "n_vector_total_variation_upper_bound": "min(1,n*per_coefficient_distance)",
            "security_break_demonstrated": False},
        "uniform_ternary": {"support": [-1, 0, 1], "pmf_numerators": ["1"] * 3,
                            "pmf_denominator": "3"},
        "word_mod3_minus_one_heavy_ternary": {"support": [-1, 0, 1],
            "pmf_numerators": [str(m // 3 + 1), str(m // 3), str(m // 3)],
            "pmf_denominator": str(m),
            "total_variation_from_uniform_per_coefficient": rational(tv),
            "security_break_demonstrated": False},
        "balanced_sparse_ternary": {"law": "uniform_ordered_disjoint_positive_negative_supports",
                                    "independent_coefficients": False},
        "embedded_original_work": {"law": "deterministic_subring_embedding_of_existing_work_secret",
                                   "independent_of_work": False},
        **{f"cbd_{eta}": cbd(eta) for eta in sorted({e["eta"] for e in named + domains})},
    }
    return {"schema": "nine65-parameter-distribution-evidence-v1",
            "source_sha": subprocess.check_output(["git", "rev-parse", "--verify",
                                                     (source_ref or "HEAD") + "^{commit}"],
                                                    cwd=root, text=True).strip(),
            "source_files_sha256": {p: hashlib.sha256(s[p].encode()).hexdigest() for p in sorted(s)},
            "registry_sha256": hashlib.sha256((root / registry_path).read_bytes()).hexdigest(),
            "scope": "named RNS/DualRNS, derived legacy Clockwork bootstrap, and native PublicRefreshCircuit; other APIs excluded",
            "assumptions": ["SecureRng supplies independent uniform words through the OS CSPRNG",
                            "FheRng trait alone does not establish a caller RNG distribution",
                            "source adapter anchors supplement manual review; not Rust semantic equivalence",
                            "listed source and registry hashes must match the recorded Git source SHA",
                            "additive total-variation bounds alone do not establish a 128-bit security transfer"],
            "named_profiles": named, "legacy_clockwork_bootstrap_profiles": legacy,
            "public_refresh_domains": domains, "distributions": distributions,
            "mask_and_error_producers": [
                {"producer": "single RNS public/evaluation keys, hybrid target/Galois keys, phase bank",
                 "mask": "independent unbiased residues per main prime; CRT-uniform on R_Q",
                 "error": "one signed CBD(eta) coefficient encoded consistently across lanes",
                 "source": [RUST + "ops/rns_fhe.rs", RUST + "ops/exact_mul.rs",
                            RUST + "ops/direct_slot_phase.rs"]},
                {"producer": "dual RNS public/evaluation keys",
                 "mask": "rejection-uniform canonical integer in [0,Q); reduced into main and anchor lanes",
                 "restriction": "sum of prime bit lengths <=256; not outer Q650 path",
                 "error": "one signed CBD(eta) coefficient shared by both bases"},
                {"producer": "public encryption u (RNS/DualRNS)", "mask": "word_mod3_ternary",
                 "error": "e1,e2 each CBD(eta); encryption phase error includes products with secrets"}],
            "claims": {"source_derived_review_inputs": True, "encrypted_execution": False,
                       "entropy_quality_test": False, "external_attestation": False,
                       "joint_key_confidentiality_established": False, "production_admitted": False}}


def validate_source_ref(root: pathlib.Path, document: dict) -> None:
    """An evidence-only commit may advance HEAD; bound runtime blobs may not drift."""
    revision = document["source_sha"]
    require(re.fullmatch(r"[0-9a-f]{40}", revision) is not None, "invalid recorded source SHA")
    paths = dict(document["source_files_sha256"])
    paths["artifacts/execution/parameter_registry.json"] = document["registry_sha256"]
    for path, expected in paths.items():
        blob = subprocess.check_output(["git", "show", f"{revision}:{path}"], cwd=root)
        require(hashlib.sha256(blob).hexdigest() == expected,
                f"{path}: recorded hashes do not match recorded source SHA")
        require(hashlib.sha256((root / path).read_bytes()).hexdigest() == expected,
                f"{path}: current source differs from recorded source SHA")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=ROOT)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--source-ref", help="pin generation to this commit; all bound files must agree")
    parser.add_argument("--check", action="store_true", help="compare existing export without modifying it")
    args = parser.parse_args()
    output = args.output or args.root / OUTPUT
    saved = json.loads(output.read_text()) if args.check else None
    source_ref = args.source_ref or (saved["source_sha"] if saved else None)
    document = build_evidence(args.root, source_ref=source_ref)
    validate_source_ref(args.root, document)
    encoded = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if args.check:
        require(output.read_text() == encoded, "parameter/distribution artifact differs from inspected sources")
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(encoded)
    print(f"{'validated' if args.check else 'wrote'} {output}")
    print(f"source={document['source_sha']} named_profiles={len(document['named_profiles'])} "
          f"native_domains={len(document['public_refresh_domains'])} distribution_laws={len(document['distributions'])}")


if __name__ == "__main__":
    main()
