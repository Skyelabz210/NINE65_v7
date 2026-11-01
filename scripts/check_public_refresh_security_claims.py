#!/usr/bin/env python3
"""Fail when PublicRefreshCircuit claims outrun the published non-claims."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import tempfile


REQUIRED_ROWS = {
    "refresh.security_model": (
        "internal",
        "exploratory",
        "docs/security/SECURITY_MODEL_PUBLIC_REFRESH.md",
    ),
    "refresh.circuit_correctness_observed": (
        "internal",
        "exploratory",
        "docs/security/CORRECTNESS_EVIDENCE_PUBLIC_REFRESH.md",
    ),
    "refresh.circuit_correctness_bounded": (
        "internal",
        "exploratory",
        "docs/security/NOISE_BOUND_PUBLIC_REFRESH.md",
    ),
    "refresh.related_key_confidentiality": (
        "internal",
        "exploratory",
        "docs/security/RELATED_KEY_ANALYSIS.md",
    ),
    "refresh.production_security": (
        "internal",
        "exploratory",
        "docs/security/EXTERNAL_PARAMETER_ATTESTATION.md",
    ),
    "refresh.constant_time_posture": (
        "internal",
        "exploratory",
        "docs/security/CT_PUBLIC_REFRESH.md",
    ),
}

REQUIRED_PHRASES = {
    "docs/security/SECURITY_MODEL_PUBLIC_REFRESH.md": [
        "K_0",
        "K_native",
        "are not the same producer",
        "supports_public_refresh",
        "does not mean the research circuit is absent",
        "malicious evaluator",
        "Chosen-ciphertext",
        "Multi-client",
        "Adaptive key queries",
        "Legacy Clockwork",
    ],
    "docs/security/RELATED_KEY_ANALYSIS.md": [
        "Route D",
        "Route B is not a confidentiality argument",
        "not established",
        "Not completed",
        "Not done",
    ],
    "docs/security/NOISE_BOUND_PUBLIC_REFRESH.md": [
        "562",
        "633",
        "A probabilistic decryption-failure bound is not derived.",
    ],
    "docs/security/EXTERNAL_PARAMETER_ATTESTATION.md": [
        "External parameter attestation is not obtained.",
        "16 bits short",
    ],
    "docs/security/CT_PUBLIC_REFRESH.md": [
        "is not established",
    ],
    "docs/security/CORRECTNESS_EVIDENCE_PUBLIC_REFRESH.md": [
        "81,920",
        "not a latest-head rerun",
        "not confidentiality",
    ],
}

FORBIDDEN = (
    "confidentiality is established",
    "production security is established",
    "is admitted for production",
    "proves related-key security",
    "failure probability is 0",
    "failure probability is zero",
    "reduces to standard rlwe",
    "128-bit security",
    "256-bit security",
)


def registry_rows(text: str) -> dict[str, tuple[str, str, str]]:
    rows = {}
    for line in text.splitlines()[1:]:
        if not line.strip():
            continue
        claim_id, visibility, profile, path = line.split(",", 3)
        rows[claim_id] = (visibility, profile, path)
    return rows


def check(root: Path) -> list[str]:
    errors: list[str] = []
    circuit = root / "crates/nine65/src/ops/public_refresh_circuit.rs"
    if not circuit.is_file() or "struct PublicRefreshCircuit" not in circuit.read_text():
        errors.append("PublicRefreshCircuit source missing while security claims are published")
    registry_path = root / "docs/CLAIM_REGISTRY.csv"
    if not registry_path.is_file():
        return errors + ["missing claim registry"]
    rows = registry_rows(registry_path.read_text())
    for claim_id, expected in REQUIRED_ROWS.items():
        if rows.get(claim_id) != expected:
            errors.append(f"registry row {claim_id} must be {expected}")
        artifact = root / expected[2]
        if not artifact.is_file() or not artifact.read_text().strip():
            errors.append(f"missing artifact for {claim_id}")
    status_path = root / "docs/status/CURRENT.json"
    if not status_path.is_file():
        return errors + ["missing docs/status/CURRENT.json"]
    status = json.loads(status_path.read_text())
    claim = status.get("publishable_claim", "")
    if status.get("production_admitted") is not False:
        errors.append("production_admitted must be false")
    if status["claims"]["refresh.related_key_confidentiality"]["status"] != "not_established":
        errors.append("related-key confidentiality must stay not_established")
    if status["claims"]["refresh.related_key_confidentiality"]["route"] != "D":
        errors.append("related-key route must stay D")
    if status["claims"]["refresh.circuit_correctness_bounded"]["probabilistic_failure_bound"] is not None:
        errors.append("probabilistic failure bound must stay null")
    if status["claims"]["refresh.circuit_correctness_observed"]["latest_head_rerun"] is not False:
        errors.append("latest-head native rerun must stay false")
    if status["claims"]["refresh.external_parameter_attestation"]["status"] != "not_obtained":
        errors.append("external attestation must stay not_obtained")
    if status["claims"]["refresh.constant_time_posture"]["status"] != "not_established":
        errors.append("constant-time posture must stay not_established")
    surfaces = [
        root / "docs/security",
        root / "docs/status",
        root / "docs/PUBLIC_REFRESH_STATUS.md",
    ]
    texts = []
    for surface in surfaces:
        if surface.is_dir():
            texts.extend(path.read_text() for path in sorted(surface.glob("*.md")))
        elif surface.is_file():
            texts.append(surface.read_text())
    blob = "\n".join(texts)
    if claim not in blob:
        errors.append("publishable claim is missing from the security pack or status guide")
    folded = blob.lower()
    for phrase in FORBIDDEN:
        if phrase in folded:
            errors.append("forbidden claim language: " + phrase)
    for relative, phrases in REQUIRED_PHRASES.items():
        path = root / relative
        if not path.is_file():
            errors.append("missing " + relative)
            continue
        text = path.read_text()
        for phrase in phrases:
            if phrase not in text:
                errors.append(f"{relative} missing required phrase: {phrase}")
    model = (root / "docs/security/SECURITY_MODEL_PUBLIC_REFRESH.md").read_text()
    if "K_0" in model and "K_native" in model:
        for line in model.splitlines():
            compact = line.replace(" ", "")
            if "K_0=K_native" in compact or "K_0isK_native" in compact:
                errors.append("K_0 and K_native equated")
    readme = root / "README.md"
    if readme.is_file():
        for line in readme.read_text().splitlines():
            lower = line.lower()
            if "public refresh is disabled" in lower or "refresh unavailable" in lower:
                if "clockwork" not in lower:
                    errors.append("refresh unavailability without a Clockwork qualifier: " + line.strip())
    return errors


def self_test() -> None:
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        circuit = root / "crates/nine65/src/ops"
        circuit.mkdir(parents=True)
        (circuit / "public_refresh_circuit.rs").write_text("struct PublicRefreshCircuit {}")
        security = root / "docs/security"
        security.mkdir(parents=True)
        status = root / "docs/status"
        status.mkdir()
        claim = "verbatim publishable claim"
        (security / "SECURITY_MODEL_PUBLIC_REFRESH.md").write_text(
            claim + " K_0 and K_native are not the same producer. "
            "supports_public_refresh staying false does not mean the research circuit is absent. "
            "malicious evaluator. Chosen-ciphertext. Multi-client. Adaptive key queries. Legacy Clockwork."
        )
        (security / "RELATED_KEY_ANALYSIS.md").write_text(
            claim + " Route D. Route B is not a confidentiality argument. not established. Not completed. Not done."
        )
        (security / "NOISE_BOUND_PUBLIC_REFRESH.md").write_text(
            claim + " 562 633 A probabilistic decryption-failure bound is not derived."
        )
        (security / "EXTERNAL_PARAMETER_ATTESTATION.md").write_text(
            claim + " External parameter attestation is not obtained. 16 bits short."
        )
        (security / "CT_PUBLIC_REFRESH.md").write_text(claim + " is not established.")
        (security / "CORRECTNESS_EVIDENCE_PUBLIC_REFRESH.md").write_text(
            claim + " 81,920 not a latest-head rerun. Bounded correctness is not confidentiality."
        )
        (security / "README.md").write_text(claim)
        (root / "docs/PUBLIC_REFRESH_STATUS.md").write_text(claim)
        (root / "README.md").write_text(
            "legacy Clockwork public refresh is disabled on every named profile.\n"
        )
        rows = ["claim_id,visibility,profile_class,artifact_path"]
        for claim_id, (visibility, profile, path) in REQUIRED_ROWS.items():
            rows.append(f"{claim_id},{visibility},{profile},{path}")
        (root / "docs/CLAIM_REGISTRY.csv").write_text("\n".join(rows) + "\n")
        (status / "CURRENT.json").write_text(json.dumps({
            "production_admitted": False,
            "publishable_claim": claim,
            "claims": {
                "refresh.related_key_confidentiality": {"status": "not_established", "route": "D"},
                "refresh.circuit_correctness_bounded": {"probabilistic_failure_bound": None},
                "refresh.circuit_correctness_observed": {"latest_head_rerun": False},
                "refresh.external_parameter_attestation": {"status": "not_obtained"},
                "refresh.constant_time_posture": {"status": "not_established"},
            },
        }))
        assert not check(root), check(root)
        (root / "README.md").write_text("public refresh is disabled on every config.\n")
        assert any("Clockwork" in error for error in check(root))
        (root / "README.md").write_text("legacy Clockwork public refresh is disabled on every named profile.\n")
        current = json.loads((status / "CURRENT.json").read_text())
        current["claims"]["refresh.related_key_confidentiality"]["status"] = "established"
        (status / "CURRENT.json").write_text(json.dumps(current))
        assert any("not_established" in error for error in check(root))
        current["claims"]["refresh.related_key_confidentiality"]["status"] = "not_established"
        (status / "CURRENT.json").write_text(json.dumps(current))
        model = security / "SECURITY_MODEL_PUBLIC_REFRESH.md"
        model.write_text(model.read_text() + "\nK_0 = K_native\n")
        assert any("equated" in error for error in check(root))
        model.write_text(model.read_text().replace("K_0 = K_native", ""))
        (security / "RELATED_KEY_ANALYSIS.md").write_text(
            (security / "RELATED_KEY_ANALYSIS.md").read_text() + "\nThis reduces to standard RLWE.\n"
        )
        assert any("standard rlwe" in error for error in check(root))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    root = Path(__file__).resolve().parents[1]
    errors = check(root)
    for error in errors:
        print("ERROR:", error)
    if errors:
        return 1
    print("PublicRefreshCircuit security claim gate passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
