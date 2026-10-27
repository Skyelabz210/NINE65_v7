#!/usr/bin/env python3
"""Validate comparison-only DualRNS smoke without disguising legacy refusal as success.

#135 deliberately refuses legacy ct*ct. It is UNSUPPORTED. Every supported
operation and each requested DualRNS depth must still decrypt exactly.
"""
import argparse
import json
from pathlib import Path

LEGACY_SUPPORTED = (
    "encrypt", "decrypt", "add_ct", "sub_ct", "negate_ct", "add_plain", "mul_plain",
)
DUAL_SUPPORTED = ("encrypt", "decrypt", "add_ct", "add_plain", "mul_plain", "mul_ct")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def validate(payload, probe_exit):
    require(probe_exit == 1, f"expected legacy refusal exit 1, got {probe_exit}")
    require(payload.get("schema") == "nine65-comparative-probe-v1", "unexpected schema")
    require(payload.get("status") == "FAIL", "raw probe status changed: audit semantics")

    metadata = payload["metadata"]
    require(metadata.get("build_profile") == "debug", "only debug comparisons admitted")
    require(metadata.get("allow_insecure_feature") is True, "comparison feature missing")
    require(metadata.get("comparison_only_parameter_set") is True, "not comparison-only tuple")
    require(metadata.get("security_claim_bits") == 0, "comparison claims security")

    legacy = payload["correctness"]["legacy"]
    dual = payload["correctness"]["dual_rns"]
    require(set(legacy) == set(LEGACY_SUPPORTED) | {"mul_ct", "mul_ct_status"},
            "unexpected legacy operation inventory")
    require(set(dual) == set(DUAL_SUPPORTED), "unexpected DualRNS operation inventory")
    for operation in LEGACY_SUPPORTED:
        require(legacy[operation] is True, f"legacy {operation} is wrong")
    for operation in DUAL_SUPPORTED:
        require(dual[operation] is True, f"DualRNS {operation} is wrong")
    require(legacy["mul_ct"] is False, "legacy mul_ct no longer marked unsupported")
    require(legacy["mul_ct_status"] == "refused-#135", "unexpected legacy mul_ct outcome")
    require(payload["operations_ns"]["legacy"]["mul_ct"] == "refused-#135",
            "operation inventory contradicts refusal")

    depth = payload["ct_mul_depth"]
    requested = depth["requested"]
    require(type(requested) is int and requested > 0, "invalid requested depth")
    require(depth["completed"] == requested, "partial depth run")
    require(depth["first_error"] is None, "recorded depth error")
    require(depth["all_completed_entries_correct"] is True, "depth correctness flag false")
    entries = depth["entries"]
    require(len(entries) == requested, "depth entry count mismatch")
    for i, entry in enumerate(entries, 1):
        require(entry.get("depth") == i, f"depth {i} missing or out of order")
        require(entry.get("correct") is True, f"depth {i} marked wrong")
        require(type(entry.get("expected")) is int, f"depth {i} expected missing")
        require(type(entry.get("decrypted")) is int, f"depth {i} decrypted missing")
        require(entry["decrypted"] == entry["expected"], f"depth {i} plaintext mismatch")
        require(entry.get("mismatch_delta_mod_t") == 0, f"depth {i} mismatch delta")

    return {
        "status": "UNSUPPORTED",
        "reason": "Legacy BFV ciphertext multiplication deliberately refused; #135",
        "first_divergence": {
            "path": "legacy", "operation": "mul_ct", "reason": "refused-#135",
        },
        "supported_operations": "PASS",
        "dual_rns_depth": "PASS",
        "checked_depth": requested,
        "security_equivalent_comparison": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--probe-exit", required=True, type=int)
    args = parser.parse_args()
    result = validate(json.loads(args.input.read_text(encoding="utf-8")), args.probe_exit)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
