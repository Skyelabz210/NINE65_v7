#!/usr/bin/env python3
"""Exact source-contract gate for the WIRE-Q and single-RNS mul boundary.

This checks the two fail-closed boundaries introduced by this branch without
depending on a Rust toolchain: the service cannot base64 transport dual-RNS
ciphertexts, and RNSFHEContext::mul verifies that the selected route is the
certified single-RNS route before entering the legacy per-limb rescale.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise AssertionError(f"unclosed function body for {signature}")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    rns_fhe = (ROOT / "crates/nine65/src/ops/rns_fhe.rs").read_text(encoding="utf-8")
    session = (ROOT / "crates/fhe-service/src/session.rs").read_text(encoding="utf-8")

    guard = function_body(rns_fhe, "fn require_bajard_single_mul_route")
    mul = function_body(rns_fhe, "pub fn mul(&self, ct1: &RNSCiphertext")
    require("matches!(self.mul_route(), MulRoute::BajardSingle)" in guard,
            "single-RNS certified-route guard is missing")
    require("self.require_bajard_single_mul_route();" in mul,
            "public single-RNS mul does not invoke its certified-route guard")
    require(mul.index("self.require_bajard_single_mul_route();")
            < mul.index("let d0 = self.rns_poly_mul"),
            "mul route guard must run before tensor/rescale work")

    export = function_body(session, "pub fn dual_ct_to_b64")
    import_ = function_body(session, "pub fn dual_ct_from_b64")
    for name, body in (("dual export", export), ("dual import", import_)):
        require("WIRE-Q:" in body, f"{name} lacks WIRE-Q failure")
        require("Err(" in body, f"{name} does not fail closed")
    require("to_bytes(" not in export, "dual export still serializes anchor lanes")
    require("from_bytes_validated(" not in import_, "dual import still deserializes anchor lanes")
    require("base64::" not in import_, "dual import must reject before decoding")

    print("WIRE-Q fail-closed source gate: PASS")
    print("single-RNS route guard: PASS")
    print("dual-RNS service export/import: PASS")


if __name__ == "__main__":
    main()
