#!/usr/bin/env python3
"""Check the refresh arithmetic proofs with the pinned, actual Lean kernel.

This gate is independent of Mathlib's cache and the existing full proof gate.
It establishes the stated algebraic/model theorems, not Rust refinement or
cryptographic security. Every invocation builds fresh oleans in a temporary
directory and audits elaborated declarations and their transitive axioms.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


MODULES = (
    "KElimination.PublicRefreshReturn",
    "KElimination.PublicRefreshBounds",
    "KElimination.PublicRefreshGeometry",
)
AUDIT = "scripts/PublicRefreshAudit.lean"


class ProofError(RuntimeError):
    """A missing input, compiler failure, or rejected proof dependency."""


def run_lean(lean, arguments, package, environment):
    try:
        result = subprocess.run(
            [lean, *arguments], cwd=package, env=environment,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=180, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ProofError(f"cannot execute Lean: {error}") from error
    if result.returncode:
        raise ProofError(f"Lean failed ({result.returncode}):\n{result.stdout}")
    return result.stdout


def verify(package, lean="lean"):
    package = Path(package).resolve()
    sources = [name.replace(".", "/") + ".lean" for name in MODULES]
    inputs = ["lean-toolchain", *sources, AUDIT]
    for name in inputs:
        if not (package / name).is_file():
            raise ProofError(f"missing proof input: {name}")
    toolchain = (package / "lean-toolchain").read_text().strip()
    prefix = "leanprover/lean4:v"
    if not toolchain.startswith(prefix):
        raise ProofError("unsupported Lean toolchain declaration")
    with tempfile.TemporaryDirectory(prefix="nine65-refresh-proofs-") as directory:
        # Only this fresh output tree and Lean's own standard library are used.
        environment = dict(os.environ, LEAN_PATH=directory)
        version = run_lean(lean, ["--version"], package, environment).strip()
        expected = toolchain[len(prefix):]
        if not version.startswith(f"Lean (version {expected},"):
            raise ProofError(f"Lean version mismatch: expected {expected}; got {version}")
        modules = []
        for name, source in zip(MODULES, sources):
            output = Path(directory) / (name.replace(".", "/") + ".olean")
            output.parent.mkdir(parents=True, exist_ok=True)
            log = run_lean(lean, ["-DwarningAsError=true", "-o", str(output), source],
                           package, environment)
            modules.append({"name": name, "source": source, "log": log})
        audit = run_lean(lean, ["-DwarningAsError=true", AUDIT], package, environment)
        if "Public refresh axiom audit OK" not in audit:
            raise ProofError("missing successful kernel axiom audit")
    return {
        "schema": "nine65-public-refresh-proofs-v1",
        "status": "passed",
        "lean_version": version,
        "toolchain": toolchain,
        "modules": modules,
        "audit": audit,
        "sha256": {name: hashlib.sha256((package / name).read_bytes()).hexdigest()
                   for name in inputs},
        "scope": "arithmetic/model theorems; no Rust refinement or security admission",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path,
                        default=Path(__file__).resolve().parents[1] / "lean4/KElimination")
    parser.add_argument("--lean", default=os.environ.get("LEAN", "lean"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = verify(args.package, args.lean)
    except ProofError as error:
        parser.exit(1, f"Public refresh proof gate FAILED: {error}\n")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(report["audit"].strip())
    print(f"Verified {len(MODULES)} public refresh proof modules with {report['lean_version']}")


if __name__ == "__main__":
    main()
