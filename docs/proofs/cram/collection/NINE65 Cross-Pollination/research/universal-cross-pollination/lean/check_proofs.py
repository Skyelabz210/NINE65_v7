#!/usr/bin/env python3
"""Fresh standalone build and transitive axiom audit; Python standard library.

All project imports are compiled into a new temporary directory. No supplied
project .olean file is read. Lean's pinned bundled standard library is used.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
MODULES = ['ExactObservation', 'UniversalLift', 'RingReadout', 'IntegerSpecialization', 'CostedReadout', 'ReferenceChange', 'CoupledAnchors', 'ResidueAlgorithms', 'ResiduePrimitives', 'StarLift', 'UniversalKElimination', 'ConsumerTransport', 'AllResearch']
ALLOWED_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}


def without_comments(text):
    """Strip Lean line comments and nested block comments for policy checks."""
    out, i, depth = [], 0, 0
    while i < len(text):
        if text.startswith("/-", i):
            depth += 1
            i += 2
        elif depth and text.startswith("-/", i):
            depth -= 1
            i += 2
        elif depth:
            out.append("\n" if text[i] == "\n" else " ")
            i += 1
        elif text.startswith("--", i):
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
        else:
            out.append(text[i])
            i += 1
    if depth:
        raise RuntimeError("Unclosed block comment")
    return "".join(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lean", default="lean", help="Pinned Lean executable or elan wrapper")
    args = parser.parse_args()
    executable = shutil.which(args.lean)
    if executable is None:
        raise RuntimeError("Lean executable not found: " + args.lean)
    executable = str(Path(executable).absolute())
    log, files, all_theorems = [], [], []
    toolchain = (ROOT / "lean-toolchain").read_text().strip()
    expected_version = toolchain.split(":v", 1)[1]
    with tempfile.TemporaryDirectory(prefix="kelim-universal-") as directory:
        build = Path(directory)
        shutil.copy2(ROOT / "lean-toolchain", build / "lean-toolchain")
        env = os.environ.copy()
        env["LEAN_PATH"] = str(build)
        version = subprocess.run([executable, "--version"], cwd=build, env=env,
                                 text=True, capture_output=True, check=True).stdout.strip()
        if not version.startswith("Lean (version " + expected_version + ","):
            raise RuntimeError("Wrong Lean version: " + version)
        log.append(version + "\n")
        for module in MODULES:
            source = ROOT / (module + ".lean")
            data = source.read_bytes()
            body = without_comments(data.decode())
            if re.search(r"\b(sorry|admit|unsafe)\b", body):
                raise RuntimeError("Admitted or unsafe declaration in " + source.name)
            if re.search(r"^\s*(axiom|constant|opaque)\s", body, re.M):
                raise RuntimeError("Custom assumed declaration in " + source.name)
            declared = re.findall(r"^\s*theorem\s+(\S+)", body, re.M)
            printed = re.findall(r"^#print axioms\s+(\S+)", body, re.M)
            if len(declared) != len(printed) or len(set(printed)) != len(printed):
                raise RuntimeError("Every theorem needs one axiom query in " + source.name)
            shutil.copy2(source, build / source.name)
            cmd = [executable, "-o", module + ".olean", source.name]
            result = subprocess.run(cmd, cwd=build, env=env, text=True, capture_output=True)
            output = result.stdout + result.stderr
            log.append("$ lean -o " + module + ".olean " + source.name + "\n" + output)
            (ROOT / "verification.log").write_text("\n".join(log))
            if result.returncode or re.search(r"\b(error|warning):", output):
                raise RuntimeError("Lean failed or warned in " + source.name)
            pattern = r"'([^']+)' (?:depends on axioms: \[([^]]*)\]|does not depend on any axioms)"
            found = re.findall(pattern, output)
            if [name for name, _ in found] != printed:
                raise RuntimeError("Axiom output does not match queries in " + source.name)
            module_theorems = []
            for name, raw in found:
                axioms = [a.strip() for a in raw.replace("\n", " ").split(",") if a.strip()]
                if set(axioms) - ALLOWED_AXIOMS:
                    raise RuntimeError("Unexpected axioms in " + name + ": " + str(axioms))
                row = {"name": name, "axioms": axioms}
                module_theorems.append(row)
                all_theorems.append(row)
            files.append({"file": source.name, "sha256": hashlib.sha256(data).hexdigest(),
                          "theorem_count": len(found), "theorems": module_theorems})
    report = {"status": "PASS", "toolchain": toolchain, "lean_version": version,
              "fresh_temporary_build": True, "project_olean_reused": False,
              "imports": "Pinned Lean bundled Std; no Mathlib dependency",
              "theorem_declarations": len(all_theorems),
              "reused_dependency_theorems": sum(f["theorem_count"] for f in files if f["file"] != "ConsumerTransport.lean"),
              "new_theorem_declarations": next(f["theorem_count"] for f in files if f["file"] == "ConsumerTransport.lean"),
              "new_axiom_free_declarations": sum(not t["axioms"] for f in files if f["file"] == "ConsumerTransport.lean" for t in f["theorems"]),
              "axiom_free_declarations": sum(not t["axioms"] for t in all_theorems),
              "allowed_foundational_axioms": sorted(ALLOWED_AXIOMS),
              "files": files}
    (ROOT / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "files"}, indent=2))


if __name__ == "__main__":
    main()
