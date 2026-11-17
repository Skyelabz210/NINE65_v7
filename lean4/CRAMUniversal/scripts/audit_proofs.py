#!/usr/bin/env python3
"""Build maintained Lean modules and audit every project theorem's axioms.

Uses the checked-in Lean and Lake manifest pins. Mathlib dependencies may use
locally compiled artifacts; the separate standard-library research audit also
supports a fully fresh project build. This checks declarations, not runtime
implementation equivalence or cryptographic security.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ALLOWED = {"propext", "Classical.choice", "Quot.sound"}


def uncomment(text):
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
        raise RuntimeError("Unclosed comment")
    return "".join(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lake", default="lake")
    parser.add_argument("--output", type=Path, default=ROOT / "verification")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.setdefault("LEAN_NUM_THREADS", "2")
    sources = [ROOT / "KElimination.lean", *sorted((ROOT / "KElimination").rglob("*.lean"))]
    files, all_names = [], []
    for source in sources:
        body = uncomment(source.read_text())
        if re.search(r"\b(sorry|admit|unsafe)\b", body):
            raise RuntimeError("Admitted or unsafe declaration: " + str(source))
        if re.search(r"^\s*(axiom|constant|opaque)\s", body, re.M):
            raise RuntimeError("Custom assumed declaration: " + str(source))
        declarations = re.findall(r"^\s*(?:theorem|lemma)\s+(\S+)", body, re.M)
        printed = re.findall(r"^#print axioms\s+(\S+)", body, re.M)
        if printed:
            if len(printed) != len(declarations):
                raise RuntimeError("Incomplete local axiom queries: " + str(source))
            names = printed
        else:
            # The two legacy files have top-level named namespaces only.
            names, namespaces = [], []
            for line in body.splitlines():
                match = re.match(r"^namespace\s+(\S+)", line)
                if match:
                    namespaces.append(match.group(1))
                elif re.match(r"^end(?:\s|$)", line):
                    if namespaces:
                        namespaces.pop()
                else:
                    match = re.match(r"^\s*(?:theorem|lemma)\s+(\S+)", line)
                    if match:
                        names.append(".".join([*namespaces, match.group(1)]))
            if len(names) != len(declarations):
                raise RuntimeError("Declaration inventory mismatch: " + str(source))
        files.append({"file": str(source.relative_to(ROOT)),
                      "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                      "theorem_count": len(names), "names": names})
        all_names.extend(names)
    if len(set(all_names)) != len(all_names):
        raise RuntimeError("Duplicate theorem inventory")
    version = subprocess.run([args.lake, "env", "lean", "--version"], cwd=ROOT,
        env=env, text=True, capture_output=True, check=True).stdout.strip()
    pin = (ROOT / "lean-toolchain").read_text().strip()
    if not version.startswith("Lean (version " + pin.split(":v", 1)[1] + ","):
        raise RuntimeError("Toolchain mismatch: " + version)
    build = subprocess.run([args.lake, "--no-cache", "build"], cwd=ROOT,
        env=env, text=True, capture_output=True)
    (args.output / "build.log").write_text(build.stdout + build.stderr)
    if build.returncode or re.search(r"\b(error|warning):", build.stdout + build.stderr):
        raise RuntimeError("Build failed or warned; see build.log")
    with tempfile.TemporaryDirectory(prefix="kelim-axioms-") as temporary:
        audit = Path(temporary) / "Audit.lean"
        audit.write_text("import KElimination\n\n" +
                         "\n".join("#print axioms " + n for n in all_names) + "\n")
        result = subprocess.run([args.lake, "env", "lean", str(audit)], cwd=ROOT,
            env=env, text=True, capture_output=True)
    output = result.stdout + result.stderr
    (args.output / "axioms.log").write_text(output)
    if result.returncode or re.search(r"\b(error|warning):", output):
        raise RuntimeError("Axiom audit failed or warned; see axioms.log")
    pattern = r"'([^']+)' (?:depends on axioms: \[([^]]*)\]|does not depend on any axioms)"
    found = re.findall(pattern, output)
    if [name for name, _ in found] != all_names:
        raise RuntimeError("Axiom output does not match complete inventory")
    audited = []
    for name, raw in found:
        axioms = [x.strip() for x in raw.replace("\n", " ").split(",") if x.strip()]
        if set(axioms) - ALLOWED:
            raise RuntimeError("Unexpected axiom in " + name + ": " + str(axioms))
        audited.append({"name": name, "axioms": axioms})
    revision = subprocess.run(["git", "-C", str(ROOT / ".lake/packages/mathlib"),
        "rev-parse", "HEAD"], text=True, capture_output=True, check=True).stdout.strip()
    report = {"status": "PASS", "toolchain": pin, "lean_version": version,
              "mathlib_revision": revision,
              "lake_manifest_sha256": hashlib.sha256((ROOT / "lake-manifest.json").read_bytes()).hexdigest(),
              "theorem_declarations": len(audited),
              "axiom_free_declarations": sum(not t["axioms"] for t in audited),
              "allowed_foundational_axioms": sorted(ALLOWED),
              "files": files, "theorems": audited,
              "scope": "All maintained project Lean declarations; no Coq revalidation or source-level runtime refinement"}
    (args.output / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k not in {"files", "theorems"}}, indent=2))


if __name__ == "__main__":
    main()
