#!/usr/bin/env python3
"""Fresh pinned Lean build and transitive axiom audit, without project cache reuse.

Uses only Python's standard library and the official Lean distribution. Audits
all authored theorems, definitions and structures, not just selected headlines.
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

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}


def strip_comments(text):
    out, i, depth = [], 0, 0
    while i < len(text):
        if text.startswith("/-", i):
            depth += 1
            out.extend("  ")
            i += 2
        elif depth and text.startswith("-/", i):
            depth -= 1
            out.extend("  ")
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
        raise RuntimeError("Unclosed Lean comment")
    return "".join(out)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lean", default="lean")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "evidence")
    args = parser.parse_args()
    executable = shutil.which(args.lean)
    if not executable:
        raise RuntimeError("Pinned Lean executable is required: " + args.lean)
    executable = str(Path(executable).absolute())
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    receipt = output / "verification.json"
    receipt.unlink(missing_ok=True)
    sources = {str(p.relative_to(ROOT).with_suffix("")).replace("/", "."): p
               for p in sorted(ROOT.rglob("*.lean")) if ".lake" not in p.parts}
    tracked = list(sources.values()) + [ROOT / "lean-toolchain", ROOT / "lakefile.toml",
                                       ROOT / "lake-manifest.json", Path(__file__).resolve()]
    snapshot = {p: p.read_bytes() for p in tracked}
    imports, declarations = {}, []
    for module, path in sources.items():
        body = strip_comments(snapshot[path].decode())
        forbidden = r"\b(sorry|admit|unsafe|native_decide|implemented_by|extern|axiom|opaque|constant)\b"
        if re.search(forbidden, body) or "skipKernelTC" in body:
            raise RuntimeError("Unapproved admission or trust escape in " + str(path))
        unsupported = r"^\s*(?:(?:private|protected|noncomputable)\s+)?(?:lemma|abbrev|instance|class|inductive|mutual|elab|macro|syntax|initialize|builtin_initialize|run_cmd)\b"
        if re.search(unsupported, body, re.M) or re.search(r"^\s*#", body, re.M):
            raise RuntimeError("Update audit for unsupported declaration/command: " + module)
        import_lines = re.findall(r"^import[^\n]*", body, re.M)
        if any(not re.fullmatch(r"import\s+\S+\s*", line) for line in import_lines):
            raise RuntimeError("Update audit for multi-module/multiline imports: " + module)
        imports[module] = re.findall(r"^import\s+(\S+)\s*$", body, re.M)
        for dependency in imports[module]:
            if dependency != "Lean" and dependency not in sources:
                raise RuntimeError("Unexpected external import: " + dependency)
        namespaces = re.findall(r"^namespace\s+(\S+)\s*$", body, re.M)
        if namespaces and namespaces != ["FoliatedCoprimeGeometry"]:
            raise RuntimeError("Update declaration inventory for nested namespaces: " + module)
        for kind, name in re.findall(r"^(?:private\s+)?(theorem|def|structure)\s+(\w+)", body, re.M):
            declarations.append({"name": "FoliatedCoprimeGeometry." + name,
                                 "kind": kind, "file": str(path.relative_to(ROOT))})
    if len({d["name"] for d in declarations}) != len(declarations):
        raise RuntimeError("Duplicate authored declaration names")
    order, visiting = [], set()

    def visit(module):
        if module in order:
            return
        if module in visiting:
            raise RuntimeError("Cyclic module imports")
        visiting.add(module)
        for dependency in imports[module]:
            if dependency in sources:
                visit(dependency)
        visiting.remove(module)
        order.append(module)

    for module in sources:
        visit(module)
    toolchain = snapshot[ROOT / "lean-toolchain"].decode().strip()
    expected = toolchain.split(":v", 1)[1]
    log = []

    def run(command, cwd, env):
        result = subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True)
        text = result.stdout + result.stderr
        log.append("$ " + " ".join(command) + "\n" + text)
        (output / "verification.log").write_text("\n".join(log))
        if result.returncode or re.search(r"\b(?:warning|error):", text):
            raise RuntimeError("Lean check failed; see " + str(output / "verification.log"))
        return text

    with tempfile.TemporaryDirectory(prefix="foliated-lean-") as directory:
        build = Path(directory)
        (build / "lean-toolchain").write_bytes(snapshot[ROOT / "lean-toolchain"])
        env = os.environ.copy()
        env["LEAN_PATH"] = str(build)
        version = run([executable, "--version"], build, env).strip()
        if not version.startswith("Lean (version " + expected + ","):
            raise RuntimeError("Wrong toolchain: " + version)
        for module in order:
            source = sources[module]
            target = build / source.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(snapshot[source])
            run([executable, "-o", str(target.relative_to(build).with_suffix(".olean")),
                 str(target.relative_to(build))], build, env)
        audit = "import FoliatedCoprimeGeometry\n" + "\n".join(
            "#print axioms " + d["name"] for d in declarations) + "\n"
        (build / "Audit.lean").write_text(audit)
        result = run([executable, "Audit.lean"], build, env)
        found = re.findall(r"'([^']+)' (?:depends on axioms: \[([^]]*)\]|does not depend on any axioms)", result)
        if [n for n, _ in found] != [d["name"] for d in declarations]:
            raise RuntimeError("Axiom output does not match full authored inventory")
        for declaration, (_, raw) in zip(declarations, found):
            axioms = [a.strip() for a in raw.replace("\n", " ").split(",") if a.strip()]
            if set(axioms) - ALLOWED_AXIOMS:
                raise RuntimeError("Unapproved axioms: " + repr((declaration, axioms)))
            declaration["axioms"] = axioms
    current_sources = {p for p in ROOT.rglob("*.lean") if ".lake" not in p.parts}
    if current_sources != set(sources.values()) or any(p.read_bytes() != data for p, data in snapshot.items()):
        raise RuntimeError("Sources changed during verification; rerun against a stable snapshot")
    source_hashes = {str(p.relative_to(ROOT)): hashlib.sha256(snapshot[p]).hexdigest() for p in sorted(tracked)}
    report = {"status": "PASS", "toolchain": toolchain, "lean_version": version,
              "fresh_temporary_build": True, "project_olean_reused": False,
              "external_packages": [], "bundled_imports": ["Lean"],
              "lean_executable_sha256": digest(Path(executable).resolve()),
              "snapshot_unchanged_at_completion": True,
              "source_base_commit": "64c1c89b191093dc12cf81b87da5fb1a02c46dc1",
              "authored_theorems": sum(d["kind"] == "theorem" for d in declarations),
              "audited_authored_declarations": len(declarations),
              "axiom_free_theorems": sum(d["kind"] == "theorem" and not d["axioms"] for d in declarations),
              "used_axioms": sorted({a for d in declarations for a in d["axioms"]}),
              "allowed_foundational_axioms": sorted(ALLOWED_AXIOMS),
              "module_order": order, "source_sha256": source_hashes,
              "declarations": declarations}
    receipt.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items()
                      if k not in {"declarations", "source_sha256", "module_order"}}, indent=2))


if __name__ == "__main__":
    main()
