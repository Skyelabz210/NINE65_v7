"""Compile unchanged user sources and run admission checks. Failures exit 1.

Requires rustc and the two original .rs attachments; no Cargo dependencies.
Raw attachments are deliberately not vendored into this repository.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("materials", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    here = Path(__file__).resolve().parent
    manifest = json.loads((here.parent / "evidence/supplied-materials.json").read_text())
    expected = {row["name"]: row["sha256"] for row in manifest}
    results = {"rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
               "sources": {}, "runs": []}
    failed = False
    with tempfile.TemporaryDirectory(prefix="nine65-materials-") as tmp:
        work = Path(tmp)
        for name in ("recumbent_crt_bigint.rs", "recumbent_weights.rs"):
            source = (args.materials / name).read_bytes()
            digest = hashlib.sha256(source).hexdigest()
            if digest != expected[name]:
                parser.error(f"{name}: SHA-256 differs from the reviewed attachment")
            results["sources"][name] = digest
            (work / name).write_bytes(source)
        shutil.copyfile(here / "adversarial.rs", work / "adversarial.rs")

        def run(label, cmd):
            nonlocal failed
            proc = subprocess.run(cmd, cwd=work, text=True, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, check=False)
            log = proc.stdout.replace(str(work), "<temporary-directory>")
            log = log.rstrip() + "\n" if log else ""
            (output / f"{label}.log").write_text(log)
            summary = re.search(r"test result: .*", log)
            results["runs"].append({"label": label, "command": cmd,
                                    "exit_code": proc.returncode,
                                    "summary": summary.group() if summary else None})
            failed |= proc.returncode != 0
            return proc.returncode == 0

        for name in ("recumbent_crt_bigint", "recumbent_weights"):
            if run(f"{name}-compile", ["rustc", "--edition=2021", "--test", "-Awarnings",
                                      f"{name}.rs", "-o", name]):
                run(f"{name}-tests", [f"./{name}", "--test-threads=1"])
        for profile, flags in (("debug", []), ("release", ["-O"])):
            binary = f"adversarial-{profile}"
            if run(f"{binary}-compile", ["rustc", "--edition=2021", "--test", "-Awarnings",
                                         *flags, "adversarial.rs", "-o", binary]):
                run(binary, [f"./{binary}", "audit_", "--test-threads=1"])
    (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results, indent=2))
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
