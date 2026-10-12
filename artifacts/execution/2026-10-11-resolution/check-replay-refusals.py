#!/usr/bin/env python3
"""Exercise compiler and database refusals using isolated invalid inputs."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def must_refuse(command, message):
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode == 0 or message not in result.stderr:
        raise RuntimeError(f"Expected refusal absent: {message}")
    print(message + ": refused")


def main():
    artifact = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix="nine65-replay-negative-") as tmp:
        root = Path(tmp)
        replay = root / "replay-add-benchmark.py"
        shutil.copyfile(artifact / replay.name, replay)
        data = json.loads((artifact / "add-benchmark.json").read_text())
        data["toolchain"] = "rustc 0.0.0 (invalid recorded compiler)"
        (root / "add-benchmark.json").write_text(json.dumps(data))
        must_refuse([sys.executable, str(replay)], "Recorded compiler differs")

        db = root / "database" / "advisory-db-3157b0e258782691"
        db.mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(db)], check=True)
        tracked = db / "fixture.toml"
        tracked.write_text('fixture = "clean"\n')
        subprocess.run(["git", "-C", str(db), "add", "fixture.toml"], check=True)
        subprocess.run(["git", "-C", str(db), "-c", "user.name=Fixture",
                        "-c", "user.email=fixture@example.invalid", "commit", "-q",
                        "-m", "Create fixture"], check=True)
        revision = subprocess.check_output(["git", "-C", str(db), "rev-parse", "HEAD"],
                                           text=True).strip()
        output = root / "output"
        command = [sys.executable, str(artifact / "verify-deny.py"),
                   "--cargo-deny", str(root / "not-invoked"),
                   "--advisory-db", str(db.parent), "--advisory-revision", revision,
                   "--output-directory", str(output)]
        tracked.write_text('fixture = "modified"\n')
        must_refuse(command, "Advisory database checkout is dirty")
        tracked.write_text('fixture = "clean"\n')
        (db / "untracked.toml").write_text('fixture = "untracked"\n')
        must_refuse(command, "Advisory database checkout is dirty")
        if output.exists():
            raise RuntimeError("Dirty fixture produced verification metadata")
    print("3 refusal cases passed")


if __name__ == "__main__":
    main()
