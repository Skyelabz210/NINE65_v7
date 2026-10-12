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
        (db / "untracked.toml").unlink()

        project = root / "project"
        test_artifact = project / "artifacts" / "execution" / "fixture"
        test_artifact.mkdir(parents=True)
        shutil.copyfile(artifact / "verify-deny.py", test_artifact / "verify-deny.py")
        (project / "src").mkdir()
        (project / "src" / "lib.rs").write_text("// Manifest verification fixture.\n")
        manifest = project / "Cargo.toml"
        original_manifest = '[package]\nname="manifest-fixture"\nversion="0.0.0"\nedition="2021"\n'
        manifest.write_text(original_manifest)
        (project / "deny.toml").write_text('[advisories]\nunmaintained="all"\n[licenses]\nallow=["MIT"]\n')
        subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=project,
                       check=True, capture_output=True)
        subprocess.run(["git", "init", "-q", str(project)], check=True)
        subprocess.run(["git", "-C", str(project), "add", "."], check=True)
        subprocess.run(["git", "-C", str(project), "-c", "user.name=Fixture",
                        "-c", "user.email=fixture@example.invalid", "commit", "-q",
                        "-m", "Create manifest fixture"], check=True)
        fake_binary = root / "fake-cargo-deny"
        fake_binary.write_text(
            "#!/usr/bin/env python3\nfrom pathlib import Path\nimport sys\n"
            "if '--version' in sys.argv: print('cargo-deny fixture')\n"
            "else:\n    p=Path(" + repr(str(manifest)) + ")\n"
            "    p.write_text(p.read_text()+'\\n# changed during verification\\n')\n"
        )
        fake_binary.chmod(0o755)
        manifest_command = [sys.executable, str(test_artifact / "verify-deny.py"),
                            "--cargo-deny", str(fake_binary), "--advisory-db", str(db.parent),
                            "--advisory-revision", revision, "--output-directory", str(output)]
        manifest.write_text(original_manifest + "\n# initially dirty\n")
        must_refuse(manifest_command, "Dependency manifests are dirty")
        manifest.write_text(original_manifest)
        must_refuse(manifest_command, "Dependency manifests are dirty")
        if (output / "cargo-deny-invocation.json").exists():
            raise RuntimeError("Changed manifest produced verification metadata")
    print("5 refusal cases passed")


if __name__ == "__main__":
    main()
