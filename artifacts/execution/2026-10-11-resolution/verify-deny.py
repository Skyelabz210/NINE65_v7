#!/usr/bin/env python3
"""Check the committed policy with an identified, frozen advisory database."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import tomllib


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cargo-deny", type=Path, required=True)
    parser.add_argument("--advisory-db", type=Path, required=True,
                        help="Cargo-deny database root containing advisory-db-3157b0e258782691")
    parser.add_argument("--advisory-revision", required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    artifact = Path(__file__).resolve().parent
    repo = artifact.parents[2]
    binary = args.cargo_deny.resolve()
    db_root = args.advisory_db.resolve()
    db_repo = db_root / "advisory-db-3157b0e258782691"
    revision = subprocess.check_output(["git", "-C", str(db_repo), "rev-parse", "HEAD"],
                                       text=True).strip()
    if revision != args.advisory_revision:
        raise RuntimeError("Advisory database revision differs from the requested snapshot")
    policy = repo / "deny.toml"
    original = policy.read_text()
    generated = original.replace("[advisories]\n",
                                 "[advisories]\ndb-path = " + json.dumps(str(db_root)) + "\n", 1)
    normalized = tomllib.loads(generated)
    normalized["advisories"].pop("db-path")
    if normalized != tomllib.loads(original):
        raise RuntimeError("Temporary policy is not identical to the committed policy")
    output = args.output_directory.resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="nine65-deny-check-") as tmp:
        config = Path(tmp) / "deny.toml"
        config.write_text(generated)
        command = [str(binary), "--offline", "--locked", "--all-features",
                   "--config", str(config), "check"]
        result = subprocess.run(command, cwd=repo, capture_output=True)
        (output / "cargo-deny-final.log").write_bytes(result.stdout + result.stderr)
        (output / "cargo-deny-config.toml").write_text(generated)
        record = {
            "command": shlex.join(command), "argv": command, "cwd": str(repo),
            "exit_code": result.returncode,
            "binary_version": subprocess.check_output([str(binary), "--version"], text=True).strip(),
            "binary_sha256": digest(binary), "policy_sha256": digest(policy),
            "cargo_lock_sha256": digest(repo / "Cargo.lock"),
            "config_sha256": digest(config), "config_archive": "cargo-deny-config.toml",
            "policy_equivalence_verified": True,
            "advisory_database": {"root": str(db_root), "repository": str(db_repo),
                                  "url": "https://github.com/RustSec/advisory-db",
                                  "revision": revision, "fetch_disabled": True},
            "log": "cargo-deny-final.log",
            "log_sha256": digest(output / "cargo-deny-final.log"),
        }
        (output / "cargo-deny-invocation.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record, indent=2))
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
