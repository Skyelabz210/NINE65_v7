#!/usr/bin/env python3
"""Check the committed policy with an identified, frozen advisory database."""
import argparse
import gzip
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
    def verify_database():
        status = subprocess.check_output(
            ["git", "-C", str(db_repo), "status", "--porcelain", "--untracked-files=all"],
            text=True,
        )
        if status.strip():
            raise RuntimeError("Advisory database checkout is dirty")
        revision = subprocess.check_output(["git", "-C", str(db_repo), "rev-parse", "HEAD"],
                                           text=True).strip()
        if revision != args.advisory_revision:
            raise RuntimeError("Advisory database revision differs from the requested snapshot")
        return revision

    revision = verify_database()

    def verify_policy_inputs():
        status = subprocess.check_output(
            ["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=all",
             "--", "deny.toml", "Cargo.lock"], text=True,
        )
        if status.strip():
            raise RuntimeError("Policy or lock inputs are dirty")

    verify_policy_inputs()

    def repository_manifests():
        patterns = ["Cargo.toml", ":(glob)**/Cargo.toml"]
        status = subprocess.check_output(
            ["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=all",
             "--", *patterns], text=True,
        )
        if status.strip():
            raise RuntimeError("Dependency manifests are dirty")
        paths = subprocess.check_output(
            ["git", "-C", str(repo), "ls-files", "-z", "--", *patterns],
        ).decode().split("\0")
        return {name: digest(repo / name) for name in paths if name}

    manifest_hashes = repository_manifests()
    source_commit = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"],
                                           text=True).strip()
    metadata = subprocess.check_output(
        ["cargo", "metadata", "--offline", "--locked", "--all-features", "--format-version", "1"],
        cwd=repo,
    )
    if repository_manifests() != manifest_hashes:
        raise RuntimeError("Dependency manifests changed while generating metadata")
    packages = json.loads(metadata)["packages"]
    package_manifests = {p["manifest_path"]: digest(Path(p["manifest_path"])) for p in packages}
    policy = repo / "deny.toml"
    original_bytes = policy.read_bytes()
    original = original_bytes.decode()
    policy_hash = hashlib.sha256(original_bytes).hexdigest()
    lock_hash = digest(repo / "Cargo.lock")
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
        graph = Path(tmp) / "cargo-metadata.json"
        graph.write_bytes(metadata)
        command = [str(binary), "--offline", "--locked", "--all-features",
                   "--config", str(config), "--metadata-path", str(graph), "check"]
        result = subprocess.run(command, cwd=repo, capture_output=True)
        verify_database()
        verify_policy_inputs()
        if repository_manifests() != manifest_hashes:
            raise RuntimeError("Dependency manifests changed during verification")
        if any(digest(Path(path)) != expected for path, expected in package_manifests.items()):
            raise RuntimeError("Dependency package manifests changed during verification")
        if digest(policy) != policy_hash or digest(repo / "Cargo.lock") != lock_hash:
            raise RuntimeError("Dependency inputs changed during verification")
        (output / "cargo-deny-final.log").write_bytes(result.stdout + result.stderr)
        (output / "cargo-deny-config.toml").write_text(generated)
        (output / "cargo-metadata.json.gz").write_bytes(gzip.compress(metadata, mtime=0))
        record = {
            "command": shlex.join(command), "argv": command, "cwd": str(repo),
            "exit_code": result.returncode,
            "binary_version": subprocess.check_output([str(binary), "--version"], text=True).strip(),
            "binary_sha256": digest(binary), "policy_sha256": policy_hash,
            "cargo_lock_sha256": lock_hash,
            "config_sha256": digest(config), "config_archive": "cargo-deny-config.toml",
            "policy_equivalence_verified": True,
            "source_commit": source_commit,
            "repository_manifest_sha256": manifest_hashes,
            "package_manifest_sha256": package_manifests,
            "metadata_archive": "cargo-metadata.json.gz",
            "metadata_sha256": hashlib.sha256(metadata).hexdigest(),
            "metadata_archive_sha256": digest(output / "cargo-metadata.json.gz"),
            "cargo_version": subprocess.check_output(["cargo", "--version"], cwd=repo,
                                                     text=True).strip(),
            "advisory_database": {"root": str(db_root), "repository": str(db_repo),
                                  "url": "https://github.com/RustSec/advisory-db",
                                  "revision": revision, "fetch_disabled": True,
                                  "worktree_clean_before_and_after": True},
            "log": "cargo-deny-final.log",
            "log_sha256": digest(output / "cargo-deny-final.log"),
        }
        (output / "cargo-deny-invocation.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record, indent=2))
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
