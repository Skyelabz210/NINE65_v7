#!/usr/bin/env python3
"""Package the versioned private collection after committing implementation.

The archive captures the delivery state at build time. Its final remote receipt
is a separate artifact because an archive cannot contain its own final hash.
Original uploads must already be copied into the private collection by source ID.
"""
from pathlib import Path
from datetime import datetime, timezone
import argparse
import hashlib
import json
import shutil
import subprocess
import zipfile

CAMPAIGN = Path(__file__).resolve().parents[1]
REPO = CAMPAIGN.parents[1]
BASE = "88a7bdadbf0e1f8fbfdb2b37e9843101b8db3484"


def git(repo, *args):
    return subprocess.check_output(["git", *args], cwd=repo)


def allowed(path):
    return not any(p in {"__pycache__", ".lake", ".git", "target"} for p in path.parts) and path.suffix not in {".pyc", ".olean", ".ilean"}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collection", type=Path, required=True)
    parser.add_argument("--lean-repo", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    output = args.collection / "NINE65 Swarm Implementation"
    if output.exists():
        raise RuntimeError("Versioned output already exists; preserve it or choose a new collection")
    output.mkdir(parents=True)
    for src in CAMPAIGN.rglob("*"):
        if src.is_file() and allowed(src.relative_to(CAMPAIGN)):
            dst = output / "research" / CAMPAIGN.name / src.relative_to(CAMPAIGN)
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
    changed = git(REPO, "diff", "--name-only", BASE, "HEAD").decode().splitlines()
    changed = [s for s in changed if not s.startswith("research/")]
    support = ["AGENTS.md", "CLAUDE.md", "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "docs/PUBLIC_REFRESH_STATUS.md"]
    for name in sorted(set(changed+support)):
        src = REPO/name
        if src.is_file():
            dst = output/name
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
    (output/"repository.patch").write_bytes(git(REPO, "diff", "--binary", BASE, "HEAD"))
    lean_out = output/"k-elimination-lean4"
    for name in git(args.lean_repo, "ls-files", "-z").decode().split("\0"):
        if not name:
            continue
        src = args.lean_repo/name
        if src.is_file() and allowed(Path(name)):
            dst = lean_out/name
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
    provenance = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "nine65_base": BASE, "nine65_implementation_commit": git(REPO,"rev-parse","HEAD").decode().strip(),
        "lean_commit": git(args.lean_repo,"rev-parse","HEAD").decode().strip(),
        "scope": "Full generated campaign; changed NINE65 sources and baseline-to-implementation patch; complete tracked original Lean repository; original uploads and prior generated collection retained separately",
        "excluded": ["compiled caches", "build targets", "private Drive source bodies", "Git credentials/configuration"],
        "delivery_receipt": "Final remote upload/readback receipt is supplied separately from this immutable archive",
    }
    (output/"provenance.json").write_text(json.dumps(provenance,indent=2)+"\n")
    (output/"README.md").write_text("# NINE65 swarm implementation\n\nStart with [campaign results](research/"+CAMPAIGN.name+"/README.md).\n\n`repository.patch` applies to NINE65 base `"+BASE+"`; source snapshots here are the changed files, not a complete NINE65 checkout. The `k-elimination-lean4` directory is the complete tracked Lean project. `provenance.json` records both local revisions. Nothing was publicly pushed.\n")
    records=[]
    manifest_path=args.collection/"collection-manifest.json"
    for path in sorted(args.collection.rglob("*")):
        if path.is_file() and path != manifest_path:
            records.append({"path":str(path.relative_to(args.collection)),"bytes":path.stat().st_size,"sha256":digest(path)})
    manifest_path.write_text(json.dumps({"files":records,"file_count":len(records),"scope":"Every payload file except this manifest itself"},indent=2)+"\n")
    with zipfile.ZipFile(args.archive,"w",zipfile.ZIP_DEFLATED,compresslevel=9) as bundle:
        for path in sorted(args.collection.rglob("*")):
            if path.is_file():
                bundle.write(path,Path("CRAM Proofs")/path.relative_to(args.collection))
    with zipfile.ZipFile(args.archive) as bundle:
        if bundle.testzip() is not None:
            raise RuntimeError("Archive CRC verification failed")
        for record in records:
            raw=bundle.read("CRAM Proofs/"+record["path"])
            if hashlib.sha256(raw).hexdigest()!=record["sha256"]:
                raise RuntimeError("Archive payload hash mismatch")
    result={"archive":str(args.archive),"bytes":args.archive.stat().st_size,
            "sha256":digest(args.archive),"payload_files":len(records)+1,
            "status":"LOCAL_ARCHIVE_CONTENTS_VERIFIED",**provenance}
    receipt=args.archive.with_suffix(".manifest.json")
    receipt.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))


if __name__=="__main__":
    main()
