#!/usr/bin/env python3
"""Run the local FHE operator service with private, reusable development tokens."""
import argparse
import json
import os
from pathlib import Path
import secrets
import shlex
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--no-build", action="store_true",
                        help="run an already built release service")
    parser.add_argument("--allow-decrypt", action="store_true",
                        help="enable owner/operator decryption for local development")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    root = Path(__file__).resolve().parents[1]
    state_dir = root / "work/local-service"
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    state_dir.chmod(0o700)
    credentials_path = state_dir / "credentials.json"
    if credentials_path.exists():
        credentials = json.loads(credentials_path.read_text())
    else:
        credentials = {key: secrets.token_urlsafe(32) for key in
                       ("internal_api", "tenant", "decrypt")}
        with os.fdopen(os.open(credentials_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as file:
            json.dump(credentials, file)
    credentials_path.chmod(0o600)
    if any(not isinstance(credentials.get(key), str) or not credentials[key] for key in
           ("internal_api", "tenant", "decrypt")):
        parser.error("invalid local credentials file")
    env = os.environ.copy()
    env.update({
        "FHE_SERVICE_HOST": "127.0.0.1", "FHE_SERVICE_PORT": str(args.port),
        "FHE_API_TOKEN": credentials["internal_api"],
        "FHE_TENANT_TOKENS": "local=" + credentials["tenant"],
    })
    env.pop("FHE_OPERATOR_TOKEN", None)
    env.pop("FHE_ENABLE_DECRYPT", None)
    env.pop("FHE_DECRYPT_TOKEN", None)
    client_env = {
        "FHE_SERVICE_URL": f"http://127.0.0.1:{args.port}",
        "FHE_TENANT_ID": "local", "FHE_TENANT_TOKEN": credentials["tenant"],
    }
    if args.allow_decrypt:
        env.update(FHE_ENABLE_DECRYPT="1", FHE_DECRYPT_TOKEN=credentials["decrypt"])
        client_env["FHE_DECRYPT_TOKEN"] = credentials["decrypt"]
    client_path = state_dir / "client.env"
    with os.fdopen(os.open(client_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as file:
        file.write("# Private local client credentials. Keep this file out of version control.\n")
        file.write("unset FHE_DECRYPT_TOKEN FHE_OPERATOR_TOKEN\n")
        for key, value in client_env.items():
            file.write(f"export {key}={shlex.quote(value)}\n")
    client_path.chmod(0o600)
    if not args.no_build:
        subprocess.run(["cargo", "build", "--locked", "--release", "-p", "fhe-service"],
                       cwd=root, check=True)
    target = Path(env.get("CARGO_TARGET_DIR", "target"))
    if not target.is_absolute():
        target = root / target
    binary = target / "release/fhe-service"
    if not binary.is_file():
        parser.error("release service is not built; rerun without --no-build")
    print(f"Starting local operator service at {client_env['FHE_SERVICE_URL']}", flush=True)
    print(f"Client setup: source {shlex.quote(str(client_path))}", flush=True)
    print(f"Operator decryption: {'enabled' if args.allow_decrypt else 'disabled'}", flush=True)
    os.chdir(root)
    os.execve(str(binary), [str(binary)], env)


if __name__ == "__main__":
    main()
