"""Check the actual PyO3 extension's entropy boundary without installing a wheel.

Select the expected mode explicitly so a release build cannot silently run only
research checks, or vice versa. No mocks and no third-party Python dependencies.
"""

import argparse
import importlib.util
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--extension", type=Path, required=True)
    parser.add_argument("--mode", choices=("release", "research"), required=True)
    args = parser.parse_args()
    extension = args.extension.resolve(strict=True)
    name = "nine65_python._nine65_python"
    spec = importlib.util.spec_from_file_location(name, extension)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load extension: {extension}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sys.modules[name] = module
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))
    import nine65_python as n65

    ctx = n65.context_for("secure_128")
    secure_keys = ctx.generate_keyset_secure()
    secure_ct = ctx.encrypt(42, secure_keys.public_key)
    assert ctx.decrypt(secure_ct, secure_keys.secret_key) == 42
    helper = n65.Nine65.build("secure_128")
    assert helper.decrypt(helper.encrypt(7)) == 7

    seeded_calls = (
        lambda: ctx.generate_keyset_seeded(42),
        lambda: ctx.encrypt_seeded(42, secure_keys.public_key, 42),
        lambda: n65.generate_keypair(ctx, seed=42),
        lambda: n65.Nine65.build("secure_128", seed=42),
    )
    if args.mode == "release":
        for call in seeded_calls:
            try:
                call()
            except ValueError as error:
                assert "disabled in release builds" in str(error), str(error)
            else:
                raise AssertionError("Release build accepted a seeded operation")
        print("PASS: 4 seeded routes raise ValueError; 2 secure round trips")
    else:
        for call in seeded_calls:
            call()
        first = ctx.generate_keyset_seeded(42)
        second = n65.generate_keypair(ctx, seed=42)
        assert first.public_key.to_bytes() == second.public_key.to_bytes()
        a = ctx.encrypt_seeded(42, first.public_key, 7)
        b = ctx.encrypt_seeded(42, second.public_key, 7)
        assert a.to_bytes() == b.to_bytes()
        assert ctx.decrypt(a, second.secret_key) == 42
        print("PASS: 4 seeded routes; reproducible keys/ciphertexts; secure controls")


if __name__ == "__main__":
    main()
