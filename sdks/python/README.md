# NINE65 HTTP SDK

This SDK connects to the Rust operator service and exposes its main-Q encrypted
arithmetic. It is separate from the native `nine65-python` extension.

## Local use

From the repository root, start the authenticated loopback service:

```bash
python3 scripts/run_local_service.py --allow-decrypt
```

The launcher builds the release binary, creates private development tokens in
`work/local-service/`, and prints the client setup path. Tokens are not printed.
Operator metrics remain disabled. Omit `--allow-decrypt` for evaluation-only
operation. `--no-build` runs an already built binary.

In your client shell:

```bash
python3 -m venv work/sdk-venv
. work/sdk-venv/bin/activate
python -m pip install -e 'sdks/python[dev]'
. work/local-service/client.env
python - <<'PY'
from nine65_sdk import FHEClient
client = FHEClient()
with client.create_session("secure_128") as session:
    a, b = session.encrypt(7, 6)
    assert session.decrypt(session.mul(a, b)) == [42]
print("Encrypted multiplication roundtrip passed")
PY
```

## Integer and ciphertext boundary

`encrypt`, `add_plain` and `mul_plain` accept plain Python `int` values only.
They reject booleans, floats (including integral floats), strings and objects
with integer-conversion methods instead of silently truncating or coercing them.
Non-integer values raise `TypeError`. Values outside the unsigned 64-bit wire
range or outside `[0, t)` raise `ValueError` before a request is sent. When an
older server omits `t`, the SDK enforces the wire range and the server enforces
its plaintext range. Decrypted plaintext responses are checked the same way.
Use `decrypt_signed` for a centered integer representative after decryption.

Python integers remain exact through JSON serialization, including values above
`2**53`; named service profiles still enforce their own plaintext modulus.
Ciphertexts remain opaque base64-encoded binary data, never numeric arrays.
This contract applies to the HTTP SDK, not the separate native PyO3 extension.

## Credentials

Pass `tenant_id`, `api_token`, and optionally `decrypt_token`/`operator_token`
to `FHEClient`, or configure `FHE_TENANT_ID`, `FHE_TENANT_TOKEN`,
`FHE_DECRYPT_TOKEN` and `FHE_OPERATOR_TOKEN`. `FHE_SERVICE_URL` selects the
URL. The tenant token is that tenant's entry in the server's
`FHE_TENANT_TOKENS` mapping. It is not the internal server `FHE_API_TOKEN`.
Public health/version requests carry no credentials; decrypt and metrics
capabilities are sent only to their specific routes. Redirects are refused.

## Tests

Boundary and authentication tests need no running service:

```bash
python -m pytest sdks/python/tests -m "not integration" -v
```

With the service running in explicit local operator decryption mode and the
client environment loaded:

```bash
python -m pytest sdks/python/tests -v
```

The live tests cover all three service profiles, full-range fresh scalar
roundtrips, ciphertext multiplication, session cleanup, tenant rejection and
decrypt-capability enforcement. The service holds the keys; this mode is not
client-owned-key public FHE. Named profiles and research refresh retain the
limitations in the repository README and security model.
