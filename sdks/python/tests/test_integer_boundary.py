"""Exact integers and opaque ciphertexts at the HTTP SDK boundary (no service)."""

import base64
from decimal import Decimal
from fractions import Fraction
import json
from unittest.mock import Mock

import pytest
import requests

from nine65_sdk import Ciphertext, FHEClient, Session


class IntSubclass(int):
    pass


class IntConvertible:
    def __int__(self):
        raise AssertionError("plaintext conversion must never be attempted")


class IndexConvertible:
    def __index__(self):
        raise AssertionError("plaintext conversion must never be attempted")


INVALID_TYPES = [
    True, False, 1.0, 1.5, -0.5, float("nan"), float("inf"), float("-inf"),
    "42", b"42", None, Decimal("1.5"), Fraction(3, 2),
    IntConvertible(), IndexConvertible(), IntSubclass(42),
]
U64_MAX = (1 << 64) - 1
# This payload is a byte-transport fixture, not a claim of valid encryption.
CIPHERTEXT_BYTES = b"N65Qv001" + bytes(range(256)) + b"\x00\xff\x80"
CIPHERTEXT_B64 = base64.b64encode(CIPHERTEXT_BYTES).decode("ascii")


@pytest.fixture
def session():
    client = Mock()
    client._request.return_value = {"ciphertexts": [CIPHERTEXT_B64],
                                  "results": [CIPHERTEXT_B64]}
    return Session(client, "s1", "secure_128", {"t": 65537}, 1000)


@pytest.mark.parametrize("value", INVALID_TYPES)
@pytest.mark.parametrize("operation", ["encrypt", "add_plain", "mul_plain"])
def test_non_integer_plaintexts_are_rejected_before_request(session, operation, value):
    with pytest.raises(TypeError, match="plain Python int"):
        if operation == "encrypt":
            session.encrypt(1, value, 2)
        else:
            getattr(session, operation)(Ciphertext(CIPHERTEXT_B64), value)
    session._client._request.assert_not_called()


@pytest.mark.parametrize("value", [-1, -(1 << 64), 65537, 65538, 1 << 64])
@pytest.mark.parametrize("operation", ["encrypt", "add_plain", "mul_plain"])
def test_out_of_range_plaintexts_are_rejected_before_request(session, operation, value):
    with pytest.raises(ValueError):
        if operation == "encrypt":
            session.encrypt(1, value, 2)
        else:
            getattr(session, operation)(Ciphertext(CIPHERTEXT_B64), value)
    session._client._request.assert_not_called()


@pytest.mark.parametrize("value", [0, 1, 65536])
def test_valid_plaintexts_are_not_coerced(session, value):
    ciphertext, = session.encrypt(value)
    assert session._client._request.call_args.args[2] == {"values": [value]}
    for operation in ("add_plain", "mul_plain"):
        result = getattr(session, operation)(ciphertext, value)
        assert session._client._request.call_args.args[2] == {"operations": [
            {"op": operation, "inputs": [CIPHERTEXT_B64], "scalar": value}
        ]}
        assert base64.b64decode(result.data, validate=True) == CIPHERTEXT_BYTES
    assert base64.b64decode(ciphertext.data, validate=True) == CIPHERTEXT_BYTES


@pytest.mark.parametrize("value", [True, 1.5, "42", -1, 65537, 1 << 64])
def test_decrypt_does_not_coerce_invalid_plaintext_responses(session, value):
    session._client._request.return_value = {"values": [value]}
    with pytest.raises((TypeError, ValueError)):
        session.decrypt(Ciphertext(CIPHERTEXT_B64))


def test_centered_decryption_remains_exact(session):
    session._client._request.return_value = {"values": [0, 32768, 32769, 65536]}
    assert session.decrypt_signed(Ciphertext(CIPHERTEXT_B64)) == [0, 32768, -32768, -1]


@pytest.mark.parametrize("value", [0, (1 << 53) + 1, (1 << 63) + 1, U64_MAX])
def test_http_json_preserves_exact_uint64_and_ciphertext(value):
    """Exercise the requests serializer, without opening a network connection."""
    client = FHEClient()
    # Empty params preserve compatibility with older servers. Modern services
    # supply t and apply their own, narrower [0, t) plaintext admission.
    session = Session(client, "s1", "older-server", {}, 1000)
    requests_seen = []

    def send(request, **kwargs):
        requests_seen.append(json.loads(request.body))
        response = requests.Response()
        response.status_code = 200
        if request.url.endswith("/encrypt"):
            body = {"ciphertexts": [CIPHERTEXT_B64]}
        elif request.url.endswith("/decrypt"):
            body = {"values": [value]}
        else:
            body = {"results": [CIPHERTEXT_B64]}
        response._content = json.dumps(body).encode("utf-8")
        return response

    client._http.send = Mock(side_effect=send)
    try:
        ciphertext, = session.encrypt(value)
        assert requests_seen[-1] == {"values": [value]}
        assert type(requests_seen[-1]["values"][0]) is int
        for operation in ("add_plain", "mul_plain"):
            ciphertext = getattr(session, operation)(ciphertext, value)
            assert requests_seen[-1] == {"operations": [
                {"op": operation, "inputs": [CIPHERTEXT_B64], "scalar": value}
            ]}
            assert type(requests_seen[-1]["operations"][0]["scalar"]) is int
        assert session.decrypt(ciphertext) == [value]
        assert requests_seen[-1] == {"ciphertexts": [CIPHERTEXT_B64]}
        assert base64.b64decode(ciphertext.data, validate=True) == CIPHERTEXT_BYTES
    finally:
        client._http.close()


@pytest.mark.parametrize("t", [True, 65537.0, "65537", 0, -1, 1 << 64])
def test_invalid_modulus_metadata_is_not_used_for_admission(session, t):
    session._params["t"] = t
    with pytest.raises(ValueError, match="modulus t"):
        session.encrypt(1)
    session._client._request.assert_not_called()


@pytest.mark.parametrize("value", [(1 << 53) + 1, (1 << 63) + 1, U64_MAX - 1])
def test_large_plaintexts_remain_exact_with_modulus_metadata(session, value):
    session._params["t"] = U64_MAX
    ciphertext, = session.encrypt(value)
    assert session._client._request.call_args.args[2] == {"values": [value]}
    session._client._request.return_value = {"values": [value]}
    result = session.decrypt(ciphertext)
    assert result == [value]
    assert type(result[0]) is int


@pytest.mark.parametrize("operation", ["add", "sub", "mul", "negate"])
def test_ciphertext_operations_preserve_opaque_bytes(session, operation):
    ciphertext = Ciphertext(CIPHERTEXT_B64)
    inputs = [ciphertext] if operation == "negate" else [ciphertext, ciphertext]
    result = getattr(session, operation)(*inputs)
    assert session._client._request.call_args.args[2] == {"operations": [
        {"op": operation, "inputs": [CIPHERTEXT_B64] * len(inputs)}
    ]}
    assert base64.b64decode(result.data, validate=True) == CIPHERTEXT_BYTES


@pytest.mark.parametrize("value", [-1, 1 << 64])
@pytest.mark.parametrize("operation", ["encrypt", "add_plain", "mul_plain"])
def test_missing_modulus_does_not_relax_wire_range(session, operation, value):
    session._params.clear()
    with pytest.raises(ValueError, match="unsigned 64-bit range"):
        if operation == "encrypt":
            session.encrypt(value)
        else:
            getattr(session, operation)(Ciphertext(CIPHERTEXT_B64), value)
    session._client._request.assert_not_called()
