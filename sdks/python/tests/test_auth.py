"""The SDK must work through the service's tenant-bound HTTP ingress."""
from unittest.mock import Mock

import pytest

from nine65_sdk import FHEClient, Nine65SDKError


@pytest.fixture
def client(monkeypatch):
    for key in ("FHE_TENANT_ID", "FHE_TENANT_TOKEN", "FHE_DECRYPT_TOKEN", "FHE_OPERATOR_TOKEN"):
        monkeypatch.delenv(key, raising=False)
    client = FHEClient(tenant_id="alpha", api_token="tenant-alpha",
                       decrypt_token="decrypt-alpha", operator_token="operator-alpha")
    response = Mock(status_code=200, content=b'{}')
    response.json.return_value = {}
    client._http.request = Mock(return_value=response)
    return client


def test_tenant_credentials_are_sent_for_protected_operations(client):
    client._request("POST", "/v1/sessions", {"config": "secure_128"})
    headers = client._http.request.call_args.kwargs["headers"]
    assert headers == {"x-fhe-tenant-id": "alpha", "x-fhe-api-token": "tenant-alpha"}


@pytest.mark.parametrize("path", ["/healthz", "/v1/version"])
def test_public_routes_receive_no_credentials(client, path):
    client._request("GET", path)
    assert client._http.request.call_args.kwargs["headers"] == {}


def test_decrypt_token_is_scoped_to_decrypt_requests(client):
    client._request("POST", "/v1/sessions/s1/decrypt", {"ciphertexts": []})
    headers = client._http.request.call_args.kwargs["headers"]
    assert headers["x-fhe-decrypt-token"] == "decrypt-alpha"
    assert "x-fhe-operator-token" not in headers
    client._request("POST", "/v1/sessions/s1/encrypt", {"values": [1]})
    assert "x-fhe-decrypt-token" not in client._http.request.call_args.kwargs["headers"]


def test_metrics_receive_operator_capability(client):
    client.metrics()
    headers = client._http.request.call_args.kwargs["headers"]
    assert headers["x-fhe-operator-token"] == "operator-alpha"
    assert "x-fhe-decrypt-token" not in headers


def test_redirects_do_not_forward_credentials(client):
    client._http.request.return_value.status_code = 302
    with pytest.raises(Nine65SDKError):
        client._request("POST", "/v1/sessions", {})
    assert client._http.request.call_args.kwargs["allow_redirects"] is False


def test_environment_credentials_are_supported(monkeypatch):
    monkeypatch.setenv("FHE_TENANT_ID", "local")
    monkeypatch.setenv("FHE_TENANT_TOKEN", "local-token")
    monkeypatch.setenv("FHE_DECRYPT_TOKEN", "decrypt-token")
    client = FHEClient()
    response = Mock(status_code=200, content=b'{}')
    response.json.return_value = {}
    client._http.request = Mock(return_value=response)
    client._request("POST", "/v1/sessions/s1/decrypt", {})
    headers = client._http.request.call_args.kwargs["headers"]
    assert headers["x-fhe-tenant-id"] == "local"
    assert headers["x-fhe-api-token"] == "local-token"
    assert headers["x-fhe-decrypt-token"] == "decrypt-token"
