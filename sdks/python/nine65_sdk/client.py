"""FHE client for the NINE65 microservice."""

import requests

from .errors import (
    Nine65SDKError,
    NoiseBudgetExhaustedError,
    ServiceUnavailableError,
    SessionNotFoundError,
)
from .session import Session


class FHEClient:
    """HTTP client for the NINE65 FHE microservice.

    Usage::

        client = FHEClient("http://localhost:8080")
        with client.create_session("secure_128") as session:
            ct = session.encrypt(42)[0]
            values = session.decrypt(ct)
            assert values == [42]

    Args:
        base_url: Root URL of the FHE service (no trailing slash).
        timeout: Request timeout in seconds (integer).
    """

    def __init__(self, base_url="http://localhost:8080", timeout=30):
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._http = requests.Session()
        self._http.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    # ------------------------------------------------------------------
    # Internal request helper
    # ------------------------------------------------------------------

    def _request(self, method, path, json_body=None):
        """Issue an HTTP request and return the parsed JSON response.

        Raises the appropriate SDK error on failure.
        """
        url = self._base_url + path

        try:
            resp = self._http.request(
                method,
                url,
                json=json_body,
                timeout=self._timeout,
            )
        except requests.ConnectionError as exc:
            raise ServiceUnavailableError(
                "Cannot connect to FHE service at %s: %s" % (self._base_url, exc)
            )
        except requests.Timeout as exc:
            raise ServiceUnavailableError(
                "Request to %s timed out after %d seconds" % (url, self._timeout)
            )

        if resp.status_code == 503:
            raise ServiceUnavailableError(
                "FHE service unavailable (503)",
                status_code=503,
            )

        # Try to parse JSON body for error details
        body = None
        if resp.content:
            try:
                body = resp.json()
            except ValueError:
                body = None

        if resp.status_code == 404:
            msg = "Not found: %s" % path
            error_code = None
            if body and isinstance(body, dict) and isinstance(body.get("error"), dict):
                error_obj = body["error"]
                msg = error_obj.get("message", msg)
                error_code = error_obj.get("code")
            raise SessionNotFoundError(msg, status_code=404, error_code=error_code)

        if resp.status_code == 422:
            msg = "Unprocessable entity"
            error_code = None
            if body and isinstance(body, dict) and isinstance(body.get("error"), dict):
                error_obj = body["error"]
                msg = error_obj.get("message", msg)
                error_code = error_obj.get("code")
            if error_code == "NOISE_BUDGET_EXCEEDED":
                raise NoiseBudgetExhaustedError(
                    msg, status_code=422, error_code=error_code
                )
            raise Nine65SDKError(msg, status_code=422, error_code=error_code)

        if not (200 <= resp.status_code < 300):
            msg = "HTTP %d" % resp.status_code
            error_code = None
            if body and isinstance(body, dict) and isinstance(body.get("error"), dict):
                error_obj = body["error"]
                msg = error_obj.get("message", msg)
                error_code = error_obj.get("code")
            raise Nine65SDKError(msg, status_code=resp.status_code, error_code=error_code)

        # Successful responses with no content (e.g. 204 DELETE)
        if resp.status_code == 204 or not resp.content:
            return {}

        if body is None:
            raise Nine65SDKError(
                "Expected JSON response from %s but got: %s"
                % (url, resp.text[:200])
            )

        return body

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def health(self):
        """Check service health.

        Returns:
            dict with health status fields.
        """
        return self._request("GET", "/healthz")

    def version(self):
        """Get service version and supported configurations.

        Returns:
            dict with ``version``, ``supported_configs``, etc.
        """
        return self._request("GET", "/v1/version")

    def create_session(self, config="secure_128"):
        """Create a new FHE session.

        The returned :class:`Session` is a context manager -- use it in a
        ``with`` block to ensure server-side key material is cleaned up.

        Args:
            config: Security configuration name (e.g. ``"secure_128"``).

        Returns:
            A :class:`Session` instance.
        """
        body = self._request("POST", "/v1/sessions", {"config": config})
        return Session(
            client=self,
            session_id=body["session_id"],
            config=body["config"],
            params=body.get("params", {}),
            noise_budget_millibits=body.get("noise_budget_estimate_millibits", body.get("noise_budget_millibits")),
        )
