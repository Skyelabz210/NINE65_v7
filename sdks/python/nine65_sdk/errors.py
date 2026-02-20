"""Error types for the NINE65 FHE SDK."""


class Nine65SDKError(Exception):
    """Base SDK error.

    Attributes:
        message: Human-readable error description.
        status_code: HTTP status code from the service, or None.
        error_code: Machine-readable error code from the service, or None.
    """

    def __init__(self, message, status_code=None, error_code=None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.error_code = error_code

    def __repr__(self):
        parts = [repr(self.message)]
        if self.status_code is not None:
            parts.append("status_code=%d" % self.status_code)
        if self.error_code is not None:
            parts.append("error_code=%s" % repr(self.error_code))
        return "%s(%s)" % (type(self).__name__, ", ".join(parts))


class SessionNotFoundError(Nine65SDKError):
    """Raised when the requested session does not exist (HTTP 404)."""

    pass


class NoiseBudgetExhaustedError(Nine65SDKError):
    """Raised when the noise budget is exhausted (HTTP 422, NOISE_BUDGET_EXCEEDED)."""

    pass


class ServiceUnavailableError(Nine65SDKError):
    """Raised when the FHE service is unreachable or returns 503."""

    pass
