"""NINE65 FHE SDK -- pure-Python HTTP client for the NINE65 FHE microservice.

Usage::

    from nine65_sdk import FHEClient

    client = FHEClient("http://localhost:8080")
    with client.create_session("secure_128") as session:
        ct_a, ct_b = session.encrypt(42, 17)
        ct_sum = session.add(ct_a, ct_b)
        result = session.decrypt(ct_sum)
        assert result == [59]
"""

from .ciphertext import Ciphertext
from .client import FHEClient
from .errors import (
    Nine65SDKError,
    NoiseBudgetExhaustedError,
    ServiceUnavailableError,
    SessionNotFoundError,
)
from .session import Session

__all__ = [
    "FHEClient",
    "Session",
    "Ciphertext",
    "Nine65SDKError",
    "SessionNotFoundError",
    "NoiseBudgetExhaustedError",
    "ServiceUnavailableError",
]

__version__ = "0.1.0"
