"""FHE session bound to server-side key material."""

from .ciphertext import Ciphertext


class Session:
    """FHE session bound to server-side key material.

    A session holds server-side encryption keys and tracks the remaining
    noise budget.  Use it as a context manager so that server resources
    are freed when the session is no longer needed::

        with client.create_session() as s:
            ct_a, ct_b = s.encrypt(42, 17)
            ct_sum = s.add(ct_a, ct_b)
            result = s.decrypt(ct_sum)
            assert result == [59]

    All integer values passed to and from this class are plain Python
    ``int`` objects.  No floating-point is used anywhere.
    """

    def __init__(self, client, session_id, config, params, noise_budget_millibits):
        self._client = client
        self._session_id = session_id
        self._config = config
        self._params = params
        self._noise_budget_millibits = int(noise_budget_millibits)
        self._closed = False

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def session_id(self):
        """Unique identifier for this session."""
        return self._session_id

    @property
    def config(self):
        """Security configuration name."""
        return self._config

    @property
    def params(self):
        """Parameter dict returned by the server at session creation."""
        return self._params

    @property
    def noise_budget_millibits(self):
        """Remaining noise budget in millibits (1000 = 1 bit)."""
        return self._noise_budget_millibits

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _path(self, suffix=""):
        return "/v1/sessions/%s%s" % (self._session_id, suffix)

    def _update_budget(self, body):
        """Update the local noise budget cache from a response body."""
        if isinstance(body, dict):
            # Support both new and old field names for backward compatibility
            new_field = body.get("noise_budget_estimate_millibits")
            old_field = body.get("noise_budget_millibits")
            
            if new_field is not None:
                self._noise_budget_millibits = int(new_field)
            elif old_field is not None:
                self._noise_budget_millibits = int(old_field)

    def _evaluate(self, operations):
        """Send an evaluate request and return the parsed response body."""
        body = self._client._request(
            "POST",
            self._path("/evaluate"),
            {"operations": operations},
        )
        self._update_budget(body)
        return body

    # ------------------------------------------------------------------
    # Encrypt / Decrypt
    # ------------------------------------------------------------------

    def encrypt(self, *values):
        """Encrypt one or more integer values.

        Args:
            *values: Integer plaintext values to encrypt.

        Returns:
            Tuple of :class:`Ciphertext` objects (one per input value).
        """
        int_values = [int(v) for v in values]
        body = self._client._request(
            "POST",
            self._path("/encrypt"),
            {"values": int_values},
        )
        self._update_budget(body)
        return tuple(Ciphertext(ct) for ct in body["ciphertexts"])

    def decrypt(self, *ciphertexts):
        """Decrypt one or more ciphertexts.

        Args:
            *ciphertexts: :class:`Ciphertext` objects to decrypt.

        Returns:
            List of integer plaintext values (unsigned, in ``[0, t)``).
        """
        ct_data = [ct.data for ct in ciphertexts]
        body = self._client._request(
            "POST",
            self._path("/decrypt"),
            {"ciphertexts": ct_data},
        )
        self._update_budget(body)
        return [int(v) for v in body["values"]]

    def decrypt_signed(self, *ciphertexts):
        """Decrypt one or more ciphertexts with centered lift.

        Values greater than ``t // 2`` are mapped to their negative
        representative, i.e. ``v - t``.  This is useful when the
        plaintext space is interpreted as signed integers in
        ``(-t/2, t/2]``.

        Args:
            *ciphertexts: :class:`Ciphertext` objects to decrypt.

        Returns:
            List of signed integer plaintext values.
        """
        raw = self.decrypt(*ciphertexts)
        t = int(self._params.get("t", 0))
        if t == 0:
            return raw
        half = t // 2
        return [(v - t if v > half else v) for v in raw]

    # ------------------------------------------------------------------
    # Homomorphic operations
    # ------------------------------------------------------------------

    def _eval_binary(self, op, ct_a, ct_b):
        """Evaluate a binary ciphertext-ciphertext operation."""
        body = self._evaluate([{"op": op, "inputs": [ct_a.data, ct_b.data]}])
        return Ciphertext(body["results"][0])

    def _eval_plain(self, op, ct, scalar):
        """Evaluate a ciphertext-plaintext operation."""
        body = self._evaluate([{"op": op, "inputs": [ct.data], "scalar": int(scalar)}])
        return Ciphertext(body["results"][0])

    def _eval_unary(self, op, ct):
        """Evaluate a unary ciphertext operation."""
        body = self._evaluate([{"op": op, "inputs": [ct.data]}])
        return Ciphertext(body["results"][0])

    def add(self, ct_a, ct_b):
        """Homomorphic addition of two ciphertexts.

        Args:
            ct_a: First ciphertext operand.
            ct_b: Second ciphertext operand.

        Returns:
            Ciphertext encrypting the sum of the two plaintexts.
        """
        return self._eval_binary("add", ct_a, ct_b)

    def sub(self, ct_a, ct_b):
        """Homomorphic subtraction (ct_a - ct_b).

        Args:
            ct_a: Ciphertext minuend.
            ct_b: Ciphertext subtrahend.

        Returns:
            Ciphertext encrypting the difference.
        """
        return self._eval_binary("sub", ct_a, ct_b)

    def mul(self, ct_a, ct_b):
        """Homomorphic multiplication of two ciphertexts.

        Args:
            ct_a: First ciphertext factor.
            ct_b: Second ciphertext factor.

        Returns:
            Ciphertext encrypting the product.
        """
        return self._eval_binary("mul", ct_a, ct_b)

    def negate(self, ct):
        """Homomorphic negation.

        Args:
            ct: Ciphertext to negate.

        Returns:
            Ciphertext encrypting the negation of the plaintext.
        """
        return self._eval_unary("negate", ct)

    def add_plain(self, ct, scalar):
        """Add an integer plaintext to a ciphertext.

        Args:
            ct: Ciphertext operand.
            scalar: Integer plaintext addend.

        Returns:
            Ciphertext encrypting (plaintext + scalar).
        """
        return self._eval_plain("add_plain", ct, scalar)

    def mul_plain(self, ct, scalar):
        """Multiply a ciphertext by an integer plaintext.

        Args:
            ct: Ciphertext operand.
            scalar: Integer plaintext multiplier.

        Returns:
            Ciphertext encrypting (plaintext * scalar).
        """
        return self._eval_plain("mul_plain", ct, scalar)

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def info(self):
        """Retrieve current session information from the server.

        Returns:
            dict with session metadata, noise budget, etc.
        """
        body = self._client._request("GET", self._path())
        self._update_budget(body)
        return body

    def close(self):
        """Destroy this session and release server-side key material.

        Safe to call multiple times.
        """
        if not self._closed:
            try:
                self._client._request("DELETE", self._path())
            finally:
                self._closed = True

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def __repr__(self):
        state = "closed" if self._closed else "open"
        return "Session(id=%s, config=%s, noise=%d mb, %s)" % (
            repr(self._session_id),
            repr(self._config),
            self._noise_budget_millibits,
            state,
        )
