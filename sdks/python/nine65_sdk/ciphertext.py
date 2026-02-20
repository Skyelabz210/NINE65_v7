"""Opaque ciphertext handle for the NINE65 FHE SDK."""


class Ciphertext:
    """Opaque handle wrapping a base64-encoded ciphertext.

    Ciphertext objects are returned by encryption and homomorphic evaluation
    operations. They should be treated as opaque blobs -- the only meaningful
    operation is to pass them back to the service for decryption or further
    evaluation.
    """

    __slots__ = ("_b64_data",)

    def __init__(self, b64_data):
        """Create a Ciphertext from its base64 wire representation.

        Args:
            b64_data: Base64-encoded ciphertext string.
        """
        if not isinstance(b64_data, str):
            raise TypeError("b64_data must be a str, got %s" % type(b64_data).__name__)
        self._b64_data = b64_data

    @property
    def data(self):
        """Return the raw base64-encoded ciphertext string."""
        return self._b64_data

    def __repr__(self):
        preview = self._b64_data[:16]
        if len(self._b64_data) > 16:
            preview += "..."
        return "Ciphertext(%s)" % repr(preview)

    def __eq__(self, other):
        if not isinstance(other, Ciphertext):
            return NotImplemented
        return self._b64_data == other._b64_data

    def __hash__(self):
        return hash(self._b64_data)
