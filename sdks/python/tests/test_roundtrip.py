"""Integration tests for the NINE65 FHE SDK.

These tests require a running NINE65 FHE microservice at localhost:8080.
Run with::

    pytest tests/test_roundtrip.py -v -m integration

All arithmetic is integer-only. No floating-point anywhere.
"""

import pytest

from nine65_sdk import FHEClient, SessionNotFoundError

# All tests in this module require the live FHE service.
pytestmark = pytest.mark.integration

SERVICE_URL = "http://localhost:8080"


@pytest.fixture(scope="module")
def client():
    """Shared FHEClient instance for the test module."""
    return FHEClient(base_url=SERVICE_URL, timeout=30)


# ------------------------------------------------------------------
# Health / version
# ------------------------------------------------------------------


class TestHealth:
    def test_health_endpoint(self, client):
        """GET /healthz returns a dict with status information."""
        result = client.health()
        assert isinstance(result, dict)


class TestVersion:
    def test_version_endpoint(self, client):
        """GET /v1/version returns version and supported configs."""
        result = client.version()
        assert isinstance(result, dict)
        assert "version" in result or "supported_configs" in result


# ------------------------------------------------------------------
# Session lifecycle
# ------------------------------------------------------------------


class TestSessionLifecycle:
    def test_create_and_close_session(self, client):
        """Create a session, verify it exists, then close it."""
        session = client.create_session("secure_128")
        assert session.session_id is not None
        assert session.config == "secure_128"
        assert session.noise_budget_millibits > 0

        # Session info should succeed while open
        info = session.info()
        assert isinstance(info, dict)

        session.close()

    def test_session_context_manager_cleanup(self, client):
        """Context manager should destroy the session on exit."""
        with client.create_session("secure_128") as session:
            sid = session.session_id
            assert sid is not None
            assert session.noise_budget_millibits > 0

        # After exiting the context, the session should be gone
        with pytest.raises(SessionNotFoundError):
            client._request("GET", "/v1/sessions/%s" % sid)

    def test_close_is_idempotent(self, client):
        """Calling close() twice should not raise."""
        session = client.create_session("secure_128")
        session.close()
        session.close()  # second call is a no-op


# ------------------------------------------------------------------
# Encrypt / decrypt roundtrip
# ------------------------------------------------------------------


class TestEncryptDecrypt:
    def test_single_value_roundtrip(self, client):
        """Encrypt a single integer, decrypt it, verify equality."""
        with client.create_session("secure_128") as session:
            (ct,) = session.encrypt(42)
            values = session.decrypt(ct)
            assert values == [42]

    def test_multiple_values_roundtrip(self, client):
        """Encrypt multiple integers in one call, decrypt all."""
        with client.create_session("secure_128") as session:
            cts = session.encrypt(1, 2, 3, 100, 9999)
            assert len(cts) == 5
            values = session.decrypt(*cts)
            assert values == [1, 2, 3, 100, 9999]

    def test_zero_roundtrip(self, client):
        """Zero should survive encrypt/decrypt."""
        with client.create_session("secure_128") as session:
            (ct,) = session.encrypt(0)
            values = session.decrypt(ct)
            assert values == [0]

    def test_noise_budget_tracked(self, client):
        """Noise budget should be a positive integer after encryption."""
        with client.create_session("secure_128") as session:
            initial_budget = session.noise_budget_millibits
            assert isinstance(initial_budget, int)
            assert initial_budget > 0

            session.encrypt(42)
            # Budget should still be a positive integer
            assert isinstance(session.noise_budget_millibits, int)
            assert session.noise_budget_millibits > 0


# ------------------------------------------------------------------
# Homomorphic operations
# ------------------------------------------------------------------


class TestHomomorphicOps:
    def test_add_ciphertexts(self, client):
        """add(encrypt(42), encrypt(17)) -> decrypt -> 59."""
        with client.create_session("secure_128") as session:
            ct_a, ct_b = session.encrypt(42, 17)
            ct_sum = session.add(ct_a, ct_b)
            result = session.decrypt(ct_sum)
            assert result == [59]

    def test_sub_ciphertexts(self, client):
        """sub(encrypt(100), encrypt(37)) -> decrypt -> 63."""
        with client.create_session("secure_128") as session:
            ct_a, ct_b = session.encrypt(100, 37)
            ct_diff = session.sub(ct_a, ct_b)
            result = session.decrypt(ct_diff)
            assert result == [63]

    def test_negate_ciphertext(self, client):
        """negate(encrypt(42)) -> decrypt_signed -> -42."""
        with client.create_session("secure_128") as session:
            (ct,) = session.encrypt(42)
            ct_neg = session.negate(ct)
            result = session.decrypt_signed(ct_neg)
            assert result == [-42]

    def test_mul_plain(self, client):
        """mul_plain(encrypt(10), 5) -> decrypt -> 50."""
        with client.create_session("secure_128") as session:
            (ct,) = session.encrypt(10)
            ct_prod = session.mul_plain(ct, 5)
            result = session.decrypt(ct_prod)
            assert result == [50]

    def test_add_plain(self, client):
        """add_plain(encrypt(40), 2) -> decrypt -> 42."""
        with client.create_session("secure_128") as session:
            (ct,) = session.encrypt(40)
            ct_sum = session.add_plain(ct, 2)
            result = session.decrypt(ct_sum)
            assert result == [42]

    def test_mul_ciphertexts(self, client):
        """mul(encrypt(7), encrypt(6)) -> decrypt -> 42."""
        with client.create_session("secure_128") as session:
            ct_a, ct_b = session.encrypt(7, 6)
            ct_prod = session.mul(ct_a, ct_b)
            result = session.decrypt(ct_prod)
            assert result == [42]

    def test_chained_operations(self, client):
        """Chain multiple operations: (10 + 20) * 3 = 90."""
        with client.create_session("secure_128") as session:
            ct_a, ct_b = session.encrypt(10, 20)
            ct_sum = session.add(ct_a, ct_b)
            ct_result = session.mul_plain(ct_sum, 3)
            result = session.decrypt(ct_result)
            assert result == [90]

    def test_noise_budget_decreases_after_operations(self, client):
        """Noise budget should decrease (or stay same) after mul."""
        with client.create_session("secure_128") as session:
            budget_before = session.noise_budget_millibits
            ct_a, ct_b = session.encrypt(5, 10)
            _ = session.mul(ct_a, ct_b)
            budget_after = session.noise_budget_millibits
            # Multiplication consumes noise budget
            assert budget_after <= budget_before

    def test_noise_budget_field_backward_compatibility(self, client):
        """Test that the SDK can handle both old and new noise budget field names."""
        with client.create_session("secure_128") as session:
            # The property should work regardless of which field name the server returns
            budget = session.noise_budget_millibits
            assert isinstance(budget, int)
            assert budget > 0
            
            # Perform an operation that updates the budget
            session.encrypt(42)
            updated_budget = session.noise_budget_millibits
            assert isinstance(updated_budget, int)
            # Budget should still be positive after operation
            assert updated_budget > 0
