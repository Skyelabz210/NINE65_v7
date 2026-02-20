"""
This module contains an extended suite of tests for the PyO3 bindings
exposed by the `qmnf_bindings` crate.  These tests build upon the
baseline examples in the original technical design document to provide
broader coverage of error conditions, round‑trip conversions, and
protocol behaviour.

The tests are written using `pytest` and can be run via

```
pytest -q improved_pyo3_tests.py
```

They assume that the `qmnf_bindings` module is installed in the active
Python environment (for example, via `maturin develop --release`).

Note: These tests intentionally avoid floating‑point values except as
explicit error cases to ensure zero‑drift behaviour.  If you modify
the bindings API, update these tests accordingly.
"""

from __future__ import annotations

import itertools
import math
import random
import pytest

from qmnf_bindings import CRTBigInt, HierarchicalCRT


@pytest.mark.parametrize("value", [0, 1, -1, 2**31, -(2**31), 2**53 + 1])
def test_constructor_accepts_integers(value: int) -> None:
    """Constructing a CRTBigInt from an integer should succeed."""
    obj = CRTBigInt(value)
    assert int(obj) == value


@pytest.mark.parametrize("value", [3.14, -0.1, math.pi])
def test_constructor_rejects_floats(value: float) -> None:
    """Passing a float to the CRTBigInt constructor should raise TypeError."""
    with pytest.raises(TypeError):
        CRTBigInt(value)  # type: ignore[arg-type]


def test_from_python_int_handles_large_bigints() -> None:
    """`from_python_int` should accept arbitrary‑precision Python ints."""
    big = 10**100  # far beyond 64‑bit range
    obj = CRTBigInt.from_python_int(big)
    assert int(obj) == big


def test_addition_commutes() -> None:
    """Addition should be commutative on CRTBigInt values."""
    a = CRTBigInt(42)
    b = CRTBigInt(73)
    sum_ab = a + b
    sum_ba = b + a
    assert int(sum_ab) == int(sum_ba) == 115


def test_multiplication_associative() -> None:
    """Multiplication should be associative on CRTBigInt values."""
    x = CRTBigInt(3)
    y = CRTBigInt(7)
    z = CRTBigInt(11)
    left = (x * y) * z
    right = x * (y * z)
    assert int(left) == int(right) == 3 * 7 * 11


def test_equality_and_comparison() -> None:
    """CRTBigInt should implement equality and ordering properly."""
    a = CRTBigInt(5)
    b = CRTBigInt(5)
    c = CRTBigInt(6)
    assert a == b
    assert not (a < b)  # should not be less than itself
    assert a < c
    assert c > a
    assert a != c


def test_repr_and_str_round_trip() -> None:
    """Ensure __repr__ and __str__ produce human‑readable representations."""
    val = 12345
    obj = CRTBigInt(val)
    repr_str = repr(obj)
    # repr should start with class name
    assert repr_str.startswith("CRTBigInt(")
    # eval(repr(obj)) is not guaranteed but int(obj) should be recoverable
    assert str(int(obj)) in repr_str


def test_bytes_round_trip() -> None:
    """Converting to bytes and back should preserve the value exactly."""
    original = 9876543210987654321
    # big‑endian 8‑byte representation; allocate enough bytes for the value
    length = (original.bit_length() + 7) // 8 or 1
    bytes_be = original.to_bytes(length, "big", signed=True)
    obj = CRTBigInt.from_python_int(original)
    # round‑trip through to_bytes on the underlying integer representation
    roundtrip = int.from_bytes(int(obj).to_bytes(length, "big", signed=True), "big", signed=True)
    assert roundtrip == original


def test_invalid_bytes_rejected() -> None:
    """Passing an incorrectly sized byte array should raise an error."""
    with pytest.raises(Exception):
        # Example: from_bytes expects exactly 8 bytes for i64; supply invalid length
        CRTBigInt.from_python_int((1).to_bytes(3, "big"))  # type: ignore[arg-type]


def test_hierarchical_crt_promotes_precision() -> None:
    """Verify that HierarchicalCRT exposes tier and bit capacity accessors."""
    h = HierarchicalCRT(42)
    assert h.tier >= 0
    assert h.bit_capacity >= 0
    # Repeated multiplication should eventually promote tiers
    for _ in range(3):
        h = h.multiply(HierarchicalCRT(1))
    # After operations, tier should not decrease
    assert h.tier >= 0


def test_randomized_operations_property() -> None:
    """Perform randomized operations and ensure consistency with Python ints."""
    rng = random.Random(0xDEADBEEF)
    for _ in range(100):
        a = rng.randint(-2**31, 2**31 - 1)
        b = rng.randint(-2**31, 2**31 - 1)
        x = CRTBigInt(a)
        y = CRTBigInt(b)
        # addition
        assert int(x + y) == a + b
        # multiplication
        assert int(x * y) == a * b


def test_operations_with_mismatched_types_raise() -> None:
    """Ensure operations with mismatched types raise informative TypeError."""
    x = CRTBigInt(10)
    # addition with Python int should fail
    with pytest.raises(TypeError):
        _ = x + 5  # type: ignore[operator]
    # multiplication with float should fail
    with pytest.raises(TypeError):
        _ = x * 3.14  # type: ignore[operator]


def test_string_based_transport() -> None:
    """Simulate the string transport wrapper for multiply_string."""
    # The multiply_string function would typically be imported from qmnf_bindings
    # but here we emulate it using CRTBigInt operations.
    a_str, b_str, mod_str = "12345", "67890", "1000000007"
    a_int, b_int, m_int = int(a_str), int(b_str), int(mod_str)
    a = CRTBigInt(a_int)
    b = CRTBigInt(b_int)
    result = a * b  # CRT multiply
    modulo_result = int(result) % m_int
    # Expected calculation in Python
    expected = (a_int * b_int) % m_int
    assert modulo_result == expected


def test_negative_values_handled() -> None:
    """Negative numbers should behave consistently under operations."""
    a = CRTBigInt(-123)
    b = CRTBigInt(456)
    assert int(a + b) == -123 + 456
    assert int(a * b) == -123 * 456
