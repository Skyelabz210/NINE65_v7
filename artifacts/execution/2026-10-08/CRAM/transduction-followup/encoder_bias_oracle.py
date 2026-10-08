#!/usr/bin/env python3
"""Exact, noise-free reproduction of the single-modulus BFV scale bias."""

import json


Q = 998_244_353
T = 65_537
DELTA = Q // T


def decode(encoded_coefficient: int) -> int:
    # BFVEncoder::decode: floor((2*t*c + q)/(2*q)) mod t.
    return ((2 * T * encoded_coefficient + Q) // (2 * Q)) % T


errors = []
for message in range(T):
    coefficient = DELTA * message
    decoded = decode(coefficient)
    if decoded != message:
        errors.append((message, decoded))

result = {
    "q": Q,
    "t": T,
    "delta_floor_q_over_t": DELTA,
    "q_mod_t": Q % T,
    "messages_checked": T,
    "roundtrip_failures": len(errors),
    "first_failure": {"message": errors[0][0], "decoded": errors[0][1]},
    "maximum_downward_bias": max(m - got for m, got in errors),
    "near_modulus_example": {
        "message": T - 1,
        "decoded": decode(DELTA * (T - 1)),
    },
    "scope": "exact integer encode/decode only; no encryption noise or homomorphic operation",
}
print(json.dumps(result, indent=2, sort_keys=True))
