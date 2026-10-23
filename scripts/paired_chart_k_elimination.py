#!/usr/bin/env python3
"""Exact integer oracle for the paired-chart K-Elimination lift.

The encrypted implementation is not present here. This module verifies the
bounded integer map and residue quotient that the CRAM encrypted gate must
realize, using the native 99/121 chart and its 2-adic clock modulus.
"""

from dataclasses import dataclass


P = 65_537
M = 32_768
M_INV_MOD_P = pow(M, -1, P)
Z99_ABS_BOUND = 16_005
SOURCE_K_RADIUS = 48
SOURCE_NORM = 96
SOURCE_PHASE_DENOMINATOR = 64
Z99_TRAY = 99


def floor_div(numerator: int, denominator: int) -> int:
    if denominator <= 0:
        raise ValueError("denominator must be positive")
    return numerator // denominator


def nearest_quotient(numerator: int, denominator: int) -> int:
    """Nearest integer via floor((x + 1/2)); exact for signed integers."""
    if denominator <= 0:
        raise ValueError("denominator must be positive")
    return floor_div(2 * numerator + denominator, 2 * denominator)


def chart_carry(z99: int, modulus: int = M, tray: int = Z99_TRAY) -> int:
    return nearest_quotient(tray * z99, modulus)


def k_eliminate_quotient(low_residue: int, high_residue: int,
                         modulus: int = M, plaintext: int = P) -> int:
    """Recover k when x = low_residue + modulus*k, from x mod plaintext.

    This is the quotient identity only; callers must supply authentic residues
    of the same bounded integer lift in the two phase-locked trays.
    """
    if modulus <= 0 or plaintext <= 1:
        raise ValueError("invalid quotient moduli")
    if low_residue < 0 or low_residue >= modulus:
        raise ValueError("low residue is not canonical")
    if high_residue < 0 or high_residue >= plaintext:
        raise ValueError("high residue is not canonical")
    if modulus % plaintext == 0:
        raise ValueError("quotient modulus must be invertible modulo plaintext")
    return ((high_residue - low_residue) * pow(modulus, -1, plaintext)) % plaintext


def lift(z99: int) -> dict:
    """K-Eliminate the nearest quotient of 99*z99 over M=32768."""
    x = Z99_TRAY * z99 + M // 2
    low = x % M
    high = x % P
    k = k_eliminate_quotient(low, high)
    # p = 2*M + 1, so M == -1/2 (mod p) and M^-1 == -2.
    k_from_two_phase_views = (2 * (low - high)) % P
    if k_from_two_phase_views != k:
        raise AssertionError("2-adic quotient shortcut disagrees with K-Elimination")
    centered_k = k - P if k > P // 2 else k
    expected = chart_carry(z99)
    residual = Z99_TRAY * z99 - M * expected
    residual_from_low_tray = low - M // 2
    if residual != residual_from_low_tray:
        raise AssertionError("K-eliminated chart residual disagrees with low tray")
    return {
        "z99": z99,
        "x": x,
        "low_residue": low,
        "high_residue": high,
        "k_eliminated_mod_p": k,
        "k_from_phase_locked_2_relation": k_from_two_phase_views,
        "k_centered": centered_k,
        "expected_k": expected,
        "centered_residual": residual,
        "residual_from_low_tray": residual_from_low_tray,
    }


def source_residual_bound() -> int:
    """Strict integer bound from 97 half-round errors plus Q/64 phase."""
    strict_real_bound_twice = Z99_TRAY * (SOURCE_NORM + 1) + 2 * M // SOURCE_PHASE_DENOMINATOR
    # |e| < (99*97/2) + M/64 = 5313.5, hence integer |e| <= 5313.
    return (strict_real_bound_twice - 1) // 2


def report() -> dict:
    if P <= 2 * SOURCE_K_RADIUS:
        raise AssertionError("carry radius is not uniquely centered modulo p")
    if M % 2 or M % P == 0:
        raise AssertionError("clock modulus must be even and invertible modulo p")
    if P != 2 * M + 1 or M_INV_MOD_P != P - 2:
        raise AssertionError("native 2-adic/plaintext relation changed")

    checks = 0
    max_abs_k = 0
    max_abs_residual = 0
    for z99 in range(-Z99_ABS_BOUND, Z99_ABS_BOUND + 1):
        result = lift(z99)
        if result["k_centered"] != result["expected_k"]:
            raise AssertionError(f"K-Elimination mismatch at Z99={z99}: {result}")
        checks += 1
        max_abs_k = max(max_abs_k, abs(result["expected_k"]))
        max_abs_residual = max(max_abs_residual, abs(result["centered_residual"]))

    residual_bound = source_residual_bound()
    if residual_bound >= M // 2:
        raise AssertionError("source residual does not fit the centered clock cell")
    if max_abs_k > SOURCE_K_RADIUS:
        raise AssertionError("native Z99 public window exceeds source carry radius")

    # The low residue is enough to form the centered chart residual after
    # K-elimination: e=99*Z99-M*K=(X mod M)-M/2. Restrict this check to the
    # source-correlated residual envelope, not the wider Z99 interval alone.
    residual_checks = 0
    for z99 in range(-Z99_ABS_BOUND, Z99_ABS_BOUND + 1):
        result = lift(z99)
        if abs(result["centered_residual"]) <= residual_bound:
            if result["centered_residual"] != result["residual_from_low_tray"]:
                raise AssertionError(f"residual mismatch at Z99={z99}: {result}")
            residual_checks += 1

    # The low/high residue identity is invariant to representative changes by
    # the full product p*M, as required for a plaintext integer modulo p*M.
    representative_checks = 0
    for z99 in range(-257, 258):
        x = Z99_TRAY * z99 + M // 2
        base = k_eliminate_quotient(x % M, x % P)
        for winding in (-3, -1, 0, 1, 4):
            shifted = x + winding * P * M
            got = k_eliminate_quotient(shifted % M, shifted % P)
            if got != base:
                raise AssertionError("full plaintext-period winding changed quotient")
            representative_checks += 1

    return {
        "scope": "clear exact quotient oracle; no encrypted K-Elimination gate",
        "chart": {
            "integer_jacobian": [[-4, 5], [9, -11]],
            "determinant": -1,
            "inverse": [[11, 5], [9, 4]],
            "reconstruction": "Z99 = 11*U + 5*D",
            "carry_map": "K = floor((99*Z99 + M/2)/M)",
        },
        "tray": {
            "clock_modulus_M": M,
            "factorization_M": "2^15",
            "plaintext_p": P,
            "composite_high_plaintext": P * M,
            "M_inverse_mod_p": M_INV_MOD_P,
            "native_relation": "p=2*M+1, hence M^(-1)=-2 mod p",
            "simplified_quotient": "K=2*(X mod M - X mod p) mod p",
            "same_safe_basis_root_required": 2,
            "new_safe_basis_root_required": False,
        },
        "domain": {
            "Z99_abs_bound": Z99_ABS_BOUND,
            "carry_radius": SOURCE_K_RADIUS,
            "strict_source_residual_bound": residual_bound,
            "exhaustive_Z99_points": checks,
            "max_abs_recovered_K_on_wide_Z99_bound": max_abs_k,
            "max_abs_residual_on_wide_Z99_bound": max_abs_residual,
            "residual_bound_is_from_source_correlation_not_Z99_window_alone": True,
        },
        "k_elimination": {
            "identity": "k = (x mod p - x mod M) * M^(-1) mod p",
            "2_adic_shortcut": "k = 2*(x mod M - x mod p) mod p",
            "tested_full_plaintext_period_windings": representative_checks,
            "all_integer_quotient_checks_pass": checks == 2 * Z99_ABS_BOUND + 1,
            "all_period_winding_checks_pass": True,
        },
        "centered_chart_residual": {
            "identity": "e=99*Z99-M*K=(X mod M)-M/2",
            "source_correlated_abs_bound": residual_bound,
            "all_residual_checks_pass": residual_checks > 0,
            "source_correlated_points_checked": residual_checks,
            "removes_sheet_direction_exactly": True,
            "refresh_reset_proved": False,
        },
        "unclosed_encrypted_obligation": (
            "Produce same-lift encrypted residues x mod M and x mod p from one "
            "authenticated 2/11-phase-locked root, then compute Enc_p(K) and "
            "e99=99*Z99-M*K in the common encoding. The actual dense-chart "
            "low-residue producer and the correction/return error certificate "
            "are still missing; the clear identity does not implement them."
        ),
        "public_refresh_admitted": False,
    }


if __name__ == "__main__":
    import json

    print(json.dumps(report(), indent=2))
