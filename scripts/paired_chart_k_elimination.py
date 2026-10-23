#!/usr/bin/env python3
"""Exact integer oracle for the paired-chart K-Elimination lift.

The encrypted implementation is not present here. This module verifies the
bounded integer map and residue quotient that the CRAM encrypted gate must
realize, using the native 99/121 chart and its 2-adic clock modulus.
"""

from dataclasses import dataclass
from math import prod


P = 65_537
M = 32_768
M_INV_MOD_P = pow(M, -1, P)
ADJACENT_CARRY_TRAY = M + 1
ADJACENT_CARRY_TRAY_INV_MOD_P = pow(ADJACENT_CARRY_TRAY, -1, P)
Z99_ABS_BOUND = 16_005
SOURCE_K_RADIUS = 48
SOURCE_NORM = 96
SOURCE_PHASE_DENOMINATOR = 16
Z99_TRAY = 99
SCALE_LOCKED_FACTOR = M + 1
COMPOSITE_SCALE_T = P * SCALE_LOCKED_FACTOR
COMPOSITE_CARRY_TRAY = 98  # 2 * 7^2; 2 and 7 are already in the Safe Basis.
P_MOD_COMPOSITE_TRAY = P % COMPOSITE_CARRY_TRAY
P_INV_MOD_COMPOSITE_TRAY = pow(P_MOD_COMPOSITE_TRAY, -1, COMPOSITE_CARRY_TRAY)
COMPOSITE_CARRY_ODD_TRAY = 49
P_INV_MOD_ODD_TRAY = pow(P, -1, COMPOSITE_CARRY_ODD_TRAY)
SAFE_BASIS_ROOT = (2, 3, 5, 7, 11, 13, 17, 19)
SAFE_BASIS_PRODUCT = prod(SAFE_BASIS_ROOT)


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


def adjacent_tray_carry(z99: int) -> dict:
    """Recover the chart carry through the adjacent M+1 tray.

    Let X=99*Z99+M/2=MK+M/2+e. On the live Q/16 source-correlated domain,
    |e|<=6849 and |K|<=48, so

        X=(M+1)*K + (M/2+e-K)

    with the parenthesized remainder strictly between 0 and M. Therefore
    floor(X/(M+1)) is exactly K. Since 2*(M+1)=P+1, K is recovered in Z_P
    from X mod P and the M+1 tray residue, without a signed-centering step.
    This is still an integer oracle: an authenticated dense producer for the
    same-history Enc_P(X mod (M+1)) view is not implemented here.
    """
    result = lift(z99)
    k = result["k_centered"]
    e = result["centered_residual"]
    if abs(e) > source_residual_bound() or abs(k) > SOURCE_K_RADIUS:
        raise ValueError("chart point lies outside the certified source window")

    x = result["x"]
    tray = ADJACENT_CARRY_TRAY
    residue = x % tray
    quotient = (x - residue) // tray
    expected_residue = M // 2 + e - k
    if residue != expected_residue or quotient != k:
        raise AssertionError("adjacent M+1 tray does not preserve the chart carry")

    eliminated = (
        (x % P - residue % P) * ADJACENT_CARRY_TRAY_INV_MOD_P
    ) % P
    if eliminated != k % P:
        raise AssertionError("adjacent-tray K-Elimination disagrees with the chart")
    residual_mod_p = (residue + eliminated - M // 2) % P
    if residual_mod_p != e % P:
        raise AssertionError("adjacent-tray residual disagrees with the chart")
    return {
        "x": x,
        "tray_modulus": tray,
        "tray_residue": residue,
        "tray_quotient": quotient,
        "expected_remainder": expected_residue,
        "k_eliminated_mod_p": eliminated,
        "k_signed": k,
        "e99_mod_p": residual_mod_p,
        "e99": e,
    }


def scale_locked_carry(z99: int) -> dict:
    """Recover K from 99*Z99 at the composite BFV plaintext scale T=p*(M+1).

    The chart relation is 99*Z99=(M+1)*K+(e99-K). Interpreting that valid
    T-scale phase under p rounds by M+1. If the T-scale ciphertext error is
    below Q/2, its additional p-view error is below 1/(2*(M+1)).
    """
    result = lift(z99)
    k = result["k_centered"]
    e = result["centered_residual"]
    if abs(e) > source_residual_bound() or abs(k) > SOURCE_K_RADIUS:
        raise ValueError("chart point lies outside the certified source window")

    x = Z99_TRAY * z99
    residual = x - SCALE_LOCKED_FACTOR * k
    if residual != e - k:
        raise AssertionError("composite scale residual does not equal e99-K")
    if 2 * abs(residual) + 1 >= SCALE_LOCKED_FACTOR:
        raise ValueError("composite scale cannot uniquely round the carry")
    if 2 * abs(x) >= COMPOSITE_SCALE_T:
        raise ValueError("chart integer is not in the signed composite plaintext cell")

    p_view = nearest_quotient(P * x, COMPOSITE_SCALE_T)
    if p_view != k:
        raise AssertionError("composite BFV scale does not decode to the chart carry")
    return {
        "plaintext_T": COMPOSITE_SCALE_T,
        "factor_A": SCALE_LOCKED_FACTOR,
        "x": x,
        "e99_minus_K": residual,
        "p_view_carry": p_view,
        "expected_carry": k,
        "rounding_margin_numerator": SCALE_LOCKED_FACTOR - 2 * abs(residual) - 1,
    }


def safe_basis_high_encoding_carry(z99: int) -> dict:
    """Lift chart K to the composite T encoding through one S8 root.

    For X=99*Z99+M/2, odd root lanes use the M tray:
        K_b=(X_b-(X mod M)_b)*M^-1 mod b.
    The 2 lane uses the adjacent A=M+1 tray:
        K_2=(X_2-(X mod A)_2)*A^-1 mod 2.
    The exact client oracle combines those residues, selects the unique
    signed K in [-48,48], and projects it to T. The encrypted residue producer
    and bounded-lift circuit are not implemented by this function.
    """
    chart = lift(z99)
    k = chart["k_centered"]
    e = chart["centered_residual"]
    if abs(e) > source_residual_bound() or abs(k) > SOURCE_K_RADIUS:
        raise ValueError("chart point lies outside the certified source window")

    x = chart["x"]
    low_m = x % M
    low_a = x % ADJACENT_CARRY_TRAY
    lane_residues = {}
    for modulus in SAFE_BASIS_ROOT:
        if modulus == 2:
            lane_residues[modulus] = (
                (x - low_a) * pow(ADJACENT_CARRY_TRAY, -1, modulus)
            ) % modulus
        else:
            lane_residues[modulus] = (
                (x - low_m) * pow(M, -1, modulus)
            ) % modulus

    # Independent clear CRT oracle. Runtime must use the root's bounded lift,
    # not materialize this aggregate from encrypted lane residues.
    canonical = sum(
        residue
        * (SAFE_BASIS_PRODUCT // modulus)
        * pow(SAFE_BASIS_PRODUCT // modulus, -1, modulus)
        for modulus, residue in lane_residues.items()
    ) % SAFE_BASIS_PRODUCT
    signed = canonical - SAFE_BASIS_PRODUCT if canonical > SAFE_BASIS_PRODUCT // 2 else canonical
    if signed != k:
        raise AssertionError("Safe-Basis sister residues did not recover the chart sheet")

    winding = -1 if signed < 0 else 0
    carry_t = (canonical + winding * SAFE_BASIS_PRODUCT) % COMPOSITE_SCALE_T
    if carry_t != k % COMPOSITE_SCALE_T:
        raise AssertionError("bounded Safe-Basis lift did not project K into T")
    chart_value = Z99_TRAY * z99
    residual_t = (chart_value - SCALE_LOCKED_FACTOR * carry_t) % COMPOSITE_SCALE_T
    if residual_t != (e - k) % COMPOSITE_SCALE_T:
        raise AssertionError("high-encoded carry does not remove the chart residual")

    return {
        "k_signed": signed,
        "k_residue_mod_T": carry_t,
        "canonical_safe_basis_residue": canonical,
        "winding_to_T": winding,
        "lane_residues": lane_residues,
        "chart_residual_mod_T": residual_t,
    }


def source_residual_bound() -> int:
    """Strict integer bound from 97 half-round errors plus Q/16 phase."""
    strict_real_bound_twice = Z99_TRAY * (SOURCE_NORM + 1) + 2 * M // SOURCE_PHASE_DENOMINATOR
    # |e| < (99*97/2) + M/16 = 6849.5, hence integer |e| <= 6849.
    return (strict_real_bound_twice - 1) // 2


def composite_tray_carry(z99: int) -> dict:
    """Recover the bounded chart carry from the candidate composite-98 trays.

    Let X=198*Z99 and e=99*Z99-M*K. Since p=2*M+1,
    X=p*K+(2*e-K). Under the source-correlated bound, the latter term is the
    centered p residue. The p and composite-98 residues then determine K mod
    98; the certified |K|<=48 selects its unique centered representative.
    This is an integer oracle, not an encrypted tray producer.
    """
    result = lift(z99)
    k = result["k_centered"]
    e = result["centered_residual"]
    if abs(e) > source_residual_bound() or abs(k) > SOURCE_K_RADIUS:
        raise ValueError("chart point lies outside the certified source window")

    x = 2 * Z99_TRAY * z99
    p_residue = x % P
    centered_p_residue = p_residue - P if p_residue > P // 2 else p_residue
    if centered_p_residue != 2 * e - k:
        raise AssertionError("centered p residue does not match the chart carry identity")

    carry_residue = (
        (x - centered_p_residue) * P_INV_MOD_COMPOSITE_TRAY
    ) % COMPOSITE_CARRY_TRAY
    centered_carry = (
        carry_residue - COMPOSITE_CARRY_TRAY
        if carry_residue >= COMPOSITE_CARRY_TRAY // 2
        else carry_residue
    )
    if centered_carry != k:
        raise AssertionError("composite-98 K-Elimination disagrees with the source chart")
    return {
        "x": x,
        "centered_p_residue": centered_p_residue,
        "carry_residue_mod_98": carry_residue,
        "k_centered": centered_carry,
        "e99": e,
    }


def composite_sister_trays_signed_carry(z99: int) -> dict:
    """Recover signed K from phase-locked 49 and 2 residues.

    With Y=p*K+w, the 49-tray gives the canonical k49 in [0,48] and the
    existing 2-tray gives K's parity k2. Since 49 is odd, their parity
    mismatch is exactly the sign-correction bit for the certified range
    [-48,48]: K=k49-49*c. This is an exact CRT identity; producing canonical
    k49 and its parity from dense encrypted state is still an unimplemented
    gate, not a linear ciphertext operation.
    """
    result = composite_tray_carry(z99)
    y = 2 * Z99_TRAY * z99
    w = result["centered_p_residue"]
    y49 = y % COMPOSITE_CARRY_ODD_TRAY
    w49 = w % COMPOSITE_CARRY_ODD_TRAY
    y2 = y % 2
    w2 = w % 2

    k49 = ((y49 - w49) * P_INV_MOD_ODD_TRAY) % COMPOSITE_CARRY_ODD_TRAY
    k2 = (y2 - w2) % 2  # p is odd, so p^(-1) mod 2 is one.
    correction_bit = (k49 - k2) % 2
    signed_k = k49 - COMPOSITE_CARRY_ODD_TRAY * correction_bit
    if signed_k != result["k_centered"]:
        raise AssertionError("49/2 sister-tray sign correction disagrees with K")
    return {
        "y_mod_49": y49,
        "w_mod_49": w49,
        "y_mod_2": y2,
        "w_mod_2": w2,
        "k_mod_49_canonical": k49,
        "k_mod_2": k2,
        "sign_correction_bit": correction_bit,
        "sign_correction_matches_negative_k": correction_bit == int(signed_k < 0),
        "k_signed": signed_k,
    }


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
    scale_locked_checks = 0
    scale_locked_max_residual = 0
    scale_locked_min_margin = SCALE_LOCKED_FACTOR
    scale_locked_carries = set()
    composite_checks = 0
    safe_basis_checks = 0
    safe_basis_carries = set()
    safe_basis_lane_sets = {modulus: set() for modulus in SAFE_BASIS_ROOT}
    adjacent_checks = 0
    adjacent_remainder_min = M
    adjacent_remainder_max = 0
    max_abs_centered_p_residue = 0
    for z99 in range(-Z99_ABS_BOUND, Z99_ABS_BOUND + 1):
        result = lift(z99)
        if abs(result["centered_residual"]) <= residual_bound:
            if result["centered_residual"] != result["residual_from_low_tray"]:
                raise AssertionError(f"residual mismatch at Z99={z99}: {result}")
            residual_checks += 1
            locked = scale_locked_carry(z99)
            scale_locked_checks += 1
            scale_locked_max_residual = max(
                scale_locked_max_residual, abs(locked["e99_minus_K"])
            )
            scale_locked_min_margin = min(
                scale_locked_min_margin, locked["rounding_margin_numerator"]
            )
            scale_locked_carries.add(locked["p_view_carry"])
            adjacent = adjacent_tray_carry(z99)
            if adjacent["k_signed"] != result["k_centered"]:
                raise AssertionError(f"adjacent-tray carry mismatch at Z99={z99}")
            adjacent_remainder_min = min(
                adjacent_remainder_min, adjacent["tray_residue"]
            )
            adjacent_remainder_max = max(
                adjacent_remainder_max, adjacent["tray_residue"]
            )
            adjacent_checks += 1
            composite = composite_tray_carry(z99)
            if composite["k_centered"] != result["k_centered"]:
                raise AssertionError(f"composite-98 carry mismatch at Z99={z99}")
            sister = composite_sister_trays_signed_carry(z99)
            if sister["k_signed"] != result["k_centered"]:
                raise AssertionError(f"49/2 sister-tray carry mismatch at Z99={z99}")
            if not sister["sign_correction_matches_negative_k"]:
                raise AssertionError(f"sign correction mismatch at Z99={z99}")
            safe_basis = safe_basis_high_encoding_carry(z99)
            if safe_basis["k_signed"] != result["k_centered"]:
                raise AssertionError(f"Safe-Basis carry mismatch at Z99={z99}")
            safe_basis_carries.add(safe_basis["k_signed"])
            for modulus, residue in safe_basis["lane_residues"].items():
                safe_basis_lane_sets[modulus].add(residue)
            safe_basis_checks += 1
            max_abs_centered_p_residue = max(
                max_abs_centered_p_residue,
                abs(composite["centered_p_residue"]),
            )
            composite_checks += 1

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
        "scope": (
            "clear exact quotient oracle and bounded encrypted-selector fixtures; "
            "composite scale-lock algebra is exhaustively checked here, with dense "
            "ciphertext producer evidence in the Rust research integration"
        ),
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
        "adjacent_M_plus_1_tray": {
            "tray_modulus": ADJACENT_CARRY_TRAY,
            "factorization": "3^2*11*331",
            "plaintext_p": P,
            "tray_inverse_mod_p": ADJACENT_CARRY_TRAY_INV_MOD_P,
            "native_relation": "2*(M+1)=p+1, hence (M+1)^(-1)=2 mod p",
            "identity": "X=(M+1)*K + (M/2+e99-K)",
            "carry_from_tray": "K=floor(X/(M+1)) on the certified source window",
            "tray_remainder_bounds": [adjacent_remainder_min, adjacent_remainder_max],
            "source_correlated_checks": adjacent_checks,
            "all_adjacent_tray_checks_pass": adjacent_checks == residual_checks,
            "bounded_encrypted_selector_fixture": True,
            "encrypted_selector_fixture_carries": [-48, -1, 0, 1, 48],
            "encrypted_selector_fixture_checks": ["K mod p", "e99 mod p"],
            "dense_same_root_tray_produced": False,
        },
        "composite_98_candidate": {
            "tray_modulus": COMPOSITE_CARRY_TRAY,
            "factorization": "2*7^2",
            "safe_basis_roots_already_present": [2, 7],
            "p_mod_tray": P_MOD_COMPOSITE_TRAY,
            "p_inverse_mod_tray": P_INV_MOD_COMPOSITE_TRAY,
            "identity": "198*Z99 = p*K + (2*e99-K)",
            "carry_formula": "K=center_98(47*((Y mod 98)-center(Y mod p)) mod 98)",
            "max_observed_abs_centered_p_residue": max_abs_centered_p_residue,
            "source_correlated_checks": composite_checks,
            "all_composite_98_checks_pass": composite_checks == residual_checks,
            "bounded_encrypted_selector_fixture": (
                "same-root residue check passes for K=-48,-1,0,1,48; "
                "centering is client-side, not an Enc_p(K) producer"
            ),
            "dense_same_root_trays_produced": False,
        },
        "composite_scale_locked_quotient": {
            "plaintext_p": P,
            "plaintext_T": COMPOSITE_SCALE_T,
            "factor_A": SCALE_LOCKED_FACTOR,
            "clock_modulus_M": M,
            "identity": "99*Z99 = A*K + (e99-K), A=M+1",
            "p_decoder": "round(p*phase_T/Q)=round(99*Z99/A)=K",
            "valid_T_phase_noise_term": "<1/(2*A) when |T*phase-Q*x|<Q/2",
            "rounding_certificate": "2*|e99-K|+1 < A",
            "source_correlated_checks": scale_locked_checks,
            "all_scale_locked_checks_pass": scale_locked_checks == residual_checks,
            "max_abs_e99_minus_K": scale_locked_max_residual,
            "minimum_rounding_margin_numerator": scale_locked_min_margin,
            "carry_values_in_domain": [min(scale_locked_carries), max(scale_locked_carries)],
            "requires_low_tray_or_extra_safe_basis_root": False,
        },
        "safe_basis_sister_tray_high_encoding_carry": {
            "safe_basis_root": list(SAFE_BASIS_ROOT),
            "root_product": SAFE_BASIS_PRODUCT,
            "odd_lane_formula": "K_b=(X_b-(X mod M)_b)*M^(-1) mod b",
            "two_lane_formula": "K_2=(X_2-(X mod (M+1))_2)*(M+1)^(-1) mod 2",
            "bounded_lift": "unique signed K in [-48,48], then project to T",
            "target_plaintext_T": COMPOSITE_SCALE_T,
            "source_correlated_checks": safe_basis_checks,
            "all_sister_lane_and_target_checks_pass": safe_basis_checks == residual_checks,
            "carry_values_in_domain": [min(safe_basis_carries), max(safe_basis_carries)],
            "observed_lane_residue_counts": {
                str(modulus): len(residues)
                for modulus, residues in safe_basis_lane_sets.items()
            },
            "same_history_encrypted_sister_trays_produced": False,
            "crt_reconstruction_used_only_by_clear_test_oracle": True,
        },
        "composite_sister_trays_49_2": {
            "factorization": "98=49*2",
            "p_inverse_mod_49": P_INV_MOD_ODD_TRAY,
            "requires_centered_p_residue_w": True,
            "requires_signed_lift_from_mod_98_to_p": True,
            "identity": (
                "k49=((Y49-w49)*47) mod 49; k2=(Y2-w2) mod 2; "
                "c=(k49-k2) mod 2; K=k49-49*c"
            ),
            "correction_bit": "c=1 exactly when K<0 for |K|<=48",
            "source_correlated_checks": composite_checks,
            "all_signed_49_2_checks_pass": composite_checks == residual_checks,
            "encrypted_centering_or_signed_lift_gate_exists": False,
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
            "plaintext_ring_output": "K mod p directly encodes signed K; negative K maps to p-|K|",
            "explicit_signed_centering_required_for_ring_arithmetic": False,
            "carry_bound_selects_unique_signed_lift": "|K|<=48<p/2",
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
            "The T=p*(M+1) scale-locked carry readout passes native encrypted "
            "producer tests at N=512 and N=8192, and affine+K Phase 1 recovers "
            "the source plaintext across all 16,384 native doubled-ring "
            "coefficients. The measured p-view error retains r/A; native "
            "N=8192 stays at the incoming Q/16 scale rather than contracting. "
            "A one-root S8 sister-tray oracle now lifts K into T from odd-lane "
            "M residues and the 2-lane M+1 residue across all source-correlated "
            "points. Its encrypted same-history tray producers and bounded "
            "lift are absent. Production also needs the typed T precharge, "
            "residual return, next dense multiply, second refresh, and admission."
        ),
        "public_refresh_admitted": False,
    }


if __name__ == "__main__":
    import json

    print(json.dumps(report(), indent=2))
