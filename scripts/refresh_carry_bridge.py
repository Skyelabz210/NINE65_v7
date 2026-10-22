#!/usr/bin/env python3
"""Exact clear-oracle experiments for the refresh carry research note.

No ciphertext evaluator, secret-key access, floating point, or refresh
admission. Toy secrets below are public exhaustive test inputs.
"""

import hashlib
import itertools
import json
from math import prod
from pathlib import Path

from bounded_digit_polynomial import certify, construct, evaluate, self_test


def nearest(value, modulus):
    if modulus < 3 or modulus % 2 == 0:
        raise ValueError("the oracle requires an odd positive modulus")
    return (value + modulus // 2) // modulus


def centered(value, modulus):
    return value - modulus * nearest(value, modulus)


def carry(a, b, modulus):
    return (centered(a, modulus) + centered(b, modulus)
            - centered(a + b, modulus)) // modulus


def carry_step(state, term, modulus):
    """Advance one centered representative and return its integer winding."""
    if centered(state, modulus) != state:
        raise ValueError("carry state must be the centered representative")
    next_state = centered(state + term, modulus)
    winding = (state + term - next_state) // modulus
    return next_state, winding


def carry_block(state, terms, modulus):
    """Compose local carry steps; equivalent to one translation by sum(terms)."""
    winding = 0
    for term in terms:
        state, increment = carry_step(state, term, modulus)
        winding += increment
    return state, winding


def wide_carry_requirements(n, q, base):
    """Exact range/encoding floor for aggregating K before one quotient."""
    half = (q - 1) // 2
    sum_bound = (n + 1) * half
    minimum_plaintext_modulus = 2 * sum_bound + 1
    exponent, modulus = 1, base
    while modulus < minimum_plaintext_modulus:
        exponent += 1
        modulus *= base
    carry_radius = (sum_bound + half) // q
    return sum_bound, minimum_plaintext_modulus, exponent, modulus, carry_radius


def convolution(a, b):
    n = len(a)
    result = [0] * n
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            result[(i + j) % n] += x * y * (1 if i + j < n else -1)
    return result


def multiplication_winding_case(c0, c1, secret, q, t):
    """Independent integer check of tensor winding and its cancellation."""
    n = len(secret)
    lifted = [a + b for a, b in zip(c0, convolution(c1, secret))]
    phase = [centered(value, q) for value in lifted]
    winding = [(a - p) // q for a, p in zip(lifted, phase)]
    d0 = convolution(c0, c0)
    d1 = [2 * value for value in convolution(c0, c1)]
    d2 = convolution(c1, c1)
    rounded = [[nearest(t * value, q) for value in part]
               for part in (d0, d1, d2)]
    tensor_phase = [a + b + c for a, b, c in zip(
        rounded[0], convolution(rounded[1], secret),
        convolution(rounded[2], convolution(secret, secret)),
    )]
    phase_only = [nearest(t * value, q) for value in convolution(phase, phase)]
    correction = [2 * t * value for value in convolution(winding, phase)]
    combined_round = [nearest(t * value, q) for value in convolution(lifted, lifted)]
    rounding_bound = (n * n + n + 2) // 2
    for actual, ideal, term, combined in zip(
            tensor_phase, phase_only, correction, combined_round):
        assert (combined - ideal - term) % q == 0
        assert abs(actual - combined) <= rounding_bound
        assert abs(centered(actual - ideal - term, q)) <= rounding_bound


def carry_encoding_adapter_case(c0, c1, secret, q, t):
    """Check raw/Delta carry adapters, including the carry ciphertext's winding.

    All coordinates and secrets are public toy inputs. No producer or security
    claim: this separates algebra, scale mismatch, and component rounding.
    """
    n, delta, remainder = len(secret), q // t, q % t
    lifted = [a + b for a, b in zip(c0, convolution(c1, secret))]
    phase = [centered(a, q) for a in lifted]
    winding = [(a - p) // q for a, p in zip(lifted, phase)]
    correction = [2 * t * v for v in convolution(winding, phase)]
    secret_square = convolution(secret, secret)
    rounding_weight = 1 + sum(map(abs, secret)) + sum(map(abs, secret_square))

    def tensor(a0, a1, b0, b1):
        parts = (convolution(a0, b0),
                 [a + b for a, b in zip(convolution(a0, b1), convolution(a1, b0))],
                 convolution(a1, b1))
        rounded = [[nearest(t * v, q) for v in part] for part in parts]
        result = [a + b + c for a, b, c in zip(
            rounded[0], convolution(rounded[1], secret),
            convolution(rounded[2], secret_square))]
        a = [x + y for x, y in zip(a0, convolution(a1, secret))]
        b = [x + y for x, y in zip(b0, convolution(b1, secret))]
        rounding = [q * x - t * y for x, y in zip(result, convolution(a, b))]
        assert all(2 * abs(v) <= q * rounding_weight for v in rounding)
        return result, rounding

    cases = nonzero_winding = 0
    original_square, _ = tensor(c0, c1, c0, c1)
    for unit_error in (-1, 0, 1):
        noise = [unit_error] + [0] * (n - 1)
        clear_control = None
        for mask in ([0] * n, c1):
            mask_phase = convolution(mask, secret)
            raw_target = [k + e for k, e in zip(winding, noise)]
            raw_b0 = [centered(v - a, q) for v, a in zip(raw_target, mask_phase)]
            raw_lift = [a + b for a, b in zip(raw_b0, mask_phase)]
            raw_product = [2 * t * v for v in convolution(lifted, raw_lift)]
            raw_error = [2 * t * v for v in convolution(phase, noise)]
            assert all((a - b - e) % q == 0
                       for a, b, e in zip(raw_product, correction, raw_error))

            target = [delta * k + e for k, e in zip(winding, noise)]
            b0 = [centered(v - a, q) for v, a in zip(target, mask_phase)]
            carry_lift = [a + b for a, b in zip(b0, mask_phase)]
            own_winding = [(a - b) // q for a, b in zip(carry_lift, target)]
            assert carry_lift == [b + q * j for b, j in zip(target, own_winding)]
            cross, cross_rounding = tensor(c0, c1, b0, mask)
            square, square_rounding = tensor(b0, mask, b0, mask)
            compensated = [2 * t * a - t * t * b for a, b in zip(cross, square)]
            v = [p + remainder * k - t * e
                 for p, k, e in zip(phase, winding, noise)]
            # A-t*B = V-t*Q*J. Even after compensating Delta's floor
            # mismatch, the encrypted carry's own J contributes 2*t^2*J*V.
            predicted_numerator = [t * (a - b) + 2 * t * t * q * j
                                   for a, b, j in zip(
                                       convolution(phase, phase), convolution(v, v),
                                       convolution(own_winding, v))]
            rounding = [2 * t * a - t * t * b
                        for a, b in zip(cross_rounding, square_rounding)]
            assert all((q * (d - w) - prediction - rounding_error) % (q * q) == 0
                       for d, w, prediction, rounding_error in zip(
                           compensated, correction, predicted_numerator, rounding))
            assert all(2 * abs(value) <= q * (2 * t + t * t) * rounding_weight
                       for value in rounding)
            second_term = [2 * t * t * value for value in convolution(own_winding, v)]
            twice_corrected = [a - b + term for a, b, term in zip(
                original_square, compensated, second_term)]
            phase_square = [nearest(t * value, q) for value in convolution(v, v)]
            amplified_bound = (n*n+n+2)//2 * (t+1)**2 + 1
            assert all(abs(centered(a-b, q)) <= amplified_bound
                       for a, b in zip(twice_corrected, phase_square))

            # Positive algebraic control: combine UNROUNDED operands, then
            # scale/round only once. It needs a wider transient certificate;
            # feeding reduced main-Q components to the old API is not this.
            f0 = [a - t*b for a, b in zip(c0, b0)]
            f1 = [a - t*b for a, b in zip(c1, mask)]
            single_tensor, _ = tensor(f0, f1, f0, f1)
            f_lift = [a - t*b for a, b in zip(lifted, carry_lift)]
            combined_round = [nearest(t*value, q) for value in convolution(f_lift, f_lift)]
            assert all(abs(a-b) <= (n*n+n+2)//2
                       for a, b in zip(single_tensor, combined_round))
            assert all((a+term-b) % q == 0
                       for a, term, b in zip(combined_round, second_term, phase_square))
            single_corrected = [a + b for a, b in zip(single_tensor, second_term)]
            assert all(abs(centered(a-b, q)) <= (n*n+n+2)//2
                       for a, b in zip(single_corrected, phase_square))
            for unit_j_error in (-1, 1):
                perturbed_j = list(own_winding)
                perturbed_j[0] += unit_j_error
                perturbed_term = [2*t*t*x for x in convolution(perturbed_j, v)]
                perturbed = [a-b+term for a, b, term in zip(
                    original_square, compensated, perturbed_term)]
                assert all((a-b-2*t*t*unit_j_error*x) % q == 0
                           for a, b, x in zip(perturbed, twice_corrected, v))
            if clear_control is None:
                clear_control = (compensated, own_winding, rounding)
            else:
                clear_result, clear_winding, clear_rounding = clear_control
                changed_winding = [a - b for a, b in zip(own_winding, clear_winding)]
                mask_term = [2 * t * t * q * value
                             for value in convolution(changed_winding, v)]
                # Same carry phase and SAME noise: only the representation
                # winding and tensor-rounding terms may change with the mask.
                assert all((q * (a - b) - term - (ra - rb)) % (q * q) == 0
                           for a, b, term, ra, rb in zip(
                               compensated, clear_result, mask_term, rounding, clear_rounding))
            nonzero_winding += any(own_winding)
            cases += 1
    return cases, nonzero_winding


def multiplication_winding_budget():
    """Sufficient next-square bound for constant plaintext one, not admission.

    For P=Delta+e and ||e||_inf<=E, ||K||_1<=N^2/2 gives a winding
    contribution at most t*N^2*E + N*r. Bound the phase-only product,
    independent component rounding and the hybrid key switch separately.
    """
    primes = [1811939329, 2113929217, 2130706433, 1107296257, 1711276033]
    n, t, eta, base_bits = 8192, 65537**2, 3, 10
    q = prod(primes)
    remainder = q % t
    half_delta = q // t // 2
    rounding = (n * n + n + 2) // 2
    switch = (eta * n * ((1 << base_bits) - 1)
              * sum((p.bit_length() + base_bits - 1) // base_bits for p in primes))

    def square_bound(error):
        quadratic = (t * n * error * error + q - 1) // q
        return (2 * error + quadratic + t * n * n * error
                + n * remainder + rounding + switch + 2)

    low, high = 0, half_delta
    while low < high:
        middle = (low + high + 1) // 2
        if square_bound(middle) < half_delta:
            low = middle
        else:
            high = middle - 1
    assert square_bound(low) < half_delta <= square_bound(low + 1)
    assert square_bound((1 << 62) - 1) < half_delta
    assert square_bound((1 << 63) - 1) >= half_delta
    # An ideal Delta-scaled unit with just ONE unit of phase error cannot be
    # converted to a raw-phase unit by modular inversion without amplification.
    delta = q // t
    inverse = pow(delta, -1, q)
    converted_unit_error = abs(centered((delta + 1) * inverse - 1, q))
    assert converted_unit_error > half_delta
    single_round_operand_bound = n//2 * (t+1)**2
    single_round_shift_multiplier = single_round_operand_bound*t + 1
    assert single_round_operand_bound >= 1 << 64
    # Existing catalog's N=8192 seven lanes, followed by two of its N=16384
    # lanes (also NTT-compatible at N=8192). Transient arithmetic ONLY: the
    # ciphertext modulus and security screen are unchanged.
    transient_pool = [2013265921, 2281701377, 2483027969, 2885681153,
                      3221225473, 3221422081, 3222306817, 3222372353, 3222568961]
    required = 2*single_round_shift_multiplier*q
    assert prod(transient_pool[:7]) <= required < prod(transient_pool)
    assert all((a-1) % (2*n) == 0 for a in transient_pool)
    aux_product = prod(transient_pool)
    reverse_rank_peak = (len(transient_pool)+1)*aux_product
    assert reverse_rank_peak.bit_length() > 256
    aux_weights = [(aux_product//a)*pow(aux_product//a, -1, a) for a in transient_pool]
    shift = single_round_shift_multiplier*q
    operand_limit = single_round_operand_bound*q*q
    wide_scale_cases = 0
    for x in (-operand_limit, -operand_limit+1, -q*q, -q//2, -1,
              0, 1, q//2, q*q, operand_limit-1, operand_limit):
        z = t*x + q//2
        w = z % q
        exact = (z-w)//q
        residues = [((t*(x % a)+(q//2) % a-w % a)*pow(q, -1, a)+shift % a) % a
                    for a in transient_pool]
        recovered = sum(value*weight for value, weight in zip(residues, aux_weights)) % aux_product
        assert 0 <= exact+shift < aux_product
        assert recovered == exact+shift
        assert recovered % q == exact % q
        wide_scale_cases += 1
    return {
        "scope": "constant-one plaintext, assumed certified input error; no correction producer",
        "primes": primes, "N": n, "t": t, "Q_bits": q.bit_length(),
        "Q_mod_t": remainder, "component_rounding_bound": rounding,
        "hybrid_switch_bound": switch,
        "compensated_separate_switch_bound": (2 * t + t * t) * switch,
        "compensated_separate_switch_bound_bits": ((2 * t + t * t) * switch).bit_length(),
        "compensated_fused_switch_bound": switch,
        "compensated_fused_switch_bound_bits": switch.bit_length(),
        "two_winding_rounding_bound_bits": (rounding*(t+1)**2+1).bit_length(),
        "single_round_unwrapped_operand_bound": single_round_operand_bound,
        "single_round_unwrapped_operand_bound_bits": single_round_operand_bound.bit_length(),
        "single_round_shift_multiplier_bits": single_round_shift_multiplier.bit_length(),
        "single_round_operand_bound_fits_current_u64_api": False,
        "single_round_required_auxiliary_capacity_bits": (2*single_round_shift_multiplier*q).bit_length(),
        "single_round_transient_catalog_7_lane_capacity_bits": prod(transient_pool[:7]).bit_length(),
        "single_round_transient_candidate_lanes": len(transient_pool),
        "single_round_transient_candidate_capacity_bits": aux_product.bit_length(),
        "single_round_reverse_rank_fallback_required_bits": reverse_rank_peak.bit_length(),
        "single_round_reverse_rank_fits_current_u256_kernel": False,
        "single_round_wide_residue_scale_boundary_cases": wide_scale_cases,
        "single_round_native_wide_kernel_implemented": False,
        "maximum_input_error_for_next_square": low,
        "adjacent_boundary_checked": True,
        "any_62_bit_input_error_fits": True,
        "arbitrary_63_bit_input_error_fits": False,
        "modular_Delta_inverse_unit_error_bits": converted_unit_error.bit_length(),
        "modular_Delta_inverse_unit_error_exceeds_half_delta": True,
        "half_delta_bits": half_delta.bit_length(),
    }


def component_case(c0, c1, secret, q, t):
    a0 = [nearest(t * v, q) for v in c0]
    a1 = [nearest(t * v, q) for v in c1]
    r0 = [t * v - q * a for v, a in zip(c0, a0)]
    r1 = [t * v - q * a for v, a in zip(c1, a1)]
    phase = [x + y for x, y in zip(c0, convolution(c1, secret))]
    affine = [x + y for x, y in zip(a0, convolution(a1, secret))]
    residual = [x + y for x, y in zip(r0, convolution(r1, secret))]
    correction = [nearest(v, q) for v in residual]
    target = [nearest(t * v, q) for v in phase]
    assert target == [a + k for a, k in zip(affine, correction)]
    assert [v % t for v in target] == [
        nearest(t * (v % q), q) % t for v in phase
    ]
    # Independently accumulate the centered-section defect, including each
    # sign from negacyclic multiplication. For ternary s, individual signed
    # residuals are already centered. Their accumulated carry is K_j.
    for j, expected in enumerate(correction):
        terms = [r0[j]]
        for i, value in enumerate(r1):
            k = (j - i) % len(secret)
            terms.append(value * secret[k] * (1 if i + k < len(secret) else -1))
        representative = winding = 0
        for term in terms:
            winding += carry(representative, term, q)
            representative = centered(representative + term, q)
        assert winding == expected
    return any(a % t != v % t for a, v in zip(affine, target))


def run():
    cocycles = scalar_cases = ring_cases = affine_failures = 0
    transfer_cases = local_rule_cases = extension_cases = carry_bound_cases = 0
    for q in (3, 5, 17, 31):
        for a, b, c in itertools.product(range(q), repeat=3):
            assert carry(a, b, q) + carry(a + b, c, q) == (
                carry(b, c, q) + carry(a, b + c, q)
            )
            cocycles += 1
    # The cocycle is a composable lift of translations on Z/QZ. Exhaustively
    # check that a block's winding equals the one-shot quotient and is
    # independent of where a sequence is split into sub-blocks.
    for q in (3, 5, 7):
        radius = q // 2
        terms = range(-radius, radius + 1)
        for initial in range(-radius, radius + 1):
            for length in range(4):
                for sequence in itertools.product(terms, repeat=length):
                    final_state, total_winding = carry_block(initial, sequence, q)
                    direct_state = centered(initial + sum(sequence), q)
                    direct_winding = (initial + sum(sequence) - direct_state) // q
                    assert (final_state, total_winding) == (direct_state, direct_winding)
                    for split in range(length + 1):
                        middle, left_winding = carry_block(initial, sequence[:split], q)
                        final, right_winding = carry_block(middle, sequence[split:], q)
                        assert (final, left_winding + right_winding) == (
                            final_state, total_winding
                        )
                        transfer_cases += 1
    # For centered x,v, a single representative crossing has only three
    # possible windings. This is the exact piecewise-threshold local rule.
    for q in (3, 5, 17, 31):
        # A full circuit of the residue generator crosses the centered cut
        # exactly once: the section cocycle represents the non-split integer
        # lift Z -> Z/QZ, rather than a carry removable by a homomorphic choice
        # of centered representatives.
        generator_winding = sum(carry(a, 1, q) for a in range(q))
        assert generator_winding == 1
        extension_cases += q
        radius = q // 2
        for state, term in itertools.product(range(-radius, radius + 1), repeat=2):
            _, actual = carry_step(state, term, q)
            total = state + term
            threshold = int(total >= radius + 1) - int(total <= -radius - 1)
            assert actual == threshold
            assert actual in (-1, 0, 1)
            local_rule_cases += 1
    # Phase-1 K is a rounded sum of one centered residual plus a ternary
    # negacyclic combination of N centered residuals. The l1 extremum is
    # (N+1)*h_Q, and for the listed even N / odd Q tuples its rounded quotient
    # reaches exactly N/2, the sharp signed carry radius.
    for n, q in (
        (2, 5), (4, 17), (8, 31),
        (8192, 348959453350711275087786864768188417),
    ):
        half = (q - 1) // 2
        max_sum = (n + 1) * half
        radius = (max_sum + half) // q
        assert radius == n // 2
        assert nearest(max_sum, q) == radius
        assert nearest(-max_sum, q) == -radius
        carry_bound_cases += 1
    native_q = 348959453350711275087786864768188417
    native_sum_bound, minimum_plaintext, wide_exp, wide_modulus, native_k = (
        wide_carry_requirements(8192, native_q, 65537)
    )
    assert native_k == 4096
    assert minimum_plaintext.bit_length() == 132
    assert wide_exp == 9 and wide_modulus.bit_length() == 145
    assert native_q.bit_length() == 119 < wide_modulus.bit_length()
    adapter_cases = adapter_own_winding_cases = 0
    for q, t in ((5, 3), (17, 5), (31, 7)):
        values = range(-q // 2 + 1, q // 2 + 1)
        for a, b, s in itertools.product(values, values, (-1, 0, 1)):
            affine_failures += component_case([a], [b], [s], q, t)
            multiplication_winding_case([a], [b], [s], q, t)
            count, own = carry_encoding_adapter_case([a], [b], [s], q, t)
            adapter_cases += count
            adapter_own_winding_cases += own
            scalar_cases += 1
    for c0 in itertools.product(range(-2, 3), repeat=2):
        for c1 in itertools.product(range(-2, 3), repeat=2):
            for s in itertools.product((-1, 0, 1), repeat=2):
                affine_failures += component_case(c0, c1, s, 5, 3)
                multiplication_winding_case(c0, c1, s, 5, 3)
                count, own = carry_encoding_adapter_case(c0, c1, s, 5, 3)
                adapter_cases += count
                adapter_own_winding_cases += own
                ring_cases += 1
    assert affine_failures > 0, "dropping the carry must have counterexamples"
    assert adapter_cases == 6 * (scalar_cases + ring_cases)
    assert adapter_own_winding_cases > 0, "the carry ciphertext's winding must be exercised"

    contractions = winding_cases = 0
    for p in (3, 5, 17, 31):
        for w in range(p * p):
            x = (w + p // 2) % (p * p)
            r = x % p
            d = (x - r) // p
            assert d == nearest(w, p) % p
            contractions += 1
            for winding in range(-3, 4):
                assert nearest(w + winding * p * p, p) % p == d
                winding_cases += 1

    bounded = []
    for p, bound in ((17, 2), (65537, 17), (65537, 32)):
        f = construct(p, bound)
        identities = certify(f, p, bound)
        cases = 0
        for r in range(-bound, bound + 1):
            for m in (0, 1, p // 2, p - 1):
                x = (r + p * m) % (p * p)
                lifted = evaluate(f, x, p * p)
                assert lifted == r % (p * p)
                assert (x - lifted) % p == 0
                assert ((x - lifted) % (p * p)) // p == m
                cases += 1
        outside = next((r for r in range(bound + 1, p // 2 + 1)
                        if evaluate(f, r, p * p) != r), None)
        assert outside is not None, "a support violation must not count as covered"
        # The signed bounded section is not the canonical [0,p) section.
        assert evaluate(f, p * p - 1, p * p) == p * p - 1
        assert evaluate(f, p * p - 1, p * p) != p - 1
        bounded.append({
            "p": p, "bound": bound, "degree": len(f) - 1,
            "degree_depth_lower_bound": (len(f) - 2).bit_length(),
            "certificate": identities, "sampled_contractions": cases,
            "outside_support_counterexample": outside,
            "output_section": "signed [-B,B], not canonical [0,p)",
            "input_support_proved_for_native_ciphertexts": False,
        })
    sources = [Path(__file__), Path(__file__).with_name("bounded_digit_polynomial.py")]
    return {
        "schema": "nine65-refresh-carry-bridge-v1",
        "scope": "clear integer identities; no encrypted correction or security admission",
        "source_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
        "checks": {
            "centered_section_cocycle_triples": cocycles,
            "composable_translation_block_cases": transfer_cases,
            "local_piecewise_threshold_cases": local_rule_cases,
            "full_cycle_extension_winding_cases": extension_cases,
            "phase1_carry_bound_boundary_cases": carry_bound_cases,
            "scalar_component_cases": scalar_cases,
            "negacyclic_n2_cases": ring_cases,
            "multiplication_winding_cancellation_cases": scalar_cases + ring_cases,
            "carry_encoding_adapter_cases": adapter_cases,
            "matched_identical_noise_mask_comparisons": adapter_cases // 2,
            "second_winding_cancellation_and_rounding_cases": adapter_cases,
            "single_round_unwrapped_tensor_cases": adapter_cases,
            "second_winding_unit_error_cases": 2*adapter_cases,
            "adapter_cases_with_nonzero_carry_ciphertext_winding": adapter_own_winding_cases,
            "cases_where_uncorrected_affine_result_is_wrong": affine_failures,
            "prime_power_contractions": contractions,
            "expanded_winding_invariance_cases": winding_cases,
            "existing_bounded_polynomial_exhaustive_cases": self_test(),
        },
        "bounded_candidates": bounded,
        "multiplication_winding_next_square_budget": multiplication_winding_budget(),
        "wide_sum_candidate": {
            "scope": "range and encoding width only; no noise or security admission",
            "native_Q": native_q,
            "native_Q_bits": native_q.bit_length(),
            "N": 8192,
            "sum_abs_bound": native_sum_bound,
            "minimum_plaintext_modulus": minimum_plaintext,
            "minimum_plaintext_bits": minimum_plaintext.bit_length(),
            "p_power_base": 65537,
            "p_power_exponent": wide_exp,
            "p_power_modulus_bits": wide_modulus.bit_length(),
            "carry_radius": native_k,
            "carry_coordinate_modulus": 8193,
            "current_main_Q_can_encode_sum": False,
        },
        "public_refresh_admitted": False,
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
