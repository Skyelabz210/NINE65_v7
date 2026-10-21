import itertools
import unittest

from certified_noise_oracle import centered, negacyclic_mul, phase_error
from bounded_digit_polynomial import construct, certify, evaluate
from digit_radius_oracle import (
    modswitch_scaled_error_bound, outer_expansion_scaled_error_bound,
    residual_radius, residual_radius_for_secret, rns_keyswitch_phase_bound, sparse_route_radius,
    supports_bounded_digit,
)


# Independent, exact toy-ring fixtures. No production sampler, security claim,
# transform implementation, or native RNS evaluator is supplied by these tests.
def reduce_poly(a, q):
    return [centered(x, q) for x in a]


def phase(ct, secret):
    power = [1] + [0] * (len(secret) - 1)
    result = [0] * len(secret)
    for component in ct:
        result = [a + b for a, b in zip(result, negacyclic_mul(component, power))]
        power = negacyclic_mul(power, secret)
    return result


def encrypt_fixture(message, secret, q, p, error):
    n = len(secret)
    c1 = [centered((j + 1) * (q // (n + 3)) + 19, q) for j in range(n)]
    product = negacyclic_mul(c1, secret)
    c0 = [q // p * centered(m, p) + e - v for m, e, v in zip(message, error, product)]
    return [reduce_poly(c0, q), c1]


def decode(ct, secret, q, p):
    return [((p * x + q // 2) // q) % p for x in phase(ct, secret)]


def public_expansion(ct, encapsulated_key, q_inner, q_outer, p):
    """Only ciphertexts/public moduli, no inner or outer secret argument."""
    expanded = p * p
    a0, a1 = [reduce_poly([(expanded * x + q_inner // 2) // q_inner
                          for x in c], expanded) for c in ct]
    result = [negacyclic_mul(a1, c) for c in encapsulated_key]
    result[0] = [x + (q_outer // expanded) * a for x, a in zip(result[0], a0)]
    return [reduce_poly(c, q_outer) for c in result], a0, a1


def public_tensor_multiply(left, right, q, p):
    """Unrelinearized toy BFV multiply; deliberately not a native circuit."""
    n = len(left[0])
    tensor = [[0] * n for _ in range(len(left) + len(right) - 1)]
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            tensor[i + j] = [x + y for x, y in zip(tensor[i + j], negacyclic_mul(a, b))]
    return [reduce_poly([(p * x + q // 2) // q for x in c], q) for c in tensor]


def public_polynomial(ct, coefficients, q, p):
    """Balanced powers on a CONSTANT plaintext projection; no secret access.

    Applying this to an untransformed coefficient vector is NOT coefficientwise
    digit extraction. The missing native transforms remain a separate gate.
    """
    n = len(ct[0])
    powers = {1: ct}

    def power(k):
        if k not in powers:
            powers[k] = public_tensor_multiply(power(k // 2), power(k - k // 2), q, p)
        return powers[k]

    out = [[q // p * centered(coefficients[0], p)] + [0] * (n - 1)]
    for k, coefficient in enumerate(coefficients[1:], 1):
        if coefficient == 0:
            continue
        term = power(k)
        out.extend([[0] * n for _ in range(len(term) - len(out))])
        for j, component in enumerate(term):
            out[j] = reduce_poly([x + centered(coefficient, p) * y
                                  for x, y in zip(out[j], component)], q)
    return out


def public_subtract(left, right, q):
    n = len(left[0])
    return [reduce_poly([a - b for a, b in zip(
        left[j] if j < len(left) else [0] * n,
        right[j] if j < len(right) else [0] * n)], q)
        for j in range(max(len(left), len(right)))]


class DigitRadiusTests(unittest.TestCase):
    def test_actual_negacyclic_phases_exhaustive(self):
        checked = 0
        rounding_is_required = False
        bound_is_attained = False
        for q, p in ((5, 3), (7, 3)):
            n = 2
            vectors = list(itertools.product(range(-(q // 2), q // 2 + 1), repeat=n))
            secrets = list(itertools.product((-1, 0, 1), repeat=n))
            for c0, c1, secret in itertools.product(vectors, vectors, secrets):
                prepared = [[(p * p * v + q // 2) // q for v in c] for c in (c0, c1)]
                expanded = [a + b for a, b in zip(prepared[0], negacyclic_mul(prepared[1], secret))]
                for message in range(p):
                    v = max(map(abs, phase_error((c0, c1), message, secret, q, p)))
                    if 2 * v >= q:
                        continue
                    radius = residual_radius(q, p, n, v)
                    residual = [centered(x - (p * centered(message, p) if j == 0 else 0), p * p)
                                for j, x in enumerate(expanded)]
                    actual = max(map(abs, residual))
                    self.assertLessEqual(actual, radius)
                    self.assertLessEqual(actual, residual_radius_for_secret(
                        q, p, sum(map(abs, secret)), v))
                    rounding_is_required |= actual > (p * v) // q
                    bound_is_attained |= actual == radius and radius > 0
                    # When admitted to a narrow interval, exact rounded
                    # extraction must preserve every plaintext coefficient.
                    if supports_bounded_digit(q, p, n, v, p // 2):
                        decoded = [((x + p // 2) // p) % p for x in expanded]
                        self.assertEqual(decoded, [message, 0])
                    checked += 1
        self.assertGreater(checked, 1000)
        self.assertTrue(rounding_is_required)
        self.assertTrue(bound_is_attained)

    def test_native_history_and_first_support_boundary(self):
        q, p, n = 348959453350711275087786864768188417, 65537, 8192
        for v, expected in ((5011390467, 4096),
                            (22046046060462580170753, 4096),
                            (96984689102983990917283450424483841, 22310)):
            self.assertEqual(residual_radius(q, p, n, v), expected)
            self.assertFalse(supports_bounded_digit(q, p, n, v, 17))
            self.assertFalse(supports_bounded_digit(q, p, n, v, 32))
            self.assertTrue(supports_bounded_digit(q, p, n, v, expected))
            self.assertFalse(supports_bounded_digit(q, p, n, v, expected - 1))
        # First V at which the floor of the exact rational radius reaches B+1.
        b = 4096
        threshold = (2 * q * (b + 1) - (n + 1) * (q - 1) + 2 * p - 1) // (2 * p)
        self.assertTrue(supports_bounded_digit(q, p, n, threshold - 1, b))
        self.assertFalse(supports_bounded_digit(q, p, n, threshold, b))

    def test_invalid_and_ambiguous_inputs_refuse(self):
        for q, p, n, v in ((4, 3, 2, 0), (17, 2, 2, 0), (17, 5, 0, 0),
                            (17, 5, 2, -1), (17, 5, 2, 9)):
            with self.assertRaises(ValueError):
                residual_radius(q, p, n, v)
        self.assertFalse(supports_bounded_digit(17, 5, 2, 0, -1))
        self.assertFalse(supports_bounded_digit(17, 5, 2, 0, 3))

    def test_sparse_native_fixtures_and_exact_boundary(self):
        q, p, h, b = 348959453350711275087786864768188417, 65537, 32, 17
        for v, expected in ((0, 16), (5011390467, 16),
                            (22046046060462580170753, 16),
                            (96984689102983990917283450424483841, 18230)):
            self.assertEqual(residual_radius_for_secret(q, p, h, v), expected)
        threshold = (2 * q * (b + 1) - (h + 1) * (q - 1) + 2 * p - 1) // (2 * p)
        self.assertEqual(residual_radius_for_secret(q, p, h, threshold - 1), b)
        self.assertEqual(residual_radius_for_secret(q, p, h, threshold), b + 1)

    def test_modswitch_exhaustive_with_floor_encoding(self):
        checked = 0
        for q, target, p in ((13, 7, 3), (17, 11, 5)):
            for c0, c1, s in itertools.product(range(-q // 2 + 1, q // 2 + 1),
                                              range(-q // 2 + 1, q // 2 + 1), (-1, 0, 1)):
                for m in range(p):
                    v = abs(phase_error(([c0], [c1]), m, [s], q, p)[0])
                    if 2 * v >= q:
                        continue
                    switched = [[(target * c + q // 2) // q] for c in (c0, c1)]
                    actual = abs(phase_error(switched, m, [s], target, p)[0])
                    self.assertLessEqual(actual, modswitch_scaled_error_bound(q, target, p, abs(s), v))
                    checked += 1
        self.assertGreater(checked, 1000)

    def test_noisy_keyswitch_then_expansion_under_every_dense_outer_key(self):
        # All signs of the four-coefficient outer key; inner key has weight 2.
        n, p, q, qo, base = 4, 17, 1000000007, 1000000000039, 16
        lanes = (1009, 1013)
        qs = lanes[0] * lanes[1]
        dense, sparse = [1, -1, 1, -1], [1, 0, -1, 0]
        changed_by_keyswitch = False
        for m in (0, 1, 8, 9, 16):
            initial = encrypt_fixture([m, 0, 0, 0], dense, q, p, [3, -2, 1, 0])
            v = p * 3 + (q % p) * (p // 2)  # public sampler/message-support bound
            self.assertLessEqual(max(map(abs, phase_error(initial, m, dense, q, p))), v)
            lowered = [reduce_poly([(qs * x + q // 2) // q for x in c], qs) for c in initial]
            switched = [list(lowered[0]), [0] * n]
            switch_bound = 0
            for lane in lanes:
                idempotent = (qs // lane) * pow(qs // lane, -1, lane)
                place = 1
                while place < lane:
                    # Per-lane digits, no global coefficient reconstruction.
                    digit = [(x % lane // place) % base for x in lowered[1]]
                    # b_j+a_j*s_sparse=idempotent*place*s_dense+e_j.
                    error = [1, -1, 1, -1]
                    a = [centered((j + 2) * place * 37, qs) for j in range(n)]
                    product = negacyclic_mul(a, sparse)
                    key = [reduce_poly([idempotent * place * s + e - x
                                        for s, e, x in zip(dense, error, product)], qs), a]
                    for k in range(2):
                        switched[k] = reduce_poly([x + y for x, y in zip(
                            switched[k], negacyclic_mul(digit, key[k]))], qs)
                    switch_bound += sum(digit)  # eta=1 and nonnegative public digits
                    place *= base
            self.assertLessEqual(switch_bound, rns_keyswitch_phase_bound(lanes, n, 1, 4))
            actual_switch = reduce_poly([x - y for x, y in zip(
                phase(switched, sparse), phase(lowered, dense))], qs)
            changed_by_keyswitch |= any(actual_switch)
            self.assertLessEqual(max(map(abs, actual_switch)), switch_bound)
            bounds = sparse_route_radius(q, qs, p, 4, 2, v, switch_bound)
            self.assertLessEqual(max(map(abs, phase_error(switched, m, sparse, qs, p))),
                                 bounds["post_keyswitch_scaled_error"])
            self.assertEqual(bounds["plaintext_residual_radius"], 1)
            reference_residual = None
            for outer in itertools.product((-1, 1), repeat=n):
                encaps = encrypt_fixture(sparse, outer, qo, p * p, [1, 0, -1, 1])
                result, a0, a1 = public_expansion(switched, encaps, qs, qo, p)
                w = [x + y for x, y in zip(a0, negacyclic_mul(a1, sparse))]
                residual = reduce_poly([x - (p * centered(m, p) if j == 0 else 0)
                                        for j, x in enumerate(w)], p * p)
                self.assertLessEqual(max(map(abs, residual)), 1)
                if reference_residual is None:
                    reference_residual = residual
                self.assertEqual(residual, reference_residual)
                outer_bound = outer_expansion_scaled_error_bound(qo, p * p, a0, a1, 2, 1)
                actual_outer = reduce_poly([p * p * x - qo * centered(y, p * p)
                                            for x, y in zip(phase(result, outer), w)], p * p * qo)
                self.assertLessEqual(max(map(abs, actual_outer)), outer_bound)
                self.assertLess(2 * outer_bound, qo)
                self.assertEqual(decode(result, outer, qo, p * p), [x % (p * p) for x in w])
        self.assertTrue(changed_by_keyswitch)

    def test_outer_noise_can_fail_without_changing_inner_residual(self):
        p, qo, inner, outer = 17, 1000003, [1, 0], [-1, 1]
        for beta, should_decode in ((1, True), (qo // (p * p), False)):
            encaps = encrypt_fixture(inner, outer, qo, p * p, [beta, 0])
            w = [1, 0]  # a0=0, a1=1; unchanged inner residual rho=1
            bound = outer_expansion_scaled_error_bound(qo, p * p, [0, 0], [1, 0], 1, beta)
            self.assertEqual(2 * bound < qo, should_decode)
            self.assertEqual(decode(encaps, outer, qo, p * p) == w, should_decode)

    def test_switch_error_and_invalid_support_cannot_be_omitted(self):
        good = sparse_route_radius(1000000007, 1000003, 17, 4, 2, 100, 0)
        bad = sparse_route_radius(1000000007, 1000003, 17, 4, 2, 100, 5000)
        self.assertEqual(good["plaintext_residual_radius"], 1)
        self.assertGreater(bad["plaintext_residual_radius"], 1)
        for args in ((1000000007, 1000003, 17, 4, 2, 100, -1),
                     (1000000007, 1000003, 17, 4, 2, 100, 1000003),
                     (1000000007, 1000004, 17, 4, 2, 100, 0),
                     (1000000007, 1000003, 17, 4, -1, 100, 0)):
            with self.assertRaises(ValueError):
                sparse_route_radius(*args)
        with self.assertRaises(ValueError):
            outer_expansion_scaled_error_bound(1009, 17, [0], [9], 1, 1)
        for lanes in ((9, 15), (17, 17), (4, 7), ()):
            with self.assertRaises(ValueError):
                rns_keyswitch_phase_bound(lanes, 4, 1, 4)

    def test_native_lane_gadget_support_and_first_switch_failure(self):
        # These exact native primes/dimensions do NOT attest the hypothetical
        # sparse key, post-transform history, or encrypted extraction circuit.
        q, lanes, p, n = 348959453350711275087786864768188417, (998244353, 985661441), 65537, 8192
        qs = lanes[0] * lanes[1]
        for bits, expected in ((4, 16), (8, 16), (10, 17), (12, 19), (14, 27), (16, 44)):
            k = rns_keyswitch_phase_bound(lanes, n, 3, bits)
            for v in (5011390467, 22046046060462580170753):
                self.assertEqual(sparse_route_radius(q, qs, p, n, 32, v, k)
                                 ["plaintext_residual_radius"], expected)
            self.assertGreater(sparse_route_radius(q, qs, p, n, 32,
                                                  96984689102983990917283450424483841, k)
                               ["plaintext_residual_radius"], 32)
        # Exact first K where the certificate ceases to support B=17.
        v = 5011390467
        lo, hi = 0, qs // (2 * p) - 1
        while lo < hi:
            mid = (lo + hi) // 2
            value = sparse_route_radius(q, qs, p, n, 32, v, mid)["plaintext_residual_radius"]
            if value > 17:
                hi = mid
            else:
                lo = mid + 1
        self.assertEqual(sparse_route_radius(q, qs, p, n, 32, v, lo - 1)["plaintext_residual_radius"], 17)
        self.assertEqual(sparse_route_radius(q, qs, p, n, 32, v, lo)["plaintext_residual_radius"], 18)
        # Composed floor boundary on SOURCE history, for native 10-bit digits.
        k = rns_keyswitch_phase_bound(lanes, n, 3, 10)
        first_refused_v = 4480644730138606536169473115611
        self.assertEqual(sparse_route_radius(q, qs, p, n, 32, first_refused_v - 1, k)
                         ["plaintext_residual_radius"], 17)
        self.assertEqual(sparse_route_radius(q, qs, p, n, 32, first_refused_v, k)
                         ["plaintext_residual_radius"], 18)

    def test_encrypted_bounded_removal_and_followup_square(self):
        # Scalar projections only, no claim of a full coefficient/slot bootstrap.
        # Deterministic wide toy Q; no security claim, no relinearization.
        for p, b, q, messages in ((17, 1, (1 << 256) - 189, range(17)),
                                  (65537, 17, (1 << 1024) - 109, (0, 32768, 65536))):
            f = construct(p, b)
            certify(f, p, b)  # all upper digits, not just the encrypted fixtures
            secret = [-1, 1]
            for r, m in itertools.product((-b, 0, b), messages):
                w = p * m + r
                ct = encrypt_fixture([w, 0], secret, q, p * p, [1, -1])
                removed = public_polynomial(ct, f, q, p * p)
                self.assertEqual(decode(removed, secret, q, p * p), [r % (p * p), 0])
                corrected = public_subtract(ct, removed, q)
                # Reinterpret Enc_{p^2}(p*m) as Enc_p(m); do not invert p modulo p^2.
                self.assertEqual(decode(corrected, secret, q, p), [m, 0])
                after = max(map(abs, phase_error(corrected, m, secret, q, p)))
                self.assertLess(2 * after, q)
                if r != 0:
                    before = max(map(abs, phase_error(ct, m, secret, q, p)))
                    self.assertLess(after, before)  # actual phase improvement, not metadata reset
                squared = public_tensor_multiply(corrected, corrected, q, p)
                self.assertEqual(decode(squared, secret, q, p), [m * m % p, 0])
            # Outside support, successful extraction is not promised.
            self.assertTrue(any(evaluate(f, p * m + b + 1, p * p) != (b + 1)
                                for m in messages))


if __name__ == "__main__":
    unittest.main()
