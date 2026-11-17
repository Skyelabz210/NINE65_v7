"""Independent finite checks for the expanded framework review.

Inputs are generated independently; this does not execute NINE65 or constitute
a cryptographic, Lean, asymptotic-complexity, or continuum validation.
"""
from collections import Counter
from fractions import Fraction
from itertools import product
from math import gcd, lcm, prod
import json

out = {"scope": "finite mathematical models and literal document counterexamples", "counts": {}, "counterexamples": {}}

# Set-level universal query criterion. Compare a brute-force search for all
# possible decoders with the fiber criterion, including noninjective views.
n_factor = 0
for n in range(6):
    for observation in product(range(2), repeat=n):
        for query in product(range(2), repeat=n):
            decoder_exists = any(all(decoder[observation[i]] == query[i] for i in range(n))
                                 for decoder in product(range(2), repeat=2))
            fiber_constant = all(observation[i] != observation[j] or query[i] == query[j]
                                 for i in range(n) for j in range(n))
            assert decoder_exists == fiber_constant
            n_factor += 1
out["counts"]["query_factorization_domains_0_through_5"] = n_factor

# Three authentic paired-residue frames. A winding is computed only as an
# ephemeral query. Neither transfer nor its state includes scalar X or stored K.
frames = ((5, 11), (7, 13), (8, 11))
def encode(x, frame):
    m, a = frame
    return (x % m, x % a)
def transfer(state, source, target):
    m, a = source
    r, s = state
    k = ((s-r) * pow(m, -1, a)) % a
    if 2*k > a:
        k -= a
    return tuple((r % p + (m % p) * (k % p)) % p for p in target)
n_edges = n_round = n_comp = 0
for x in range(-20, 21):
    for source, target in product(frames, repeat=2):
        state = encode(x, source)
        got = transfer(state, source, target)
        assert got == encode(x, target)
        n_edges += 1
        assert transfer(got, target, source) == state
        n_round += 1
    for a, b, c in product(frames, repeat=3):
        state = encode(x, a)
        assert transfer(transfer(state, a, b), b, c) == transfer(state, a, c)
        n_comp += 1
out["counts"].update(transfer_edges=n_edges, transfer_round_trips=n_round, transfer_compositions=n_comp)
assert encode(-20, frames[0]) == encode(35, frames[0])
assert encode(-20, frames[1]) != encode(35, frames[1])
out["counterexamples"]["transfer_needs_source_domain_certificate"] = {"x": -20, "y": 35, "source": frames[0], "same_observation": encode(-20, frames[0]), "distinct_target_observations": [encode(-20, frames[1]), encode(35, frames[1])]}

# Heterogeneous operators are exact maps in the same CRT product ring.
# On mod 3 use addition, on mod 5 use multiplication; CRT idempotents 10,6
# give a single polynomial representative modulo 15 without scalar decoding.
for x, y in product(range(15), repeat=2):
    f = (10*(x+y) + 6*x*y) % 15
    assert (f % 3, f % 5) == ((x+y) % 3, (x*y) % 5)
out["counts"]["heterogeneous_operator_polynomial_pairs"] = 225
crt_image = {(x % 3, x % 5) for x in range(15)}
assert len(crt_image) == 3*5 == 15
out["counterexamples"]["chimera_value_space_expansion"] = {"product_ring_size": 15, "image_of_Z_mod_15": len(crt_image), "actual_size_ratio": 1, "claimed_M_power_k_minus_1": 15}

# Literal Theorem 9 in white paper 8 reverses the subtraction; theorem 7
# and appendix A in that same document give the correct sign.
n_adj = bad_sign = 0
for p in range(2, 65):
    a = p+1
    for x in range(p*a):
        correct = (x % p - x % a) % a
        published = (x % a - x % p) % a
        assert correct == x//p
        n_adj += 1
        bad_sign += published != x//p
out["counts"].update(adjacency_all_values=n_adj, reversed_sign_disagreements=bad_sign)
out["counterexamples"]["one_wave_sign"] = {"P": 2, "A": 3, "X": 2, "published": 2, "correct": 1}

# White paper 8 Theorem 12: a genuine range restriction is needed for the
# constructed Y, not merely x<Q. Test the corrected guard independently.
n_guard = n_alias = 0
first_alias = None
for t in range(2, 31):
    for delta in range(1, 31):
        qmod = t*delta
        a = qmod+1
        for x in range(qmod):
            y = x*t + delta//2
            got = ((y % a - y % delta)*pow(delta, -1, a)) % a
            expected = y//delta
            assert got == expected % a
            if y < delta*a:
                assert got == expected
                n_guard += 1
            elif got != expected:
                n_alias += 1
                if first_alias is None and delta > 1:
                    first_alias = dict(t=t, delta=delta, Q=qmod, A=a, x=x, Y=y, published_K=got, actual_K=expected)
out["counts"].update(rescale_correct_guard_cases=n_guard, missing_guard_aliases=n_alias)
out["counterexamples"]["unified_rescale_missing_range"] = first_alias

# Initial data error is transported/amplified even when the arithmetic is exact.
truth, stored = Fraction(11, 10), Fraction(1)
epsilon = abs(truth-stored)
assert abs(10*truth - 10*stored) == 10*epsilon > epsilon
out["counterexamples"]["frozen_total_error"] = {"truth": str(truth), "stored": str(stored), "initial_error": str(epsilon), "after_exact_times_10_error": str(abs(10*truth-10*stored))}
assert all(13 % p for p in (2,3,5,7,11))
out["counterexamples"]["all_natural_denominators_11_smooth"] = {"exact_rational": "1/13", "grid_spacing": "1/13", "prime_factor_outside_basis": 13}

# Finite prime-only anchor completions allow torsion: use compatible CRT
# residues of a vector supported at prime 3. This does not occur in Z-hat.
primes = (3,5,7,11,13)
torsion_residues = []
for j in range(1, len(primes)+1):
    ps = primes[:j]
    modulus = prod(ps)
    residue = next(x for x in range(1, modulus) if x % 3 == 1 and all(x % p == 0 for p in ps[1:]))
    assert (3*residue) % modulus == 0
    if torsion_residues:
        assert residue % torsion_residues[-1][0] == torsion_residues[-1][1]
    torsion_residues.append((modulus, residue))
out["counts"]["prime_only_completion_compatible_torsion_prefixes"] = len(torsion_residues)
out["counterexamples"]["prime_only_ladder_not_full_profinite_Z"] = torsion_residues

# Literal degree < 3 does not imply injectivity, volume conservation, or
# invertibility of an update on the residue torus.
assert pow(1,2,3) == pow(2,2,3)
out["counterexamples"]["degree_2_map_not_reversible"] = {"modulus": 3, "map": "x^2", "distinct_inputs": [1,2], "same_output": 1, "output_counts_uniform_inputs": dict(Counter(x*x % 3 for x in range(3)))}

orders = {}
for p in (3,5,7,11,13,17,19):
    orders[p] = next(k for k in range(1,p) if pow(4,k,p) == 1)
assert lcm(*orders.values()) == 180
out["counterexamples"]["safe_S8_refinement_cycle_30"] = {"orders_of_4_odd_S8": orders, "joint_period": 180, "prime_2": "4 is not a unit"}

out["positive_scope_notes"] = [
    "No persistent winding is used by the paired-view transfer model.",
    "The transfer checks concern authenticated views over x in [-20,20].",
    "Heterogeneous operators can be distinct operational semantics while using the same residue value set.",
    "No new arithmetic-roundoff error and no growth of initial-data error are different claims.",
]
print(json.dumps(out, indent=2))
