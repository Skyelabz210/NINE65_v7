"""Exact-integer oracle for the unrestricted digit/StarLift proof.

Read-only proof regression; no production coordinate or CRT reconstruction.
The native producer's narrower signed support is checked in the refinement.
"""

import json


P = 65537
B = 49
SHELL = 36
ANCHORS = (37, 73)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def verify_digit_identity() -> int:
    modulus = P * P
    quotient_lifts = (-P, -1, 0, 1, 1331, 1332, P - 1, P, P + 1)
    checks = 0
    for r in range(-B, B + 1):
        derivative = 1
        for j in range(-B, B + 1):
            if j != r:
                derivative = derivative * (r - j) % P
        require(derivative != 0, f"repeated support root at {r}")
        inverse = pow(derivative, -1, P)
        for k in quotient_lifts:
            x = (r + P * k) % modulus
            g_x = 1
            for j in range(-B, B + 1):
                g_x = g_x * (x - j) % modulus
            require(g_x % P == 0, f"G(x) not divisible by p at {(r, k)}")
            require((g_x // P) * inverse % P == k % P,
                    f"extracted digit differs at {(r, k)}")
            checks += 1
    for r in (-B, 0, B):
        require(r % modulus == (r + P * P) % modulus,
                f"unbounded quotient collision missing at {r}")
    require((P % SHELL, P % ANCHORS[0], P % ANCHORS[1]) ==
            (17, 10, 56), "integer quotient residues unexpectedly agree")
    return checks


def verify_starlift_capacity() -> int:
    require(SHELL * ANCHORS[0] == 1332, "36/37 period changed")
    require(SHELL * ANCHORS[0] * ANCHORS[1] == 97236,
            "three-lane period changed")
    require(0 % SHELL == 1332 % SHELL and
            0 % ANCHORS[0] == 1332 % ANCHORS[0],
            "36/37 collision missing")
    require(1332 % ANCHORS[1] != 0, "second anchor did not separate collision")

    seen = set()
    pair_views = set()
    for k in range(P):
        g, a37, a73 = k % SHELL, k % ANCHORS[0], k % ANCHORS[1]
        pair_views.add((g, a37))
        view = (g, a37, a73)
        require(view not in seen, f"three-lane collision at {k}")
        seen.add(view)

        q = k // SHELL  # Oracle only: checks the derived anchor congruences.
        require((g - a37) % 37 == q % 37,
                f"37-anchor winding mismatch at {k}")
        require(2 * (g - a73) % 73 == q % 73,
                f"73-anchor winding mismatch at {k}")
        require(q <= 1820 < 37 * 73, f"winding capacity failed at {k}")

    require(len(seen) == P, "canonical interval not exhausted")
    require(len(pair_views) == 1332, "36/37 pair capacity changed")
    residual_views = {(y % SHELL, y % ANCHORS[0]) for y in range(2 * B + 1)}
    require(len(residual_views) == 2 * B + 1,
            "residual pair lost injectivity")
    return len(seen)


def main() -> None:
    print(json.dumps({
        "scope": "unrestricted_digit_primitive",
        "polynomial_point_checks": verify_digit_identity(),
        "canonical_k_values_checked": verify_starlift_capacity(),
        "pair_period": 1332,
        "three_lane_period": 97236,
        "unbounded_epoch_recovery": False,
        "production_admission": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
