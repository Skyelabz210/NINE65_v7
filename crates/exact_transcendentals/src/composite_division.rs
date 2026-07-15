//! Composite Division D4/D5 — u128 Lift Corridors
//!
//! Extended-precision exact division using composite modular lanes:
//!   Lane 4 = 2^63 * 7^22 (carries 2-content + wide lift corridor)
//!   Lane 5 = 5^25 (output-passive, derived post-hoc)
//!
//! Joint corridor (NTT lanes + lane 4) ~ 1.4 x 10^47, providing 19 orders
//! of headroom beyond NS step values.
//!
//! Zero floating point. All arithmetic exact integer (A1).

// ============================================================================
// u128 modular arithmetic (self-contained, no external deps)
// ============================================================================

pub fn addmod_u128(a: u128, b: u128, m: u128) -> u128 {
    let s = a + b;
    if s >= m {
        s - m
    } else {
        s
    }
}

pub fn submod_u128(a: u128, b: u128, m: u128) -> u128 {
    if a >= b {
        a - b
    } else {
        a + m - b
    }
}

pub fn mulmod_u128(a: u128, b: u128, m: u128) -> u128 {
    debug_assert!(a < m && b < m, "mulmod_u128: input >= modulus");
    if m < (1u128 << 64) {
        a.wrapping_mul(b) % m
    } else {
        mulmod_u128_wide(a, b, m)
    }
}

fn mulmod_u128_wide(a: u128, b: u128, m: u128) -> u128 {
    let mut result: u128 = 0;
    let mut acc = a % m;
    let mut multiplier = b;
    while multiplier > 0 {
        if multiplier & 1 == 1 {
            result = addmod_u128(result, acc, m);
        }
        acc = addmod_u128(acc, acc, m);
        multiplier >>= 1;
    }
    result
}

pub fn modinv_u128(a: u128, m: u128) -> u128 {
    debug_assert!(m > 0, "modinv_u128: modulus 0");
    let m_i = m as i128;
    let (mut old_r, mut r) = (a as i128, m_i);
    let (mut old_s, mut s) = (1i128, 0i128);
    while r != 0 {
        let q = old_r / r;
        let new_r = old_r - q * r;
        old_r = r;
        r = new_r;
        let new_s = old_s - q * s;
        old_s = s;
        s = new_s;
    }
    assert_eq!(
        old_r, 1,
        "modinv_u128({}, {}): gcd = {} != 1",
        a, m, old_r
    );
    old_s.rem_euclid(m_i) as u128
}

fn gcd_u128(a: u128, b: u128) -> u128 {
    if b == 0 {
        a
    } else {
        gcd_u128(b, a % b)
    }
}

// ============================================================================
// Substrate constants
// ============================================================================

pub const NTT_PRIMES_V5: [u128; 4] = [769, 929, 1153, 1217];

pub const LANE_2POW_V5: u128 = 1u128 << 63;
pub const LANE_7POW_V5: u128 = 3_909_821_048_582_988_049u128; // 7^22
/// Composite lane 4 = 2^63 * 7^22.
pub const LANE_COMPOSITE_V5: u128 = LANE_2POW_V5 * LANE_7POW_V5;

pub const LANE_5POW_V5: u128 = 5u128.pow(25);

pub const EXT_BASIS_V5: [u128; 6] = [
    769,
    929,
    1153,
    1217,
    LANE_COMPOSITE_V5,
    LANE_5POW_V5,
];

pub const M_NTT_V5: u128 = 769u128 * 929u128 * 1153u128 * 1217u128;

const _: () = {
    assert!(LANE_2POW_V5 < (1u128 << 64));
    assert!(LANE_7POW_V5 < (1u128 << 64));
    assert!(LANE_5POW_V5 < (1u128 << 64));
    assert!(LANE_COMPOSITE_V5 < u128::MAX / 2);
};

// ============================================================================
// ExtResV5 — 6-lane residue representation
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtResV5 {
    pub res: [u128; 6],
}

impl ExtResV5 {
    pub fn from_i128(x: i128) -> Self {
        let mut r = [0u128; 6];
        for i in 0..6 {
            let m = EXT_BASIS_V5[i] as i128;
            r[i] = x.rem_euclid(m) as u128;
        }
        ExtResV5 { res: r }
    }

    pub fn zero() -> Self {
        ExtResV5 { res: [0u128; 6] }
    }

    pub fn ntt_part(&self) -> u128 {
        garner4_ntt(&self.res[0..4])
    }

    pub fn mixed_radix_garner(&self) -> [u128; 6] {
        let m = EXT_BASIS_V5;
        let r = &self.res;
        let mut a = [0u128; 6];
        a[0] = r[0] % m[0];
        for k in 1..6 {
            let mk = m[k];
            let mut partial = a[0] % mk;
            let mut prod = m[0] % mk;
            for j in 1..k {
                let term = mulmod_u128(prod, a[j] % mk, mk);
                partial = addmod_u128(partial, term, mk);
                prod = mulmod_u128(prod, m[j] % mk, mk);
            }
            let r_k = r[k] % mk;
            let diff = submod_u128(r_k, partial, mk);
            let prod_inv = modinv_u128(prod, mk);
            a[k] = mulmod_u128(diff, prod_inv, mk);
        }
        a
    }

    pub fn to_i128(&self) -> i128 {
        let a = self.mixed_radix_garner();
        let half = mixed_radix_half_v5();
        let cmp = mixed_radix_cmp_digits(&a, &half);
        let is_negative = cmp >= 0;

        if !is_negative {
            mixed_radix_to_i128_positive(&a)
        } else {
            let m_minus_a = mixed_radix_sub_from_full(&a);
            -mixed_radix_to_i128_positive(&m_minus_a)
        }
    }
}

fn mixed_radix_cmp_digits(a: &[u128; 6], b: &[u128; 6]) -> i32 {
    for k in (0..6).rev() {
        if a[k] > b[k] {
            return 1;
        }
        if a[k] < b[k] {
            return -1;
        }
    }
    0
}

fn mixed_radix_to_i128_positive(a: &[u128; 6]) -> i128 {
    let m = EXT_BASIS_V5;
    let mut x: i128 = 0;
    for k in (0..6).rev() {
        if k == 5 {
            x = a[5] as i128;
        } else {
            let prev = x;
            let mk = m[k] as i128;
            let prod = mk
                .checked_mul(prev)
                .expect("to_i128 v5: Horner overflow");
            x = (a[k] as i128).checked_add(prod).expect("to_i128 v5: add overflow");
        }
    }
    x
}

fn mixed_radix_half_v5() -> [u128; 6] {
    let r = [0u128, 0u128, 0u128, 0u128, LANE_COMPOSITE_V5 / 2, 0u128];
    let er = ExtResV5 { res: r };
    er.mixed_radix_garner()
}

fn mixed_radix_sub_from_full(a: &[u128; 6]) -> [u128; 6] {
    let m = EXT_BASIS_V5;
    let mut residues = [0u128; 6];
    for i in 0..6 {
        let mi = m[i];
        let mut x = a[5] % mi;
        for k in (0..5).rev() {
            x = mulmod_u128(x, m[k] % mi, mi);
            x = addmod_u128(x, a[k] % mi, mi);
        }
        residues[i] = x;
    }
    let mut neg_residues = [0u128; 6];
    for i in 0..6 {
        neg_residues[i] = if residues[i] == 0 {
            0
        } else {
            m[i] - residues[i]
        };
    }
    let er = ExtResV5 { res: neg_residues };
    er.mixed_radix_garner()
}

pub fn garner4_ntt(r: &[u128]) -> u128 {
    let p = NTT_PRIMES_V5;
    let a0 = r[0];
    let a1 = mulmod_u128(
        submod_u128(r[1], a0 % p[1], p[1]),
        modinv_u128(p[0] % p[1], p[1]),
        p[1],
    );
    let p01 = p[0] * p[1];
    let t2 = (a0 + p[0] * a1) % p[2];
    let a2 = mulmod_u128(
        submod_u128(r[2], t2, p[2]),
        modinv_u128(p01 % p[2], p[2]),
        p[2],
    );
    let p012 = p01 * p[2];
    let t3 = (a0 + p[0] * a1 + p01 * a2) % p[3];
    let a3 = mulmod_u128(
        submod_u128(r[3], t3, p[3]),
        modinv_u128(p012 % p[3], p[3]),
        p[3],
    );
    a0 + p[0] * a1 + p01 * a2 + p012 * a3
}

// ============================================================================
// Exact division
// ============================================================================

/// Exact division in v5 substrate. d must have prime factors in {2, 5} only.
pub fn cram_div_exact_pos_v5(x: &ExtResV5, d: u128) -> ExtResV5 {
    debug_assert!(d > 0);
    debug_assert!(d % 7 != 0, "v5: d must not have factor 7");

    let mut d2 = 1u128;
    let mut dd = d;
    while dd % 2 == 0 {
        d2 *= 2;
        dd /= 2;
    }
    let mut d5 = 1u128;
    while dd % 5 == 0 {
        d5 *= 5;
        dd /= 5;
    }
    debug_assert!(dd == 1, "v5: d has factors other than 2, 5");

    let r_mod_d2 = if d2 == 1 {
        0
    } else {
        (x.res[4] % LANE_2POW_V5) % d2
    };
    let r_mod_d5 = if d5 == 1 { 0 } else { x.res[5] % d5 };

    let r = if d5 == 1 {
        r_mod_d2
    } else if d2 == 1 {
        r_mod_d5
    } else {
        let inv_d2_mod_d5 = modinv_u128(d2 % d5, d5);
        let diff = submod_u128(r_mod_d5, r_mod_d2 % d5, d5);
        let k = mulmod_u128(diff, inv_d2_mod_d5, d5);
        r_mod_d2 + d2 * k
    };
    debug_assert!(r < d);

    let mut q_res = [0u128; 6];
    for i in 0..4 {
        let p = EXT_BASIS_V5[i];
        let r_p = x.res[i];
        let r_mod_p = r % p;
        let diff = submod_u128(r_p, r_mod_p, p);
        let d_inv = modinv_u128(d % p, p);
        q_res[i] = mulmod_u128(diff, d_inv, p);
    }

    let (qp4, pm4) = small_lane_partial_v5(x.res[4], r, d, LANE_COMPOSITE_V5);
    q_res[4] = lift_partial_to_full_v5(qp4, pm4, LANE_COMPOSITE_V5, &q_res[0..4]);

    let q_partial_5modulus = garner_5modulus_to_u128(&q_res[0..4], q_res[4]);
    q_res[5] = q_partial_5modulus % LANE_5POW_V5;

    ExtResV5 { res: q_res }
}

fn small_lane_partial_v5(
    x_lane: u128,
    r: u128,
    d: u128,
    lane_mod: u128,
) -> (u128, u128) {
    let xr = submod_u128(x_lane, r % lane_mod, lane_mod);
    let g = gcd_u128(d, lane_mod);
    let lane_g = lane_mod / g;
    let d_g = d / g;
    let xr_over_g = xr / g;
    let d_g_inv = modinv_u128(d_g % lane_g, lane_g);
    let q_partial = mulmod_u128(xr_over_g % lane_g, d_g_inv, lane_g);
    (q_partial, lane_g)
}

fn lift_partial_to_full_v5(
    q_partial: u128,
    partial_mod: u128,
    lane_mod: u128,
    q_ntt_residues: &[u128],
) -> u128 {
    let q_ntt_full = garner4_ntt(q_ntt_residues);
    if partial_mod == lane_mod {
        return q_partial;
    }
    let m_ntt_mod_p = M_NTT_V5 % partial_mod;
    let m_ntt_inv = modinv_u128(m_ntt_mod_p, partial_mod);
    let q_ntt_mod_p = q_ntt_full % partial_mod;
    let s = mulmod_u128(
        submod_u128(q_partial, q_ntt_mod_p, partial_mod),
        m_ntt_inv,
        partial_mod,
    );
    let mns_mod_lane = mulmod_u128(M_NTT_V5 % lane_mod, s % lane_mod, lane_mod);
    addmod_u128(q_ntt_full % lane_mod, mns_mod_lane, lane_mod)
}

fn garner_5modulus_to_u128(ntt_residues: &[u128], lane4_residue: u128) -> u128 {
    let q_ntt = garner4_ntt(ntt_residues);
    let m_ntt_inv = modinv_u128(M_NTT_V5 % LANE_COMPOSITE_V5, LANE_COMPOSITE_V5);
    let diff = submod_u128(lane4_residue, q_ntt % LANE_COMPOSITE_V5, LANE_COMPOSITE_V5);
    let s = mulmod_u128(diff, m_ntt_inv, LANE_COMPOSITE_V5);
    let prod = M_NTT_V5
        .checked_mul(s)
        .expect("garner_5modulus: M_NTT * s overflow u128");
    q_ntt
        .checked_add(prod)
        .expect("garner_5modulus: q_ntt + M_NTT*s overflow u128")
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substrate_constants() {
        assert_eq!(LANE_2POW_V5, 1u128 << 63);
        assert_eq!(LANE_7POW_V5, 7u128.pow(22));
        assert_eq!(LANE_5POW_V5, 5u128.pow(25));
        assert_eq!(LANE_COMPOSITE_V5, LANE_2POW_V5 * LANE_7POW_V5);
        assert!(LANE_COMPOSITE_V5 < u128::MAX / 2);
    }

    #[test]
    fn ntt_part_consistent() {
        let cases = [0i128, 1, 1000, 1_000_000_000_000_000];
        for &x in &cases {
            let er = ExtResV5::from_i128(x);
            let q = er.ntt_part();
            assert_eq!(q, (x as u128) % M_NTT_V5);
        }
    }

    #[test]
    fn to_i128_roundtrip() {
        let cases: &[i128] = &[
            0,
            1,
            -1,
            100,
            -100,
            1_000_000,
            -1_000_000,
            1_000_000_000_000,
            -1_000_000_000_000,
            i64::MAX as i128,
            i64::MIN as i128,
            1i128 << 80,
            -(1i128 << 80),
            1i128 << 100,
            -(1i128 << 100),
            1i128 << 110,
            -(1i128 << 110),
        ];
        for &x in cases {
            let er = ExtResV5::from_i128(x);
            let recon = er.to_i128();
            assert_eq!(recon, x, "v5 to_i128 roundtrip x={}", x);
        }
    }

    #[test]
    fn div_three_divisors() {
        let divisors: [u128; 3] = [1024, 1u128 << 30, 100_000_000];
        let test_xs: &[i128] = &[
            0,
            1,
            1023,
            1024,
            100_000,
            1_000_000_000,
            1_000_000_000_000,
            1i128 << 50,
            1i128 << 80,
            1i128 << 100,
        ];
        for &d in &divisors {
            for &x in test_xs {
                if x >= 0 {
                    let er = ExtResV5::from_i128(x);
                    let q = cram_div_exact_pos_v5(&er, d).to_i128();
                    assert_eq!(q, x / d as i128, "v5 div d={} x={}", d, x);
                }
            }
        }
    }

    #[test]
    fn div_at_v4_failure_magnitudes() {
        let d: u128 = 100_000_000;
        let test_xs: &[i128] = &[
            1_600_000_000_000_000_000_000_000_000,
            1_000_000_000_000_000_000_000_000_000_000,
            5_000_000_000_000_000_000_000_000_000_000,
        ];
        for &x in test_xs {
            let er = ExtResV5::from_i128(x);
            let q = cram_div_exact_pos_v5(&er, d).to_i128();
            assert_eq!(q, x / d as i128, "v5 div S^2 x={}", x);
        }
    }

    #[test]
    fn stress_at_corridor() {
        let mut state = 0xFEEDFACEu64;
        for _ in 0..200 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let scale: u128 = 9_000_000_000_000_000_000_000_000_000_000;
            let r = (state as u128) % scale;
            let x = r as i128;
            for &d in &[1024u128, 1u128 << 30, 100_000_000u128] {
                let er = ExtResV5::from_i128(x);
                let q = cram_div_exact_pos_v5(&er, d).to_i128();
                let canonical = x / d as i128;
                assert_eq!(q, canonical, "v5 stress: x={} d={}", x, d);
            }
        }
    }
}
