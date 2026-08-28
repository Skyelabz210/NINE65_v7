//! CRAM Chimera Tritray — composite coprime carriers for prime selection.
//!
//! In CRAM the architectural primitive is *not* the individual prime: it is
//! the **coprime composite chimera** that bundles several prime lanes into a
//! single CRT carrier. A chimera `M = p_1 * p_2 * ... * p_k` (with distinct
//! prime factors) preserves the CRT bijection between Z/MZ and the product of
//! its per-prime residue rings,
//! and therefore acts as one actionable lane that simultaneously witnesses
//! every architectural role of its prime factors. This module provides:
//!
//! 1. A typed catalogue of S8 prime roles (parity, ternary, surface, bridge,
//!    shadow, boundary, saturation, signature) with per-prime metadata.
//! 2. A curated tray (the "tritray") of composite chimeras built from S8,
//!    each tagged with the architectural roles its factors cover.
//! 3. An auxiliary-prime pool {23, 29, 31, 37, 41, 43, 47} for fused
//!    piggyback division and base extension.
//! 4. Selection helpers (`select_chimera_by_role`, `select_aux_for_fpd`)
//!    plus projection of a [`TriadTranscendental`] onto any chimera.
//!
//! The thorough prime-family analysis requested at construction time is
//! encoded in the [`PrimeFamily`] table and validated by the test suite
//! (pairwise coprimality, role coverage, totient bounds, lane-product
//! invariants).

use crate::triad::TriadTranscendental;
use crate::Vec;

// ─── Architectural Roles ──────────────────────────────────────────────────

/// One of the eight architectural roles assigned to S8 primes. Every chimera
/// carries the union of its factors' roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LaneRole {
    /// p=2: parity / integrity / carry witness.
    Parity,
    /// p=3: ternary structure / inverse control.
    Ternary,
    /// p=5: surface / Ramanujan / K-Elim main candidate.
    Surface,
    /// p=7: bridge / K-Elim anchor / quartic-residue oracle.
    Bridge,
    /// p=11: shadow disambiguator / SD-11 / Hensel lift.
    Shadow,
    /// p=13: boundary / spectral extender / first cusp obstruction.
    Boundary,
    /// p=17: saturation / priority / post-boundary lift.
    Saturation,
    /// p=19: spectral complement / signature lane.
    Signature,
}

impl LaneRole {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Parity => "parity",
            Self::Ternary => "ternary",
            Self::Surface => "surface",
            Self::Bridge => "bridge",
            Self::Shadow => "shadow",
            Self::Boundary => "boundary",
            Self::Saturation => "saturation",
            Self::Signature => "signature",
        }
    }
}

// ─── Prime Family Metadata ────────────────────────────────────────────────

/// Membership of a prime in the named CRAM prime families.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FamilyMembership {
    /// Ramanujan partition-congruence prime (5, 7, or 11).
    pub ramanujan: bool,
    /// Quadratic-residue surface prime (5).
    pub qr_surface: bool,
    /// Boundary cusp-form obstruction (13).
    pub cusp_obstruction: bool,
    /// Member of the (17, 19) saturation/turbulence pair.
    pub saturation_pair: bool,
}

/// Per-prime architectural metadata.
#[derive(Debug, Clone, Copy)]
pub struct PrimeFamily {
    pub p: u32,
    pub role: LaneRole,
    pub family: FamilyMembership,
    /// Short human-readable description of the lane's primary use.
    pub description: &'static str,
}

/// The eight S8 primes, each with role and family membership populated.
///
/// This table is the canonical thorough prime-family analysis for the
/// CRAM substrate. Tests below confirm pairwise coprimality, role
/// uniqueness, and Ramanujan-set closure (5, 7, 11 only).
pub const S8_FAMILIES: [PrimeFamily; 8] = [
    PrimeFamily {
        p: 2,
        role: LaneRole::Parity,
        family: FamilyMembership {
            ramanujan: false,
            qr_surface: false,
            cusp_obstruction: false,
            saturation_pair: false,
        },
        description: "parity / integrity / carry witness",
    },
    PrimeFamily {
        p: 3,
        role: LaneRole::Ternary,
        family: FamilyMembership {
            ramanujan: false,
            qr_surface: false,
            cusp_obstruction: false,
            saturation_pair: false,
        },
        description: "ternary structure / modular inverse control",
    },
    PrimeFamily {
        p: 5,
        role: LaneRole::Surface,
        family: FamilyMembership {
            ramanujan: true,
            qr_surface: true,
            cusp_obstruction: false,
            saturation_pair: false,
        },
        description: "surface / Ramanujan / K-Elim main candidate",
    },
    PrimeFamily {
        p: 7,
        role: LaneRole::Bridge,
        family: FamilyMembership {
            ramanujan: true,
            qr_surface: false,
            cusp_obstruction: false,
            saturation_pair: false,
        },
        description: "bridge / K-Elim anchor / quartic-residue oracle",
    },
    PrimeFamily {
        p: 11,
        role: LaneRole::Shadow,
        family: FamilyMembership {
            ramanujan: true,
            qr_surface: false,
            cusp_obstruction: false,
            saturation_pair: false,
        },
        description: "shadow disambiguator / SD-11 / Hensel lift",
    },
    PrimeFamily {
        p: 13,
        role: LaneRole::Boundary,
        family: FamilyMembership {
            ramanujan: false,
            qr_surface: false,
            cusp_obstruction: true,
            saturation_pair: false,
        },
        description: "boundary / spectral extender / first cusp obstruction",
    },
    PrimeFamily {
        p: 17,
        role: LaneRole::Saturation,
        family: FamilyMembership {
            ramanujan: false,
            qr_surface: false,
            cusp_obstruction: false,
            saturation_pair: true,
        },
        description: "saturation / priority / post-boundary lift",
    },
    PrimeFamily {
        p: 19,
        role: LaneRole::Signature,
        family: FamilyMembership {
            ramanujan: false,
            qr_surface: false,
            cusp_obstruction: false,
            saturation_pair: true,
        },
        description: "spectral complement / signature lane",
    },
];

/// Look up the family entry for a prime in S8.
pub fn family_for(prime: u32) -> Option<&'static PrimeFamily> {
    S8_FAMILIES.iter().find(|f| f.p == prime)
}

/// The Ramanujan partition-congruence primes — exactly {5, 7, 11}.
pub const RAMANUJAN_PRIMES: [u32; 3] = [5, 7, 11];

/// Auxiliary FPD pool: small primes coprime to S8, used for fused piggyback
/// division and ephemeral base extension.
pub const AUX_FPD_POOL: [u32; 7] = [23, 29, 31, 37, 41, 43, 47];

// ─── Chimera ──────────────────────────────────────────────────────────────

/// A coprime composite carrier with named architectural roles.
#[derive(Debug, Clone)]
pub struct Chimera {
    /// Short identifier (e.g., `"shadow_bridge"`).
    pub name: &'static str,
    /// Distinct prime factors.
    pub factors: &'static [u32],
    /// Product of `factors`.
    pub product: u64,
    /// Roles covered by the union of factors' roles.
    pub roles: &'static [LaneRole],
    /// Free-text use case.
    pub description: &'static str,
}

impl Chimera {
    /// Compute residue of an exact integer modulo this chimera's composite.
    pub fn project(&self, exact: i128) -> u64 {
        exact.rem_euclid(self.product as i128) as u64
    }

    /// Number of units in (ℤ/Mℤ)ˣ — Euler's totient.
    pub fn totient(&self) -> u64 {
        let mut t = 1u64;
        for &p in self.factors {
            t *= (p - 1) as u64;
        }
        t
    }

    /// True iff this chimera covers the given role.
    pub fn covers(&self, role: LaneRole) -> bool {
        self.roles.contains(&role)
    }
}

// ─── The Tritray ──────────────────────────────────────────────────────────

/// Curated tray of composite-coprime chimeras built from S8.
///
/// The tritray is intentionally small. Each entry pairs adjacent or
/// architecturally complementary primes into a single CRT lane that
/// captures the joint behaviour of two roles.
pub const TRITRAY: &[Chimera] = &[
    Chimera {
        name: "shadow_bridge",
        factors: &[7, 11],
        product: 77,
        roles: &[LaneRole::Bridge, LaneRole::Shadow],
        description: "bridge-shadow coherence (Ramanujan twin pair)",
    },
    Chimera {
        name: "shadow_signature",
        factors: &[11, 19],
        product: 209,
        roles: &[LaneRole::Shadow, LaneRole::Signature],
        description: "shadow-signature coherence",
    },
    Chimera {
        name: "boundary_saturation",
        factors: &[13, 17],
        product: 221,
        roles: &[LaneRole::Boundary, LaneRole::Saturation],
        description: "boundary to post-boundary lift",
    },
    Chimera {
        name: "spectral_saturation",
        factors: &[17, 19],
        product: 323,
        roles: &[LaneRole::Saturation, LaneRole::Signature],
        description: "spectral saturation / turbulence pair",
    },
    Chimera {
        name: "ramanujan_triple",
        factors: &[5, 7, 11],
        product: 385,
        roles: &[LaneRole::Surface, LaneRole::Bridge, LaneRole::Shadow],
        description: "complete Ramanujan partition-congruence basis",
    },
    Chimera {
        name: "post_boundary_band",
        factors: &[13, 17, 19],
        product: 4199,
        roles: &[LaneRole::Boundary, LaneRole::Saturation, LaneRole::Signature],
        description: "post-boundary spectral band",
    },
    Chimera {
        name: "s6_colony",
        factors: &[2, 3, 5, 7, 11, 13],
        product: 30_030,
        roles: &[
            LaneRole::Parity,
            LaneRole::Ternary,
            LaneRole::Surface,
            LaneRole::Bridge,
            LaneRole::Shadow,
            LaneRole::Boundary,
        ],
        description: "S6 Colony — classical 6-prime safe basis",
    },
    Chimera {
        name: "s8_colony",
        factors: &[2, 3, 5, 7, 11, 13, 17, 19],
        product: 9_699_690,
        roles: &[
            LaneRole::Parity,
            LaneRole::Ternary,
            LaneRole::Surface,
            LaneRole::Bridge,
            LaneRole::Shadow,
            LaneRole::Boundary,
            LaneRole::Saturation,
            LaneRole::Signature,
        ],
        description: "S8 Colony — full eight-prime witness basis",
    },
];

/// Look up a chimera by name.
pub fn chimera_by_name(name: &str) -> Option<&'static Chimera> {
    TRITRAY.iter().find(|c| c.name == name)
}

/// Return every chimera in the tritray that covers the given role.
pub fn chimeras_covering(role: LaneRole) -> Vec<&'static Chimera> {
    TRITRAY.iter().filter(|c| c.covers(role)).collect()
}

/// Pick the smallest chimera that covers the requested role pair.
pub fn select_chimera_for_role_pair(a: LaneRole, b: LaneRole) -> Option<&'static Chimera> {
    TRITRAY
        .iter()
        .filter(|c| c.covers(a) && c.covers(b))
        .min_by_key(|c| c.product)
}

// ─── Auxiliary Prime Selection (FPD) ──────────────────────────────────────

fn gcd_u64(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

/// Select the smallest auxiliary prime from [`AUX_FPD_POOL`] that is coprime
/// to both the divisor and the active basis product. Returns `None` if no
/// member of the pool qualifies.
pub fn select_aux_for_fpd(divisor: u64, active_product: u64) -> Option<u32> {
    AUX_FPD_POOL
        .iter()
        .copied()
        .find(|&p| gcd_u64(p as u64, divisor) == 1 && gcd_u64(p as u64, active_product) == 1)
}

// ─── TriadTranscendental Projection ───────────────────────────────────────

/// Project a triad onto a chimera, returning the residue of its exact value
/// modulo the chimera's composite product.
pub fn project_triad_onto_chimera(t: &TriadTranscendental, c: &Chimera) -> u64 {
    c.project(t.exact)
}

// ─── Shadow anchor family ─────────────────────────────────────────────────

/// The shadow lane lifted to its Hensel power, `11^6`.
///
/// The bare prime 11 disambiguates over only ~3.46 bits, which is far too
/// narrow to separate states whose winding differs at working magnitudes. The
/// lift is what gives the shadow lane the range to be an anchor rather than a
/// parity-sized hint.
pub const SHADOW_LIFT_11_6: u64 = 1_771_561;

/// The shadow anchor set, `{11^6, 13, 17, 19}`.
///
/// This is the S8 tail — Shadow, Boundary, Saturation, Signature — with the
/// shadow lane Hensel-lifted. It is the family against which a winding is
/// recovered, and it is what phase-locks the shallow residues to the deep
/// winding: the shallow track carries `r = x mod M`, this family carries
/// `r_s = x mod A`, and [`shadow_winding`] closes between them in O(1).
pub const SHADOW_ANCHOR_SET: [u64; 4] = [SHADOW_LIFT_11_6, 13, 17, 19];

/// Product of [`SHADOW_ANCHOR_SET`] — the winding resolution it provides.
///
/// `11^6 * 13 * 17 * 19 = 7,438,784,639`, i.e. ~32.79 bits. A winding is
/// recovered exactly while `K < A`; past that it aliases, and the caller needs
/// a wider family or an explicit tower.
pub const SHADOW_ANCHOR_PRODUCT: u64 = 7_438_784_639;

/// Recover the winding `K` of `x = r + K * M` from its shadow-anchor residue.
///
/// `r` is the shallow residue `x mod M`, `r_s` is `x mod A` against
/// [`SHADOW_ANCHOR_PRODUCT`], and `m_mod_a` is `M mod A`. From
/// `x = r + K*M` reduced mod `A`:
///
/// ```text
///     K * M  ==  r_s - r   (mod A)
///     K      == (r_s - r) * M^-1  (mod A)
/// ```
///
/// One modular subtraction and one modular multiplication against a
/// precomputed inverse — O(1), no mixed-radix cascade, so it is legal in the
/// hot path where a Garner reconstruction is not.
///
/// Returns `None` when `M` is not invertible mod `A`, i.e. when `M` shares a
/// factor with `11^6 * 13 * 17 * 19`. Callers holding a basis built from lanes
/// disjoint from `{11, 13, 17, 19}` never see that case, but it is reported
/// rather than assumed, because a silently wrong winding is exactly the
/// failure this family exists to prevent.
///
/// The result is exact only for `K < A`. This function cannot check that — `K`
/// is what it is computing — so the caller owns that bound.
pub fn shadow_winding(r: u64, r_s: u64, m_mod_a: u64) -> Option<u64> {
    let a = SHADOW_ANCHOR_PRODUCT as u128;
    let inv = crate::composite_division::modinv_u128(m_mod_a as u128 % a, a);
    // modinv_u128 yields 0 when no inverse exists; a genuine inverse is never 0.
    if inv == 0 || (m_mod_a as u128 % a) * inv % a != 1 {
        return None;
    }
    let diff = (r_s as u128 + a - (r as u128 % a)) % a;
    Some((diff * inv % a) as u64)
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::triad::{pi_table, EngineTag, TriadTranscendental, S8};

    /// The shadow anchor family must be exactly what CRAM section 13 specifies:
    /// {11^6, 13, 17, 19}, product 7,438,784,639. Pinned as a number, because
    /// the whole point of the family is its winding resolution.
    #[test]
    fn shadow_anchor_family_matches_the_specification() {
        assert_eq!(SHADOW_LIFT_11_6, 11u64.pow(6));
        assert_eq!(SHADOW_ANCHOR_SET, [11u64.pow(6), 13, 17, 19]);

        let product: u64 = SHADOW_ANCHOR_SET.iter().product();
        assert_eq!(product, SHADOW_ANCHOR_PRODUCT);
        assert_eq!(product, 7_438_784_639);

        // ~32.79 bits of winding resolution; the bare prime 11 would give 3.46.
        assert_eq!(64 - product.leading_zeros(), 33);
        assert!(SHADOW_ANCHOR_PRODUCT / SHADOW_LIFT_11_6 == 13 * 17 * 19);

        // Pairwise coprime, and the lanes are the S8 tail roles.
        for i in 0..SHADOW_ANCHOR_SET.len() {
            for j in (i + 1)..SHADOW_ANCHOR_SET.len() {
                let (mut a, mut b) = (SHADOW_ANCHOR_SET[i], SHADOW_ANCHOR_SET[j]);
                while b != 0 {
                    let t = a % b;
                    a = b;
                    b = t;
                }
                assert_eq!(a, 1, "shadow anchor lanes must be pairwise coprime");
            }
        }
        assert_eq!(family_for(11).map(|f| f.role), Some(LaneRole::Shadow));
        assert_eq!(family_for(13).map(|f| f.role), Some(LaneRole::Boundary));
        assert_eq!(family_for(17).map(|f| f.role), Some(LaneRole::Saturation));
        assert_eq!(family_for(19).map(|f| f.role), Some(LaneRole::Signature));
    }

    /// The phase lock itself: given the shallow residue and the shadow-anchor
    /// residue of the same integer, the winding comes back exactly. This is
    /// the O(1) step that a plain transduction cannot do on its own, and the
    /// reason a transduction needs this family to preserve winding identity.
    #[test]
    fn shadow_anchor_recovers_the_winding_exactly() {
        let a = SHADOW_ANCHOR_PRODUCT as u128;
        // A main product disjoint from {11,13,17,19}: 2^20 * 3^8 * 5^5 * 7^4.
        let m: u128 = 2u128.pow(20) * 3u128.pow(8) * 5u128.pow(5) * 7u128.pow(4);
        let m_mod_a = (m % a) as u64;

        let mut x: u128 = 0x9E3779B97F4A7C15;
        for _ in 0..20_000 {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            // Keep K strictly under A, which is the family's stated range.
            let k = x % (SHADOW_ANCHOR_PRODUCT as u128);
            let r = x % m;
            let value = r + k * m;

            let recovered = shadow_winding((value % m) as u64, (value % a) as u64, m_mod_a)
                .expect("M is coprime to the shadow anchor family");
            assert_eq!(
                recovered as u128, k,
                "winding must be exact for K < A (K={k})"
            );
        }
    }

    /// A modulus sharing a factor with the family has no inverse, and that is
    /// reported rather than silently producing a wrong winding.
    #[test]
    fn shadow_winding_refuses_a_modulus_sharing_a_factor() {
        assert!(shadow_winding(0, 0, 11).is_none());
        assert!(shadow_winding(0, 0, 13 * 4).is_none());
        assert!(shadow_winding(1, 2, 2u64.pow(10) * 3).is_some());
    }


    // ---- Prime-family analysis (thorough) ------------------------------

    #[test]
    fn s8_families_match_basis_order() {
        let basis: [u32; 8] = S8_FAMILIES.map(|f| f.p);
        assert_eq!(basis, S8);
    }

    #[test]
    fn every_role_appears_exactly_once() {
        let mut roles: Vec<LaneRole> = S8_FAMILIES.iter().map(|f| f.role).collect();
        let n = roles.len();
        roles.sort_by_key(|r| r.name());
        roles.dedup();
        assert_eq!(roles.len(), n, "roles must be unique across S8");
    }

    #[test]
    fn ramanujan_membership_is_exactly_5_7_11() {
        let r: Vec<u32> = S8_FAMILIES
            .iter()
            .filter(|f| f.family.ramanujan)
            .map(|f| f.p)
            .collect();
        assert_eq!(r, vec![5, 7, 11]);
        assert_eq!(r, RAMANUJAN_PRIMES.to_vec());
    }

    #[test]
    fn cusp_obstruction_is_only_13() {
        let c: Vec<u32> = S8_FAMILIES
            .iter()
            .filter(|f| f.family.cusp_obstruction)
            .map(|f| f.p)
            .collect();
        assert_eq!(c, vec![13]);
    }

    #[test]
    fn saturation_pair_is_17_and_19() {
        let s: Vec<u32> = S8_FAMILIES
            .iter()
            .filter(|f| f.family.saturation_pair)
            .map(|f| f.p)
            .collect();
        assert_eq!(s, vec![17, 19]);
    }

    #[test]
    fn family_lookup_works_for_all_s8_primes() {
        for &p in &S8 {
            assert!(family_for(p).is_some(), "missing family for {p}");
        }
        assert!(family_for(23).is_none(), "23 is auxiliary, not S8");
    }

    // ---- Aux pool ------------------------------------------------------

    #[test]
    fn aux_pool_is_disjoint_from_s8() {
        for &a in &AUX_FPD_POOL {
            assert!(!S8.contains(&a), "aux prime {a} collides with S8");
        }
    }

    #[test]
    fn aux_selection_avoids_divisor_and_active_basis() {
        // Divide by 6, basis = 2·3·5·7 = 210. The first aux prime coprime
        // to both is 11 (in S8) ... but 11 is not in the aux pool, so the
        // function returns the smallest aux pool member coprime to both.
        let chosen = select_aux_for_fpd(6, 210).unwrap();
        assert!(AUX_FPD_POOL.contains(&chosen));
        assert_eq!(gcd_u64(chosen as u64, 6), 1);
        assert_eq!(gcd_u64(chosen as u64, 210), 1);
    }

    #[test]
    fn aux_selection_returns_none_when_pool_blocked() {
        // active_product = 23·29·31·37·41·43·47 wipes the pool.
        let blocking: u64 = AUX_FPD_POOL.iter().map(|&p| p as u64).product();
        assert!(select_aux_for_fpd(1, blocking).is_none());
    }

    // ---- Chimera tritray ------------------------------------------------

    #[test]
    fn every_chimera_product_matches_factor_product() {
        for c in TRITRAY {
            let p: u64 = c.factors.iter().map(|&p| p as u64).product();
            assert_eq!(c.product, p, "{}: declared product wrong", c.name);
        }
    }

    #[test]
    fn every_chimera_factor_set_is_pairwise_coprime() {
        for c in TRITRAY {
            for i in 0..c.factors.len() {
                for j in (i + 1)..c.factors.len() {
                    assert_eq!(
                        gcd_u64(c.factors[i] as u64, c.factors[j] as u64),
                        1,
                        "{}: factors not coprime",
                        c.name
                    );
                }
            }
        }
    }

    #[test]
    fn every_chimera_factor_lives_in_s8() {
        for c in TRITRAY {
            for &f in c.factors {
                assert!(S8.contains(&f), "{}: factor {} not in S8", c.name, f);
            }
        }
    }

    #[test]
    fn every_chimera_role_set_matches_factor_roles() {
        for c in TRITRAY {
            let mut expected: Vec<LaneRole> = c
                .factors
                .iter()
                .map(|p| family_for(*p).unwrap().role)
                .collect();
            let mut declared: Vec<LaneRole> = c.roles.to_vec();
            expected.sort_by_key(|r| r.name());
            declared.sort_by_key(|r| r.name());
            assert_eq!(expected, declared, "{}: role set mismatch", c.name);
        }
    }

    #[test]
    fn s8_colony_product_matches_constant() {
        let s8c = chimera_by_name("s8_colony").unwrap();
        assert_eq!(s8c.product, crate::triad::S8_PRODUCT as u64);
    }

    #[test]
    fn s6_colony_totient_is_5760() {
        let c = chimera_by_name("s6_colony").unwrap();
        // φ(30030) = 1·2·4·6·10·12 = 5760.
        assert_eq!(c.totient(), 5_760);
    }

    #[test]
    fn s8_colony_totient_is_1658880() {
        let c = chimera_by_name("s8_colony").unwrap();
        // φ(9_699_690) = 1·2·4·6·10·12·16·18 = 1_658_880.
        assert_eq!(c.totient(), 1_658_880);
    }

    #[test]
    fn role_pair_selection_picks_smallest_match() {
        let c = select_chimera_for_role_pair(LaneRole::Bridge, LaneRole::Shadow).unwrap();
        assert_eq!(c.name, "shadow_bridge");
        assert_eq!(c.product, 77);
    }

    #[test]
    fn role_pair_selection_handles_unique_role_pair() {
        let c = select_chimera_for_role_pair(LaneRole::Saturation, LaneRole::Signature).unwrap();
        assert_eq!(c.name, "spectral_saturation");
        assert_eq!(c.product, 323);
    }

    #[test]
    fn chimeras_covering_shadow_includes_three_entries() {
        let hits: Vec<&str> = chimeras_covering(LaneRole::Shadow)
            .into_iter()
            .map(|c| c.name)
            .collect();
        for name in &["shadow_bridge", "shadow_signature", "ramanujan_triple"] {
            assert!(hits.contains(name), "missing {} in shadow coverage", name);
        }
    }

    // ---- Triad ⇄ Chimera projection ------------------------------------

    #[test]
    fn pi_projects_consistently_onto_each_chimera() {
        let pi = pi_table(0);
        for c in TRITRAY {
            let r = project_triad_onto_chimera(&pi, c);
            // CRT consistency: the projection mod M must agree with each
            // factor's individual S8 residue.
            for &p in c.factors {
                let expected = pi.residue_mod(p).unwrap() as u64;
                assert_eq!(
                    r % p as u64,
                    expected,
                    "{}: chimera proj inconsistent on factor {}",
                    c.name,
                    p
                );
            }
        }
    }

    #[test]
    fn projection_is_pure_function_of_exact_value() {
        let a = TriadTranscendental::from_exact(123_456_789, 30, EngineTag::PrecomputedTable);
        let b = TriadTranscendental::from_exact(123_456_789, 30, EngineTag::Cordic);
        for c in TRITRAY {
            assert_eq!(
                project_triad_onto_chimera(&a, c),
                project_triad_onto_chimera(&b, c)
            );
        }
    }
}
