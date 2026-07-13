#![allow(clippy::manual_is_multiple_of)]

use cram_core::{
    anchor::recover_winding, ArchitectureCounters, BasisFrame, BoundCertificate, CramState,
    DomainState, FrameId, LaneId, LaneOperator, LineageDigest, OperatorTopology, ResidueLane,
    ShadowState, WindingState,
};

#[derive(Clone, Copy, Debug)]
struct ScaleProfile {
    name: &'static str,
    lane_counts: &'static [usize],
    steps: usize,
    kelim_samples: usize,
}

fn scale_profile() -> ScaleProfile {
    match std::env::var("CRAM_SCALE_PROFILE").as_deref() {
        Ok("medium") => ScaleProfile {
            name: "medium",
            lane_counts: &[8, 16, 32],
            steps: 1_024,
            kelim_samples: 16_384,
        },
        Ok("large") => ScaleProfile {
            name: "large",
            lane_counts: &[32, 64],
            steps: 8_192,
            kelim_samples: 131_072,
        },
        Ok("endurance") => ScaleProfile {
            name: "endurance",
            lane_counts: &[64],
            steps: 65_536,
            kelim_samples: 1_048_576,
        },
        _ => ScaleProfile {
            name: "small",
            lane_counts: &[2, 4, 8],
            steps: 128,
            kelim_samples: 2_048,
        },
    }
}

#[derive(Clone, Copy)]
struct XorShift64(u64);

impl XorShift64 {
    fn new(seed: u64) -> Self {
        assert_ne!(seed, 0);
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }
}

fn is_prime(value: u64) -> bool {
    if value < 2 {
        return false;
    }
    if value == 2 {
        return true;
    }
    if value % 2 == 0 {
        return false;
    }
    let mut divisor = 3_u64;
    while divisor <= value / divisor {
        if value % divisor == 0 {
            return false;
        }
        divisor += 2;
    }
    true
}

fn first_primes(count: usize) -> Vec<u64> {
    let mut primes = Vec::with_capacity(count);
    let mut candidate = 2_u64;
    while primes.len() < count {
        if is_prime(candidate) {
            primes.push(candidate);
        }
        candidate += 1;
    }
    primes
}

fn topology(lane_count: usize) -> OperatorTopology {
    let assignments = (0..lane_count)
        .map(|index| {
            let lane = LaneId(u16::try_from(index).expect("test lane count fits u16"));
            let operator = match index % 7 {
                0 => LaneOperator::Add,
                1 => LaneOperator::Sub,
                2 => LaneOperator::Mul,
                3 => LaneOperator::Sqr,
                4 => LaneOperator::Neg,
                5 => LaneOperator::Identity,
                _ => LaneOperator::Transduce(
                    u32::try_from((index + 1) % lane_count)
                        .expect("test lane count fits u32"),
                ),
            };
            (lane, operator)
        })
        .collect();
    OperatorTopology::try_new(assignments, lane_count).expect("valid test topology")
}

#[test]
fn residue_lane_correctness_scales_by_lanes_and_depth() {
    let profile = scale_profile();
    let mut total_lane_operations = 0_u128;

    for &lane_count in profile.lane_counts {
        let moduli = first_primes(lane_count);
        let basis = BasisFrame::try_new(moduli.clone()).expect("prime basis is pairwise coprime");
        let mut rng = XorShift64::new(0x9E37_79B9_7F4A_7C15 ^ lane_count as u64);
        let mut lanes: Vec<ResidueLane> = moduli
            .iter()
            .enumerate()
            .map(|(index, &modulus)| {
                ResidueLane::try_new(
                    LaneId(u16::try_from(index).expect("test lane count fits u16")),
                    modulus,
                    rng.next() % modulus,
                )
                .expect("canonical residue")
            })
            .collect();

        for step in 0..profile.steps {
            for (index, lane) in lanes.iter_mut().enumerate() {
                let modulus = lane.modulus;
                let rhs_residue = rng.next() % modulus;
                let rhs = ResidueLane::try_new(lane.lane_id, modulus, rhs_residue)
                    .expect("canonical right operand");
                let old = lane.residue;

                let (updated, expected) = match (step + index) % 3 {
                    0 => (
                        lane.add(rhs).expect("compatible add"),
                        ((old as u128 + rhs_residue as u128) % modulus as u128) as u64,
                    ),
                    1 => (
                        lane.sub(rhs).expect("compatible subtract"),
                        (old + modulus - rhs_residue) % modulus,
                    ),
                    _ => (
                        lane.mul(rhs).expect("compatible multiply"),
                        ((old as u128 * rhs_residue as u128) % modulus as u128) as u64,
                    ),
                };

                assert_eq!(updated.residue, expected, "lane={index} step={step}");
                assert!(updated.residue < modulus);
                *lane = updated;
                total_lane_operations += 1;
            }
        }

        let state = CramState::try_new(
            basis,
            lanes,
            WindingState {
                cells: vec![0_i128; lane_count].into_boxed_slice(),
                generation: u64::try_from(profile.steps).expect("test step count fits u64"),
            },
            ShadowState {
                residues: vec![0_u64; lane_count].into_boxed_slice(),
                integrity_epoch: 0,
            },
            BoundCertificate {
                height_bits: 1,
                guard_bits: 2,
            },
            topology(lane_count),
            FrameId(u64::try_from(lane_count).expect("test lane count fits u64")),
            LineageDigest([0_u8; 32]),
            DomainState::Coefficient,
        )
        .expect("scaled state remains structurally valid");

        assert_eq!(state.lanes.len(), lane_count);
        assert_eq!(state.basis.lane_count(), lane_count);
    }

    println!(
        "CRAM_SCALE profile={} lane_operations={} status=PASS",
        profile.name, total_lane_operations
    );
}

#[test]
fn bound_rules_remain_sound_at_profile_depth() {
    let profile = scale_profile();
    let mut add_bound = BoundCertificate {
        height_bits: 1,
        guard_bits: 3,
    };
    let mut mul_bound = add_bound;

    for step in 0..profile.steps {
        let rhs = BoundCertificate {
            height_bits: u32::try_from((step % 31) + 1).expect("small height fits u32"),
            guard_bits: 3,
        };
        let previous_add = add_bound;
        add_bound = BoundCertificate::for_add(add_bound, rhs);
        assert!(add_bound.height_bits >= previous_add.height_bits);
        assert!(add_bound.height_bits >= rhs.height_bits);

        let previous_mul = mul_bound;
        mul_bound = BoundCertificate::for_mul(mul_bound, rhs);
        assert!(mul_bound.height_bits >= previous_mul.height_bits);
        assert!(mul_bound.height_bits >= rhs.height_bits);
        assert_eq!(mul_bound.guard_bits, 3);
    }

    println!(
        "CRAM_BOUNDS profile={} steps={} add_height={} mul_height={} status=PASS",
        profile.name, profile.steps, add_bound.height_bits, mul_bound.height_bits
    );
}

#[test]
fn anchor_phase_winding_is_exhaustively_exact_on_small_pairs() {
    let pairs = [(4_u64, 9_u64), (8, 9), (15, 16), (25, 49), (36, 37)];
    let mut states = 0_u64;

    for (main, anchor) in pairs {
        assert_eq!(cram_core::gcd(main, anchor), 1);
        for value in 0..main * anchor {
            let witness = recover_winding(value % main, value % anchor, main, anchor)
                .expect("coprime pair");
            assert_eq!(
                witness.winding_mod_anchor,
                value / main,
                "main={main} anchor={anchor} value={value}"
            );
            assert!(witness.verify());
            states += 1;
        }
    }

    println!("CRAM_ANCHOR exhaustive_states={states} status=PASS");
}

#[test]
fn anchor_phase_winding_scales_to_large_composite_frame() {
    let profile = scale_profile();
    let main = 9_699_690_u64;
    let anchor = 23_u64;
    let range = main * anchor;
    let mut rng = XorShift64::new(0xD1B5_4A32_D192_ED03);

    assert_eq!(cram_core::gcd(main, anchor), 1);
    for sample in 0..profile.kelim_samples {
        let value = rng.next() % range;
        let witness = recover_winding(value % main, value % anchor, main, anchor)
            .expect("coprime frame and anchor");
        assert_eq!(
            witness.winding_mod_anchor,
            value / main,
            "sample={sample} value={value}"
        );
        assert!(witness.verify());
    }

    println!(
        "CRAM_ANCHOR profile={} sampled_states={} status=PASS",
        profile.name, profile.kelim_samples
    );
}

#[test]
fn architecture_counters_stay_clean_during_scaled_checks() {
    let counters = ArchitectureCounters::default();
    assert!(counters.assert_production_clean().is_ok());
    let snapshot = counters.snapshot();
    assert_eq!(snapshot.internal_projections, 0);
    assert_eq!(snapshot.crt_reconstructions, 0);
    assert_eq!(snapshot.scalar_materializations, 0);
    assert_eq!(snapshot.garner_calls, 0);
    assert_eq!(snapshot.mixed_radix_calls, 0);
}
