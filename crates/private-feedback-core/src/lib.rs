#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]

/// Canonical CRAM safe basis used by the reference application.
pub const SAFE_BASIS: [u64; 8] = [2, 3, 5, 7, 11, 13, 17, 19];
pub const SLOT_COUNT: usize = 8;
pub const LANE_COUNT: usize = SAFE_BASIS.len();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum QuestionClass {
    ClarifyGoal = 0,
    ClarifyObstacle = 1,
    DistinguishLocationFromComprehension = 2,
    IdentifyImpact = 3,
    IdentifyExpectedOutcome = 4,
    IdentifyTrustConcern = 5,
    ConfirmNoFollowupNeeded = 6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FrictionClass {
    Unknown = 0,
    Missing = 1,
    Confusing = 2,
    Broken = 3,
    Slow = 4,
    Pricing = 5,
    Trust = 6,
    Accessibility = 7,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SentimentClass {
    Unknown = 0,
    Positive = 1,
    Neutral = 2,
    Frustrated = 3,
    Concerned = 4,
    Angry = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalError {
    TopicOutOfRange,
    ProductAreaOutOfRange,
    SeverityOutOfRange,
    ConfidenceOutOfRange,
}

/// Structured application signal. Raw response text is intentionally absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeedbackSignal {
    topic: u16,
    friction: FrictionClass,
    severity: u8,
    sentiment: SentimentClass,
    product_area: u16,
    followup: QuestionClass,
    consent_to_retain: bool,
    confidence_permille: u16,
}

impl FeedbackSignal {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        topic: u16,
        friction: FrictionClass,
        severity: u8,
        sentiment: SentimentClass,
        product_area: u16,
        followup: QuestionClass,
        consent_to_retain: bool,
        confidence_permille: u16,
    ) -> Result<Self, SignalError> {
        if topic >= 256 {
            return Err(SignalError::TopicOutOfRange);
        }
        if product_area >= 1024 {
            return Err(SignalError::ProductAreaOutOfRange);
        }
        if severity >= 8 {
            return Err(SignalError::SeverityOutOfRange);
        }
        if confidence_permille > 1000 {
            return Err(SignalError::ConfidenceOutOfRange);
        }

        Ok(Self {
            topic,
            friction,
            severity,
            sentiment,
            product_area,
            followup,
            consent_to_retain,
            confidence_permille,
        })
    }

    /// Exact fixed-slot encoding. No free-form text enters the aggregate frame.
    pub fn slots(self) -> [u64; SLOT_COUNT] {
        let consent = if self.consent_to_retain { 1 } else { 0 };
        [
            u64::from(self.topic),
            self.friction as u64,
            u64::from(self.severity),
            self.sentiment as u64,
            u64::from(self.product_area),
            self.followup as u64,
            consent,
            u64::from(self.confidence_permille),
        ]
    }
}

/// Residue-native signal frame: one row per structured slot, one column per basis lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResidueSignal {
    residues: [[u64; LANE_COUNT]; SLOT_COUNT],
}

impl ResidueSignal {
    pub fn from_signal(signal: FeedbackSignal) -> Self {
        Self::from_slots(signal.slots())
    }

    pub fn from_slots(slots: [u64; SLOT_COUNT]) -> Self {
        let mut residues = [[0_u64; LANE_COUNT]; SLOT_COUNT];
        let mut slot_index = 0;
        while slot_index < SLOT_COUNT {
            let mut lane_index = 0;
            while lane_index < LANE_COUNT {
                residues[slot_index][lane_index] =
                    slots[slot_index] % SAFE_BASIS[lane_index];
                lane_index += 1;
            }
            slot_index += 1;
        }
        Self { residues }
    }

    pub fn lane(&self, slot: usize, lane: usize) -> Option<u64> {
        self.residues
            .get(slot)
            .and_then(|row| row.get(lane))
            .copied()
    }

    /// Lane-wise aggregate. The value remains in the residue domain.
    pub fn add_assign(&mut self, rhs: &Self) {
        let mut slot_index = 0;
        while slot_index < SLOT_COUNT {
            let mut lane_index = 0;
            while lane_index < LANE_COUNT {
                let modulus = SAFE_BASIS[lane_index];
                self.residues[slot_index][lane_index] =
                    (self.residues[slot_index][lane_index]
                        + rhs.residues[slot_index][lane_index])
                        % modulus;
                lane_index += 1;
            }
            slot_index += 1;
        }
    }

    pub fn validate(&self) -> bool {
        let mut slot_index = 0;
        while slot_index < SLOT_COUNT {
            let mut lane_index = 0;
            while lane_index < LANE_COUNT {
                if self.residues[slot_index][lane_index] >= SAFE_BASIS[lane_index] {
                    return false;
                }
                lane_index += 1;
            }
            slot_index += 1;
        }
        true
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FollowupState {
    pub goal_known: bool,
    pub obstacle_known: bool,
    pub location_vs_comprehension_known: bool,
    pub impact_known: bool,
    pub expected_outcome_known: bool,
    pub trust_concern_possible: bool,
    pub remaining_questions: u8,
}

/// Deterministic next-best-question policy for a strict two-reply interaction.
/// A model may provide the state classification; this function spends the remaining
/// turn on the highest-value unresolved field rather than customer-facing filler.
pub fn select_next_question(state: FollowupState) -> QuestionClass {
    if state.remaining_questions == 0 {
        return QuestionClass::ConfirmNoFollowupNeeded;
    }
    if !state.goal_known {
        return QuestionClass::ClarifyGoal;
    }
    if !state.obstacle_known {
        return QuestionClass::ClarifyObstacle;
    }
    if !state.location_vs_comprehension_known {
        return QuestionClass::DistinguishLocationFromComprehension;
    }
    if state.trust_concern_possible {
        return QuestionClass::IdentifyTrustConcern;
    }
    if !state.impact_known {
        return QuestionClass::IdentifyImpact;
    }
    if !state.expected_outcome_known {
        return QuestionClass::IdentifyExpectedOutcome;
    }
    QuestionClass::ConfirmNoFollowupNeeded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gcd(mut a: u64, mut b: u64) -> u64 {
        while b != 0 {
            let next = a % b;
            a = b;
            b = next;
        }
        a
    }

    fn sample_signal(topic: u16, severity: u8) -> FeedbackSignal {
        FeedbackSignal::try_new(
            topic,
            FrictionClass::Confusing,
            severity,
            SentimentClass::Frustrated,
            17,
            QuestionClass::DistinguishLocationFromComprehension,
            false,
            900,
        )
        .unwrap()
    }

    #[test]
    fn safe_basis_is_pairwise_coprime() {
        for i in 0..LANE_COUNT {
            for j in (i + 1)..LANE_COUNT {
                assert_eq!(gcd(SAFE_BASIS[i], SAFE_BASIS[j]), 1);
            }
        }
    }

    #[test]
    fn residue_frame_stays_in_lane_ranges() {
        let frame = ResidueSignal::from_signal(sample_signal(42, 5));
        assert!(frame.validate());
        for slot in 0..SLOT_COUNT {
            for lane in 0..LANE_COUNT {
                assert!(frame.lane(slot, lane).unwrap() < SAFE_BASIS[lane]);
            }
        }
    }

    #[test]
    fn lane_aggregation_matches_direct_modular_addition() {
        let a = sample_signal(42, 5).slots();
        let b = sample_signal(99, 6).slots();
        let mut residue_a = ResidueSignal::from_slots(a);
        let residue_b = ResidueSignal::from_slots(b);
        residue_a.add_assign(&residue_b);

        for slot in 0..SLOT_COUNT {
            for lane in 0..LANE_COUNT {
                let expected = (a[slot] + b[slot]) % SAFE_BASIS[lane];
                assert_eq!(residue_a.lane(slot, lane), Some(expected));
            }
        }
    }

    #[test]
    fn invalid_domain_values_fail_closed() {
        assert_eq!(
            FeedbackSignal::try_new(
                256,
                FrictionClass::Unknown,
                0,
                SentimentClass::Unknown,
                0,
                QuestionClass::ClarifyGoal,
                false,
                0,
            ),
            Err(SignalError::TopicOutOfRange)
        );
    }

    #[test]
    fn next_question_spends_turn_on_highest_value_missing_field() {
        let state = FollowupState {
            goal_known: true,
            obstacle_known: true,
            location_vs_comprehension_known: false,
            impact_known: false,
            expected_outcome_known: false,
            trust_concern_possible: false,
            remaining_questions: 1,
        };
        assert_eq!(
            select_next_question(state),
            QuestionClass::DistinguishLocationFromComprehension
        );
    }

    #[test]
    fn no_remaining_turn_returns_terminal_class() {
        let state = FollowupState {
            goal_known: false,
            obstacle_known: false,
            location_vs_comprehension_known: false,
            impact_known: false,
            expected_outcome_known: false,
            trust_concern_possible: true,
            remaining_questions: 0,
        };
        assert_eq!(
            select_next_question(state),
            QuestionClass::ConfirmNoFollowupNeeded
        );
    }
}
