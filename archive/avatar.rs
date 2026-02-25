//! Behavioral Avatar Module
//!
//! Port of HackFate's BehavioralAvatar system, adapted for SEBV FHE integration.
//!
//! The BehavioralAvatar is a privacy-preserving digital persona that:
//! 1. Captures behavioral entropy profile from user interactions
//! 2. Adapts to cultural context through configurable weights
//! 3. Uses Q-learning for continuous optimization
//! 4. Generates synthetic behavioral data for testing
//! 5. Integrates with FHE for zero-knowledge classification
//!
//! # HackFate Integration
//!
//! Original HackFate components mapped:
//! - `BehavioralAvatar` → `SEBVAvatar` (this module)
//! - `AttributeWeightPlugin` → `weights.rs`
//! - `DynamicPolicyModule` → `policy.rs`
//! - `ReinforcementLearningModule` → `learning.rs`
//!
//! # Privacy Properties
//!
//! - Avatar stores only entropy profiles (not raw behavior)
//! - Cultural weights are non-identifying metadata
//! - All classification happens in FHE (THEOREM FHE1: Semantic Security)

use crate::{CognitiveEntropyVector, BotType, ENTROPY_SCALE};
use crate::weights::EntropyWeights;
use crate::policy::{ClassificationPolicy, PolicyAdjustment};
use crate::learning::{LearningModule, LearningState, LearningAction, ClassificationFeedback};
use crate::entropy::compute_cognitive_entropy_default;

/// Cultural identity configuration
///
/// Determines how user preferences blend with environmental factors.
/// Based on HackFate's `cultural_identity` dictionary.
#[derive(Clone, Debug)]
pub struct CulturalIdentity {
    /// Weight given to user preferences vs environment (0.0-1.0)
    /// Default: 0.7 (70% user, 30% environment)
    pub preference_weight: i64,
    
    /// User's privacy preference level (0 = minimal, 1 = maximum)
    pub privacy_level: i64,
    
    /// Tolerance for false positives (0 = strict, 1 = lenient)
    pub fp_tolerance: i64,
    
    /// Tolerance for false negatives (0 = strict, 1 = lenient)
    pub fn_tolerance: i64,
    
    /// Region/locale code (affects threshold calibration)
    pub region_code: u32,
}

impl Default for CulturalIdentity {
    fn default() -> Self {
        Self {
            preference_weight: 700_000, // 0.7 scaled
            privacy_level: ENTROPY_SCALE / 2, // Medium privacy
            fp_tolerance: 200_000, // 0.2 - moderately strict
            fn_tolerance: 100_000, // 0.1 - strict on false negatives
            region_code: 0,
        }
    }
}

impl CulturalIdentity {
    /// Create from permille values (1000 = 1.0, 700 = 0.7)
    pub fn from_permille(
        preference_weight_permille: i64,
        privacy_level_permille: i64,
        fp_tolerance_permille: i64,
        fn_tolerance_permille: i64,
    ) -> Self {
        Self {
            preference_weight: preference_weight_permille * ENTROPY_SCALE / 1000,
            privacy_level: privacy_level_permille * ENTROPY_SCALE / 1000,
            fp_tolerance: fp_tolerance_permille * ENTROPY_SCALE / 1000,
            fn_tolerance: fn_tolerance_permille * ENTROPY_SCALE / 1000,
            region_code: 0,
        }
    }
    
    /// Calculate user and environment weights
    ///
    /// Returns (user_weight, env_weight) where user_weight + env_weight = ENTROPY_SCALE
    pub fn calculate_weights(&self) -> (i64, i64) {
        let user_weight = self.preference_weight.clamp(0, ENTROPY_SCALE);
        let env_weight = ENTROPY_SCALE - user_weight;
        (user_weight, env_weight)
    }
}

/// Environment context for classification
///
/// Captures external factors that influence classification policy.
#[derive(Clone, Debug, Default)]
pub struct EnvironmentContext {
    /// Current threat level (0 = low, 1 = high)
    pub threat_level: i64,
    
    /// Time of day factor (affects expected behavioral entropy)
    pub time_factor: i64,
    
    /// Device type (0 = desktop, 1 = mobile, 2 = tablet)
    pub device_type: u8,
    
    /// Network latency estimate (ms, scaled)
    pub latency_ms: i64,
    
    /// Session duration so far (seconds)
    pub session_duration_s: i64,
}

impl EnvironmentContext {
    /// Create high-security environment
    pub fn high_security() -> Self {
        Self {
            threat_level: 800_000, // 0.8
            time_factor: ENTROPY_SCALE / 2,
            device_type: 0,
            latency_ms: 50_000,
            session_duration_s: 0,
        }
    }
    
    /// Create relaxed environment
    pub fn relaxed() -> Self {
        Self {
            threat_level: 100_000, // 0.1
            time_factor: ENTROPY_SCALE / 2,
            device_type: 0,
            latency_ms: 100_000,
            session_duration_s: 600,
        }
    }
}

/// SEBV Behavioral Avatar
///
/// Privacy-preserving digital persona that captures behavioral entropy profile
/// and adapts to user/environmental context through Q-learning.
pub struct SEBVAvatar {
    /// Unique identifier (hashed, not PII)
    pub avatar_id: u64,
    
    /// Cultural identity configuration
    pub cultural_identity: CulturalIdentity,
    
    /// Current entropy profile (learned from behavior)
    entropy_profile: CognitiveEntropyVector,
    
    /// Entropy weights (adapted to user)
    weights: EntropyWeights,
    
    /// Classification policy
    policy: ClassificationPolicy,
    
    /// Learning module for adaptation
    learning: LearningModule,
    
    /// Historical entropy samples (for trend analysis)
    history: Vec<CognitiveEntropyVector>,
    
    /// Maximum history size
    max_history: usize,
    
    /// Classification count for this session
    classification_count: u64,
    
    /// Correct classifications count
    correct_count: u64,
}

impl SEBVAvatar {
    /// Create new avatar with default settings
    pub fn new(avatar_id: u64) -> Self {
        Self {
            avatar_id,
            cultural_identity: CulturalIdentity::default(),
            entropy_profile: CognitiveEntropyVector::from_normalized(0.5, 0.7, 0.45, 0.65),
            weights: EntropyWeights::default(),
            policy: ClassificationPolicy::sebv_standard(),
            learning: LearningModule::new(),
            history: Vec::with_capacity(100),
            max_history: 100,
            classification_count: 0,
            correct_count: 0,
        }
    }
    
    /// Create with cultural identity
    pub fn with_cultural_identity(avatar_id: u64, cultural_identity: CulturalIdentity) -> Self {
        let mut avatar = Self::new(avatar_id);
        avatar.cultural_identity = cultural_identity;
        avatar.update_weights_from_culture();
        avatar
    }
    
    /// Update weights based on cultural identity
    fn update_weights_from_culture(&mut self) {
        let (_user_weight, _env_weight) = self.cultural_identity.calculate_weights();
        
        // Adjust weights based on privacy preference
        // Higher privacy → favor permutation entropy (invariant to monotonic transforms)
        let privacy_factor = self.cultural_identity.privacy_level;
        
        self.weights = EntropyWeights {
            sample_weight: 700_000 - (privacy_factor / 10), // Reduce if high privacy
            permutation_weight: 900_000 + (privacy_factor / 10), // Increase if high privacy
            approximate_weight: 500_000,
            lz_weight: 800_000,
        };
        
        // Adjust policy threshold based on tolerance settings
        let fp_adjustment = (self.cultural_identity.fp_tolerance - 200_000) / 10;
        let fn_adjustment = (self.cultural_identity.fn_tolerance - 100_000) / 10;
        
        self.policy.threshold += fp_adjustment - fn_adjustment;
    }
    
    /// Update entropy profile from new behavioral data
    ///
    /// This is the main input from behavioral telemetry.
    pub fn update_from_behavior(&mut self, behavioral_data: &[i64]) {
        let new_entropy = compute_cognitive_entropy_default(behavioral_data);
        
        // Blend with existing profile using cultural weights
        let (user_weight, env_weight) = self.cultural_identity.calculate_weights();
        
        self.entropy_profile = self.merge_entropy(
            &self.entropy_profile,
            &new_entropy,
            user_weight, // Existing profile acts as "user" preference
            env_weight,  // New data acts as "environment" update
        );
        
        // Add to history
        if self.history.len() >= self.max_history {
            self.history.remove(0);
        }
        self.history.push(new_entropy);
    }
    
    /// Merge two entropy vectors using cultural weights
    ///
    /// Implements HackFate's `merge_attributes` pattern.
    fn merge_entropy(
        &self,
        existing: &CognitiveEntropyVector,
        new: &CognitiveEntropyVector,
        existing_weight: i64,
        new_weight: i64,
    ) -> CognitiveEntropyVector {
        let total = existing_weight + new_weight;
        if total == 0 {
            return existing.clone();
        }
        
        CognitiveEntropyVector {
            sample_entropy: (existing.sample_entropy * existing_weight + 
                            new.sample_entropy * new_weight) / total,
            permutation_entropy: (existing.permutation_entropy * existing_weight + 
                                  new.permutation_entropy * new_weight) / total,
            approximate_entropy: (existing.approximate_entropy * existing_weight + 
                                  new.approximate_entropy * new_weight) / total,
            lz_complexity: (existing.lz_complexity * existing_weight + 
                           new.lz_complexity * new_weight) / total,
        }
    }
    
    /// Align avatar with user profile and environment
    ///
    /// Implements HackFate's `align_with_user` method.
    pub fn align_with_context(
        &mut self,
        user_entropy: &CognitiveEntropyVector,
        environment: &EnvironmentContext,
    ) {
        let (user_weight, env_weight) = self.cultural_identity.calculate_weights();
        
        // Create environment entropy profile (baseline expected for device/time)
        let env_entropy = self.expected_environment_entropy(environment);
        
        // Merge user and environment entropy profiles
        self.entropy_profile = self.merge_entropy(
            user_entropy,
            &env_entropy,
            user_weight,
            env_weight,
        );
        
        // Adjust policy for threat level
        if environment.threat_level > 500_000 {
            // High threat: stricter classification
            self.policy.threshold = (self.policy.threshold * 800_000) / ENTROPY_SCALE;
        }
    }
    
    /// Compute expected environment entropy for given context
    fn expected_environment_entropy(&self, env: &EnvironmentContext) -> CognitiveEntropyVector {
        // Device type affects expected entropy
        let device_factor = match env.device_type {
            0 => 1_000_000, // Desktop: full range
            1 => 900_000,   // Mobile: slightly lower
            2 => 950_000,   // Tablet: middle
            _ => 1_000_000,
        };
        
        // Time factor affects expected patterns
        let time_adj = env.time_factor;
        
        CognitiveEntropyVector {
            sample_entropy: (550_000 * device_factor) / ENTROPY_SCALE,
            permutation_entropy: (750_000 * device_factor * time_adj) / (ENTROPY_SCALE * ENTROPY_SCALE),
            approximate_entropy: (500_000 * device_factor) / ENTROPY_SCALE,
            lz_complexity: (650_000 * device_factor) / ENTROPY_SCALE,
        }
    }
    
    /// Simulate behavior (select action based on current state)
    ///
    /// Implements HackFate's `simulate_behavior` using Q-learning.
    pub fn simulate_behavior(&mut self) -> LearningAction {
        // Create learning state from current metrics
        let fp_rate = if self.classification_count > 0 {
                        ((self.classification_count - self.correct_count) as i64) * ENTROPY_SCALE / 
             (self.classification_count as i64)
        } else {
            0
        };
        
        let state = LearningState::from_metrics(fp_rate, 0, self.policy.threshold, ENTROPY_SCALE);
        
        // Choose action via epsilon-greedy
        self.learning.choose_action(&state)
    }
    
    /// Process feedback to refine avatar behavior
    ///
    /// Implements HackFate's `process_feedback` method.
    pub fn process_feedback(&mut self, feedback: &[ClassificationFeedback]) {
        self.learning.learn_from_classification_feedback(feedback, self.policy.threshold);
        
        // Update accuracy metrics
        for fb in feedback {
            self.classification_count += 1;
            if fb.was_human == fb.classified_human {
                self.correct_count += 1;
            }
        }
        
        // Apply learned adjustments to policy
        let adjustments = self.learning.suggest_adjustments(feedback);
        for adj in adjustments {
            self.apply_adjustment(&adj);
        }
    }
    
    /// Apply a policy adjustment
    fn apply_adjustment(&mut self, adj: &PolicyAdjustment) {
        match adj {
            PolicyAdjustment::IncreaseThreshold(amount) => {
                self.policy.threshold += amount;
            }
            PolicyAdjustment::DecreaseThreshold(amount) => {
                self.policy.threshold -= amount;
            }
            PolicyAdjustment::AdjustWeight { entropy_idx, delta } => {
                match entropy_idx {
                    0 => self.weights.sample_weight += delta,
                    1 => self.weights.permutation_weight += delta,
                    2 => self.weights.approximate_weight += delta,
                    3 => self.weights.lz_weight += delta,
                    _ => {}
                }
            }
            _ => {}
        }
    }
    
    /// Get current entropy profile
    pub fn entropy_profile(&self) -> &CognitiveEntropyVector {
        &self.entropy_profile
    }
    
    /// Get current weights
    pub fn weights(&self) -> &EntropyWeights {
        &self.weights
    }
    
    /// Get current policy
    pub fn policy(&self) -> &ClassificationPolicy {
        &self.policy
    }
    
    /// Get classification accuracy as permille (1000 = 100%)
    pub fn accuracy_permille(&self) -> u32 {
        if self.classification_count == 0 {
            return 1000;
        }
        (self.correct_count as u64 * 1000 / self.classification_count as u64) as u32
    }
    
    /// Generate synthetic behavioral data (for testing/training)
    ///
    /// Creates data that should classify as human based on avatar's profile.
    pub fn generate_synthetic_human_data(&self, length: usize) -> Vec<i64> {
        let mut data = Vec::with_capacity(length);
        let mut state = self.avatar_id;
        
        // Target entropy profile
        let target = &self.entropy_profile;
        
        for i in 0..length {
            // Mix structured pattern with noise (human-like)
            // Use integer triangle-wave approximation instead of f64 sin
            // Period ~31 samples (close to 2π/0.2 ≈ 31.4)
            let phase = (i % 31) as i64;
            let half = 15i64;
            // Triangle wave: ramps from -half to +half then back
            let wave = if phase <= half { phase * 2 - half } else { 3 * half - phase * 2 };
            // Scale by sample_entropy/2, normalized to half range
            let structure = wave * target.sample_entropy / (2 * half);
            
            // LFSR-based noise
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let noise = ((state % 200_001) as i64 - 100_000) * 
                       target.lz_complexity / ENTROPY_SCALE;
            
            let base = ENTROPY_SCALE / 2;
            data.push((base + structure + noise).clamp(0, ENTROPY_SCALE));
        }
        
        data
    }
    
    /// Generate synthetic bot data (for testing)
    pub fn generate_synthetic_bot_data(&self, length: usize, bot_type: BotType) -> Vec<i64> {
        let mut data = Vec::with_capacity(length);
        let mut state = self.avatar_id.wrapping_add(1);
        
        match bot_type {
            BotType::Scripted => {
                // Very repetitive pattern
                for i in 0..length {
                    data.push(((i % 5) as i64) * ENTROPY_SCALE / 5);
                }
            }
            BotType::Noisy => {
                // Pure random noise
                for _ in 0..length {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    data.push((state % (ENTROPY_SCALE as u64 + 1)) as i64);
                }
            }
        }
        
        data
    }
}

/// Avatar Manager
///
/// Manages multiple behavioral avatars, providing aggregate statistics
/// for system-wide learning.
pub struct AvatarManager {
    /// Active avatars
    avatars: std::collections::HashMap<u64, SEBVAvatar>,
    
    /// Global learning module (aggregates across avatars)
    global_learning: LearningModule,
    
    /// Global policy for new avatars
    default_policy: ClassificationPolicy,
}

impl AvatarManager {
    pub fn new() -> Self {
        Self {
            avatars: std::collections::HashMap::new(),
            global_learning: LearningModule::new(),
            default_policy: ClassificationPolicy::sebv_standard(),
        }
    }
    
    /// Get or create avatar
    pub fn get_or_create(&mut self, avatar_id: u64) -> &mut SEBVAvatar {
        self.avatars.entry(avatar_id).or_insert_with(|| {
            let mut avatar = SEBVAvatar::new(avatar_id);
            avatar.policy = self.default_policy.clone();
            avatar
        })
    }
    
    /// Remove avatar
    pub fn remove(&mut self, avatar_id: u64) -> Option<SEBVAvatar> {
        self.avatars.remove(&avatar_id)
    }
    
    /// Process global feedback (from all avatars)
    pub fn process_global_feedback(&mut self, feedback: &[ClassificationFeedback]) {
        self.global_learning.learn_from_classification_feedback(feedback, self.default_policy.threshold);
        
        // Apply global learning to default policy for new avatars
        let adjustments = self.global_learning.suggest_adjustments(feedback);
        for adj in adjustments {
            self.apply_global_adjustment(&adj);
        }
    }
    
    fn apply_global_adjustment(&mut self, adj: &PolicyAdjustment) {
        match adj {
            PolicyAdjustment::IncreaseThreshold(amount) => {
                self.default_policy.threshold += amount;
            }
            PolicyAdjustment::DecreaseThreshold(amount) => {
                self.default_policy.threshold -= amount;
            }
            _ => {}
        }
    }
    
    /// Get aggregate accuracy across all avatars as permille (1000 = 100%)
    pub fn global_accuracy_permille(&self) -> u32 {
        if self.avatars.is_empty() {
            return 1000;
        }

        let total: u32 = self.avatars.values().map(|a| a.accuracy_permille()).sum();
        total / self.avatars.len() as u32
    }
    
    /// Get avatar count
    pub fn avatar_count(&self) -> usize {
        self.avatars.len()
    }
}

impl Default for AvatarManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cultural_identity_weights() {
        let identity = CulturalIdentity::from_permille(700, 500, 200, 100);
        
        let (user_w, env_w) = identity.calculate_weights();
        
        assert_eq!(user_w + env_w, ENTROPY_SCALE);
        assert_eq!(user_w, 700_000);
        assert_eq!(env_w, 300_000);
    }
    
    #[test]
    fn test_avatar_creation() {
        let avatar = SEBVAvatar::new(12345);
        
        assert_eq!(avatar.avatar_id, 12345);
        assert!(avatar.entropy_profile().sample_entropy > 0);
    }
    
    #[test]
    fn test_avatar_with_culture() {
        let culture = CulturalIdentity::from_permille(800, 900, 100, 50);
        let avatar = SEBVAvatar::with_cultural_identity(123, culture);
        
        // High privacy should favor permutation entropy
        assert!(avatar.weights().permutation_weight > avatar.weights().sample_weight);
    }
    
    #[test]
    fn test_update_from_behavior() {
        let mut avatar = SEBVAvatar::new(1);
        
        let initial = avatar.entropy_profile().sample_entropy;
        
        // Generate and process behavioral data
        let data: Vec<i64> = (0..100)
            .map(|i| ((i * 37 + 13) % 100) * ENTROPY_SCALE / 100)
            .collect();
        
        avatar.update_from_behavior(&data);
        
        // Profile should have changed
        let updated = avatar.entropy_profile().sample_entropy;
        assert_ne!(initial, updated);
    }
    
    #[test]
    fn test_merge_entropy() {
        let avatar = SEBVAvatar::new(1);
        
        let e1 = CognitiveEntropyVector::from_normalized(0.4, 0.6, 0.3, 0.5);
        let e2 = CognitiveEntropyVector::from_normalized(0.8, 0.8, 0.7, 0.9);
        
        // 70% e1, 30% e2
        let merged = avatar.merge_entropy(&e1, &e2, 700_000, 300_000);
        
        // Check sample: 0.4 * 0.7 + 0.8 * 0.3 = 0.28 + 0.24 = 0.52
        let expected_sample = (400_000 * 700_000 + 800_000 * 300_000) / ENTROPY_SCALE;
        assert_eq!(merged.sample_entropy, expected_sample);
    }
    
    #[test]
    fn test_align_with_context() {
        let mut avatar = SEBVAvatar::new(1);
        
        let user_entropy = CognitiveEntropyVector::from_normalized(0.6, 0.8, 0.5, 0.7);
        let env = EnvironmentContext::high_security();
        
        let old_threshold = avatar.policy().threshold;
        
        avatar.align_with_context(&user_entropy, &env);
        
        // High threat should lower threshold (stricter)
        assert!(avatar.policy().threshold < old_threshold);
    }
    
    #[test]
    fn test_simulate_behavior() {
        let mut avatar = SEBVAvatar::new(1);
        
        let action = avatar.simulate_behavior();
        
        // Should return a valid action
        match action {
            LearningAction::IncreaseThreshold |
            LearningAction::DecreaseThreshold |
            LearningAction::MaintainThreshold |
            LearningAction::IncreaseSampleWeight |
            LearningAction::DecreaseSampleWeight |
            LearningAction::IncreasePermWeight |
            LearningAction::DecreasePermWeight => {}
        }
    }
    
    #[test]
    fn test_synthetic_data_generation() {
        let avatar = SEBVAvatar::new(42);
        
        // Generate human-like data
        let human_data = avatar.generate_synthetic_human_data(100);
        assert_eq!(human_data.len(), 100);
        
        // All values should be in valid range
        for &v in &human_data {
            assert!(v >= 0 && v <= ENTROPY_SCALE);
        }
        
        // Generate bot data
        let bot_scripted = avatar.generate_synthetic_bot_data(100, BotType::Scripted);
        let bot_noisy = avatar.generate_synthetic_bot_data(100, BotType::Noisy);
        
        // Bot scripted should be very repetitive (check pattern)
        assert_eq!(bot_scripted[0], bot_scripted[5]); // Period 5
        
        // Bot noisy should have high variance
        let mean: i64 = bot_noisy.iter().sum::<i64>() / bot_noisy.len() as i64;
        let variance: i64 = bot_noisy.iter()
            .map(|&v| (v - mean) * (v - mean))
            .sum::<i64>() / bot_noisy.len() as i64;
        
        assert!(variance > ENTROPY_SCALE / 10, "Noisy bot should have high variance");
    }
    
    #[test]
    fn test_process_feedback() {
        let mut avatar = SEBVAvatar::new(1);
        
        let feedback = vec![
            ClassificationFeedback {
                was_human: true,
                classified_human: true,
                confidence: 800_000,
            },
            ClassificationFeedback {
                was_human: true,
                classified_human: false,
                confidence: 400_000,
            },
        ];
        
        avatar.process_feedback(&feedback);
        
        assert_eq!(avatar.classification_count, 2);
        assert_eq!(avatar.correct_count, 1);
        assert_eq!(avatar.accuracy_permille(), 500); // 50% = 500 permille
    }
    
    #[test]
    fn test_avatar_manager() {
        let mut manager = AvatarManager::new();
        
        // Create avatars
        {
            let a1 = manager.get_or_create(1);
            a1.update_from_behavior(&[500_000; 50]);
        }
        {
            let a2 = manager.get_or_create(2);
            a2.update_from_behavior(&[600_000; 50]);
        }
        
        assert_eq!(manager.avatar_count(), 2);
        
        // Remove avatar
        manager.remove(1);
        assert_eq!(manager.avatar_count(), 1);
    }
    
    #[test]
    fn test_global_feedback() {
        let mut manager = AvatarManager::new();
        
        let feedback = vec![
            ClassificationFeedback {
                was_human: true,
                classified_human: true,
                confidence: 900_000,
            },
        ];
        
        let _old_threshold = manager.default_policy.threshold;
        manager.process_global_feedback(&feedback);
        
        // Good feedback might not change threshold much
        // but the Q-table should be updated
    }
}
