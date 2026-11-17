//! # GSO - Glowworm Swarm Optimization with Qbit Operations
//!
//! Quantum-inspired swarm optimization for FHE parameter search.
//!
//! ## Architecture
//!
//! Each agent has a "qbit" state - a superposition of search states
//! represented as CRT residues. The swarm evolves through:
//!
//! 1. **Luciferin update**: Agent brightness based on fitness
//! 2. **Movement**: Probabilistic movement toward brighter neighbors
//! 3. **Qbit rotation**: Quantum-inspired amplitude adjustment
//!
//! All operations are INTEGER-ONLY. No floating point.
//!
//! ## Applications
//!
//! - FHE noise budget optimization
//! - Parameter space exploration
//! - NTT prime selection

use crate::stream::ManaStream;

/// Qbit state - quantum-inspired amplitude representation
///
/// Instead of complex amplitudes, we use integer "weights" in CRT form.
/// The probability of measuring state i is proportional to weight[i]².
#[derive(Clone, Debug)]
pub struct QbitState {
    /// Amplitude weights (squared sum = normalization factor)
    pub weights: Vec<u64>,
    /// Normalization factor (sum of weights²)
    pub norm_sq: u128,
    /// Prime modulus for arithmetic
    pub prime: u64,
}

impl QbitState {
    /// Create uniform superposition over n states
    pub fn uniform(n: usize, prime: u64) -> Self {
        // All weights = 1 means uniform distribution
        let weights = vec![1; n];
        let norm_sq = n as u128;
        Self {
            weights,
            norm_sq,
            prime,
        }
    }

    /// Create from explicit weights
    pub fn from_weights(weights: Vec<u64>, prime: u64) -> Self {
        let norm_sq: u128 = weights.iter().map(|&w| (w as u128) * (w as u128)).sum();
        Self {
            weights,
            norm_sq,
            prime,
        }
    }

    /// Number of states
    pub fn num_states(&self) -> usize {
        self.weights.len()
    }

    /// Get probability of state i (as integer ratio: numerator, denominator)
    pub fn probability(&self, i: usize) -> (u128, u128) {
        let w = self.weights[i] as u128;
        (w * w, self.norm_sq)
    }

    /// Rotate amplitude toward state i (increase its probability)
    ///
    /// This is analogous to Grover's amplitude amplification.
    /// rotation_amount in range [0, prime) controls rotation strength.
    pub fn rotate_toward(&mut self, target: usize, rotation_amount: u64) {
        let q = self.prime;
        let current = self.weights[target];

        // Increase target weight
        let new_weight = (current + rotation_amount) % q;
        self.weights[target] = new_weight;

        // Recalculate normalization
        self.norm_sq = self
            .weights
            .iter()
            .map(|&w| (w as u128) * (w as u128))
            .sum();
    }

    /// Apply Hadamard-like mixing (spreads amplitude across states)
    pub fn mix(&mut self) {
        let n = self.weights.len();
        let q = self.prime as u128;

        // Compute mean weight
        let sum: u128 = self.weights.iter().map(|&w| w as u128).sum();
        let mean = (sum / n as u128) as u64;

        // Move all weights toward mean
        for w in &mut self.weights {
            *w = ((*w as u128 + mean as u128) / 2 % q) as u64;
        }

        self.norm_sq = self
            .weights
            .iter()
            .map(|&w| (w as u128) * (w as u128))
            .sum();
    }

    /// Measure (collapse) to a single state
    ///
    /// Uses a deterministic seed for reproducibility.
    /// Returns the measured state index.
    pub fn measure(&self, seed: u64) -> usize {
        // Use seed to pick a "random" point in [0, norm_sq)
        let point = (seed as u128 * 6364136223846793005u128 + 1) % self.norm_sq;

        let mut cumulative = 0u128;
        for (i, &w) in self.weights.iter().enumerate() {
            cumulative += (w as u128) * (w as u128);
            if point < cumulative {
                return i;
            }
        }

        self.weights.len() - 1
    }
}

/// Single GSO agent with qbit state
#[derive(Clone, Debug)]
pub struct QbitAgent {
    /// Agent ID
    pub id: usize,
    /// Current position (parameter values as CRT stream)
    pub position: ManaStream,
    /// Qbit search state
    pub qbit: QbitState,
    /// Luciferin (brightness) value
    pub luciferin: u64,
    /// Sensor range (neighborhood size)
    pub sensor_range: u64,
    /// Best fitness found
    pub best_fitness: u64,
}

impl QbitAgent {
    /// Create new agent at given position
    pub fn new(id: usize, position: ManaStream, qbit: QbitState) -> Self {
        Self {
            id,
            position,
            qbit,
            luciferin: 0,
            sensor_range: 100,
            best_fitness: 0,
        }
    }

    /// Update luciferin based on fitness
    pub fn update_luciferin(&mut self, fitness: u64, decay: u64, enhancement: u64) {
        // L(t+1) = (1 - decay) * L(t) + enhancement * fitness
        // Using integer arithmetic: L(t+1) = L(t) - L(t)*decay/1000 + fitness*enhancement/1000
        let decayed = self.luciferin - (self.luciferin * decay / 1000);
        let enhanced = fitness * enhancement / 1000;
        self.luciferin = decayed + enhanced;

        if fitness > self.best_fitness {
            self.best_fitness = fitness;
        }
    }

    /// Check if another agent is in sensor range
    pub fn can_see(&self, other_luciferin: u64) -> bool {
        other_luciferin > self.luciferin
    }
}

/// GSO Swarm - collection of qbit agents
#[derive(Clone, Debug)]
pub struct GsoSwarm {
    /// Agents in the swarm
    pub agents: Vec<QbitAgent>,
    /// GSO parameters
    pub params: GsoParams,
    /// Current iteration
    pub iteration: u64,
}

/// GSO algorithm parameters (all integers, no floats!)
#[derive(Clone, Debug)]
pub struct GsoParams {
    /// Luciferin decay rate (per-mille, i.e., /1000)
    pub luciferin_decay_permille: u64,
    /// Luciferin enhancement rate (per-mille)
    pub luciferin_enhance_permille: u64,
    /// Sensor range decay (per-mille)
    pub range_decay_permille: u64,
    /// Step size for movement (integer)
    pub step_size: u64,
    /// Qbit rotation strength
    pub rotation_strength: u64,
}

impl Default for GsoParams {
    fn default() -> Self {
        Self {
            luciferin_decay_permille: 400,   // 0.4 as 400/1000
            luciferin_enhance_permille: 600, // 0.6 as 600/1000
            range_decay_permille: 20,        // 0.02 as 20/1000
            step_size: 3,
            rotation_strength: 1,
        }
    }
}

impl GsoSwarm {
    /// Create new swarm with given agents
    pub fn new(agents: Vec<QbitAgent>, params: GsoParams) -> Self {
        Self {
            agents,
            params,
            iteration: 0,
        }
    }

    /// Create swarm from initial positions
    pub fn from_positions(
        positions: Vec<ManaStream>,
        qbit_states: usize,
        prime: u64,
        params: GsoParams,
    ) -> Self {
        let agents = positions
            .into_iter()
            .enumerate()
            .map(|(id, pos)| {
                let qbit = QbitState::uniform(qbit_states, prime);
                QbitAgent::new(id, pos, qbit)
            })
            .collect();

        Self::new(agents, params)
    }

    /// Run one iteration of GSO
    ///
    /// fitness_fn: evaluates an agent's position, returns integer fitness
    pub fn tick<F>(&mut self, fitness_fn: F)
    where
        F: Fn(&ManaStream) -> u64,
    {
        // Phase 1: Update luciferin
        for agent in &mut self.agents {
            let fitness = fitness_fn(&agent.position);
            agent.update_luciferin(
                fitness,
                self.params.luciferin_decay_permille,
                self.params.luciferin_enhance_permille,
            );
        }

        // Phase 2: Pre-collect luciferin and qbit states to avoid borrow issues
        let luciferins: Vec<u64> = self.agents.iter().map(|a| a.luciferin).collect();
        let qbit_states: Vec<QbitState> = self.agents.iter().map(|a| a.qbit.clone()).collect();

        // Phase 3: Find neighbors and rotate qbits toward better agents
        for (idx, agent) in self.agents.iter_mut().enumerate() {
            // Find brighter neighbors
            let brighter: Vec<usize> = luciferins
                .iter()
                .enumerate()
                .filter(|(i, &l)| *i != idx && l > agent.luciferin)
                .map(|(i, _)| i)
                .collect();

            // Rotate qbit toward best neighbor's state
            if let Some(&best_neighbor) = brighter.iter().max_by_key(|&&i| luciferins[i]) {
                // Collapse neighbor's qbit to get target state (use pre-collected state)
                let target_state = qbit_states[best_neighbor].measure(idx as u64 ^ self.iteration);
                agent
                    .qbit
                    .rotate_toward(target_state, self.params.rotation_strength);
            } else {
                // No brighter neighbor - explore via mixing
                agent.qbit.mix();
            }
        }

        self.iteration += 1;
    }

    /// Get the globally best agent
    pub fn best_agent(&self) -> Option<&QbitAgent> {
        self.agents.iter().max_by_key(|a| a.best_fitness)
    }

    /// Get swarm statistics
    pub fn stats(&self) -> SwarmStats {
        let total_luciferin: u64 = self.agents.iter().map(|a| a.luciferin).sum();
        let best_fitness = self
            .agents
            .iter()
            .map(|a| a.best_fitness)
            .max()
            .unwrap_or(0);
        let avg_luciferin = total_luciferin / self.agents.len().max(1) as u64;

        SwarmStats {
            iteration: self.iteration,
            num_agents: self.agents.len(),
            total_luciferin,
            avg_luciferin,
            best_fitness,
        }
    }
}

/// Swarm statistics
#[derive(Clone, Debug)]
pub struct SwarmStats {
    /// Current iteration
    pub iteration: u64,
    /// Number of agents
    pub num_agents: usize,
    /// Sum of all luciferin
    pub total_luciferin: u64,
    /// Average luciferin
    pub avg_luciferin: u64,
    /// Best fitness found
    pub best_fitness: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PRIME: u64 = 998244353;

    #[test]
    fn test_qbit_uniform() {
        let qbit = QbitState::uniform(4, TEST_PRIME);
        assert_eq!(qbit.num_states(), 4);
        assert_eq!(qbit.norm_sq, 4);

        // All probabilities should be equal
        for i in 0..4 {
            let (num, den) = qbit.probability(i);
            assert_eq!(num * 4, den); // 1/4 each
        }
    }

    #[test]
    fn test_qbit_rotation() {
        let mut qbit = QbitState::uniform(4, TEST_PRIME);

        // Rotate toward state 0
        qbit.rotate_toward(0, 3);

        // State 0 should now have higher probability
        let (p0_num, p0_den) = qbit.probability(0);
        let (p1_num, p1_den) = qbit.probability(1);

        // p0/p0_den > p1/p1_den ?
        // Cross multiply: p0_num * p1_den > p1_num * p0_den
        assert!(p0_num * p1_den > p1_num * p0_den);
    }

    #[test]
    fn test_qbit_measure_deterministic() {
        let qbit = QbitState::from_weights(vec![10, 1, 1, 1], TEST_PRIME);

        // Same seed should give same result
        let m1 = qbit.measure(42);
        let m2 = qbit.measure(42);
        assert_eq!(m1, m2);

        // State 0 has weight 10, others have weight 1
        // Most measurements with various seeds should land on state 0
        let hits_on_0 = (0..100).filter(|&s| qbit.measure(s) == 0).count();
        assert!(hits_on_0 > 50, "State 0 should dominate");
    }

    #[test]
    fn test_gso_swarm_iteration() {
        let primes = vec![17, 19, 23];
        let positions: Vec<ManaStream> = (0..5)
            .map(|i| ManaStream::from_ints(&[i * 10, i * 10 + 1], &primes))
            .collect();

        let params = GsoParams::default();
        let mut swarm = GsoSwarm::from_positions(positions, 8, TEST_PRIME, params);

        // Simple fitness: sum of first coefficients
        let fitness_fn = |pos: &ManaStream| -> u64 { pos.lanes[0].coeffs.iter().sum() };

        // Run a few iterations
        for _ in 0..10 {
            swarm.tick(fitness_fn);
        }

        let stats = swarm.stats();
        assert_eq!(stats.num_agents, 5);
        assert!(stats.iteration == 10);
    }

    #[test]
    fn test_agent_luciferin_update() {
        let primes = vec![17, 19];
        let position = ManaStream::from_ints(&[1, 2, 3], &primes);
        let qbit = QbitState::uniform(4, TEST_PRIME);
        let mut agent = QbitAgent::new(0, position, qbit);

        // Initial state
        assert_eq!(agent.luciferin, 0);
        assert_eq!(agent.best_fitness, 0);

        // Update with fitness
        agent.update_luciferin(1000, 400, 600);

        // Should have luciferin now
        assert!(agent.luciferin > 0);
        assert_eq!(agent.best_fitness, 1000);
    }
}
