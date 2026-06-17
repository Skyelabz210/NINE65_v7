//! Digital Time Crystal — Phi-Resonant Integer Oscillator
//!
//! A phi-resonant oscillator with Fibonacci aperiodic gating.
//! Phase advances by Fibonacci step sizes mod M61 (2^61-1, Mersenne prime).
//! Gate events fire at Fibonacci-indexed tick counts, capturing phase snapshots
//! for deterministic entropy extraction.
//!
//! Zero floating point. All arithmetic exact integer (A1).

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

/// First 93 Fibonacci numbers (all fit in u64; F(92) = 7540113804746346429).
pub const FIB: [u64; 93] = {
    let mut f = [0u64; 93];
    f[0] = 0;
    f[1] = 1;
    let mut i = 2;
    while i < 93 {
        f[i] = f[i - 1] + f[i - 2];
        i += 1;
    }
    f
};

/// Golden ratio numerator: F(46) = 1836311903.
pub const PHI_NUM: u64 = 1_836_311_903;
/// Golden ratio denominator: F(45) = 1134903170.
pub const PHI_DEN: u64 = 1_134_903_170;

#[inline]
fn addmod(a: u64, b: u64, m: u64) -> u64 {
    ((a as u128 + b as u128) % m as u128) as u64
}

/// Crystal modulus: 2^61 - 1 (Mersenne prime M61).
pub const CRYSTAL_MODULUS: u64 = (1u64 << 61) - 1;

/// Phi-resonant oscillator. Phase advances by Fibonacci-quantized steps.
#[derive(Clone, Debug)]
pub struct PhiOscillator {
    phase: u64,
    fib_index: usize,
    tick_count: u64,
    modulus: u64,
}

impl PhiOscillator {
    pub fn new(seed: u64) -> Self {
        let phase = Self::hash_seed(seed);
        Self {
            phase,
            fib_index: 10,
            tick_count: 0,
            modulus: CRYSTAL_MODULUS,
        }
    }

    fn hash_seed(seed: u64) -> u64 {
        let mut h = seed;
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51afd7ed558ccd);
        h ^= h >> 33;
        h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
        h ^= h >> 33;
        h % CRYSTAL_MODULUS
    }

    pub fn tick(&mut self) {
        let step = FIB[self.fib_index];
        self.phase = addmod(self.phase, step, self.modulus);
        self.tick_count += 1;
        self.fib_index += 1;
        if self.fib_index >= 80 {
            self.fib_index = 10;
        }
    }

    pub fn tick_n(&mut self, n: u64) {
        for _ in 0..n {
            self.tick();
        }
    }

    pub fn phase(&self) -> u64 {
        self.phase
    }

    pub fn tick_count(&self) -> u64 {
        self.tick_count
    }

    pub fn extract_entropy(&self) -> [u8; 8] {
        let mixed = self.mix_phase();
        mixed.to_le_bytes()
    }

    fn mix_phase(&self) -> u64 {
        let mut h = self.phase;
        h ^= self.tick_count.wrapping_mul(PHI_NUM);
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51afd7ed558ccd);
        h ^= h >> 33;
        h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
        h ^= h >> 33;
        h
    }
}

/// Aperiodic gate that fires at Fibonacci-indexed tick counts.
#[derive(Clone, Debug)]
pub struct FibonacciGate {
    next_gate_index: usize,
    fire_count: u64,
    snapshots: Vec<u64>,
    max_snapshots: usize,
}

impl FibonacciGate {
    pub fn new() -> Self {
        Self {
            next_gate_index: 5,
            fire_count: 0,
            snapshots: Vec::new(),
            max_snapshots: 256,
        }
    }

    pub fn check(&mut self, tick_count: u64, phase: u64) -> bool {
        if self.next_gate_index >= 93 {
            self.next_gate_index = 10;
        }

        if tick_count >= FIB[self.next_gate_index] {
            self.fire_count += 1;
            self.snapshots.push(phase);
            if self.snapshots.len() > self.max_snapshots {
                self.snapshots.remove(0);
            }
            self.next_gate_index += 1;
            true
        } else {
            false
        }
    }

    pub fn fire_count(&self) -> u64 {
        self.fire_count
    }

    pub fn recent_snapshots(&self, n: usize) -> Vec<u64> {
        self.snapshots.iter().rev().take(n).copied().collect()
    }

    pub fn gate_entropy(&self) -> u64 {
        self.snapshots.iter().fold(0u64, |acc, &s| acc ^ s)
    }
}

impl Default for FibonacciGate {
    fn default() -> Self {
        Self::new()
    }
}

/// Complete Digital Time Crystal: oscillator + gate.
#[derive(Clone, Debug)]
pub struct TimeCrystal {
    oscillator: PhiOscillator,
    gate: FibonacciGate,
}

/// Event emitted when the gate fires.
#[derive(Clone, Debug)]
pub struct GateEvent {
    pub tick: u64,
    pub phase: u64,
    pub entropy: [u8; 8],
    pub fire_count: u64,
    pub cumulative_entropy: u64,
}

impl TimeCrystal {
    pub fn new(seed: u64) -> Self {
        Self {
            oscillator: PhiOscillator::new(seed),
            gate: FibonacciGate::new(),
        }
    }

    pub fn tick(&mut self) -> Option<GateEvent> {
        self.oscillator.tick();

        let fired = self
            .gate
            .check(self.oscillator.tick_count(), self.oscillator.phase());

        if fired {
            Some(GateEvent {
                tick: self.oscillator.tick_count(),
                phase: self.oscillator.phase(),
                entropy: self.oscillator.extract_entropy(),
                fire_count: self.gate.fire_count(),
                cumulative_entropy: self.gate.gate_entropy(),
            })
        } else {
            None
        }
    }

    pub fn tick_n(&mut self, n: u64) -> Vec<GateEvent> {
        let mut events = Vec::new();
        for _ in 0..n {
            if let Some(event) = self.tick() {
                events.push(event);
            }
        }
        events
    }

    pub fn tick_until_gate(&mut self, max_ticks: u64) -> Option<GateEvent> {
        for _ in 0..max_ticks {
            if let Some(event) = self.tick() {
                return Some(event);
            }
        }
        None
    }

    pub fn phase(&self) -> u64 {
        self.oscillator.phase()
    }

    pub fn tick_count(&self) -> u64 {
        self.oscillator.tick_count()
    }

    pub fn gate_fire_count(&self) -> u64 {
        self.gate.fire_count()
    }

    pub fn cumulative_entropy(&self) -> u64 {
        self.gate.gate_entropy()
    }

    pub fn extract_entropy(&self) -> [u8; 8] {
        self.oscillator.extract_entropy()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fibonacci_table_correct() {
        assert_eq!(FIB[0], 0);
        assert_eq!(FIB[1], 1);
        assert_eq!(FIB[2], 1);
        assert_eq!(FIB[10], 55);
        assert_eq!(FIB[20], 6765);
        assert_eq!(FIB[45], PHI_DEN);
        assert_eq!(FIB[46], PHI_NUM);
        for i in 2..93 {
            assert_eq!(FIB[i], FIB[i - 1] + FIB[i - 2]);
        }
    }

    #[test]
    fn oscillator_deterministic() {
        let mut osc1 = PhiOscillator::new(42);
        let mut osc2 = PhiOscillator::new(42);
        for _ in 0..1000 {
            osc1.tick();
            osc2.tick();
        }
        assert_eq!(osc1.phase(), osc2.phase());
        assert_eq!(osc1.tick_count(), osc2.tick_count());
    }

    #[test]
    fn oscillator_different_seeds_diverge() {
        let mut osc1 = PhiOscillator::new(1);
        let mut osc2 = PhiOscillator::new(2);
        for _ in 0..100 {
            osc1.tick();
            osc2.tick();
        }
        assert_ne!(osc1.phase(), osc2.phase());
    }

    #[test]
    fn oscillator_phase_bounded() {
        let mut osc = PhiOscillator::new(0);
        for _ in 0..10000 {
            osc.tick();
            assert!(osc.phase() < CRYSTAL_MODULUS);
        }
    }

    #[test]
    fn gate_fires_at_fibonacci_ticks() {
        let mut gate = FibonacciGate::new();
        for t in 1..5 {
            assert!(!gate.check(t, t * 100));
        }
        assert!(gate.check(5, 500));
        assert_eq!(gate.fire_count(), 1);
    }

    #[test]
    fn gate_fires_increase_monotonically() {
        let mut gate = FibonacciGate::new();
        let mut last_fire = 0u64;
        for t in 1..10000 {
            if gate.check(t, t) {
                assert!(t > last_fire);
                last_fire = t;
            }
        }
        assert!(gate.fire_count() > 5);
    }

    #[test]
    fn crystal_deterministic() {
        let mut c1 = TimeCrystal::new(42);
        let mut c2 = TimeCrystal::new(42);
        let events1 = c1.tick_n(1000);
        let events2 = c2.tick_n(1000);
        assert_eq!(events1.len(), events2.len());
        for (e1, e2) in events1.iter().zip(&events2) {
            assert_eq!(e1.tick, e2.tick);
            assert_eq!(e1.phase, e2.phase);
            assert_eq!(e1.entropy, e2.entropy);
        }
    }

    #[test]
    fn crystal_produces_gate_events() {
        let mut crystal = TimeCrystal::new(0);
        let events = crystal.tick_n(10000);
        assert!(events.len() >= 10);
    }

    #[test]
    fn crystal_tick_until_gate() {
        let mut crystal = TimeCrystal::new(99);
        let event = crystal.tick_until_gate(10000);
        assert!(event.is_some());
        let e = event.unwrap();
        assert!(e.tick > 0);
        assert_eq!(e.fire_count, 1);
    }

    #[test]
    fn crystal_entropy_nonzero() {
        let mut crystal = TimeCrystal::new(42);
        crystal.tick_n(1000);
        let entropy = crystal.cumulative_entropy();
        assert_ne!(entropy, 0);
    }

    #[test]
    fn crystal_aperiodic_gate_spacing() {
        let mut crystal = TimeCrystal::new(7);
        let events = crystal.tick_n(10000);
        if events.len() >= 3 {
            let spacings: Vec<u64> = events.windows(2).map(|w| w[1].tick - w[0].tick).collect();
            let all_same = spacings.windows(2).all(|w| w[0] == w[1]);
            assert!(!all_same);
        }
    }

    #[test]
    fn crystal_phase_readout() {
        let mut crystal = TimeCrystal::new(42);
        let initial_phase = crystal.phase();
        crystal.tick_n(100);
        let after_phase = crystal.phase();
        assert_ne!(initial_phase, after_phase);
        assert_eq!(crystal.tick_count(), 100);
    }
}
