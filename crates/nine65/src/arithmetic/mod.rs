//! Arithmetic Module - QMNF Integer-Only Foundations
//!
//! ZERO floating point. ALL computations exact.
//!
//! Core Components:
//! - **Persistent Montgomery**: Never leave Montgomery form (50-100× speedup)
//! - **NTT Gen 3**: Negacyclic convolution with ψ-twist
//! - **RNS/CRT**: Parallel computation across coprime moduli
//! - **K-Elimination**: Exact polynomial division (50× speedup)
//! - **Exact Divider**: Dual-track integer reconstruction
//! - **Exact Coeff**: Dual-track coefficient representation
//! - **CT Mul Exact**: Exact ciphertext multiplication
//! - **MobiusInt**: Signed arithmetic (no M/2 threshold failure)
//! - **Padé/Exact Transcendentals**: Integer-only transcendentals (exp/sin/cos/log)
//! - **MQ-ReLU**: O(1) sign detection via q/2 threshold
//! - **Integer Softmax**: Exact sum guarantee softmax
//! - **Cyclotomic Phase**: Native ring trig (sin/cos via coefficient extraction)

pub mod barrett;
pub mod ct_mul_exact; // EXACT CT×CT
pub mod cyclotomic_phase; // NATIVE RING TRIGONOMETRY
pub mod exact_coeff; // DUAL-TRACK COEFFICIENTS
pub mod exact_divider; // K-ELIMINATION PRIMITIVE
pub mod integer_math;
pub mod integer_softmax; // EXACT SUM SOFTMAX
pub mod k_elimination; // EXACT DIVISION
pub mod mobius_int; // SIGNED ARITHMETIC (no M/2 threshold failure)
pub mod montgomery;
pub mod mq_relu; // O(1) SIGN DETECTION
pub mod ntt;
pub mod ntt_fft; // V2: O(N log N) FFT-based NTT (500-2000× faster)
pub mod order_finding; // NON-CIRCULAR BSGS (Shor's classical reduction)
pub mod pade_engine; // INTEGER TRANSCENDENTALS (exp/sin/cos/sigmoid)
pub mod persistent_montgomery; // MONTGOMERY FORM
pub mod rns;
pub mod transcendental_backend; // FEATURE-GATED EXACT TRANSCENDENTAL ADAPTER
pub mod valuation; // INTEGER UTILITIES (log2, sqrt, format, trig LUT)

pub use barrett::{BarrettContext, HybridModContext};
pub use montgomery::MontgomeryContext;
pub use persistent_montgomery::{PersistentMontgomery, PersistentPolynomial};

// NTT: Use FFT version (O(N log N)) when feature enabled, else DFT (O(N²))
#[cfg(not(feature = "ntt_fft"))]
pub use ntt::NTTEngine;
#[cfg(feature = "ntt_fft")]
pub use ntt_fft::NTTEngineFFT as NTTEngine;

// Also export both explicitly for users who need specific version
pub use ct_mul_exact::{ExactCiphertext, ExactCiphertext2, ExactFHEContext};
pub use cyclotomic_phase::{
    modular_distance, toric_coupling, CyclotomicPolynomial, CyclotomicRing,
};
pub use exact_coeff::{AnchorTrack, ExactCoeff, ExactContext, ExactPoly, RnsInner};
pub use exact_divider::ExactDivider;
pub use integer_math::{
    fixed_cos_sin, format_as_bits, format_millibits, format_ops, integer_log2, integer_log2_u128,
    integer_sqrt, COS_SIN_TABLE, GOLDEN_ANGLE_Q30,
};
pub use integer_softmax::{IntegerSoftmax, SOFTMAX_SCALE};
pub use k_elimination::KElimination;
pub use mobius_int::{MobiusInt, MobiusPolynomial, MobiusVector, Polarity};
pub use mq_relu::{MQReLU, MQReLUPolynomial, Sign};
pub use ntt::NTTEngine as NTTEngineDFT;
pub use ntt_fft::NTTEngineFFT;
pub use order_finding::{
    factor_semiprime, factor_via_order, gcd, multiplicative_order, multiplicative_order_detailed,
    verify_order_k_elimination, FactorResult, KRecurrence, OrderResult,
};
pub use pade_engine::{PadeEngine, PADE_SCALE};
pub(crate) use rns::{compute_delta_rns_overflow_safe, U256};
pub use rns::{DualRNSContext, DualRNSPolynomial, DualRNSValue, RNSContext, RNSPolynomial};

#[cfg(feature = "exact_rational")]
pub mod rational_bridge;
#[cfg(feature = "exact_rational")]
pub use rational_bridge::RationalBridge;

#[cfg(feature = "clockwork")]
pub mod bounded_rns;
#[cfg(feature = "clockwork")]
pub use bounded_rns::BoundedValue;
