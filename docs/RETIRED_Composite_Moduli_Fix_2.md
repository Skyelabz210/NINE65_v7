# RETIRED: CRITICAL_Composite_Moduli_Fix_2.md

This document has been retired and is no longer treated as live guidance.

The security and parameter classifications formerly discussed here have been superseded by the **NINE65 v8 "Shadow Butterfly" Parameter Specification** and the **Separation Principle**.

### Reference Specification
- **Implementation**: `crates/nine65/src/arithmetic/k_elimination.rs`
- **Theory**: QMNF Separation Principle (Theorem 2.1)

### Key Reclassifications
1. **CLASS-F Moduli**: NTT-adjacent moduli (alpha track) MUST remain prime.
2. **CLASS-R Moduli**: Anchor track moduli (beta track) require only pairwise coprimality. Composite values are permitted and encouraged for hardware optimization.

Current production configurations (Minimal, Standard, Extended, Maximum, and HardwareOpt) in `crates/nine65/src/params/secure_configs.rs` adhere to these v8 requirements.
