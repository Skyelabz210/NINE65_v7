# Public Mode Depth Baseline (2026-01-27)

Command:
- cargo test -p nine65 ops::rns_fhe::tests::test_public_mode_depth_sweep -- --ignored --nocapture

Configs and results:

## standard_128 (N=4096, t=65537)
- base=2^16: max depth 4 (fail at depth 5)
- base=2^12: max depth 4 (fail at depth 5)
- base=2^10: max depth 4 (fail at depth 5)
- base=2^8:  max depth 5 (fail at depth 6)

## high_192 (N=8192, t=65537)
- base=2^16: max depth 4 (fail at depth 5)
- base=2^12: max depth 4 (fail at depth 5)
- base=2^10: max depth 4 (fail at depth 5)
- base=2^8:  max depth 4 (fail at depth 5)

## Diagnostic (light_rns_exact)
- test_mul_dual_public_mode_deep: depth-2 failed (expected 120, got 32)
- Command: cargo test -p nine65 ops::rns_fhe::tests::test_mul_dual_public_mode_deep -- --ignored --nocapture
