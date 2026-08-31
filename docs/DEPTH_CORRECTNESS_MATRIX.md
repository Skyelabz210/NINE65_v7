# Depth-Correctness Matrix

Generated on 2026-08-31 09:38:22 UTC

## Symmetric Mode Depth Verification

This matrix shows the maximum depth achieved and correctness verification for each secure configuration.

| Config | Max Depth Achieved | Total Collapses | Correctness Verified | Avg Time/Mul |
|--------|-------------------|-----------------|---------------------|--------------|
| secure_128 | 50 | 0 | ✓ PASS | 100.15ms |
| secure_192 | 50 | 0 | ✓ PASS | 234.60ms |


## Pass/Fail Thresholds

- **Max Depth Target**: 50 levels for symmetric mode
- **Collapses Limit**: 0 (no collapses allowed for verified correctness)
- **Correctness**: Verified if max depth ≥ 50 AND total collapses = 0

## Notes

- Collapses indicate when noise budget is exceeded and rescaling occurs
- For symmetric mode, 0 collapses indicates that the computation maintained full precision
- All tested configurations achieved the target depth of 50 levels without collapses
