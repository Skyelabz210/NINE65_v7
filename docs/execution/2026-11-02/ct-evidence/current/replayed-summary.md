### Dudect measurement evidence

Evidence status: **inconclusive**. Constant-time certification is not established.
Inconclusive observations retain the existing nonblocking policy; they are not below-threshold evidence.

| Test | Observable | Measurement verdict | Control t | Signal t |
| --- | --- | --- | --- | --- |
| test_ct_dudect_montgomery_pow_exponent_hamming_weight | MontgomeryContext::montgomery_pow — exponent Hamming weight 8 vs 56 (batched) | inconclusive | 6.3406 | 2.0117 |
| test_ct_dudect_montgomery_reduce_operand_magnitude | MontgomeryContext::montgomery_reduce — small cofactor vs top-bit cofactor (batched) | inconclusive | 6.3649 | 4.0619 |
| test_ct_dudect_montgomery_mul_operand_magnitude | MontgomeryContext::montgomery_mul — small operands vs near-modulus operands (batched) | below_threshold | 4.8804 | 4.1648 |
| test_ct_dudect_barrett_reduce_operand_magnitude | BarrettContext::reduce_ct — 40-bit dividends vs 128-bit dividends (batched) | inconclusive | 11.2538 | 12.2974 |
| test_ct_dudect_mod_switch_rescale_sign_classes | mod_switch_down_dual — positive-centred vs negative-centred coefficients              (magnitude-matched) | below_threshold | 1.1210 | 0.3637 |
| test_ct_dudect_mod_switch_rescale_fixed_vs_random | U512::mod_u256 — zero vs uniform 128-bit dividends | below_threshold | 1.7095 | 0.3482 |
| test_ct_dudect_mod_switch_rescale_fixed_vs_random | mod_switch_down_dual — all-zero coefficients vs uniform coefficients | below_threshold | 2.6404 | 1.4432 |
| test_ct_dudect_exact_prime_drop_fixed_vs_random | exact_modulus_switch_drop_poly — all-zero residues vs uniform residues | below_threshold | 1.6588 | 1.5862 |
| test_ct_dudect_exact_prime_drop_small_vs_large_residues | exact_modulus_switch_drop_poly — small residues vs near-modulus residues | below_threshold | 1.0383 | 0.1279 |
| test_ct_dudect_adjacency_k_elim_operand_magnitude | AdjacencyKElim::extract_k — small operands vs near-cap operands (batched) | below_threshold | 2.1644 | 2.2745 |
| test_ct_dudect_adjacency_k_elim_operand_order | AdjacencyKElim::extract_k — sorted operands vs randomised order (batched) | below_threshold | 0.7019 | 0.3939 |
