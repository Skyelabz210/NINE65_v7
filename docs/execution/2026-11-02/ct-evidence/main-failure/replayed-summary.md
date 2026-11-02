### Dudect measurement evidence

Evidence status: **timing_dependence**. Constant-time certification is not established.
Inconclusive observations retain the existing nonblocking policy; they are not below-threshold evidence.

| Test | Observable | Measurement verdict | Control t | Signal t |
| --- | --- | --- | --- | --- |
| test_ct_dudect_montgomery_pow_exponent_hamming_weight | MontgomeryContext::montgomery_pow — exponent Hamming weight 8 vs 56 (batched) | below_threshold | 1.0674 | 1.3906 |
| test_ct_dudect_montgomery_reduce_operand_magnitude | MontgomeryContext::montgomery_reduce — small cofactor vs top-bit cofactor (batched) | below_threshold | 1.1049 | 0.6942 |
| test_ct_dudect_montgomery_mul_operand_magnitude | MontgomeryContext::montgomery_mul — small operands vs near-modulus operands (batched) | timing_dependence | 1.4003 | 8.6550 |
| test_ct_dudect_barrett_reduce_operand_magnitude | BarrettContext::reduce_ct — 40-bit dividends vs 128-bit dividends (batched) | below_threshold | 0.2273 | 0.8878 |
| test_ct_dudect_mod_switch_rescale_sign_classes | mod_switch_down_dual — positive-centred vs negative-centred coefficients              (magnitude-matched) | below_threshold | 0.1421 | 0.5403 |
| test_ct_dudect_mod_switch_rescale_fixed_vs_random | U512::mod_u256 — zero vs uniform 128-bit dividends | below_threshold | 1.3111 | 0.1984 |
| test_ct_dudect_mod_switch_rescale_fixed_vs_random | mod_switch_down_dual — all-zero coefficients vs uniform coefficients | below_threshold | 0.8117 | 0.2027 |
| test_ct_dudect_exact_prime_drop_fixed_vs_random | exact_modulus_switch_drop_poly — all-zero residues vs uniform residues | below_threshold | 0.3763 | 0.3404 |
| test_ct_dudect_exact_prime_drop_small_vs_large_residues | exact_modulus_switch_drop_poly — small residues vs near-modulus residues | below_threshold | 0.1723 | 1.3070 |
| test_ct_dudect_adjacency_k_elim_operand_magnitude | AdjacencyKElim::extract_k — small operands vs near-cap operands (batched) | below_threshold | 0.0621 | 1.2620 |
| test_ct_dudect_adjacency_k_elim_operand_order | AdjacencyKElim::extract_k — sorted operands vs randomised order (batched) | below_threshold | 2.0232 | 0.0526 |
