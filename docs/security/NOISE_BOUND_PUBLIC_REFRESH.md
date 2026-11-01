# Noise bound for PublicRefreshCircuit

Current routing: [public refresh status](../PUBLIC_REFRESH_STATUS.md).

This note separates the deterministic certificate the code computes from a probabilistic decryption-failure bound, which is not derived.

## What the certificate is

`PublicRefreshCircuitPlan::new` refuses to build a plan unless every checked bound fits. The native plan is `native_research`. `security_bits` on that tuple is 0. The certificate is an infinity-norm envelope, not a measured error and not a tail bound.

The refresh path in `PublicRefreshCircuit::refresh_with_progress` is:

1. Source preparation under the dense work key, then the sparse switch. Drop rounding is charged while the ciphertext is still under the work key (`PublicRefreshSourcePlan::bounds`).
2. Coherent phase evaluation. The support proof in [PUBLIC_REFRESH_LIFT_REFINEMENT.md](../execution/2026-10-31/PUBLIC_REFRESH_LIFT_REFINEMENT.md) gives `|x| ≤ 3,178,496`, `|rho| ≤ 49`, and `|K_native| ≤ 48`.
3. Encrypted carry extraction: `SplitDigitEvaluator::evaluate_prepared_with_progress` on the high and low phase outputs. This is the G/H quotient step. It is not an older line number in a previous file.
4. Fused restoration: `AdjacentLiftRestorationCertificate::apply` adds the affine ciphertext and the carry. The certificate records zero additional ciphertext products. It does not materialize remainder ciphertexts.
5. Slot return, charging `input_error_factor` and `added_error`.
6. Return to the work key: `ReturnNoisePlan::output_bound` scales by t, drops the extra boot primes, adds switch error `t · N_boot · eta · (2^base_bits − 1) · digits`, and refuses if the result exceeds `Q_work / 2`.

The published native figures, quoted from that lift note and not recomputed in this change, are 517 bits before slot return and 562 bits after, against a 633-bit threshold. The next square-then-source radius is 48, inside support 49. If this prose and the executable certificate disagree, the executable certificate wins and this sentence has to be updated from the new preflight.

## What a failure probability would have to be

Under this infinity-norm model, an accepted `output_bound` means the certified error sits strictly below `Q/2`, so the model's decryption-failure event for that return is empty. That is a predicate of the model. A probabilistic decryption-failure bound is not derived.

In particular, this repository does not publish:

* a standard-deviation or subgaussian tail for the return error;
* `Pr[decrypt fail]` as a function of the parameters;
* a union bound over `2^k` refreshes.

The next-radius check is a worst-case fixed point of the same envelope (returned bound, one square, one source conversion, still inside the planned support). It is not a concentration result. Headroom against the screening budget is the documented gap between the 562-bit certificate and the 633-bit threshold. It is not a statistical margin.

Malformed inputs are refused when lineage, radius, family, or the key inventory does not match the plan. Those refusals are not a failure-probability calculation.
