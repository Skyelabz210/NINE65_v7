Project: NINE65 v5
Date: 2026-02-11
Purpose: unresolved questions that block a fully credible benchmark and validation program

## Question Matrix

| ID | Question | Why it matters | Resolution method | Owner | Target |
|---|---|---|---|---|---|
| Q01 | Which metric profile is official for external claims (`secure_128`, `secure_192`, `secure_256`, or profile set)? | Prevents selective reporting and confusion | Governance decision plus docs policy update | Core + Docs | Week 1 |
| Q02 | Should `light_rns_exact` numbers remain in headline docs or move to internal engineering appendix only? | Avoids mismatch between test-focused and deployment-focused messaging | Benchmark policy vote with security sign-off | Core + Security | Week 1 |
| Q03 | Which comparison targets (OpenFHE, SEAL, TFHE-rs, HElib, others) are in official scope for recurring comparison runs? | Sets reproducible comparison perimeter | Create comparator list and version pin file | Perf Eng | Week 1 |
| Q04 | What parameter-equivalence mapping will be used for cross-library comparisons? | Ensures fairness and technical legitimacy | Publish parameter map schema and review by cryptography owner | Crypto | Week 2 |
| Q05 | Is benchmark CI warning-only acceptable, or should critical benchmarks be merge-blocking? | Direct impact on regression control | Run historical replay and false-positive analysis; choose policy | DevOps + Perf | Week 2 |
| Q06 | What is the minimum statistical standard for publishing performance deltas (sample size, confidence interval, run count)? | Prevents overfitting and noise-driven claims | Write benchmark statistics standard and gate in scripts | Perf Eng | Week 2 |
| Q07 | Which environment fields are mandatory for every benchmark artifact (CPU governor, kernel, rustc, commit, feature flags, seed)? | Reproducibility and artifact integrity | Introduce schema validation before artifact publish | DevOps | Week 2 |
| Q08 | Do we require instruction-level benchmarking (for noise-resistant comparisons) in addition to wall-clock benchmarking? | Reduces host variability effects | Evaluate callgrind-style pipeline and adopt or reject explicitly | Perf Eng | Week 3 |
| Q09 | What is the release gate for side-channel readiness before any production language can appear? | High-stakes security control | Define measurable exit criteria and sign-off workflow | Security | Week 3 |
| Q10 | What is the policy for deprecated or stale benchmark docs (auto-archive vs hard-fail docs check)? | Prevents drift between docs and code | Implement docs freshness check in CI | Docs + DevOps | Week 3 |
| Q11 | Should benchmark claims in `README.md` be generated automatically from machine-readable baseline artifacts? | Eliminates manual copy drift | Build docs generation pipeline and remove manual tables | Docs + Tooling | Week 4 |
| Q12 | How will proprietary feature-path evidence (`accelerated`) be surfaced for reviewers without exposing private code? | Confidence in optional acceleration paths | Signed evidence package from private CI with public digest | Core + DevOps | Week 4 |
| Q13 | What end-to-end service benchmark scenarios are mandatory (single session, concurrent sessions, mixed op payloads, large ciphertext payloads)? | Captures real deployment behavior | Define macrobench suite and acceptance thresholds | Backend + Perf | Week 4 |
| Q14 | What is the canonical noise-budget and correctness envelope for public-mode depth testing under secure configs? | Avoids ambiguous depth claims | Add explicit depth-correctness matrix with pass/fail thresholds | Crypto | Week 4 |
| Q15 | Should baseline regeneration be per merge, nightly, or release-only for different benchmark tiers? | Balances cost and freshness | Adopt tiered cadence policy (smoke/nightly/release) | DevOps + Perf | Week 5 |
| Q16 | How many historical artifact sets (v2, early v5, pre-upgrade snapshots) must remain in active analysis context? | Reduces stale-analysis contamination | Define lineage policy and archive index | Docs + PM | Week 5 |
| Q17 | Which fuzz targets become mandatory CI jobs and what runtime budget is acceptable? | Security and robustness assurance | Add scheduled fuzz gate and monitor flake rate | Security + DevOps | Week 5 |
| Q18 | What is the policy for benchmark claims when measured values hit timer resolution limits (for example 0ns rows)? | Prevents invalid headline numbers | Require higher-precision harness or larger workload scaling | Perf Eng | Week 5 |
| Q19 | Should service-level SLOs be defined now (p95/p99 latency by operation and config)? | Needed for production readiness planning | Draft SLO proposal from macrobench data | Backend + SRE | Week 6 |
| Q20 | Who is the final approving authority for benchmark publication and claim language changes? | Ownership clarity and faster execution | Assign formal approver matrix in runbook | PM + Core | Week 6 |
