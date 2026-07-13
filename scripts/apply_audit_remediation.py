#!/usr/bin/env python3
"""Apply the July 2026 NINE65 audit remediation deterministically.

This one-shot script is executed on the audit remediation branch by GitHub Actions.
It performs exact text substitutions, writes regression tests and the remediation
record, and aborts if the expected source state has drifted.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def write(rel: str, text: str) -> None:
    path = ROOT / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one literal match, found {count}")
    return text.replace(old, new, 1)


def sub_once(text: str, pattern: str, replacement: str, label: str) -> str:
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.DOTALL | re.MULTILINE)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one regex match, found {count}")
    return updated


def patch_secure_configs() -> None:
    rel = "crates/nine65/src/params/secure_configs.rs"
    text = read(rel)

    text = replace_once(
        text,
        "//! | `secure_128` | 4096 | 90 | 129-bit | 86-bit | 129-bit |",
        "//! | `secure_128` | 8192 | 90 | internally screened; external estimate required |",
        "secure_128 header table",
    )
    text = replace_once(
        text,
        "//! Production-ready FHE parameter sets with verified security levels.",
        "//! Production parameter candidates with fail-closed internal screening.",
        "security module posture",
    )
    text = replace_once(
        text,
        "//! All configurations in this module have been validated against:",
        "//! Configurations in this module are checked against:",
        "security validation wording",
    )
    text = replace_once(
        text,
        "    /// Verified classical security bits\n    pub classical_security: u32,",
        "    /// Security claim that this configuration must satisfy.\n    pub claimed_security: u32,\n    /// Internal classical screening result in bits.\n    pub classical_security: u32,",
        "claimed security field",
    )

    text = sub_once(
        text,
        r"        // RUNTIME ASSERTION: Verify claimed security matches actual security\n.*?\n        let config = FHEConfig \{",
        """        // Fail closed: a named production claim must pass the complete internal\n        // screening result. External lattice-estimator output remains mandatory for\n        // a release/security attestation; this heuristic is not a certificate.\n        #[cfg(not(any(test, feature = \"allow_insecure\")))]\n        assert!(\n            estimate.effective_bits >= claimed_security,\n            \"SECURITY ERROR: Config '{}' claims {} bits but the internal screening result is {} bits.\\n\\\n             Increase N, reduce Q, or lower the claim.\",\n            name,\n            claimed_security,\n            estimate.effective_bits,\n        );\n\n        let config = FHEConfig {""",
        "strict security assertion",
    )
    text = replace_once(
        text,
        "            security_bits: estimate.effective_bits as usize,",
        "            security_bits: claimed_security as usize,",
        "FHEConfig security claim",
    )
    text = replace_once(
        text,
        "        Self {\n            config,\n            classical_security: estimate.classical_bits,",
        "        Self {\n            config,\n            claimed_security,\n            classical_security: estimate.classical_bits,",
        "SecureConfig initializer",
    )
    text = replace_once(
        text,
        "        self.hybrid_security >= 128 && self.he_standard_compliant",
        "        self.hybrid_security >= self.claimed_security && self.he_standard_compliant",
        "production-safe predicate",
    )

    text = sub_once(
        text,
        r"    /// # Security Analysis\n.*?    /// # Performance\n",
        """    /// # Security posture\n    /// - N=8192, raised from 4096 after the July 2026 independent audit.\n    /// - The internal estimator is a deterministic screening gate, not an\n    ///   independent security certificate.\n    /// - Release attestations must archive an external lattice-estimator run.\n    ///\n    /// # Performance\n""",
        "secure_128 documentation",
    )
    text = sub_once(
        text,
        r"(    pub fn secure_128\(\) -> Self \{\n        // N=)4096( with log\(Q\)~90 bits \(3x30-bit primes\)\n        // HE Standard allows up to 109 bits for 128-bit security at N=4096\n        Self::new_verified\(\n            )4096,",
        r"\g<1>8192\g<2>8192,",
        "secure_128 ring dimension",
    )
    text = replace_once(
        text,
        "    /// - Polynomial degree: 4096",
        "    /// - Polynomial degree: 8192",
        "secure_128 performance N",
    ) if "    /// - Polynomial degree: 4096" in text else text

    text = sub_once(
        text,
        r"pub fn assert_production_safe_fhe_config\(config: &crate::params::FHEConfig\) \{.*?\n\}",
        """pub fn assert_production_safe_fhe_config(config: &crate::params::FHEConfig) {\n    if cfg!(any(test, debug_assertions, feature = \"allow_insecure\")) {\n        return;\n    }\n\n    let log_q: u32 = config.primes.iter().map(|&p| 64 - p.leading_zeros()).sum();\n    let required_security = (config.security_bits as u32).max(128);\n    let estimator = crate::params::security_estimator::LatticeSecurityEstimator::default();\n    let estimate = estimator.estimate(\n        config.n,\n        log_q,\n        crate::params::security_estimator::SecretDistribution::Ternary,\n        required_security,\n    );\n\n    if estimate.effective_bits < required_security {\n        panic!(\n            \"PRODUCTION SECURITY VIOLATION: Config '{}' screens at {} bits ({} required).\\n\\\n             Analysis: {}\\n\\\n             Action: Increase N or decrease the number/size of RNS primes.\",\n            config.name, estimate.effective_bits, required_security, estimate.analysis\n        );\n    }\n}""",
        "raw FHEConfig production gate",
    )

    text = sub_once(
        text,
        r"pub fn verify_production_safety\(config: &SecureConfig\) -> Result<\(\), String> \{.*?\n\}",
        """pub fn verify_production_safety(config: &SecureConfig) -> Result<(), String> {\n    if config.hybrid_security < config.claimed_security {\n        return Err(format!(\n            \"Config '{}' fails its security claim: internal hybrid screening={} bits, claim={} bits\",\n            config.config.name, config.hybrid_security, config.claimed_security\n        ));\n    }\n\n    if !config.he_standard_compliant {\n        return Err(\"Not HE Standard v1.1 compliant\".to_string());\n    }\n\n    if config.config.n < 8192 && config.claimed_security >= 128 {\n        return Err(format!(\n            \"Polynomial degree N={} is below the audited production floor N=8192\",\n            config.config.n\n        ));\n    }\n\n    Ok(())\n}""",
        "verify_production_safety",
    )

    text = sub_once(
        text,
        r"        // N=4096 with log\(Q\)~90 bits should give >100 bits security\n        assert!\(\n            config\.hybrid_security >= 100,\n            \"secure_128 should have >= 100 bits hybrid security, got \{\}\",\n            config\.hybrid_security\n        \);\n        assert!\(config\.is_production_safe\(\)\);",
        """        assert_eq!(config.config.n, 8192, \"audited secure_128 floor\");\n        assert!(\n            config.hybrid_security >= config.claimed_security,\n            \"secure_128 internal screening {} is below claim {}\",\n            config.hybrid_security,\n            config.claimed_security\n        );\n        assert!(config.is_production_safe());""",
        "secure_128 test",
    )
    text = text.replace(
        "// N=8192 with log(Q)~150 bits should give >150 bits security",
        "// secure_192 must satisfy its complete named claim",
    )
    text = replace_once(
        text,
        "            config.hybrid_security >= 150,\n            \"secure_192 should have >= 150 bits hybrid security, got {}\",",
        "            config.hybrid_security >= config.claimed_security,\n            \"secure_192 should meet its {}-bit claim, got {}\",\n            config.claimed_security,",
        "secure_192 test threshold",
    )

    write(rel, text)


def patch_params() -> None:
    rel = "crates/nine65/src/params/mod.rs"
    text = read(rel)
    text = text.replace(
        "//! | `SecureConfig::secure_128()` | 4096 | 128-bit | **128-bit** | PRODUCTION |",
        "//! | `SecureConfig::secure_128()` | 8192 | 128-bit | externally estimated per release | PRODUCTION CANDIDATE |",
    )
    text = text.replace(
        "//! | `SecureConfig::secure_192()` | 8192 | 192-bit | **192-bit** | PRODUCTION |",
        "//! | `SecureConfig::secure_192()` | 16384 | 192-bit | externally estimated per release | PRODUCTION CANDIDATE |",
    )
    text = replace_once(
        text,
        "        // Estimate security\n        let security_bits = estimate_security(n, primes[0]);",
        """        if primes.iter().any(|&p| t >= p) {\n            return Err(\"Plaintext modulus must be smaller than every RNS prime\");\n        }\n\n        // Estimate security\n        let security_bits = estimate_security(n, primes[0]);""",
        "custom plaintext modulus validation",
    )

    text = sub_once(
        text,
        r"    /// Get the effective modulus product Q for RNS configs\..*?    pub fn rns_noise_budget_millibits\(&self\) -> u64 \{.*?\n    \}",
        """    /// Return the exact RNS product when it fits in `u128`.\n    ///\n    /// Large production chains intentionally return `None`; callers must not\n    /// substitute saturation or wrapping for the true modulus product.\n    pub fn try_rns_product(&self) -> Option<u128> {\n        self.primes\n            .iter()\n            .try_fold(1u128, |acc, &p| acc.checked_mul(p as u128))\n    }\n\n    /// Return the exact RNS product and fail closed if it exceeds `u128`.\n    pub fn rns_product(&self) -> u128 {\n        self.try_rns_product().expect(\n            \"RNS product exceeds u128; use rns_product_bit_length() or a wide-integer path\",\n        )\n    }\n\n    /// Exact bit length of the RNS modulus product using eight 64-bit limbs.\n    ///\n    /// This handles products up to 512 bits without floating-point arithmetic.\n    pub fn rns_product_bit_length(&self) -> u32 {\n        let mut limbs = [0u64; 8];\n        limbs[0] = 1;\n\n        for &factor in &self.primes {\n            let mut carry = 0u128;\n            for limb in &mut limbs {\n                let product = (*limb as u128) * (factor as u128) + carry;\n                *limb = product as u64;\n                carry = product >> 64;\n            }\n            assert_eq!(carry, 0, \"RNS product exceeds 512-bit accounting capacity\");\n        }\n\n        for index in (0..limbs.len()).rev() {\n            let limb = limbs[index];\n            if limb != 0 {\n                return index as u32 * 64 + (64 - limb.leading_zeros());\n            }\n        }\n        0\n    }\n\n    /// Conservative noise-budget estimate in millibits.\n    ///\n    /// For products above 128 bits, the delta bit length is bounded from below\n    /// using exact product and plaintext bit lengths. No saturated surrogate is\n    /// admitted into the calculation.\n    pub fn rns_noise_budget_millibits(&self) -> u64 {\n        if self.primes.len() < 2 {\n            return self.noise_budget() as u64 * 1000;\n        }\n\n        let delta_bits = match self.try_rns_product() {\n            Some(q_product) => {\n                let delta = q_product / self.t as u128;\n                if delta == 0 {\n                    0\n                } else {\n                    128 - delta.leading_zeros()\n                }\n            }\n            None => {\n                let q_bits = self.rns_product_bit_length();\n                let t_bits = 64 - self.t.leading_zeros();\n                q_bits.saturating_sub(t_bits)\n            }\n        };\n\n        let eta_bits = self.eta as u32 + 1;\n        let n_bits_half = self.n.trailing_zeros() / 2;\n        let initial_noise_bits = eta_bits + n_bits_half + 3;\n\n        (delta_bits as u64).saturating_sub(initial_noise_bits as u64) * 1000\n    }""",
        "exact RNS product accounting",
    )

    text = replace_once(
        text,
        "                    \"RNS Q={}, RNS budget={}mb\",\n                    config.rns_product(),\n                    config.rns_noise_budget_millibits()",
        "                    \"RNS Q_bits={}, RNS budget={}mb\",\n                    config.rns_product_bit_length(),\n                    config.rns_noise_budget_millibits()",
        "params unit-test product display",
    )
    write(rel, text)


def patch_full_system_test() -> None:
    rel = "crates/nine65/tests/full_system_exercise.rs"
    text = read(rel)
    text = sub_once(
        text,
        r"        let q_prod = cfg\.rns_product\(\);\n        println!\(\n            \"\{:<30\} \{:>6\} \{:>8\} \{:>8\} \{:>8\} \{:>10\}\",\n            name,\n            cfg\.n,\n            cfg\.primes\.len\(\),\n            cfg\.q,\n            cfg\.t,\n            if q_prod > 1_000_000_000_000 \{\n                format!\(\"~2\^\{\}\", 128 - q_prod\.leading_zeros\(\)\)\n            \} else \{\n                format!\(\"\{\}\", q_prod\)\n            \}\n        \);",
        """        let q_display = match cfg.try_rns_product() {\n            Some(q_prod) if q_prod <= 1_000_000_000_000 => format!(\"{}\", q_prod),\n            Some(_) | None => format!(\"2^{} bits\", cfg.rns_product_bit_length()),\n        };\n        println!(\n            \"{:<30} {:>6} {:>8} {:>8} {:>8} {:>10}\",\n            name, cfg.n, cfg.primes.len(), cfg.q, cfg.t, q_display\n        );""",
        "full-system exact product display",
    )
    text = sub_once(
        text,
        r"    // Note: FHEConfig::custom does not currently reject t >= q\..*?    \}\n\n    println!\(\"\\nCustom config validation: all checks passed\.\"\);",
        """    let result = FHEConfig::custom(1024, vec![998244353], 998244354, 2);\n    assert!(result.is_err(), \"t >= an RNS prime must fail closed\");\n\n    println!(\"\\nCustom config validation: all checks passed.\");""",
        "custom-config regression in full-system test",
    )
    write(rel, text)


def patch_benchmark() -> None:
    rel = "crates/nine65/src/bin/nine65_bench.rs"
    text = read(rel)
    text = text.replace("use nine65::ops::auto_bootstrap::AutoBootstrapEvaluator;\n", "")
    text = replace_once(
        text,
        "use std::time::Instant;\n\nfn main() {",
        """use std::time::Instant;\n\nfn percent_floor(remaining: i64, total: i64) -> u64 {\n    if remaining <= 0 || total <= 0 {\n        return 0;\n    }\n    ((remaining as u128 * 100) / total as u128) as u64\n}\n\nfn rate_per_second(count: u64, elapsed_us: u64) -> u64 {\n    if elapsed_us == 0 {\n        0\n    } else {\n        ((count as u128 * 1_000_000) / elapsed_us as u128) as u64\n    }\n}\n\nfn main() {""",
        "integer benchmark helpers",
    )
    text = replace_once(
        text,
        "    // Select config\n    let config = match config_name.as_str() {",
        """    if max_depth == 0 {\n        eprintln!(\"--max-depth must be positive\");\n        std::process::exit(2);\n    }\n    if trigger_pct > 100 {\n        eprintln!(\"--trigger-pct must be in 0..=100\");\n        std::process::exit(2);\n    }\n\n    // Both flags request the real bootstrap path. Statistical verification\n    // cannot run against a simulated budget reset.\n    if auto_bootstrap || statistical_test {\n        with_bootstrap = true;\n    }\n\n    // Select config\n    let config = match config_name.as_str() {""",
        "benchmark argument validation",
    )
    text = sub_once(
        text,
        r"    let mut ct_result = encryptor\.encrypt\(init_a, &mut rng\);\n    let _ = budget\.consume\(NoiseOpType::Encrypt, NoiseBudget::encrypt_cost\(&config\)\);\n\n    // --- LEGACY INITIALIZATION ---\n    let mut ct_result = encryptor\.encrypt\(init_a, &mut rng\);",
        """    // --- LEGACY INITIALIZATION ---\n    let mut ct_result = encryptor.encrypt(init_a, &mut rng);\n    let _ = budget.consume(NoiseOpType::Encrypt, NoiseBudget::encrypt_cost(&config));""",
        "duplicate benchmark initialization",
    )
    text = text.replace(
        "    let noise_pct = (budget.remaining_millibits() as f64 / initial_budget_mb as f64 * 100.0) as u64;",
        "    let noise_pct = percent_floor(budget.remaining_millibits(), initial_budget_mb);",
    )
    text = replace_once(
        text,
        "    let mut total_refreshes: u64 = 0;\n    let mut depth: usize = 1;",
        "    let mut total_refreshes: u64 = 0;\n    let mut depth: usize = 1;\n    let mut terminated_on_budget = false;",
        "benchmark termination state",
    )
    text = sub_once(
        text,
        r"        let mut refreshed = false;\n        if consume_result\.is_err\(\) \|\| \(with_bootstrap && budget\.should_bootstrap\(trigger_pct \* 10\)\) \{.*?\n        \}\n\n        let noise_pct = \(budget\.remaining_millibits\(\) as f64 / initial_budget_mb as f64 \* 100\.0\)\n            \.max\(0\.0\) as u64;",
        """        let mut refreshed = false;\n        if consume_result.is_err() && !with_bootstrap {\n            terminated_on_budget = true;\n            depth = depth.saturating_sub(1);\n            eprintln!(\n                \"  Noise budget exhausted before requested operation count; terminating without fake refresh\"\n            );\n            break;\n        }\n\n        if with_bootstrap\n            && (consume_result.is_err() || budget.should_bootstrap(trigger_pct * 10))\n        {\n            let bk = boot_keys.as_ref().expect(\"real bootstrap keys\");\n            ct_dual = boot\n                .bootstrap(&ct_dual, &bk.bsk, &bk.ksk)\n                .expect(\"Bootstrap failed\");\n            budget.reset_after_bootstrap(&config);\n            total_refreshes += 1;\n            refreshed = true;\n            eprintln!(\n                \"  Operation {depth}: REAL BOOTSTRAP REFRESH (refresh #{})\",\n                total_refreshes\n            );\n        }\n\n        let noise_pct = percent_floor(budget.remaining_millibits(), initial_budget_mb);""",
        "remove simulated depth refresh",
    )
    text = replace_once(
        text,
        "    let correct = decrypted == plaintext_result;",
        "    let correct = !terminated_on_budget && decrypted == plaintext_result;",
        "depth-chain correctness state",
    )
    text = replace_once(
        text,
        "    let depth_per_sec = if total_chain_us > 0 {\n        (depth as f64 / (total_chain_us as f64 / 1_000_000.0)) as u64\n    } else {\n        0\n    };",
        "    let depth_per_sec = rate_per_second(depth as u64, total_chain_us);",
        "integer depth rate",
    )
    text = replace_once(
        text,
        "            \"max_depth\": max_depth,\n            \"nine65_version\": env!(\"CARGO_PKG_VERSION\"),",
        """            \"requested_operation_count\": max_depth,\n            \"chain_semantics\": \"mixed ct-plain operation count; not ct-ct multiplicative depth\",\n            \"bootstrap_mode\": if with_bootstrap { \"real\" } else { \"disabled\" },\n            \"nine65_version\": env!(\"CARGO_PKG_VERSION\"),""",
        "benchmark metadata semantics",
    )
    text = replace_once(
        text,
        "            \"correct\": correct,\n            \"decrypted_result\": decrypted,",
        "            \"correct\": correct,\n            \"terminated_on_budget\": terminated_on_budget,\n            \"decrypted_result\": decrypted,",
        "benchmark termination output",
    )
    text = text.replace('"max_depth_achieved": depth,', '"operations_achieved": depth,')
    text = text.replace('"depth_per_sec": depth_per_sec,', '"operations_per_sec": depth_per_sec,')
    text = text.replace('eprintln!("  Max depth: {depth}");', 'eprintln!("  Operations achieved: {depth}");')

    text = sub_once(
        text,
        r"/// Run a scale test workload and return JSON summary\n#\[allow\(clippy::too_many_arguments\)\]\nfn run_scale_test\(.*?\n\}\n\n/// Minimal timestamp without chrono dependency",
        """/// Run a scale-test workload without inventing ciphertext refreshes.\n#[allow(clippy::too_many_arguments)]\nfn run_scale_test(\n    config: &FHEConfig,\n    _ntt: &NTTEngine,\n    _encoder: &BFVEncoder,\n    encryptor: &BFVEncryptor,\n    evaluator: &BFVEvaluator,\n    rng: &mut ShadowHarvester,\n    target_operations: usize,\n    workload_type: &str,\n) -> Value {\n    let mut budget = NoiseBudget::from_config(config);\n    let initial_mb = budget.remaining_millibits();\n    let mut ct = encryptor.encrypt(42, rng);\n    let _ = budget.consume(NoiseOpType::Encrypt, NoiseBudget::encrypt_cost(config));\n\n    let mut operations: u64 = 0;\n    let mut terminated_on_budget = false;\n    let t0 = Instant::now();\n\n    for d in 0..target_operations {\n        let (noise_op, noise_cost) = match workload_type {\n            \"arithmetic\" => {\n                if d % 3 == 0 {\n                    ct = evaluator.mul_plain(&ct, 3);\n                    (NoiseOpType::MulPlain, NoiseBudget::mul_plain_cost(config))\n                } else {\n                    ct = evaluator.add_plain(&ct, 7);\n                    (NoiseOpType::Add, NoiseBudget::add_plain_cost())\n                }\n            }\n            \"statistical\" => {\n                ct = evaluator.add_plain(&ct, (d as u64) + 1);\n                (NoiseOpType::Add, NoiseBudget::add_plain_cost())\n            }\n            \"neural_network\" => {\n                if d % 2 == 0 {\n                    ct = evaluator.mul_plain(&ct, 2);\n                    (NoiseOpType::MulPlain, NoiseBudget::mul_plain_cost(config))\n                } else {\n                    ct = evaluator.add_plain(&ct, 1);\n                    (NoiseOpType::Add, NoiseBudget::add_plain_cost())\n                }\n            }\n            \"polynomial\" => {\n                if d % 2 == 0 {\n                    ct = evaluator.mul_plain(&ct, 5);\n                    (NoiseOpType::MulPlain, NoiseBudget::mul_plain_cost(config))\n                } else {\n                    ct = evaluator.add_plain(&ct, (d as u64) + 1);\n                    (NoiseOpType::Add, NoiseBudget::add_plain_cost())\n                }\n            }\n            _ => unreachable!(),\n        };\n\n        if budget.consume(noise_op, noise_cost).is_err() {\n            terminated_on_budget = true;\n            break;\n        }\n        operations += 1;\n    }\n\n    let total_us = t0.elapsed().as_micros() as u64;\n    let operations_per_sec = rate_per_second(operations, total_us);\n    let final_noise_pct = percent_floor(budget.remaining_millibits(), initial_mb);\n\n    eprintln!(\n        \"  {}: requested={}, achieved={}, time={}us, ops/s={}, exhausted={}\",\n        workload_type,\n        target_operations,\n        operations,\n        total_us,\n        operations_per_sec,\n        terminated_on_budget\n    );\n\n    json!({\n        \"workload\": workload_type,\n        \"requested_operations\": target_operations,\n        \"operations_achieved\": operations,\n        \"total_time_us\": total_us,\n        \"operations_per_sec\": operations_per_sec,\n        \"simulated_refreshes\": 0,\n        \"terminated_on_budget\": terminated_on_budget,\n        \"final_noise_pct\": final_noise_pct,\n    })\n}\n\n/// Minimal timestamp without chrono dependency""",
        "scale-test fail-closed rewrite",
    )

    forbidden = [" as f64", "f64", "f32", "SIMULATED REFRESH"]
    for token in forbidden:
        if token in text:
            raise RuntimeError(f"benchmark still contains forbidden token: {token}")

    write(rel, text)


def patch_symmetric_bootstrap_claims() -> None:
    rel = "crates/nine65/src/ops/symmetric_bootstrap.rs"
    text = read(rel)
    text = text.replace(
        "//! - Any scenario where symmetric mode depth >200 isn't enough\n//!   (which is... almost never, but the bootstrap exists as a safety net)",
        "//! - Any scenario that reaches the measured unbootstrapped ceiling for the\n//!   selected parameter chain. The ceiling must be established by a real ct×ct\n//!   correctness sweep; it is not inferred from operation count.",
    )
    text = sub_once(
        text,
        r"    // Actual symmetric depth is MUCH higher because:.*?    // In practice: symmetric depth > 200, public depth = 4-5\n",
        """    // These arithmetic estimates are planning bounds only. Correctness depth\n    // must be measured by level-aligned ct×ct chains with decrypt-and-compare at\n    // every level. The July 2026 audit observed failure near depth 8 for the old\n    // secure_128 parameter set and near depth 5 for secure_192/256.\n""",
        "depth-analysis claim correction",
    )
    text = replace_once(
        text,
        'actual_sym_depth_note: "200+ tested, zero collapses, limited by prime count not noise",',
        'actual_sym_depth_note: "measure per config with level-aligned ct×ct correctness sweep",',
        "symmetric depth note",
    )
    text = replace_once(
        text,
        'actual_pub_depth_note: "4-5 (Clockwork Bootstrap extends to unlimited)",',
        'actual_pub_depth_note: "finite without bootstrap; unlimited only after verified real refreshes",',
        "public depth note",
    )
    write(rel, text)


def write_regression_tests() -> None:
    write(
        "crates/nine65/tests/audit_regressions.rs",
        r'''//! Regression gates for the July 2026 physical audit.

use nine65::params::{FHEConfig, SecureConfig};

#[test]
fn secure_128_uses_audited_ring_dimension_floor() {
    let config = SecureConfig::secure_128();
    assert_eq!(config.claimed_security, 128);
    assert!(config.config.n >= 8192);
    assert!(config.is_production_safe());
}

#[test]
fn custom_config_rejects_plaintext_modulus_at_or_above_any_lane() {
    let equal = FHEConfig::custom(1024, vec![998244353], 998244353, 2);
    let above = FHEConfig::custom(1024, vec![998244353], 998244354, 2);
    assert!(equal.is_err());
    assert!(above.is_err());
}

#[test]
fn large_rns_products_are_not_saturated_or_wrapped() {
    let config = SecureConfig::secure_256().into_config();
    assert!(config.try_rns_product().is_none());
    assert!(config.rns_product_bit_length() > 128);
}

#[test]
fn secure_128_product_is_exact_in_u128() {
    let config = SecureConfig::secure_128().into_config();
    let expected = config
        .primes
        .iter()
        .fold(1u128, |acc, &prime| acc * prime as u128);
    assert_eq!(config.try_rns_product(), Some(expected));
    assert_eq!(config.rns_product(), expected);
}
''',
    )


def write_remediation_record() -> None:
    write(
        "docs/AUDIT_REMEDIATION_2026-07-13.md",
        r'''# NINE65 Audit Remediation - 2026-07-13

## Scope

This change set addresses the independent physical audit findings and additional defects discovered while tracing the benchmark, parameter, and depth-reporting paths.

## Closed findings

1. **`secure_128` parameter floor** - the ring dimension is raised from `N=4096` to `N=8192` while retaining the three-prime 90-bit RNS chain. Named security claims now fail closed against the full internal screening result. The internal estimator is explicitly treated as a screening gate; each release still requires archived output from an independent lattice estimator.
2. **Depth semantics** - the benchmark now labels its mixed `ct+plain`/`ct*plain` chain as an operation count. It no longer presents that count as ciphertext-ciphertext multiplicative depth.
3. **Fake refresh removal** - exhausted noise budgets terminate unbootstrapped runs. Resetting the budget object without refreshing the ciphertext has been removed from the main chain and scale tests.
4. **Benchmark exactness** - all `f32`/`f64` calculations were removed from `nine65_bench`; percentages and rates use checked-width integer arithmetic.
5. **Duplicate ciphertext initialization** - the discarded first encryption and double-counted budget initialization were removed.
6. **Statistical mode** - statistical verification now implies real bootstrap key generation. It cannot execute against a simulated refresh.
7. **RNS product overflow** - saturating `u128` multiplication was replaced by `try_rns_product()` plus exact 512-bit limb accounting for product bit length. `rns_product()` fails closed when the exact product does not fit in `u128`.
8. **Custom BFV parameters** - `FHEConfig::custom` rejects `t >= q_i` for any RNS lane, preventing a zero scaling factor.
9. **Depth documentation** - unsupported `200+` unbootstrapped depth claims were removed. Correctness depth must be established by level-aligned `ct*ct` chains with decryption checked after every multiplication.

## CRAM/RNS invariants

- NTT lanes remain prime and satisfy `q_i = 1 (mod 2N)`.
- Anchor and K-Elimination layers remain coprime ring layers; no Garner or mixed-radix conversion is added to the hot path.
- No floating-point variable or operation is introduced.
- Large modulus products are represented by exact lane factors and exact bit-length accounting rather than a saturated scalar surrogate.

## Verification gates

The remediation workflow runs:

- exact-integer Python checks for NTT compatibility and product bit lengths;
- `cargo fmt --all`;
- `cargo check -p nine65 --all-targets --features serde`;
- targeted parameter and audit regression tests.

A security release is not complete until an independent lattice-estimator artifact is attached to the release record.
''',
    )


def exact_integer_harness() -> None:
    primes = [998244353, 985661441, 754974721]
    n = 8192
    assert all((prime - 1) % (2 * n) == 0 for prime in primes)
    product = 1
    for prime in primes:
        product *= prime
    assert product.bit_length() == 90

    larger = [998244353, 985661441, 754974721, 469762049, 167772161, 595591169]
    product = 1
    for prime in larger:
        product *= prime
    assert product.bit_length() > 128


def main() -> None:
    patch_secure_configs()
    patch_params()
    patch_full_system_test()
    patch_benchmark()
    patch_symmetric_bootstrap_claims()
    write_regression_tests()
    write_remediation_record()
    exact_integer_harness()
    print("audit remediation applied and integer harness passed")


if __name__ == "__main__":
    main()
