use exact_transcendentals::chimera_page::S8_CORE;
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::params::secure_configs::SecureConfig;
use std::fmt::{self, Write};
use std::fs;
use std::path::Path;

const OUTPUT_PATH: &str = "artifacts/execution/parameter_registry.json";
const PRIMING_ROOT_CONTRACT: &str = "docs/execution/2026-10-03/PRIMING_ROOT_CONTRACT.md";

struct RegistryEntry {
    name: &'static str,
    ring_degree: usize,
    main_primes: Vec<u64>,
    main_modulus_hex: String,
    main_modulus_product_bits: u32,
    plaintext_modulus: u64,
    eta: usize,
    declared_security_claim_bits: u32,
    context_fingerprint: u64,
    automatic_route: String,
    exact_evaluator_route: String,
    auxiliary_moduli: Vec<u64>,
    auxiliary_product_bits: u32,
    required_capacity_bits: u32,
    operand_bound_over_q_squared: u64,
}

fn exact_product(primes: &[u64]) -> Result<Vec<u64>, String> {
    if primes.is_empty() {
        return Err("cannot export an empty main modulus".to_string());
    }
    if primes.contains(&0) {
        return Err("main modulus contains a zero lane".to_string());
    }

    let mut limbs = vec![1_u64];
    for &factor in primes {
        let mut carry = 0_u128;
        for limb in &mut limbs {
            let product = *limb as u128 * factor as u128 + carry;
            *limb = product as u64;
            carry = product >> 64;
        }
        if carry != 0 {
            limbs.push(carry as u64);
        }
    }
    Ok(limbs)
}

fn product_bit_length(limbs: &[u64]) -> u32 {
    let Some((index, &top)) = limbs.iter().enumerate().rev().find(|(_, limb)| **limb != 0) else {
        return 0;
    };
    index as u32 * 64 + (64 - top.leading_zeros())
}

fn product_hex(limbs: &[u64]) -> String {
    let mut encoded = String::from("0x");
    let mut started = false;

    for &limb in limbs.iter().rev() {
        let part = format!("{limb:016x}");
        if !started {
            let trimmed = part.trim_start_matches('0');
            if trimmed.is_empty() {
                continue;
            }
            encoded.push_str(trimmed);
            started = true;
        } else {
            encoded.push_str(&part);
        }
    }

    if !started {
        encoded.push('0');
    }
    encoded
}

fn same_tuple(left: &RegistryEntry, right: &RegistryEntry) -> bool {
    left.ring_degree == right.ring_degree
        && left.main_primes == right.main_primes
        && left.plaintext_modulus == right.plaintext_modulus
        && left.eta == right.eta
}

fn build_entry(secure: SecureConfig) -> Result<RegistryEntry, String> {
    let name = secure.config.name;
    let declared_security_claim_bits = secure.claimed_security;
    let context_fingerprint = secure.fingerprint().0;
    let source_product_bits = secure.log_q();

    let main_modulus = exact_product(&secure.config.primes)?;
    let main_modulus_product_bits = product_bit_length(&main_modulus);
    if main_modulus_product_bits != source_product_bits {
        return Err(format!(
            "{name}: independent exact-product width {main_modulus_product_bits} differs from \
             SecureConfig::log_q() {source_product_bits}"
        ));
    }

    let context = RNSFHEContext::new(&secure.config);
    let evaluator = context
        .try_exact_evaluator()
        .map_err(|error| format!("{name}: failed to construct exact evaluator: {error}"))?;
    let plan = evaluator.plan();
    let certificate = plan.certificate();
    let auxiliary_moduli = plan.auxiliary_basis().to_vec();
    let automatic_route = format!("{:?}", context.mul_route());
    let exact_evaluator_route = format!("{:?}", evaluator.route());

    let config = secure.into_config();
    Ok(RegistryEntry {
        name,
        ring_degree: config.n,
        main_primes: config.primes,
        main_modulus_hex: product_hex(&main_modulus),
        main_modulus_product_bits,
        plaintext_modulus: config.t,
        eta: config.eta,
        declared_security_claim_bits,
        context_fingerprint,
        automatic_route,
        exact_evaluator_route,
        auxiliary_moduli,
        auxiliary_product_bits: certificate.aux_bits,
        required_capacity_bits: certificate.required_bits,
        operand_bound_over_q_squared: certificate.x_bound_over_q_sq,
    })
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character <= '\u{1f}' => {
                escaped.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => escaped.push(character),
        }
    }
    escaped
}

fn write_u64_array(output: &mut String, values: &[u64], indent: &str) -> fmt::Result {
    output.push('[');
    for (index, &value) in values.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        write!(output, "\n{indent}{value}")?;
    }
    if !values.is_empty() {
        write!(output, "\n{}", &indent[..indent.len().saturating_sub(2)])?;
    }
    output.push(']');
    Ok(())
}

fn build_registry(entries: &[RegistryEntry]) -> Result<String, fmt::Error> {
    let mut output = String::new();
    writeln!(output, "{{")?;
    writeln!(output, "  \"schema\": 1,")?;
    writeln!(
        output,
        "  \"registry_kind\": \"current_source_parameter_snapshot\","
    )?;
    writeln!(output, "  \"integer_arithmetic_only\": true,")?;
    writeln!(
        output,
        "  \"main_modulus_width_method\": \"bit_length_of_exact_product\","
    )?;
    writeln!(
        output,
        "  \"security_note\": \"Declared source claim bits are metadata only; this registry performs no \
         security screen, attestation, or acceptance claim.\","
    )?;
    writeln!(output, "  \"modulus_roles\": {{")?;
    writeln!(output, "    \"priming_roots\": [")?;
    writeln!(
        output,
        "      {{\"name\": \"S8\", \"role\": \"source_identity_priming_root\", \
         \"contract\": \"{}\", \"value\": null, \"ordered_factors\": {:?}, \
         \"value_policy\": \"The contract-defined root is a role, not a modulus; it is not expanded \
         as total dynamic range.\", \
         \"must_not_substitute_for\": [\"total_dynamic_range\", \
         \"rlwe_ciphertext_modulus\", \"rlwe_parameter\"]}}",
        json_escape(PRIMING_ROOT_CONTRACT),
        S8_CORE,
    )?;
    writeln!(output, "    ],")?;
    writeln!(output, "    \"plaintext_payload_moduli\": [")?;
    for (index, entry) in entries.iter().enumerate() {
        writeln!(
            output,
            "      {{\"name\": \"{}.plaintext_payload\", \"role\": \
             \"bfv_plaintext_payload_modulus\", \"owner_config\": \"{}\", \
             \"value\": {}, \"is_rlwe_ciphertext_modulus\": false, \
             \"is_dependent_view_modulus\": false}}{}",
            entry.name,
            entry.name,
            entry.plaintext_modulus,
            if index + 1 == entries.len() { "" } else { "," }
        )?;
    }
    writeln!(output, "    ],")?;
    writeln!(output, "    \"rlwe_ciphertext_moduli\": [")?;
    for (index, entry) in entries.iter().enumerate() {
        writeln!(
            output,
            "      {{\"name\": \"{}.rlwe_ciphertext_main\", \"role\": \
             \"main_rlwe_ciphertext_modulus\", \"owner_config\": \"{}\", \
             \"value_hex\": \"{}\", \"product_bits\": {}, \
             \"width_method\": \"exact_product\", \
             \"is_plaintext_payload_modulus\": false, \
             \"is_dependent_view_modulus\": false}}{}",
            entry.name,
            entry.name,
            entry.main_modulus_hex,
            entry.main_modulus_product_bits,
            if index + 1 == entries.len() { "" } else { "," }
        )?;
    }
    writeln!(output, "    ],")?;
    writeln!(output, "    \"dependent_view_moduli\": [")?;
    for (index, entry) in entries.iter().enumerate() {
        write!(
            output,
            "      {{\"name\": \"{}.derived_transient_auxiliary_view\", \
             \"role\": \"derived_transient_exact_multiply_view\", \
             \"owner_config\": \"{}\", \"auxiliary_moduli\": ",
            entry.name, entry.name
        )?;
        write_u64_array(&mut output, &entry.auxiliary_moduli, "        ")?;
        writeln!(
            output,
            ", \"auxiliary_product_bits\": {}, \"required_capacity_bits\": {}, \
             \"operand_bound_over_q_squared\": {}, \
             \"is_plaintext_payload_modulus\": false, \
             \"is_published_rlwe_ciphertext_modulus\": false, \
             \"is_rlwe_parameter\": false, \
             \"depends_on\": [\"ordered main primes\", \"plaintext payload modulus\", \
             \"N/2 operand bound\"]}}{}",
            entry.auxiliary_product_bits,
            entry.required_capacity_bits,
            entry.operand_bound_over_q_squared,
            if index + 1 == entries.len() { "" } else { "," }
        )?;
    }
    writeln!(output, "    ]")?;
    writeln!(output, "  }},")?;
    writeln!(output, "  \"configurations\": [")?;

    for (index, entry) in entries.iter().enumerate() {
        let same = entries
            .iter()
            .filter(|candidate| same_tuple(entry, candidate))
            .map(|candidate| candidate.name)
            .collect::<Vec<_>>();
        let canonical_name = same[0];
        let aliases = same
            .iter()
            .copied()
            .filter(|name| *name != entry.name)
            .collect::<Vec<_>>();

        writeln!(output, "    {{")?;
        writeln!(output, "      \"name\": \"{}\",", entry.name)?;
        writeln!(output, "      \"status\": \"current\",")?;
        writeln!(
            output,
            "      \"source_constructor\": \"SecureConfig::{}\",",
            entry.name
        )?;
        writeln!(output, "      \"ring_degree\": {},", entry.ring_degree)?;
        write!(output, "      \"main_primes\": ")?;
        write_u64_array(&mut output, &entry.main_primes, "        ")?;
        writeln!(output, ",")?;
        writeln!(
            output,
            "      \"main_modulus_hex\": \"{}\",",
            entry.main_modulus_hex
        )?;
        writeln!(
            output,
            "      \"main_modulus_product_bits\": {},",
            entry.main_modulus_product_bits
        )?;
        writeln!(
            output,
            "      \"plaintext_modulus\": {},",
            entry.plaintext_modulus
        )?;
        writeln!(output, "      \"eta\": {},", entry.eta)?;
        writeln!(
            output,
            "      \"declared_security_claim_bits\": {},",
            entry.declared_security_claim_bits
        )?;
        writeln!(
            output,
            "      \"context_fingerprint\": {{\"algorithm\": \
             \"fnv1a64-le-fields-n-prime-list-t-eta\", \"value_hex\": \"0x{:016x}\"}},",
            entry.context_fingerprint
        )?;
        writeln!(output, "      \"route\": {{")?;
        writeln!(
            output,
            "        \"automatic_rns_route\": \"{}\",",
            json_escape(&entry.automatic_route)
        )?;
        writeln!(
            output,
            "        \"exact_evaluator_route\": \"{}\"",
            json_escape(&entry.exact_evaluator_route)
        )?;
        writeln!(output, "      }},")?;
        writeln!(output, "      \"alias_relation\": {{")?;
        writeln!(
            output,
            "        \"kind\": \"{}\",",
            if same.len() == 1 {
                "unique_current_tuple"
            } else {
                "identical_current_tuple"
            }
        )?;
        writeln!(output, "        \"canonical_name\": \"{canonical_name}\",")?;
        writeln!(output, "        \"aliases\": [")?;
        for (alias_index, alias) in aliases.iter().enumerate() {
            writeln!(
                output,
                "          \"{alias}\"{}",
                if alias_index + 1 == aliases.len() {
                    ""
                } else {
                    ","
                }
            )?;
        }
        writeln!(output, "        ]")?;
        writeln!(output, "      }},")?;
        writeln!(
            output,
            "      \"dependent_view_modulus_name\": \"{}.derived_transient_auxiliary_view\"",
            entry.name
        )?;
        writeln!(
            output,
            "    }}{}",
            if index + 1 == entries.len() { "" } else { "," }
        )?;
    }

    writeln!(output, "  ]")?;
    writeln!(output, "}}")?;
    Ok(output)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secure = vec![
        SecureConfig::secure_128(),
        SecureConfig::secure_128_deep(),
        SecureConfig::secure_192(),
        SecureConfig::secure_256(),
    ];
    let entries = secure
        .into_iter()
        .map(build_entry)
        .collect::<Result<Vec<_>, _>>()?;
    let registry = build_registry(&entries)?;

    let output = Path::new(OUTPUT_PATH);
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, registry)?;

    println!("wrote {OUTPUT_PATH}");
    for entry in &entries {
        println!(
            "{}: n={}, lanes={}, exact_Q_bits={}, fingerprint=0x{:016x}",
            entry.name,
            entry.ring_degree,
            entry.main_primes.len(),
            entry.main_modulus_product_bits,
            entry.context_fingerprint,
        );
    }
    Ok(())
}
