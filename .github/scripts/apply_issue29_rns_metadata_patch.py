#!/usr/bin/env python3
"""Apply the exact RNS-context metadata portion of issue #29.

The transformer is deliberately conservative. It patches only known source
blocks in `ops/rns_fhe.rs`, requires every old block exactly once, and refuses
to write when source drift or residual zero-sentinel use is detected.

Usage:
    python3 .github/scripts/apply_issue29_rns_metadata_patch.py --check
    python3 .github/scripts/apply_issue29_rns_metadata_patch.py --apply

`--check` succeeds only after the patch is present. `--apply` writes the patched
file but does not commit it and does not address the independent bootstrap
recumbency work.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "crates/nine65/src/ops/rns_fhe.rs"


def replace_once(text: str, pattern: str, replacement: str, label: str) -> str:
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.MULTILINE | re.DOTALL)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one matching source block, found {count}")
    return updated


def apply_patch(source: str) -> str:
    updated = source

    updated = replace_once(
        updated,
        r"(?P<indent>    )/// Q = product of main primes \(0 if too large for u128\)\n"
        r"    pub q_product: u128,\n"
        r"    /// Exact bit-width of Q \(sum of prime bit-widths\)\n"
        r"    pub q_bits: usize,",
        "    /// Checked scalar projection of Q; `None` means the exact product exceeds u128.\n"
        "    pub q_product_checked: Option<u128>,\n"
        "    /// Exact little-endian limbs of the full main-modulus product.\n"
        "    pub q_product_limbs: Vec<u64>,\n"
        "    /// Exact bit length of the full main-modulus product.\n"
        "    pub q_bits: usize,",
        "context metadata fields",
    )

    updated = replace_once(
        updated,
        r"        // Compute Q bit-width \(sum of prime bit-widths\) - always valid\n"
        r"        let q_bits: usize = config\n"
        r"            \.primes\n"
        r"            \.iter\(\)\n"
        r"            \.map\(\|&p\| \(64 - p\.leading_zeros\(\)\) as usize\)\n"
        r"            \.sum\(\);\n\n"
        r"        // Compute Q = product of main primes \(0 sentinel if overflow\)\n"
        r"        // When Q overflows u128, we use 0 as sentinel and rely on RNS-native paths\n"
        r"        let q_product: u128 = config\n"
        r"            \.primes\n"
        r"            \.iter\(\)\n"
        r"            \.try_fold\(1u128, \|acc, &p\| acc\.checked_mul\(p as u128\)\)\n"
        r"            \.unwrap_or\(0\); // 0 = overflow sentinel\n\n"
        r"        // Compute Δ = floor\(Q/t\) and store in RNS form\n"
        r"        // When q_product=0 \(overflow\), compute delta_rns using RNS-native modular arithmetic\n"
        r"        let delta_rns: Vec<u64> = if q_product == 0 \{\n"
        r"            compute_delta_rns_overflow_safe\(&config\.primes, config\.t\)\n"
        r"        \} else \{\n"
        r"            // Normal path: Q fits in u128\n"
        r"            let delta_big = q_product / config\.t as u128;\n"
        r"            config\n"
        r"                \.primes\n"
        r"                \.iter\(\)\n"
        r"                \.map\(\|&p\| \(delta_big % p as u128\) as u64\)\n"
        r"                \.collect\(\)\n"
        r"        \};",
        "        // The ordered factor vector and exact limbs are canonical.\n"
        "        let q_product_limbs = config.rns_product_limbs();\n"
        "        let q_bits = config.rns_product_bit_length() as usize;\n"
        "        let q_product_checked = config.try_rns_product();\n\n"
        "        // Compute Δ = floor(Q/t) in residue form without an overflow sentinel.\n"
        "        let delta_rns: Vec<u64> = match q_product_checked {\n"
        "            Some(q_product) => {\n"
        "                let delta_big = q_product / config.t as u128;\n"
        "                config\n"
        "                    .primes\n"
        "                    .iter()\n"
        "                    .map(|&prime| (delta_big % prime as u128) as u64)\n"
        "                    .collect()\n"
        "            }\n"
        "            None => compute_delta_rns_overflow_safe(&config.primes, config.t),\n"
        "        };",
        "constructor exact-product block",
    )

    updated = replace_once(
        updated,
        r"            q_product,\n            q_bits,",
        "            q_product_checked,\n            q_product_limbs,\n            q_bits,",
        "context initializer",
    )

    updated = replace_once(
        updated,
        r"    pub fn mul_route\(&self\) -> MulRoute \{\n"
        r"        // If Q does not fit in u128 we store q_product = 0 as a sentinel\.\n"
        r"        // Any routing decision based on u128 arithmetic would be invalid in that mode,\n"
        r"        // so we MUST force the Dual/K-Elimination regime\.\n"
        r"        if self\.q_product == 0 \{\n"
        r"            return MulRoute::KElimDual;\n"
        r"        \}\n\n"
        r"        let delta = self\.q_product / self\.t as u128;\n\n"
        r"        match delta\.checked_mul\(delta\) \{\n"
        r"            Some\(delta_squared\) if delta_squared <= self\.q_product => MulRoute::BajardSingle,\n"
        r"            _ => MulRoute::KElimDual, // Overflow or Δ² > Q\n"
        r"        \}\n"
        r"    \}",
        "    pub fn mul_route(&self) -> MulRoute {\n"
        "        let Some(q_product) = self.q_product_checked else {\n"
        "            return MulRoute::KElimDual;\n"
        "        };\n"
        "        let delta = q_product / self.t as u128;\n"
        "        match delta.checked_mul(delta) {\n"
        "            Some(delta_squared) if delta_squared <= q_product => MulRoute::BajardSingle,\n"
        "            _ => MulRoute::KElimDual,\n"
        "        }\n"
        "    }",
        "route selection",
    )

    updated = replace_once(
        updated,
        r"        #\[cfg\(debug_assertions\)\]\n"
        r"        \{\n"
        r"            if self\.q_product == 0 \{.*?\n"
        r"            \}\n"
        r"        \}\n\n"
        r"        match route",
        "        #[cfg(debug_assertions)]\n"
        "        {\n"
        "            match self.q_product_checked {\n"
        "                None => eprintln!(\n"
        "                    \"[auto-routing] Q=(exact {}-bit product), t={}, route={:?}\",\n"
        "                    self.q_bits, self.t, route\n"
        "                ),\n"
        "                Some(q_product) => {\n"
        "                    let delta = q_product / self.t as u128;\n"
        "                    let delta_squared = delta.checked_mul(delta);\n"
        "                    eprintln!(\n"
        "                        \"[auto-routing] Q={}, Δ={}, Δ²={}, route={:?}\",\n"
        "                        sci_notation_u128(q_product),\n"
        "                        sci_notation_u128(delta),\n"
        "                        delta_squared\n"
        "                            .map(|value| format!(\"{} (fits)\", sci_notation_u128(value)))\n"
        "                            .unwrap_or_else(|| \"OVERFLOW\".to_string()),\n"
        "                        route\n"
        "                    );\n"
        "                }\n"
        "            }\n"
        "        }\n\n"
        "        match route",
        "diagnostic routing block",
    )

    residual = [
        r"self\.q_product\b",
        r"q_product\s*==\s*0",
        r"unwrap_or\s*\(\s*0\s*\)",
        r"sum of prime bit-widths",
        r"overflow sentinel",
    ]
    for pattern in residual:
        if re.search(pattern, updated):
            raise RuntimeError(f"residual legacy metadata pattern remains: {pattern}")

    return updated


def is_patched(source: str) -> bool:
    required = [
        "pub q_product_checked: Option<u128>",
        "pub q_product_limbs: Vec<u64>",
        "let q_product_limbs = config.rns_product_limbs();",
        "let q_bits = config.rns_product_bit_length() as usize;",
        "let Some(q_product) = self.q_product_checked else",
    ]
    forbidden = [
        "pub q_product: u128",
        "q_product == 0",
        ".unwrap_or(0)",
        "sum of prime bit-widths",
        "overflow sentinel",
    ]
    return all(item in source for item in required) and not any(item in source for item in forbidden)


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    source = TARGET.read_text(encoding="utf-8")
    if args.check:
        if is_patched(source):
            print("RNS context exact-metadata patch is present")
            return 0
        print("RNS context exact-metadata patch is missing", file=sys.stderr)
        return 1

    if is_patched(source):
        print("RNS context exact-metadata patch already present")
        return 0

    patched = apply_patch(source)
    if not is_patched(patched):
        raise RuntimeError("postcondition failed after metadata patch")
    TARGET.write_text(patched, encoding="utf-8")
    print(f"patched {TARGET.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
