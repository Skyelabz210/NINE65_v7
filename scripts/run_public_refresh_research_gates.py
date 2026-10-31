#!/usr/bin/env python3
"""Run named public-refresh regressions; research passes do not admit refresh.

Some research probes are intentionally ignored by the general test sweep.
Use exact names here so a module filter cannot start expensive native probes.
Cargo's successful zero-test exit is not accepted as evidence.
"""

import argparse
import os
from pathlib import Path
import re
import signal
import subprocess
import sys


PIPELINE = "phase_clock_compaction::public_bootstrap_pipeline"
BATCHED = f"{PIPELINE}::outer_ring_return::sparse_source_encapsulation::batched_lift_phase"
SOURCE = "ops::public_refresh_source::tests"
CIRCUIT = "ops::public_refresh_circuit::tests"
VIEWS = "ops::bounded_digit_circuit::protected_adjacent_view_tests"
SUITES = {
    "production-boundary": (
        ("--lib", None, "params::secure_configs::tests::public_refresh_support_requires_sound_phase1", False),
        ("--lib", None, "ops::bootstrap::tests::public_phase1_is_typed_fail_closed", False),
    ),
    "research": (
        ("--lib", None, f"{CIRCUIT}::fused_adjacent_restore_covers_every_native_lift_and_rejects_aliases", False),
        ("--lib", None, f"{CIRCUIT}::fused_native_lift_query_funds_slot_return_and_next_refresh", False),
        ("--lib", None, f"{VIEWS}::linear_adjacency_consumes_compatible_views_but_cannot_change_plaintext_modulus", False),
        ("--lib", None, f"{VIEWS}::derived_defect_is_tautological_and_zero_plaintext_need_not_have_zero_error", False),
        ("--lib", None, f"{VIEWS}::bounded_adjacency_correction_evaluates_under_encryption_on_all_97_values", False),
        ("--lib", None, f"{VIEWS}::native_adjacency_consumer_budget_is_conditional_and_does_not_fund_slot_return", False),
        ("--lib", None, f"{CIRCUIT}::native_plan_certifies_signed_carry_separately_from_residual_support", False),
        ("--lib", None, "ops::direct_slot_phase::tests::coherent_source_phases_extract_all_carries_and_restore_affine_message", False),
        ("--lib", None, "ops::public_refresh_native::complete_public_refresh_returns_original_key_for_three_cycles", False),
        ("--lib", None, f"{CIRCUIT}::public_refresh_conforms_on_full_polynomials_histories_and_forks_across_seeds", False),
        ("--lib", None, f"{CIRCUIT}::public_refresh_refuses_wrong_families_and_exhausted_history_without_counting", False),
        ("--lib", None, f"{CIRCUIT}::public_refresh_plan_refuses_invalid_geometry_scale_support_basis_and_resources", False),
        ("--test", "coefficient_slot_gate", "tropical_cocycle_state::encrypted_cocycle_works_over_composite_two_eleven_without_plaintext_roots", False),
        ("--test", "coefficient_slot_gate", f"{PIPELINE}::phase_clock_full_polynomial_public_return_and_two_dependent_refresh_cycles", True),
        ("--test", "coefficient_slot_gate", f"{PIPELINE}::outer_ring_return::sparse_source_encapsulation::sparse_source_public_transform_closes_two_dense_work_refresh_cycles", True),
        ("--test", "coefficient_slot_gate", f"{BATCHED}::p_locked_sister_scale_requires_exact_divisibility", False),
        ("--test", "coefficient_slot_gate", f"{BATCHED}::p_locked_scale_jacobian_extracts_carry_and_residual_from_one_history", False),
        ("--test", "coefficient_slot_gate", f"{BATCHED}::p_locked_scale_jacobian_corrects_the_medium_phase_without_oracle_residual", False),
        ("--test", "coefficient_slot_gate", f"{BATCHED}::wide_p_locked_scale_jacobian_tests_larger_step_and_dependent_square", False),
    ),
    "native-arithmetic": (
        ("--test", "coefficient_slot_gate", f"{BATCHED}::triple_lift_chart::frobenius_chart_section::frobenius_chart_section_native_contracts_coherent_residue_and_tracks_quotient", True),
    ),
    "source-preparation": (
        ("--lib", None, f"{SOURCE}::direct_phase_quotient_bound_covers_signed_lifts_and_native_endpoints", False),
        ("--lib", None, f"{SOURCE}::source_preparation_tracks_full_polynomial_history_and_ring_embedding", False),
        ("--lib", None, f"{SOURCE}::source_preparation_rejects_wrong_families_and_invalid_parameters", False),
        ("--lib", None, f"{SOURCE}::source_preparation_refuses_exhausted_switch_margin_without_resetting_input", False),
        ("--lib", None, f"{SOURCE}::source_preparation_native_same_ring_h96_checks_all_coefficients", False),
        ("--lib", None, f"{SOURCE}::source_preparation_native_embedded_h32_checks_all_coefficients_and_zeros", False),
    ),
    "return-boundary": (
        ("--lib", None, "ops::public_refresh_return::tests::public_return_noise_plan_is_key_free_and_checks_geometry", False),
        ("--lib", None, "ops::public_refresh_return::tests::public_return_restores_dense_work_and_preserves_history", False),
        ("--lib", None, "ops::public_refresh_return::tests::public_return_rejects_foreign_family_and_stale_source_lineage", False),
        ("--lib", None, "ops::public_refresh_return::tests::public_return_rejects_malformed_outputs_and_exhausted_bounds", False),
    ),
}
SUMMARY = re.compile(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; "
    r"(\d+) ignored; (\d+) measured; (\d+) filtered out;.*$",
    re.MULTILINE,
)


def validate_result(output, returncode, name):
    if returncode != 0:
        raise ValueError(f"{name}: test command exited {returncode}")
    summaries = SUMMARY.findall(output)
    if len(summaries) != 1 or summaries[0][:5] != ("ok", "1", "0", "0", "0"):
        raise ValueError(f"{name}: expected exactly one passed test and no failures or ignores")
    if not re.search(rf"^test {re.escape(name)} \.\.\. ", output, re.MULTILINE):
        raise ValueError(f"{name}: successful result did not identify the requested test")


def command_for(spec):
    selector, target, name, ignored = spec
    command = [
        "cargo", "test", "--locked", "--config", "profile.test.package.nine65.opt-level=2",
        "-j2", "-p", "nine65", "--features", "allow_insecure", selector,
    ]
    if target:
        command.append(target)
    command += ["--", name, "--exact", "--test-threads=1", "--nocapture", "--color=never"]
    if ignored:
        command.append("--ignored")
    return command


def run_suite(suite, log_dir, timeout_seconds):
    root = Path(__file__).resolve().parents[1]
    log_dir.mkdir(parents=True, exist_ok=True)
    for spec in SUITES[suite]:
        name = spec[2]
        command = command_for(spec)
        log = log_dir / f"{name.rsplit('::', 1)[-1]}.log"
        print(f"Running {name}\nLog: {log}", flush=True)
        try:
            with log.open("w") as output:
                process = subprocess.Popen(
                    command, cwd=root, stdout=output, stderr=subprocess.STDOUT,
                    text=True, start_new_session=True,
                )
                try:
                    returncode = process.wait(timeout=timeout_seconds)
                except subprocess.TimeoutExpired:
                    # Cargo launches the test binary as a child. Terminate
                    # the group so a timed-out native probe cannot linger.
                    if os.name == "posix":
                        os.killpg(process.pid, signal.SIGKILL)
                    else:
                        process.kill()
                    process.wait()
                    raise
        except subprocess.TimeoutExpired as error:
            raise ValueError(f"{name}: exceeded {timeout_seconds}s; partial log: {log}") from error
        output = log.read_text()
        print(output, end="", flush=True)
        validate_result(output, returncode, name)
    print(f"{suite}: {len(SUITES[suite])} exact regressions passed; no production refresh admission")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", required=True, choices=SUITES)
    parser.add_argument("--log-dir", type=Path, default=Path("work/public-refresh-gates"))
    parser.add_argument("--timeout-seconds", type=int, default=600,
                        help="per command, including compilation (default: 600)")
    args = parser.parse_args()
    if args.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be positive")
    try:
        run_suite(args.suite, args.log_dir, args.timeout_seconds)
    except (ValueError, OSError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
