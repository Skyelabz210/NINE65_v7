# cram-core

Residue-native substrate primitives and opt-in architecture instrumentation.
The commissioned policy permits reconstruction and prohibits Garner/MRC
synthetic emissions in residue compute; see
[the implementation contract](../../docs/execution/2026-10-27/IMPLEMENTATION.md).

With nine65's `architecture-meter` feature, RNSContext's main and anchor
counters are shared by the owning FHE context. Actual to_int, partial-level
CRT and to_u256_level calls increment reconstruction counts; main-Q and DualRNS decrypt
requests record user-output projections. The feature test performs genuine
public encryption, multiplication and decryption and verifies the counters.
The context exposes a read-only snapshot and the emission-policy guard.

`assert_no_synthetic_emissions` rejects recorded Garner/MRC emissions while
allowing counted CRT. The historical stricter `assert_production_clean`
remains available and still rejects all internal materialization counters.
Negative controls deliberately inject both synthetic-emission counters.

This first wiring covers those context-owned routes. Standalone projectors,
free reconstruction helpers, other FHE contexts and parallel pipelines are
not a globally complete call inventory. A clean snapshot is not a proof that
un-instrumented code is compliant. Keep the structural residue-native scanner
and actual-operation arrow gates alongside these counters. The diagnostic
feature is disabled by default so atomic counters do not enter default timing
measurements or change their admission threshold.
