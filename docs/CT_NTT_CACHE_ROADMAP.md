# Constant-Time NTT and Cache-Side-Channel Roadmap

**Status:** Required completion plan. Existing timing hardening does not by itself close cache, speculative-execution, power, or EM channels.

## Threat surface

The critical surfaces are:

- secret-key polynomial multiplication during decryption and key generation;
- NTT butterfly arithmetic and twiddle access;
- decomposition and key-switch loops;
- K-Elimination and anchor correction on secret-bearing values;
- table lookup, branch selection, and memory allocation conditioned on secret data;
- diagnostic output and error timing;
- compiler transformation of branchless source into variable-time machine code.

## Gate CT-0 — inventory

Produce a machine-readable inventory of every function reachable from:

- key generation;
- decryption;
- symmetric refresh;
- bootstrap-key construction;
- secret-key serialization/destruction.

Each function is classified as `CT_REQUIRED`, `PUBLIC_DATA_ONLY`, or `BOUNDARY_ONLY`. Unclassified functions fail the gate.

## Gate CT-1 — data-independent control flow

For every `CT_REQUIRED` function:

- no branch condition depends on secret coefficients;
- loop counts depend only on public parameters;
- no early exit depends on secret values;
- modular correction uses constant-time select;
- error variants do not expose secret-dependent failure classes.

Source scanning is advisory. Disassembly or compiler-IR review is required for claim-grade evidence.

## Gate CT-2 — data-independent memory access

The NTT schedule must use a public, deterministic butterfly order. Twiddle indices depend only on stage and public loop indices. Secret coefficients may select values but never addresses.

Required evidence:

- fixed stride/address trace for equal-size inputs;
- cache-line-aligned twiddle tables;
- no coefficient-dependent sparse shortcuts;
- no secret-dependent allocation or vector resizing;
- documented prefetch behavior or explicit absence of prefetch assumptions.

## Gate CT-3 — arithmetic primitive verification

For Montgomery, Barrett, and wide modular multiplication:

- prove or exhaustively verify exact reduction bounds;
- use fixed iteration counts;
- reject modulus zero/even-invalid configurations where required;
- keep values in persistent Montgomery form across approved chains;
- convert only at explicit boundaries;
- compare optimized output against an independent exact-integer oracle.

Persistent Montgomery performance claims must report saved conversions separately from NTT, K-Elimination, and memory effects.

## Gate CT-4 — empirical timing tests

Run a dudect-style fixed-vs-random timing experiment for each supported CPU family and production parameter candidate. Record integer cycle counts and integer test statistics; do not use floating-point in the repository’s decision path.

A timing test is diagnostic evidence, not a proof. Any statistically significant separation blocks release.

## Gate CT-5 — speculative execution and process isolation

Document:

- supported CPU families and microcode assumptions;
- Spectre-class mitigations at process or deployment level;
- co-tenancy restrictions for secret-key processes;
- thread pinning and scheduler assumptions where timing claims depend on them;
- prohibition on sharing key-holder processes with untrusted plugins.

## Gate CT-6 — edge and WASM boundary

For WASM/browser execution:

- secret-key export remains disabled;
- key objects are not copied into JS strings;
- linear-memory lifetime and zeroization limitations are documented;
- browser timing and shared-memory risks are documented;
- cross-origin isolation requirements are explicit when shared memory is enabled;
- no consumer-side privacy claim depends on browser memory being physically unreadable.

## Gate CT-7 — claim release

The phrase `constant-time` is public only for the exact function set, compiler, target, and commit covered by evidence. Until CT-0 through CT-6 are complete, use:

> constant-time-oriented source paths with documented residual hardware and compiler risks.

## Current priority order

1. Generate CT-0 reachability inventory.
2. Replace remaining diagnostic output in secret-bearing paths with structured, disabled-by-default logging.
3. Verify NTT address traces and align twiddle tables.
4. Add target-specific disassembly review artifacts.
5. Add integer-cycle dudect-style harnesses.
6. Re-run after every compiler or target update.
