# WR-8 — Service, Decode, and Constructor Hardening

## Objective

Harden network framing, decoded ciphertext validation, and caller-controlled error paths without changing evaluator or bootstrap arithmetic.

## Required tracks

1. Fail-closed HTTP framing (#94).
2. Convert caller-controlled panic/unwrap/expect constructors to typed errors (#85).
3. Context-complete validated decode and trailing-byte rejection (#86).
4. Correct negative-branch diagnostic ideal-point calculation (#84).
5. Maintain a panic/unwrap/expect ratchet (#89).
6. Restore production allow_insecure gating without destroying testability (#74).

## Boundaries and acceptance

D4 published artifacts remain mod-Q-only; dual/anchor wire data stays rejected. Add hostile-input and trailing-byte tests. Run canonical FHE baseline before and after and report each changed result. Do not change evaluator/base-extension/bootstrap semantics.
