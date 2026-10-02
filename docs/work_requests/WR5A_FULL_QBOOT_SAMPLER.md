# WR-5A — Exact Full-Q_boot Bootstrap Mask Sampling

## Objective

Replace narrow or per-lane sampling with one exact rejection sampler uniform on [0, Q_boot), then reduce each accepted value into boot main lanes.

## Requirements

- exact full-width rejection sampling, no narrow modulo joint-support shortcut;
- representation sufficient above u128 where needed;
- published boot material remains mod-Q/boot-Q-only;
- later D3 residues derive from the accepted public value and are never serialized;
- deterministic support, identity, keygen, and roundtrip tests;
- typed refusal for invalid contexts.

## Scope boundary

This is a prerequisite only. It must not remove the public Phase-1 soundness gate or claim correct public bootstrap under #95.
