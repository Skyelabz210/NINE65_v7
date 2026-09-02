# WIRE-Q fail-closed boundary

## Contract

Published keys and ciphertexts carry only their declared single-RNS mod-Q
representation.  Anchor, Shadow, StarLift, redundant, lift, and other CRAM
execution residues are operation-local state and are never serialized by the
FHE service.

## Current gate

The service's historical dual-RNS base64 import/export methods now reject
before encoding or decoding.  This keeps the existing dual implementation
available for local diagnostic work while preventing its anchor limbs from
crossing the service boundary.

The public `RNSFHEContext::mul` entry point also checks that the configuration
selects `BajardSingle` before it enters the legacy per-limb rescale.  A
configuration selected for K-Elimination/dual rescaling must use `mul_auto`
with matching auto keys; the public single-RNS method stops instead of
producing a ciphertext from an uncertified rescale.

## Required replacement before re-enabling transport

1. Derive the evaluator's CRAM execution frame from a canonical mod-Q input.
2. Complete tensor, relinearization, and rescale in that operation-local frame.
3. Prove and differential-test the exact projection back to a single-RNS
   mod-Q ciphertext.
4. Zeroize/discard every transient residue before serialization.
5. Add a round-trip test for the single-RNS wire type and a byte-level test
   that no auxiliary/anchor lane is present.

`python3 scripts/verify_wire_q_fail_closed.py` is the source-contract gate for
this stop condition.  Rust compilation and integration tests remain required
before the branch is promoted.
