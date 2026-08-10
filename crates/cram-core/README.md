# cram-core

Residue-native substrate primitives, plus the **A2 architecture meter**: the
counters that make "no reconstruction on the hot path" a measured property
rather than a claim.

## CRAM opportunity action items

Mirrored from `CRAM_OPPORTUNITY_REPORT.md` (pass 1). Level-2 node is `pending`.

- `[14]` `src/lib.rs:276-317` — the meter exists (`crt_reconstructions`,
  `mixed_radix_calls`, and an `== 0` compliance check) but is **not wired to
  the nine65 FHE path**, so it currently measures nothing. Wiring it is what
  converts entries `[5]`–`[9]` from a reading exercise into a build-failing
  gate. → `reconstruction-retirement`

Related, in sibling crates:

- `crates/exact_transcendentals` `[5]`–`[9]` — the Garner call sites the meter
  would catch once connected.
- `crates/nine65` `[10]`, `[13]` — the RNS path and the BFV↔CRAM seam the meter
  would have to instrument.
