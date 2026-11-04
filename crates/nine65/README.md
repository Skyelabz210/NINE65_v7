# nine65

Rust BFV/DualRNS research core. See the [repository README](../../README.md),
[current refresh status and notation](../../docs/PUBLIC_REFRESH_STATUS.md),
[architecture map](../../docs/ARCHITECTURE.md) and
[security pack](../../docs/security/README.md).

The explicit research refresh has encrypted carry correction and native
execution evidence. Default legacy Clockwork public refresh remains gated;
related-key production security remains unadmitted.

From the workspace root, with the pinned Rust toolchain:

```bash
cargo test --locked -p nine65 --lib --release
```

This command does not run ignored or feature-gated integration targets.
The old test census and opportunity inventory are
[archived](../../archive/hygiene/2026-11-04/crates/nine65/README.md);
line numbers and pending flags there are historical.
