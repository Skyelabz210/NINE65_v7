# WASM single-modulus client

This standalone browser/device binding supports OS-random key generation,
fresh scalar encryption, decryption, addition and plaintext-scalar arithmetic.
Its surface identifier is `single-modulus-bfv-leveled`. It does not expose
DualRNS or automatic public refresh; ciphertext multiplication remains refused
at the retired single-modulus boundary. Secret-key byte export is disabled.

## Build and execute locally

Use Rust 1.89.0, the WASM standard library target, Node, and the wasm-bindgen
CLI version matching the lockfile (currently 0.2.129):

```bash
rustup target add wasm32-unknown-unknown
cargo build --locked --release --manifest-path crates/nine65-wasm/Cargo.toml \
  --target wasm32-unknown-unknown --features wasm
wasm-bindgen crates/nine65-wasm/target/wasm32-unknown-unknown/release/nine65_wasm.wasm \
  --target nodejs --out-dir work/wasm-node
node crates/nine65-wasm/tests/node_roundtrip.cjs work/wasm-node/nine65_wasm.js
```

The runtime check executes the release WASM binary using real randomness. It
checks lower/middle/upper-domain plaintexts, encrypted addition and scalar
multiplication, and verifies that seeded-test key generation and secret-key
export are refused. This is a Node execution check, not a browser deployment or
security certification. For ciphertext multiplication from Python, use the
[HTTP SDK and main-Q service](../../sdks/python/README.md).
