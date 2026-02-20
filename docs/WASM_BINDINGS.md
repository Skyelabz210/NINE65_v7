# NINE65 WASM Bindings

The `nine65-wasm` crate provides a minimal wasm-bindgen surface for demo and pilot use. It is intentionally seeded and deterministic by default to avoid OS RNG dependencies in wasm.

## Build
```bash
cargo build -p nine65-wasm --features wasm --target wasm32-unknown-unknown
```

## API Surface
- `new(security_bits)` → context (supports 128/192/256)
- `generate_keyset_seeded(seed)`
- `encrypt_seeded(value, public_key, seed)` → ciphertext bytes
- `decrypt(ciphertext_bytes, secret_key)` → value
- `add`, `add_plain`, `mul_plain`, `mul`

## Notes
- The wasm API uses serialized ciphertext bytes via `bincode`.
- Secret key export is disabled in the wasm wrapper.
- Use only for evaluation and integration pilots.
