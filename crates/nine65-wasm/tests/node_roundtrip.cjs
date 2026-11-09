// Run against the release binary's generated wasm-bindgen Node module.
const assert = require('node:assert/strict');
const path = require('node:path');
if (!process.argv[2]) throw new Error('pass the generated nine65_wasm.js module path');
const { WasmFHEContext } = require(path.resolve(process.argv[2]));
const context = new WasmFHEContext(128);
assert.equal(context.surface(), 'single-modulus-bfv-leveled');
assert.equal(context.supports_dual_rns(), false);
assert.equal(context.supports_auto_bootstrap(), false);
const keys = context.generate_keyset();
const publicKey = keys.public_key();
const secretKey = keys.secret_key();
const t = context.plaintext_modulus();
for (const value of [0n, 1n, t / 2n, t - 1n]) {
    assert.equal(context.decrypt(context.encrypt(value, publicKey), secretKey), value);
}
const a = context.encrypt(7n, publicKey);
const b = context.encrypt(6n, publicKey);
assert.equal(context.decrypt(context.add(a, b), secretKey), 13n);
assert.equal(context.decrypt(context.mul_plain(a, 6n), secretKey), 42n);
assert.throws(() => context.generate_keyset_seeded_for_test(1n));
assert.throws(() => secretKey.to_bytes());
console.log('Release WASM: encrypted full-range roundtrips, addition, scalar multiply and boundary refusals passed');
