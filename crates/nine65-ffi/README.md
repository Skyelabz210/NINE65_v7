# C kiosk binding

This standalone crate exports kiosk lifecycle and modular arithmetic functions.
Build it independently from the root workspace:

```bash
CARGO_TARGET_DIR=target cargo build --locked --release \
  --manifest-path crates/nine65-ffi/Cargo.toml
CARGO_TARGET_DIR=target cargo test --locked --release \
  --manifest-path crates/nine65-ffi/Cargo.toml
cc -Wall -Wextra -Werror -I crates/nine65-ffi/include \
  crates/nine65-ffi/examples/roundtrip.c -L target/release -lnine65_ffi \
  -Wl,-rpath,"$PWD/target/release" -o work/kiosk-roundtrip
./work/kiosk-roundtrip
```

Use `include/nine65.h` and the version-2 destruction/verification functions.
Version 2 carries every field hashed by the Rust receipt, so a real emitted
record can be checked. The hash checks data consistency; it does not prove
remote destruction or authenticate a sender. Duration is informational and
outside that hash.

The original version-1 symbols/layout remain available for ABI compatibility;
their partial receipt does not carry enough data for full verification.
The new API avoids enlarging an existing caller-owned C struct.

Constructors reject invalid Montgomery moduli. Checked operations reject zero
and one as operation moduli. Raw pointers must still reference valid correctly
sized storage, with one owner freeing each handle exactly once. The layer does
not recover from arbitrary memory corruption or aborting failures.
