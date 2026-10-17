# Ciphertext round-trip triage (2026-10-17)

This note records a bounded correction to the single-modulus BFV scalar and
coefficient-batch encoders. It does not accept the wider depth, refresh, or
security gates.

## First divergence

The fuzz harness uses `FHEConfig::for_depth(1, 4096, 0)`, for which `q =
998244353`, `t = 65537`, `floor(q/t) = 15231`, and `q mod t = 50306`. The old
encoder stored `floor(q/t) * m`, while the decoder rounded `t * c / q`. Even
with zero encryption noise, the decoder returned:

| Message | Old decode | Saved failing surface |
| ---: | ---: | --- |
| 16640 | 16639 | `fuzz_encrypt_decrypt`, seed `8246779862454530674` |
| 59905 | 59902 | October 14 hosted fuzz round-trip |
| 65292 | 65289 | `fuzz_homomorphic` addition with zero |

The exact scale deficit is `m * (q mod t) / q` message units. An independent
integer sweep found 55,615 wrong zero-noise round-trips among the 65,537
messages for this tuple. The same defect exists in `BatchEncoder`.

The new encoding uses `round(q*m/t)` and decoding uses `round(t*c/q)`. The
arithmetic uses `u128`, including the decoder's product, without a leading
factor of two that could overflow at wide `u64` bounds. An independent
integer sweep of every message for `(q,t) = (998244353,65537)`,
`(132120577,65537)`, and `(998244353,2053)` found zero zero-noise mismatches.
The same exact Rust helper bodies also passed all messages and sampled
addition-wrap cases in a standalone `no_std` executable.

## Malformed ciphertext input

The validated binary decoders checked input byte length before Bincode, but
used Bincode's unlimited default decode budget. A short payload could declare
a very large vector before structural validation ran. Ciphertext and dual-RNS
keyset imports now set a 64 MiB Bincode decode limit. Regression tests use
the saved five-byte `/AoKCgo=` and six-byte `/Pz8/Pxb` fuzz witnesses.

## Validation state

`rustfmt --check` passed on the changed Rust files. The independent arithmetic
checks passed as described above. Cargo tests remain **UNRUN** in this executor:
Rust 1.89 is not installed, `crc32fast` and the rest of the locked registry are
not cached, and this executor cannot resolve the package download hosts. The
new Rust tests cover the saved seeded encrypt/decrypt and addition cases, the
full plaintext message range, batch boundaries, and malformed byte witnesses;
they still need execution with the locked toolchain and dependencies before
this correction is accepted.
