# NINE65 Entropy and Rerandomization Model

This document separates three mechanisms that must not be conflated in code, claims, or application design.

## 1. Secure cryptographic entropy

**Components:** `SecureRng`, OS CSPRNG access, fallible secure constructors.

Use for:

- secret-key generation;
- public-key and evaluation-key randomness;
- production encryption randomness;
- bootstrap-key generation;
- any value whose predictability would affect IND-CPA security.

Rules:

- OS entropy failure propagates as an error or terminates before key material is produced.
- Deterministic seeds are prohibited in production key generation.
- Each thread obtains an independent secure RNG state.
- VM/container cloning and entropy health belong in the deployment threat model.

## 2. ShadowHarvester

`ShadowHarvester` is a deterministic stateful generator. An OS seed can make its stream non-repeating across runs, but the generated sequence remains deterministic given its state.

Permitted uses:

- reproducible tests;
- deterministic differential harnesses;
- non-secret simulation streams;
- explicitly reviewed evaluation-noise paths whose security proof does not require fresh CSPRNG output at each sample.

Prohibited uses:

- direct production secret-key generation;
- any claim that statistical test success establishes cryptographic unpredictability;
- sharing a mutable harvester across threads;
- default fixed seeds in production APIs.

The phrase “shadow entropy” does not authorize replacing a CSPRNG. Code and documentation must state the seed source and intended security role.

## 3. Shadow Butterfly Noise Injection — retired

SBNI is retired (2026-08-09) and is not part of the current entropy model.
`crates/nine65/src/ops/sbni.rs` is kept on disk as the record of the removal
but is not compiled into the crate (`pub mod sbni;` was removed from
`ops/mod.rs`). See `docs/LADDER_REMOVAL.md` §1 for the full record and
`docs/RETIRED_MECHANISMS.md` for the companion retirement of modulus
switching and the noise-exhaustion ladder.

The mechanism never delivered the properties this section used to claim for
it: its "butterfly entropy" was an NTT over a hardcoded constant through
fixed twiddles, producing an identical shadow vector on every call, keyed
only by a monotonic counter through an unkeyed hash — a deterministic,
publicly recomputable function of the operation index. It masked nothing,
and its numerical effect on the emitted ciphertext was, with overwhelming
probability, already a no-op before removal (`docs/LADDER_REMOVAL.md` §1.2).
Any prior claim that SBNI strengthened rerandomization, timing resistance,
or IND-CPA/IND-CCA security is retracted.

## Required terminology

| Mechanism | Approved label | Disallowed shorthand |
|---|---|---|
| OS CSPRNG / `SecureRng` | cryptographic entropy | shadow entropy |
| `ShadowHarvester` | deterministic harvester or OS-seeded deterministic harvester | CSPRNG replacement |

## Release gates

1. Secret-key constructors use only secure entropy APIs.
2. Fixed deterministic seeds are absent from non-test key paths.
3. Entropy mechanism names appear in the claim ledger with their exact scope.
4. Security documentation does not infer unpredictability from NIST-style statistical tests alone.
