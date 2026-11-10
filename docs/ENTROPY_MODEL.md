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

### Native single-modulus API boundary

`SecretKey::generate`, `PublicKey::generate`, `EvaluationKey::generate` and
`KeySet::generate` retain their deterministic signatures for compatibility,
but call `require_secure_rng` before sampling. In a default release-linked
library, a `ShadowHarvester` therefore causes a security panic, even if it
was initialized with an OS seed. Use the corresponding `generate_secure` or
`try_generate_secure` methods for OS-backed key generation.

`BFVEncryptor::encrypt_poly` and `encrypt_poly_with_rng` enforce the same
policy through their fallible counterparts, `try_encrypt_poly` and
`try_encrypt_poly_with_rng`. Scalar, seeded and generic `try_encrypt*` methods
return `Nine65Error::ConfigError` before sampling when entropy is prohibited;
out-of-range scalar messages still return their input error first. These
policy refusals do not unwind or abort the process.

The existing infallible key constructors and encryption methods retain their
signatures and panic on a policy refusal. With `panic = "abort"`, they terminate
the process. Callers that must handle failures should migrate to
`try_generate_secure`, `try_encrypt_secure` or `try_encrypt_poly_secure`.
Generic fallible encryption is available with `SecureRng`, but the `FheRng`
trait's sampling methods are themselves infallible; the direct `try_*_secure`
methods are the path that also returns OS entropy errors. Polynomial/key/NTT
dimensions must still be compatible. Secure sampling itself is unchanged.

The shared guard intentionally permits deterministic research when the library
is compiled with `cfg(test)`, debug assertions, or `allow_insecure`. Normal
release library builds reject `allow_insecure` at compile time; it is not a
release bypass. Integration tests link the library without `cfg(test)`, so
release boundary coverage must use a separate integration target rather than
only `--lib` tests. Run seeded research targets in the development/test profile
with any required feature enabled. Do not deploy those research builds.

These checks protect the named entry points, not arbitrary custom code:
`FheRng::is_secure` is supplied by its implementer, and callers can still
construct public key/polynomial fields manually. They do not constitute a
type-level proof of RNG quality, parameter security, or production admission.

## 3. Shadow Butterfly Noise Injection — retired

SBNI is retired (2026-08-09) and is not part of the current entropy model.
`pub mod sbni;` was removed from `ops/mod.rs` at that date, and
`crates/nine65/src/ops/sbni.rs` itself was subsequently deleted outright
(issue #68, 2026-09-03) rather than kept as an unreachable file. See
`docs/LADDER_REMOVAL.md` §1 for the full retirement record and
`docs/RETIRED_MECHANISMS.md` for the companion retirement of modulus
switching and the noise-exhaustion ladder.

The same pass deleted `crates/nine65/src/entropy/wassan_noise.rs`
(`WassanNoiseField`, "WASSAN Holographic Noise Field"). It was never
authorized by this document's entropy sources above, had zero production
callers, and sat behind the non-default `shadow-entropy` feature; only its
own tests ever constructed one. It is not, and never was, part of the
current entropy model either.

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
