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

## 3. Shadow Butterfly Noise Injection

SBNI is a ciphertext rerandomization and timing-noise mechanism. It derives bounded injection values from butterfly-associated material, a monotonic operation counter, lane identity, and a cryptographic hash.

SBNI must satisfy:

- injection bounds are exact integers;
- the same signed polynomial is represented consistently across all live main and anchor lanes;
- lane counts are taken from the live ciphertext state after modulus switching;
- empty entropy input is rejected;
- injection never indexes beyond a live limb;
- decrypt-after-injection correctness is tested for every production parameter candidate;
- SBNI is not counted as bootstrap and does not reset the noise budget by itself.

SBNI may strengthen rerandomization and timing resistance. Its existence does not independently establish IND-CCA security or remove the need for authenticated service boundaries.

## Required terminology

| Mechanism | Approved label | Disallowed shorthand |
|---|---|---|
| OS CSPRNG / `SecureRng` | cryptographic entropy | shadow entropy |
| `ShadowHarvester` | deterministic harvester or OS-seeded deterministic harvester | CSPRNG replacement |
| SBNI | bounded ciphertext noise injection / rerandomization | bootstrap, key refresh, free entropy |

## Release gates

1. Secret-key constructors use only secure entropy APIs.
2. Fixed deterministic seeds are absent from non-test key paths.
3. SBNI tests cover empty inputs, live-lane shrinkage, coefficient bounds, anchor consistency, and decrypt correctness.
4. Entropy mechanism names appear in the claim ledger with their exact scope.
5. Security documentation does not infer unpredictability from NIST-style statistical tests alone.
