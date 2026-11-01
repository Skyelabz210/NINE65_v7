# Native canonical plaintext root and refresh binding

The owner selected canonical plaintext m as the authoritative root quantity,
with noise/sheet coordinates belonging to dependent representation trays.
For ring plaintext this applies coefficientwise: each m_j is the unique
integer in [0,65536] representing its coefficient in F_65537.

## Actual producer relation

`SourceWorkCiphertext` now contains a sealed `CanonicalPlaintextRoot` capability
alongside its encrypted carrier. The ordered logical roles are
`[2,3,5,7,11,13,17,19]`, denoting m_j modulo each modulus. The bound 65536 is
below the S8 product 9699690, so the mathematical S8 tuple uniquely identifies
each coefficient. The encrypted F_65537 carrier also represents that canonical
coefficient uniquely. No clear reconstruction is performed.

Only validated ciphertext producers mint the root:

* Encryption binds the supplied coefficients and actual ciphertext to a new
  value occurrence. Addition/multiplication issue new roots for their canonical
  F_65537 results after the existing full-polynomial error checks.
* Source conversion preserves the identical root capability while changing
  ciphertext representation and recording exact source lineage.
* Refresh computes `affine+K=m` in F_65537. The return proof contains the source's
  root capability. Acceptance checks family, source lineage, root identity,
  ciphertext structure and returned error bound before publishing the result.
* The returned ciphertext has new representation lineage and retains the same
  immutable root object. The pair is assembled before it is visible to callers.

Correctness of the sealed encrypted producers establishes this relation. No
public constructor imports a raw ciphertext/root claim or caller bound.
This is a local typed capability boundary, not remote execution attestation.

Identity denotes a producer-issued **value occurrence**. Equal plaintexts
encrypted twice may have different identities. The digest binds ciphertext
lineage and a separate domain label, not plaintext; it is not a plaintext
commitment vulnerable to dictionary testing. Identity is provenance metadata,
not an arithmetic epoch or retained K. Refresh preserves it; arithmetic issues
a new occurrence even if its result happens to be mathematically equal.
Content-identical operation histories can share a digest. Local acceptance
checks the actual capability object's identity, not digest equality alone.

## Protected projection scope

The preservation argument uses canonicality, not a reduction between unrelated
plaintext rings: `m_B = m_A mod65537` and both canonical representatives in
`[0,65536]` imply integer equality. Therefore `m_B mod r = m_A mod r` for
every S8 role r, including roles that do not divide 65537.

The authoritative object is the encrypted canonical carrier and its logical
S8 projection family. This does not allocate eight independent encrypted
remainder ciphertexts. An API returning those ciphertexts still requires an
admitted producer/error bound. Refresh needs no such emission: equality of
canonical m preserves every logical projection simultaneously.

The legacy test-only `Root211` describes a different full phase integer; it
is not constructed or relabeled here. Legacy sister-tray APIs requiring its
concrete coordinates remain separate. This selected canonical root does not
authorize filling those APIs with placeholder residue values.

## Verification and security scope

The encrypted fork regression checks root sharing through three refreshes,
changed representation lineage, new identities after arithmetic, and canonical
plaintext equality. Return tests substitute a different root occurrence while
retaining the original family and lineage; acceptance refuses it. Source tests
check actual capability identity through conversion. The repeated-refresh test
now checks root preservation after each refresh and new roots after squaring.

All 25 selected Rust refresh tests pass, including native source-conversion
tests; two expensive native full-refresh runs remain ignored. This is not a
new full native refresh execution. The backend remains under `allow_insecure`:
local root/value binding does not prove joint/KDM security of the published keys.
