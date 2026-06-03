# CRAM × RLWE Security Assessment

**Date:** 2026-06-03
**Scope:** Impact of CRAM (Configurable Residue Arithmetic Machine) integration on
RLWE-based BFV FHE cryptographic guarantees, new adversarial surfaces, and
deployment prerequisites.
**Method:** Code-grounded audit of all CRAM-related modules + literature cross-reference.

---

## 0. Architectural Premise

CRAM is not a replacement for RLWE — it is a **heterogeneous operator fabric** that
sits on top of standard BFV ciphertexts. The S8 safe basis {2,3,5,7,11,13,17,19}
is a *generative substrate*: the primes are chosen for their quadratic-reciprocity
relationships (Legendre Force Law creating directed bonds 3→7→11), not for their
product's magnitude. S8 is the foundation of a vertically stackable architecture
where additional CRT fixtures are layered on top, synchronized through a shadow
prime and a unity anchor (prime 1). The effective workspace grows multiplicatively
with each fixture layer.

The witness layer (S8 signature, phase-lock network, operator log) tracks
**provenance**: two paths to the same value (12+3 vs 14+1) produce identical
residues but distinct operator histories. CRAM's infrastructure distinguishes
them through the `OperatorSignature` log and per-lane observables.

This assessment evaluates security at three levels:

- **Level 1: RLWE hardness** — does CRAM weaken the underlying lattice problem?
- **Level 2: Protocol security** — does CRAM create new attack surfaces in FHE protocols?
- **Level 3: Implementation** — are there code-level gaps in the current implementation?

---

## 1. RLWE Hardness: Preserved

### 1.1 Witness Derivation Path

The S8 signature is derived exclusively from the *public* ciphertext component `c0`:

```
cram_ct_wrap.rs:71-73
fn lane0_as_i128(ct: &DualRNSCiphertext) -> Vec<i128> {
    ct.c0.main[0].iter().map(|&x| x as i128).collect()
}
```

Since `c0` is already visible to any party holding the ciphertext, the S8 witness
(which is a lossy projection of c0 onto Z/2 × Z/3 × ... × Z/19) reveals strictly
less information than the ciphertext itself. Decision-RLWE and Search-RLWE hardness
assumptions are unaffected: an adversary who can break RLWE can already read c0
directly; the S8 projection gives them nothing new.

**Severity: None.** The witness is a deterministic function of public data.

### 1.2 Phase-Lock Constraints

The five lock types (Anchor 5↔7, Agreement 11↔17, Shadow 2↔11, Boundary 13↔17,
Signature 19→19) impose cross-lane algebraic relationships. In standard CRT,
residues modulo coprime bases are independent. However, these locks do not create
*new* algebraic dependencies — they are **redundant encodings** of relationships
that already exist within the single integer value from which all residues derive.
Given a coefficient value `v`, the residues `v mod 5` and `v mod 7` are already
deterministically related through `v`. The anchor lock merely records the K-Elim
winding `k` that encodes this relationship explicitly.

An adversary who can observe the ciphertext can recompute every lock predicate
independently. The locks add zero information beyond what CRT projection of the
public ciphertext already provides.

**Severity: None.** Redundant encodings of public data.

### 1.3 Literature Confirmation

Halevi, Polyakov, and Shoup (CT-RSA 2019) established that RNS-BFV with fixed,
public, small prime bases is standard practice. Residues modulo individual primes
do not reveal RLWE secrets because the error term, reduced modulo each small prime,
is essentially uniform. A 2025 study on CRT representation in TFHE (Comp. & Appl.
Math., Springer) confirms this for the LWE family.

**Verdict: RLWE hardness is preserved.** The S8 witness layer is information-
theoretically dominated by the ciphertext it derives from.

---

## 2. Protocol Security: Three Open Questions

### 2.1 CRITICAL — Exact Division Changes the Noise Distribution

**Severity: Critical (requires formal resolution before deployment)**

The BFV security proof (Fan-Vercauteren 2012, Brakerski 2012) includes rounding
error from rescaling as part of the noise distribution. The security reduction
proves IND-CPA under an assumed noise distribution that *includes* this rounding
term. CRAM's exact division operators (D0-D3) eliminate rounding entirely.

Cheon, Choe, Passelègue, Stehlé, and Suvanto ("Attacks Against the IND-CPA^D
Security of Exact FHE Schemes", CCS 2024) demonstrated that *any* deviation from
the assumed noise model can be exploitable. Their IND-CPA^D attack works precisely
because noise is more structured than the security proof assumes. A tighter noise
distribution (less rounding error) improves correctness but may invalidate the
security reduction.

**What this means for CRAM:** Eliminating rounding noise via exact division is
the mechanism that converts exponential noise growth to additive. This is CRAM's
core value proposition for unlimited-depth FHE. But the standard BFV security proof
no longer applies as-is.

**Resolution paths:**
1. **New security proof** under the actual (tighter) noise distribution — prove
   that the exact-division noise model is at least as hard as standard RLWE.
2. **Noise flooding** — after exact division, inject calibrated noise to restore
   the distribution assumed by the standard proof. This preserves the existing
   reduction at the cost of some noise budget.
3. **Hybrid** — use exact division for correctness, then flood to the standard
   distribution's variance. The rounding error is replaced by controlled noise
   rather than uncontrolled rounding.

SBNI (Shadow Butterfly Noise Injection, `sbni.rs`) is already designed to inject
calibrated noise. It may serve as the noise-flooding mechanism — but its current
distribution (bounded [-20, 20] via BLAKE3 + GRO nonces) would need to be
validated against the BFV proof's assumed error distribution.

**Ref:** Bultel et al. (ePrint 2025/2288) propose pragmatic approaches to CPA-D
security for BFV that may be directly applicable.

### 2.2 HIGH — Heterogeneous Per-Lane Operations Are Unprecedented

**Severity: High (requires formal analysis)**

No published work applies different algebraic operations to different CRT residue
lanes of the same ciphertext simultaneously. FLASH-FHE (arXiv 2501.18371, 2025)
proposes heterogeneous *hardware* but uniform *operations*. CRT-based gadget
decomposition (ePrint 2024/909) studies per-lane approximation but not per-lane
operator heterogeneity.

The concern: if lane 2 applies `AddParity` while lane 7 applies `InverseMultiply`
and lane 11 applies `DivExact`, the cross-lane residue relationships differ from
what any single homomorphic operation would produce. An adversary who knows the
CRAM operator assignment (which is public — `S8_CHIMERA_V1_LANES` is a compile-time
constant at `cram_ct.rs:144-245`) could potentially use this structure to identify
*which computation was performed*, even on encrypted data.

**However:** The operator heterogeneity applies to the *witness signature*, not
to the *base ciphertext*. The base `DualRNSCiphertext` undergoes standard BFV
operations (`add_dual`, `mul_dual_public`). The CRAM operators are applied to the
S8 projection of the *result*, not to the ciphertext polynomials themselves. This
means the heterogeneous structure is a post-hoc annotation of public data, not a
modification of the encrypted computation.

**Residual risk:** If CRAM is ever extended to apply heterogeneous operators to
the actual RNS lanes of the ciphertext (rather than the witness), this would
require a completely new security model. The current architecture avoids this.

**Resolution:** Formal proof that the witness operator structure is simulatable —
i.e., an adversary can produce valid-looking CRAM witnesses without knowledge of
the plaintext, because the witness depends only on public ciphertext coefficients.

### 2.3 HIGH — Cross-Residue Dependencies Need Satisfiability Proof

**Severity: High (requires formal analysis)**

The phase-lock constraints create algebraic structure that random values may or
may not satisfy. If CRAM-processed ciphertexts always satisfy the locks while
random ciphertexts do not, the locks become a **distinguisher** — an adversary
can tell whether a ciphertext has been CRAM-wrapped.

This is distinct from RLWE hardness (Section 1). The question is not whether the
adversary can recover the secret, but whether they can detect the *use of CRAM*.
In most applications this is acceptable (the protocol is public), but it violates
the ciphertext indistinguishability property if the CRAM witness is transmitted
alongside the ciphertext.

**Resolution:** Prove that for a random RLWE ciphertext `(a, a*s+e)`, the S8
projection of c0 satisfies all phase-lock constraints with overwhelming probability.
Since the locks are deterministic functions of the residues, and the residues of
random ring elements are uniformly distributed modulo small primes, this should
hold — but it requires a formal argument.

---

## 3. Implementation Findings

### 3.1 Signature Lane Hash Is Non-Cryptographic

**Severity: Medium** | `cram_ct.rs:421-439`

The signature lock uses FNV-1a folded to `mod 19` — 19 possible values. The code
itself acknowledges this: *"Replace with a real cryptographic hash before claiming
proof-carrying status"* (line 422). Finding a collision requires examining at most
19 candidates. This is fine for a diagnostic/integrity layer but must not be treated
as a cryptographic commitment.

**Action:** Before any claim of proof-carrying or tamper-proof status, replace
with BLAKE3 or SHA-256 truncated to the desired lane width.

### 3.2 AuxResidueSet Combined Reconstruction Range

**Severity: Medium-High** | `cram_ct.rs:1286-1310`

The FPD auxiliary primes {23,29,31,37,41,43,47} project each coefficient modulo
each auxiliary prime. Combined with S8 residues, the total CRT product is:
`9,699,690 × 23 × 29 × 31 × 37 × 41 × 43 × 47 ≈ 7.2 × 10^16` (~56 bits).

If the `AuxResidueSet` is ever exposed alongside the ciphertext, the combined
reconstruction range could exceed the noise budget and leak plaintext information.

**Action:** AuxResidueSet must be ephemeral — computed during division, used for
the quotient, then discarded. It must never be serialized alongside the ciphertext
or transmitted in any protocol message.

### 3.3 No Cross-Validation Between Base Ciphertext and Witness

**Severity: Medium** | `cram_ct_wrap.rs:75-98`

`DualRNSCiphertext::validate()` and `CramCiphertext::verify()` run independently.
An adversary could construct a `CramCiphertext<DualRNSCiphertext>` where the base
ciphertext and the witness signature disagree. Both validation checks would pass.

**Action:** Add a binding check in `verify()` that recomputes the S8 signature
from the base ciphertext and compares it to the stored witness signature. This is
exactly what `rewrap_after_op` does — it should also be done in `verify()`.

### 3.4 CramWitnessState Lacks Zeroize

**Severity: Medium** | `cram_ct.rs:671-705`

`DualRNSPoly` and `DualRNSSecretKey` implement `Zeroize`/`ZeroizeOnDrop`. The
CRAM witness does not. Currently the witness derives only from public ciphertext
coefficients, so this is not a secret-leakage risk. But if the witness is ever
extended to carry secret-dependent state, the lack of zeroization becomes a
memory-safety gap.

**Action:** Derive `Zeroize` on `CramWitnessState` proactively.

### 3.5 SBNI May Desynchronize CRAM Witness

**Severity: Medium** | `sbni.rs:46-99`

SBNI injects noise directly into the RNS ciphertext. After injection, the CRAM
witness (derived from `c0.main[0]`) is stale — it reflects the pre-injection
coefficients. The `rewrap_after_op` function re-extracts the signature, but SBNI
operates at a different layer and may not trigger rewrapping.

**Action:** Any code path that calls `inject_dual_in_place` on a CRAM-wrapped
ciphertext must rewrap afterward. Consider making this a type-level guarantee
(e.g., SBNI consumes the `CramCiphertext` wrapper and returns a rewrapped one).

### 3.6 Lock Evidence Is Recomputable From Public Data

**Severity: Low** | `cram_ct.rs:462-531`

Lock evidence can be recomputed by anyone with the S8 signature and op counter.
The locks detect accidental corruption, not adversarial tampering. This is fine
for a diagnostic layer but must not be promoted as tamper-proof without adding
a binding mechanism (e.g., HMAC with a key derived from the secret key).

The `CertificateAuth` enum already has the right structure for this:
`HashOnly`, `HmacInternal`, `PublicKeySigned` (`chimera_division.rs:75-91`).
The `None` variant is explicitly flagged as not production-acceptable.

### 3.7 Topology ID Is Unauthenticated

**Severity: Low** | `cram_ct.rs:242`

The topology is identified by a static string `TopologyId("S8_CHIMERA_V1")`.
An adversary could substitute a different topology with different lane operators.
`verify_metadata` validates structural consistency but not that the topology is
the expected one.

**Action:** In any multi-party protocol, the expected topology must be agreed
upon out-of-band and checked by the receiver.

### 3.8 Division Certificate Without Auth

**Severity: Low** | `chimera_division.rs:76-77`

`CertificateAuth::None` is permitted. The code already flags this as not production-
acceptable (`is_production_acceptable()` returns `false` for `None`). Enforcement
should be added at the protocol layer: reject certificates with `auth == None` in
production mode.

---

## 4. Shadow Entropy Interaction

### 4.1 Operator Heterogeneity and Shadow Fingerprints

CRAM's heterogeneous operators create per-lane quotient distributions with
operator-specific structure. In standard RNS (uniform operations), shadow
quotient distributions are harder to distinguish across lanes. With CRAM:

- Lane 2 (AddParity): quotient always 0 or 1 (1 bit)
- Lane 3 (InverseMultiply): quotient ranges over [0, 2] (2 bits)
- Higher lanes: wider quotient ranges, more entropy per shadow

This makes shadow analysis *slightly easier* for an attacker who knows the
operator assignment, because the per-lane distributions are typed. However,
since the operator assignment is public (`S8_CHIMERA_V1_LANES`), this reveals
no information beyond what is already known. The attacker's advantage is not
in knowing *what* operators run, but in having structured expectations for the
quotient distributions.

**Severity: Low-Medium.** The structured shadow distributions are a consequence
of public operator assignments acting on RLWE-randomized data. The RLWE
randomness dominates the quotient distribution for lanes with sufficiently
large primes (11+).

### 4.2 Dual-Use Tension Remains

The fundamental tension identified in the original codebase persists: the same
modular-reduction quotients that provide entropy (via `ShadowAccumulator`) also
carry deterministic information about the computation. CRAM does not worsen this
tension — it structures it. With typed lane operators, the entropy contribution
per lane is more predictable, which is actually *better* for conservative entropy
estimation.

**Action:** Shadow entropy should never be the sole randomness source for
security-critical operations. Use it as a supplement to a CSPRNG, with a
security margin for the adversary's ability to predict quotient distributions.

---

## 5. What Stacking Changes

When CRT fixtures are layered (S8 as foundation, additional fixtures on top
synchronized through shadow prime + unity anchor), the security analysis extends:

- **Effective witness space** grows as the product of layer products. Two S8
  layers give ~94 trillion possible states — birthday bound at ~9.7M observations.
  Three layers push collisions beyond practical reach.

- **Inter-layer synchronization** through prime 1 (the unity anchor) creates a
  lane where every value maps to residue 0. This carries metadata/provenance only,
  not value information. The synchronization through prime 11 (the shadow link)
  creates a discriminator that ties layers together via their residue-11 agreement.

- **Security question for stacking:** Does the inter-layer synchronization create
  algebraic constraints that reduce the effective entropy of the combined witness
  space below the naive product? This requires analysis of the specific sync
  protocol, which is not yet implemented in the codebase.

---

## 6. Deployment Prerequisites

### Must-Have (Before Any Production Use)

| # | Requirement | Status |
|---|-------------|--------|
| 1 | Formal proof or noise flooding for exact-division noise model (§2.1) | Not started |
| 2 | Simulatability proof for witness operator structure (§2.2) | Not started |
| 3 | Satisfiability proof for phase-locks on random RLWE ciphertexts (§2.3) | Not started |
| 4 | Cross-validation binding in `verify()` (§3.3) | Not implemented |
| 5 | AuxResidueSet ephemerality enforcement (§3.2) | Not enforced |

### Should-Have (Before Adversarial Deployment)

| # | Requirement | Status |
|---|-------------|--------|
| 6 | Upgrade signature hash from FNV-1a to BLAKE3 (§3.1) | Acknowledged in code |
| 7 | SBNI → CRAM rewrap type-level guarantee (§3.5) | Not implemented |
| 8 | Zeroize on CramWitnessState (§3.4) | Not implemented |
| 9 | CertificateAuth::None rejection in production mode (§3.8) | Policy exists, not enforced |
| 10 | Topology authentication in multi-party protocols (§3.7) | Not implemented |

### Nice-to-Have (Defense in Depth)

| # | Requirement | Status |
|---|-------------|--------|
| 11 | HMAC-bound lock evidence via secret key (§3.6) | Architecture exists |
| 12 | Shadow entropy mixing with hardware RNG (§4.2) | Not implemented |
| 13 | Inter-layer sync protocol security analysis (§5) | Stacking not yet implemented |

---

## 7. Summary

**RLWE hardness is preserved.** The CRAM witness layer derives exclusively from
public ciphertext data and reveals strictly less information than the ciphertext
itself. The S8 safe basis, phase-lock constraints, and operator heterogeneity do
not weaken the underlying lattice problem.

**Three formal questions must be answered before deployment:**

1. The exact-division noise model deviates from BFV's assumed distribution.
   Either prove security under the tighter distribution or add calibrated noise
   flooding (SBNI is a natural vehicle for this).

2. The heterogeneous witness operators must be proven simulatable — an adversary
   must not be able to distinguish CRAM-annotated ciphertexts from random ones
   based on the witness structure.

3. The phase-lock constraints must be shown to be satisfied by random RLWE
   ciphertexts with overwhelming probability.

**The implementation has five concrete gaps** (§3.1-3.8) that are fixable with
bounded engineering effort. None are fundamental architectural issues.

**The shadow entropy dual-use tension persists** but is not worsened by CRAM.
Structured operator assignments make entropy estimation more predictable, which
is net positive for conservative security margins.

**Ethical deployment** requires items 1-5 from the prerequisites table. The
system should not be presented as having standard BFV security guarantees until
the noise-model question (§2.1) is formally resolved — this is the most important
open item.
