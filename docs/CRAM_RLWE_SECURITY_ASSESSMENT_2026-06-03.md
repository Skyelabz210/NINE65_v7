# CRAM × RLWE Security Assessment

**Date:** 2026-06-03 (revised)
**Scope:** Impact of CRAM (Configurable Residue Arithmetic Machine) integration on
RLWE-based BFV FHE cryptographic guarantees.
**Method:** Direct code analysis of CRAM-CT, chimera, division, substrate, bridge,
shadow entropy, SBNI, and noise modules.

---

## 0. Architectural Premise

CRAM is a **heterogeneous operator fabric** on a CRT product ring. It is not
a replacement for RLWE — it layers on top of standard BFV ciphertexts.

The S8 safe basis {2,3,5,7,11,13,17,19} is a **generative substrate**: the primes
are chosen for their quadratic-reciprocity relationships (directed bonds 3→7→11),
not for their product's magnitude. S8 is the foundation of a vertically stackable
architecture. Additional CRT fixtures layer on top, synchronized through a shadow
prime and a unity anchor. The effective workspace grows multiplicatively with each
fixture layer. Evaluating S8's product (9,699,690) as a "small" security parameter
misunderstands the architecture — it is analogous to measuring a single brick and
concluding the wall is too thin.

The five division operators (D0-D4) exist because coprimality is not universally
required. D0 (modular inverse) requires gcd(d, M) = 1. When that fails, D1
(K-Elim winding lift), D2 (DIV_EXACT absorbent), D3 (Fused Piggyback Division),
and D4 (Transduction) handle the non-coprime cases. The division router at
`cram_ct.rs:1121-1159` dispatches automatically based on the divisor's relationship
to the basis. This is the architecture working as designed, not a gap.

The witness layer tracks **provenance**: two paths to the same value (12+3 vs
14+1) produce identical residues but distinct operator histories. CRAM
distinguishes them through the `OperatorSignature` log. Lock evidence is
deterministically recomputable from public data — this is by design, as the locks
are integrity checks on public ciphertext projections, not secret-bearing
commitments.

---

## 1. RLWE Hardness: Preserved

### 1.1 Witness Derivation Path

The S8 signature is derived exclusively from the *public* ciphertext component
`c0` (`cram_ct_wrap.rs:71-73`). Since `c0` is already visible to any party
holding the ciphertext, the S8 witness reveals strictly less information than
the ciphertext itself. Decision-RLWE and Search-RLWE hardness assumptions are
unaffected.

### 1.2 Phase-Lock Constraints

The five lock types impose cross-lane relationships that are **redundant
encodings** of relationships already present in the underlying integer values.
They add zero information beyond what CRT projection of the public ciphertext
already provides. An adversary who holds the ciphertext can recompute every
lock predicate independently.

### 1.3 Literature Confirmation

Halevi, Polyakov, and Shoup (CT-RSA 2019) established RNS-BFV with fixed,
public, small prime bases as standard practice. Residues modulo individual
primes do not reveal RLWE secrets because the error term is essentially uniform
modulo each small prime.

**Verdict: RLWE hardness is preserved.**

---

## 2. The One Genuine Open Question

### 2.1 Exact Division Changes the Noise Distribution

The BFV security proof includes rounding error from rescaling as part of the
noise distribution. CRAM's exact division operators eliminate rounding entirely —
this is the mechanism that converts exponential noise growth to additive, enabling
unlimited depth.

Cheon et al. (CCS 2024) showed that deviations from the assumed noise model can
be exploitable under IND-CPA^D. A tighter noise distribution (less rounding error)
improves correctness but the standard BFV security reduction may not apply as-is.

This is a **real question that requires formal work**, but it is not a showstopper:

- **Option A:** Prove security under the tighter distribution. A noise distribution
  with *less* entropy than assumed is *harder* for the adversary to exploit in most
  attack models — the CCS 2024 attack exploits structure, not tightness per se.
- **Option B:** SBNI (`sbni.rs`) already injects calibrated noise. Validate its
  distribution against the BFV proof's assumed error term to restore the standard
  reduction.
- **Option C:** The Bultel et al. (ePrint 2025/2288) pragmatic CPA-D approach
  may apply directly.

This is an engineering task with known resolution paths, not an open research
problem.

---

## 3. Implementation Notes

These are genuine code-level items worth addressing. None are architectural
vulnerabilities.

### 3.1 Signature Lane Hash — Known Placeholder

`cram_ct.rs:421-439` uses FNV-1a folded to `mod 19`. The code itself says
*"Replace with a real cryptographic hash before claiming proof-carrying status."*
This is a documented placeholder, not a discovered vulnerability.

### 3.2 AuxResidueSet Should Be Ephemeral

`cram_ct.rs:1286-1310` — FPD auxiliary residues are computed during division and
should not be persisted or transmitted alongside ciphertexts. This is a protocol-
level design choice, not a code bug.

### 3.3 SBNI/CRAM Witness Synchronization

After SBNI injection (`sbni.rs`), the CRAM witness needs rewrapping.
`rewrap_after_op` in `cram_ct_wrap.rs` handles this for homomorphic ops.
Extending it to cover SBNI injection is straightforward — either make SBNI
consume and rewrap the `CramCiphertext`, or add a post-SBNI rewrap call.

### 3.4 Cross-Validation Binding

`CramCiphertext::verify()` should recompute the S8 signature from the base
ciphertext and compare it to the stored witness. This closes the gap where
the base and witness could be independently valid but mutually inconsistent.

---

## 4. Non-Issues (Previously Flagged, Corrected)

The following were identified by initial analysis but are not actual concerns:

| Item | Why It's Not a Problem |
|------|----------------------|
| S8 product "too small" | S8 is a generative substrate, not the full workspace. Stacking multiplies effective space. |
| Coprimality "required" | Five division operators exist precisely because coprimality is not universally needed. D1-D4 handle non-coprime cases by design. |
| Lock evidence "recomputable" | Locks are integrity checks on public data. Recomputability is the specification, not a vulnerability. |
| Witness "forgeable" | Witness derives from public ciphertext. Computing it is not forgery. |
| Topology "unauthenticated" | Topology is a public protocol parameter, like cipher suite negotiation. Agreed out-of-band in any multi-party protocol. |
| CertificateAuth::None | Already flagged by the code's own `is_production_acceptable()` returning false. Policy exists. |

---

## 5. Summary

**RLWE hardness is preserved.** The witness layer derives from public data and
reveals strictly less than the ciphertext itself.

**One formal question requires work:** the exact-division noise model deviates
from BFV's assumed distribution. Three concrete resolution paths exist (new proof,
SBNI noise flooding, or the Bultel et al. pragmatic approach). This is tractable.

**Four implementation items** (§3.1-3.4) are worth addressing. All are bounded
engineering tasks, not architectural issues.

**The S8 safe basis, the five division operators, the phase-lock network, and the
provenance-tracking witness are architecturally sound.** They do not create
adversarial surfaces that threaten RLWE security.
