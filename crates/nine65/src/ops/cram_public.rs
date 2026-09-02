//! CRAM-Public Mode — the single working CRAM variant of the FHE evaluator.
//!
//! This module is the deliberate "gut" of the dual-mode evaluator: it exposes
//! ONLY the public path, and it carries an explicit per-operation emission
//! ledger so the variant's residue-space status is measured, not asserted.
//!
//! # What is kept, what is cut
//!
//! **Kept** (delegated to `rns_fhe`): dual-RNS public key generation,
//! public-key encryption, the lane-local homomorphic primitives
//! (`add_dual`, `sub_dual`, `add_plain_dual`, `mul_plain_dual`,
//! `negate_dual`), the public ct x ct multiply (`mul_dual_public`), and
//! client-side decryption. Exact lane-wise division — previously test-only
//! code in `tests/residue_space_ciphertext.rs` — is promoted here as a
//! first-class evaluator operation.
//!
//! **Cut** (no entry point exists on this surface, by construction):
//! `mul_dual_symmetric`, `mul_dual_symmetric_with_s2`, every `*_with_s2`
//! variant, the symmetric bootstrap path, and the retired modulus ladder
//! (`mod_switch_ct_down` / `mod_switch_down_dual`). A caller holding a
//! `CramPublicEvaluator` cannot reach a secret-key evaluator operation
//! through it; the secret key exists only in the client half of the keygen
//! result and is needed solely to decrypt.
//!
//! # The emission ledger
//!
//! Every operation is classified by the observable that
//! `tests/residue_space_ciphertext.rs` measures:
//!
//! * [`EmissionClass::LaneLocal`] — perturbing input lane `i` moves output
//!   lane `i` and nothing else. The i.i.d. observable holds.
//! * [`EmissionClass::Materialization`] — the operation materialises an
//!   exact CRT integer internally (an R8-class direct materialization in
//!   the lift-inventory taxonomy), coupling output lanes to input lanes.
//!   `mul` is currently in this class through exactly two sites:
//!   `k_elim_rescale_dual` -> `to_u256_level` and `extract_digit_dual`.
//!   The classification is GATE-QUALIFIED, not assumed — the arrow harness
//!   is the measuring stick:
//!     * G2 order-invariance: PASS, measured bit-exact by
//!       `ct_multiply_is_order_equivariant_bit_exact` — so this is NOT a
//!       Garner/MRC cascade (R9, retired); no running value threads lanes.
//!     * i.i.d. lane-locality: coupled, measured by
//!       `ct_multiply_is_not_lane_independent_every_lane_moves`.
//!     * G1: the Delta-rescale discard is DECLARED — metered by the noise
//!       ledger (the entropy meter and the noise budget are one number).
//!     * G5: the level inverses are derived by extended Euclid from the
//!       declared chain at construction — derivable, nothing opaque.
//!   Cross-lane reads and linear combinations are not the fault (Universal
//!   Projection reads every lane and is compliant); the residue-native
//!   policy point is narrower: R8 materialization is licensed for
//!   boundaries/proofs/tests, and the hot path should be elimination-first.
//!   Milestones M2/M3 in `docs/CRAM_PUBLIC_MODE.md` move `mul` to
//!   elimination-first; the discriminator and the ledger pin must then be
//!   INVERTED, not deleted.
//!
//! The ledger makes the variant's honesty mechanical: a chain's report says
//! how many operations ran lane-local and how many took an R8
//! materialization, and the M4 acceptance criterion is a report whose
//! materialization count is zero with the discriminator inverted.

use crate::entropy::FheRng;
use crate::errors::{Nine65Error, Nine65Result};
use crate::ops::rns_fhe::{
    DualRNSCiphertext, DualRNSEvalKey, DualRNSPoly, DualRNSPublicKey, DualRNSSecretKey,
    RNSFHEContext,
};
use crate::params::primes::extended_gcd;
use crate::params::FHEConfig;

/// Emission class of one evaluator operation, per the observables in
/// `tests/residue_space_ciphertext.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmissionClass {
    /// Perturbing input lane `i` moves output lane `i` and nothing else.
    LaneLocal,
    /// The operation materialises an exact CRT integer internally
    /// (R8-class direct materialization): output lanes couple to input
    /// lanes. Gate-qualified: order-invariant (G2 PASS — not a cascade),
    /// declared Delta-discard (G1 METERED), derivable constants (G5 PASS).
    /// Not elimination-first; see docs/CRAM_PUBLIC_MODE.md M2/M3.
    Materialization,
    /// M4 — the multiply's RESCALE and RELINEARIZATION steps perform zero
    /// raw-tensor CRT materialization (M2b's `k_elim_rescale_manufactured`
    /// and M3's `relinearize_rns_limb`, both R4-under-certificate
    /// composition: align-and-drop / CRT-idempotent reads, never a running
    /// value). **Scope, precisely:** this does NOT claim the whole
    /// operation is free of every materialization anywhere in its call
    /// graph — `canonicalize_dual_anchor`'s winding-reset (part of the M1
    /// gut manifest's KEPT surface, not a target of M2/M3) still recomputes
    /// anchor lanes from main lanes via `to_u256_level`, and remains a
    /// separate, already gate-qualified R8 site. `EliminationFirst`
    /// certifies the core multiply computation (tensor → rescale → relin);
    /// it is not an i.i.d.-lane-locality claim (cross-lane reads —
    /// Δ-lane drops, the anchor-certificate ladder, canonicalize's own
    /// reconstruction — remain, and are compliant, not lane-independent).
    /// See docs/CRAM_PUBLIC_MODE.md M2b/M3/M4 and
    /// docs/roadmap/T4_M4_REPIN_VERDICTS.md.
    EliminationFirst,
}

/// One ledger entry: which operation ran, in which class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmissionEvent {
    pub op: &'static str,
    pub class: EmissionClass,
}

/// Append-only record of every operation the evaluator has performed.
#[derive(Debug, Default, Clone)]
pub struct EmissionLedger {
    events: Vec<EmissionEvent>,
}

impl EmissionLedger {
    fn record(&mut self, op: &'static str, class: EmissionClass) {
        self.events.push(EmissionEvent { op, class });
    }

    pub fn events(&self) -> &[EmissionEvent] {
        &self.events
    }

    pub fn lane_local_count(&self) -> usize {
        self.events
            .iter()
            .filter(|e| e.class == EmissionClass::LaneLocal)
            .count()
    }

    pub fn materialization_count(&self) -> usize {
        self.events
            .iter()
            .filter(|e| e.class == EmissionClass::Materialization)
            .count()
    }

    /// M4 — count of operations whose rescale+relin core is elimination-
    /// first. See [`EmissionClass::EliminationFirst`] for the precise scope
    /// (`canonicalize_dual_anchor`'s separate materialization is not part
    /// of this claim).
    pub fn elimination_first_count(&self) -> usize {
        self.events
            .iter()
            .filter(|e| e.class == EmissionClass::EliminationFirst)
            .count()
    }

    /// Human-readable summary, suitable for test output and audits.
    pub fn report(&self) -> String {
        format!(
            "cram-public emission ledger: {} ops ({} lane-local, {} R8 materialization, \
             {} elimination-first){}",
            self.events.len(),
            self.lane_local_count(),
            self.materialization_count(),
            self.elimination_first_count(),
            if self.materialization_count() == 0 && self.elimination_first_count() == 0 {
                " — elimination-first throughout"
            } else if self.materialization_count() == 0 {
                " — elimination-first rescale+relin core throughout (canonicalize_dual_anchor's \
                 separate winding-reset materialization is a distinct, gate-qualified site — \
                 see docs/CRAM_PUBLIC_MODE.md M4)"
            } else {
                " — R8 materialization on the hot path (gate-qualified: order-invariant, \
                 metered discard, no cascade; see docs/CRAM_PUBLIC_MODE.md M2/M3)"
            }
        )
    }
}

/// Evaluator-side key material for the public mode: no secret key.
#[derive(Clone)]
pub struct CramPublicKeys {
    pub public_key: DualRNSPublicKey,
    pub eval_key: DualRNSEvalKey,
}

/// Client-side key material: the decryption key. Never handed to the
/// evaluator; `CramPublicEvaluator` has no method that accepts it.
pub struct CramClientKeys {
    pub secret_key: DualRNSSecretKey,
    pub public_key: DualRNSPublicKey,
}

/// The public-only CRAM evaluator. Wraps `RNSFHEContext` and exposes the
/// public surface exclusively, with an emission ledger on every operation.
pub struct CramPublicEvaluator {
    ctx: RNSFHEContext,
    ledger: EmissionLedger,
}

impl CramPublicEvaluator {
    pub fn new(config: &FHEConfig) -> Self {
        Self {
            ctx: RNSFHEContext::new(config),
            ledger: EmissionLedger::default(),
        }
    }

    /// The underlying context, read-only (diagnostics, parameters).
    pub fn context(&self) -> &RNSFHEContext {
        &self.ctx
    }

    pub fn ledger(&self) -> &EmissionLedger {
        &self.ledger
    }

    // ── key generation ───────────────────────────────────────────────────

    /// Generate the public-mode key split: evaluator keys (public + eval)
    /// and client keys (secret + public). Uses the deep public
    /// relinearization base so public multiplication chains have depth
    /// headroom.
    pub fn keygen_with_rng<R: FheRng>(&self, rng: &mut R) -> (CramPublicKeys, CramClientKeys) {
        let keys = self.ctx.generate_keys_dual_full_public_deep_with_rng(rng);
        (
            CramPublicKeys {
                public_key: keys.public_key.clone(),
                eval_key: keys.eval_key,
            },
            CramClientKeys {
                secret_key: keys.secret_key,
                public_key: keys.public_key,
            },
        )
    }

    /// M3 — same key split as [`Self::keygen_with_rng`], plus the RNS-limb
    /// gadget key ([`crate::ops::rns_fhe::DualRNSGadgetKey`]) for
    /// [`Self::mul_manufactured_gadget`]. Requires a manufactured chain
    /// (typed error otherwise). Additive: [`Self::keygen_with_rng`] is
    /// unchanged and still the entry point for the digit-based path.
    pub fn keygen_with_gadget_with_rng<R: FheRng>(
        &self,
        rng: &mut R,
    ) -> Nine65Result<(
        CramPublicKeys,
        crate::ops::rns_fhe::DualRNSGadgetKey,
        CramClientKeys,
    )> {
        let keys = self.ctx.generate_keys_dual_full_public_deep_with_rng(rng);
        let gadget = self
            .ctx
            .generate_gadget_key_with_rng(&keys.secret_key, rng)?;
        Ok((
            CramPublicKeys {
                public_key: keys.public_key.clone(),
                eval_key: keys.eval_key,
            },
            gadget,
            CramClientKeys {
                secret_key: keys.secret_key,
                public_key: keys.public_key,
            },
        ))
    }

    // ── client half (encrypt / decrypt) ──────────────────────────────────

    /// Public-key encryption (client side).
    pub fn encrypt_with_rng<R: FheRng>(
        &self,
        m: u64,
        pk: &DualRNSPublicKey,
        rng: &mut R,
    ) -> DualRNSCiphertext {
        self.ctx.encrypt_dual_with_rng(m, pk, rng)
    }

    /// Decryption (client side). Takes the client keys; the evaluator never
    /// holds them.
    pub fn decrypt(&self, ct: &DualRNSCiphertext, client: &CramClientKeys) -> u64 {
        self.ctx.decrypt_dual(ct, &client.secret_key)
    }

    // ── lane-local evaluator operations ──────────────────────────────────

    pub fn add(&mut self, a: &DualRNSCiphertext, b: &DualRNSCiphertext) -> DualRNSCiphertext {
        self.ledger.record("add", EmissionClass::LaneLocal);
        self.ctx.add_dual(a, b)
    }

    pub fn sub(&mut self, a: &DualRNSCiphertext, b: &DualRNSCiphertext) -> DualRNSCiphertext {
        self.ledger.record("sub", EmissionClass::LaneLocal);
        self.ctx.sub_dual(a, b)
    }

    pub fn add_plain(&mut self, a: &DualRNSCiphertext, scalar: u64) -> DualRNSCiphertext {
        self.ledger.record("add_plain", EmissionClass::LaneLocal);
        self.ctx.add_plain_dual(a, scalar)
    }

    pub fn mul_plain(&mut self, a: &DualRNSCiphertext, scalar: u64) -> DualRNSCiphertext {
        self.ledger.record("mul_plain", EmissionClass::LaneLocal);
        self.ctx.mul_plain_dual(a, scalar)
    }

    pub fn negate(&mut self, a: &DualRNSCiphertext) -> DualRNSCiphertext {
        self.ledger.record("negate", EmissionClass::LaneLocal);
        self.ctx.negate_dual(a)
    }

    /// Exact lane-wise division by a unit divisor: every main and anchor
    /// lane multiplied by the lane reciprocal, no lane dropped, `level`
    /// untouched, no reconstruction. Refuses (typed error) any divisor that
    /// is not a unit on every lane — refuse, don't corrupt.
    pub fn exact_divide(
        &mut self,
        ct: &DualRNSCiphertext,
        d: u64,
    ) -> Nine65Result<DualRNSCiphertext> {
        let out = DualRNSCiphertext {
            c0: self.exact_divide_poly(&ct.c0, d)?,
            c1: self.exact_divide_poly(&ct.c1, d)?,
            level: ct.level,
        };
        self.ledger.record("exact_divide", EmissionClass::LaneLocal);
        Ok(out)
    }

    fn lane_reciprocal(d: u64, prime: u64) -> Nine65Result<u64> {
        let (g, x, _) = extended_gcd((d % prime) as i128, prime as i128);
        if g != 1 {
            return Err(Nine65Error::InvalidParameter {
                message: format!(
                    "exact_divide: divisor {d} is not a unit on lane {prime} (gcd={g}); \
                     route through FPD (aux lane) instead of corrupting the lane"
                ),
            });
        }
        Ok(((x % prime as i128 + prime as i128) % prime as i128) as u64)
    }

    fn exact_divide_poly(&self, poly: &DualRNSPoly, d: u64) -> Nine65Result<DualRNSPoly> {
        let divide_lane = |limb: &[u64], prime: u64| -> Nine65Result<Vec<u64>> {
            let inv = Self::lane_reciprocal(d, prime)? as u128;
            let p = prime as u128;
            Ok(limb
                .iter()
                .map(|&r| ((r as u128 * inv) % p) as u64)
                .collect())
        };
        let mut main = Vec::with_capacity(poly.main.len());
        for (i, limb) in poly.main.iter().enumerate() {
            main.push(divide_lane(limb, self.ctx.config.primes[i])?);
        }
        let mut anchor = Vec::with_capacity(poly.anchor.len());
        for (j, limb) in poly.anchor.iter().enumerate() {
            anchor.push(divide_lane(limb, self.ctx.dual_rns.anchor.primes[j])?);
        }
        Ok(DualRNSPoly {
            main,
            anchor,
            n: poly.n,
        })
    }

    // ── the multiply: correct, and honestly classified ───────────────────

    /// Public ct x ct multiplication. Correct (exact decrypts, basis never
    /// moves), recorded as an R8-class MATERIALIZATION — a gate-qualified
    /// classification, not a predisposition: order-equivariant bit-exact
    /// (G2 PASS, so no Garner cascade), i.i.d.-coupled (measured), declared
    /// Delta-discard (G1 METERED via the noise ledger), derivable constants
    /// (G5). Elimination-first replacement of the two materialization sites
    /// is milestones M2/M3; until then the ledger tells the truth about
    /// every chain that includes a multiply.
    /// M2b variant: public multiply with the elimination-first rescale
    /// (`k_elim_rescale_manufactured` — no value materialization in the
    /// rescale; align-and-drop + certified anchor-ladder winding read).
    /// Requires a manufactured chain (`t | Q`, `t` a main lane). Still
    /// recorded as an R8 materialization because relinearization
    /// (`extract_digit_dual`) materializes until milestone M3 lands.
    pub fn mul_manufactured(
        &mut self,
        a: &DualRNSCiphertext,
        b: &DualRNSCiphertext,
        keys: &CramPublicKeys,
    ) -> Nine65Result<DualRNSCiphertext> {
        let out = self
            .ctx
            .mul_dual_public_manufactured(a, b, &keys.eval_key)?;
        self.ledger
            .record("mul_m2b", EmissionClass::Materialization);
        Ok(out)
    }

    /// M3+M4 — manufactured-chain multiply with the RNS-limb gadget relin.
    /// Rescale (M2b) and relin (M3) are both elimination-first — zero
    /// `to_u256_level` calls in either step, guardrail-pinned by
    /// `ops::rns_fhe::tests::m3_guardrail_gadget_relin_never_calls_to_u256_level`
    /// — so this is recorded as [`EmissionClass::EliminationFirst`], NOT
    /// `Materialization`. Read that variant's doc comment for the precise
    /// scope: `canonicalize_dual_anchor` (called at the end of this
    /// multiply, same as the digit-based path) still performs its own,
    /// separate, already gate-qualified materialization — this
    /// classification is about the multiply's rescale+relin CORE, not a
    /// claim that the whole call graph is materialization-free.
    /// **Depth scope:** only measured reliable to depth 2 (see
    /// `docs/CRAM_PUBLIC_MODE.md` M3 finding) — this classification is
    /// about WHAT COMPUTATION RAN, not a noise/correctness guarantee at
    /// arbitrary depth.
    pub fn mul_manufactured_gadget(
        &mut self,
        a: &DualRNSCiphertext,
        b: &DualRNSCiphertext,
        gadget: &crate::ops::rns_fhe::DualRNSGadgetKey,
    ) -> Nine65Result<DualRNSCiphertext> {
        let out = self.ctx.mul_dual_public_manufactured_gadget(a, b, gadget)?;
        self.ledger
            .record("mul_m3_gadget", EmissionClass::EliminationFirst);
        Ok(out)
    }

    pub fn mul(
        &mut self,
        a: &DualRNSCiphertext,
        b: &DualRNSCiphertext,
        keys: &CramPublicKeys,
    ) -> Nine65Result<DualRNSCiphertext> {
        let out = self.ctx.mul_dual_public(a, b, &keys.eval_key)?;
        self.ledger.record("mul", EmissionClass::Materialization);
        Ok(out)
    }
}
