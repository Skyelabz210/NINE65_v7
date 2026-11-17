/-
Scope clarification, 2026-11-12.

The bounded K-recovery statements below retain their exact premises.
A mathematical quotient used in a specification is not a requirement to store
a persistent scalar K in production. Current CRAM intent derives K on demand
at each winding from authentic phase-locked residue/anchor state and supports
heterogeneous CRT trays. Garner/mixed-radix synthetic emission is retired from
residue compute; declared reconstruction remains permitted.

These proofs alone do not establish runtime source binding, state layout,
an O(1) magnitude gauge, ciphertext refresh, or security of a full FHE system.
The declared complexity functions are not extracted Rust operation counts.
See https://github.com/Skyelabz210/qmnf-lean-coq-security-proofs/blob/main/docs/CRAM_INTENT_AND_PROOF_SCOPE.md
-/

/-
  K-Elimination: Exact Division in Residue Number Systems

  A 60-Year Breakthrough in RNS Arithmetic
  QMNF Advanced Mathematics, December 2025

  Formalized in Lean 4 with Mathlib
-/

import Mathlib.Data.ZMod.Basic
import Mathlib.Data.Nat.GCD.Basic
import Mathlib.RingTheory.Coprime.Basic
import Mathlib.Tactic.Ring
import KElimination.Basic
import KElimination.UniversalResearch.AllCampaign
import KElimination.AnchorSaturation

/-!
# K-Elimination Theorem

For a value X represented in two coprime modulus systems (main M, anchor A):
- v_M = X mod M  (main residue)
- v_A = X mod A  (anchor residue)
- k = floor(X / M)  (overflow count)

The K-Elimination theorem proves:
  k ≡ (v_A - v_M) * M⁻¹ (mod A)

This enables exact k recovery without floating-point approximation.
-/

namespace KElimination

/-! ## Basic Definitions -/

/-- The overflow count k for value X with modulus product M -/
def overflow_count (X M : ℕ) : ℕ := X / M

/-- Main residue: X mod M -/
def main_residue (X M : ℕ) : ℕ := X % M

/-- Anchor residue: X mod A -/
def anchor_residue (X A : ℕ) : ℕ := X % A

/-- Phase differential -/
def phase_diff (v_A v_M A : ℕ) : ℕ := (v_A + A - v_M % A) % A

/-- RNS Configuration -/
structure RNSConfig where
  M : ℕ
  A : ℕ
  coprime : Nat.Coprime M A
  M_pos : M > 0
  A_pos : A > 0

/-! ## Division Algorithm Lemmas -/

/-- Division Algorithm: M * (X / M) + X % M = X -/
theorem div_add_mod (X M : ℕ) : M * (X / M) + X % M = X :=
  Nat.div_add_mod X M

/-- Alternative form: X % M + M * (X / M) = X -/
theorem mod_add_div (X M : ℕ) : X % M + M * (X / M) = X := by
  have h := Nat.div_add_mod X M
  omega

/-- Commutativity form: X = X % M + (X / M) * M -/
theorem div_mod_identity (X M : ℕ) : X = X % M + (X / M) * M := by
  have h := mod_add_div X M
  have hcomm : M * (X / M) = (X / M) * M := Nat.mul_comm M (X / M)
  rw [hcomm] at h
  exact h.symm

/-- Residue is bounded -/
theorem residue_lt_mod (X M : ℕ) (hM : M > 0) : X % M < M :=
  Nat.mod_lt X hM

/-- Division bound -/
theorem div_mul_le (X M : ℕ) : (X / M) * M ≤ X :=
  Nat.div_mul_le_self X M

/-! ## Range Bounds for k -/

/-- If X < M * A then X / M < A -/
theorem k_lt_A (X M A : ℕ) (hRange : X < M * A) : X / M < A :=
  Nat.div_lt_of_lt_mul hRange

/-- When k < A, k mod A = k -/
theorem k_mod_eq_k (k A : ℕ) (hk : k < A) : k % A = k :=
  Nat.mod_eq_of_lt hk

/-! ## Key Congruence (THE CORE INSIGHT) -/

/--
  KEY LEMMA: The anchor residue equals the reconstruction formula mod A

  X % A = (X % M + (X / M) * M) % A

  This is the algebraic foundation of K-Elimination.
-/
theorem key_congruence (X M A : ℕ) :
    X % A = (X % M + (X / M) * M) % A := by
  have h : X = X % M + (X / M) * M := div_mod_identity X M
  calc X % A = (X % M + (X / M) * M) % A := by rw [← h]

/-! ## Modular Arithmetic Properties -/

/-- (a + b * M) % M = a % M -/
theorem add_mul_mod (a b M : ℕ) : (a + b * M) % M = a % M :=
  Nat.add_mul_mod_self_right a b M

/-- When a < M: (a + b * M) % M = a -/
theorem add_mul_mod_small (a b M : ℕ) (ha : a < M) : (a + b * M) % M = a := by
  rw [add_mul_mod]
  exact Nat.mod_eq_of_lt ha

/-! ## Modular Inverse -/

/-- When gcd(M, A) = 1, the modular inverse exists -/
theorem modular_inverse_exists (M A : ℕ) (hA : A > 1) (hcop : Nat.Coprime M A) :
    ∃ M_inv : ℕ, (M * M_inv) % A = 1 := by
  have hApos : A > 0 := Nat.lt_trans Nat.zero_lt_one hA
  have hAne : NeZero A := ⟨Nat.pos_iff_ne_zero.mp hApos⟩
  haveI : Fact (1 < A) := ⟨hA⟩
  -- Use unitOfCoprime to get the unit
  let u := ZMod.unitOfCoprime M hcop
  -- The inverse element
  let inv_unit := u⁻¹
  use ZMod.val inv_unit.val
  -- Key: M * u⁻¹ = 1 in ZMod A
  have hmul : (M : ZMod A) * inv_unit.val = 1 := by
    have hu : (u : ZMod A) = (M : ZMod A) := ZMod.coe_unitOfCoprime M hcop
    rw [← hu]
    exact Units.mul_inv u
  -- val of inv_unit coerced back is inv_unit
  have hvalcast : (ZMod.val inv_unit.val : ZMod A) = inv_unit.val := ZMod.natCast_zmod_val inv_unit.val
  -- Convert: (M * inv.val) mod A = val of (M * inv) in ZMod A = val of 1 = 1
  have hmod : (M * ZMod.val inv_unit.val) % A = ZMod.val ((M : ZMod A) * inv_unit.val) := by
    rw [← ZMod.val_natCast (n := A)]
    congr 1
    push_cast
    rw [hvalcast]
  rw [hmod, hmul]
  exact ZMod.val_one (n := A)

/-! ## Reconstruction Theorems -/

/-- X can be reconstructed from vM and k -/
theorem reconstruction (X M : ℕ) :
    X = main_residue X M + overflow_count X M * M := by
  unfold main_residue overflow_count
  exact div_mod_identity X M

/-- Reconstruction preserves the main residue -/
theorem reconstruction_mod (X M : ℕ) (hM : 0 < M) :
    (main_residue X M + overflow_count X M * M) % M = main_residue X M := by
  unfold main_residue overflow_count
  rw [add_mul_mod]
  exact Nat.mod_eq_of_lt (residue_lt_mod X M hM)

/-! ## K-Elimination Core Theorem -/

/--
  K-Elimination Core Theorem

  For X in range [0, M*A):
  1. The overflow count k = X / M is bounded by A
  2. The key congruence holds: X % A = (vM + k * M) % A
-/
theorem kElimination_core (X M A : ℕ) (_hM : 0 < M) (hRange : X < M * A) :
    let vM := X % M
    let k := X / M
    -- Part 1: k is bounded
    k < A ∧
    -- Part 2: Key congruence holds
    X % A = (vM + k * M) % A := by
  constructor
  · -- k < A
    exact k_lt_A X M A hRange
  · -- X % A = (vM + k * M) % A
    exact key_congruence X M A

/-- K-Elimination Uniqueness: k % A = k when X < M * A -/
theorem kElimination_unique (X M A : ℕ) (_hM : 0 < M) (hRange : X < M * A) :
    (X / M) % A = X / M := by
  apply Nat.mod_eq_of_lt
  exact k_lt_A X M A hRange

/-! ## Validation Identities -/

/-- V1: Basic reconstruction -/
theorem validation_v1 (X M : ℕ) : X = X % M + (X / M) * M :=
  div_mod_identity X M

/-- V2: Main residue consistency -/
theorem validation_v2 (X M : ℕ) (hM : 0 < M) :
    (X % M + (X / M) * M) % M = X % M := by
  rw [add_mul_mod]
  exact Nat.mod_eq_of_lt (residue_lt_mod X M hM)

/-- V3: Anchor residue consistency (key congruence) -/
theorem validation_v3 (X M A : ℕ) :
    (X % M + (X / M) * M) % A = X % A := by
  have h := div_mod_identity X M
  rw [← h]

/-- V4: k uniqueness when k < A -/
theorem validation_v4 (k A : ℕ) (hk : k < A) : k % A = k :=
  Nat.mod_eq_of_lt hk

/-- V5: Remainder bounds -/
theorem validation_v5 (X d : ℕ) (hd : 0 < d) : X % d < d :=
  Nat.mod_lt X hd

/-- V6: k range bound -/
theorem validation_v6 (X M A : ℕ) (_hM : 0 < M) (hRange : X < M * A) :
    X / M < A := k_lt_A X M A hRange

/-! ## Division Correctness -/

/-- After k-recovery, division is exact when d divides X -/
theorem division_exact (X d : ℕ) (hdiv : d ∣ X) :
    X % d = 0 := Nat.mod_eq_zero_of_dvd hdiv

/-- Division produces correct quotient and remainder -/
theorem division_correct (X M : ℕ) (hM : 0 < M) :
    X = (X / M) * M + X % M ∧ X % M < M := by
  constructor
  · have h := div_mod_identity X M; omega
  · exact residue_lt_mod X M hM

/-! ## Complexity -/

def k_elimination_complexity (k l : ℕ) : ℕ := k + l

def mrc_complexity (k : ℕ) : ℕ := k * k

theorem complexity_improvement (k : ℕ) (hk : k > 1) :
    k_elimination_complexity k 0 < mrc_complexity k := by
  simp only [k_elimination_complexity, mrc_complexity, Nat.add_zero]
  -- k < k * k when k > 1
  have hk2 : k ≥ 2 := hk
  have hmul : k * k ≥ k * 2 := Nat.mul_le_mul_left k hk2
  omega

end KElimination

/-! ## Soundness -/

namespace Soundness

theorem k_elimination_sound (cfg : KElimination.RNSConfig) (X : ℕ)
    (hX : X < cfg.M * cfg.A) (M_inv : ℕ) (hMinv : (cfg.M * M_inv) % cfg.A = 1) :
    let v_M := X % cfg.M
    let v_A := X % cfg.A
    let k_true := X / cfg.M
    let phase := (v_A + cfg.A - v_M % cfg.A) % cfg.A
    let k_computed := (phase * M_inv) % cfg.A
    k_computed = k_true := by
    simp only
    have hAne : NeZero cfg.A := ⟨Nat.pos_iff_ne_zero.mp cfg.A_pos⟩
    have hkLt : X / cfg.M < cfg.A := Nat.div_lt_of_lt_mul hX
    have hkMod : (X / cfg.M) % cfg.A = X / cfg.M := Nat.mod_eq_of_lt hkLt
    have hfund : X = X % cfg.M + (X / cfg.M) * cfg.M := KElimination.div_mod_identity X cfg.M
    -- Work in ZMod cfg.A
    have hXmodA : (X % cfg.A : ZMod cfg.A) = (X : ZMod cfg.A) := ZMod.natCast_mod X cfg.A
    have hvMmodA : (X % cfg.M % cfg.A : ZMod cfg.A) = (X % cfg.M : ZMod cfg.A) := ZMod.natCast_mod (X % cfg.M) cfg.A
    have hAzero : (cfg.A : ZMod cfg.A) = 0 := ZMod.natCast_self cfg.A
    -- M * M_inv = 1 in ZMod A
    have hMinvZMod : (cfg.M : ZMod cfg.A) * (M_inv : ZMod cfg.A) = 1 := by
      -- hMinv : cfg.M * M_inv % cfg.A = 1
      -- Use ZMod.natCast_mod: (n : ZMod A) = (n % A : ZMod A)
      -- So (M * M_inv % A : ZMod A) = (M * M_inv : ZMod A)
      -- And hMinv tells us M * M_inv % A = 1
      -- Therefore (M * M_inv : ZMod A) = (1 : ZMod A)
      have h : ((cfg.M * M_inv : ℕ) : ZMod cfg.A) = (1 : ZMod cfg.A) := by
        have mod_eq : ((cfg.M * M_inv : ℕ) : ZMod cfg.A) = ((cfg.M * M_inv) % cfg.A : ZMod cfg.A) := by
          rw [ZMod.natCast_mod]
        simp only [mod_eq, hMinv, Nat.cast_one]
      -- Now use Nat.cast_mul: ↑(a * b) = ↑a * ↑b
      rw [← Nat.cast_mul]
      exact h
    -- X = vM + k*M in ZMod A
    have hXeq : (X : ZMod cfg.A) = (X % cfg.M : ZMod cfg.A) + (X / cfg.M : ZMod cfg.A) * (cfg.M : ZMod cfg.A) := by
      conv_lhs => rw [hfund]
      push_cast
      ring
    -- phase = k*M in ZMod A
    have hsub : X % cfg.M % cfg.A ≤ X % cfg.A + cfg.A := by
      have h : X % cfg.M % cfg.A < cfg.A := Nat.mod_lt _ cfg.A_pos; omega
    have hphase : ((X % cfg.A + cfg.A - X % cfg.M % cfg.A) % cfg.A : ZMod cfg.A)
                = (X / cfg.M : ZMod cfg.A) * (cfg.M : ZMod cfg.A) := by
      rw [ZMod.natCast_mod]
      rw [Nat.cast_sub hsub]
      push_cast
      rw [hXmodA, hvMmodA, hAzero, add_zero, hXeq]
      ring
    -- phase * M_inv = k in ZMod A
    have hresult : ((X % cfg.A + cfg.A - X % cfg.M % cfg.A) % cfg.A : ZMod cfg.A) * (M_inv : ZMod cfg.A)
                 = (X / cfg.M : ZMod cfg.A) := by
      rw [hphase]
      calc (X / cfg.M : ZMod cfg.A) * (cfg.M : ZMod cfg.A) * (M_inv : ZMod cfg.A)
          = (X / cfg.M : ZMod cfg.A) * ((cfg.M : ZMod cfg.A) * (M_inv : ZMod cfg.A)) := by ring
        _ = (X / cfg.M : ZMod cfg.A) * 1 := by rw [hMinvZMod]
        _ = (X / cfg.M : ZMod cfg.A) := by ring
    -- Convert back to ℕ using ZMod.val
    suffices h : ((X % cfg.A + cfg.A - X % cfg.M % cfg.A) % cfg.A * M_inv) % cfg.A
               = (X / cfg.M) % cfg.A by rw [h, hkMod]
    -- Use ZMod.val_natCast: (n : ZMod A).val = n % A for casting
    have lhs_val : ((X % cfg.A + cfg.A - X % cfg.M % cfg.A) % cfg.A * M_inv) % cfg.A
                 = ZMod.val (((X % cfg.A + cfg.A - X % cfg.M % cfg.A) % cfg.A : ZMod cfg.A) * (M_inv : ZMod cfg.A)) := by
      have cast_eq : (((X % cfg.A + cfg.A - X % cfg.M % cfg.A) % cfg.A * M_inv : ℕ) : ZMod cfg.A)
                   = ((X % cfg.A + cfg.A - X % cfg.M % cfg.A) % cfg.A : ZMod cfg.A) * (M_inv : ZMod cfg.A) := by
        push_cast; ring
      rw [← cast_eq, ZMod.val_natCast]
    have rhs_val : (X / cfg.M) % cfg.A = ZMod.val (X / cfg.M : ZMod cfg.A) := by
      rw [ZMod.val_natCast]
    rw [lhs_val, rhs_val, hresult]

theorem k_elimination_complete (cfg : KElimination.RNSConfig) (k : ℕ) (_hk : k < cfg.A)
    (v_M : ℕ) (hv : v_M < cfg.M) :
    let X := v_M + k * cfg.M
    X / cfg.M = k := by
  simp only
  rw [Nat.mul_comm k cfg.M]
  rw [Nat.add_mul_div_left v_M k cfg.M_pos]
  have hdiv : v_M / cfg.M = 0 := Nat.div_eq_of_lt hv
  omega

end Soundness

/-! ## Error Taxonomy -/

namespace ErrorTaxonomy

def coprimality_violation (M A : ℕ) : Prop := ¬Nat.Coprime M A

def range_overflow (M A X : ℕ) : Prop := X ≥ M * A

theorem detect_coprimality_violation (M A : ℕ) :
    coprimality_violation M A ↔ Nat.gcd M A ≠ 1 := by
  simp [coprimality_violation, Nat.Coprime]

end ErrorTaxonomy
