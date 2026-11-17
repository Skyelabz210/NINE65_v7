import Std

/-!
# Dense phase-clock ring return

The implementation in `phase_clock_return.rs` extracts residue class zero
under `X = Y^D`.  A product of classes `r,s < D` contributes precisely for
`(r,s) = (0,0)` or `s = D-r` with `r > 0`.  The latter case carries one
factor of `X`; it cannot be dropped even if the plaintext was embedded in
class zero, because the ciphertext components use the full dense secret.

This file proves that identity for every ratio `D > 0` and work degree
`N > 0`, including the negacyclic sign.  Monomial lists represent an
unnormalized polynomial expansion: equality of the lists is stronger than
equality after collecting equal degrees.  This is an algebraic theorem,
not a proof of key-switch noise, key security, or Rust code refinement.
-/

set_option warningAsError true

namespace KElimination.PublicRefreshReturn

/-- A monomial in the work variable, before reduction modulo `X^N + 1`. -/
structure Monomial where
  degree : Nat
  coefficient : Int
  deriving DecidableEq, Repr

/-- The sign introduced by `X^N = -1`. -/
def negacyclicSign (turns : Nat) : Int :=
  if turns % 2 = 0 then 1 else -1

/-- Canonical monomial reduction, including every negacyclic turn. -/
def reduceMonomial (N degree : Nat) (coefficient : Int) : Monomial :=
  ⟨degree % N, coefficient * negacyclicSign (degree / N)⟩

/-- A boot-ring monomial given by its work degree and residue class. -/
structure BlockMonomial where
  workDegree : Nat
  residue : Nat
  coefficient : Int
  deriving DecidableEq, Repr

/-- Exactly the two cases that can land in class zero. -/
theorem residue_zero_iff (D r s : Nat) (hD : 0 < D)
    (hr : r < D) (hs : s < D) :
    (r + s) % D = 0 ↔
      (r = 0 ∧ s = 0) ∨ (0 < r ∧ s = D - r) := by
  have hsum : r + s < 2 * D := by omega
  have hdiv : r + s = (r + s) % D + D * ((r + s) / D) :=
    (Nat.mod_add_div (r + s) D).symm
  have hquot : (r + s) / D < 2 := (Nat.div_lt_iff_lt_mul hD).2 (by omega)
  constructor
  · intro hz
    rw [hz] at hdiv
    generalize heq : (r + s) / D = q at hdiv hquot
    have hc : q = 0 ∨ q = 1 := by omega
    rcases hc with h | h
    · left
      rw [h] at hdiv
      omega
    · right
      rw [h] at hdiv
      omega
  · rintro (⟨rfl, rfl⟩ | ⟨hr0, hsEq⟩)
    · simp
    · have : r + s = D := by omega
      simp [this]

/-- The boot exponent has the expected block quotient and residue. -/
theorem block_degree_div_mod (D a b r s : Nat) (hD : 0 < D) :
    ((D * a + r) + (D * b + s)) / D = a + b + (r + s) / D ∧
    ((D * a + r) + (D * b + s)) % D = (r + s) % D := by
  have hexp : (D * a + r) + (D * b + s) = (r + s) + D * (a + b) := by
    simp only [Nat.mul_add]
    omega
  rw [hexp]
  constructor
  · rw [Nat.add_mul_div_left _ _ hD]
    omega
  · simp

/-- Reduction in the boot ring and then division by `D` has exactly the
    same winding count as reduction in the work ring. -/
theorem negacyclic_quotient_identity (D N degree : Nat) :
    degree / (D * N) = (degree / D) / N := by
  rw [Nat.div_div_eq_div_mul]

/-- Extract the class-zero monomial of an actual boot product.
The sign is computed in the boot ring of degree `D*N`. -/
def extractedPair (D N : Nat) (a b : BlockMonomial) : Option Monomial :=
  let exponent := (D * a.workDegree + a.residue) + (D * b.workDegree + b.residue)
  if exponent % D = 0 then
    some ⟨(exponent / D) % N,
      a.coefficient * b.coefficient * negacyclicSign (exponent / (D * N))⟩
  else none

/-- First reduce the product in the boot ring `Y^(D*N) = -1`, then
extract its class-zero block. This is the direct ring interpretation. -/
def bootProjectedPair (D N : Nat) (a b : BlockMonomial) : Option Monomial :=
  let exponent := (D * a.workDegree + a.residue) + (D * b.workDegree + b.residue)
  let bootDegree := exponent % (D * N)
  if bootDegree % D = 0 then
    some ⟨bootDegree / D,
      a.coefficient * b.coefficient * negacyclicSign (exponent / (D * N))⟩
  else none

/-- Actual boot reduction commutes with block extraction, without an
assumption on the degrees or coefficients of either monomial. -/
theorem boot_projection_eq_extracted_pair (D N : Nat) (a b : BlockMonomial) :
    bootProjectedPair D N a b = extractedPair D N a b := by
  simp only [bootProjectedPair, extractedPair, Nat.mod_mul_right_mod,
    Nat.mod_mul_right_div_self]

/-- The two branches implemented by the dense ring return. Nonzero
complementary blocks are multiplied by `X` before work-ring reduction. -/
def returnedPair (D N : Nat) (a b : BlockMonomial) : Option Monomial :=
  if a.residue = 0 ∧ b.residue = 0 then
    some (reduceMonomial N (a.workDegree + b.workDegree) (a.coefficient * b.coefficient))
  else if 0 < a.residue ∧ b.residue = D - a.residue then
    some (reduceMonomial N (a.workDegree + b.workDegree + 1)
      (a.coefficient * b.coefficient))
  else none

/-- Every coefficient product, including its work degree and negacyclic
sign, agrees with the unshifted-zero plus shifted-complementary rule. -/
theorem extracted_pair_eq_returned_pair (D N : Nat) (hD : 0 < D)
    (a b : BlockMonomial) (ha : a.residue < D) (hb : b.residue < D) :
    extractedPair D N a b = returnedPair D N a b := by
  have hblock := block_degree_div_mod D a.workDegree b.workDegree a.residue b.residue hD
  simp only [extractedPair, negacyclic_quotient_identity, hblock.1, hblock.2]
  unfold returnedPair
  by_cases hz : a.residue = 0 ∧ b.residue = 0
  · rcases hz with ⟨har, hbr⟩
    simp [har, hbr, reduceMonomial]
  · by_cases hc : 0 < a.residue ∧ b.residue = D - a.residue
    · have hsum : a.residue + b.residue = D := by omega
      rw [if_neg hz, if_pos hc, hsum]
      simp [hD, reduceMonomial]
    · have hnot : (a.residue + b.residue) % D ≠ 0 := by
        intro heq
        rcases (residue_zero_iff D a.residue b.residue hD ha hb).1 heq with h | h
        · exact hz h
        · exact hc h
      simp [hz, hc, hnot]

/-- The complete dense product expansion, without discarding secret
blocks whose residue class is nonzero. -/
def extractedProduct (D N : Nat) (as bs : List BlockMonomial) : List Monomial :=
  as.flatMap fun a => bs.filterMap fun b => extractedPair D N a b

/-- The return expansion, using one `X` shift for each complementary pair. -/
def returnedProduct (D N : Nat) (as bs : List BlockMonomial) : List Monomial :=
  as.flatMap fun a => bs.filterMap fun b => returnedPair D N a b

/-- The finite dense product, reduced in the boot ring before projection. -/
def bootProjectedProduct (D N : Nat) (as bs : List BlockMonomial) : List Monomial :=
  as.flatMap fun a => bs.filterMap fun b => bootProjectedPair D N a b

/-- General dense ring-return identity for finite polynomial expansions.
It does not assume sparsity or zero nonconstant secret blocks. -/
theorem dense_product_return (D N : Nat) (hD : 0 < D)
    (as bs : List BlockMonomial)
    (ha : ∀ a ∈ as, a.residue < D) (hb : ∀ b ∈ bs, b.residue < D) :
    extractedProduct D N as bs = returnedProduct D N as bs := by
  unfold extractedProduct returnedProduct
  have hmap (a : BlockMonomial) (ha' : a.residue < D) :
      bs.filterMap (fun b => extractedPair D N a b) =
      bs.filterMap (fun b => returnedPair D N a b) := by
    induction bs with
    | nil => rfl
    | cons b tail ih =>
      have heq := extracted_pair_eq_returned_pair D N hD a b ha' (hb b (by simp))
      have htail : ∀ b ∈ tail, b.residue < D := by
        intro b hmem
        exact hb b (by simp [hmem])
      simp only [List.filterMap_cons, heq, ih htail]
  induction as with
  | nil => rfl
  | cons a tail ih =>
    have htail : ∀ a ∈ tail, a.residue < D := by
      intro a hmem
      exact ha a (by simp [hmem])
    simp only [List.flatMap_cons, hmap a (ha a (by simp)), ih htail]

/-- The direct boot-ring product, reduced modulo `Y^(D*N) + 1` and
projected to class zero, equals the return kernel's complete shifted
complementary-block expansion modulo `X^N + 1`. -/
theorem dense_boot_product_return (D N : Nat) (hD : 0 < D)
    (as bs : List BlockMonomial)
    (ha : ∀ a ∈ as, a.residue < D) (hb : ∀ b ∈ bs, b.residue < D) :
    bootProjectedProduct D N as bs = returnedProduct D N as bs := by
  simp only [bootProjectedProduct, boot_projection_eq_extracted_pair]
  exact dense_product_return D N hD as bs ha hb

/-- Boot-ring reduction and projection for an individual `c0` monomial. -/
def bootProjectedBase (D N : Nat) (a : BlockMonomial) : Option Monomial :=
  let exponent := D * a.workDegree + a.residue
  if (exponent % (D * N)) % D = 0 then
    some ⟨(exponent % (D * N)) / D,
      a.coefficient * negacyclicSign (exponent / (D * N))⟩
  else none

/-- The `c0` component needs only its zero block, without an extra shift. -/
def returnedBase (N : Nat) (a : BlockMonomial) : Option Monomial :=
  if a.residue = 0 then some (reduceMonomial N a.workDegree a.coefficient) else none

theorem boot_projection_eq_returned_base (D N : Nat) (hD : 0 < D)
    (a : BlockMonomial) (ha : a.residue < D) :
    bootProjectedBase D N a = returnedBase N a := by
  have hdiv : (D * a.workDegree + a.residue) / D = a.workDegree := by
    rw [Nat.add_comm, Nat.add_mul_div_left _ _ hD, Nat.div_eq_of_lt ha]
    simp
  have hmod : (D * a.workDegree + a.residue) % D = a.residue := by
    simp [Nat.add_mod, Nat.mod_eq_of_lt ha]
  simp only [bootProjectedBase, returnedBase, Nat.mod_mul_right_mod,
    Nat.mod_mul_right_div_self, negacyclic_quotient_identity, hdiv, hmod,
    reduceMonomial]

/-- Complete algebraic phase identity for `c0 + c1*s`. The list append
represents addition of the two unnormalized polynomial expansions. -/
theorem dense_phase_return (D N : Nat) (hD : 0 < D)
    (c0 c1 secret : List BlockMonomial)
    (h0 : ∀ a ∈ c0, a.residue < D) (h1 : ∀ a ∈ c1, a.residue < D)
    (hs : ∀ a ∈ secret, a.residue < D) :
    c0.filterMap (bootProjectedBase D N) ++ bootProjectedProduct D N c1 secret =
      c0.filterMap (returnedBase N) ++ returnedProduct D N c1 secret := by
  have hbase : c0.filterMap (bootProjectedBase D N) = c0.filterMap (returnedBase N) := by
    induction c0 with
    | nil => rfl
    | cons a tail ih =>
      have heq := boot_projection_eq_returned_base D N hD a (h0 a (by simp))
      have htail : ∀ a ∈ tail, a.residue < D := by
        intro a hmem
        exact h0 a (by simp [hmem])
      simp only [List.filterMap_cons, heq, ih htail]
  rw [hbase, dense_boot_product_return D N hD c1 secret h1 hs]

/-- Omitting the `X` shift loses a real term even for the smallest
nontrivial ratio. This is a kernel-checked counterexample to block0-only
return: `Y * Y = X` when `D=2`. -/
theorem complementary_term_requires_shift :
    extractedPair 2 4 ⟨0, 1, 1⟩ ⟨0, 1, 1⟩ = some ⟨1, 1⟩ := by decide

/-- The same shift carries the negacyclic minus sign at the boundary. -/
theorem complementary_term_negacyclic_sign :
    extractedPair 2 4 ⟨1, 1, 1⟩ ⟨2, 1, 1⟩ = some ⟨0, -1⟩ := by decide

end KElimination.PublicRefreshReturn
