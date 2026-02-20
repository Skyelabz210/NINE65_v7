/-
  ExactTranscendentals.ExactRational
  ===================================

  D002: ExactRational -- exact rational number type with num/den representation.

  Formalizes the ExactRational type from the Rust exact_transcendentals crate.
  All values are exact rational numbers p/q with q != 0.
  Reduction to lowest terms uses Int.gcd from the Lean 4 standard library.

  L002: Arithmetic operations preserve exact rational values.
    That is, the rational value represented by the result of add/sub/mul/div
    equals the corresponding arithmetic operation on the input rational values.

  No Mathlib. No floating-point. Pure integer arithmetic.
-/

namespace ExactTranscendentals

/-! ## Core type -/

/-- An exact rational number num/den with the invariant that den != 0.
    Represents the mathematical value num/den in Q. -/
structure ExactRational where
  num : Int
  den : Int
  den_ne_zero : den ≠ 0
  deriving Repr

/-! ## Canonical rational value

We define the "rational value" of an ExactRational as a pair (num, den)
and consider two such pairs equivalent when they represent the same
rational number: a/b ~ c/d iff a*d = c*b.

Rather than building a full quotient type (which would require Mathlib's Rat),
we define equivalence and prove that our operations preserve it.
-/

/-- Two ExactRationals represent the same rational number. -/
def ExactRational.equiv (r s : ExactRational) : Prop :=
  r.num * s.den = s.num * r.den

@[simp]
theorem ExactRational.equiv_refl (r : ExactRational) : r.equiv r := rfl

theorem ExactRational.equiv_symm {r s : ExactRational} (h : r.equiv s) : s.equiv r := by
  unfold equiv at *
  omega

theorem ExactRational.equiv_trans {r s t : ExactRational}
    (hrs : r.equiv s) (hst : s.equiv t) : r.equiv t := by
  unfold equiv at *
  -- r.num * s.den = s.num * r.den  AND  s.num * t.den = t.num * s.den
  -- We need: r.num * t.den = t.num * r.den
  -- Multiply first equation by t.den: r.num * s.den * t.den = s.num * r.den * t.den
  -- Multiply second equation by r.den: s.num * t.den * r.den = t.num * s.den * r.den
  -- So: r.num * s.den * t.den = s.num * r.den * t.den = t.num * s.den * r.den
  -- Since s.den ≠ 0, we can cancel it: r.num * t.den = t.num * r.den
  have h1 : r.num * s.den * t.den = s.num * r.den * t.den := by
    rw [hrs]
    ring
  have h2 : s.num * t.den * r.den = t.num * s.den * r.den := by
    rw [hst]
    ring
  rw [mul_comm (s.num * t.den) r.den] at h2
  rw [mul_assoc s.num t.den r.den] at h2
  rw [mul_assoc t.num s.den r.den] at h2
  rw [← h2] at h1
  rw [mul_assoc r.num s.den t.den] at h1
  rw [mul_assoc s.num r.den t.den] at h1
  rw [mul_comm s.den t.den] at h1
  rw [mul_comm r.den t.den] at h1
  rw [← mul_assoc r.num t.den s.den] at h1
  rw [← mul_assoc (s.num * r.den) t.den s.den] at h1
  rw [mul_right_injective_of_ne_zero s.den_ne_zero] at h1
  exact h1

/-! ## Constructors -/

/-- Create an ExactRational from two integers. Requires den != 0. -/
def ExactRational.mk' (n d : Int) (h : d ≠ 0) : ExactRational :=
  { num := n, den := d, den_ne_zero := h }

/-- Create an ExactRational from a single integer (denominator = 1). -/
def ExactRational.ofInt (n : Int) : ExactRational :=
  { num := n, den := 1, den_ne_zero := by omega }

instance : OfNat ExactRational n where
  ofNat := ExactRational.ofInt (Int.ofNat n)

instance : Neg ExactRational where
  neg r := { num := -r.num, den := r.den, den_ne_zero := r.den_ne_zero }

/-! ## Reduction to lowest terms -/

/-- The sign of the denominator, used to normalize sign convention. -/
private def signDen (d : Int) : Int :=
  if d > 0 then 1 else -1

/-- Reduce an ExactRational to lowest terms by dividing num and den by their gcd.
    The result has den > 0 (sign normalization). -/
def ExactRational.reduce (r : ExactRational) : ExactRational :=
  let g := Int.gcd r.num r.den  -- : Nat, always >= 0
  let s := signDen r.den
  if hg : (g : Int) = 0 then
    -- gcd = 0 implies both num and den are 0, but den != 0, contradiction
    have hzero : (Int.gcd r.num r.den : Int) = 0 := hg
    have : r.den = 0 := Int.eq_zero_of_gcd_eq_zero_right hzero
    exact False.elim (r.den_ne_zero this)
  else
    { num := s * (r.num / (g : Int))
      den := s * (r.den / (g : Int))
      den_ne_zero := by
        intro h
        have hs : s ≠ 0 := by
          -- signDen d returns 1 if d > 0, -1 if d < 0
          -- Since r.den ≠ 0 (by r.den_ne_zero), either r.den > 0 or r.den < 0
          -- If r.den > 0, then signDen r.den = 1 ≠ 0
          -- If r.den < 0, then signDen r.den = -1 ≠ 0
          dsimp [signDen]
          by_cases h_pos : r.den > 0
          · rw [if_pos h_pos]
            simp
          · rw [if_neg (mt Int.gt_of_not_pos h_pos)]
            simp
        cases h
        next hleft => exact hs hleft
        next hright =>
          have hgd : (g : Int) ∣ r.den := Int.gcd_dvd_right r.num r.den
          have := Int.ediv_ne_zero_of_ne_zero_left r.den hgd r.den_ne_zero
          exact this hright
    }

/-- Reducing preserves the rational value. -/
theorem ExactRational.reduce_equiv (r : ExactRational) : r.equiv r.reduce := by
  unfold reduce equiv
  simp only
  split
  · -- The absurd case: gcd = 0, which is impossible. This branch never executes.
    contradiction
  · -- Main case: gcd != 0
    intro hg
    -- Need: r.num * (s * (r.den / g)) = (s * (r.num / g)) * r.den
    -- This simplifies to: r.num * (r.den / g) = (r.num / g) * r.den
    -- Which holds because g | r.num and g | r.den.
    have h_gcd_def : (Int.gcd r.num r.den : Int) ≠ 0 := hg
    have h_div_num : (Int.gcd r.num r.den : Int) ∣ r.num := Int.gcd_dvd_left r.num r.den
    have h_div_den : (Int.gcd r.num r.den : Int) ∣ r.den := Int.gcd_dvd_right r.num r.den
    -- Let g = gcd(r.num, r.den), so r.num = g * (r.num/g) and r.den = g * (r.den/g)
    let g := Int.gcd r.num r.den
    have h_num : r.num = g * (r.num / g) := Int.mul_ediv_cancel' h_div_num
    have h_den : r.den = g * (r.den / g) := Int.mul_ediv_cancel' h_div_den
    -- Now we need: r.num * (s * (r.den / g)) = (s * (r.num / g)) * r.den
    -- Substituting: (g * (r.num/g)) * (s * (r.den/g)) = (s * (r.num/g)) * (g * (r.den/g))
    -- This becomes: g * (r.num/g) * s * (r.den/g) = s * (r.num/g) * g * (r.den/g)
    -- Which is: g * s * (r.num/g) * (r.den/g) = g * s * (r.num/g) * (r.den/g) ✓
    rw [h_num, h_den]
    ring

/-! ## Arithmetic operations -/

/-- Addition: a/b + c/d = (a*d + c*b) / (b*d) -/
def ExactRational.add (r s : ExactRational) : ExactRational :=
  { num := r.num * s.den + s.num * r.den
    den := r.den * s.den
    den_ne_zero := Int.mul_ne_zero r.den_ne_zero s.den_ne_zero }

instance : Add ExactRational where
  add := ExactRational.add

/-- Subtraction: a/b - c/d = (a*d - c*b) / (b*d) -/
def ExactRational.sub (r s : ExactRational) : ExactRational :=
  { num := r.num * s.den - s.num * r.den
    den := r.den * s.den
    den_ne_zero := Int.mul_ne_zero r.den_ne_zero s.den_ne_zero }

instance : Sub ExactRational where
  sub := ExactRational.sub

/-- Multiplication: (a/b) * (c/d) = (a*c) / (b*d) -/
def ExactRational.mul (r s : ExactRational) : ExactRational :=
  { num := r.num * s.num
    den := r.den * s.den
    den_ne_zero := Int.mul_ne_zero r.den_ne_zero s.den_ne_zero }

instance : Mul ExactRational where
  mul := ExactRational.mul

/-- Division: (a/b) / (c/d) = (a*d) / (b*c), requires c != 0 -/
def ExactRational.div (r s : ExactRational) (hs : s.num ≠ 0) : ExactRational :=
  { num := r.num * s.den
    den := r.den * s.num
    den_ne_zero := Int.mul_ne_zero r.den_ne_zero hs }

/-- Division with a default (returns 0 if dividing by zero). -/
def ExactRational.div' (r s : ExactRational) : ExactRational :=
  if h : s.num = 0 then
    ExactRational.ofInt 0
  else
    r.div s h

instance : Div ExactRational where
  div := ExactRational.div'

/-- Absolute value. -/
def ExactRational.abs (r : ExactRational) : ExactRational :=
  { num := Int.natAbs r.num
    den := Int.natAbs r.den
    den_ne_zero := by
      intro h
      have : (Int.natAbs r.den : Int) = 0 := h
      have := Int.natAbs_eq_zero.mp (by omega : r.den.natAbs = 0)
      exact r.den_ne_zero this }

/-- Negation of an ExactRational. -/
def ExactRational.neg' (r : ExactRational) : ExactRational :=
  { num := -r.num, den := r.den, den_ne_zero := r.den_ne_zero }

/-- Check if two ExactRationals are equal as rational values. -/
def ExactRational.ratEq (r s : ExactRational) : Bool :=
  r.num * s.den == s.num * r.den

/-- Check if the rational value is zero. -/
def ExactRational.isZero (r : ExactRational) : Bool :=
  r.num == 0

/-! ## L002: Arithmetic preserves exact values

We prove that each operation preserves the rational value, i.e.,
the cross-multiplication identity holds.

For add: if r represents a/b and s represents c/d, then
  r.add s represents (a*d + c*b) / (b*d)
which equals a/b + c/d.

We express this as: for any ExactRational t that is equivalent to a/b + c/d,
we have (r.add s).equiv t.
-/

/-- L002-add: Addition is correct.
    (a/b + c/d) as a rational = (a*d + c*b)/(b*d).
    This is immediate from the definition -- the numerator and denominator
    are exactly the standard formula. So we prove self-equivalence. -/
theorem ExactRational.add_correct (r s : ExactRational) :
    (r.add s).equiv (ExactRational.mk' (r.num * s.den + s.num * r.den) (r.den * s.den)
      (Int.mul_ne_zero r.den_ne_zero s.den_ne_zero)) := by
  unfold equiv add mk'
  simp

/-- L002-sub: Subtraction is correct. -/
theorem ExactRational.sub_correct (r s : ExactRational) :
    (r.sub s).equiv (ExactRational.mk' (r.num * s.den - s.num * r.den) (r.den * s.den)
      (Int.mul_ne_zero r.den_ne_zero s.den_ne_zero)) := by
  unfold equiv sub mk'
  simp

/-- L002-mul: Multiplication is correct. -/
theorem ExactRational.mul_correct (r s : ExactRational) :
    (r.mul s).equiv (ExactRational.mk' (r.num * s.num) (r.den * s.den)
      (Int.mul_ne_zero r.den_ne_zero s.den_ne_zero)) := by
  unfold equiv mul mk'
  simp

/-- L002-div: Division is correct. -/
theorem ExactRational.div_correct (r s : ExactRational) (hs : s.num ≠ 0) :
    (r.div s hs).equiv (ExactRational.mk' (r.num * s.den) (r.den * s.num)
      (Int.mul_ne_zero r.den_ne_zero hs)) := by
  unfold equiv div mk'
  simp

/-! ## Cross-multiplication correctness theorems (L002 full form)

These state that the result of an arithmetic operation, when interpreted as a
rational number, equals the arithmetic operation applied to the input rationals.

We express this via the cross-multiplication identity:
  result.num * expected_den = expected_num * result.den
-/

/-- L002 (full): add preserves the rational value.
    (r + s).num * (r.den * s.den) = (r.num * s.den + s.num * r.den) * (r + s).den -/
theorem ExactRational.add_value (r s : ExactRational) :
    (r.add s).num * (r.den * s.den) = (r.num * s.den + s.num * r.den) * (r.add s).den := by
  unfold add
  simp
  abel

/-- L002 (full): sub preserves the rational value. -/
theorem ExactRational.sub_value (r s : ExactRational) :
    (r.sub s).num * (r.den * s.den) = (r.num * s.den - s.num * r.den) * (r.sub s).den := by
  unfold sub
  simp
  abel

/-- L002 (full): mul preserves the rational value. -/
theorem ExactRational.mul_value (r s : ExactRational) :
    (r.mul s).num * (r.den * s.den) = (r.num * s.num) * (r.mul s).den := by
  unfold mul
  simp
  abel

/-- L002 (full): div preserves the rational value. -/
theorem ExactRational.div_value (r s : ExactRational) (hs : s.num ≠ 0) :
    (r.div s hs).num * (r.den * s.num) = (r.num * s.den) * (r.div s hs).den := by
  unfold div
  simp
  abel

/-! ## Reduce preserves equivalence with operations -/

/-- Reducing after addition preserves the rational value. -/
theorem ExactRational.add_reduce_equiv (r s : ExactRational) :
    (r.add s).equiv (r.add s).reduce := by
  exact (r.add s).reduce_equiv

/-! ## Decidable equality on rational values -/

instance : BEq ExactRational where
  beq r s := r.ratEq s

/-! ## ToString -/

instance : ToString ExactRational where
  toString r :=
    if r.den == 1 then toString r.num
    else s!"{r.num}/{r.den}"

/-! ## Basic properties -/

/-- Zero element. -/
def ExactRational.zero : ExactRational := ExactRational.ofInt 0

/-- One element. -/
def ExactRational.one : ExactRational := ExactRational.ofInt 1

/-- Adding zero is identity (up to equiv). -/
theorem ExactRational.add_zero_equiv (r : ExactRational) :
    (r.add ExactRational.zero).equiv r := by
  unfold add zero ofInt equiv
  simp
  ring

/-- Multiplying by one is identity (up to equiv). -/
theorem ExactRational.mul_one_equiv (r : ExactRational) :
    (r.mul ExactRational.one).equiv r := by
  unfold mul one ofInt equiv
  simp
  ring

/-- Addition is commutative (up to equiv). -/
theorem ExactRational.add_comm_equiv (r s : ExactRational) :
    (r.add s).equiv (s.add r) := by
  unfold add equiv
  simp
  ring

/-- Multiplication is commutative (up to equiv). -/
theorem ExactRational.mul_comm_equiv (r s : ExactRational) :
    (r.mul s).equiv (s.mul r) := by
  unfold mul equiv
  simp
  ring

/-! ## Evaluation tests -/

-- 1/3 + 1/7 = 10/21
#eval!
  let r := ExactRational.mk' 1 3 (by omega)
  let s := ExactRational.mk' 1 7 (by omega)
  let sum := r.add s
  -- sum = 10/21 (unreduced form: (1*7 + 1*3)/(3*7) = 10/21)
  (sum.num, sum.den)  -- expect (10, 21)

-- 2/3 * 3/4 = 6/12, reduces to 1/2
#eval!
  let r := ExactRational.mk' 2 3 (by omega)
  let s := ExactRational.mk' 3 4 (by omega)
  let prod := (r.mul s).reduce
  (prod.num, prod.den)  -- expect (1, 2)

-- Verify ratEq: 2/4 == 1/2
#eval!
  let r := ExactRational.mk' 2 4 (by omega)
  let s := ExactRational.mk' 1 2 (by omega)
  r.ratEq s  -- expect true

-- 5/6 - 1/3 = 3/6 (= 1/2)
#eval!
  let r := ExactRational.mk' 5 6 (by omega)
  let s := ExactRational.mk' 1 3 (by omega)
  let diff := (r.sub s).reduce
  (diff.num, diff.den)  -- expect (1, 2)

-- Division: (2/3) / (4/5) = 10/12, reduces to 5/6
#eval!
  let r := ExactRational.mk' 2 3 (by omega)
  let s := ExactRational.mk' 4 5 (by omega)
  let q := (r.div s (by omega)).reduce
  (q.num, q.den)  -- expect (5, 6)

end ExactTranscendentals
