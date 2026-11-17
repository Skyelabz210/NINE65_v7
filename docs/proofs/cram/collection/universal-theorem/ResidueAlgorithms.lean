import Std

/-!
Executable bounded arithmetic from residue operations. Runtime data contains
only observation states and a public capacity/fuel; the semantic encoding is
supplied separately to correctness theorems. No persistent scalar K or scalar
source value is a field of the executable interface.
-/

namespace KElimination.ResidueAlgorithms

universe u

structure Ops (S : Type u) where
  capacity : Nat
  zero : S
  increment : S → S
  subtract : S → S → S
  less : S → S → Bool
  isZero : S → Bool

structure Correct {S : Type u} (ops : Ops S) (encode : Nat → S) : Prop where
  zero_eq : ops.zero = encode 0
  increment_eq : ∀ n, n + 1 < ops.capacity →
    ops.increment (encode n) = encode (n + 1)
  subtract_eq : ∀ a b, b ≤ a → a < ops.capacity →
    ops.subtract (encode a) (encode b) = encode (a - b)
  less_eq : ∀ a b, a < ops.capacity → b < ops.capacity →
    ops.less (encode a) (encode b) = decide (a < b)
  isZero_eq : ∀ a, a < ops.capacity → ops.isZero (encode a) = decide (a = 0)

/-- The exact comparison contract itself implies faithful encoding on the
admitted domain. Thus equal represented results identify a unique value. -/
theorem encode_injective_on {S : Type u} (ops : Ops S) (encode : Nat → S)
    (correct : Correct ops encode) (a b : Nat)
    (ha : a < ops.capacity) (hb : b < ops.capacity)
    (heq : encode a = encode b) : a = b := by
  have hself : ops.less (encode b) (encode b) = false := by
    simpa using correct.less_eq b b hb hb
  have hab : decide (a < b) = false := by
    rw [← correct.less_eq a b ha hb, heq]
    exact hself
  have hba : decide (b < a) = false := by
    rw [← correct.less_eq b a hb ha, heq]
    exact hself
  have hnotab : ¬ a < b := of_decide_eq_false hab
  have hnotba : ¬ b < a := of_decide_eq_false hba
  omega

/-- Repeated-subtraction division. At zero fuel an already completed division
still succeeds. Failure denotes exhausted fuel, not an incorrect quotient. -/
def divLoop {S : Type u} (ops : Ops S) : Nat → S → S → S → Option (S × S)
  | 0, quotient, remainder, divisor =>
      if ops.less remainder divisor then some (quotient, remainder) else none
  | fuel + 1, quotient, remainder, divisor =>
      if ops.less remainder divisor then some (quotient, remainder)
      else divLoop ops fuel (ops.increment quotient)
        (ops.subtract remainder divisor) divisor

/-- Division refuses a represented zero divisor. Public capacity is sufficient
fuel on the admitted domain; no scalar dividend is used to obtain the fuel. -/
def divmod {S : Type u} (ops : Ops S) (dividend divisor : S) : Option (S × S) :=
  if ops.isZero divisor then none
  else divLoop ops ops.capacity ops.zero dividend divisor

def gcdLoop {S : Type u} (ops : Ops S) : Nat → S → S → Option S
  | 0, a, b => if ops.isZero b then some a else none
  | fuel + 1, a, b =>
      if ops.isZero b then some a
      else match divmod ops a b with
        | none => none
        | some (_, remainder) => gcdLoop ops fuel b remainder

def gcd {S : Type u} (ops : Ops S) (a b : S) : Option S :=
  gcdLoop ops ops.capacity a b

/-- The quotient and remainder remain represented throughout. The invariant
q+r<capacity admits the increment and subtraction, and r≤fuel proves that
public fuel cannot expire on a valid computation. -/
theorem divLoop_correct {S : Type u} (ops : Ops S) (encode : Nat → S)
    (correct : Correct ops encode) (fuel q r d : Nat)
    (hd : 0 < d) (hdcap : d < ops.capacity)
    (hcap : q + r < ops.capacity) (hfuel : r ≤ fuel) :
    divLoop ops fuel (encode q) (encode r) (encode d) =
      some (encode (q + r / d), encode (r % d)) := by
  induction fuel generalizing q r with
  | zero =>
    have hr : r = 0 := by omega
    subst r
    rw [divLoop, correct.less_eq 0 d (by omega) hdcap]
    simp [hd]
  | succ fuel ih =>
    have hrcap : r < ops.capacity := by omega
    by_cases hlt : r < d
    · rw [divLoop, correct.less_eq r d hrcap hdcap]
      simp [hlt, Nat.div_eq_of_lt hlt, Nat.mod_eq_of_lt hlt]
    · have hge : d ≤ r := by omega
      rw [divLoop, correct.less_eq r d hrcap hdcap]
      simp only [hlt, decide_false, Bool.false_eq_true, ↓reduceIte]
      rw [correct.increment_eq q (by omega), correct.subtract_eq r d hge hrcap]
      rw [ih (q + 1) (r - d) (by omega) (by omega)]
      have hquot : q + 1 + (r - d) / d = q + r / d := by
        have hdiv := Nat.div_eq_sub_div hd hge
        omega
      rw [hquot, ← Nat.mod_eq_sub_mod hge]

theorem divmod_correct {S : Type u} (ops : Ops S) (encode : Nat → S)
    (correct : Correct ops encode) (n d : Nat)
    (hn : n < ops.capacity) (hdcap : d < ops.capacity) (hd : 0 < d) :
    divmod ops (encode n) (encode d) =
      some (encode (n / d), encode (n % d)) := by
  unfold divmod
  rw [correct.isZero_eq d hdcap]
  have hdz : d ≠ 0 := by omega
  simp only [hdz, decide_false, Bool.false_eq_true, ↓reduceIte]
  rw [correct.zero_eq]
  simpa using divLoop_correct ops encode correct ops.capacity 0 n d hd hdcap
    (by omega) (by omega)

theorem divmod_zero_refused {S : Type u} (ops : Ops S) (encode : Nat → S)
    (correct : Correct ops encode) (dividend : S) (hcap : 0 < ops.capacity) :
    divmod ops dividend (encode 0) = none := by
  simp [divmod, correct.isZero_eq 0 hcap]

/-- The Euclidean loop uses the residue division result, whose second semantic
operand decreases. Neither a semantic remainder nor its magnitude is stored. -/
theorem gcdLoop_correct {S : Type u} (ops : Ops S) (encode : Nat → S)
    (correct : Correct ops encode) (fuel a b : Nat)
    (ha : a < ops.capacity) (hb : b < ops.capacity) (hfuel : b ≤ fuel) :
    gcdLoop ops fuel (encode a) (encode b) = some (encode (Nat.gcd a b)) := by
  induction fuel generalizing a b with
  | zero =>
    have hzero : b = 0 := by omega
    subst b
    simp [gcdLoop, correct.isZero_eq 0 hb]
  | succ fuel ih =>
    by_cases hzero : b = 0
    · subst b
      simp [gcdLoop, correct.isZero_eq 0 hb]
    · have hpos : 0 < b := by omega
      rw [gcdLoop, correct.isZero_eq b hb]
      simp only [hzero, decide_false, Bool.false_eq_true, ↓reduceIte]
      rw [divmod_correct ops encode correct a b ha hb hpos]
      change gcdLoop ops fuel (encode b) (encode (a % b)) =
        some (encode (Nat.gcd a b))
      have hrlt : a % b < b := Nat.mod_lt a hpos
      rw [ih b (a % b) hb (by omega) (by omega)]
      have hgcd : Nat.gcd b (a % b) = Nat.gcd a b := by
        rw [Nat.gcd_comm b (a % b), ← Nat.gcd_rec b a, Nat.gcd_comm b a]
      rw [hgcd]

theorem gcd_correct {S : Type u} (ops : Ops S) (encode : Nat → S)
    (correct : Correct ops encode) (a b : Nat)
    (ha : a < ops.capacity) (hb : b < ops.capacity) :
    gcd ops (encode a) (encode b) = some (encode (Nat.gcd a b)) := by
  exact gcdLoop_correct ops encode correct ops.capacity a b ha hb (by omega)

end KElimination.ResidueAlgorithms

#print axioms KElimination.ResidueAlgorithms.divLoop_correct
#print axioms KElimination.ResidueAlgorithms.encode_injective_on
#print axioms KElimination.ResidueAlgorithms.divmod_correct
#print axioms KElimination.ResidueAlgorithms.divmod_zero_refused
#print axioms KElimination.ResidueAlgorithms.gcdLoop_correct
#print axioms KElimination.ResidueAlgorithms.gcd_correct
