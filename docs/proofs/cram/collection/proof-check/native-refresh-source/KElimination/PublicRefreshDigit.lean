import Std

/-!
# Symbolic first-order identity for the split-encoding digit producer

The bounded digit circuit evaluates `G` at plaintext modulus `p²`, divides its
proved multiple of `p`, then multiplies by `H` evaluated from the coherent
modulo-`p` input. This file proves the underlying integer polynomial identity
for arbitrary finite coefficient lists, without assuming Taylor expansion.

The root and derivative-inverse certificates remain explicit hypotheses.
There is no assumption that a ciphertext view is coherent or correctly
bounded: those are separate producer/refinement obligations. These theorems
do not establish security of the encrypted circuit or named-profile refresh.
-/

namespace KElimination.PublicRefreshDigit

/-- Integer polynomial evaluation in ascending coefficient order. -/
def evaluate : List Int → Int → Int
  | [], _ => 0
  | a :: coefficients, x => a + x * evaluate coefficients x

/-- Evaluation of the formal derivative, given by the differentiated Horner
recurrence. Thus `[a,b,c]` gives `b+2*c*x`. -/
def derivativeAt : List Int → Int → Int
  | [], _ => 0
  | _ :: coefficients, x => evaluate coefficients x + x * derivativeAt coefficients x

/-- Multiply ascending coefficients by consecutive integer indices. -/
def indexedCoefficients : Int → List Int → List Int
  | _, [] => []
  | index, a :: coefficients =>
    (index * a) :: indexedCoefficients (index + 1) coefficients

/-- The explicit coefficient derivative used by the runtime certificate:
drop the constant and multiply each remaining coefficient by its index. -/
def derivative : List Int → List Int
  | [] => []
  | _ :: coefficients => indexedCoefficients 1 coefficients

theorem indexed_evaluation (coefficients : List Int) (index x : Int) :
    evaluate (indexedCoefficients index coefficients) x =
      index * evaluate coefficients x + x * derivativeAt coefficients x := by
  induction coefficients generalizing index with
  | nil => simp [evaluate, derivativeAt, indexedCoefficients]
  | cons a coefficients ih =>
    simp only [evaluate, indexedCoefficients, derivativeAt, ih,
      Int.add_mul, Int.mul_add, Int.one_mul]
    ac_rfl

/-- The Horner derivative recurrence equals the explicit indexed derivative,
so the certificate is about the same polynomial derivative as the Rust code. -/
theorem derivative_evaluation (coefficients : List Int) (x : Int) :
    evaluate (derivative coefficients) x = derivativeAt coefficients x := by
  cases coefficients with
  | nil => rfl
  | cons a coefficients =>
    simp [derivative, derivativeAt, indexed_evaluation]

/-- Exact first-order Taylor expansion with an integer `p²` remainder.
No primality, positivity, or root hypothesis is needed for this identity. -/
theorem taylor_remainder (coefficients : List Int) (r p k : Int) :
    ∃ remainder : Int,
      evaluate coefficients (r + p * k) = evaluate coefficients r +
        p * k * derivativeAt coefficients r + p * p * remainder := by
  induction coefficients with
  | nil => exact ⟨0, by simp [evaluate, derivativeAt]⟩
  | cons a coefficients ih =>
    obtain ⟨remainder, heval⟩ := ih
    refine ⟨r * remainder + k * k * derivativeAt coefficients r + p * k * remainder, ?_⟩
    simp only [evaluate, derivativeAt, heval, Int.add_mul, Int.mul_add]
    ac_rfl

/-- Polynomial evaluation respects the coherent `r+p*k` view modulo `p`.
This includes `H` evaluated in the less noisy modulo-`p` view. -/
theorem coherent_evaluation_mod (coefficients : List Int) (r p k : Int) :
    evaluate coefficients (r + p * k) % p = evaluate coefficients r % p := by
  obtain ⟨remainder, heval⟩ := taylor_remainder coefficients r p k
  rw [heval]
  simp [Int.add_emod, Int.mul_emod]

/-- A root certificate modulo `p²` is sufficient, even when the stored
coefficients are canonical modular representatives of the product polynomial.
The value at the shifted input is an exact integer multiple of `p`. -/
theorem rooted_taylor_multiple (coefficients : List Int) (r p k : Int)
    (hroot : evaluate coefficients r % (p * p) = 0) :
    ∃ remainder : Int, evaluate coefficients (r + p * k) =
      p * (k * derivativeAt coefficients r + p * remainder) := by
  obtain ⟨remainder, heval⟩ := taylor_remainder coefficients r p k
  obtain ⟨rootRemainder, hrootValue⟩ := Int.dvd_of_emod_eq_zero hroot
  refine ⟨rootRemainder + remainder, ?_⟩
  rw [heval, hrootValue]
  simp only [Int.mul_add]
  ac_rfl

/-- Dividing the proved multiple by `p` leaves the quotient times the
derivative modulo `p`. No inverse of `p` modulo `p` is introduced. -/
theorem rooted_quotient_mod (coefficients : List Int) (r p k : Int)
    (hp : p ≠ 0) (hroot : evaluate coefficients r % (p * p) = 0) :
    (evaluate coefficients (r + p * k) / p) % p =
      (k * derivativeAt coefficients r) % p := by
  obtain ⟨remainder, heval⟩ := rooted_taylor_multiple coefficients r p k hroot
  rw [heval, Int.mul_ediv_cancel_left _ hp]
  simp [Int.add_emod, Int.mul_emod]

/-- Reinterpreting the canonical `p²` plaintext after exact division gives
the same modulo-`p` quotient as division before canonical reduction. -/
theorem canonical_p_square_quotient (value p : Int) (hp : 0 < p)
    (hmultiple : p ∣ value) :
    (value % (p * p)) / p = (value / p) % p := by
  obtain ⟨quotient, hvalue⟩ := hmultiple
  rw [hvalue, Int.mul_emod_mul_of_pos _ _ hp]
  rw [Int.mul_ediv_cancel_left _ (Int.ne_of_gt hp)]
  rw [Int.mul_ediv_cancel_left _ (Int.ne_of_gt hp)]

/-- The complete split-encoding digit formula: evaluate `G` modulo `p²`,
reinterpret its exact `p` multiple at scale `p`, evaluate `H` from the coherent
`p` view, and multiply. Root and inverse certificates are the ones checked by
the bounded-digit planner. The identity holds for every signed integer `k`.
-/
theorem split_digit_correct (g h : List Int) (r p k : Int) (hp : 0 < p)
    (hroot : evaluate g r % (p * p) = 0)
    (hinverse : (derivativeAt g r * evaluate h r) % p = 1 % p) :
    (((evaluate g (r + p * k) % (p * p)) / p) *
      evaluate h (r + p * k)) % p = k % p := by
  obtain ⟨remainder, heval⟩ := rooted_taylor_multiple g r p k hroot
  have hmultiple : p ∣ evaluate g (r + p * k) := ⟨_, heval⟩
  rw [canonical_p_square_quotient _ p hp hmultiple]
  rw [Int.mul_emod, Int.emod_emod,
    rooted_quotient_mod g r p k (Int.ne_of_gt hp) hroot,
    coherent_evaluation_mod h r p k]
  rw [← Int.mul_emod, Int.mul_assoc, Int.mul_emod, hinverse]
  rw [← Int.mul_emod, Int.mul_one]

/-- The same result with the inverse certificate stated using the explicit
indexed derivative coefficients produced by the runtime polynomial planner. -/
theorem certified_split_digit (g h : List Int) (r p k : Int) (hp : 0 < p)
    (hroot : evaluate g r % (p * p) = 0)
    (hinverse : (evaluate (derivative g) r * evaluate h r) % p = 1 % p) :
    (((evaluate g (r + p * k) % (p * p)) / p) *
      evaluate h (r + p * k)) % p = k % p := by
  apply split_digit_correct g h r p k hp hroot
  simpa only [derivative_evaluation] using hinverse


/-- The attachment's residual-polynomial form F(X)=X-G(X)H(X).
The same finite root/inverse certificates recover the signed residual modulo
p², for every signed quotient. This is an integer polynomial identity, not
an admission certificate for a particular ciphertext/noise implementation. -/
theorem residual_polynomial_correct (g h : List Int) (r p k : Int) (hp : 0 < p)
    (hroot : evaluate g r % (p * p) = 0)
    (hinverse : (evaluate (derivative g) r * evaluate h r) % p = 1 % p) :
    (r + p * k - evaluate g (r + p * k) * evaluate h (r + p * k)) % (p * p) =
      r % (p * p) := by
  obtain ⟨rem, heval⟩ := rooted_taylor_multiple g r p k hroot
  have hmultiple : p ∣ evaluate g (r + p * k) := ⟨_, heval⟩
  have hdigit := certified_split_digit g h r p k hp hroot hinverse
  rw [canonical_p_square_quotient _ p hp hmultiple] at hdigit
  have hmod : ((evaluate g (r + p * k) / p) * evaluate h (r + p * k)) % p =
      k % p := by
    simpa only [Int.mul_emod, Int.emod_emod] using hdigit
  obtain ⟨d, hd⟩ := Int.dvd_of_emod_eq_zero
    (Int.emod_eq_emod_iff_emod_sub_eq_zero.mp hmod)
  have hq : evaluate g (r + p * k) = p * (evaluate g (r + p * k) / p) := by
    rw [heval, Int.mul_ediv_cancel_left _ (Int.ne_of_gt hp)]
  have hprod : (evaluate g (r + p * k) / p) * evaluate h (r + p * k) = k + p * d := by
    omega
  have heq : r + p * k - evaluate g (r + p * k) * evaluate h (r + p * k) =
      r - (p * p) * d := by
    rw [hq, Int.mul_assoc, hprod, Int.mul_add]
    simp only [← Int.mul_assoc]
    omega
  rw [heq, Int.sub_mul_emod_self_left]

end KElimination.PublicRefreshDigit
