import Lean

/-!
# Finite-cover arithmetic helpers

Only the pinned Lean distribution is imported; no external packages are required.
These helpers support the finite-cover and cocycle formalization.
-/

namespace FoliatedCoprimeGeometry

def iter {α : Type} (f : α → α) : Nat → α → α
  | 0, x => x
  | k + 1, x => f (iter f k x)

theorem iter_add {α : Type} (f : α → α) (a b : Nat) (x : α) :
    iter f (a + b) x = iter f b (iter f a x) := by
  induction b with
  | zero => rfl
  | succ b ih => simp [iter, ih]

theorem iter_mul {α : Type} (f : α → α) (m k : Nat) (x : α) :
    iter f (m * k) x = iter (iter f m) k x := by
  induction k with
  | zero => rfl
  | succ k ih =>
    rw [Nat.mul_succ, iter_add, ih]
    rfl

theorem iter_conj {α β : Type} (f : α → α) (g : β → β) (h : α → β)
    (hconj : ∀ x, h (f x) = g (h x)) (k : Nat) (x : α) :
    h (iter f k x) = iter g k (h x) := by
  induction k with
  | zero => rfl
  | succ k ih => simp [iter, hconj, ih]

theorem add_mod_left_drop (a b n : Nat) :
    (a % n + b) % n = (a + b) % n := by
  rw [Nat.add_mod, Nat.mod_mod, ← Nat.add_mod]

theorem add_mod_right_drop (a b n : Nat) :
    (a + b % n) % n = (a + b) % n := by
  rw [Nat.add_mod, Nat.mod_mod, ← Nat.add_mod]

theorem nat_mod_cancel {A : Nat} (hA : 0 < A) (x y : Nat) :
    (x + (A - y % A) + y) % A = x % A := by
  have hlt : y % A < A := Nat.mod_lt y hA
  have hdiv : A * (y / A) + y % A = y := Nat.div_add_mod y A
  have heq : x + (A - y % A) + y = x + A * (y / A) + A := by omega
  rw [heq, Nat.add_mod_right, Nat.add_mul_mod_self_left]

theorem mod_eq_of_add_eq {A x y z : Nat} (h : (x + z) % A = (y + z) % A) :
    x % A = y % A := by
  cases Nat.eq_zero_or_pos A with
  | inl h0 =>
    subst h0
    simp at h ⊢
    omega
  | inr hA =>
    have h1 : (x + z + (A - z % A)) % A = x % A := by
      have heq : x + z + (A - z % A) = x + (A - z % A) + z := by omega
      rw [heq]
      exact nat_mod_cancel hA x z
    have h2 : (y + z + (A - z % A)) % A = y % A := by
      have heq : y + z + (A - z % A) = y + (A - z % A) + z := by omega
      rw [heq]
      exact nat_mod_cancel hA y z
    rw [← h1, ← h2, ← add_mod_left_drop (x + z), h, add_mod_left_drop]

theorem mod_mod_of_dvd {a d n : Nat} (hd : d ∣ n) :
    (a % n) % d = a % d :=
  Nat.mod_mod_of_dvd a hd

def bezout : Nat → Nat → Int × Int
  | _, 0 => (1, 0)
  | a, b + 1 =>
    let p := bezout (b + 1) (a % (b + 1))
    (p.2, p.1 - ((a / (b + 1) : Nat) : Int) * p.2)
termination_by _ b => b
decreasing_by exact Nat.mod_lt a (Nat.succ_pos b)

theorem bezout_spec (a b : Nat) :
    (a : Int) * (bezout a b).1 + (b : Int) * (bezout a b).2 = (Nat.gcd a b : Int) := by
  match b with
  | 0 => simp [bezout, Nat.gcd_zero_right]
  | b + 1 =>
    have ih := bezout_spec (b + 1) (a % (b + 1))
    have hgcd : Nat.gcd a (b + 1) = Nat.gcd (b + 1) (a % (b + 1)) := by
      rw [Nat.gcd_comm, Nat.gcd_rec, Nat.gcd_comm]
    rw [bezout, hgcd, ← ih]
    dsimp only
    have hdiv_nat : (b + 1) * (a / (b + 1)) + a % (b + 1) = a := Nat.div_add_mod a (b + 1)
    have hdiv : ((b + 1 : Nat) : Int) * ((a / (b + 1) : Nat) : Int) + ((a % (b + 1) : Nat) : Int) = (a : Int) := by
      rw [← Int.natCast_mul, ← Int.natCast_add, hdiv_nat]
    have hmul := congrArg (fun z : Int => z * (bezout (b + 1) (a % (b + 1))).2) hdiv
    simp only [Int.add_mul, Int.mul_assoc] at hmul
    rw [Int.mul_sub]
    omega
termination_by b
decreasing_by exact Nat.mod_lt a (Nat.succ_pos b)

theorem gcd_div_coprime {a b : Nat} (ha : 0 < a) :
    Nat.gcd (a / Nat.gcd a b) (b / Nat.gcd a b) = 1 :=
  Nat.coprime_div_gcd_div_gcd (Nat.gcd_pos_of_pos_left b ha)

theorem coprime_dvd_of_dvd_mul {a b m : Nat}
    (hcop : Nat.gcd a b = 1) (hdvd : a ∣ m * b) : a ∣ m :=
  Nat.Coprime.dvd_of_dvd_mul_right hcop hdvd

end FoliatedCoprimeGeometry
