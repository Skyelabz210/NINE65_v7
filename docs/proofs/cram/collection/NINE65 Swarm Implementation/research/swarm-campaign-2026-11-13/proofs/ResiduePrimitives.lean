import IntegerSpecialization
import ResidueAlgorithms

namespace KElimination.ResiduePrimitives

/-- Public frame data and inverse certificate. No source value is stored. -/
structure Frame where
  M : Nat
  A : Nat
  positiveM : 0 < M
  positiveA : 0 < A
  inverse : Int
  inverse_ok : (inverse * (M : Int)) % (A : Int) = 1 % (A : Int)

/-- The complete runtime number state: two residue observations only. -/
structure State where
  main : Int
  anchor : Int
  deriving DecidableEq, Repr

def Frame.capacity (f : Frame) : Nat := f.M * f.A

/-- Semantic ingress/specification map; runtime algorithms do not call this. -/
def Frame.encode (f : Frame) (n : Nat) : State :=
  ⟨(n : Int) % (f.M : Int), (n : Int) % (f.A : Int)⟩

def zero : State := ⟨0, 0⟩

def Frame.kQuery (f : Frame) (x : State) : Int :=
  IntegerSpecialization.query x.main x.anchor (f.A : Int) f.inverse

def Frame.increment (f : Frame) (x : State) : State :=
  ⟨(x.main + 1) % (f.M : Int), (x.anchor + 1) % (f.A : Int)⟩

def Frame.subtract (f : Frame) (x y : State) : State :=
  ⟨(x.main - y.main) % (f.M : Int), (x.anchor - y.anchor) % (f.A : Int)⟩

def Frame.less (f : Frame) (x y : State) : Bool :=
  decide (f.kQuery x < f.kQuery y ∨
    (f.kQuery x = f.kQuery y ∧ x.main < y.main))

def isZero (x : State) : Bool := decide (x = zero)

theorem zero_eq_encode (f : Frame) : zero = f.encode 0 := by
  simp [zero, Frame.encode]

theorem kQuery_exact (f : Frame) (n : Nat) (hn : n < f.capacity) :
    f.kQuery (f.encode n) = (n : Int) / (f.M : Int) := by
  apply IntegerSpecialization.query_exact_of_source_window
    (n : Int) ((n : Int) % (f.M : Int)) ((n : Int) % (f.A : Int))
    (f.M : Int) (f.A : Int) f.inverse
  · exact_mod_cast f.positiveM
  · rfl
  · rfl
  · exact f.inverse_ok
  · omega
  · unfold Frame.capacity at hn
    have hn' : (n : Int) < (f.M * f.A : Nat) := by omega
    simpa [Int.natCast_mul] using hn'

theorem increment_encode (f : Frame) (n : Nat) :
    f.increment (f.encode n) = f.encode (n + 1) := by
  simp [Frame.increment, Frame.encode, Int.add_emod, Int.natCast_add]

theorem subtract_encode (f : Frame) (a b : Nat) (h : b ≤ a) :
    f.subtract (f.encode a) (f.encode b) = f.encode (a - b) := by
  simp [Frame.subtract, Frame.encode, Int.natCast_sub h, Int.sub_emod]

/-- Euclidean coordinates preserve the ordinary integer order. -/
theorem euclidean_lex_order (a b M : Int) (hM : 0 < M) :
    (a / M < b / M ∨ (a / M = b / M ∧ a % M < b % M)) ↔ a < b := by
  have ha := Int.emod_add_ediv_mul a M
  have hb := Int.emod_add_ediv_mul b M
  constructor
  · intro h
    rcases h with hq | ⟨hq, hr⟩
    · by_cases hab : a < b
      · exact hab
      · have hba : b ≤ a := by omega
        have := Int.ediv_le_ediv hM hba
        omega
    · rw [hq] at ha
      omega
  · intro hab
    have hq := Int.ediv_le_ediv hM (Int.le_of_lt hab)
    by_cases heq : a / M = b / M
    · right
      refine ⟨heq, ?_⟩
      rw [heq] at ha
      omega
    · left
      omega

theorem less_encode (f : Frame) (a b : Nat)
    (ha : a < f.capacity) (hb : b < f.capacity) :
    f.less (f.encode a) (f.encode b) = decide (a < b) := by
  unfold Frame.less
  rw [kQuery_exact f a ha, kQuery_exact f b hb]
  change decide ((a : Int) / f.M < (b : Int) / f.M ∨
    ((a : Int) / f.M = (b : Int) / f.M ∧ (a : Int) % f.M < (b : Int) % f.M)) = _
  simp only [euclidean_lex_order (a : Int) (b : Int) (f.M : Int) (by exact_mod_cast f.positiveM), Int.ofNat_lt]

theorem encode_injective_on_window (f : Frame) (a b : Nat)
    (ha : a < f.capacity) (hb : b < f.capacity)
    (heq : f.encode a = f.encode b) : a = b := by
  have hq : (a : Int) / f.M = (b : Int) / f.M := by
    rw [← kQuery_exact f a ha, ← kQuery_exact f b hb, heq]
  have hr : (a : Int) % f.M = (b : Int) % f.M := congrArg State.main heq
  have hdecA := Int.emod_add_ediv_mul (a : Int) (f.M : Int)
  have hdecB := Int.emod_add_ediv_mul (b : Int) (f.M : Int)
  rw [hq, hr] at hdecA
  omega

theorem capacity_positive (f : Frame) : 0 < f.capacity :=
  Nat.mul_pos f.positiveM f.positiveA

theorem isZero_encode (f : Frame) (a : Nat) (ha : a < f.capacity) :
    isZero (f.encode a) = decide (a = 0) := by
  unfold isZero
  rw [zero_eq_encode f]
  by_cases hz : a = 0
  · simp [hz]
  · have hne : f.encode a ≠ f.encode 0 := by
      intro heq
      exact hz (encode_injective_on_window f a 0 ha (capacity_positive f) heq)
    simp [hz, hne]

/-- Adjacent frames provide their inverse algebraically, without a GCD search. -/
def Frame.adjacent (M : Nat) (hM : 0 < M) : Frame where
  M := M
  A := M + 1
  positiveM := hM
  positiveA := by omega
  inverse := -1
  inverse_ok := by
    simpa using IntegerSpecialization.star_inverse_certificate (M : Int) 1

theorem adjacent_query (M : Nat) (hM : 0 < M) (x : State) :
    (Frame.adjacent M hM).kQuery x = (x.main - x.anchor) % ((M : Int) + 1) := by
  change IntegerSpecialization.query x.main x.anchor ((M + 1 : Nat) : Int) (-1) = _
  simpa using IntegerSpecialization.adjacent_query_subtraction x.main x.anchor (M : Int)

/-- Concrete executable operations. encode occurs only in the separate theorem. -/
def Frame.ops (f : Frame) : ResidueAlgorithms.Ops State where
  capacity := f.capacity
  zero := zero
  increment := f.increment
  subtract := f.subtract
  less := f.less
  isZero := isZero

/-- Every abstract primitive obligation is discharged by the actual paired-view
implementation. There is no assumed correct comparator or hidden decoder. -/
theorem ops_correct (f : Frame) : ResidueAlgorithms.Correct f.ops f.encode where
  zero_eq := zero_eq_encode f
  increment_eq n _ := increment_encode f n
  subtract_eq a b h _ := subtract_encode f a b h
  less_eq a b ha hb := less_encode f a b ha hb
  isZero_eq a ha := isZero_encode f a ha

/-- Runtime division consumes two residue states and public frame data. -/
def Frame.divmod (f : Frame) (x y : State) : Option (State × State) :=
  ResidueAlgorithms.divmod f.ops x y

/-- Runtime GCD consumes two residue states and public frame data. -/
def Frame.gcd (f : Frame) (x y : State) : Option State :=
  ResidueAlgorithms.gcd f.ops x y

/-- All positive admitted divisors are supported, including those sharing
factors with either observer modulus, and including inexact divisions. -/
theorem divmod_correct (f : Frame) (n d : Nat)
    (hn : n < f.capacity) (hdcap : d < f.capacity) (hd : 0 < d) :
    f.divmod (f.encode n) (f.encode d) =
      some (f.encode (n / d), f.encode (n % d)) :=
  ResidueAlgorithms.divmod_correct f.ops f.encode (ops_correct f) n d hn hdcap hd

theorem divmod_zero_refused (f : Frame) (dividend : State) :
    f.divmod dividend (f.encode 0) = none :=
  ResidueAlgorithms.divmod_zero_refused f.ops f.encode (ops_correct f)
    dividend (capacity_positive f)

/-- Euclid's result remains a paired-residue state throughout the computation. -/
theorem gcd_correct (f : Frame) (a b : Nat)
    (ha : a < f.capacity) (hb : b < f.capacity) :
    f.gcd (f.encode a) (f.encode b) = some (f.encode (Nat.gcd a b)) :=
  ResidueAlgorithms.gcd_correct f.ops f.encode (ops_correct f) a b ha hb

end KElimination.ResiduePrimitives

#print axioms KElimination.ResiduePrimitives.zero_eq_encode
#print axioms KElimination.ResiduePrimitives.kQuery_exact
#print axioms KElimination.ResiduePrimitives.increment_encode
#print axioms KElimination.ResiduePrimitives.subtract_encode
#print axioms KElimination.ResiduePrimitives.euclidean_lex_order
#print axioms KElimination.ResiduePrimitives.less_encode
#print axioms KElimination.ResiduePrimitives.encode_injective_on_window
#print axioms KElimination.ResiduePrimitives.capacity_positive
#print axioms KElimination.ResiduePrimitives.isZero_encode
#print axioms KElimination.ResiduePrimitives.adjacent_query
#print axioms KElimination.ResiduePrimitives.ops_correct
#print axioms KElimination.ResiduePrimitives.divmod_correct
#print axioms KElimination.ResiduePrimitives.divmod_zero_refused
#print axioms KElimination.ResiduePrimitives.gcd_correct
