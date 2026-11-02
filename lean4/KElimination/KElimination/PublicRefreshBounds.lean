import Std

/-!
# Exact arithmetic obligations for the conditional public refresh loop

These theorems formalize the natural-number bound model used by
`public_phase_clock.rs`, `phase_clock_return.rs`, and `noise/certified.rs`.
They do not assert correctness of the ciphertext implementation, lookup geometry,
key security, or native-profile admission. In particular, the loop theorem needs
an independently justified refresh envelope and an explicit budget inequality.
No measured error or fresh-encryption bound is substituted for that envelope.
-/

namespace KElimination.PublicRefreshBounds

/-- `V` is an ideal-grid error bound `|t*phase-Q*message|`. -/
def Admitted (q v : Nat) : Prop := 2 * v < q

/-- The return implementation compares with `floor(Q/2)` because Q is odd. -/
theorem odd_half_headroom_iff (q v : Nat) (hq : q % 2 = 1) :
    v ≤ q / 2 ↔ Admitted q v := by
  unfold Admitted
  omega

/-- Exact Euclidean nearest-integer decoding for signed messages and errors.
This quotient identity assumes a positive odd modulus and the strict ideal-grid
error corridor; it does not establish how a Rust ciphertext obtains that error.
-/
theorem nearest_integer_decode (q m e : Int) (hq : 0 < q) (hodd : q % 2 = 1)
    (hlower : -q < 2 * e) (hupper : 2 * e < q) :
    (q * m + e + q / 2) / q = m := by
  have hnonneg : 0 ≤ e + q / 2 := by omega
  have hlt : e + q / 2 < q := by omega
  have hnum : q * m + e + q / 2 = (e + q / 2) + m * q := by
    simp only [Int.mul_comm q m]
    omega
  have hqne : q ≠ 0 := Int.ne_of_gt hq
  rw [hnum, Int.add_mul_ediv_right _ _ hqne, Int.ediv_eq_zero_of_lt hnonneg hlt]
  simp

/-- Exact admission boundary for the component-rounding residual envelope.
The numerator bounds twice Q times the residual magnitude. Its derivation
from source error and ternary support is a separate producer obligation. -/
theorem residual_envelope_admission (q numerator radius : Nat) (hq : 0 < q) :
    numerator / (2 * q) ≤ radius ↔ numerator < 2 * q * (radius + 1) := by
  have hden : 0 < 2 * q := Nat.mul_pos (by decide) hq
  have h : numerator / (2 * q) < radius + 1 ↔ numerator < (radius + 1) * (2 * q) := Nat.div_lt_iff_lt_mul hden
  rw [Nat.mul_comm (radius + 1)] at h
  omega

/-- The conservative quadratic envelope used by `ScalarNoiseModel::multiply`.
The even source degree is represented as `2*k`. The inequality is in exact
integers before division by Q, so no rounding convention is hidden. -/
theorem quadratic_envelope (q k a b : Nat)
    (ha : Admitted q a) (hb : Admitted q b) :
    (2 * k) * a * b ≤ q * (k * min a b) := by
  unfold Admitted at ha hb
  by_cases hab : a ≤ b
  · rw [Nat.min_eq_left hab]
    have h := Nat.mul_le_mul_right (k * a) (Nat.le_of_lt hb)
    simpa [Nat.mul_assoc, Nat.mul_comm, Nat.mul_left_comm] using h
  · have hba : b ≤ a := by omega
    rw [Nat.min_eq_right hba]
    have h := Nat.mul_le_mul_right (k * b) (Nat.le_of_lt ha)
    simpa [Nat.mul_assoc, Nat.mul_comm, Nat.mul_left_comm] using h

/-- This is exactly the divided envelope charged by the scalar implementation.
Every supported scalar ring degree is even. -/
theorem quadratic_div_envelope (q n a b : Nat) (hn : n % 2 = 0)
    (ha : Admitted q a) (hb : Admitted q b) :
    n * a * b / q ≤ (n / 2) * min a b := by
  have h := quadratic_envelope q (n / 2) a b ha hb
  have hdegree : 2 * (n / 2) = n := by omega
  rw [hdegree] at h
  exact Nat.div_le_of_le_mul h

/-- Sum complete error envelopes; coefficient errors need not have disjoint
support after the trace/assembly operation. -/
def accumulated : List Nat → Nat
  | [] => 0
  | x :: xs => x + accumulated xs

theorem assembly_envelope (errors : List Nat) (cap : Nat)
    (h : ∀ e ∈ errors, e ≤ cap) :
    accumulated errors ≤ errors.length * cap := by
  induction errors with
  | nil => simp [accumulated]
  | cons e es ih =>
    have he : e ≤ cap := h e (by simp)
    have hs : accumulated es ≤ es.length * cap :=
      ih (by intro x hx; exact h x (by simp [hx]))
    simp only [accumulated, List.length_cons, Nat.add_mul, Nat.one_mul]
    omega

/-- Error deposited by all D hybrid return switches, in ideal-grid units.
Here `digitCount` is the sum over all active limbs, and `base` is B (not bits).
-/
def switchDeposit (t d n eta base digitCount : Nat) : Nat :=
  t * d * n * eta * (base - 1) * digitCount

def returnEnvelope (n coefficientCap t d eta base digitCount : Nat) : Nat :=
  n * coefficientCap + switchDeposit t d n eta base digitCount

theorem assembled_return_envelope
    (errors : List Nat) (n coefficientCap t d eta base digitCount : Nat)
    (hlen : errors.length = n) (h : ∀ e ∈ errors, e ≤ coefficientCap) :
    accumulated errors + switchDeposit t d n eta base digitCount ≤
      returnEnvelope n coefficientCap t d eta base digitCount := by
  have hs := assembly_envelope errors coefficientCap h
  rw [hlen] at hs
  unfold returnEnvelope
  omega

/-- Linear coefficient in the conservative centered scalar product bound. -/
def productFactor (n t : Nat) : Nat :=
  (t - 1) / 2 + n * t * (n / 2 + 1)

/-- Exact square specialization of the bound in `noise/certified.rs`.
`roundingDeposit` and `switchingDeposit` are independently justified deposits.
-/
def squareEnvelope (n t roundingDeposit switchingDeposit v : Nat) : Nat :=
  (v + v) * productFactor n t + v * (n / 2) +
    roundingDeposit + switchingDeposit

theorem square_envelope_monotone (n t roundingDeposit switchingDeposit a b : Nat)
    (hab : a ≤ b) :
    squareEnvelope n t roundingDeposit switchingDeposit a ≤
      squareEnvelope n t roundingDeposit switchingDeposit b := by
  have hlinear := Nat.mul_le_mul_right (productFactor n t) (Nat.add_le_add hab hab)
  have hquadratic := Nat.mul_le_mul_right (n / 2) hab
  unfold squareEnvelope
  omega

/-- Every cycle refreshes to a complete returned envelope `r`, then squares and
adds plaintext with a deposit bounded by `plainDeposit`. The original input
allowance is reused, rather than reset to an encryption bound.
-/
theorem refresh_square_add_closed
    (q allowance r n t roundingDeposit switchingDeposit plainDeposit : Nat)
    (hinput : Admitted q allowance)
    (hbudget : squareEnvelope n t roundingDeposit switchingDeposit r +
      plainDeposit ≤ allowance)
    (v offsetDeposit : Nat) (hv : v ≤ r) (hoffset : offsetDeposit ≤ plainDeposit) :
    squareEnvelope n t roundingDeposit switchingDeposit v + offsetDeposit ≤ allowance ∧
      Admitted q (squareEnvelope n t roundingDeposit switchingDeposit v + offsetDeposit) := by
  have hmono := square_envelope_monotone n t roundingDeposit switchingDeposit v r hv
  unfold Admitted at hinput ⊢
  constructor <;> omega

/-- A state transition for one publicly bounded refresh/product cycle. The
refresh producer's correctness and provenance are hypotheses, not consequences
of this arithmetic theorem. Offsets and envelopes may vary on every iteration.
-/
def CycleStep
    (r n t roundingDeposit switchingDeposit plainDeposit next : Nat) : Prop :=
  ∃ v offsetDeposit, v ≤ r ∧ offsetDeposit ≤ plainDeposit ∧
    next = squareEnvelope n t roundingDeposit switchingDeposit v + offsetDeposit

theorem all_cycles_admitted
    (q allowance r n t roundingDeposit switchingDeposit plainDeposit : Nat)
    (hinput : Admitted q allowance)
    (hbudget : squareEnvelope n t roundingDeposit switchingDeposit r +
      plainDeposit ≤ allowance)
    (states : Nat → Nat) (hzero : states 0 ≤ allowance)
    (hstep : ∀ j, states j ≤ allowance →
      CycleStep r n t roundingDeposit switchingDeposit plainDeposit (states (j + 1))) :
    ∀ j, states j ≤ allowance ∧ Admitted q (states j) := by
  intro j
  induction j with
  | zero =>
    unfold Admitted at hinput ⊢
    exact ⟨hzero, by omega⟩
  | succ j ih =>
    obtain ⟨v, off, hv, hoff, hnext⟩ := hstep j ih.1
    rw [hnext]
    exact refresh_square_add_closed q allowance r n t roundingDeposit switchingDeposit
      plainDeposit hinput hbudget v off hv hoff

/-! ## Concrete budget for the executed degree-8 / degree-256 fixture

`cram_main_phase_clock.rs` starts from `secure_128()` and changes the work degree
to 8 and the security label to 0. The four listed primes, t=65537 and eta=3 come
from `SecureConfig::secure_128`; `HYBRID_BASE_BITS=10` gives three digits per
listed prime, hence twelve digits in total. Boot degree is 256 and D=32.

The maximum centered lookup coefficient is bounded by t/2, and the affine norm
by (N+1)*(t/2). These conservative caps dominate every possible source value;
they do not depend on the plaintext trace or a measured ciphertext error.
The following arithmetic is kernel evaluated with `decide`, not native code.
-/

namespace Fixture

def q : Nat := 998244353 * 985661441 * 754974721 * 469762049
def t : Nat := 65537
def rho : Nat := q % t
def bootSwitch : Nat := 256 * 3 * (1024 - 1) * 12
def lookupCap : Nat :=
  256 * (rho * (t / 2) + bootSwitch * t * 4 * 8) + bootSwitch * t * 255
def coefficientCap : Nat :=
  lookupCap + rho * ((8 + 1) * (t / 2)) + bootSwitch * t * 4 * 8
def returnedCap : Nat := returnEnvelope 8 coefficientCap t 32 3 1024 12
def rounding : Nat := (t * (1 + 8 + 8 * 8) + 1) / 2
def workSwitch : Nat := t * 8 * 3 * (1024 - 1) * 12
def plainCap : Nat := rho * (t - 1)
def allowance : Nat := q / 128

/-- Full assembly/return, subsequent square, and the largest canonical
plaintext offset fit the same immutable input allowance on every cycle. -/
theorem budget_closed :
    squareEnvelope 8 t rounding workSwitch returnedCap + plainCap ≤ allowance := by
  decide

theorem allowance_admitted : Admitted q allowance := by
  unfold Admitted
  decide

/-- An exact numerical anchor for review and cross-language conformance tests. -/
theorem budget_values :
    q = 348959453350711275087786864768188417 ∧
    returnedCap = 41914601470491648 ∧
    squareEnvelope 8 t rounding workSwitch returnedCap + plainCap =
      222503661906126014492421 := by
  decide

/-- No finite iteration limit occurs in this arithmetic model. Ciphertext
correctness, issuer checks and the refresh producer remain explicit premises.
This theorem does not admit any named native security profile. -/
theorem arbitrary_cycles
    (states : Nat → Nat) (hzero : states 0 ≤ allowance)
    (hstep : ∀ j, states j ≤ allowance →
      CycleStep returnedCap 8 t rounding workSwitch plainCap (states (j + 1))) :
    ∀ j, states j ≤ allowance ∧ Admitted q (states j) :=
  all_cycles_admitted q allowance returnedCap 8 t rounding workSwitch plainCap
    allowance_admitted budget_closed states hzero hstep

end Fixture

/-- Concrete closure of the standalone toy ledger: following-square error
fits the next radius-3 corridor and the source decoding threshold. This checks
the budget arithmetic; the stage-error derivations require implementation review. -/
theorem toy_full_polynomial_cycle_budget :
    (2 * 97 * 97 * 5772257706 + (97 * 2^40) * 5 : Nat) <
      2 * (97 * 2^40) * (3 + 1) ∧
    (2 * 5772257706 : Nat) < 2^40 ∧
    (9 + 16 * 8 * (2^8 - 1) * 6 : Nat) = 195849 := by
  decide

end KElimination.PublicRefreshBounds
