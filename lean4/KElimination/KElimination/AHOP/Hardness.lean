/-
  AHOP Hardness Formalization

  This file captures the hardness assumption and basic structural
  definitions needed for later security reductions.

  Date: 2026-02-04
  Status: Ported from SwarmProofs to NINE65 v5
-/

import Mathlib.Data.ZMod.Basic
import Mathlib.Data.Set.Basic
import Mathlib.Data.Vector.Basic
import Mathlib.Data.Fintype.BigOperators
import Mathlib.Data.Finite.Card
import Mathlib.Data.Nat.Basic
import Mathlib.Tactic
import KElimination.AHOP.Algebra

namespace KElimination.AHOP.Hardness

open KElimination.AHOP

instance neZero_of_fact {q : ℕ} [Fact (0 < q)] : NeZero q :=
  ⟨Nat.ne_of_gt (Fact.out)⟩

/-- Sum of coordinates for a quadruple. -/
def sum4 {q : ℕ} [Fact (0 < q)] (k : Fin 4 → ZMod q) : ZMod q :=
  k 0 + k 1 + k 2 + k 3

/-- A state is zero-tagged if it has a unique zero coordinate. -/
def ZeroTagged {q : ℕ} [Fact (0 < q)] (s : Fin 4 → ZMod q) : Prop :=
  ∃! i : Fin 4, s i = 0

noncomputable def zeroTag {q : ℕ} [Fact (0 < q)] (s : Fin 4 → ZMod q)
    (h : ZeroTagged s) : Fin 4 :=
  Classical.choose h

lemma zeroTag_spec {q : ℕ} [Fact (0 < q)] (s : Fin 4 → ZMod q) (h : ZeroTagged s) :
    s (zeroTag s h) = 0 :=
  (Classical.choose_spec h).1

lemma zeroTag_unique {q : ℕ} [Fact (0 < q)] (s : Fin 4 → ZMod q) (h : ZeroTagged s)
    {i : Fin 4} (hi : s i = 0) : i = zeroTag s h :=
  (Classical.choose_spec h).2 i hi

/-- Decoding lemma: the unique zero index is recovered by `zeroTag`. -/
lemma zeroTag_decodes {q : ℕ} [Fact (0 < q)] (s : Fin 4 → ZMod q) (h : ZeroTagged s)
    {i : Fin 4} (hi : s i = 0) : zeroTag s h = i := by
  exact (zeroTag_unique s h hi).symm

/-- Apply a list of reflections (right-fold). -/
def applyWordList {q : ℕ} [Fact (0 < q)] : List (Fin 4) → (Fin 4 → ZMod q) → (Fin 4 → ZMod q)
  | [], k => k
  | i :: w, k => reflect i (applyWordList w k)

lemma applyWordList_cons {q : ℕ} [Fact (0 < q)] {n : Nat}
    (i : Fin 4) (v : List.Vector (Fin 4) n) (k : Fin 4 → ZMod q) :
    applyWordList (List.Vector.cons i v).1 k = reflect i (applyWordList v.1 k) := by
  rfl

/-- Convert a list to an AHOP word. -/
def wordOfList : List (Fin 4) → AHOPWord
  | [] => AHOPWord.empty
  | i :: w => AHOPWord.cons i (wordOfList w)

/-- Applying a list matches applying its AHOP word. -/
theorem applyWord_ofList {q : ℕ} [Fact (0 < q)] (w : List (Fin 4)) (k : Fin 4 → ZMod q) :
    applyWord (wordOfList w) k = applyWordList w k := by
  induction w with
  | nil => rfl
  | cons i w ih => simp [wordOfList, applyWordList, applyWord, ih]

/-- Any list action lands in the orbit. -/
theorem applyWordList_in_orbit {q : ℕ} [Fact (0 < q)] (k : Fin 4 → ZMod q) (w : List (Fin 4)) :
    applyWordList w k ∈ orbit k := by
  refine ⟨wordOfList w, ?_⟩
  simp [applyWord_ofList]

lemma applyWordList_head_tail {q : ℕ} [Fact (0 < q)] {n : Nat}
    (v : List.Vector (Fin 4) (Nat.succ n)) (k : Fin 4 → ZMod q) :
    applyWordList v.1 k =
      reflect (List.Vector.head v) (applyWordList (List.Vector.tail v).1 k) := by
  calc
    applyWordList v.1 k =
        applyWordList (List.Vector.cons (List.Vector.head v) (List.Vector.tail v)).1 k := by
          simp
    _ = reflect (List.Vector.head v) (applyWordList (List.Vector.tail v).1 k) := by
          rfl

/-- Distinct reflections on a fixed `k` under a simple separation condition. -/
theorem reflect_injective_on_indices {q : ℕ} [Fact (0 < q)]
    (k : Fin 4 → ZMod q)
    (h : ∀ i : Fin 4, 2 * sum4 k ≠ 4 * k i) :
    Function.Injective (fun i : Fin 4 => reflect i k) := by
  intro i j hij
  by_cases hji : i = j
  · exact hji
  · have hcoord : (reflect i k) i = (reflect j k) i := by
      simpa using congrArg (fun f => f i) hij
    have hcoord' : 2 * sum4 k - 3 * k i = k i := by
      simpa [reflect, sum4, hji] using hcoord
    have hbad : 2 * sum4 k = 4 * k i := by
      have h' := congrArg (fun x => x + 3 * k i) hcoord'
      ring_nf at h'
      simpa [mul_comm, mul_left_comm, mul_assoc] using h'
    exfalso
    exact (h i) hbad

/-- Finite instance for orbit subtype (inherited from the ambient finite type). -/
instance orbitSubtype_finite {q : ℕ} [Fact (0 < q)] (k : Fin 4 → ZMod q) :
    Finite {k' // k' ∈ orbit k} := by
  classical
  refine Finite.of_injective (fun x : {k' // k' ∈ orbit k} => (x : Fin 4 → ZMod q)) ?_
  intro x y h
  apply Subtype.ext
  simpa using h

noncomputable instance orbitSubtype_fintype {q : ℕ} [Fact (0 < q)] (k : Fin 4 → ZMod q) :
    Fintype {k' // k' ∈ orbit k} :=
  Fintype.ofFinite _

/-- Length of an AHOP word. -/
def wordLength : AHOPWord -> Nat
  | AHOPWord.empty => 0
  | AHOPWord.cons _ w => wordLength w + 1

/-- Solution validity for an AHOP instance. -/
def isValidSolution {q : ℕ} [Fact (0 < q)] (inst : AHOPInstance q) (w : AHOPWord) : Prop :=
  applyWord w inst.k_start = inst.k_target

/-- AHOP hardness assumption (axiomatic). -/
axiom ahop_hardness (q : ℕ) [Fact (0 < q)] :
  ∀ (alg : AHOPInstance q → Option AHOPWord),
    ∃ inst : AHOPInstance q,
      match alg inst with
      | none => True
      | some w => ¬ isValidSolution inst w ∨ wordLength w > q * q

/-- The orbit is nonempty (contains the starting point). -/
theorem orbit_nonempty {q : ℕ} [Fact (0 < q)] (k : Fin 4 → ZMod q) :
    Set.Nonempty (orbit k) := by
  refine ⟨k, ?_⟩
  exact ⟨AHOPWord.empty, rfl⟩

/--
  Exponential lower bound on the orbit size under an injective action assumption.

  If all length-ℓ reflection sequences produce distinct outputs, then the orbit
  has at least 4^ℓ elements.
-/
theorem orbit_exponential_lower_bound {q : ℕ} [Fact (0 < q)]
    (k : Fin 4 → ZMod q) (ℓ : Nat)
    (inj : Function.Injective (fun v : List.Vector (Fin 4) ℓ => applyWordList v.1 k)) :
    (4 : Nat) ^ ℓ ≤ Fintype.card {k' // k' ∈ orbit k} := by
  classical
  let f : List.Vector (Fin 4) ℓ → {k' // k' ∈ orbit k} :=
    fun v => ⟨applyWordList v.1 k, applyWordList_in_orbit k v.1⟩
  have hinj : Function.Injective f := by
    intro v1 v2 h
    apply inj
    simpa using congrArg Subtype.val h
  have hcardNat : Nat.card (List.Vector (Fin 4) ℓ) ≤ Nat.card {k' // k' ∈ orbit k} :=
    Nat.card_le_card_of_injective f hinj
  have hvec : Nat.card (List.Vector (Fin 4) ℓ) = (4 : Nat) ^ ℓ := by
    classical
    have hvec' : Fintype.card (List.Vector (Fin 4) ℓ) = (Fintype.card (Fin 4)) ^ ℓ :=
      card_vector (α := Fin 4) ℓ
    have hvec'' : Fintype.card (List.Vector (Fin 4) ℓ) = (4 : Nat) ^ ℓ := by
      calc
        Fintype.card (List.Vector (Fin 4) ℓ) = (Fintype.card (Fin 4)) ^ ℓ := hvec'
        _ = (4 : Nat) ^ ℓ := by simp
    simp [Nat.card_eq_fintype_card, hvec'']
  have hnat : (4 : Nat) ^ ℓ ≤ Nat.card {k' // k' ∈ orbit k} := by
    simpa [hvec] using hcardNat
  simpa [Nat.card_eq_fintype_card] using hnat

/-- Injectivity for length-1 words under the separation condition. -/
theorem injective_length_one {q : ℕ} [Fact (0 < q)]
    (k : Fin 4 → ZMod q)
    (h : ∀ i : Fin 4, 2 * sum4 k ≠ 4 * k i) :
    Function.Injective (fun v : List.Vector (Fin 4) 1 => applyWordList v.1 k) := by
  intro v1 v2 hv
  rcases v1 with ⟨l1, hl1⟩
  rcases v2 with ⟨l2, hl2⟩
  rcases List.length_eq_one_iff.mp hl1 with ⟨i, rfl⟩
  rcases List.length_eq_one_iff.mp hl2 with ⟨j, rfl⟩
  have hv' : reflect i k = reflect j k := by
    simpa [applyWordList] using hv
  have hij : i = j := reflect_injective_on_indices k h hv'
  subst hij
  apply Subtype.ext
  rfl

/-- Injectivity for all lengths given a decoding tag. -/
theorem injective_all_lengths {q : ℕ} [Fact (0 < q)] [Fact (q > 2)]
    (k : Fin 4 → ZMod q)
    (tag : (Fin 4 → ZMod q) → Fin 4)
    (htag : ∀ s i, tag (reflect i s) = i) :
    ∀ ℓ, Function.Injective (fun v : List.Vector (Fin 4) ℓ => applyWordList v.1 k) := by
  intro ℓ
  induction ℓ with
  | zero =>
      intro v1 v2 _h
      calc
        v1 = List.Vector.nil := by simpa using (List.Vector.eq_nil v1)
        _ = v2 := by simpa using (List.Vector.eq_nil v2).symm
  | succ n ih =>
      intro v1 v2 hEq
      have h' :
          reflect (List.Vector.head v1) (applyWordList (List.Vector.tail v1).1 k) =
          reflect (List.Vector.head v2) (applyWordList (List.Vector.tail v2).1 k) := by
        simpa [applyWordList_head_tail] using hEq
      have hhead : List.Vector.head v1 = List.Vector.head v2 := by
        have ht := congrArg tag h'
        simpa [htag] using ht
      have htailEq :
          applyWordList (List.Vector.tail v1).1 k =
          applyWordList (List.Vector.tail v2).1 k := by
        have h'' :
            reflect (List.Vector.head v1) (applyWordList (List.Vector.tail v1).1 k) =
            reflect (List.Vector.head v1) (applyWordList (List.Vector.tail v2).1 k) := by
          simpa [hhead] using h'
        have h''' := congrArg (fun x => reflect (List.Vector.head v1) x) h''
        simpa [reflect_involution] using h'''
      have htail : List.Vector.tail v1 = List.Vector.tail v2 :=
        ih htailEq
      calc
        v1 = List.Vector.cons (List.Vector.head v1) (List.Vector.tail v1) := by
          simp
        _ = List.Vector.cons (List.Vector.head v2) (List.Vector.tail v2) := by
          simp [hhead, htail]
        _ = v2 := by
          simp

/-- Concrete orbit lower bound from length-1 injectivity. -/
theorem orbit_at_least_four {q : ℕ} [Fact (0 < q)]
    (k : Fin 4 → ZMod q)
    (h : ∀ i : Fin 4, 2 * sum4 k ≠ 4 * k i) :
    4 ≤ Fintype.card {k' // k' ∈ orbit k} := by
  have hinj := injective_length_one (k := k) h
  simpa using (orbit_exponential_lower_bound (k := k) (ℓ := 1) hinj)

/-- Exponential orbit bound for all lengths when a decoding tag exists. -/
theorem orbit_exponential_from_tag {q : ℕ} [Fact (0 < q)] [Fact (q > 2)]
    (k : Fin 4 → ZMod q)
    (tag : (Fin 4 → ZMod q) → Fin 4)
    (htag : ∀ s i, tag (reflect i s) = i) (ℓ : Nat) :
    (4 : Nat) ^ ℓ ≤ Fintype.card {k' // k' ∈ orbit k} := by
  have hinj := injective_all_lengths (k := k) (tag := tag) htag ℓ
  exact orbit_exponential_lower_bound (k := k) (ℓ := ℓ) hinj

/-- Words whose successive results always have a unique zero at the head index. -/
def ZeroTaggedWord {q : ℕ} [Fact (0 < q)] :
    ∀ {ℓ : Nat}, List.Vector (Fin 4) ℓ → (Fin 4 → ZMod q) → Prop
  | 0, _v, _k => True
  | Nat.succ _n, v, k =>
      let s := applyWordList v.1 k
      s (List.Vector.head v) = 0 ∧ ZeroTagged s ∧ ZeroTaggedWord (List.Vector.tail v) k

/-- Head decoding for zero-tagged words. -/
lemma zeroTaggedWord_head_decodes {q : ℕ} [Fact (0 < q)] {n : Nat}
    (v : List.Vector (Fin 4) (Nat.succ n)) (k : Fin 4 → ZMod q)
    (h : ZeroTaggedWord v k) :
    ∃ hz : ZeroTagged (applyWordList v.1 k),
      zeroTag (applyWordList v.1 k) hz = List.Vector.head v := by
  have h' :
      (applyWordList v.1 k) (List.Vector.head v) = 0 ∧
      ZeroTagged (applyWordList v.1 k) ∧
      ZeroTaggedWord (List.Vector.tail v) k := by
    simpa [ZeroTaggedWord] using h
  refine ⟨h'.2.1, ?_⟩
  exact zeroTag_decodes (s := applyWordList v.1 k) (h := h'.2.1)
    (i := List.Vector.head v) h'.1

/-- Tail preservation for zero-tagged words. -/
lemma zeroTaggedWord_tail {q : ℕ} [Fact (0 < q)] {n : Nat}
    (v : List.Vector (Fin 4) (Nat.succ n)) (k : Fin 4 → ZMod q)
    (h : ZeroTaggedWord v k) : ZeroTaggedWord (List.Vector.tail v) k := by
  have h' :
      (applyWordList v.1 k) (List.Vector.head v) = 0 ∧
      ZeroTagged (applyWordList v.1 k) ∧
      ZeroTaggedWord (List.Vector.tail v) k := by
    simpa [ZeroTaggedWord] using h
  exact h'.2.2

/-- Injectivity for zero-tagged words (explicit tag via unique zero coordinate). -/
theorem injective_zeroTagged {q : ℕ} [Fact (0 < q)] [Fact (q > 2)]
    (k : Fin 4 → ZMod q) :
    ∀ {ℓ : Nat} {v1 v2 : List.Vector (Fin 4) ℓ},
      ZeroTaggedWord v1 k → ZeroTaggedWord v2 k →
      applyWordList v1.1 k = applyWordList v2.1 k → v1 = v2 := by
  intro ℓ
  induction ℓ with
  | zero =>
      intro v1 v2 _ _ _h
      calc
        v1 = List.Vector.nil := by simpa using (List.Vector.eq_nil v1)
        _ = v2 := by simpa using (List.Vector.eq_nil v2).symm
  | succ n ih =>
      intro v1 v2 hv1 hv2 hEq
      have hhead : List.Vector.head v1 = List.Vector.head v2 := by
        rcases zeroTaggedWord_head_decodes (v := v1) (k := k) hv1 with ⟨hz1, htag1⟩
        rcases zeroTaggedWord_head_decodes (v := v2) (k := k) hv2 with ⟨hz2, htag2⟩
        have hz2' : ZeroTagged (applyWordList v1.1 k) := by
          simpa [hEq] using hz2
        have htag2' : zeroTag (applyWordList v1.1 k) hz2' = List.Vector.head v2 := by
          simpa [hEq] using htag2
        have htag_eq :
            zeroTag (applyWordList v1.1 k) hz1 =
            zeroTag (applyWordList v1.1 k) hz2' := by
          exact zeroTag_unique (applyWordList v1.1 k) hz2'
            (zeroTag_spec (applyWordList v1.1 k) hz1)
        calc
          List.Vector.head v1 = zeroTag (applyWordList v1.1 k) hz1 := by
            exact htag1.symm
          _ = zeroTag (applyWordList v1.1 k) hz2' := htag_eq
          _ = List.Vector.head v2 := htag2'
      have htailEq :
          applyWordList (List.Vector.tail v1).1 k =
          applyWordList (List.Vector.tail v2).1 k := by
        have h' :
            reflect (List.Vector.head v1) (applyWordList (List.Vector.tail v1).1 k) =
            reflect (List.Vector.head v2) (applyWordList (List.Vector.tail v2).1 k) := by
          simpa [applyWordList_head_tail] using hEq
        have h'' :
            reflect (List.Vector.head v1) (applyWordList (List.Vector.tail v1).1 k) =
            reflect (List.Vector.head v1) (applyWordList (List.Vector.tail v2).1 k) := by
          simpa [hhead] using h'
        have h''' := congrArg (fun x => reflect (List.Vector.head v1) x) h''
        simpa [reflect_involution] using h'''
      have htail : List.Vector.tail v1 = List.Vector.tail v2 :=
        ih (v1 := List.Vector.tail v1) (v2 := List.Vector.tail v2)
          (zeroTaggedWord_tail (v := v1) (k := k) hv1)
          (zeroTaggedWord_tail (v := v2) (k := k) hv2)
          htailEq
      calc
        v1 = List.Vector.cons (List.Vector.head v1) (List.Vector.tail v1) := by
          simp
        _ = List.Vector.cons (List.Vector.head v2) (List.Vector.tail v2) := by
          simp [hhead, htail]
        _ = v2 := by
          simp

/-- Orbit lower bound from zero-tagged words. -/
theorem orbit_lower_bound_zeroTagged {q : ℕ} [Fact (0 < q)] [Fact (q > 2)]
    (k : Fin 4 → ZMod q) (ℓ : Nat) :
    Nat.card {v : List.Vector (Fin 4) ℓ // ZeroTaggedWord v k} ≤
      Nat.card {k' // k' ∈ orbit k} := by
  classical
  let f : {v : List.Vector (Fin 4) ℓ // ZeroTaggedWord v k} → {k' // k' ∈ orbit k} :=
    fun v => ⟨applyWordList v.1.1 k, applyWordList_in_orbit k v.1.1⟩
  have hinj : Function.Injective f := by
    intro v1 v2 h
    apply Subtype.ext
    apply injective_zeroTagged (k := k)
      (v1 := v1.1) (v2 := v2.1)
    · exact v1.2
    · exact v2.2
    · simpa using congrArg Subtype.val h
  exact Nat.card_le_card_of_injective f hinj

end KElimination.AHOP.Hardness
