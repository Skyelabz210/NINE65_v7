import KElimination.UniversalResearch.IntegerSpecialization

/-!
StarLift as an observed-coordinate query, with both subtraction orientations
explicit. Source/reference/lift variables occur only in theorem specifications.
The word "infinity" is not an arithmetic object in these definitions: a source
coordinate may be unbounded while its requested residue is finite.
-/

namespace KElimination.StarLift

open IntegerSpecialization

def positiveAdjacent (main source M : Int) : Int := (main - source) % (M + 1)
def negativeAdjacent (main source M : Int) : Int := (source - main) % (M + 1)

theorem negate_residue (k A : Int) : (-(k % A)) % A = (-k) % A := by
  simpa only [Int.zero_sub] using (Int.sub_emod_emod 0 k A)

/-- The general-anchor negative-coordinate query uses a negated public inverse. -/
def negativeQuery (chart source A inverse : Int) : Int :=
  (((source - chart) % A) * (-inverse)) % A

theorem negative_query_eq_negate (chart source A inverse : Int) :
    negativeQuery chart source A inverse = (-(query chart source A inverse)) % A := by
  unfold negativeQuery query
  rw [Int.mul_neg, negate_residue]

theorem negative_query_of_decomposition (X r chart source M A inverse k : Int)
    (hsource : X = r + M * k) (hchart : chart = r % A)
    (hs : source = X % A) (hinv : (inverse * M) % A = 1 % A) :
    negativeQuery chart source A inverse = (-k) % A := by
  rw [negative_query_eq_negate,
    query_chart_of_decomposition X r chart source M A inverse k hsource hchart hs hinv,
    negate_residue]

/-- Both orientations are valid for arbitrary signed X, without a magnitude
bound. Their results are congruence classes of the Euclidean quotient. -/
theorem positive_adjacent_congruence (X main source M : Int)
    (hm : main = X % M) (hs : source = X % (M + 1)) :
    positiveAdjacent main source M = (X / M) % (M + 1) := by
  unfold positiveAdjacent
  rw [← adjacent_query_subtraction]
  apply query_quotient_congruence X main source M (M + 1) (-1) hm hs
  simpa using star_inverse_certificate M 1

theorem adjacent_orientations (main source M : Int) :
    negativeAdjacent main source M = (-(positiveAdjacent main source M)) % (M + 1) := by
  unfold positiveAdjacent negativeAdjacent
  rw [negate_residue]
  congr 1
  omega

theorem negative_adjacent_congruence (X main source M : Int)
    (hm : main = X % M) (hs : source = X % (M + 1)) :
    negativeAdjacent main source M = (-(X / M)) % (M + 1) := by
  rw [adjacent_orientations, positive_adjacent_congruence X main source M hm hs,
    negate_residue]

/-- For the raw defect source-chart, the negative-coordinate decoder at an
adjacent anchor is the identity; the positive-coordinate decoder negates it. -/
theorem negative_query_adjacent (chart source M : Int) :
    negativeQuery chart source (M + 1) (-1) = negativeAdjacent chart source M := by
  simp [negativeQuery, negativeAdjacent]

/-- Negate the negative-coordinate class, then select the public window. -/
def decodeNegative (negativeClass A lo : Int) : Int :=
  windowDecode ((-negativeClass) % A) A lo

theorem negative_decode_exact (k A lo : Int)
    (hlower : lo ≤ k) (hupper : k < lo + A) :
    decodeNegative ((-k) % A) A lo = k := by
  unfold decodeNegative
  rw [negate_residue, Int.neg_neg]
  exact window_decode_exact k A lo hlower hupper

theorem negative_adjacent_exact_window (X main source M lo : Int)
    (hm : main = X % M) (hs : source = X % (M + 1))
    (hlower : lo ≤ X / M) (hupper : X / M < lo + (M + 1)) :
    decodeNegative (negativeAdjacent main source M) (M + 1) lo = X / M := by
  rw [negative_adjacent_congruence X main source M hm hs]
  exact negative_decode_exact _ _ _ hlower hupper

theorem positive_adjacent_exact_source_window (X main source M : Int)
    (hM : 0 < M) (hm : main = X % M) (hs : source = X % (M + 1))
    (hlower : 0 ≤ X) (hupper : X < M * (M + 1)) :
    positiveAdjacent main source M = X / M :=
  adjacent_readout_exact X main source M hM hm hs hlower hupper

/-- The observed multiplication and coordinate reduction have the same
kernel under a valid inverse certificate. This is the transport criterion. -/
theorem unit_kernel_equal (M A inverse k : Int)
    (hinv : (inverse * M) % A = 1 % A) :
    (M * k) % A = 0 ↔ k % A = 0 := by
  constructor
  · intro hz
    have h := query_of_decomposition (M * k) 0 ((M * k) % A) M A inverse k
      (by omega) rfl hinv
    rw [hz] at h
    simpa [query] using h.symm
  · intro hk
    rw [Int.mul_emod, hk]
    simp

theorem adjacent_kernel_equal (M k : Int) :
    (M * k) % (M + 1) = 0 ↔ k % (M + 1) = 0 := by
  apply unit_kernel_equal M (M + 1) (-1) k
  simpa using star_inverse_certificate M 1

/-- The nonunit negative query retains the same reduced resolution. -/
def negativeNonunitQuery (chart source A d inverse : Int) : Int :=
  (-(nonunitQuery chart source A d inverse)) % (A / d)

theorem negative_nonunit_chart_query (X r chart source M A d inverse k : Int)
    (hsource : X = r + M * k) (hchart : chart = r % A) (hs : source = X % A)
    (hd : d ≠ 0) (hM : d ∣ M) (hA : d ∣ A)
    (hinv : (inverse * (M / d)) % (A / d) = 1 % (A / d)) :
    d ∣ source - chart ∧
      negativeNonunitQuery chart source A d inverse = (-k) % (A / d) := by
  have h := nonunit_chart_query X r chart source M A d inverse k
    hsource hchart hs hd hM hA hinv
  refine ⟨h.1, ?_⟩
  unfold negativeNonunitQuery
  rw [h.2, negate_residue]

end KElimination.StarLift

#print axioms KElimination.StarLift.negate_residue
#print axioms KElimination.StarLift.negative_query_eq_negate
#print axioms KElimination.StarLift.negative_query_of_decomposition
#print axioms KElimination.StarLift.positive_adjacent_congruence
#print axioms KElimination.StarLift.adjacent_orientations
#print axioms KElimination.StarLift.negative_adjacent_congruence
#print axioms KElimination.StarLift.negative_query_adjacent
#print axioms KElimination.StarLift.negative_decode_exact
#print axioms KElimination.StarLift.negative_adjacent_exact_window
#print axioms KElimination.StarLift.positive_adjacent_exact_source_window
#print axioms KElimination.StarLift.unit_kernel_equal
#print axioms KElimination.StarLift.adjacent_kernel_equal
#print axioms KElimination.StarLift.negative_nonunit_chart_query
