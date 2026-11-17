import Std

/-!
# Integer specialization of exact observation / K-elimination

The computational interface consumes paired readings and public constants.
The mathematical source `X` occurs only in theorem statements/proofs. No
persistent quotient register or scalar materialization is an input to `query`.

The unconditional output is a quotient congruence. Equality to an integer
quotient uses an explicit public window. The source/provenance hypotheses
cannot be inferred from an arbitrary pair of supplied integers.
-/

namespace KElimination.IntegerSpecialization

/-- One modular subtraction followed by one modular multiplication, with the
inverse `u` supplied as a precomputed public constant. The two reductions spell
out the arithmetic-gate interface; no division of the source is evaluated. -/
def query (r s A u : Int) : Int := (((s - r) % A) * u) % A

/-- Equivalent fused expression for the query. -/
theorem query_fused (r s A u : Int) :
    query r s A u = ((s - r) * u) % A := by
  simp [query, Int.mul_emod]

/-- Readout for any authentic affine decomposition. This includes noncanonical
residuals; no claim of Euclidean quotient is made until `r = X % M` is supplied.
The inverse certificate is a congruence and works also for modulus one. -/
theorem query_of_decomposition (X r s M A u k : Int)
    (hsource : X = r + M * k) (hs : s = X % A)
    (hinv : (u * M) % A = 1 % A) :
    query r s A u = k % A := by
  rw [query_fused, hs]
  calc
    ((X % A - r) * u) % A = ((X - r) * u) % A := by
      rw [Int.mul_emod, Int.mul_emod (X - r)]
      simp only [Int.emod_sub_emod]
    _ = ((u * M) * k) % A := by
      congr 1
      rw [hsource]
      grind
    _ = (((u * M) % A) * (k % A)) % A := Int.mul_emod _ _ _
    _ = ((1 % A) * (k % A)) % A := by rw [hinv]
    _ = k % A := by rw [← Int.mul_emod]; simp

/-- The runtime chart reading may itself be only a residue of the affine base
point. There is no need to provide the potentially wide base point `r`. -/
theorem query_chart_of_decomposition (X r chart s M A u k : Int)
    (hsource : X = r + M * k) (hchart : chart = r % A)
    (hs : s = X % A) (hinv : (u * M) % A = 1 % A) :
    query chart s A u = k % A := by
  rw [hchart]
  have h := query_of_decomposition X r s M A u k hsource hs hinv
  simpa only [query, Int.sub_emod_emod] using h

/-- Arbitrary signed source; the computed query is its Euclidean quotient
modulo the anchor. Neither nonnegativity nor a source bound is needed here. -/
theorem query_quotient_congruence (X r s M A u : Int)
    (hr : r = X % M) (hs : s = X % A)
    (hinv : (u * M) % A = 1 % A) :
    query r s A u = (X / M) % A := by
  apply query_of_decomposition X r s M A u (X / M)
  · rw [hr, Int.mul_comm M]
    exact (Int.emod_add_ediv_mul X M).symm
  · exact hs
  · exact hinv

/-- Exact quotient when the public quotient window is `[0,A)`. -/
theorem query_exact_of_quotient_window (X r s M A u : Int)
    (hr : r = X % M) (hs : s = X % A)
    (hinv : (u * M) % A = 1 % A)
    (hlower : 0 ≤ X / M) (hupper : X / M < A) :
    query r s A u = X / M := by
  rw [query_quotient_congruence X r s M A u hr hs hinv]
  exact Int.emod_eq_of_lt hlower hupper

/-- The usual source-range condition is sufficient for exact quotient readout.
No hidden scalar reconstruction occurs in `query`. -/
theorem query_exact_of_source_window (X r s M A u : Int)
    (hM : 0 < M) (hr : r = X % M) (hs : s = X % A)
    (hinv : (u * M) % A = 1 % A)
    (hlower : 0 ≤ X) (hupper : X < M * A) :
    query r s A u = X / M := by
  apply query_exact_of_quotient_window X r s M A u hr hs hinv
  · exact Int.ediv_nonneg hlower (Int.le_of_lt hM)
  · apply Int.ediv_lt_of_lt_mul hM
    simpa [Int.mul_comm] using hupper

/-- Decode the unique representative in the public interval `[lo,lo+A)`. -/
def windowDecode (q A lo : Int) : Int := lo + ((q - lo) % A)

theorem window_decode_exact (k A lo : Int)
    (hlower : lo ≤ k) (hupper : k < lo + A) :
    windowDecode (k % A) A lo = k := by
  unfold windowDecode
  rw [Int.emod_sub_emod]
  rw [Int.emod_eq_of_lt (by omega) (by omega)]
  omega

/-- Exact readout for signed quotients using an explicit public window. -/
theorem query_exact_signed_window (X r s M A u lo : Int)
    (hr : r = X % M) (hs : s = X % A)
    (hinv : (u * M) % A = 1 % A)
    (hlower : lo ≤ X / M) (hupper : X / M < lo + A) :
    windowDecode (query r s A u) A lo = X / M := by
  rw [query_quotient_congruence X r s M A u hr hs hinv]
  exact window_decode_exact _ _ _ hlower hupper

/-- Star anchors have a public inverse `-c`; the inverse is proved from the
anchor relation rather than postulated as a query-correctness assumption. -/
theorem star_inverse_certificate (M c : Int) :
    ((-c) * M) % (c * M + 1) = 1 % (c * M + 1) := by
  have h : (-c) * M = 1 - (c * M + 1) := by grind
  rw [h, Int.sub_emod_right]

theorem star_query_congruence (X r s M c : Int)
    (hr : r = X % M) (hs : s = X % (c * M + 1)) :
    query r s (c * M + 1) (-c) = (X / M) % (c * M + 1) := by
  exact query_quotient_congruence X r s M (c * M + 1) (-c)
    hr hs (star_inverse_certificate M c)

/-- With adjacent anchor `M+1`, readout reduces to modular subtraction. -/
theorem adjacent_query_subtraction (r s M : Int) :
    query r s (M + 1) (-1) = (r - s) % (M + 1) := by
  rw [query_fused]
  congr 1
  grind

/-- Exact Euclidean quotient from adjacent authentic readings in the public
source window. This is a direct operation on the two views. -/
theorem adjacent_readout_exact (X r s M : Int)
    (hM : 0 < M) (hr : r = X % M) (hs : s = X % (M + 1))
    (hlower : 0 ≤ X) (hupper : X < M * (M + 1)) :
    (r - s) % (M + 1) = X / M := by
  rw [← adjacent_query_subtraction]
  apply query_exact_of_source_window X r s M (M + 1) (-1)
    hM hr hs
  · simpa using star_inverse_certificate M 1
  · exact hlower
  · exact hupper

/-- Generalized readout first removes a certified common factor d from the
observed defect, then uses a precomputed inverse in the reduced anchor. Unlike
the unit query, this interface explicitly includes an exact division by d. -/
def nonunitQuery (r s A d u : Int) : Int :=
  (((s - r) / d) * u) % (A / d)

/-- Exact factor removal from a consistent affine defect. Divisibility of the
defect is derived from the two public divisibility certificates. -/
theorem affine_defect_reduction (defect M A d k z : Int)
    (hd : d ≠ 0) (hM : d ∣ M) (hA : d ∣ A)
    (hdefect : defect = M * k + A * z) :
    d ∣ defect ∧ defect / d = (M / d) * k + (A / d) * z := by
  have hm := Int.mul_ediv_cancel_of_dvd hM
  have ha := Int.mul_ediv_cancel_of_dvd hA
  have hscaled : defect = d * ((M / d) * k + (A / d) * z) := by
    grind
  exact ⟨⟨_, hscaled⟩, Int.ediv_eq_of_eq_mul_right hd hscaled⟩

/-- The generalized formula is calculated from the defect. Its correctness is
not a premise: the affine consistency equation and reduced inverse suffice. -/
theorem nonunit_query_of_affine_defect (r s M A d u k z : Int)
    (hd : d ≠ 0) (hM : d ∣ M) (hA : d ∣ A)
    (hdefect : s - r = M * k + A * z)
    (hinv : (u * (M / d)) % (A / d) = 1 % (A / d)) :
    nonunitQuery r s A d u = k % (A / d) := by
  have hred := (affine_defect_reduction (s - r) M A d k z hd hM hA hdefect).2
  unfold nonunitQuery
  rw [hred]
  calc
    (((M / d) * k + (A / d) * z) * u) % (A / d) =
        (((M / d) * k) * u) % (A / d) := by
      rw [Int.mul_emod, Int.mul_emod ((M / d) * k)]
      rw [Int.add_mul_emod_self_left]
    _ = ((u * (M / d)) * k) % (A / d) := by
      congr 1
      grind
    _ = (((u * (M / d)) % (A / d)) * (k % (A / d))) % (A / d) :=
      Int.mul_emod _ _ _
    _ = ((1 % (A / d)) * (k % (A / d))) % (A / d) := by rw [hinv]
    _ = k % (A / d) := by rw [← Int.mul_emod]; simp

/-- For an authentic source and affine base point, the exact-defect formula
is valid even when M is not a unit modulo A. -/
theorem nonunit_query_of_decomposition (X r s M A d u k : Int)
    (hsource : X = r + M * k) (hs : s = X % A)
    (hd : d ≠ 0) (hM : d ∣ M) (hA : d ∣ A)
    (hinv : (u * (M / d)) % (A / d) = 1 % (A / d)) :
    d ∣ s - r ∧ nonunitQuery r s A d u = k % (A / d) := by
  have hdec := Int.emod_add_ediv_mul X A
  have hdefect : s - r = M * k + A * (-(X / A)) := by grind
  exact ⟨(affine_defect_reduction (s - r) M A d k (-(X / A))
      hd hM hA hdefect).1,
    nonunit_query_of_affine_defect r s M A d u k (-(X / A))
      hd hM hA hdefect hinv⟩

/-- Fully observed nonunit readout: the chart and source are both residues in
the anchor lane. Neither the wide affine base point r nor X is a runtime input.
Consistency of the exact defect division is proved from authenticity. -/
theorem nonunit_chart_query (X r chart s M A d u k : Int)
    (hsource : X = r + M * k) (hchart : chart = r % A) (hs : s = X % A)
    (hd : d ≠ 0) (hM : d ∣ M) (hA : d ∣ A)
    (hinv : (u * (M / d)) % (A / d) = 1 % (A / d)) :
    d ∣ s - chart ∧ nonunitQuery chart s A d u = k % (A / d) := by
  have hx := Int.emod_add_ediv_mul X A
  have hr := Int.emod_add_ediv_mul r A
  have hdefect : s - chart = M * k + A * (r / A - X / A) := by grind
  exact ⟨(affine_defect_reduction (s - chart) M A d k (r / A - X / A)
      hd hM hA hdefect).1,
    nonunit_query_of_affine_defect chart s M A d u k (r / A - X / A)
      hd hM hA hdefect hinv⟩

theorem nonunit_chart_query_signed_window (X r chart s M A d u k lo : Int)
    (hsource : X = r + M * k) (hchart : chart = r % A) (hs : s = X % A)
    (hd : d ≠ 0) (hM : d ∣ M) (hA : d ∣ A)
    (hinv : (u * (M / d)) % (A / d) = 1 % (A / d))
    (hlower : lo ≤ k) (hupper : k < lo + A / d) :
    windowDecode (nonunitQuery chart s A d u) (A / d) lo = k := by
  rw [(nonunit_chart_query X r chart s M A d u k
    hsource hchart hs hd hM hA hinv).2]
  exact window_decode_exact _ _ _ hlower hupper

/-- Emit directly into a target residue lane. Both multiplicands are reduced
in the target; a full-width scalar `r + M*k` is not a runtime intermediate. -/
def targetProjection (r k M B : Int) : Int :=
  ((r % B) + (M % B) * (k % B)) % B

theorem target_projection_of_decomposition (X r k M B : Int)
    (hsource : X = r + M * k) :
    targetProjection r k M B = X % B := by
  unfold targetProjection
  rw [hsource, Int.add_emod r (M * k) B, Int.mul_emod M k B]
  simp only [Int.add_emod_emod]

/-- A target that annihilates the unknown period M*A does not require an
exact integer lift of k. Its output is already determined by k modulo A. -/
theorem target_projection_of_period_dvd (r k M A B : Int)
    (hperiod : B ∣ M * A) :
    targetProjection r (k % A) M B = targetProjection r k M B := by
  rw [target_projection_of_decomposition (r + M * (k % A)) r (k % A) M B rfl]
  rw [target_projection_of_decomposition (r + M * k) r k M B rfl]
  rcases hperiod with ⟨t, ht⟩
  have hdec := Int.emod_add_ediv_mul k A
  have heq : r + M * k = (r + M * (k % A)) + (t * (k / A)) * B := by
    grind
  rw [heq, Int.add_mul_emod_self_right]

/-- Direct query transport can be exact without knowing k as an integer.
Only the target modulus must annihilate the source ambiguity M*A. -/
theorem query_target_projection_of_period_dvd (X r s M A u B : Int)
    (hr : r = X % M) (hs : s = X % A)
    (hinv : (u * M) % A = 1 % A) (hperiod : B ∣ M * A) :
    targetProjection r (query r s A u) M B = X % B := by
  rw [query_quotient_congruence X r s M A u hr hs hinv]
  rw [target_projection_of_period_dvd r (X / M) M A B hperiod]
  apply target_projection_of_decomposition
  rw [hr, Int.mul_comm M]
  exact (Int.emod_add_ediv_mul X M).symm

/-- Target-lane interface: only a target base-point view, a quotient reading,
and the public multiplier reduced in that lane are runtime arguments. -/
def targetLaneProjection (t q mB B : Int) : Int :=
  (t + mB * (q % B)) % B

theorem target_lane_projection_eq (r t k M mB B : Int)
    (ht : t = r % B) (hm : mB = M % B) :
    targetLaneProjection t k mB B = targetProjection r k M B := by
  simp only [targetLaneProjection, targetProjection, ht, hm]

/-- All runtime readings in this transport are lane-sized observations. The
wide base point r, source X, and quotient k occur only in proof hypotheses.
No exact quotient window is needed when B divides the ambiguity period. -/
theorem chart_query_target_lane_transport (X r chart s k t M A u mB B : Int)
    (hsource : X = r + M * k) (hchart : chart = r % A)
    (hs : s = X % A) (ht : t = r % B) (hm : mB = M % B)
    (hinv : (u * M) % A = 1 % A) (hperiod : B ∣ M * A) :
    targetLaneProjection t (query chart s A u) mB B = X % B := by
  rw [target_lane_projection_eq r t (query chart s A u) M mB B ht hm]
  rw [query_chart_of_decomposition X r chart s M A u k hsource hchart hs hinv]
  rw [target_projection_of_period_dvd r k M A B hperiod]
  exact target_projection_of_decomposition X r k M B hsource

/-- After certified common-factor reduction, the target only needs to
annihilate M*(A/d). This transports a desired residue without lifting k exactly.
For positive M,A and d=gcd(M,A), this is the least-common-multiple period. -/
theorem nonunit_chart_target_lane_transport
    (X r chart s k t M A d u mB B : Int)
    (hsource : X = r + M * k) (hchart : chart = r % A) (hs : s = X % A)
    (ht : t = r % B) (hm : mB = M % B)
    (hd : d ≠ 0) (hM : d ∣ M) (hA : d ∣ A)
    (hinv : (u * (M / d)) % (A / d) = 1 % (A / d))
    (hperiod : B ∣ M * (A / d)) :
    targetLaneProjection t (nonunitQuery chart s A d u) mB B = X % B := by
  rw [target_lane_projection_eq r t (nonunitQuery chart s A d u) M mB B ht hm]
  rw [(nonunit_chart_query X r chart s M A d u k
    hsource hchart hs hd hM hA hinv).2]
  rw [target_projection_of_period_dvd r k M (A / d) B hperiod]
  exact target_projection_of_decomposition X r k M B hsource

theorem query_target_projection (X r s M A u B : Int)
    (hr : r = X % M) (hs : s = X % A)
    (hinv : (u * M) % A = 1 % A)
    (hlower : 0 ≤ X / M) (hupper : X / M < A) :
    targetProjection r (query r s A u) M B = X % B := by
  rw [query_exact_of_quotient_window X r s M A u hr hs hinv hlower hupper]
  apply target_projection_of_decomposition
  rw [hr, Int.mul_comm M]
  exact (Int.emod_add_ediv_mul X M).symm

theorem signed_query_target_projection (X r s M A u lo B : Int)
    (hr : r = X % M) (hs : s = X % A)
    (hinv : (u * M) % A = 1 % A)
    (hlower : lo ≤ X / M) (hupper : X / M < lo + A) :
    targetProjection r (windowDecode (query r s A u) A lo) M B = X % B := by
  rw [query_exact_signed_window X r s M A u lo hr hs hinv hlower hupper]
  apply target_projection_of_decomposition
  rw [hr, Int.mul_comm M]
  exact (Int.emod_add_ediv_mul X M).symm

/-- Two authentic paired readings identify a source exactly on a common
quotient window. This is a uniqueness theorem; it does not materialize X in
the computation. -/
theorem same_views_source_unique (X Y r s M A u lo : Int)
    (hrX : r = X % M) (hsX : s = X % A)
    (hrY : r = Y % M) (hsY : s = Y % A)
    (hinv : (u * M) % A = 1 % A)
    (hXlo : lo ≤ X / M) (hXhi : X / M < lo + A)
    (hYlo : lo ≤ Y / M) (hYhi : Y / M < lo + A) : X = Y := by
  have hqX := query_exact_signed_window X r s M A u lo hrX hsX hinv hXlo hXhi
  have hqY := query_exact_signed_window Y r s M A u lo hrY hsY hinv hYlo hYhi
  have hquot : X / M = Y / M := hqX.symm.trans hqY
  have hdecX := Int.emod_add_ediv_mul X M
  have hdecY := Int.emod_add_ediv_mul Y M
  rw [← hrX, hquot] at hdecX
  rw [← hrY] at hdecY
  exact hdecX.symm.trans hdecY

/-- Finite residue views repeat with period M*A. Shared factors can shorten
the minimal period; repetition itself needs no inverse. -/
theorem paired_views_periodic (X M A : Int) :
    (X + M * A) % M = X % M ∧ (X + M * A) % A = X % A := by
  simp

/-- A fixed pair of nonzero residue moduli cannot determine every unbounded
integer quotient. Windows or further authentic observations are necessary;
this statement is compatible with exact on-demand readout on a known window. -/
theorem no_unbounded_pair_quotient_decoder (M A : Int)
    (hM : M ≠ 0) (hA : A ≠ 0) :
    ¬ ∃ decode : Int → Int → Int,
      ∀ X : Int, decode (X % M) (X % A) = X / M := by
  rintro ⟨decode, hdecode⟩
  have hz := hdecode 0
  have hp := hdecode (M * A)
  have hq : (M * A) / M = A := by
    simpa using Int.add_mul_ediv_left 0 A hM
  simp only [Int.zero_emod, Int.zero_ediv] at hz
  simp only [Int.mul_emod_left, Int.mul_emod_right, hq] at hp
  exact hA (hp.symm.trans hz)

end KElimination.IntegerSpecialization

#print axioms KElimination.IntegerSpecialization.query_fused
#print axioms KElimination.IntegerSpecialization.query_of_decomposition
#print axioms KElimination.IntegerSpecialization.query_chart_of_decomposition
#print axioms KElimination.IntegerSpecialization.query_quotient_congruence
#print axioms KElimination.IntegerSpecialization.query_exact_of_quotient_window
#print axioms KElimination.IntegerSpecialization.query_exact_of_source_window
#print axioms KElimination.IntegerSpecialization.window_decode_exact
#print axioms KElimination.IntegerSpecialization.query_exact_signed_window
#print axioms KElimination.IntegerSpecialization.star_inverse_certificate
#print axioms KElimination.IntegerSpecialization.star_query_congruence
#print axioms KElimination.IntegerSpecialization.adjacent_query_subtraction
#print axioms KElimination.IntegerSpecialization.adjacent_readout_exact
#print axioms KElimination.IntegerSpecialization.affine_defect_reduction
#print axioms KElimination.IntegerSpecialization.nonunit_query_of_affine_defect
#print axioms KElimination.IntegerSpecialization.nonunit_query_of_decomposition
#print axioms KElimination.IntegerSpecialization.nonunit_chart_query
#print axioms KElimination.IntegerSpecialization.nonunit_chart_query_signed_window
#print axioms KElimination.IntegerSpecialization.target_projection_of_decomposition
#print axioms KElimination.IntegerSpecialization.target_projection_of_period_dvd
#print axioms KElimination.IntegerSpecialization.query_target_projection_of_period_dvd
#print axioms KElimination.IntegerSpecialization.target_lane_projection_eq
#print axioms KElimination.IntegerSpecialization.chart_query_target_lane_transport
#print axioms KElimination.IntegerSpecialization.nonunit_chart_target_lane_transport
#print axioms KElimination.IntegerSpecialization.query_target_projection
#print axioms KElimination.IntegerSpecialization.signed_query_target_projection
#print axioms KElimination.IntegerSpecialization.same_views_source_unique
#print axioms KElimination.IntegerSpecialization.paired_views_periodic
#print axioms KElimination.IntegerSpecialization.no_unbounded_pair_quotient_decoder
