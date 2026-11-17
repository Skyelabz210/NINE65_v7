import Std

/-!
# Complete-carry chart geometry for the public phase clock

`PhaseClockPlan` bounds twice the uncertainty window by
`phase + m * (H + 1)`, where `H` bounds source-secret support and `phase`
is a nonnegative exact rounded allowance. Full-carry transduction additionally
requires `H + 1 < m`. The lookup requires this entire window to be strictly
smaller than the clock degree `N`.

These are arithmetic consequences of those checked hypotheses. They do not
prove lookup correctness, a source noise/support certificate, or cryptographic
security, and do not exclude other native refresh constructions.
-/

namespace KElimination.PublicRefreshGeometry

/-- The complete-carry chart consumes strictly more than quadratic clock
degree in its source-support allowance, even with zero phase uncertainty. -/
theorem complete_chart_clock_lower_bound (H m N phase : Nat)
    (hcomplete : H + 1 < m)
    (hwindow : phase + m * (H + 1) < N) :
    (H + 1) * (H + 1) < N := by
  have hpositive : 0 < H + 1 := by omega
  have hproduct := Nat.mul_lt_mul_of_pos_right hcomplete hpositive
  omega

/-- Since coordinates are integers, the actual minimal window contribution
is `(H+2)*(H+1)`. An odd-coordinate restriction can only raise it further. -/
theorem complete_chart_integer_lower_bound (H m N phase : Nat)
    (hcomplete : H + 1 < m)
    (hwindow : phase + m * (H + 1) < N) :
    (H + 2) * (H + 1) < N := by
  have hcoordinate : H + 2 ≤ m := by omega
  have hproduct := Nat.mul_le_mul_right (H + 1) hcoordinate
  omega

/-- A degree cap at or below the quadratic lower bound cannot satisfy this
complete-carry chart, regardless of the nonnegative phase uncertainty. -/
theorem complete_chart_degree_cap_refuses (H m N phase cap : Nat)
    (hcomplete : H + 1 < m)
    (hwindow : phase + m * (H + 1) < N)
    (hcap : N ≤ cap)
    (hsmall : cap ≤ (H + 1) * (H + 1)) : False := by
  have hlower := complete_chart_clock_lower_bound H m N phase hcomplete hwindow
  omega

/-- At dense support 8192, no complete single chart fits the implementation's
maximum clock degree `2^20`, even if its coordinate limit were removed. -/
theorem dense_8192_complete_chart_refuses (m N phase : Nat)
    (hcomplete : 8192 + 1 < m)
    (hwindow : phase + m * (8192 + 1) < N)
    (hcap : N ≤ 2 ^ 20) : False := by
  exact complete_chart_degree_cap_refuses 8192 m N phase (2 ^ 20)
    hcomplete hwindow hcap (by decide)

/-- The degree required by the integer-coordinate inequalities alone is
strictly above 67,133,442 at support 8192. -/
theorem dense_8192_clock_degree_requirement (m N phase : Nat)
    (hcomplete : 8192 + 1 < m)
    (hwindow : phase + m * (8192 + 1) < N) :
    67_133_442 < N := by
  have hlower := complete_chart_integer_lower_bound 8192 m N phase hcomplete hwindow
  exact hlower

/-- The existing sparse geometry fixture is arithmetically feasible when
its rounded phase allowance is 4096. This proves the window inequalities
only; obtaining an admitted support-96 source is a separate obligation. -/
theorem sparse_96_coordinate_99_window :
    96 + 1 < 99 ∧
    4096 + 99 * (96 + 1) = 13_699 ∧
    4096 + 99 * (96 + 1) < 16_384 := by
  decide

end KElimination.PublicRefreshGeometry
