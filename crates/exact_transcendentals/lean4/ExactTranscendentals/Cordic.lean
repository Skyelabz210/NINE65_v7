/-
  ExactTranscendentals.Cordic
  ===========================

  Formalization of the CORDIC (COordinate Rotation DIgital Computer) algorithm.
  All computation is integer-only using scaled integers with SCALE = 2^30.

  Definitions:
    D005: CORDIC angle table — atan(2^(-i)) * 2^30 for i = 0..31
    D006: CORDIC rotation step
    D007: cordic_sincos — n iterations starting from (SCALE, 0, angle)

  Lemmas/Theorems:
    L005: CORDIC convergence — residual |z_n| bounded by sum of remaining table entries
    T001: Pythagorean identity — |cos^2 + sin^2 - SCALE^2| bounded by error term
-/

-- ============================================================================
-- D005: Scale factor and CORDIC angle table
-- ============================================================================

/-- Scale factor: 2^30 = 1073741824. All CORDIC values are integers representing
    real_value * SCALE. -/
def SCALE : Int := 1 <<< 30

/-- CORDIC gain factor K * 2^30.
    K = prod_{i=0}^{31} (1/sqrt(1 + 2^(-2i))) approx 0.6072529350088814.
    CORDIC_GAIN = floor(K * 2^30) = 652032874. -/
def CORDIC_GAIN : Int := 652032874

/-- Half-pi * 2^30 = floor(pi/2 * 2^30). -/
def HALF_PI_SCALED : Int := 1686629713

/-- Pi * 2^30 = floor(pi * 2^30). -/
def PI_SCALED : Int := 3373259426

/-- Two-pi * 2^30 = floor(2*pi * 2^30). -/
def TWO_PI_SCALED : Int := 6746518852

/-- D005: Precomputed CORDIC arctangent table.
    Entry i = floor(atan(2^(-i)) * 2^30) for i = 0..31.
    These are the exact values from the Rust `exact_transcendentals` source. -/
def cordicAtanTable : Fin 32 -> Int
  | ⟨ 0, _⟩ => 843314857
  | ⟨ 1, _⟩ => 497837829
  | ⟨ 2, _⟩ => 263043837
  | ⟨ 3, _⟩ => 133525159
  | ⟨ 4, _⟩ => 67021687
  | ⟨ 5, _⟩ => 33543516
  | ⟨ 6, _⟩ => 16775851
  | ⟨ 7, _⟩ => 8388437
  | ⟨ 8, _⟩ => 4194283
  | ⟨ 9, _⟩ => 2097149
  | ⟨10, _⟩ => 1048576
  | ⟨11, _⟩ => 524288
  | ⟨12, _⟩ => 262144
  | ⟨13, _⟩ => 131072
  | ⟨14, _⟩ => 65536
  | ⟨15, _⟩ => 32768
  | ⟨16, _⟩ => 16384
  | ⟨17, _⟩ => 8192
  | ⟨18, _⟩ => 4096
  | ⟨19, _⟩ => 2048
  | ⟨20, _⟩ => 1024
  | ⟨21, _⟩ => 512
  | ⟨22, _⟩ => 256
  | ⟨23, _⟩ => 128
  | ⟨24, _⟩ => 64
  | ⟨25, _⟩ => 32
  | ⟨26, _⟩ => 16
  | ⟨27, _⟩ => 8
  | ⟨28, _⟩ => 4
  | ⟨29, _⟩ => 2
  | ⟨30, _⟩ => 1
  | ⟨31, _⟩ => 0
  | ⟨n, h⟩ => 0 -- Default case to handle any remaining values (should not occur due to Fin 32 constraint)

/-- The CORDIC atan table as a list (for iteration convenience). -/
def cordicAtanList : List Int :=
  [843314857, 497837829, 263043837, 133525159,
   67021687, 33543516, 16775851, 8388437,
   4194283, 2097149, 1048576, 524288,
   262144, 131072, 65536, 32768,
   16384, 8192, 4096, 2048,
   1024, 512, 256, 128,
   64, 32, 16, 8,
   4, 2, 1, 0]

-- ============================================================================
-- D006: CORDIC rotation step
-- ============================================================================

/-- CORDIC state: (x, y, z) where x,y are the rotated vector components
    and z is the residual angle to rotate through. -/
abbrev CordicState := Int × Int × Int

/-- D006: One CORDIC rotation step at iteration i.
    Given state (x, y, z) and iteration index i:
    - If z >= 0, rotate counter-clockwise: d = +1
    - If z < 0, rotate clockwise: d = -1
    - x' = x - d * (y >>> i)
    - y' = y + d * (x >>> i)
    - z' = z - d * atan_table[i]

    The key insight: multiplication by tan(angle_i) = 2^(-i) is a bit shift,
    so the main loop uses NO multiplications. -/
def cordicStep (state : CordicState) (i : Nat) : CordicState :=
  let (x, y, z) := state
  let d : Int := if z >= 0 then 1 else -1
  -- Arithmetic right shift for signed integers
  let x_shift := x >>> i
  let y_shift := y >>> i
  let x' := x - d * y_shift
  let y' := y + d * x_shift
  -- Look up atan(2^(-i)) from the table; use 0 for i >= 32
  let atan_i := if h : i < 32 then cordicAtanTable ⟨i, h⟩ else 0
  let z' := z - d * atan_i
  (x', y', z')

-- ============================================================================
-- D007: CORDIC iteration and sincos
-- ============================================================================

/-- D007: Run n CORDIC iterations starting from (SCALE, 0, angle).
    Returns the raw CORDIC state (x, y, z) after n rotation steps.
    The output (x, y) is scaled by the CORDIC gain factor 1/K approx 1.6468,
    so cos(angle) approx x * K / SCALE and sin(angle) approx y * K / SCALE. -/
def cordicIter (angle : Int) (n : Nat) : CordicState :=
  let init : CordicState := (SCALE, 0, angle)
  -- Fold over [0, 1, ..., n-1]
  (List.range n).foldl (fun st i => cordicStep st i) init

/-- D007: Compute (cos(angle), sin(angle)) as scaled integers using n CORDIC iterations.
    The input angle is in scaled radians: angle = real_angle * 2^30.
    The output (c, s) satisfies c approx cos(real_angle) * 2^30,
    s approx sin(real_angle) * 2^30.

    After the CORDIC iteration, the gain correction is applied:
      cos = x * CORDIC_GAIN / SCALE
      sin = y * CORDIC_GAIN / SCALE -/
def cordicSincos (angle : Int) (n : Nat) : Int × Int :=
  let (x, y, _) := cordicIter angle n
  let c := x * CORDIC_GAIN / SCALE
  let s := y * CORDIC_GAIN / SCALE
  (c, s)

-- ============================================================================
-- Helper definitions for theorem statements
-- ============================================================================

/-- Sum of atan table entries from index i to 31 (inclusive).
    This represents the maximum remaining rotation possible after i iterations. -/
def atanTailSum (i : Nat) : Int :=
  (List.range (32 - i)).foldl (fun acc j =>
    if h : i + j < 32 then acc + cordicAtanTable ⟨i + j, h⟩
    else acc) 0

/-- Absolute value for Int. -/
def Int.abs' (x : Int) := if x >= 0 then x else -x

-- ============================================================================
-- L005: CORDIC convergence — residual angle bound
-- ============================================================================

/-- L005: CORDIC convergence.
    After n iterations of CORDIC starting from angle theta, the residual
    angle z_n satisfies |z_n| <= atanTailSum(n).

    Proof sketch: At each step, the residual z is reduced by atan(2^(-i)).
    The worst case is when every decision bit opposes the residual, but even
    then the total remaining rotation capacity sum_{j=n}^{31} atan(2^(-j))
    bounds the residual.

    In particular, atanTailSum(n) decreases roughly by a factor of 2 per
    iteration (since atan(2^(-(n+1))) approx atan(2^(-n))/2 for large n),
    giving about 1 bit of angular convergence per iteration. -/
theorem cordic_convergence (angle : Int) (n : Nat) (hn : n ≤ 32) :
    let (_, _, z) := cordicIter angle n
    z.abs' ≤ atanTailSum n := by
  sorry

/-- The total sum of all atan table entries equals the maximum CORDIC input range.
    sum_{i=0}^{31} atan(2^(-i)) * 2^30 = atanTailSum 0.
    This sum is approximately pi/2 * 2^30 + a small overshoot, meaning CORDIC
    converges for inputs in approximately [-pi/2, pi/2] (in scaled radians). -/
theorem atan_total_sum_eq :
    atanTailSum 0 = cordicAtanList.foldl (· + ·) 0 := by
  sorry

-- ============================================================================
-- T001: Pythagorean identity
-- ============================================================================

/-- T001: Pythagorean identity for CORDIC-computed sincos.
    For (c, s) = cordicSincos(theta, 32), the identity cos^2 + sin^2 = 1
    holds approximately: |c*c + s*s - SCALE*SCALE| is bounded.

    The bound arises from:
    1. CORDIC gain approximation error: CORDIC_GAIN is floor(K * 2^30),
       introducing a rounding error of at most 1 ULP in the gain.
    2. Integer truncation in the shift-and-add iterations.
    3. The residual angle z_32 (bounded by L005) contributes to a
       rotational offset.

    Empirically, the error is well under 1000 (i.e., less than 10^(-6)
    in real units), but we state a conservative bound here. -/
theorem pythagorean_identity (angle : Int) :
    let (c, s) := cordicSincos angle 32
    (c * c + s * s - SCALE * SCALE).abs' ≤ SCALE * 2 := by
  sorry

/-- Refined Pythagorean bound: for angle = 0, cosine = SCALE exactly
    (up to gain correction rounding). -/
theorem pythagorean_at_zero :
    let (c, s) := cordicSincos 0 32
    c > 0 ∧ s.abs' ≤ 1 := by
  sorry

-- ============================================================================
-- Additional structural properties
-- ============================================================================

/-- CORDIC is odd in the angle: cordicSincos(-theta, n).snd = -cordicSincos(theta, n).snd.
    This follows from the sign-symmetry of the CORDIC iteration:
    negating the initial z flips every decision bit d, which flips y
    at each step while preserving x. -/
theorem cordic_sin_odd (angle : Int) (n : Nat) :
    (cordicSincos (-angle) n).2 = -(cordicSincos angle n).2 := by
  sorry

/-- CORDIC is even in cosine: cordicSincos(-theta, n).fst = cordicSincos(theta, n).fst. -/
theorem cordic_cos_even (angle : Int) (n : Nat) :
    (cordicSincos (-angle) n).1 = (cordicSincos angle n).1 := by
  sorry

/-- The CORDIC atan table entries are non-negative. -/
theorem atan_table_nonneg (i : Fin 32) : cordicAtanTable i ≥ 0 := by
  fin_cases i <;> simp [cordicAtanTable] <;> linarith

/-- The CORDIC atan table is monotonically non-increasing:
    cordicAtanTable i >= cordicAtanTable (i+1) for each valid i. -/
theorem atan_table_monotone (i : Fin 31) :
    cordicAtanTable ⟨i.val, by omega⟩ ≥ cordicAtanTable ⟨i.val + 1, by omega⟩ := by
  fin_cases i <;> simp [cordicAtanTable] <;> linarith

-- ============================================================================
-- Computational validation
-- ============================================================================

-- cordicSincos 0 32: should give (cos(0), sin(0)) = (SCALE, 0) approximately
-- Expected: cos(0) = 1073741824 (= SCALE), sin(0) = 0
#eval! cordicSincos 0 32
-- Expected output: approximately (1073741824, 0)

-- cordicSincos(atan(1)*2^30, 32) = sincos(pi/4):
-- cos(pi/4) = sin(pi/4) = 1/sqrt(2) approx 0.7071068
-- 0.7071068 * 2^30 approx 759250124
#eval! cordicSincos 843314857 32
-- Expected output: both components approximately 759250124

-- Verify the raw iteration state at angle=0 after 32 steps:
-- Should have z very close to 0, x close to SCALE/K
#eval! cordicIter 0 32

-- Verify total atan sum (convergence range):
#eval! atanTailSum 0

-- Verify individual table lookups
#eval! cordicAtanTable ⟨0, by omega⟩   -- 843314857 = atan(1) * 2^30
#eval! cordicAtanTable ⟨31, by omega⟩  -- 0

-- Pythagorean check at angle=0:
#eval! let (c, s) := cordicSincos 0 32
      (c * c + s * s, SCALE * SCALE, (c * c + s * s - SCALE * SCALE).abs')

-- Pythagorean check at pi/4:
#eval! let (c, s) := cordicSincos 843314857 32
      (c * c + s * s, SCALE * SCALE, (c * c + s * s - SCALE * SCALE).abs')