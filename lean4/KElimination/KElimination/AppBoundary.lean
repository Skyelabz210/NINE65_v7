import Mathlib

namespace KElimination.AppBoundary

inductive DeploymentMode where
  | publicEvaluator
  | publicEvaluatorKsk
  | symmetricProtected
  | serviceOperator
  | wasmClient
  | experimental
  deriving DecidableEq, Repr

inductive Capability where
  | encrypt
  | evaluate
  | decrypt
  | bootstrap
  | boundaryProject
  deriving DecidableEq, Repr

/-- Capabilities held by the evaluator process itself. Client-held capabilities are not
included in the public evaluator rows. -/
def evaluatorGrants : DeploymentMode → Capability → Prop
  | .publicEvaluator, .evaluate => True
  | .publicEvaluator, .bootstrap => True
  | .publicEvaluatorKsk, .evaluate => True
  | .publicEvaluatorKsk, .bootstrap => True
  | .symmetricProtected, _ => True
  | .serviceOperator, .encrypt => True
  | .serviceOperator, .evaluate => True
  | .serviceOperator, .boundaryProject => True
  | .wasmClient, _ => True
  | .experimental, _ => True
  | _, _ => False

@[simp] theorem publicEvaluator_no_decrypt :
    ¬ evaluatorGrants .publicEvaluator .decrypt := by
  simp [evaluatorGrants]

@[simp] theorem publicEvaluatorKsk_no_decrypt :
    ¬ evaluatorGrants .publicEvaluatorKsk .decrypt := by
  simp [evaluatorGrants]

@[simp] theorem publicEvaluator_no_boundary_projection :
    ¬ evaluatorGrants .publicEvaluator .boundaryProject := by
  simp [evaluatorGrants]

@[simp] theorem publicEvaluatorKsk_no_boundary_projection :
    ¬ evaluatorGrants .publicEvaluatorKsk .boundaryProject := by
  simp [evaluatorGrants]

@[simp] theorem publicEvaluator_can_evaluate :
    evaluatorGrants .publicEvaluator .evaluate := by
  simp [evaluatorGrants]

structure ServicePolicy where
  enableDecrypt : Bool
  tokenConfigured : Bool
  deriving DecidableEq, Repr

instance : Inhabited ServicePolicy :=
  ⟨{ enableDecrypt := false, tokenConfigured := false }⟩

/-- Decryption is granted only when the operator both enables it and configures a token. -/
def serviceDecryptGranted (policy : ServicePolicy) : Prop :=
  policy.enableDecrypt = true ∧ policy.tokenConfigured = true

@[simp] theorem default_service_no_decrypt :
    ¬ serviceDecryptGranted default := by
  simp [serviceDecryptGranted, default]

theorem service_decrypt_requires_enablement (policy : ServicePolicy)
    (h : serviceDecryptGranted policy) : policy.enableDecrypt = true := by
  exact h.1

theorem service_decrypt_requires_token (policy : ServicePolicy)
    (h : serviceDecryptGranted policy) : policy.tokenConfigured = true := by
  exact h.2

structure StructuredSignal where
  topic : Nat
  friction : Nat
  severity : Nat
  sentiment : Nat
  productArea : Nat
  followupClass : Nat
  consent : Nat
  confidence : Nat
  deriving DecidableEq, Repr

/-- Exact application-domain bounds matching `private-feedback-core`. -/
def StructuredSignal.Valid (s : StructuredSignal) : Prop :=
  s.topic < 256 ∧
  s.friction < 8 ∧
  s.severity < 8 ∧
  s.sentiment < 6 ∧
  s.productArea < 1024 ∧
  s.followupClass < 7 ∧
  s.consent < 2 ∧
  s.confidence < 1001

/-- Fixed slot encoding contains no raw-text field. -/
def StructuredSignal.slots (s : StructuredSignal) (index : Fin 8) : Nat :=
  match index.val with
  | 0 => s.topic
  | 1 => s.friction
  | 2 => s.severity
  | 3 => s.sentiment
  | 4 => s.productArea
  | 5 => s.followupClass
  | 6 => s.consent
  | _ => s.confidence

@[simp] theorem valid_consent_is_bit {s : StructuredSignal} (h : s.Valid) :
    s.consent < 2 := by
  exact h.2.2.2.2.2.2.1

/-- Lane projection is direct reduction, not reconstruction. -/
def laneResidue (value modulus : Nat) : Nat := value % modulus

theorem laneResidue_lt {value modulus : Nat} (hmod : 0 < modulus) :
    laneResidue value modulus < modulus := by
  exact Nat.mod_lt value hmod

theorem lane_add_hom (a b modulus : Nat) :
    laneResidue (a + b) modulus =
      laneResidue (laneResidue a modulus + laneResidue b modulus) modulus := by
  simpa [laneResidue] using Nat.add_mod a b modulus

theorem lane_mul_hom (a b modulus : Nat) :
    laneResidue (a * b) modulus =
      laneResidue (laneResidue a modulus * laneResidue b modulus) modulus := by
  simpa [laneResidue] using Nat.mul_mod a b modulus

inductive DivisionRoute where
  | kElimination
  | fusedPiggyback
  | reject
  deriving DecidableEq, Repr

/-- The application path enables K-Elimination only for coprime divisors.
Shared-factor division remains rejected until the production FPD adapter is enabled. -/
def chooseDivisionRoute (divisor basisProduct : Nat) : DivisionRoute :=
  if Nat.Coprime divisor basisProduct then .kElimination else .reject

@[simp] theorem coprime_divisor_routes_to_kElimination
    {divisor basisProduct : Nat} (h : Nat.Coprime divisor basisProduct) :
    chooseDivisionRoute divisor basisProduct = .kElimination := by
  simp [chooseDivisionRoute, h]

@[simp] theorem shared_factor_divisor_is_rejected
    {divisor basisProduct : Nat} (h : ¬ Nat.Coprime divisor basisProduct) :
    chooseDivisionRoute divisor basisProduct = .reject := by
  simp [chooseDivisionRoute, h]

structure CipherShape where
  degree : Nat
  mainLimbs : Nat
  anchorLimbs : Nat
  level : Nat
  deriving DecidableEq, Repr

def CipherShape.Valid
    (shape : CipherShape)
    (expectedDegree expectedMain expectedAnchor : Nat) : Prop :=
  shape.degree = expectedDegree ∧
  shape.mainLimbs = expectedMain ∧
  shape.anchorLimbs = expectedAnchor ∧
  shape.level ≤ shape.mainLimbs

theorem valid_shape_has_expected_degree
    {shape : CipherShape} {expectedDegree expectedMain expectedAnchor : Nat}
    (h : shape.Valid expectedDegree expectedMain expectedAnchor) :
    shape.degree = expectedDegree := by
  exact h.1

theorem valid_shape_level_is_live
    {shape : CipherShape} {expectedDegree expectedMain expectedAnchor : Nat}
    (h : shape.Valid expectedDegree expectedMain expectedAnchor) :
    shape.level ≤ shape.mainLimbs := by
  exact h.2.2.2

structure RefreshEvidence where
  ciphertextTransition : Bool
  budgetRestored : Bool
  deriving DecidableEq, Repr

def RefreshEvidence.IsBootstrapped (evidence : RefreshEvidence) : Prop :=
  evidence.ciphertextTransition = true ∧ evidence.budgetRestored = true

@[simp] theorem counter_reset_alone_is_not_bootstrap :
    ¬ RefreshEvidence.IsBootstrapped
      { ciphertextTransition := false, budgetRestored := true } := by
  simp [RefreshEvidence.IsBootstrapped]

@[simp] theorem ciphertext_transition_without_budget_is_not_bootstrap :
    ¬ RefreshEvidence.IsBootstrapped
      { ciphertextTransition := true, budgetRestored := false } := by
  simp [RefreshEvidence.IsBootstrapped]

end KElimination.AppBoundary
