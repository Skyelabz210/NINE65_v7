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
  | .wasmClient, _ => True
  | .experimental, _ => True
  | _, _ => False

@[simp] theorem publicEvaluator_no_decrypt :
    ¬ evaluatorGrants .publicEvaluator .decrypt := by
  simp [evaluatorGrants]

@[simp] theorem publicEvaluatorKsk_no_decrypt :
    ¬ evaluatorGrants .publicEvaluatorKsk .decrypt := by
  simp [evaluatorGrants]

@[simp] theorem publicEvaluator_can_evaluate :
    evaluatorGrants .publicEvaluator .evaluate := by
  simp [evaluatorGrants]

structure ServicePolicy where
  enableDecrypt : Bool
  tokenConfigured : Bool
  deriving DecidableEq, Repr

instance : Inhabited ServicePolicy := ⟨{ enableDecrypt := false, tokenConfigured := false }⟩

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

/-- Application-domain bounds. All fields are exact nonnegative integers. -/
def StructuredSignal.Valid (s : StructuredSignal) : Prop :=
  s.topic < 256 ∧
  s.friction < 64 ∧
  s.severity < 8 ∧
  s.sentiment < 8 ∧
  s.productArea < 1024 ∧
  s.followupClass < 64 ∧
  s.consent < 2 ∧
  s.confidence < 1024

/-- Fixed slot encoding contains no raw-text field. -/
def StructuredSignal.slots (s : StructuredSignal) : Fin 8 → Nat
  | ⟨0, _⟩ => s.topic
  | ⟨1, _⟩ => s.friction
  | ⟨2, _⟩ => s.severity
  | ⟨3, _⟩ => s.sentiment
  | ⟨4, _⟩ => s.productArea
  | ⟨5, _⟩ => s.followupClass
  | ⟨6, _⟩ => s.consent
  | ⟨7, _⟩ => s.confidence

@[simp] theorem valid_consent_is_bit {s : StructuredSignal} (h : s.Valid) : s.consent < 2 := by
  exact h.2.2.2.2.2.2.1

/-- Lane projection is direct reduction, not reconstruction. -/
def laneResidue (value modulus : Nat) : Nat := value % modulus

 theorem laneResidue_lt {value modulus : Nat} (hmod : 0 < modulus) :
    laneResidue value modulus < modulus := by
  exact Nat.mod_lt value hmod

 theorem lane_add_hom (a b modulus : Nat) :
    laneResidue (a + b) modulus =
      laneResidue (laneResidue a modulus + laneResidue b modulus) modulus := by
  simp [laneResidue, Nat.add_mod]

 theorem lane_mul_hom (a b modulus : Nat) :
    laneResidue (a * b) modulus =
      laneResidue (laneResidue a modulus * laneResidue b modulus) modulus := by
  simp [laneResidue, Nat.mul_mod]

end KElimination.AppBoundary
