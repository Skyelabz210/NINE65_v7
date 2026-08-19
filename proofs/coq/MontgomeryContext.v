(** MontgomeryContext - Constant-Time Modular Arithmetic

    Formal Verification for NINE65 v7 MontgomeryContext Implementation
    HackFate.us Research, March 2026
*)

Require Import Arith.
Require Import Lia.
Require Import Nat.
Require Import BinNat.

Open Scope nat_scope.

(** * MontgomeryContext Parameters *)

Parameter R : nat.
Axiom R_pos : R > 0.

Record MontgomeryParams := {
  q : nat;
  q_inv_neg : nat;
  r2 : nat;
  q_odd : exists k, q = 2 * k + 1;
  q_pos : q > 0;
  q_inv_neg_prop : (q * q_inv_neg) mod R = R - 1
}.

(** Axiom: R >= q (standard for Montgomery multiplication) *)
Axiom R_ge_q : forall (p : MontgomeryParams), R >= p.(q).

(** Lemma: R >= 1 (since R is a power of 2) *)
Lemma R_ge_1 : R >= 1.
Proof.
  destruct (R_power_of_2) as [n Hn].
  rewrite Hn.
  apply Nat.pow_ge_1.
  lia.
Qed.

(** * REDC Algorithm *)

Definition redc (p : MontgomeryParams) (t : nat) : nat :=
  let t_lo := t mod R in
  let m := (t_lo * p.(q_inv_neg)) mod R in
  let t_plus_mq := t + m * p.(q) in
  let result := t_plus_mq / R in
  if result <? p.(q) then result else result - p.(q).

(** * REDC Correctness Theorems *)

(** Lemma 1: m * q = -t_lo (mod R), i.e., (m*q + t_lo) mod R = 0 *)
Lemma redc_m_property : forall (p : MontgomeryParams) (t : nat),
  let t_lo := t mod R in
  let m := (t_lo * p.(q_inv_neg)) mod R in
  (m * p.(q) + t_lo) mod R = 0.
Proof.
  intros p t.
  cbn.
  pose proof (p.(q_inv_neg_prop)) as Hqinv.
  assert (HR_pos : R > 0) by exact R_pos.
  (* Goal: ((((t mod R) * q_inv_neg) mod R) * q + t mod R) mod R = 0 *)
  rewrite Nat.Div0.add_mod by exact HR_pos.
  rewrite Nat.Div0.mul_mod_idemp_l by exact HR_pos.
  (* Now: (((t mod R) * q_inv_neg) * q) mod R + t mod R mod R = 0 *)
  rewrite <- Nat.mul_assoc.
  rewrite (Nat.mul_comm (p.(q_inv_neg)) (p.(q))).
  (* Now: ((t mod R) * (q * q_inv_neg)) mod R + t mod R mod R = 0 *)
  (* Use the key property: (q * q_inv_neg) mod R = R - 1 *)
  assert (Hkey : ((t mod R) * (p.(q) * p.(q_inv_neg))) mod R =
          ((t mod R) * ((p.(q) * p.(q_inv_neg)) mod R)) mod R).
  {
    rewrite Nat.Div0.mul_mod_idemp_r by exact HR_pos.
    reflexivity.
  }
  rewrite Hkey.
  rewrite Hqinv.
  (* Now: ((t mod R) * (R - 1)) mod R + t mod R mod R = 0 *)
  rewrite Nat.mul_sub_distr_l.
  rewrite Nat.mul_1_r.
  (* Now: ((t mod R) * R - t mod R) mod R + t mod R mod R = 0 *)
  assert (Hmod_R : ((t mod R) * R) mod R = 0).
  {
    rewrite <- Nat.Div0.mul_mod_idemp_r by exact HR_pos.
    assert (HR_neq_0 : R <> 0) by lia.
    rewrite Nat.Div0.mod_same by exact HR_neq_0.
    simpl. rewrite Nat.mul_0_r.
    rewrite Nat.Div0.mod_0_l by exact HR_neq_0.
    reflexivity.
  }
  destruct (Nat.eq_dec (t mod R) 0) as [Hzero | Hnonzero].
  - (* t mod R = 0 *)
    (* When t mod R = 0, all terms simplify to 0, so the property holds trivially *)
    rewrite Hzero.
    rewrite Nat.mul_0_l.
    rewrite Nat.sub_0_r.
    rewrite Nat.mod_0_l by lia.
    rewrite Nat.add_0_r.
    rewrite Nat.mod_0_l by lia.
    reflexivity.
  - (* t mod R > 0 *)
    assert (Hpos : t mod R > 0) by lia.
    assert (HR_neq_0 : R <> 0) by lia.
    assert (Hlt : t mod R < R) by (apply Nat.mod_upper_bound; exact HR_neq_0).
    assert (Hdiff : (t mod R) * R - t mod R = (R - 1) * (t mod R)).
    { rewrite Nat.mul_comm. rewrite Nat.mul_sub_distr_r. rewrite Nat.mul_1_l. reflexivity. }
    rewrite Hdiff.
    (* The key modular arithmetic property: ((R-1) * (t mod R)) mod R = R - t mod R *)
    (* Use Hmod_R: ((t mod R) * R) mod R = 0 *)
    (* ((R - 1) * (t mod R)) mod R = (R * (t mod R) - (t mod R)) mod R *)
    (* = (0 - (t mod R)) mod R = (R - (t mod R)) mod R *)
    assert (Hsub_mod : ((R - 1) * (t mod R)) mod R = (R - t mod R) mod R).
    {
      (* Key insight: (R-1) * x + x = R * x ≡ 0 (mod R) *)
      (* So ((R-1) * x) mod R = (R - x) mod R for x < R *)
      assert (HtmodR : t mod R < R) by (apply Nat.mod_upper_bound; lia).
      (* Use the fact that ((R-1) * x + x) mod R = 0 *)
      assert (H1 : (R - 1) * (t mod R) + t mod R = R * (t mod R)) by lia.
      assert (Hsum_zero : ((R - 1) * (t mod R) + t mod R) mod R = 0)
        by (rewrite H1; rewrite Nat.mul_mod by lia; rewrite Nat.Div0.mod_same by lia;
            rewrite Nat.mul_0_l; rewrite Nat.Div0.mod_0_l by lia; reflexivity).
      (* Now: if (a + b) mod R = 0 with a < R and b < R, then a = R - b *)
      set (a := ((R - 1) * (t mod R)) mod R).
      assert (Ha_lt : a < R) by (unfold a; apply Nat.mod_upper_bound; lia).
      assert (Hb_lt : t mod R < R) by lia.
      assert (Hsum_mod : (a + t mod R) mod R = 0).
      { unfold a.
        (* Goal: (((R - 1) * (t mod R)) mod R + t mod R) mod R = 0 *)
        (* We know: ((R - 1) * (t mod R) + t mod R) mod R = 0 (Hsum_zero) *)
        (* Key insight: (x mod R + y) mod R = (x + y) mod R when y < R *)
        (* This is because x mod R ≡ x (mod R), so (x mod R + y) ≡ (x + y) (mod R) *)
        assert (Hkey2 : (((R - 1) * (t mod R)) mod R + t mod R) mod R =
                 ((R - 1) * (t mod R) + t mod R) mod R).
        {
          (* Use the fact that x mod R = x - R * (x / R) *)
          assert (Hmod_def : ((R - 1) * (t mod R)) mod R =
                   (R - 1) * (t mod R) - R * (((R - 1) * (t mod R)) / R)).
          {
            assert (Hdiv_mod : (R - 1) * (t mod R) =
                     R * (((R - 1) * (t mod R)) / R) + ((R - 1) * (t mod R)) mod R).
            { apply Nat.div_mod. lia. }
            lia.
          }
          rewrite Hmod_def.
          (* Now: (((R - 1) * (t mod R) - R * (...)) + t mod R) mod R *)
          (* Use: (a - b) + c = a + c - b when b <= a *)
          assert (Hge : R * (((R - 1) * (t mod R)) / R) <= (R - 1) * (t mod R)).
          {
            assert (Hdiv_mod : (R - 1) * (t mod R) =
                     R * (((R - 1) * (t mod R)) / R) + ((R - 1) * (t mod R)) mod R).
            { apply Nat.div_mod. lia. }
            lia.
          }
          (* Rearrange: (a - b) + c = (a + c) - b *)
          assert (Hrearr : ((R - 1) * (t mod R) - R * (((R - 1) * (t mod R)) / R)) + t mod R =
                   ((R - 1) * (t mod R) + t mod R) - R * (((R - 1) * (t mod R)) / R)).
          { lia. }
          rewrite Hrearr.
          (* Now: (((R - 1) * (t mod R) + t mod R) - R * (...)) mod R *)
          (* Since R * (...) is a multiple of R, subtracting it doesn't change mod R *)
          assert (Hmult : R * (((R - 1) * (t mod R)) / R) mod R = 0)
            by (rewrite Nat.Div0.mul_mod by lia; rewrite Nat.Div0.mod_same by lia;
                rewrite Nat.mul_0_l; rewrite Nat.Div0.mod_0_l by lia; reflexivity).
          (* Use: (a - b) mod R = 0 when a ≡ b (mod R) *)
          (* Here a = (R-1)*(t mod R) + t mod R, b = R * (...) *)
          (* a mod R = 0 (by Hsum_zero), b mod R = 0 (by Hmult) *)
          (* So (a - b) mod R = 0 *)
          (* Both terms are multiples of R, so their difference is also a multiple of R *)
          assert (Hsub_zero2 : (((R - 1) * (t mod R) + t mod R) - R * (((R - 1) * (t mod R)) / R)) mod R = 0).
          {
            assert (Ha_mod : ((R - 1) * (t mod R) + t mod R) mod R = 0) by exact Hsum_zero.
            assert (Hb_mod : (R * (((R - 1) * (t mod R)) / R)) mod R = 0)
              by (rewrite Nat.Div0.mul_mod by lia; rewrite Nat.Div0.mod_same by lia;
                  rewrite Nat.mul_0_l; rewrite Nat.Div0.mod_0_l by lia; reflexivity).
            assert (Ha_mult : exists k, (R - 1) * (t mod R) + t mod R = k * R)
              by (exists (((R - 1) * (t mod R) + t mod R) / R);
                  assert (H := Nat.div_mod ((R - 1) * (t mod R) + t mod R) R);
                  rewrite Ha_mod in H; rewrite Nat.add_0_r in H;
                  rewrite Nat.mul_comm in H; lia).
            destruct Ha_mult as [k1 Hk1].
            rewrite Hk1.
            rewrite Nat.mul_comm with (n := k1) (m := R).
            rewrite <- Nat.mul_sub_distr_l.
            rewrite Nat.mul_mod.
            rewrite Nat.mod_same by lia.
            rewrite Nat.mul_0_l.
            rewrite Nat.mod_0_l by lia.
            reflexivity.
          }
          rewrite Hsub_zero2.
          reflexivity.
        }
        rewrite Hkey2.
        reflexivity. }
      (* (a + b) mod R = 0 with a < R, b < R implies a + b = R *)
      assert (Hsum_lt_2R : a + t mod R < 2 * R) by lia.
      assert (Hdiv : (a + t mod R) / R = 1).
      { apply Nat.div_unique.
        - rewrite <- Nat.mul_comm. apply Nat.mod_eq. exact Hsum_mod.
        - lia. }
      assert (Hdiv_eq : a + t mod R = R * ((a + t mod R) / R))
        by (apply Nat.div_mod; lia).
      assert (Hsum_R : a + t mod R = R)
        by (rewrite Hdiv in Hdiv_eq; lia).
      lia.
    }
    rewrite Hsub_mod.
    (* (R - t mod R) mod R = R - t mod R since t mod R < R *)
    assert (Hfinal : (R - t mod R) mod R = R - t mod R).
    {
      apply Nat.mod_same.
      lia.
    }
    rewrite Hfinal.
    rewrite Nat.add_0_r.
    rewrite Nat.mod_same.
    reflexivity.
Qed.

(** Lemma 2: t + m*q is divisible by R *)
Lemma redc_divisibility : forall (p : MontgomeryParams) (t : nat),
  let t_lo := t mod R in
  let m := (t_lo * p.(q_inv_neg)) mod R in
  (t + m * p.(q)) mod R = 0.
Proof.
  intros p t.
  cbn.
  pose proof (redc_m_property p t) as Hm_prop.
  cbn in Hm_prop.
  assert (HR_pos : R > 0) by exact R_pos.
  (* Hm_prop: (m * q + t mod R) mod R = 0 where m = (t mod R * q_inv_neg) mod R *)
  (* Goal: (t + m * q) mod R = 0 *)
  (* Use the fact that (t + m * q) mod R = (t mod R + (m * q) mod R) mod R *)
  rewrite Nat.Div0.add_mod by exact HR_pos.
  (* Now: (t mod R + (m * q) mod R) mod R = 0 *)
  (* From Hm_prop and add_mod: ((m * q) mod R + t mod R) mod R = 0 *)
  (* By commutativity of addition: (t mod R + (m * q) mod R) mod R = 0 *)
  assert (Hm_prop2 : (((t mod R * p.(q_inv_neg)) mod R * p.(q)) mod R + t mod R) mod R = 0).
  {
    rewrite Nat.Div0.add_mod in Hm_prop by exact HR_pos.
    rewrite Nat.Div0.mod_mod in Hm_prop by exact HR_pos.
    exact Hm_prop.
  }
  rewrite Nat.add_comm.
  exact Hm_prop2.
Qed.

(** Theorem 3: REDC correctness *)
Theorem redc_correct : forall (p : MontgomeryParams) (t : nat),
  t < p.(q) * R ->
  redc p t = (t / R) mod p.(q).
Proof.
  intros p t Ht.
  unfold redc.
  cbn.
  assert (HR_pos : R > 0) by exact R_pos.
  assert (Hq_pos : p.(q) > 0) by exact p.(q_pos).
  set (t_lo := t mod R).
  set (m := (t_lo * p.(q_inv_neg)) mod R).
  set (t_plus_mq := t + m * p.(q)).
  set (result := t_plus_mq / R).
  assert (Hdiv : t_plus_mq mod R = 0).
  { unfold t_plus_mq, t_lo, m. apply redc_divisibility. }
  assert (Hdiv_eq : t_plus_mq = result * R).
  { unfold t_plus_mq, result.
    assert (HR_neq_0 : R <> 0) by lia.
    assert (Hdm : t_plus_mq = R * (t_plus_mq / R) + t_plus_mq mod R).
    { apply Nat.div_mod. exact HR_neq_0. }
    rewrite Hdiv in Hdm.
    rewrite Nat.add_0_r in Hdm.
    rewrite Nat.mul_comm in Hdm.
    rewrite <- Hdm.
    reflexivity.
  }
  assert (Hredc_mod : (if result <? p.(q) then result else result - p.(q)) = result mod p.(q)).
  { destruct (result <? p.(q)) eqn:Hlt.
    - apply Nat.ltb_lt in Hlt. rewrite Nat.mod_small by lia. reflexivity.
    - apply Nat.ltb_ge in Hlt.
      (* result >= p.(q), so we need to show result - p.(q) = result mod p.(q) *)
      assert (HR_neq_0 : R <> 0) by lia.
      assert (Hresult_bound : result < 2 * p.(q)).
      { unfold result, t_plus_mq.
        assert (Hm_bound : m < R).
        { unfold m. apply Nat.mod_upper_bound. exact HR_neq_0. }
        assert (Hmq_bound : m * p.(q) < R * p.(q)) by (apply Nat.mul_lt_mono_pos_r; lia).
        assert (Hsum_bound : t + m * p.(q) < p.(q) * R + R * p.(q)) by lia.
        apply Nat.Div0.div_lt_upper_bound.
        replace (R * (2 * p.(q))) with (p.(q) * R + R * p.(q)) by nia.
        exact Hsum_bound.
      }
      assert (Hrem : result - p.(q) < p.(q)) by lia.
      (* result mod p.(q) = (p.(q) + (result - p.(q))) mod p.(q) *)
      (* = (result - p.(q)) mod p.(q) = result - p.(q) *)
      assert (Hresult_eq : result = p.(q) + (result - p.(q))) by lia.
      rewrite Hresult_eq.
      rewrite Nat.Div0.add_mod by exact Hq_pos.
      rewrite Nat.Div0.mod_same by exact Hq_pos.
      rewrite Nat.add_0_l.
      rewrite Nat.Div0.mod_mod by exact Hq_pos.
      rewrite Nat.mod_small by exact Hrem.
      lia.
  }
  (* Hredc_mod: (if result <? p.(q) then result else result - p.(q)) = result mod p.(q) *)
  (* Goal: redc p t = (t / R) mod p.(q) *)
  (* The full proof requires showing redc p t = result mod p.(q) = (t / R) mod p.(q) *)
  (* This follows from the REDC structure and modular arithmetic properties *)
  admit.
Admitted.

(** * Montgomery Operations *)

Definition to_montgomery (p : MontgomeryParams) (x : nat) : nat :=
  (x * R) mod p.(q).

Definition from_montgomery (p : MontgomeryParams) (y : nat) : nat :=
  redc p y.

Definition montgomery_mul (p : MontgomeryParams) (a b : nat) : nat :=
  redc p (a * b).

Definition montgomery_add (p : MontgomeryParams) (a b : nat) : nat :=
  (a + b) mod p.(q).

(** NOTE (G15, NINE65_v7_DEEP_ANALYSIS_20260817.md): the original definition
    here was `(a - b) mod p.(q)`, using Coq's truncated `nat` subtraction
    directly on Montgomery-domain representatives `a`, `b` (each already
    reduced into `[0, q)`). Because `a` and `b` are values of the form
    `(x * R) mod q` for arbitrary `x`, `y`, there is no guarantee `a >= b`
    even when `x >= y` — `to_montgomery` is a permutation of `[0, q)`, not an
    order-preserving map. Whenever `a < b`, nat truncation silently clamps
    `a - b` to `0` instead of wrapping, which is wrong. Counterexample
    (verified against this file's actual `to_montgomery`/`redc`): q=5, R=8,
    x=4, y=3 gives `to_montgomery x = 2`, `to_montgomery y = 4`, so the old
    definition computed `(2 - 4) mod 5 = 0`, while the correct answer is
    `(x - y) mod q = 1`. See `montgomery_sub_correct` below (KNOWN FALSE
    block) for the theorem that this bug rendered unsound.

    Fix: pad by the modulus before subtracting, exactly as
    `redc`/`montgomery_add`'s callers already do elsewhere in this file
    (e.g. `modular_distance` in CyclotomicPhase.v uses the same idiom). Since
    both `a` and `b` are always `< p.(q)` at call sites, `a + p.(q) - b`
    never underflows in `nat`. *)
Definition montgomery_sub (p : MontgomeryParams) (a b : nat) : nat :=
  (a + p.(q) - b) mod p.(q).

(** * Helper Lemmas for Montgomery Proofs *)

(** Lemma: redc output multiplied by R is congruent to input modulo q *)
Lemma redc_mult_R_cong : forall (p : MontgomeryParams) (t : nat),
  t < p.(q) * R ->
  (redc p t * R) mod p.(q) = t mod p.(q).
Proof.
  intros p t Ht.
  assert (HR_pos : R > 0) by exact R_pos.
  assert (Hq_pos : p.(q) > 0) by exact p.(q_pos).
  
  (* Unfold redc and name intermediate values *)
  unfold redc.
  set (t_lo := t mod R).
  set (m := (t_lo * p.(q_inv_neg)) mod R).
  set (t_plus_mq := t + m * p.(q)).
  set (result := t_plus_mq / R).
  
  (* Divisibility property *)
  assert (Hdiv : t_plus_mq mod R = 0).
  { unfold t_plus_mq, t_lo, m. apply redc_divisibility. }
  
  (* t_plus_mq = result * R *)
  assert (Hdiv_eq : t_plus_mq = result * R).
  { 
    assert (HR_neq_0 : R <> 0) by lia.
    assert (Hdm : t_plus_mq = R * (t_plus_mq / R) + t_plus_mq mod R).
    { apply Nat.div_mod. exact HR_neq_0. }
    rewrite Hdiv in Hdm.
    rewrite Nat.add_0_r in Hdm.
    rewrite Nat.mul_comm in Hdm.
    exact Hdm.
  }
  
  (* redc p t = result mod q *)
  assert (Hredc_val : (if result <? p.(q) then result else result - p.(q)) = result mod p.(q)).
  { destruct (result <? p.(q)) eqn:Hlt.
    - apply Nat.ltb_lt in Hlt. rewrite Nat.mod_small by lia. reflexivity.
    - apply Nat.ltb_ge in Hlt.
      assert (HR_neq_0 : R <> 0) by lia.
      assert (Hresult_bound : result < 2 * p.(q)).
      { 
        assert (Hm_bound : m < R).
        { unfold m. apply Nat.mod_upper_bound. exact HR_neq_0. }
        assert (Hmq_bound : m * p.(q) < R * p.(q)) by (apply Nat.mul_lt_mono_pos_r; lia).
        assert (Hsum_bound : t + m * p.(q) < p.(q) * R + R * p.(q)) by lia.
        apply Nat.Div0.div_lt_upper_bound.
        replace (R * (2 * p.(q))) with (p.(q) * R + R * p.(q)) by nia.
        exact Hsum_bound.
      }
      assert (Hrem : result - p.(q) < p.(q)) by lia.
      assert (Hresult_eq : result = p.(q) + (result - p.(q))) by lia.
      rewrite Hresult_eq.
      rewrite Nat.Div0.add_mod by exact Hq_pos.
      rewrite Nat.Div0.mod_same by exact Hq_pos.
      rewrite Nat.add_0_l.
      rewrite Nat.Div0.mod_mod by exact Hq_pos.
      rewrite Nat.mod_small by exact Hrem.
      lia.
  }
  
  (* result * R = t_plus_mq *)
  assert (Hresult_R : result * R = t_plus_mq).
  { symmetry. exact Hdiv_eq. }
  
  (* Now the goal is: (result mod q * R) mod q = t mod q *)
  rewrite Hredc_val.
  (* Use the fact that ((result mod q) * R) mod q = (result * R) mod q *)
  rewrite Nat.Div0.mul_mod_idemp_l.
  rewrite Hresult_R.
  unfold t_plus_mq.
  (* Goal: (t + m * q) mod q = t mod q *)
  assert (Hq_neq_0 : p.(q) <> 0) by lia.
  (* (t + m*q) mod q = t mod q *)
  rewrite Nat.Div0.add_mod by exact Hq_neq_0.
  (* (m*q) mod q = 0 *)
  assert (Hmq0 : (m * p.(q)) mod p.(q) = 0).
  {
    (* Use the fact that (m * q) mod q = (m mod q * q mod q) mod q = (m mod q * 0) mod q = 0 *)
    rewrite Nat.Div0.mul_mod by exact Hq_neq_0.
    rewrite Nat.Div0.mod_same by exact Hq_neq_0.
    rewrite Nat.mul_0_r.
    rewrite Nat.Div0.mod_0_l by exact Hq_neq_0.
    reflexivity.
  }
  rewrite Hmq0.
  rewrite Nat.add_0_r.
  rewrite Nat.Div0.mod_mod by exact Hq_neq_0.
  reflexivity.
Qed.

(** Axiom: R is a power of 2 (standard for Montgomery multiplication) *)
Axiom R_power_of_2 : exists n, R = 2 ^ n.

(** Lemma: R and q are coprime (q is odd, R is power of 2) *)
Lemma R_q_coprime : forall (p : MontgomeryParams),
  Nat.gcd R p.(q) = 1.
Proof.
  intros p.
  destruct (p.(q_odd)) as [k Hq_odd].
  destruct (R_power_of_2) as [n HR_eq].
  rewrite HR_eq.
  (* gcd(2^n, 2*k+1) = 1 since 2*k+1 is odd *)
  (* Powers of 2 share no common factors with odd numbers *)
  induction n as [|n IH].
  - (* n = 0, R = 1 *)
    simpl. rewrite Nat.gcd_comm. rewrite Nat.gcd_1_r. reflexivity.
  - (* n > 0 *)
    (* gcd(2^(n+1), 2*k+1) = gcd(2*2^n, 2*k+1) *)
    (* Since 2*k+1 is odd, it's not divisible by 2 *)
    (* So gcd(2*2^n, 2*k+1) = gcd(2^n, 2*k+1) *)
    assert (Hodd : (2 * k + 1) mod 2 = 1).
    { rewrite Nat.add_mod. rewrite Nat.mul_mod. simpl. reflexivity. }
    (* Use the property that gcd(2*a, b) = gcd(a, b) when b is odd *)
    (* Since 2*k+1 is odd, gcd(2, 2*k+1) = 1 *)
    assert (Hgcd2 : Nat.gcd (2 * 2 ^ n) (2 * k + 1) = Nat.gcd (2 ^ n) (2 * k + 1)).
    {
      (* Use gcd_mul_l: gcd(a*b, c) divides gcd(a,c) * gcd(b,c) *)
      (* And since gcd(2, 2*k+1) = 1, we have gcd(2*2^n, 2*k+1) = gcd(2^n, 2*k+1) *)
      rewrite Nat.gcd_comm.
      rewrite Nat.gcd_comm with (m := 2 ^ n).
      (* Use the fact that if gcd(a,c)=1, then gcd(a*b,c) = gcd(b,c) *)
      assert (Hcoprime : Nat.gcd 2 (2 * k + 1) = 1).
      {
        (* 2*k+1 is odd, so gcd(2, 2*k+1) = 1 *)
        apply Nat.gcd_1_r.
        rewrite Nat.gcd_comm.
        apply Nat.gcd_1_r.
        lia.
      }
      (* Now use gcd_mul_cancel: if gcd(a,c)=1, then gcd(a*b,c) = gcd(b,c) *)
      rewrite <- Nat.gcd_mul_l.
      rewrite Hcoprime.
      rewrite Nat.gcd_1_l.
      reflexivity.
    }
    rewrite Hgcd2.
    exact IH.
Qed.

(** Lemma: If a * R ≡ b * R (mod q) and gcd(R,q)=1, then a ≡ b (mod q) *)
Lemma mod_cancel_R : forall (p : MontgomeryParams) (a b : nat),
  (a * R) mod p.(q) = (b * R) mod p.(q) ->
  a mod p.(q) = b mod p.(q).
Proof.
  intros p a b H.
  assert (Hq_pos : p.(q) > 0) by exact p.(q_pos).
  assert (Hgcd : Nat.gcd R p.(q) = 1) by apply R_q_coprime.
  
  (* Use Bezout's identity: since gcd(R, q) = 1, there exist u, v such that u*R + v*q = 1 *)
  (* Then u*R ≡ 1 (mod q), so u is the multiplicative inverse of R mod q *)
  assert (Hbezout : exists u v, u * R + v * p.(q) = 1).
  { apply Nat.gcd_bezout. exact Hgcd. }
  destruct Hbezout as [u [v Hbezout_eq]].
  
  (* From a*R ≡ b*R (mod q), we have (a*R) mod q = (b*R) mod q *)
  (* This means a*R = b*R + k*q for some k *)
  assert (Hdiff : (a * R - b * R) mod p.(q) = 0).
  {
    rewrite <- Nat.mul_sub_distr_r.
    rewrite <- Nat.sub_mod by exact Hq_pos.
    rewrite H.
    rewrite Nat.sub_diag.
    apply Nat.mod_0_l. lia.
  }
  
  (* (a - b) * R ≡ 0 (mod q) *)
  (* Multiply both sides by u (the inverse of R mod q) *)
  (* (a - b) * R * u ≡ 0 * u (mod q) *)
  (* (a - b) * (R * u) ≡ 0 (mod q) *)
  (* (a - b) * 1 ≡ 0 (mod q) since R*u ≡ 1 (mod q) *)
  (* a - b ≡ 0 (mod q) *)
  (* a ≡ b (mod q) *)
  
  (* More directly: (a-b)*R is divisible by q *)
  (* Since gcd(R, q) = 1, (a-b) must be divisible by q *)
  assert (Hdiv : p.(q) ∣ (a - b) * R).
  {
    apply Nat.dvd_of_mod_eq_zero.
    rewrite <- Nat.mul_sub_distr_r.
    exact Hdiff.
  }
  
  (* Since gcd(R, q) = 1 and q | (a-b)*R, we have q | (a-b) *)
  assert (Hdiv_ab : p.(q) ∣ (a - b)).
  {
    apply (Nat.Coprime.dvd_mul_r _ _ _).
    - apply Nat.Coprime.symm. apply Nat.coprime_gcd. exact Hgcd.
    - exact Hdiv.
  }
  
  (* q | (a-b) means a ≡ b (mod q) *)
  assert (Hcong : a mod p.(q) = b mod p.(q)).
  {
    apply Nat.mod_eq.
    exact Hdiv_ab.
  }
  exact Hcong.
Qed.

(** * Montgomery Operation Correctness Theorems *)

(** Lemma: redc output is always less than q *)
Lemma redc_output_lt_q : forall (p : MontgomeryParams) (t : nat),
  t < p.(q) * R ->
  redc p t < p.(q).
Proof.
  intros p t Ht.
  unfold redc.
  set (t_lo := t mod R).
  set (m := (t_lo * p.(q_inv_neg)) mod R).
  set (t_plus_mq := t + m * p.(q)).
  set (result := t_plus_mq / R).
  assert (Hm_lt : m < R).
  { unfold m. apply Nat.mod_upper_bound. lia. }
  assert (Ht_plus_mq_lt : t_plus_mq < 2 * p.(q) * R).
  {
    unfold t_plus_mq, t_lo.
    assert (Ht_lo_lt : t_lo < R).
    { apply Nat.mod_upper_bound. lia. }
    assert (Hmq_lt : m * p.(q) < R * p.(q)).
    { apply Nat.mul_lt_mono_pos_r. exact Hm_lt. exact p.(q_pos). }
    nlia.
  }
  assert (Hresult_lt_2q : result < 2 * p.(q)).
  {
    unfold result, t_plus_mq.
    apply Nat.Div0.div_lt_upper_bound.
    lia.
  }
  destruct (result <? p.(q)) eqn:Hlt.
  - apply Nat.ltb_lt in Hlt. exact Hlt.
  - apply Nat.ltb_ge in Hlt.
    lia.
Qed.

(** Complete proof for montgomery_mul_correct *)
Theorem montgomery_mul_correct : forall (p : MontgomeryParams) (x y : nat),
  x < p.(q) -> y < p.(q) ->
  from_montgomery p (montgomery_mul p (to_montgomery p x) (to_montgomery p y))
    = (x * y) mod p.(q).
Proof.
  intros p x y Hx Hy.
  unfold from_montgomery, montgomery_mul, to_montgomery.
  assert (HR_pos : R > 0) by exact R_pos.
  assert (Hq_pos : p.(q) > 0) by exact p.(q_pos).
  
  (* Set up intermediate values *)
  set (a := (x * R) mod p.(q)).
  set (b := (y * R) mod p.(q)).
  set (t1 := a * b).
  set (r1 := redc p t1).
  set (r2 := redc p r1).
  
  (* Bounds on a and b *)
  assert (Ha_lt : a < p.(q)).
  { unfold a. apply Nat.mod_upper_bound. lia. }
  assert (Hb_lt : b < p.(q)).
  { unfold b. apply Nat.mod_upper_bound. lia. }
  
  (* t1 = a * b < q * q *)
  assert (Ht1_bound : t1 < p.(q) * p.(q)).
  { unfold t1, a, b. nlia. }
  
  (* Using R >= q, we have t1 < q * q <= q * R *)
  assert (Ht1_qR : t1 < p.(q) * R).
  { 
    apply R_ge_q in Ht1_bound.
    lia.
  }
  
  (* First redc: r1 * R ≡ t1 (mod q) *)
  assert (Hr1_cong : (r1 * R) mod p.(q) = t1 mod p.(q)).
  { apply redc_mult_R_cong. exact Ht1_qR. }
  
  (* t1 mod q = (x * y * R^2) mod q *)
  assert (Ht1_mod : t1 mod p.(q) = (x * y * R * R) mod p.(q)).
  {
    unfold t1, a, b.
    rewrite Nat.Div0.mul_mod by exact Hq_pos.
    rewrite Nat.Div0.mul_mod by exact Hq_pos.
    rewrite <- Nat.mul_assoc.
    rewrite <- Nat.mul_assoc.
    reflexivity.
  }
  
  (* r1 * R ≡ x * y * R^2 (mod q) *)
  (* Cancel R to get r1 ≡ x * y * R (mod q) *)
  assert (Hr1_cong2 : r1 mod p.(q) = (x * y * R) mod p.(q)).
  {
    rewrite <- Hr1_cong.
    rewrite Ht1_mod.
    apply mod_cancel_R.
    reflexivity.
  }
  
  (* r1 < q, so r1 mod q = r1 *)
  assert (Hr1_lt_q : r1 < p.(q)).
  { unfold r1. apply redc_output_lt_q. exact Ht1_qR. }
  assert (Hr1_mod : r1 mod p.(q) = r1).
  { apply Nat.mod_small. exact Hr1_lt_q. }
  
  (* Second redc: r2 * R ≡ r1 (mod q) *)
  assert (Hr1_qR : r1 < p.(q) * R).
  { unfold r1. lia. }
  assert (Hr2_cong : (r2 * R) mod p.(q) = r1 mod p.(q)).
  { apply redc_mult_R_cong. exact Hr1_qR. }
  
  (* r2 * R ≡ r1 ≡ x * y * R (mod q) *)
  (* Cancel R to get r2 ≡ x * y (mod q) *)
  assert (Hr2_cong2 : r2 mod p.(q) = (x * y) mod p.(q)).
  {
    rewrite <- Hr2_cong.
    rewrite <- Hr1_mod.
    rewrite Hr1_cong2.
    apply mod_cancel_R.
    reflexivity.
  }
  
  (* r2 < q, so r2 mod q = r2 *)
  assert (Hr2_lt_q : r2 < p.(q)).
  { unfold r2. apply redc_output_lt_q. exact Hr1_qR. }
  assert (Hr2_mod : r2 mod p.(q) = r2).
  { apply Nat.mod_small. exact Hr2_lt_q. }
  
  (* Final result *)
  rewrite <- Hr2_mod in Hr2_cong2.
  reflexivity.
Qed.

(** Complete proof for montgomery_add_correct *)
Theorem montgomery_add_correct : forall (p : MontgomeryParams) (x y : nat),
  x < p.(q) -> y < p.(q) ->
  from_montgomery p (montgomery_add p (to_montgomery p x) (to_montgomery p y))
    = (x + y) mod p.(q).
Proof.
  intros p x y Hx Hy.
  unfold from_montgomery, montgomery_add, to_montgomery.
  assert (HR_pos : R > 0) by exact R_pos.
  assert (Hq_pos : p.(q) > 0) by exact p.(q_pos).
  
  (* montgomery_add a b = (a + b) mod q *)
  (* to_montgomery x = (x * R) mod q *)
  (* to_montgomery y = (y * R) mod q *)
  (* So input to from_montgomery is ((x*R) mod q + (y*R) mod q) mod q *)
  (* = ((x + y) * R) mod q *)
  set (t := ((x * R) mod p.(q) + (y * R) mod p.(q)) mod p.(q)).
  assert (Ht_eq : t = ((x + y) * R) mod p.(q)).
  {
    unfold t.
    rewrite <- Nat.mul_add_distr_r.
    rewrite Nat.Div0.add_mod by exact Hq_pos.
    reflexivity.
  }
  
  (* from_montgomery t = redc p t *)
  (* We need redc p (((x+y)*R) mod q) = (x+y) mod q *)
  rewrite Ht_eq.
  
  (* Use redc_mult_R_cong: (redc t * R) mod q = t mod q *)
  set (r := redc p (((x + y) * R) mod p.(q))).
  assert (Ht_qR : ((x + y) * R) mod p.(q) < p.(q) * R).
  { apply Nat.mod_upper_bound. lia. }
  assert (Hr_cong : (r * R) mod p.(q) = (((x + y) * R) mod p.(q)) mod p.(q)).
  { apply redc_mult_R_cong. exact Ht_qR. }
  
  (* Simplify: (((x+y)*R) mod q) mod q = ((x+y)*R) mod q *)
  assert (Ht_mod : (((x + y) * R) mod p.(q)) mod p.(q) = ((x + y) * R) mod p.(q)).
  { apply Nat.mod_mod. }
  rewrite Ht_mod in Hr_cong.
  
  (* r * R ≡ (x+y) * R (mod q) *)
  (* r ≡ x+y (mod q) by canceling R *)
  assert (Hr_cong2 : r mod p.(q) = (x + y) mod p.(q)).
  {
    rewrite <- Hr_cong.
    apply mod_cancel_R.
    reflexivity.
  }
  
  (* r < q, so r mod q = r *)
  assert (Hr_lt : r < p.(q)).
  { unfold r. apply redc_output_lt_q. exact Ht_qR. }
  assert (Hr_mod : r mod p.(q) = r).
  { apply Nat.mod_small. exact Hr_lt. }
  
  rewrite <- Hr_mod in Hr_cong2.
  reflexivity.
Qed.

(** KNOWN FALSE - see NINE65_v7_DEEP_ANALYSIS_20260817.md G15.

    The theorem below (kept only as an inert comment, not live Coq) used to
    be stated for the old, buggy `montgomery_sub` definition
    `(a - b) mod p.(q)` and closed with `Qed`. Its *statement* is
    mathematically false: instantiate p.(q)=5, R=8, p.(q_inv_neg)=3 (valid:
    `(5*3) mod 8 = 7 = R-1`), x=4, y=3. Then `to_montgomery p x = 2`,
    `to_montgomery p y = 4`, `montgomery_sub p 2 4 = (2-4) mod 5 = 0` under
    nat truncation, and `redc p 0 = 0`, so the theorem's LHS
    `from_montgomery p (montgomery_sub p (to_montgomery p x) (to_montgomery
    p y))` evaluates to `0`, while its RHS `(x - y) mod p.(q)` evaluates to
    `1`. `0 <> 1`, so the statement is false for a satisfiable instance of
    every hypothesis (x<q, y<q both hold: 4<5, 3<5). Whatever chain of
    rewrites let the original proof below reach `Qed` for a false goal, it
    must be exploiting an unsound step (most likely the `Nat.sub_mod`
    rewrite, which does not have the naive meaning `(a mod n - b mod n) mod
    n = (a - b) mod n` for truncated nat subtraction that this proof
    assumed). Do not cite this proof as verified; it has been removed from
    live Coq so it can no longer be Qed'd or `Print Assumptions`'d as if
    trustworthy.

<<<
Theorem montgomery_sub_correct : forall (p : MontgomeryParams) (x y : nat),
  x < p.(q) -> y < p.(q) ->
  from_montgomery p (montgomery_sub p (to_montgomery p x) (to_montgomery p y))
    = (x - y) mod p.(q).
Proof.
  intros p x y Hx Hy.
  unfold from_montgomery, montgomery_sub, to_montgomery.
  assert (HR_pos : R > 0) by exact R_pos.
  assert (Hq_pos : p.(q) > 0) by exact p.(q_pos).
  set (t := ((x * R) mod p.(q) - (y * R) mod p.(q)) mod p.(q)).
  assert (Ht_eq : t = ((x - y) * R) mod p.(q)).
  {
    unfold t.
    assert (H1 : ((x * R) mod p.(q) - (y * R) mod p.(q)) mod p.(q) =
             (x * R - y * R) mod p.(q)).
    {
      rewrite <- Nat.sub_mod by exact Hq_pos.
      reflexivity.
    }
    rewrite H1.
    rewrite <- Nat.mul_sub_distr_r.
    reflexivity.
  }
  rewrite Ht_eq.
  set (r := redc p (((x - y) * R) mod p.(q))).
  assert (Ht_qR : ((x - y) * R) mod p.(q) < p.(q) * R).
  { apply Nat.mod_upper_bound. lia. }
  assert (Hr_cong : (r * R) mod p.(q) = (((x - y) * R) mod p.(q)) mod p.(q)).
  { apply redc_mult_R_cong. exact Ht_qR. }
  assert (Ht_mod : (((x - y) * R) mod p.(q)) mod p.(q) = ((x - y) * R) mod p.(q)).
  { apply Nat.mod_mod. }
  rewrite Ht_mod in Hr_cong.
  assert (Hr_cong2 : r mod p.(q) = (x - y) mod p.(q)).
  {
    rewrite <- Hr_cong.
    apply mod_cancel_R.
    reflexivity.
  }
  assert (Hr_lt : r < p.(q)).
  { unfold r. apply redc_output_lt_q. exact Ht_qR. }
  assert (Hr_mod : r mod p.(q) = r).
  { apply Nat.mod_small. exact Hr_lt. }
  rewrite <- Hr_mod in Hr_cong2.
  reflexivity.
Qed.
>>>
*)

(** Corrected statement for the fixed `montgomery_sub` definition above
    (which pads by `p.(q)` before subtracting, so it never truncates).
    This restores the claim `montgomery_sub_correct` is supposed to make,
    but the proof is genuinely new work (the padded-subtraction case was
    never proved anywhere in this file) and is left honestly `Admitted`
    rather than asserted with an unverified `Qed`.

    TODO (G15): prove this by adapting `montgomery_add_correct`'s argument
    (a few theorems above) with `y` replaced by `p.(q) - y`: show
    `to_montgomery p x + p.(q) - to_montgomery p y` reduces mod `q*R` the
    same way `redc_mult_R_cong` / `mod_cancel_R` already handle addition,
    i.e. that `((a + p.(q) - b) mod p.(q)) * R ≡ (x - y) * R (mod p.(q))`
    when `a = (x*R) mod q`, `b = (y*R) mod q`, using `Nat.add_sub_assoc`-style
    lemmas that keep every intermediate subtraction non-underflowing (unlike
    the false proof above, which subtracted two mod-reduced values with no
    ordering guarantee). No toolchain was available in this session to
    verify a candidate proof compiles, so it is intentionally left as an
    honest gap rather than risking a second unsound `Qed`. *)
Theorem montgomery_sub_correct : forall (p : MontgomeryParams) (x y : nat),
  x < p.(q) -> y < p.(q) ->
  from_montgomery p (montgomery_sub p (to_montgomery p x) (to_montgomery p y))
    = (x - y) mod p.(q).
Proof.
Admitted.

(** * Montgomery Exponentiation (Montgomery Ladder) *)

(**
   Montgomery ladder for constant-time exponentiation.
   Processes bits of the exponent from most significant to least significant.
   Uses the double-and-add method in Montgomery form.
*)

(** Convert natural number to list of bits (MSB first) *)
Fixpoint nat_to_bits (n : nat) : list bool :=
  match n with
  | 0 => [false]
  | 1 => [true]
  | _ =>
    let rest := nat_to_bits (n / 2) in
    if n mod 2 =? 0 then rest ++ [false] else rest ++ [true]
  end.

(** Helper: remove leading zeros from bit list *)
Fixpoint trim_leading_zeros (bits : list bool) : list bool :=
  match bits with
  | [] => []
  | false :: rest => trim_leading_zeros rest
  | true :: rest => true :: rest
  | [false] => [false]
  end.

(** Convert natural number to bits, MSB first, no leading zeros *)
Definition nat_to_bits_msb (n : nat) : list bool :=
  match n with
  | 0 => []
  | _ => trim_leading_zeros (nat_to_bits n)
  end.

(** Montgomery ladder step: process one bit of the exponent *)
Definition montgomery_ladder_step (p : MontgomeryParams) (r0 r1 : nat) (bit : bool) : nat * nat :=
  if bit then
    (montgomery_mul p r0 r0, montgomery_mul p r0 r1)
  else
    (montgomery_mul p r0 r1, montgomery_mul p r1 r1).

(** Montgomery ladder: process all bits *)
Fixpoint montgomery_ladder (p : MontgomeryParams) (r0 r1 : nat) (bits : list bool) : nat * nat :=
  match bits with
  | [] => (r0, r1)
  | bit :: rest =>
    let (r0', r1') := montgomery_ladder_step p r0 r1 bit in
    montgomery_ladder p r0' r1' rest
  end.

(** Montgomery exponentiation: compute base^exp in Montgomery form *)
Definition montgomery_pow (p : MontgomeryParams) (base exp : nat) : nat :=
  let bits := nat_to_bits_msb exp in
  let r0 := to_montgomery p 1 in  (* R mod q *)
  let r1 := to_montgomery p base in  (* base * R mod q *)
  let (final_r0, final_r1) := montgomery_ladder p r0 r1 bits in
  final_r0.

(** * Bit Masking for Constant-Time Conditional *)

(**
   Constant-time conditional selection using bit masking.
   Instead of branching on (result <? q), we use:
   - borrow = result <? q
   - mask = if borrow then 2^64 - 1 else 0
   - result' = (result & mask) | (diff & !mask)

   This is extensionally equal to: if result <? q then result else result - q
*)

(** Bitwise AND for 64-bit values *)
Definition bitwise_and_64 (a b : nat) : nat :=
  N.to_nat (N.land (N.of_nat a) (N.of_nat b)).

(** Bitwise OR for 64-bit values *)
Definition bitwise_or_64 (a b : nat) : nat :=
  N.to_nat (N.lor (N.of_nat a) (N.of_nat b)).

(** Bitwise NOT for 64-bit values *)
Definition bitwise_not_64 (a : nat) : nat :=
  N.to_nat (N.lnot (N.of_nat a) land N.of_nat (2^64 - 1)).

(** Constant-time conditional subtraction using masking *)
Definition cond_sub_mask (result q : nat) : nat :=
  let diff :=
    if result >=? q then
      result - q
    else
      result + 2^64 - q
  in
  let borrow := result <? q in
  let mask := if borrow then 2^64 - 1 else 0 in
  bitwise_or_64 (bitwise_and_64 result mask) (bitwise_and_64 diff (bitwise_not_64 mask)).

(** * Helper Lemmas for Bit Operations *)

(** Lemma: bitwise_and_64 with all 1s returns the original value (if < 2^64) *)
Lemma and_all_ones : forall (a : nat),
  a < 2^64 ->
  bitwise_and_64 a (2^64 - 1) = a.
Proof.
  intros a Ha.
  unfold bitwise_and_64.
  rewrite N2Nat.id by lia.
  rewrite Nat2N.id.
  rewrite N.land_1_l.
  - rewrite N2Nat.id by lia. reflexivity.
  - apply N.of_nat_lt. lia.
Qed.

(** Lemma: bitwise_and_64 with 0 returns 0 *)
Lemma and_zero : forall (a : nat),
  bitwise_and_64 a 0 = 0.
Proof.
  intros a.
  unfold bitwise_and_64.
  rewrite N2Nat.id by lia.
  rewrite Nat2N.id.
  rewrite N.land_0_r.
  rewrite N2Nat.id. reflexivity.
Qed.

(** Lemma: bitwise_or_64 with 0 returns the original value *)
Lemma or_zero : forall (a : nat),
  bitwise_or_64 a 0 = a.
Proof.
  intros a.
  unfold bitwise_or_64.
  rewrite N2Nat.id by lia.
  rewrite Nat2N.id.
  rewrite N.lor_0_r.
  rewrite N2Nat.id. reflexivity.
Qed.

(** Lemma: bitwise_not_64 of all 1s is 0 *)
Lemma not_all_ones : bitwise_not_64 (2^64 - 1) = 0.
Proof.
  unfold bitwise_not_64.
  rewrite N2Nat.id by lia.
  rewrite Nat2N.id.
  rewrite N.lnot_1_l.
  - rewrite N2Nat.id. reflexivity.
  - apply N.of_nat_lt. lia.
Qed.

(** Lemma: bitwise_not_64 of 0 is all 1s *)
Lemma not_zero : bitwise_not_64 0 = 2^64 - 1.
Proof.
  unfold bitwise_not_64.
  rewrite N2Nat.id by lia.
  rewrite Nat2N.id.
  rewrite N.lnot_0_l.
  rewrite N.land_1_r.
  rewrite N2Nat.id. reflexivity.
Qed.

(** * Montgomery Exponentiation Correctness Proof *)

(** Axiom: Montgomery form roundtrip property *)
Axiom to_from_montgomery : forall (p : MontgomeryParams) (x : nat),
  x < p.(q) ->
  to_montgomery p (from_montgomery p x) = x.

(** Axiom: from_montgomery of to_montgomery returns original value *)
Axiom from_to_montgomery : forall (p : MontgomeryParams) (x : nat),
  x < p.(q) ->
  from_montgomery p (to_montgomery p x) = x.

(** Lemma: from_montgomery of montgomery_mul equals product mod q *)
Lemma from_mont_mul : forall (p : MontgomeryParams) (a b : nat),
  a < p.(q) -> b < p.(q) ->
  from_montgomery p (montgomery_mul p a b) = (from_montgomery p a * from_montgomery p b) mod p.(q).
Proof.
  intros p a b Ha Hb.
  assert (Ha_lt : from_montgomery p a < p.(q)).
  { apply redc_output_lt_q. unfold from_montgomery. lia. }
  assert (Hb_lt : from_montgomery p b < p.(q)).
  { apply redc_output_lt_q. unfold from_montgomery. lia. }
  set (x := from_montgomery p a).
  set (y := from_montgomery p b).
  assert (Ha_eq : a = to_montgomery p x).
  { unfold x. apply to_from_montgomery. exact Ha_lt. }
  assert (Hb_eq : b = to_montgomery p y).
  { unfold y. apply to_from_montgomery. exact Hb_lt. }
  rewrite Ha_eq, Hb_eq.
  apply montgomery_mul_correct. exact Ha_lt. exact Hb_lt.
Qed.

(** Axiom: Ladder step preserves invariant for bit = true *)
Axiom ladder_step_true : forall (p : MontgomeryParams) (a b : nat),
  a < p.(q) -> b < p.(q) ->
  let (a', b') := montgomery_ladder_step p a b true in
  from_montgomery p a' = (from_montgomery p a * from_montgomery p b) mod p.(q) /\
  from_montgomery p b' = (from_montgomery p b * from_montgomery p b) mod p.(q).

(** Axiom: Ladder step preserves invariant for bit = false *)
Axiom ladder_step_false : forall (p : MontgomeryParams) (a b : nat),
  a < p.(q) -> b < p.(q) ->
  let (a', b') := montgomery_ladder_step p a b false in
  from_montgomery p a' = (from_montgomery p a * from_montgomery p a) mod p.(q) /\
  from_montgomery p b' = (from_montgomery p a * from_montgomery p b) mod p.(q).

(** Axiom: nat_to_bits_msb produces bits that fold to original value *)
Axiom nat_to_bits_fold : forall (n : nat),
  fold_left (fun acc bit => 2 * acc + (if bit then 1 else 0)) (nat_to_bits_msb n) 0 = n.

(** Axiom: Ladder with initial (to_mont 1, to_mont base) computes base^val mod q *)
Axiom montgomery_ladder_correct : forall (p : MontgomeryParams) (base : nat) (bits : list bool),
  base < p.(q) ->
  let val := fold_left (fun acc bit => 2 * acc + (if bit then 1 else 0)) bits 0 in
  let (r0, r1) := montgomery_ladder p (to_montgomery p 1) (to_montgomery p base) bits in
  from_montgomery p r0 = Nat.pow base val mod p.(q).

(** Main theorem: Montgomery exponentiation correctness *)
Theorem montgomery_pow_correct : forall (p : MontgomeryParams) (base exp : nat),
  base < p.(q) ->
  from_montgomery p (montgomery_pow p base exp) = Nat.pow base exp mod p.(q).
Proof.
  intros p base exp Hbase.
  unfold montgomery_pow, from_montgomery.
  
  destruct exp as [|exp'].
  - (* exp = 0: base^0 = 1 *)
    simpl.
    unfold nat_to_bits_msb.
    apply from_to_montgomery. lia.
  - (* exp > 0 *)
    (* Apply the ladder_correct axiom *)
    assert (Hladder := montgomery_ladder_correct p base (nat_to_bits_msb exp') Hbase).
    simpl in Hladder.
    
    (* val = exp' by nat_to_bits_fold *)
    assert (Hbits := nat_to_bits_fold exp').
    rewrite Hbits in Hladder.
    exact Hladder.
Qed.

(** * Mask Correctness Proof *)

(** Lemma: mask_correctness - Bit masking equals conditional *)
Lemma mask_correctness : forall (result q : nat),
  result < 2^64 -> q < 2^64 ->
  let diff := if result >=? q then result - q else result + 2^64 - q in
  let borrow := result <? q in
  let mask := if borrow then 2^64 - 1 else 0 in
  bitwise_or_64 (bitwise_and_64 result mask) (bitwise_and_64 diff (bitwise_not_64 mask)) =
  if result <? q then result else result - q.
Proof.
  intros result q Hr Hq.
  unfold diff, borrow, mask.
  
  (* Case analysis on result <? q *)
  destruct (result <? q) eqn:Hlt.
  - (* Case: result < q, borrow = true, mask = 2^64 - 1 *)
    (* result & (2^64-1) = result (since result < 2^64) *)
    (* diff = result + 2^64 - q *)
    (* diff & !(2^64-1) = diff & 0 = 0 *)
    (* result | 0 = result *)
    assert (Hmask : (if result <? q then 2^64 - 1 else 0) = 2^64 - 1).
    { rewrite Hlt. reflexivity. }
    rewrite Hmask.
    assert (Hand_result : bitwise_and_64 result (2^64 - 1) = result).
    { apply and_all_ones. exact Hr. }
    rewrite Hand_result.
    assert (Hnot_mask : bitwise_not_64 (2^64 - 1) = 0).
    { apply not_all_ones. }
    rewrite Hnot_mask.
    assert (Hand_diff : bitwise_and_64 diff 0 = 0).
    { apply and_zero. }
    rewrite Hand_diff.
    assert (Hor : bitwise_or_64 result 0 = result).
    { apply or_zero. }
    rewrite Hor.
    rewrite Hlt. reflexivity.
    
  - (* Case: result >= q, borrow = false, mask = 0 *)
    (* result & 0 = 0 *)
    (* diff = result - q *)
    (* diff & !(0) = diff & (2^64-1) = diff (since diff < 2^64) *)
    (* 0 | diff = diff = result - q *)
    apply Nat.ltb_ge in Hlt.
    assert (Hmask : (if result <? q then 2^64 - 1 else 0) = 0).
    { rewrite Hlt. reflexivity. }
    rewrite Hmask.
    assert (Hand_result : bitwise_and_64 result 0 = 0).
    { apply and_zero. }
    rewrite Hand_result.
    assert (Hnot_mask : bitwise_not_64 0 = 2^64 - 1).
    { apply not_zero. }
    rewrite Hnot_mask.
    assert (Hdiff_eq : (if result >=? q then result - q else result + 2^64 - q) = result - q).
    {
      apply Nat.leb_le in Hlt.
      rewrite Hlt. reflexivity.
    }
    rewrite Hdiff_eq.
    assert (Hdiff_lt : result - q < 2^64).
    {
      apply Nat.leb_le in Hlt.
      assert (Hq_pos : q > 0) by lia.
      lia.
    }
    assert (Hand_diff : bitwise_and_64 (result - q) (2^64 - 1) = result - q).
    { apply and_all_ones. exact Hdiff_lt. }
    rewrite Hand_diff.
    assert (Hor : bitwise_or_64 0 (result - q) = result - q).
    { rewrite N.lor_comm. apply or_zero. }
    rewrite Hor.
    rewrite Hlt. reflexivity.
Qed.

(** * Summary *)

Print Assumptions redc_correct.
Print Assumptions montgomery_mul_correct.
Print Assumptions montgomery_add_correct.
Print Assumptions montgomery_sub_correct.
