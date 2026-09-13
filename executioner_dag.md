# executioner_dag.md — NINE65 Exact-Multiply + WIRE-Q + CT + #95 Build DAG

**Created:** 2026-09-13 · **Branch of record:** `claude/track-1-derived-transient-exact-mul` (PR #103)
**Companion PRs:** #102 (plan), #104 (Track 2 compare_bit decrypt)
**Invariants in force:** I1 ZERO FLOAT · I2 MANIFEST FIRST · I3 GATE BEFORE ADVANCE · I6 NO REDUNDANCY
**Blueprint sources:** `docs/TRACK1_D3_EXACT_MULTIPLY_IMPLEMENTATION.md`, `docs/CRAM_RLWE_COEXISTENCE_PLAN_2026-09-01.md`, `docs/CRAM_APPLICABILITY_MAP_2026-09-01.md`, `docs/TRACK2_D2_FIXED_WORK_DECRYPT.md` (branch `codex/track-2-fixed-work-compare-bit-decrypt`)

This file IS the session record. Append; never overwrite.

---

## 0. Governing math (read once; every node cites it)

### 0.1 Wire invariant (WIRE-Q)
A published, secret-dependent object (`pk0`, `c0`, `c1`, `rlk0`, galois/bootstrap keys) carries residues **only modulo divisors of `Q`**. Any coprime-to-`Q` residue on such an object is a total break (rational inversion recovers `s`; proven, reproduced with the real anchor primes). Exactness lives in the *compute*, never in the *wire format*.

### 0.2 Derived-transient auxiliary base
`AUX = canonical_anchor_primes_for_n(n)` (rns.rs:1289) is reused **as a transient basis only**. It is never stored on a ciphertext/key. Every aux residue is `f(mod-Q residues)` via `MainOnlyBaseExt::project` (PASS, main_only_base_ext.rs).

### 0.3 Exact rounded rescale by two base extensions (the core algorithm)
BFV multiply must output `round(t · V / Q) mod Q` where `V` is an exact tensor coefficient, `|V| ≤ N·Q²`. Exact, float-free, X-free:

```
INPUT : V as residues in MAIN ∪ AUX      (exact iff Q·A > max|V|)
        t (plaintext modulus), Q, A=∏AUX, hQ = floor(Q/2)
STEP 1: W = t·V + hQ            lane-wise in MAIN ∪ AUX   (constants t, hQ mod each lane)
STEP 2: γ = W mod Q             = MAIN lanes of W (free)
STEP 3: γ_aux = ext_Q→AUX(γ)    MainOnlyBaseExt(main=MAIN, aux=AUX).project   [exact: γ canonical < Q]
STEP 4: K_j = (W_j − γ_aux_j) · Qinv_j  mod a_j   ∀ aux lane j     (Qinv_j = Q⁻¹ mod a_j)
        ⇒ K = floor(W/Q) as residues in AUX,   exact iff K < A
STEP 5: out_i = ext_AUX→Q(K)_i  MainOnlyBaseExt(main=AUX, aux=MAIN).project   [exact: K canonical < A]
OUTPUT: out = round(t·V/Q) mod q_i  on MAIN lanes only;  AUX dropped
```
Correctness: `floor((t·V + floor(Q/2))/Q) = round(t·V/Q)` (round-half-up). `W = γ + K·Q ⇒ K ≡ (W−γ)·Q⁻¹ (mod a_j)`.
Capacity certificate (proved per call, typed error on failure): `t·N·Q² + hQ < Q·A` ⇔ roughly `A > t·N·Q`.
For secure_128_deep: `t·N·Q ≈ 2^16·2^13·2^119 = 2^148 < A = 2^220` ✓. secure_256: `2^16·2^14·2^175 = 2^205 < A₁₀ = 2^315` ✓.

### 0.4 Negative/centered values
Tensor coefficients are signed. Represent centered: a lane value `v` with `v > q/2` means `v − q`. STEP 1 uses the centered lift consistently (all lanes agree on sign because they are residues of one integer). Round-half-up on the *signed* value: `W = t·V + hQ` then floor-division toward −∞. Implement floor for negatives by adding a known multiple of `Q` (shift by `S = Q·ceil(N·Q·t/Q)`, i.e. `W' = W + S·Q`, guaranteed ≥ 0, subtract `S` from `K` after) — all exact integers, no branch on the secret-independent public tensor.

### 0.5 Both multiply orders are legal; the math picks
- **Order A (standard SEAL):** tensor → rescale each of `d0,d1,d2` → relin `d2` with mod-`Q` `evk` in mod-`Q`.
- **Order B (current NINE65):** tensor → relin `d2` in MAIN∪AUX (evk base-extended) → rescale `d0',d1'`.
Both are implemented (E-nodes); gate G-DIFF runs both against the U512 oracle and G-NOISE measures post-mul noise; the surviving order is the one that is exact AND lower-noise. No pre-selection.

---

## M — Manifest (discovered this session; SKIP-EXISTS / PASS)

## NODE-M01 — Bignum types
- **Type:** SCAFFOLD · **Size:** — · **Status:** SKIP-EXISTS
- **Notes:** `U256 {lo,hi}` (rns.rs:213; `add, cmp/ge/gt/le, mod_u64, product_u64s, from_u64/u128, ge_ct, select_mask_ct`), `U512 {d0..d3}` (rns.rs:55; `add, sub, mul_u128, div_u64, mod_u64, mod_u256, product_u64s, from_u256`). Oracle-grade for values ≤ 2^512. Use these; do not add `num-bigint`.

## NODE-M02 — MainOnlyBaseExt (canonical-rank base extension)
- **Type:** IMPL · **Status:** PASS (commits ae3b7d6, df25fa2)
- **Output:** `crates/nine65/src/arithmetic/main_only_base_ext.rs`
- **Notes:** `MainOnlyBaseExt::new(main,aux) -> Result`, `.project(&r, &mut out) -> Result<RankPath>`. Fixed-point common path + exact U256 fallback; both paths asserted under test; U512 oracle over real 4/5/6-lane prefixes. **This is the primitive for STEP 3 and STEP 5 of §0.3 — the same struct instantiated twice (Q→AUX and AUX→Q).**

## NODE-M03 — Existing dual machinery (reference oracle, not production route)
- **Type:** SCAFFOLD · **Status:** SKIP-EXISTS
- **Notes:** `DualRNSPoly/DualRNSCiphertext` (rns_fhe.rs:233-320), `dual_poly_mul/add/neg`, `mul_dual_symmetric` (3258), `mul_dual_public` (3475), `k_elim_rescale_dual[_two_stage]`, `relinearize_dual` (3726), `extract_k_rns*` (rns.rs). Keep as **cross-check oracle** (G-DIFF-B). Never the wire.

## NODE-M04 — Single-modulus (mod-Q) path
- **Type:** SCAFFOLD · **Status:** SKIP-EXISTS
- **Notes:** `RNSCiphertext`, `RNSPublicKey`, `RNSEvalKey`, `encrypt` (rns_fhe.rs:1596), `mul` (1759), `decrypt` (1688, centered). This is the **wire format**. E-nodes produce/consume it.

## NODE-M05 — Sampler prerequisite
- **Type:** IMPL · **Status:** PASS (already on main)
- **Notes:** `sample_uniform_dual_poly` (rns_fhe.rs:1135) rejection-samples uniform on `[0,M)` full-width. Contract prerequisite "exact full-width sampling" is MET. No node needed.

## NODE-M06 — Unified rescale (manufactured-chain primitive)
- **Type:** SCAFFOLD · **Status:** SKIP-EXISTS
- **Notes:** `unified_rescale.rs`: `RescaleChain::new`, `exact_delta_rescale`, `RescaleExit::{ModulusReduced,Reraise}`, `universal_project`, `adjacency_project`; 24/24 tests pass; requires `Q = t·D` (refuses hunted chains). This is **R-path-B**.

## NODE-M07 — compare_bit fixed-work decrypt (Track 2)
- **Type:** IMPL · **Status:** PASS on branch `codex/track-2-fixed-work-compare-bit-decrypt` (10/10 Rust, 265,360 Python oracle checks, full lib suite no regression; reported PR #104)
- **Notes:** `CompareBit::decide_ct`, `U256::ge_mask_ct` borrow-propagation fix, wired into single-RNS/dual decrypt. Remaining: C-nodes (hardware evidence).

## NODE-M08 — Serialization surface
- **Type:** SCAFFOLD · **Status:** SKIP-EXISTS
- **Notes:** `DualRNSCiphertext::to_bytes/from_bytes_validated` (bincode, includes `.anchor`); `fhe-service/src/wire.rs:9-11` sizes payload for anchor; `session.rs:128 dual_ct_to_b64`. **This is where WIRE-Q is currently violated on the ciphertext wire.** W-nodes retire it.

## NODE-M09 — Source gates
- **Type:** SCAFFOLD · **Status:** SKIP-EXISTS
- **Notes:** `scripts/check_residue_native_architecture.py` (21 pre-existing findings in `cram_ct.rs`, `bootstrap.rs`), `scripts/verify_compare_bit_ct.py`. G-SRC extends the scanner.

## NODE-M10 — Baseline fmt state
- **Type:** GATE · **Status:** FAIL (pre-existing)
- **Notes:** `cargo fmt --all -- --check` fails on 100+ files across every crate on `main`. Per-PR fmt gates cannot pass until F01 lands a repo-wide fmt commit.

---

## R — Exact rounded rescale (T1.3) — ALL PATHS, math decides

## NODE-R01 — Capacity certificate type + prover
- **Type:** STRUCT · **Size:** S
- **Inputs:** `rns.rs` (U256/U512, `canonical_anchor_primes_for_n`), `secure_configs.rs`
- **Output:** `crates/nine65/src/arithmetic/exact_rescale.rs` (new; `RescaleCapacity` section)
- **Gate:** unit tests: certificate PASSES for secure_128_deep/192/256 with canonical AUX; FAILS (typed `Nine65Error::CapacityUncertified{need,have}`) when AUX truncated to 3 lanes; zero float.
- **Pseudocode:**
```
struct RescaleCapacity { q_bits:u32, a_bits:u32, n:usize, t:u64, certified:bool }
fn certify(main:&[u64], aux:&[u64], n:usize, t:u64) -> Result<RescaleCapacity, Nine65Error>:
    Q  = U512::product_u64s(main);  A = U512::product_u64s(aux)
    // bound on |t·V + hQ|  ≤ t·N·Q² + Q/2  <  (t·N·Q + 1)·Q
    // need  (t·N·Q + 1)·Q  <  Q·A   ⇔   t·N·Q + 1 < A
    lhs = Q.mul_u128(t as u128).mul_u128(n as u128).add(U512::from_u64(1))
    if !(lhs < A)  -> Err(CapacityUncertified{need: bits(lhs), have: bits(A)})
    // also K = floor(W/Q) < A  ⇔  same inequality
    Ok(RescaleCapacity{..., certified:true})
```

## NODE-R02 — Centered lift + non-negative shift constants
- **Type:** IMPL · **Size:** S
- **Inputs:** exact_rescale.rs (R01)
- **Output:** exact_rescale.rs (`CenteredShift` section)
- **Gate:** for random signed V (U512, |V| ≤ N·Q²): `lift_shift(V) ≥ 0` and `lift_shift(V) ≡ V (mod q_i)` ∀ lanes and `≡ V (mod a_j)` ∀ aux; recover sign exactly; zero float.
- **Pseudocode:**
```
// choose S = smallest integer with S·Q > t·N·Q² + hQ   (public constant per config)
S = ceil((t·N·Q² + hQ) / Q) = t·N·Q + 1            (exact integer, U512)
S_mod_lane[i] = S mod q_i ;  S_mod_aux[j] = S mod a_j   (precomputed once)
// per coefficient, lane-wise: W' = W + S·Q  ≥ 0  (add (S·Q) mod lane = 0 on MAIN lanes!, = (S·Q) mod a_j on AUX)
// NOTE: S·Q ≡ 0 mod q_i, so MAIN lanes of W' == MAIN lanes of W. Only AUX lanes shift.
// after STEP 4:  K' = floor(W'/Q) = K + S   ⇒  K = K' − S   (subtract S mod a_j lane-wise in AUX, then ext AUX→Q)
```

## NODE-R03 — R-path-A: two-extension exact rounded rescale (§0.3), single coefficient
- **Type:** IMPL · **Size:** M
- **Inputs:** main_only_base_ext.rs (M02), exact_rescale.rs (R01,R02)
- **Output:** exact_rescale.rs (`fn exact_round_rescale_coeff`)
- **Gate:** U512 oracle: for 20,000 random signed V per config (4/5/6 lanes) + edges (0, ±1, ±(Q/2), ±(N·Q²−1), rounding ties `t·V ≡ hQ mod Q`): output == `round_half_up(t·V/Q) mod q_i` bit-exact ∀ lanes; both `RankPath`s observed in ext_Q→AUX and ext_AUX→Q; zero float; no `U512` in the non-test path.
- **Pseudocode:**
```
struct ExactRescale { extQA: MainOnlyBaseExt(MAIN→AUX), extAQ: MainOnlyBaseExt(AUX→MAIN),
                      t_mod_main[i], t_mod_aux[j], hq_mod_main[i], hq_mod_aux[j],
                      qinv_aux[j] = Q⁻¹ mod a_j, s_mod_aux[j], cap: RescaleCapacity }
fn exact_round_rescale_coeff(v_main:&[u64], v_aux:&[u64], out:&mut [u64]) -> Result<()>:
    // STEP 1  W = t·V + hQ   (lane-wise, u128 mulmod)
    w_main[i] = (v_main[i]·t_mod_main[i] + hq_mod_main[i]) mod q_i
    w_aux[j]  = (v_aux[j] ·t_mod_aux[j]  + hq_mod_aux[j] + sQ_mod_aux[j]) mod a_j   // R02 shift on AUX only
    // STEP 2  γ = W mod Q  == w_main (canonical by construction)
    // STEP 3  γ_aux = ext_Q→AUX(γ)
    extQA.project(&w_main, &mut g_aux)?
    // STEP 4  K'_j = (w_aux_j − g_aux_j)·qinv_aux[j] mod a_j ;  K_j = K'_j − s_mod_aux[j]
    k_aux[j] = ((w_aux[j] + a_j − g_aux[j]) · qinv_aux[j]) mod a_j
    k_aux[j] = (k_aux[j] + a_j − s_mod_aux[j]) mod a_j
    // STEP 5  out = ext_AUX→Q(K)
    extAQ.project(&k_aux, out)?          // exact: 0 ≤ K < A certified by R01
    Ok(())
```

## NODE-R04 — R-path-A polynomial driver
- **Type:** IMPL · **Size:** S
- **Inputs:** R03
- **Output:** exact_rescale.rs (`fn exact_round_rescale_poly(&[Vec<u64>] main, &[Vec<u64>] aux) -> Vec<Vec<u64>>`)
- **Gate:** N-coefficient loop == N calls of R03 (U512 oracle on 3 random polys per config); AUX buffers dropped (return type carries MAIN lanes only); zero float.

## NODE-R05 — R-path-B: unified_rescale on a manufactured profile
- **Type:** WIRE · **Size:** M
- **Inputs:** unified_rescale.rs (M06), `params/manufactured.rs`, `secure_configs.rs`
- **Output:** `secure_configs.rs` (new `manufactured_128_deep()` with `Q = t·∏D_i`, `D_i = c·t+1` star lanes), `exact_rescale.rs` (`fn manufactured_rescale_poly` delegating to `RescaleChain`)
- **Gate:** `RescaleChain::new` accepts the chain (does NOT refuse); `two_exits_are_one_primitive`-style test on the new chain; U512 oracle equality with R03 on the manufactured chain (both paths must agree exactly where both apply); zero float.
- **Notes:** This path only applies to chains with `t | Q`. It is kept as a second exact route; S02 re-screens the manufactured tuple.

## NODE-R06 — Rescale decision gate (math decides)
- **Type:** GATE · **Size:** S
- **Inputs:** R03/R04 (path A), R05 (path B), U512 oracle
- **Output:** `executioner_dag.md` (this file, appended table)
- **Gate:** table with, per config: path applicability, oracle exactness (must be 100% for any path kept), per-coefficient integer op count (u128 mulmods, base-ext calls), measured ns/coeff (release). **Rule:** keep every path that is 100% exact; the production default is the exact path with the lowest measured cost per config; the other remains as cross-check oracle. No path is deleted for being slower.

---

## E — Evaluator integration (T1.4): mod-Q in, mod-Q out, AUX transient

## NODE-E01 — Transient extension of a mod-Q ciphertext
- **Type:** IMPL · **Size:** S
- **Inputs:** M02, M04
- **Output:** `crates/nine65/src/ops/exact_mul.rs` (new; `struct TransientPoly { main: Vec<Vec<u64>>, aux: Vec<Vec<u64>> }`, `fn extend_ct(ct:&RNSCiphertext, ext:&MainOnlyBaseExt) -> (TransientPoly, TransientPoly)`)
- **Gate:** for each coefficient, `aux[j][k] == X_k mod a_j` with `X_k` the U512 canonical value of the mod-Q coefficient (U512 oracle); `TransientPoly` is `!Serialize` (no serde derive) and has a `Drop` that zeroizes `aux`; zero float.
- **Pseudocode:**
```
fn extend_poly(main:&[Vec<u64>], ext:&MainOnlyBaseExt) -> TransientPoly:
    for k in 0..N: r[i]=main[i][k]; ext.project(&r,&mut o)?; aux[j][k]=o[j]
    TransientPoly{main: main.clone(), aux}
```

## NODE-E02 — Tensor in MAIN∪AUX
- **Type:** IMPL · **Size:** M
- **Inputs:** E01, existing NTT engines per prime (`self.dual_rns.main/anchor` NTT tables — reuse `anchor_engines[j]` (rns_fhe.rs:2965) as AUX engines; they exist because AUX == canonical anchor primes)
- **Output:** exact_mul.rs (`fn tensor(a:&(TP,TP), b:&(TP,TP)) -> (TP,TP,TP)  // d0,d1,d2`)
- **Gate:** U512 oracle: each lane of `d_i` equals (exact negacyclic product of the U512 lifts) mod that lane, for random ciphertext pairs per config; zero float.
- **Pseudocode:** `d0=c0a*c0b; d1=c0a*c1b+c1a*c0b; d2=c1a*c1b` per lane via NTT mul; MAIN via existing main engines, AUX via existing anchor engines.

## NODE-E03 — Order A: rescale-then-relin (mod-Q evk)
- **Type:** IMPL · **Size:** M
- **Inputs:** E02, R04, `relinearize` (rns_fhe.rs:1874, mod-Q gadget), `RNSEvalKey`
- **Output:** exact_mul.rs (`fn mul_exact_order_a(ct1,ct2,evk) -> Result<RNSCiphertext>`)
- **Gate:** decrypt(mul_exact_order_a(enc(m1),enc(m2))) == m1·m2 mod t for 200 seeded pairs per config; residues bit-identical to U512 BFV oracle (G02); output has exactly `main.len()` lanes; zero float.
- **Pseudocode:**
```
(a0,a1)=extend_ct(ct1); (b0,b1)=extend_ct(ct2)
(d0,d1,d2)=tensor(...)
r0=exact_round_rescale_poly(d0); r1=...(d1); r2=...(d2)      // each → MAIN lanes only
(c0,c1)=relinearize_modq(r0,r1,r2,evk)                        // existing mod-Q gadget relin
drop(d*,a*,b*)  // TransientPoly zeroizes aux
RNSCiphertext{c0,c1,level}
```

## NODE-E04 — Order B: relin-in-AUX then rescale (evk base-extended)
- **Type:** IMPL · **Size:** M
- **Inputs:** E02, R04, E01 (extend evk limbs), `relinearize_dual` logic (M03)
- **Output:** exact_mul.rs (`fn mul_exact_order_b(ct1,ct2,evk) -> Result<RNSCiphertext>`)
- **Gate:** same as E03; additionally evk extension is recomputed per call (never cached on the key object).
- **Pseudocode:**
```
evk_ext = extend each rlk_i limb (canonical < Q) via E01
(d0,d1,d2)=tensor(...)
(e0,e1)=relin_in_main_aux(d2, evk_ext)   // gadget decompose d2 (MAIN∪AUX), dot with evk_ext
c0_pre=d0+e0; c1_pre=d1+e1               // lane-wise MAIN∪AUX
c0=exact_round_rescale_poly(c0_pre); c1=...(c1_pre)
```

## NODE-E05 — `mul_no_relin` exact (degree-2 output)
- **Type:** IMPL · **Size:** S
- **Inputs:** E02, R04
- **Output:** exact_mul.rs (`fn mul_no_relin_exact -> Result<RNSCiphertextDeg2>`)
- **Gate:** `decrypt_degree2` == m1·m2; residues == oracle.

## NODE-E06 — Route selection + public API
- **Type:** WIRE · **Size:** S
- **Inputs:** E03, E04, R06 outcome
- **Output:** `rns_fhe.rs` (`pub fn mul_exact(&self, ct1:&RNSCiphertext, ct2:&RNSCiphertext, evk:&RNSEvalKey) -> Nine65Result<RNSCiphertext>` delegating to the R06/E-gate winner; `MulRoute::ExactDerivedTransient` variant in `mul_route()`), `lib.rs` re-export
- **Gate:** no public API accepts or returns `TransientPoly`; `cargo doc` shows only mod-Q types on the signature; existing `mul`/`mul_dual_*` untouched and still green.

---

## G — Gates (T1.5): differential, wire, source, capacity, noise

## NODE-G01 — U512 BFV reference oracle
- **Type:** TEST · **Size:** M
- **Inputs:** M01
- **Output:** `crates/nine65/tests/exact_mul_oracle.rs` (`mod oracle { fn lift(ct)->Vec<U512>; fn negacyclic_mul_u512; fn round_t_over_q; fn to_residues }`)
- **Gate:** oracle self-check: `to_residues(lift(ct)) == ct`; oracle multiply of `enc(m1),enc(m2)` decrypts (via U512 arithmetic + centered reduce) to `m1·m2`; **test-only** (`#[cfg(test)]` / tests dir), never linked into lib.

## NODE-G02 — Differential: exact route vs oracle (bit-identical residues)
- **Type:** TEST · **Size:** M
- **Inputs:** G01, E03, E04, E05
- **Output:** exact_mul_oracle.rs
- **Gate:** for every named config admitted (128_deep/192/256) AND secure_128/hardware_opt (3-lane; exact mul does not need public refresh so these are admitted here): 500 seeded pairs + edge plaintexts {0,1,t−1,t/2} + rounding-tie neighborhoods: `mul_exact_order_a`, `_b`, `mul_no_relin_exact` residues **bit-identical** to oracle; decrypt == tracked plaintext oracle.

## NODE-G03 — Differential-B: exact route vs existing dual route
- **Type:** TEST · **Size:** S
- **Inputs:** G02, M03
- **Output:** exact_mul_oracle.rs
- **Gate:** `mul_exact_*` output (mod-Q) == MAIN lanes of `mul_dual_public` output on identical inputs/keys (dual path is a second independent implementation). Any mismatch is a finding, not a tolerance.

## NODE-G04 — Noise measurement per order
- **Type:** TEST · **Size:** S
- **Inputs:** E03, E04, `noise/budget.rs` (millibits, exact integer)
- **Output:** exact_mul_oracle.rs + table appended here
- **Gate:** post-mul noise (exact integer, from decrypt residual) reported per order per config; repeated multiply until first decrypt failure → measured exact depth per order; **no float**; numbers appended to this DAG. Feeds E06 selection.

## NODE-G05 — WIRE-Q serialization gate
- **Type:** TEST · **Size:** S
- **Inputs:** M04, M08, E06
- **Output:** `crates/nine65/tests/wire_q_gate.rs`
- **Gate:** (a) serde roundtrip of `RNSPublicKey`, `RNSEvalKey`, `RNSCiphertext` (fresh, after add, after `mul_exact`) — lane count == `main.len()` and every lane modulus ∈ `config.primes`; (b) a `WireInspector::assert_only_q_divisors(bytes, &config)` helper that **rejects** `DualRNSCiphertext::to_bytes()` output; (c) `TransientPoly` fails to compile with `serde::Serialize` (compile-fail test via `trybuild` or a `static_assertions` negative bound). Green only when E06 emits main-only.

## NODE-G06 — Source/call-graph gate
- **Type:** GATE · **Size:** S
- **Inputs:** M09, exact_mul.rs, exact_rescale.rs
- **Output:** `scripts/check_residue_native_architecture.py` (extended), `scripts/check_exact_mul_callgraph.py` (new)
- **Gate:** production call graph of `mul_exact*`/`exact_round_rescale*` contains none of: `garner`, `mixed_radix`, `to_u256_level`, `reconstruct`, `crt_reconstruct_*`, `f32|f64`, `BaseExt::project` (the redundant-lane one), `.anchor` field reads on `RNSCiphertext`; comment-only matches (e.g. "Garner coefficient" in docs) are whitelisted by an explicit allowlist with line refs. Runs in CI.

## NODE-G07 — Capacity gate is executable
- **Type:** TEST · **Size:** XS
- **Inputs:** R01, E06
- **Output:** exact_mul_oracle.rs
- **Gate:** constructing the exact route with a truncated AUX (3 lanes) returns `Err(CapacityUncertified)` before any arithmetic; never a wrong result.

---

## W — Retire the anchor from every wire (WIRE-Q enforcement)

## NODE-W01 — fhe-service wire → mod-Q types
- **Type:** WIRE · **Size:** M
- **Inputs:** `fhe-service/src/{wire.rs,session.rs,handlers.rs}`, M04, E06
- **Output:** same files
- **Gate:** `Session` holds `RNSFullKeySet` (mod-Q); `encrypt/evaluate/decrypt` handlers exchange `RNSCiphertext` bytes; `wire.rs` MAX_CIPHERTEXT_FIELD_LEN recomputed for main-only (`2 polys × lanes × N × 8 × 4/3`); fhe-service 22 tests green; a new test serializes one ciphertext from `/encrypt` and passes `WireInspector`.

## NODE-W02 — Public/eval key export is main-only
- **Type:** WIRE · **Size:** S
- **Inputs:** rns_fhe.rs key types, G05
- **Output:** rns_fhe.rs (`impl DualRNSPublicKey { fn to_wire(&self)->RNSPublicKey }`, same for eval key: strips anchor; the dual struct itself loses `Serialize`)
- **Gate:** `DualRNSPublicKey`/`DualRNSFullKeySet` no longer derive `serde::Serialize`; only `to_wire()` products serialize; G05 green.

## NODE-W03 — Dual path demoted to internal/oracle
- **Type:** WIRE · **Size:** S
- **Inputs:** M03
- **Output:** rns_fhe.rs (`#[doc(hidden)]`/`pub(crate)` on `mul_dual_*`, `DualRNSCiphertext` serde behind `cfg(test)`), `docs/CLAIM_SURFACE_AND_LIMITS` updated
- **Gate:** no `pub` API returns a serializable dual object; G03 still uses it as oracle under `cfg(test)`.

---

## S — Security binding

## NODE-S01 — Estimator on the exact wire modulus
- **Type:** TEST · **Size:** XS
- **Inputs:** `security_estimator.rs`, `secure_configs.rs`
- **Output:** secure_configs.rs tests
- **Gate:** `screened_levels_for_named_configs` asserts the screened `log2(q)` equals the bit length of `∏ config.primes` **and** that no AUX prime is included; unchanged numbers (90/119/146/175) re-asserted.

## NODE-S02 — Re-screen any manufactured chain (R05)
- **Type:** TEST · **Size:** XS
- **Inputs:** R05, S01
- **Gate:** the manufactured tuple's Core-SVP and MATZOV screening recorded here; if below its name, the profile is renamed to its screened level (no over-claim).

## NODE-S03 — secure_256 MATZOV gap (240 < 256): recut, do not rename
- **Type:** IMPL · **Size:** M
- **Inputs:** secure_configs.rs, `canonical_anchor_primes_for_n(16384)` (10 lanes, A₁₀≈2^315), estimator
- **Output:** secure_configs.rs (`secure_256()` recut to the smallest `Q` that clears 256 under **both** Core-SVP and MATZOV at n=16384; candidate: drop to 5 lanes ≈2^146 already screens 288/288 as secure_192's chain — verify at n=16384 with t and Δ headroom), R01 recertified, G02 rerun
- **Gate:** `screened_security_dual()` ≥ 256 on both models; R01 capacity still certified with A₁₀; G02/G04 green on the recut chain; the constructor doc gap note removed only when the number clears.
- **Notes:** This is the "no tradeoff" node: the chain moves, the name stays. If no 16384 chain clears 256/MATZOV with Δ headroom, the finding is recorded here with the exact shortfall — that is a result, not a hedge.

---

## C — Track 2 remainder: hardware constant-time evidence (`decide_ct`)

## NODE-C01 — Disassembly evidence
- **Type:** GATE · **Size:** S
- **Inputs:** `compare_bit.rs` (branch codex/track-2…), release build
- **Output:** `scripts/ct_disasm.sh`, `docs/CT_EVIDENCE_compare_bit_<arch>.md`
- **Gate:** `objdump -d` (or `cargo asm`) of `CompareBit::decide_ct` and `U256::ge_mask_ct` on x86-64: zero `div/idiv`, zero conditional branches whose predicate derives from a residue/lane value (allowlist: loop counters bounded by `lane_count`, a public constant); `black_box` barriers present in asm. Same on aarch64 if a runner exists; otherwise the doc states "x86-64 only" explicitly.
- **Pseudocode:** `cargo rustc -p nine65 --release --features allow_insecure -- --emit=asm`; `grep -nE "\b(div|idiv|jcc-family)\b" <fn body>` → must be empty except allowlisted.

## NODE-C02 — Two-class timing (dudect-style, exact integer statistics)
- **Type:** TEST · **Size:** M
- **Inputs:** M07
- **Output:** `crates/nine65/tests/ct_timing_compare_bit.rs` (`#[ignore]`), `docs/CT_EVIDENCE_…md`
- **Gate:** classes: {X near 0, X near M/2, X near M, random}; ≥ 1e6 samples each via `rdtsc`/`Instant`; **Welch t computed in exact integer/rational arithmetic (nexgen_rational)** — no f64; |t| < 4.5 on this box recorded as "shared-container, indicative"; the doc names the CPU model. A dedicated-hardware rerun is a listed follow-up node C03, not a substitute for running C02 now.

## NODE-C03 — Dedicated-hardware rerun
- **Type:** GATE · **Size:** XS · **Status:** PENDING (needs a pinned-CPU host)
- **Gate:** C02 rerun with pinned affinity, governor=performance, results appended; until then C02's result is labeled indicative in `docs/TRACK2_D2_FIXED_WORK_DECRYPT.md`.

---

## X — #95: secret-dependent displaced quotient under public refresh (the wall)

Problem, exactly: public bootstrap must compute `floor((c0 + c1·s)/Δ)`-type corrections; the quotient `K_s = floor((c0 + c1·s)/Q)` depends on `s` and is currently dropped ("Phase 1 does not yet propagate the secret-dependent displaced quotient/carry"), producing wrong-but-plausible outputs; fail-closed today. Three routes; all built; math decides.

## NODE-X01 — Route α: eliminate the need for `K_s` by exact rescale before refresh
- **Type:** IMPL · **Size:** M
- **Inputs:** R04, `ops/bootstrap.rs`, `bootstrap/clockwork.rs`
- **Output:** `crates/nine65/src/bootstrap/displaced_state.rs` (`fn refresh_input_normalize`)
- **Gate:** hypothesis test: with `mul_exact` (no rounding drift) feeding refresh, measure whether the dropped `K_s` is identically zero on admitted configs (it is a rounding-carry artifact if so). Test: 500 refreshes per config; count `K_s ≠ 0` **computed in-test with sk** (test-only) → if 0/500, route α closes #95 for those configs and `ensure_public_refresh_supported` widens; else record the exact distribution of `K_s` here.

## NODE-X02 — Route β: carry `K_s` under encryption as a winding ciphertext
- **Type:** IMPL · **Size:** L
- **Inputs:** X01 distribution, `keys/bootstrap.rs`, `bootstrap/three_lock.rs`
- **Output:** displaced_state.rs (`struct EncryptedWinding`, `fn refresh_with_encrypted_winding`)
- **Gate:** exact roundtrip on admitted configs; WIRE-Q holds (the winding ciphertext is mod-Q); depth cost measured in exact millibits (G04 harness).
- **Pseudocode:**
```
// K_s is small (|K_s| ≤ N·‖s‖₁ ≈ N for ternary s). Encode K_s in plaintext space t' ≥ 2N+1.
// Public party cannot compute K_s, but CAN compute an encryption of it homomorphically:
//   K_s = floor((c0 + c1·s)/Q).  Under the bootstrap key BSK=Enc(s):
//   u = c0 + c1 ⊗ BSK          (homomorphic inner product, mod-Q ct of (c0 + c1·s))
//   K_ct = ExactRescaleHom(u, Q→t')   // homomorphic floor-division by Q using R03's structure:
//          the two base extensions are linear maps over residues ⇒ applicable to ciphertexts lane-wise;
//          the only non-linear step is floor, realized by the bootstrap's own digit extraction.
//   refresh(c) := refresh_phase1(c) + Δ'·K_ct     (add the encrypted carry back)
// Gate cost: one extra homomorphic inner product + one digit extraction.
```

## NODE-X03 — Route γ: encoding migration (BGV modulus-switch exit) removes the quotient
- **Type:** IMPL · **Size:** L
- **Inputs:** unified_rescale `RescaleExit::ModulusReduced` (M06), R05 manufactured chain
- **Output:** displaced_state.rs (`fn refresh_bgv_exit`)
- **Gate:** on a manufactured chain, refresh via modulus-reduction exit needs no `K_s` (the value divides exactly by `Δ` on star lanes: `star_lanes_give_message_transparency_and_the_inverse_by_construction` already proves the algebra); exact roundtrip; depth measured.

## NODE-X04 — #95 decision gate
- **Type:** GATE · **Size:** S
- **Inputs:** X01, X02, X03
- **Output:** this DAG (table), `docs/OPEN_WORK` update, `ensure_public_refresh_supported` widened only for routes/configs that pass
- **Gate:** per config × route: exact roundtrip rate (must be 100% to admit), measured depth after refresh, WIRE-Q status. Every passing route is kept; the fail-closed guard is lifted **only** where a route passes. Public bootstrap tests un-`#[ignore]`d for exactly those (config, route) pairs.

---

## F — Finish

## NODE-F01 — Repo-wide fmt baseline
- **Type:** GATE · **Size:** XS
- **Output:** one commit `cargo fmt --all` (no semantic change; verified by `cargo test` unchanged), so per-PR `fmt --check` is meaningful from then on.

## NODE-F02 — Claim surface + CLAUDE.md
- **Type:** REPORT · **Size:** S
- **Output:** `docs/CLAIM_SURFACE_AND_LIMITS_*.md`, `CLAUDE.md`, `README.md` capability table: exact mod-Q multiply (routes kept), measured depths per order, WIRE-Q enforced, CT evidence status per arch, #95 status per (config, route), secure_256 screening after S03.
- **Gate:** every number cites the test that produced it; no deprecated phrase reappears (`unlimited depth`, `bootstrap-free`, `noise-free multiply`).

## NODE-F03 — Lean registration
- **Type:** REPORT · **Size:** S
- **Output:** `lean4/KElimination/` new module stating §0.3 (two-extension rounded rescale) as a theorem over ℤ with the capacity hypothesis; `lake build` 0 errors; proof may start as a stated lemma with `sorry` **only if** listed in `docs/LEAN_FORMAL_VERIFICATION` as open — record it, don't hide it.

---

## Dependency order (topological)
```
M* (done) → R01 → R02 → R03 → R04 ─┐
                         R05 ───────┼→ R06
E01 → E02 → {E03, E04, E05} ────────┘→ E06
G01 → G02 → G03 ; G04 ; G07                    (after E03/E04)
G05 ; G06 ; W02 → W01 → W03                    (after E06)
S01 → S02 (after R05) ; S03 (after G02 harness exists)
C01 ; C02 → C03                                (independent of R/E; branch codex/track-2…)
X01 (after R04) → X02 ; X03 (after R05) → X04
F01 ; F02 (after everything) ; F03 (after R03)
```
Parallel fronts available immediately: {R01–R04}, {R05}, {E01–E02}, {G01}, {C01–C02}, {S01}, {F01}.

## Gate summary (contract completion checkboxes ↔ nodes)
| Contract gate | Nodes |
|---|---|
| no float in arithmetic/crypto graph | G06 + every node's G2 |
| no Garner/MRC / canonical-X in production multiply | G06 |
| main-only rank agrees with oracle on every vector | M02 (PASS) + G02 |
| both rank paths execute | M02 (PASS) |
| every rescale has chain identity + capacity certificate | R01, R05, G07 |
| multiply + relin bit-identical to bigint oracle | G02, G03 |
| WIRE-Q for all public artifacts | G05, W01–W03 |
| exact full-width key sampling | M05 (PASS) |
| named security targets pass binding estimator | S01–S03 |
| benchmarks only after correctness green | R06, G04 |

---
## CHECKPOINT — 2026-09-13 — DAG authored; execution not started
### Completed This Session
| NODE-ID | Status | Output |
|---|---|---|
| M02 | PASS | crates/nine65/src/arithmetic/main_only_base_ext.rs |
| M05 | PASS | (already on main) |
| M07 | PASS (branch codex/track-2…) | compare_bit.rs, PR #104 comment |
### Next step
Run ultracode against this file starting with the independent fronts listed under "Dependency order". First node to build: NODE-R01.
