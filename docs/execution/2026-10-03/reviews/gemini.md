# Gemini source review

Unaccepted reviewer suggestions; see REVIEW_DISPOSITIONS.md.

### 1. Concrete Source Contradictions & Gaps

*   **Logic Contradiction (Quotient vs. Remainder):**
    *   `nist/shadow_nist_tests.py:72`: Defines shadow as the **quotient** (`V // m_s`).
    *   `lean4/shadow-nist/ShadowUniform.lean:99`: The formal proof `shadow_uniform_distribution` actually checks `v.val % m2 == s.val`, proving the **remainder** is uniform.
    *   **Gap:** The project harvests the quotient but proves the remainder.
*   **Proof Tautology:**
    *   `lean4/shadow-nist/ShadowNISTCompliance.lean:138-146`: `nist_compliance` is defined as `True := trivial` by assuming all precursors are `True`. It provides no formal connection between mathematical bounds and NIST p-value thresholds.
*   **Axiomatic Dependency:**
    *   `lean4/shadow-nist/ShadowSecurityTheorems.lean:97`: `func_of_indep_is_indep` is an `axiom`. The core security claim (independence) is assumed rather than derived from Lean's probability primitives.
*   **Elided Implementation:**
    *   `lean4/shadow-nist/ShadowSecurityTheorems.lean:134`: `shadow_independence` uses `by trivial` with a comment stating "computational details elided." This bypasses the actual logic of modular multiplication.
*   **Entropy Estimation Gap:**
    *   `nist/shadow_nist_tests.py:53`: `bits_per_shadow` is set to `m.bit_length() - 1` as a "conservative" estimate. There is no source evidence or proof that this truncation preserves the uniform properties claimed in line 48.

### 2. Implementable Work Tickets

**Ticket 1: Formal Quotient Uniformity Proof**
*   **Target:** `lean4/shadow-nist/ShadowUniform.lean`
*   **Negative Test:** Attempt to prove uniformity for `v // m2` where `v` is restricted to a range not multiple of `m2`.
*   **Done Condition:** Theorem `shadow_uniform_distribution` updated to use `v.val / m2` and verified by Lean compiler.

**Ticket 2: Entropy Source Linkage Verification**
*   **Target:** `crates/nine65/src/entropy/crt_shadow.rs:390`
*   **Negative Test:** Modify `mul_with_shadows` to return `prod % p` as the shadow; verify NIST tests fail or Lean model mismatches.
*   **Done Condition:** Add a doc-test linking the Rust `quotient` calculation to the Lean `L004` theorem symbol.

**Ticket 3: Axiom Replacement (Independence)**
*   **Target:** `lean4/shadow-nist/ShadowSecurityTheorems.lean`
*   **Negative Test:** Define two RVs sharing a seed; ensure the `Independent` predicate fails.
*   **Done Condition:** Replace `axiom func_of_indep_is_indep` with a proof using Lean's `MeasureTheory.ProbabilityTheory`.

**Ticket 4: Bit Extraction Soundness**
*   **Target:** `nist/shadow_nist_tests.py:75`
*   **Negative Test:** Pass a non-uniform shadow to `generate_shadow_bits`; verify `Frequency Test` (line 83) detects the bias.
*   **Done Condition:** Implement a formal lemma in Lean showing bit-slicing a uniform integer in $[0, 2^k)$ yields independent Bernoulli(0.5) bits.

**Ticket 5: NIST Bridge Theorem**
*   **Target:** `lean4/shadow-nist/ShadowNISTCompliance.lean`
*   **Negative Test:** Set a mock p-value to 0.009; ensure the compliance theorem cannot be closed.
*   **Done Condition:** Redefine `nist_compliance` to take an empirical p-value vector and prove `p > 0.01` implies compliance.

### 3. Unknowns

*   **Input Distribution:** The NIST test uses `secrets.randbelow(M)` (line 67) for the product `V`. In the live implementation (`crt_shadow.rs:386`), `prod` is `a * b`. It is unknown if the product of two uniform variables $[0, p)$ yields a quotient with the same entropy as a single uniform variable $[0, p^2)$.
*   **Modulus Coprimality:** `shadow_nist_tests.py:59` uses `m` and `m+1`. The live implementation uses `self.moduli`. It is unknown if the live moduli are guaranteed to be coprime in all execution paths.
*   **Harvesting Efficiency:** The "conservative" use of `m.bit_length() - 1` (line 53) suggests lost entropy. The exact fraction of discarded vs. harvested entropy is unquantified.
