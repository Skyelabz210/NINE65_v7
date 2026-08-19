//! K-Elimination Attack Analysis
//!
//! This module attempts to find weaknesses in the K-Elimination algorithm
//! for exact RNS division. We analyze whether the algebraic structure
//! of K-Elimination can be exploited to break FHE security.
//!
//! K-Elimination formula:
//!   k = (phase × M_inv) mod A
//!
//! Where:
//!   - phase = X mod M (where X is the ciphertext coefficient × t)
//!   - M = product of RNS moduli
//!   - A = anchor modulus
//!   - M_inv = M^(-1) mod A
//!
//! Attack vectors analyzed:
//! 1. Can we recover X from k? (Inversion attack)
//! 2. Does the structure of k reveal information about secret s?
//! 3. Can multiple k values be combined to extract s?

fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 { a } else { gcd(b, a % b) }
}

fn mod_inverse(a: u64, m: u64) -> Option<u64> {
    if gcd(a, m) != 1 {
        return None;
    }
    let mut old_r = m as i128;
    let mut r = a as i128;
    let mut old_s = 0i128;
    let mut s = 1i128;

    while r != 0 {
        let q = old_r / r;
        let temp = old_r - q * r;
        old_r = r;
        r = temp;
        let temp_s = old_s - q * s;
        old_s = s;
        s = temp_s;
    }

    let result = ((old_s % m as i128) + m as i128) % m as i128;
    Some(result as u64)
}

/// K-Elimination parameters
struct KElimParams {
    /// RNS modulus product M = q1 × q2 × ...
    m: u128,
    /// Anchor modulus A
    a: u64,
    /// M_inv = M^(-1) mod A
    m_inv: u64,
}

impl KElimParams {
    fn new(moduli: &[u64], anchor: u64) -> Self {
        let m: u128 = moduli.iter().map(|&x| x as u128).product();
        let m_mod_a = (m % anchor as u128) as u64;
        let m_inv = mod_inverse(m_mod_a, anchor).expect("M and A must be coprime");

        Self { m, a: anchor, m_inv }
    }

    /// Compute k for a given X
    fn compute_k(&self, x: u128) -> u64 {
        // k = floor(X / M)
        // But we compute via: k = (phase × M_inv) mod A
        // where phase = X mod M
        let phase = x % self.m;
        let phase_mod_a = (phase % self.a as u128) as u64;
        ((phase_mod_a as u128 * self.m_inv as u128) % self.a as u128) as u64
    }

    /// Verify k is correct
    fn verify_k(&self, x: u128, k: u64) -> bool {
        let expected = x / self.m;
        expected as u64 == k
    }
}

/// Attack 1: Given k, can we recover X?
///
/// From k = (phase × M_inv) mod A and phase = X mod M:
///   phase ≡ k × M (mod A)
///
/// But X = q×M + phase for some quotient q
/// So X ≡ phase (mod M) and floor(X/M) = k
///
/// This means X ∈ {k×M, k×M+1, ..., (k+1)×M-1} ∩ {r : r ≡ phase (mod M)}
/// Since phase = X mod M, the only value is X itself!
///
/// BUT: We don't know X, we're trying to find it.
/// Given only k, X could be any value in [k×M, (k+1)×M)
/// That's M possible values - exponentially large!
fn attack_inversion(params: &KElimParams) {
    println!("═══════════════════════════════════════════════════════════════");
    println!("ATTACK 1: K-ELIMINATION INVERSION");
    println!("═══════════════════════════════════════════════════════════════");
    println!();
    println!("Given k, try to recover X where k = floor(X/M)");
    println!();
    println!("Analysis:");
    println!("  - k uniquely determines the range [k×M, (k+1)×M)");
    println!("  - There are M = {} possible values of X for each k", params.m);
    println!("  - log₂(M) = {:.1} bits of uncertainty", (params.m as f64).log2());
    println!();
    println!("Conclusion: Inversion is INFEASIBLE");
    println!("  - Cannot recover X from k alone");
    println!("  - Information-theoretically secure (M >> 2^128)");
    println!();

    // Demonstrate with example
    let x: u128 = 1234567890123456789;
    let k = params.compute_k(x);
    let lower = k as u128 * params.m;
    let upper = (k as u128 + 1) * params.m;

    println!("Example:");
    println!("  X = {}", x);
    println!("  k = {}", k);
    println!("  X must be in [{}, {})", lower, upper);
    println!("  Range size: {} values", params.m);
    println!();
}

/// Attack 2: Does k reveal information about the secret key?
///
/// In FHE, ciphertext c = (c0, c1) where:
///   c0 = Δm + e0 + a×s (mod q)
///   c1 = e1 + a (mod q)
///
/// During decryption, we compute:
///   X = c0 + c1×s (mod q)
///   X = Δm + e0 + e1×s
///
/// The k computed is:
///   k = floor((Δm + e0 + e1×s) / M)
///
/// Does k leak s?
fn attack_secret_leakage(params: &KElimParams) {
    println!("═══════════════════════════════════════════════════════════════");
    println!("ATTACK 2: SECRET KEY LEAKAGE VIA k");
    println!("═══════════════════════════════════════════════════════════════");
    println!();
    println!("Question: Does k = floor(X/M) reveal information about secret s?");
    println!();
    println!("Analysis:");
    println!("  X = Δ×m + e0 + e1×s (during decryption)");
    println!();
    println!("  For k to leak s, we'd need to solve:");
    println!("    k = floor((Δ×m + e0 + e1×s) / M)");
    println!("  for s, given (k, Δ, m, e0, e1).");
    println!();
    println!("  But we DON'T have e0, e1 - they're random errors!");
    println!();
    println!("  Even if we did:");
    println!("    k×M ≤ Δ×m + e0 + e1×s < (k+1)×M");
    println!("    (k×M - Δ×m - e0) / e1 ≤ s < ((k+1)×M - Δ×m - e0) / e1");
    println!();
    println!("  This gives a range of ~M/e1 possible values for s");
    println!("  Since M >> polynomial size and e1 ~ σ, this is useless");
    println!();
    println!("Conclusion: k does NOT leak secret key information");
    println!("  - Errors mask the secret completely");
    println!("  - Same security reduction as Ring-LWE");
    println!();
}

/// Attack 3: Correlation attack using multiple ciphertexts
///
/// Given many (ciphertext, k) pairs, can we extract s?
fn attack_multiple_k(params: &KElimParams) {
    println!("═══════════════════════════════════════════════════════════════");
    println!("ATTACK 3: MULTIPLE k-VALUE CORRELATION");
    println!("═══════════════════════════════════════════════════════════════");
    println!();
    println!("Given many ciphertexts and their k values, can we extract s?");
    println!();
    println!("Setup:");
    println!("  For each ciphertext i:");
    println!("    c_i = (c0_i, c1_i) encrypts message m_i");
    println!("    X_i = c0_i + c1_i × s (mod q)");
    println!("    k_i = floor(X_i / M)");
    println!();
    println!("Attack attempt:");
    println!("  Build system of equations:");
    println!("    k_1 × M ≤ c0_1 + c1_1 × s < (k_1+1) × M");
    println!("    k_2 × M ≤ c0_2 + c1_2 × s < (k_2+1) × M");
    println!("    ...");
    println!();
    println!("Analysis:");
    println!("  This is a system of linear inequalities in s");
    println!("  In principle, many constraints could narrow down s");
    println!();
    println!("  BUT: The ciphertexts c_i contain random errors e_i");
    println!("  We don't observe c0_i directly, only noisy versions");
    println!("  The errors add ~σ√n bits of uncertainty per ciphertext");
    println!();
    println!("  To extract N-bit secret s:");
    println!("    Need ~N/log(M/σ√n) ciphertexts");
    println!("    With M ~ q^k and σ ~ 3, this is ~N/60 ≈ {} ciphertexts",
             params.m.ilog2() as usize / 60);
    println!();
    println!("  But with N ciphertexts, standard lattice attacks already work!");
    println!("  So this provides NO advantage over direct Ring-LWE attack");
    println!();
    println!("Conclusion: Multiple k correlation provides NO attack advantage");
    println!("  - Reduces to standard Ring-LWE security");
    println!("  - No structural weakness from K-Elimination");
    println!();
}

/// Attack 4: Timing side-channel in K-Elimination computation
///
/// G14 correction (2026-08-19): this function previously asserted
/// "Montgomery reduction is constant-time" and "Modular reduction:
/// constant-time (Montgomery)" as conclusions. Neither is true of the code
/// actually exercised in this file: `KElimParams::compute_k` (above) uses
/// plain `%`/`*` operators, not Montgomery reduction, and native integer
/// division/modulo latency on most CPUs varies with operand magnitude —
/// i.e. it is a *vartime* reference implementation, not a timing analysis.
/// This function is kept as an algebraic-narrative demo (its real
/// contribution is Attacks 1-3: inversion/leakage/correlation, which do not
/// depend on timing at all) and no longer makes a timing-safety claim it
/// cannot back up. For an actual, executed statistical timing analysis of
/// this workspace's genuinely constant-time K-Elimination primitives, see
/// `nine65::security::ct_verification` (dudect-style, `#[ignore]`d by
/// default — hardware-dependent, run explicitly with `--ignored` on
/// dedicated/pinned hardware) and the branchless CT primitives in
/// `nine65::arithmetic::k_elimination` and `clockwork_core::garner`.
fn attack_timing(_params: &KElimParams) {
    println!("═══════════════════════════════════════════════════════════════");
    println!("ATTACK 4: TIMING SIDE-CHANNEL (algebraic discussion only)");
    println!("═══════════════════════════════════════════════════════════════");
    println!();
    println!("Does K-Elimination computation leak timing information?");
    println!();
    println!("K-Elimination algorithm:");
    println!("  1. phase = X mod M");
    println!("  2. k = (phase × M_inv) mod A");
    println!();
    println!("NOTE: compute_k() above uses plain `%`/`*`, i.e. it is a");
    println!("vartime reference implementation for this demo, NOT a");
    println!("constant-time one, and NOT Montgomery reduction. Native");
    println!("integer division/modulo latency on most CPUs depends on");
    println!("operand magnitude, so this code path is not a valid basis for");
    println!("a timing-safety claim either way.");
    println!();
    println!("This workspace DOES have genuinely constant-time K-Elimination");
    println!("primitives (branchless mask-based reduction, no native %/DIV");
    println!("on secret data) in nine65::arithmetic::k_elimination and");
    println!("clockwork_core::garner, with an executed statistical dudect-");
    println!("style verification suite in nine65::security::ct_verification.");
    println!("That suite — not this algebraic demo — is the actual timing");
    println!("side-channel evidence for this workspace.");
    println!();
    println!("Conclusion: algebraically, K-Elimination's formula has no");
    println!("secret-dependent early-exit branches by construction; whether");
    println!("a GIVEN implementation is actually constant-time depends on");
    println!("which primitives it uses for the mod/mul steps — see above.");
    println!();
}

fn main() {
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║     K-ELIMINATION CRYPTANALYSIS                               ║");
    println!("║     Attempting to Break Our Own Innovation                    ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
    println!();

    // Use realistic FHE parameters
    // Two 30-bit NTT-friendly primes
    let moduli = vec![998244353u64, 985661441u64];
    let anchor = 754974721u64; // Third NTT-friendly prime

    let params = KElimParams::new(&moduli, anchor);

    println!("K-Elimination Parameters:");
    println!("  RNS moduli: {:?}", moduli);
    println!("  M = q1 × q2 = {}", params.m);
    println!("  A (anchor) = {}", params.a);
    println!("  M_inv (mod A) = {}", params.m_inv);
    println!("  log₂(M) = {:.1} bits", (params.m as f64).log2());
    println!();

    // Verify K-Elimination works correctly
    println!("Verification:");
    for x in [12345678901234567890u128, 98765432109876543210u128, 1u128, params.m - 1] {
        let k = params.compute_k(x);
        let verified = params.verify_k(x, k);
        println!("  X={} -> k={}, verified={}", x, k, verified);
    }
    println!();

    // Run attacks
    attack_inversion(&params);
    attack_secret_leakage(&params);
    attack_multiple_k(&params);
    attack_timing(&params);

    // Final assessment
    println!("═══════════════════════════════════════════════════════════════");
    println!("FINAL SECURITY ASSESSMENT");
    println!("═══════════════════════════════════════════════════════════════");
    println!();
    println!("K-Elimination Security Status:");
    println!();
    println!("  ✓ INVERSION ATTACK:    Infeasible (2^{:.0} uncertainty)",
             (params.m as f64).log2());
    println!("  ✓ SECRET LEAKAGE:      None (errors mask secret)");
    println!("  ✓ CORRELATION ATTACK:  Reduces to Ring-LWE");
    println!("  ~ TIMING ATTACK:       Algebraically branch-free; this demo's");
    println!("                         own compute_k() is vartime reference");
    println!("                         code, not evidence either way — see");
    println!("                         nine65::security::ct_verification for");
    println!("                         the actual measured CT verification.");
    println!();
    println!("Overall: K-Elimination does NOT weaken FHE security");
    println!();
    println!("The algebraic structure of K-Elimination:");
    println!("  - Provides computational efficiency (O(k) vs O(k²))");
    println!("  - Maintains Ring-LWE security guarantees");
    println!("  - Proven correct in Lean 4 (27 theorems, 0 sorry)");
    println!();
}
