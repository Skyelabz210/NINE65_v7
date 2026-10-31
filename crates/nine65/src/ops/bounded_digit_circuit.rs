//! Split-encoding bounded digit extraction for a coherent encrypted slot pair.
//!
//! For `x = r + p*k`, `|r| <= B`, put `G(X)=prod_{j=-B}^B(X-j)` and
//! interpolate `H(r)=1/G'(r)` over F_p. Taylor expansion modulo p² proves
//! `G(x)/p = k*G'(r) mod p`. Evaluate G at p², reinterpret its proved
//! multiple of p at p, evaluate H from the coherent p view, and multiply.
//! This avoids evaluating H, or the final product, at the noisier p² scale.
//! Since `2N | p-1`, the plaintext CRT is invertible modulo p. Vanishing
//! of G in every slot modulo p therefore proves that ALL ring coefficients
//! of G are multiples of p; the encoding reinterpretation applies to the
//! whole ciphertext, not merely to one observed scalar or one chosen slot.
//!
//! This crate-private building block does not authenticate its input history.
//! Its caller MUST establish matching slot order/key/epoch, coherent x views,
//! the radius at EVERY slot, and both coefficient phase-error bounds. A
//! parameter-only plan is not production-refresh admission.

use std::collections::BTreeMap;

use crate::arithmetic::wide::U1024;
use crate::arithmetic::RNSPolynomial;
use crate::errors::{Nine65Error, Nine65Result};
#[cfg(test)]
use crate::ops::rns_fhe::exact_mul::RNSHybridGadgetKey;
use crate::ops::rns_fhe::exact_mul::{ExactMulError, ExactMulEvaluator, PreparedHybridGadgetKey};
use crate::ops::rns_fhe::{RNSCiphertext, RNSFHEContext};
use crate::ops::rns_galois::validate_main;
use crate::params::is_prime;

#[cfg(test)]
#[path = "protected_adjacent_view_tests.rs"]
mod protected_adjacent_view_tests;

fn refused(reason: impl Into<String>) -> Nine65Error {
    Nine65Error::BootstrapFailed {
        reason: reason.into(),
    }
}

fn checked(value: Option<U1024>) -> Nine65Result<U1024> {
    value.ok_or_else(|| refused("split-digit public error bound exceeds U1024"))
}

fn centered(value: u64, modulus: u64) -> i64 {
    if value <= modulus / 2 {
        value as i64
    } else {
        value as i64 - modulus as i64
    }
}

fn polynomial_product(a: &[u64], b: &[u64], modulus: u64) -> Vec<u64> {
    let mut out = vec![0; a.len() + b.len() - 1];
    for (i, &x) in a.iter().enumerate() {
        for (j, &y) in b.iter().enumerate() {
            out[i + j] = ((out[i + j] as u128 + x as u128 * y as u128) % modulus as u128) as u64;
        }
    }
    out
}

fn polynomial_value(poly: &[u64], x: u64, modulus: u64) -> u64 {
    poly.iter().rev().fold(0, |value, &coefficient| {
        ((value as u128 * x as u128 + coefficient as u128) % modulus as u128) as u64
    })
}

fn power_mod(mut a: u64, mut e: u64, modulus: u64) -> u64 {
    let mut out = 1;
    while e != 0 {
        if e & 1 != 0 {
            out = (out as u128 * a as u128 % modulus as u128) as u64;
        }
        a = (a as u128 * a as u128 % modulus as u128) as u64;
        e >>= 1;
    }
    out
}

/// The finite value/derivative identities prove the formula for EVERY k.
fn polynomials(p: u64, radius: usize) -> Nine65Result<(Vec<u64>, Vec<u64>)> {
    if !(3..=65_537).contains(&p)
        || !is_prime(p)
        || radius == 0
        || radius > 128
        || 2 * radius as u64 >= p
    {
        return Err(refused(
            "split digit needs prime 3<=p<=65537 and 1<=B<=128, 2B<p",
        ));
    }
    let modulus = p * p;
    let mut g = vec![1];
    for r in -(radius as i64)..=radius as i64 {
        g = polynomial_product(&g, &[(-r).rem_euclid(modulus as i64) as u64, 1], modulus);
    }
    let mut h = vec![0; g.len() - 1];
    for r in -(radius as i64)..=radius as i64 {
        let root = r.rem_euclid(p as i64) as u64;
        let mut quotient = vec![0; g.len() - 1];
        let last = quotient.len() - 1;
        quotient[last] = g[g.len() - 1] % p;
        for i in (0..last).rev() {
            quotient[i] =
                ((g[i + 1] as u128 + root as u128 * quotient[i + 1] as u128) % p as u128) as u64;
        }
        let derivative = polynomial_value(&quotient, root, p);
        if derivative == 0 {
            return Err(refused("split-digit support has a repeated root"));
        }
        let inverse = power_mod(derivative, p - 2, p);
        let inverse_squared = (inverse as u128 * inverse as u128 % p as u128) as u64;
        for (value, &coefficient) in h.iter_mut().zip(&quotient) {
            *value = ((*value as u128 + coefficient as u128 * inverse_squared as u128) % p as u128)
                as u64;
        }
    }
    let derivative: Vec<_> = g
        .iter()
        .enumerate()
        .skip(1)
        .map(|(i, &c)| (i as u128 * c as u128 % p as u128) as u64)
        .collect();
    for r in -(radius as i64)..=radius as i64 {
        let root = r.rem_euclid(p as i64) as u64;
        if polynomial_value(&g, r.rem_euclid(modulus as i64) as u64, modulus) != 0
            || polynomial_value(&derivative, root, p) as u128
                * polynomial_value(&h, root, p) as u128
                % p as u128
                != 1
        {
            return Err(refused(
                "split-digit polynomial value/derivative certificate failed",
            ));
        }
    }
    if h.iter().enumerate().any(|(i, &c)| i % 2 == 1 && c != 0) {
        return Err(refused("split-digit H polynomial is not even"));
    }
    while h.len() > 1 && h.last() == Some(&0) {
        h.pop();
    }
    Ok((g, h))
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Node {
    Input,
    Constant(i64),
    Add(usize, usize),
    Scale(usize, i64),
    Product(usize, usize),
}

impl Node {
    fn inputs(&self) -> Vec<usize> {
        match *self {
            Self::Add(a, b) | Self::Product(a, b) => vec![a, b],
            Self::Scale(a, _) => vec![a],
            _ => vec![],
        }
    }
}

struct Dag {
    modulus: u64,
    nodes: Vec<Node>,
    memo: BTreeMap<Node, usize>,
}

impl Dag {
    fn new(modulus: u64) -> Self {
        Self {
            modulus,
            nodes: vec![Node::Input],
            memo: BTreeMap::new(),
        }
    }
    fn push(&mut self, node: Node) -> usize {
        if let Some(&index) = self.memo.get(&node) {
            return index;
        }
        let index = self.nodes.len();
        self.nodes.push(node.clone());
        self.memo.insert(node, index);
        index
    }
    fn constant(&mut self, c: i64) -> usize {
        self.push(Node::Constant(centered(
            c.rem_euclid(self.modulus as i64) as u64,
            self.modulus,
        )))
    }
    fn product(&mut self, a: usize, b: usize) -> usize {
        self.push(Node::Product(a.min(b), a.max(b)))
    }
    fn add(&mut self, a: usize, b: usize) -> usize {
        self.push(Node::Add(a.min(b), a.max(b)))
    }
    fn scale(&mut self, a: usize, c: u64) -> usize {
        let c = centered(c, self.modulus);
        if c == 1 {
            a
        } else {
            self.push(Node::Scale(a, c))
        }
    }
    fn power(&mut self, a: usize, e: usize) -> usize {
        if e == 0 {
            return self.constant(1);
        }
        if e == 1 {
            return a;
        }
        let left = self.power(a, e / 2);
        let right = self.power(a, e - e / 2);
        self.product(left, right)
    }
    fn combine(&mut self, values: &[usize], product: bool) -> usize {
        if values.is_empty() {
            return self.constant(if product { 1 } else { 0 });
        }
        if values.len() == 1 {
            return values[0];
        }
        let middle = values.len() / 2;
        let a = self.combine(&values[..middle], product);
        let b = self.combine(&values[middle..], product);
        if product {
            self.product(a, b)
        } else {
            self.add(a, b)
        }
    }
    fn symbolic(&self, output: usize) -> Vec<u64> {
        let mut values: Vec<Vec<u64>> = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            let mut value = match *node {
                Node::Input => vec![0, 1],
                Node::Constant(c) => vec![c.rem_euclid(self.modulus as i64) as u64],
                Node::Scale(a, c) => values[a]
                    .iter()
                    .map(|&x| (x as i128 * c as i128).rem_euclid(self.modulus as i128) as u64)
                    .collect(),
                Node::Product(a, b) => polynomial_product(&values[a], &values[b], self.modulus),
                Node::Add(a, b) => {
                    let mut sum = vec![0; values[a].len().max(values[b].len())];
                    for (i, &x) in values[a].iter().enumerate() {
                        sum[i] = x;
                    }
                    for (i, &x) in values[b].iter().enumerate() {
                        sum[i] = (sum[i] + x) % self.modulus;
                    }
                    sum
                }
            };
            while value.len() > 1 && value.last() == Some(&0) {
                value.pop();
            }
            values.push(value);
        }
        values[output].clone()
    }
}

fn circuits(p: u64, radius: usize) -> Nine65Result<(Dag, usize, Dag, usize)> {
    let (g, h) = polynomials(p, radius)?;
    let mut high = Dag::new(p * p);
    let y = high.product(0, 0);
    let mut factors = vec![0];
    for r in 1..=radius {
        let constant = high.constant(-((r * r) as i64));
        factors.push(high.add(y, constant));
    }
    let go = high.combine(&factors, true);
    let mut low = Dag::new(p);
    let y = low.product(0, 0);
    let block = 10.min(radius + 1);
    let giant = low.power(y, block);
    let even: Vec<_> = h.iter().step_by(2).copied().collect();
    let mut chunks = Vec::new();
    for (j, chunk) in even.chunks(block).enumerate() {
        let mut terms = Vec::new();
        for (k, &c) in chunk.iter().enumerate() {
            if c == 0 {
                continue;
            }
            let term = if k == 0 {
                low.constant(centered(c, p))
            } else {
                let power = low.power(y, k);
                low.scale(power, c)
            };
            terms.push(term);
        }
        let mut value = low.combine(&terms, false);
        if j != 0 {
            let power = low.power(giant, j);
            value = low.product(value, power);
        }
        chunks.push(value);
    }
    let ho = low.combine(&chunks, false);
    if high.symbolic(go) != g || low.symbolic(ho) != h {
        return Err(refused(
            "split-digit DAG does not match its certified polynomial",
        ));
    }
    Ok((high, go, low, ho))
}

struct Noise {
    n: u128,
    t: u64,
    q: U1024,
    half: U1024,
    switch: U1024,
}

impl Noise {
    fn new(ctx: &RNSFHEContext, exact: &ExactMulEvaluator<'_>) -> Nine65Result<Self> {
        let certificate = exact.plan().certificate();
        let q = checked(U1024::checked_product_u64s(&ctx.config.primes))?;
        let switch = checked(
            U1024::from_u64(ctx.n as u64)
                .checked_mul_u128(ctx.config.eta as u128 * ((1u128 << certificate.base_bits) - 1)),
        )?;
        let switch = checked(
            switch.checked_mul_u64(certificate.digits_per_lane.iter().sum::<usize>() as u64),
        )?;
        Ok(Self {
            n: ctx.n as u128,
            t: ctx.t,
            q,
            half: q.div_mod_u64(ctx.t).unwrap().0.shr1(),
            switch,
        })
    }
    fn admit(&self, e: U1024) -> Nine65Result<U1024> {
        if e >= self.half {
            Err(refused(format!(
                "split-digit node needs {} error bits, half-Delta has {}",
                e.bit_length(),
                self.half.bit_length()
            )))
        } else {
            Ok(e)
        }
    }
    fn multiply(&self, a: U1024, b: U1024) -> Nine65Result<U1024> {
        self.admit(a)?;
        self.admit(b)?;
        // Both plaintexts are GENERAL slot-encoded ring polynomials. The
        // message l1 term therefore includes N, unlike constant projection.
        let np = self.n * self.t as u128;
        let factor = self.n * ((self.t - 1) / 2) as u128 + np * (self.n / 2 + 1);
        let linear = checked(checked(a.checked_add(b))?.checked_mul_u128(factor))?;
        let exponent = (a.bit_length() + b.bit_length() + (128 - np.leading_zeros()))
            .saturating_sub(self.q.bit_length() - 1);
        let quadratic = if a == U1024::ZERO || b == U1024::ZERO {
            U1024::ZERO
        } else {
            if exponent >= 1024 {
                return Err(refused("split-digit quadratic bound exceeds U1024"));
            }
            let mut limbs = [0; 16];
            limbs[exponent as usize / 64] = 1u64 << (exponent % 64);
            U1024::from_limbs(limbs)
        };
        let rounding = U1024::from_u128((self.n * self.n + self.n + 2) / 2);
        let result = checked(
            checked(checked(linear.checked_add(quadratic))?.checked_add(rounding))?
                .checked_add(self.switch),
        )?;
        self.admit(result)
    }
    fn dag(&self, dag: &Dag, input: U1024) -> Nine65Result<Vec<U1024>> {
        let mut errors: Vec<U1024> = Vec::with_capacity(dag.nodes.len());
        for node in &dag.nodes {
            let error = match *node {
                Node::Input => input,
                Node::Constant(c) => {
                    let numerator =
                        self.q.mod_u64(self.t).unwrap() as u128 * c.unsigned_abs() as u128;
                    U1024::from_u128(numerator.div_ceil(self.t as u128))
                }
                Node::Add(a, b) => checked(errors[a].checked_add(errors[b]))?,
                Node::Scale(a, c) => checked(errors[a].checked_mul_u64(c.unsigned_abs()))?,
                Node::Product(a, b) => self.multiply(errors[a], errors[b])?,
            };
            errors.push(self.admit(error)?);
        }
        Ok(errors)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SplitDigitCertificate {
    #[allow(
        dead_code,
        reason = "Retained for certificate audits and independent node-bound regression tests"
    )]
    pub radius: usize,
    #[allow(
        dead_code,
        reason = "Retained for certificate audits and independent node-bound regression tests"
    )]
    pub high_node_error_bounds: Vec<U1024>,
    #[allow(
        dead_code,
        reason = "Retained for certificate audits and independent node-bound regression tests"
    )]
    pub low_node_error_bounds: Vec<U1024>,
    #[allow(
        dead_code,
        reason = "Retained for certificate audits and independent node-bound regression tests"
    )]
    pub high_product_error: U1024,
    #[allow(
        dead_code,
        reason = "Retained for certificate audits and independent node-bound regression tests"
    )]
    pub low_polynomial_error: U1024,
    pub output_error: U1024,
    pub ciphertext_products: usize,
}

pub(crate) struct SplitDigitEvaluator<'a> {
    high_ctx: &'a RNSFHEContext,
    low_ctx: &'a RNSFHEContext,
    high_exact: ExactMulEvaluator<'a>,
    low_exact: ExactMulEvaluator<'a>,
    high: Dag,
    low: Dag,
    go: usize,
    ho: usize,
    certificate: SplitDigitCertificate,
}

#[derive(Clone, Copy)]
enum GadgetKeyView<'a> {
    #[cfg(test)]
    Raw(&'a RNSHybridGadgetKey),
    Prepared(&'a PreparedHybridGadgetKey),
}

impl GadgetKeyView<'_> {
    fn multiply(
        self,
        exact: &ExactMulEvaluator<'_>,
        a: &RNSCiphertext,
        b: &RNSCiphertext,
    ) -> Result<RNSCiphertext, ExactMulError> {
        match self {
            #[cfg(test)]
            Self::Raw(key) => exact.try_mul_exact(a, b, key),
            Self::Prepared(key) => exact.try_mul_exact_prepared(a, b, key),
        }
    }
}

impl<'a> SplitDigitEvaluator<'a> {
    pub(crate) fn new(
        high: &'a RNSFHEContext,
        low: &'a RNSFHEContext,
        radius: usize,
        high_input_error: U1024,
        low_input_error: U1024,
    ) -> Nine65Result<Self> {
        if low.t.checked_mul(low.t) != Some(high.t)
            || high.n != low.n
            || high.config.primes != low.config.primes
            || high.config.eta != low.config.eta
            || high.n > 32_768
            || high.n < 2
            || (low.t - 1) % (2 * high.n as u64) != 0
        {
            return Err(refused(
                "split-digit contexts need the same N/Q/eta, plaintext p²,p, and 2N dividing p-1",
            ));
        }
        let high_exact = high
            .try_exact_evaluator()
            .map_err(|e| refused(format!("split-digit high arithmetic: {e:?}")))?;
        let low_exact = low
            .try_exact_evaluator()
            .map_err(|e| refused(format!("split-digit low arithmetic: {e:?}")))?;
        let (high_dag, go, low_dag, ho) = circuits(low.t, radius)?;
        let high_noise = Noise::new(high, &high_exact)?;
        let low_noise = Noise::new(low, &low_exact)?;
        let high_bounds = high_noise.dag(&high_dag, high_input_error)?;
        let low_bounds = low_noise.dag(&low_dag, low_input_error)?;
        let output_error = low_noise.multiply(high_bounds[go], low_bounds[ho])?;
        let products = high_dag
            .nodes
            .iter()
            .chain(&low_dag.nodes)
            .filter(|node| matches!(node, Node::Product(..)))
            .count()
            + 1;
        let certificate = SplitDigitCertificate {
            radius,
            high_product_error: high_bounds[go],
            low_polynomial_error: low_bounds[ho],
            high_node_error_bounds: high_bounds,
            low_node_error_bounds: low_bounds,
            output_error,
            ciphertext_products: products,
        };
        Ok(Self {
            high_ctx: high,
            low_ctx: low,
            high_exact,
            low_exact,
            high: high_dag,
            low: low_dag,
            go,
            ho,
            certificate,
        })
    }
    pub(crate) fn certificate(&self) -> &SplitDigitCertificate {
        &self.certificate
    }

    /// Inputs must carry the coherent producer's support/history authority.
    /// The same same-Q hybrid key is valid at both plaintext scales because
    /// its encrypted target is s² and its digit distribution is unchanged.
    #[cfg(test)]
    pub(crate) fn evaluate(
        &self,
        high: &RNSCiphertext,
        low: &RNSCiphertext,
        relin: &RNSHybridGadgetKey,
    ) -> Nine65Result<RNSCiphertext> {
        self.evaluate_with_progress(high, low, relin, &mut |_, _, _| {})
    }

    /// Optional public schedule progress; counters never depend on plaintext.
    #[cfg(test)]
    pub(crate) fn evaluate_with_progress(
        &self,
        high: &RNSCiphertext,
        low: &RNSCiphertext,
        relin: &RNSHybridGadgetKey,
        progress: &mut dyn FnMut(&str, usize, usize),
    ) -> Nine65Result<RNSCiphertext> {
        self.evaluate_key(high, low, GadgetKeyView::Raw(relin), progress)
    }

    /// Reuse one validated transform cache throughout both plaintext scales.
    /// Preparation binds N, Q and the gadget radix; it does not bind p.
    #[cfg(test)]
    pub(crate) fn evaluate_prepared(
        &self,
        high: &RNSCiphertext,
        low: &RNSCiphertext,
        relin: &PreparedHybridGadgetKey,
    ) -> Nine65Result<RNSCiphertext> {
        self.evaluate_prepared_with_progress(high, low, relin, &mut |_, _, _| {})
    }

    pub(crate) fn evaluate_prepared_with_progress(
        &self,
        high: &RNSCiphertext,
        low: &RNSCiphertext,
        relin: &PreparedHybridGadgetKey,
        progress: &mut dyn FnMut(&str, usize, usize),
    ) -> Nine65Result<RNSCiphertext> {
        self.evaluate_key(high, low, GadgetKeyView::Prepared(relin), progress)
    }

    fn evaluate_key(
        &self,
        high: &RNSCiphertext,
        low: &RNSCiphertext,
        relin: GadgetKeyView<'_>,
        progress: &mut dyn FnMut(&str, usize, usize),
    ) -> Nine65Result<RNSCiphertext> {
        validate_main(self.high_ctx, high)?;
        validate_main(self.low_ctx, low)?;
        let g = evaluate_dag(
            self.high_ctx,
            &self.high_exact,
            &self.high,
            self.go,
            high,
            relin,
            "high digit product",
            progress,
        )?;
        let h = evaluate_dag(
            self.low_ctx,
            &self.low_exact,
            &self.low,
            self.ho,
            low,
            relin,
            "low correction polynomial",
            progress,
        )?;
        // Ideal-grid proof: phase=(Q/p²)*(p*z)+E=(Q/p)*z+E mod Q.
        // The same components have unchanged E; no Q mod p² assumption or
        // new rounding step is introduced by this algebraic interpretation.
        progress("quotient product", 0, 1);
        let result = relin
            .multiply(&self.low_exact, &g, &h)
            .map_err(|e| refused(format!("split-digit final product: {e:?}")))?;
        progress("quotient product", 1, 1);
        Ok(result)
    }
}

fn constant_ciphertext(ctx: &RNSFHEContext, c: i64) -> RNSCiphertext {
    let mut c0 = RNSPolynomial::zero(&ctx.rns);
    for (lane, &q) in ctx.config.primes.iter().enumerate() {
        let value = (c as i128 * ctx.delta_rns[lane] as i128).rem_euclid(q as i128) as u64;
        c0.limbs[lane][0] = ctx.rns.mont_contexts[lane].to_montgomery(value);
    }
    RNSCiphertext {
        c0,
        c1: RNSPolynomial::zero(&ctx.rns),
        num_primes: ctx.config.primes.len(),
    }
}

fn scale_ciphertext(ctx: &RNSFHEContext, ct: &RNSCiphertext, c: i64) -> RNSCiphertext {
    let scale = |poly: &RNSPolynomial| RNSPolynomial {
        n: ctx.n,
        limbs: poly
            .limbs
            .iter()
            .zip(&ctx.config.primes)
            .map(|(lane, &q)| {
                let factor = (c as i128).rem_euclid(q as i128) as u128;
                lane.iter()
                    .map(|&x| (factor * x as u128 % q as u128) as u64)
                    .collect()
            })
            .collect(),
    };
    RNSCiphertext {
        c0: scale(&ct.c0),
        c1: scale(&ct.c1),
        num_primes: ct.num_primes,
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "One shared DAG evaluator preserves identical raw/prepared execution for both plaintext contexts"
)]
fn evaluate_dag(
    ctx: &RNSFHEContext,
    exact: &ExactMulEvaluator<'_>,
    dag: &Dag,
    output: usize,
    input: &RNSCiphertext,
    relin: GadgetKeyView<'_>,
    stage: &str,
    progress: &mut dyn FnMut(&str, usize, usize),
) -> Nine65Result<RNSCiphertext> {
    let mut remaining = vec![0usize; dag.nodes.len()];
    for node in &dag.nodes {
        for index in node.inputs() {
            remaining[index] += 1;
        }
    }
    remaining[output] += 1;
    let products = dag
        .nodes
        .iter()
        .filter(|node| matches!(node, Node::Product(..)))
        .count();
    let mut complete = 0;
    progress(stage, complete, products);
    let mut values: Vec<Option<RNSCiphertext>> = Vec::with_capacity(dag.nodes.len());
    for node in &dag.nodes {
        let value = match *node {
            Node::Input => input.clone(),
            Node::Constant(c) => constant_ciphertext(ctx, c),
            Node::Add(a, b) => ctx.add(values[a].as_ref().unwrap(), values[b].as_ref().unwrap()),
            Node::Scale(a, c) => scale_ciphertext(ctx, values[a].as_ref().unwrap(), c),
            Node::Product(a, b) => relin
                .multiply(
                    exact,
                    values[a].as_ref().unwrap(),
                    values[b].as_ref().unwrap(),
                )
                .map_err(|e| refused(format!("split-digit ciphertext product: {e:?}")))?,
        };
        values.push(Some(value));
        if matches!(node, Node::Product(..)) {
            complete += 1;
            progress(stage, complete, products);
        }
        for index in node.inputs() {
            remaining[index] -= 1;
            if remaining[index] == 0 {
                values[index] = None;
            }
        }
    }
    Ok(values[output].take().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_digit_exact_identity_covers_every_small_domain_value() {
        let mut cases = 0;
        for p in [3, 5, 7, 11, 17, 31] {
            for radius in 1..=(p as usize - 1) / 2 {
                let (high, go, low, ho) = circuits(p, radius).unwrap();
                let g = high.symbolic(go);
                let h = low.symbolic(ho);
                for r in -(radius as i64)..=radius as i64 {
                    for k in 0..p {
                        let x = (r + p as i64 * k as i64).rem_euclid((p * p) as i64) as u64;
                        let gv = polynomial_value(&g, x, p * p);
                        assert_eq!(gv % p, 0);
                        assert_eq!(gv / p * polynomial_value(&h, x % p, p) % p, k);
                        cases += 1;
                    }
                }
            }
        }
        assert!(cases > 9_000);
    }

    #[test]
    fn split_digit_native_schedule_has_checked_identity_and_68_products() {
        let (high, go, low, ho) = circuits(65_537, 49).unwrap();
        assert_eq!(high.symbolic(go).len(), 100);
        assert_eq!(low.symbolic(ho).len(), 99);
        assert_eq!(
            high.nodes
                .iter()
                .chain(&low.nodes)
                .filter(|n| matches!(n, Node::Product(..)))
                .count()
                + 1,
            68
        );
        assert!(circuits(15, 2).is_err());
        assert!(circuits(17, 9).is_err());
    }

    #[test]
    fn split_digit_native_width_noise_ledger_matches_integer_oracle() {
        use crate::params::SecureConfig;
        // Public arithmetic fixture only. The 2^42 input bounds below must
        // still come from a coherent admitted producer for actual execution.
        let mut config = SecureConfig::secure_128().into_config();
        config.n = 32_768;
        config.t = 65_537 * 65_537;
        config.security_bits = 0;
        config.name = "split-digit 650-bit arithmetic ledger fixture";
        config.primes = vec![
            998244353,
            985661441,
            754974721,
            469762049,
            576460752301785089,
            576460752301391873,
            576460752300015617,
            576460752298835969,
            576460752298180609,
            576460752293134337,
            576460752291954689,
            576460752290775041,
            575870995836829697,
        ];
        let q = U1024::checked_product_u64s(&config.primes).unwrap();
        assert_eq!(q.bit_length(), 650);
        assert_eq!(q.mod_u64(config.t), Some(1));
        let high = RNSFHEContext::try_new(&config).unwrap();
        config.t = 65_537;
        let low = RNSFHEContext::try_new(&config).unwrap();
        let input_bound = U1024::from_u64(1 << 42);
        let evaluator =
            SplitDigitEvaluator::new(&high, &low, 49, input_bound, input_bound).unwrap();
        let certificate = evaluator.certificate();
        assert_eq!(certificate.radius, 49);
        assert_eq!(certificate.ciphertext_products, 68);
        assert_eq!(certificate.high_product_error.bit_length(), 476);
        assert_eq!(certificate.low_polynomial_error.bit_length(), 408);
        assert_eq!(certificate.output_error.bit_length(), 521);
        // Independent arbitrary-precision Python recurrence, with every
        // actual main prime and Q mod p²=1, not merely matching bit counts.
        let from_hex = |hex: &str| {
            let mut limbs = [0; 16];
            for (i, chunk) in hex.as_bytes().rchunks(16).enumerate() {
                limbs[i] = u64::from_str_radix(core::str::from_utf8(chunk).unwrap(), 16).unwrap();
            }
            U1024::from_limbs(limbs)
        };
        assert_eq!(certificate.high_product_error, from_hex("901f8327610ac5c550ded90f12763d2b345d7173db0e1b7706ff26dba74434ed53c67b8158abe048bb0dc6c6356d0be73764a8fd96efba42b9e4001"));
        assert_eq!(certificate.low_polynomial_error, from_hex("c02a041d3cec51c907307d608b8a9c061e7709fa8b55fbb86c2850dc949ce030d4b1808b8e7ad64b4a3d6e3d7fe3d42281c94b"));
        assert_eq!(certificate.output_error, from_hex("12046e80c6f38f35c92e43521560266dcdbb5c838901bc99cb90b154e2fe644da561a99e320073c80288424d84ec171b16cddb2993c73ff18c4b541af3430434001"));
        assert_eq!(certificate.high_node_error_bounds[0], input_bound);
        assert_eq!(certificate.low_node_error_bounds[0], input_bound);
        assert!(SplitDigitEvaluator::new(&high, &low, 49, q.shr1(), input_bound).is_err());
    }

    #[test]
    fn split_digit_encrypted_slots_recover_signed_quotients_with_independent_oracle() {
        use crate::arithmetic::canonical_scale_round::CanonicalScaleRound;
        use crate::entropy::ShadowHarvester;
        use crate::params::SecureConfig;
        let mut config = SecureConfig::secure_128().into_config();
        config.n = 8;
        config.t = 17 * 17;
        config.security_bits = 0;
        config.name = "INSECURE split-digit encrypted polynomial oracle";
        let high = RNSFHEContext::try_new(&config).unwrap();
        config.t = 17;
        let low = RNSFHEContext::try_new(&config).unwrap();
        let mut rng = ShadowHarvester::with_seed(0x5350_4c49_5444_4947);
        let keys = high.generate_keys(&mut rng);
        let exact = high.try_exact_evaluator().unwrap();
        let relin = exact.generate_hybrid_gadget_key_with_rng(&keys.secret_key, &mut rng);
        let root = (2..high.t)
            .find(|&r| power_mod(r, high.n as u64, high.t) == high.t - 1)
            .unwrap();
        let roots: Vec<_> = (0..high.n)
            .map(|i| power_mod(root, (2 * i + 1) as u64, high.t))
            .collect();
        let residual = [-3i64, -2, -1, 0, 1, 2, 3, -3];
        let quotient = [-8i64, -5, -1, 0, 1, 3, 7, 8];
        let encode = |ctx: &RNSFHEContext, slots: &[i64], rng: &mut ShadowHarvester| {
            let inv_n = (1..ctx.t).find(|&v| v * ctx.n as u64 % ctx.t == 1).unwrap();
            let mut ct = ctx.encrypt(0, &keys.public_key, rng);
            for coefficient in 0..ctx.n {
                let mut value = 0u64;
                for (slot, &root) in slots.iter().zip(&roots) {
                    let inverse_power =
                        power_mod(root % ctx.t, (2 * ctx.n - coefficient) as u64, ctx.t);
                    let term = slot.rem_euclid(ctx.t as i64) as u64;
                    value = ((value as u128 + term as u128 * inverse_power as u128) % ctx.t as u128)
                        as u64;
                }
                let value = centered(value * inv_n % ctx.t, ctx.t);
                for (lane, &q) in ctx.config.primes.iter().enumerate() {
                    let encoded =
                        (value as i128 * ctx.delta_rns[lane] as i128).rem_euclid(q as i128) as u64;
                    let encoded = ctx.rns.mont_contexts[lane].to_montgomery(encoded);
                    ct.c0.limbs[lane][coefficient] = ((ct.c0.limbs[lane][coefficient] as u128
                        + encoded as u128)
                        % q as u128) as u64;
                }
            }
            ct
        };
        let high_slots: Vec<_> = residual
            .iter()
            .zip(&quotient)
            .map(|(&r, &k)| r + 17 * k)
            .collect();
        let high_input = encode(&high, &high_slots, &mut rng);
        let low_input = encode(&low, &residual, &mut rng);
        let evaluator = SplitDigitEvaluator::new(
            &high,
            &low,
            3,
            U1024::from_u64(3 * 17 + high.t),
            U1024::from_u64(3 * 17 + low.t),
        )
        .unwrap();
        let output = evaluator.evaluate(&high_input, &low_input, &relin).unwrap();
        let prepared = exact.prepare_hybrid_gadget_key(&relin).unwrap();
        let prepared_output = evaluator
            .evaluate_prepared(&high_input, &low_input, &prepared)
            .unwrap();
        assert_eq!(prepared_output.c0.limbs, output.c0.limbs);
        assert_eq!(prepared_output.c1.limbs, output.c1.limbs);
        assert_eq!(prepared_output.num_primes, output.num_primes);
        // Client observer only: exact ring phase then independent coefficient
        // decoding and polynomial evaluation at the plaintext CRT roots.
        let mut phase = vec![vec![0; low.n]; low.config.primes.len()];
        for (lane, &q) in low.config.primes.iter().enumerate() {
            let mont = &low.rns.mont_contexts[lane];
            let c1: Vec<_> = output.c1.limbs[lane]
                .iter()
                .map(|&v| mont.from_montgomery(v))
                .collect();
            let secret: Vec<_> = keys.secret_key.s.limbs[lane]
                .iter()
                .map(|&v| mont.from_montgomery(v))
                .collect();
            let product = low.ntt_engines[lane].multiply(&c1, &secret);
            for j in 0..low.n {
                phase[lane][j] = ((product[j] as u128
                    + mont.from_montgomery(output.c0.limbs[lane][j]) as u128)
                    % q as u128) as u64;
            }
        }
        let decoder = CanonicalScaleRound::new(&low.config.primes, low.t).unwrap();
        let coefficients: Vec<_> = (0..low.n)
            .map(|j| {
                decoder
                    .scale_round(&phase.iter().map(|lane| lane[j]).collect::<Vec<_>>())
                    .unwrap()
            })
            .collect();
        for (&root, &expected) in roots.iter().zip(&quotient) {
            assert_eq!(
                polynomial_value(&coefficients, root % low.t, low.t),
                expected.rem_euclid(low.t as i64) as u64
            );
        }
        assert!(
            evaluator.certificate().output_error
                < U1024::checked_product_u64s(&low.config.primes)
                    .unwrap()
                    .div_mod_u64(low.t)
                    .unwrap()
                    .0
                    .shr1()
        );
        let mut malformed = high_input.clone();
        malformed.c0.limbs.pop();
        assert!(evaluator.evaluate(&malformed, &low_input, &relin).is_err());
        assert!(SplitDigitEvaluator::new(&high, &high, 3, U1024::ONE, U1024::ONE).is_err());
    }
}
