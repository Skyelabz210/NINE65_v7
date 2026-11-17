//! # certified_lift
//!
//! One kernel for the CRAM magnitude story. Exact integers only (no floating point).
//!
//! A value is X = r + K*M with `M` a single *shell* lane; the anchors are the other lanes.
//!
//! 1. **State**: lane residues plus a magnitude bound `U` (a certificate, not a count).
//! 2. **Arithmetic**: add, multiply, subtract, exact division are lane-wise.
//! 3. **Magnitude is a reading**: `K mod A_j = (v_Aj - v_M) * M^-1 mod A_j`, taken on demand.
//!    Nothing stores K and no function in this crate assembles X (the oracle lives in the tests).
//! 4. **Capacity is a certificate**: unsigned needs `U < W`, signed needs `2U < W`, `W = M*prod(A_j)`.
//!    Otherwise the operation is refused with [`LiftError::Capacity`]. There is no uncertified mode.
//! 5. **Depth levers**: exact division lowers `U`; **tightening** re-certifies `U` from a K reading;
//!    [`Machine::grow`] adds a lane from (r, K) (Universal Projection) before the window fills.
//!
//! Signed values are lane residues of the signed integer S with `|S| <= U`. Sign and order are read
//! through a common bias B >= U: T = S + B lies in [0, 2B] inside the window, and (K, r) of T is
//! compared lexicographically. The bias is a constant added lane-wise at read time; it is not stored.
use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiftError {
    BadBasis(&'static str),
    Capacity { need_bits: u64, window_bits: u64 },
    Underflow,
    NotCoprime(u64),
    UnknownDivisor(u64),
}

fn gcd(mut a: u64, mut b: u64) -> u64 { while b != 0 { let t = a % b; a = b; b = t; } a }
fn inv(a: u64, p: u64) -> Option<u64> {
    let (mut t, mut nt) = (0i128, 1i128);
    let (mut r, mut nr) = (p as i128, (a % p) as i128);
    while nr != 0 { let q = r / nr; let x = t - q * nt; t = nt; nt = x; let y = r - q * nr; r = nr; nr = y; }
    if r != 1 { return None; }
    Some((((t % p as i128) + p as i128) % p as i128) as u64)
}
fn mulmod(a: u64, b: u64, p: u64) -> u64 { ((a as u128 * b as u128) % p as u128) as u64 }
fn addmod(a: u64, b: u64, p: u64) -> u64 { ((a as u128 + b as u128) % p as u128) as u64 }
fn submod(a: u64, b: u64, p: u64) -> u64 { ((a as u128 + p as u128 - (b % p) as u128) % p as u128) as u64 }
fn lo(x: &BigUint) -> u64 { x.to_u64_digits().first().copied().unwrap_or(0) }
/// Certified divisors: constant -> multiplicity. Counts saturate, which only under-claims (sound).
type Factors = BTreeMap<u64, u64>;
fn meet(a: &Factors, b: &Factors) -> Factors {
    a.iter().filter_map(|(&k, &x)| b.get(&k).map(|&y| (k, x.min(y)))).collect()
}
fn join(a: &Factors, b: &Factors) -> Factors {
    let mut o = a.clone(); for (&k, &y) in b { let e = o.entry(k).or_insert(0); *e = e.saturating_add(y); } o
}

/// Unsigned value: lane residues (index 0 = shell), certified bound U >= X, certified factors.
#[derive(Clone, Debug)]
pub struct Lift { v: Vec<u64>, bound: BigUint, factors: Factors }
impl Lift { pub fn lanes(&self) -> &[u64] { &self.v } pub fn bound(&self) -> &BigUint { &self.bound } }

/// Signed value: lane residues of S, certified bound |S| <= U, certified factors.
#[derive(Clone, Debug)]
pub struct SLift { v: Vec<u64>, bound: BigUint, factors: Factors }
impl SLift { pub fn lanes(&self) -> &[u64] { &self.v } pub fn bound(&self) -> &BigUint { &self.bound } }

pub struct Kernel {
    lanes: Vec<u64>, window: BigUint, minv: Vec<u64>, cmod: BigUint, coef: Vec<BigUint>,
    k_derivations: Cell<u64>, k_combines: Cell<u64>,
    // redundant-modulus tables: anchors 0..s-2 are regular (product cp), anchor s-1 is the redundant lane r
    sk_cp: BigUint, sk_terms: Vec<BigUint>, sk_xinv: Vec<u64>, sk_term_r: Vec<u64>, sk_cinv_r: u64,
    sk_reads: Cell<u64>,
    /// divisor constants the user wants to stay usable: growth never picks a lane sharing a factor with them
    reserved: Vec<u64>,
}

impl Kernel {
    pub fn new(shell: u64, anchors: &[u64]) -> Result<Kernel, LiftError> {
        if shell < 2 { return Err(LiftError::BadBasis("shell < 2")); }
        if anchors.is_empty() { return Err(LiftError::BadBasis("need at least one anchor")); }
        let mut k = Kernel { lanes: vec![shell], window: BigUint::from(shell), minv: vec![], cmod: BigUint::one(), coef: vec![],
            k_derivations: Cell::new(0), k_combines: Cell::new(0),
            sk_cp: BigUint::one(), sk_terms: vec![], sk_xinv: vec![], sk_term_r: vec![], sk_cinv_r: 0, sk_reads: Cell::new(0), reserved: vec![] };
        for &a in anchors { k.push_lane(a)?; }
        Ok(k)
    }
    fn push_lane(&mut self, p: u64) -> Result<(), LiftError> {
        if p < 2 { return Err(LiftError::BadBasis("lane < 2")); }
        if self.lanes.iter().any(|&q| gcd(p, q) != 1) { return Err(LiftError::BadBasis("lanes not pairwise coprime")); }
        let mi = inv(self.lanes[0] % p, p).ok_or(LiftError::BadBasis("shell not invertible mod anchor"))?;
        self.lanes.push(p); self.window *= p; self.cmod *= p; self.minv.push(mi);
        self.coef = (1..self.lanes.len()).map(|j| {
            let a = self.lanes[j]; let cj = &self.cmod / a; let y = inv(lo(&(&cj % a)), a).unwrap(); cj * y
        }).collect();
        self.build_sk();
        Ok(())
    }
    /// Shenoy-Kumaresan style tables: needs >= 2 anchors; the last anchor is the redundant modulus.
    fn build_sk(&mut self) {
        let s = self.anchors();
        if s < 2 { self.sk_terms.clear(); return; }
        let r = self.lanes[s]; // last anchor
        let reg = &self.lanes[1..s];
        let mut cp = BigUint::one(); for &a in reg { cp *= a; }
        self.sk_terms = reg.iter().map(|&a| &cp / a).collect();
        self.sk_xinv = reg.iter().zip(&self.sk_terms).map(|(&a, t)| inv(lo(&(t % a)), a).unwrap()).collect();
        self.sk_term_r = self.sk_terms.iter().map(|t| lo(&(t % r))).collect();
        self.sk_cinv_r = inv(lo(&(&cp % r)), r).unwrap_or(0);
        self.sk_cp = cp;
    }
    /// K by the redundant-modulus route: valid only when K < product of the regular anchors (certificate-checked
    /// by the caller) and the redundant lane exceeds the regular-anchor count. No big-integer reduction.
    fn derive_k_sk(&self, v: &[u64]) -> BigUint {
        self.sk_reads.set(self.sk_reads.get() + 1);
        let s = self.anchors(); let r = self.lanes[s];
        let kap = |j: usize| { let p = self.lanes[1 + j]; mulmod(submod(v[1 + j], v[0], p), self.minv[j], p) };
        let (mut acc_r, mut sum) = (0u64, BigUint::zero());
        for j in 0..s - 1 {
            let a = self.lanes[1 + j];
            let xi = mulmod(kap(j), self.sk_xinv[j], a);
            acc_r = addmod(acc_r, mulmod(xi % r, self.sk_term_r[j], r), r);
            sum += &self.sk_terms[j] * xi;
        }
        let alpha = mulmod(submod(acc_r, kap(s - 1), r), self.sk_cinv_r, r); // exact: alpha < s-1 < r
        sum - BigUint::from(alpha) * &self.sk_cp
    }
    /// Can the SK route be used for a value with this certified bound?
    fn sk_ok(&self, bound: &BigUint) -> bool {
        self.anchors() >= 2 && self.lanes[self.anchors()] > self.anchors() as u64 && (bound / self.lanes[0]) < self.sk_cp
    }
    pub fn sk_reads(&self) -> u64 { self.sk_reads.get() }
    /// K for a bounded value: SK route when the certificate allows, else the full combine. Same answer either way.
    pub fn derive_k_bounded(&self, a: &Lift) -> BigUint {
        self.k_derivations.set(self.k_derivations.get() + 1);
        if self.sk_ok(&a.bound) { return self.derive_k_sk(&a.v); }
        self.k_derivations.set(self.k_derivations.get() - 1);
        self.derive_k_lanes(&a.v)
    }
    pub fn derive_k_combine(&self, a: &Lift) -> BigUint { self.derive_k_lanes(&a.v) }
    /// Declare divisors that must stay invertible on every lane (current and future).
    pub fn reserve_divisors(&mut self, ds: &[u64]) -> Result<(), LiftError> {
        for &d in ds {
            if d == 0 || self.lanes.iter().any(|&q| gcd(d, q) != 1) { return Err(LiftError::NotCoprime(d)); }
            if !self.reserved.contains(&d) { self.reserved.push(d); }
        }
        Ok(())
    }
    fn pick_coprime(&self, live: &[u64]) -> Result<u64, LiftError> {
        let mut p = *self.lanes.last().unwrap();
        loop {
            if p <= 3 { return Err(LiftError::BadBasis("no coprime lane left")); }
            p -= 1;
            // addressing layer needs coprimality only: any integer coprime to every lane is admissible
            if self.lanes.iter().all(|&q| gcd(p, q) == 1) && self.reserved.iter().chain(live).all(|&d| gcd(p, d) == 1) { return Ok(p); }
        }
    }
    pub fn lanes(&self) -> &[u64] { &self.lanes }
    pub fn window(&self) -> &BigUint { &self.window }
    pub fn anchors(&self) -> usize { self.lanes.len() - 1 }
    /// (K derivations, multi-anchor combines). X assemblies are not counted because none exist.
    pub fn counters(&self) -> (u64, u64) { (self.k_derivations.get(), self.k_combines.get()) }

    fn check(&self, bound: &BigUint) -> Result<(), LiftError> {
        if *bound >= self.window { Err(LiftError::Capacity { need_bits: bound.bits(), window_bits: self.window.bits() }) } else { Ok(()) }
    }
    fn scheck(&self, bound: &BigUint) -> Result<(), LiftError> { self.check(&(bound * 2u32)) }
    fn lanewise(&self, a: &[u64], b: &[u64], f: impl Fn(u64, u64, u64) -> u64) -> Vec<u64> {
        (0..self.lanes.len()).map(|i| f(a[i], b[i], self.lanes[i])).collect()
    }
    fn const_lanes(&self, c: &BigUint) -> Vec<u64> { self.lanes.iter().map(|&p| lo(&(c % p))).collect() }

    /// K = floor(X / shell) read from the anchors. Exact while the certificate holds.
    fn derive_k_lanes(&self, v: &[u64]) -> BigUint {
        self.k_derivations.set(self.k_derivations.get() + 1);
        let s = self.anchors();
        let kap = |j: usize| { let p = self.lanes[1 + j]; mulmod(submod(v[1 + j], v[0], p), self.minv[j], p) };
        if s == 1 { return BigUint::from(kap(0)); }
        self.k_combines.set(self.k_combines.get() + 1);
        let mut sum = BigUint::zero();
        for j in 0..s { sum += BigUint::from(kap(j)) * &self.coef[j]; }
        sum % &self.cmod
    }
    pub fn derive_k(&self, a: &Lift) -> BigUint { self.derive_k_lanes(&a.v) }

    // ------------------------- unsigned -------------------------
    pub fn lift(&self, x: u64) -> Result<Lift, LiftError> {
        let b = BigUint::from(x); self.check(&b)?;
        Ok(Lift { v: self.lanes.iter().map(|&p| x % p).collect(), bound: b, factors: Factors::new() })
    }
    pub fn add(&self, a: &Lift, b: &Lift) -> Result<Lift, LiftError> {
        let bound = &a.bound + &b.bound; self.check(&bound)?;
        Ok(Lift { v: self.lanewise(&a.v, &b.v, addmod), bound, factors: meet(&a.factors, &b.factors) })
    }
    pub fn mul(&self, a: &Lift, b: &Lift) -> Result<Lift, LiftError> {
        let bound = &a.bound * &b.bound; self.check(&bound)?;
        let f = join(&a.factors, &b.factors);
        Ok(Lift { v: self.lanewise(&a.v, &b.v, mulmod), bound, factors: f })
    }
    pub fn sub(&self, a: &Lift, b: &Lift) -> Result<Lift, LiftError> {
        if self.cmp(a, b) == Ordering::Less { return Err(LiftError::Underflow); }
        Ok(Lift { v: self.lanewise(&a.v, &b.v, submod), bound: a.bound.clone(), factors: meet(&a.factors, &b.factors) })
    }
    pub fn mul_const(&self, a: &Lift, d: u64) -> Result<Lift, LiftError> {
        let bound = &a.bound * d; self.check(&bound)?;
        let mut f = a.factors.clone();
        if d > 1 && self.lanes.iter().all(|&p| gcd(d, p) == 1) { let e = f.entry(d).or_insert(0); *e = e.saturating_add(1); }
        Ok(Lift { v: (0..self.lanes.len()).map(|i| mulmod(a.v[i], d % self.lanes[i], self.lanes[i])).collect(), bound, factors: f })
    }
    pub fn div_exact(&self, a: &Lift, d: u64) -> Result<Lift, LiftError> {
        let (v, bound, f) = self.divide(&a.v, &a.bound, &a.factors, d)?; Ok(Lift { v, bound, factors: f })
    }
    fn divide(&self, v: &[u64], bound: &BigUint, factors: &Factors, d: u64) -> Result<(Vec<u64>, BigUint, Factors), LiftError> {
        if d == 0 || self.lanes.iter().any(|&p| gcd(d, p) != 1) { return Err(LiftError::NotCoprime(d)); }
        let have = factors.get(&d).copied().unwrap_or(0);
        if have == 0 { return Err(LiftError::UnknownDivisor(d)); }
        let mut f = factors.clone(); if have == 1 { f.remove(&d); } else { f.insert(d, have - 1); }
        let nv = (0..self.lanes.len()).map(|i| mulmod(v[i], inv(d % self.lanes[i], self.lanes[i]).unwrap(), self.lanes[i])).collect();
        Ok((nv, bound / d, f))
    }
    /// Integer order from derived (K, r) pairs: (K, r) lexicographic is the integer order.
    pub fn cmp(&self, a: &Lift, b: &Lift) -> Ordering { (self.derive_k_bounded(a), a.v[0]).cmp(&(self.derive_k_bounded(b), b.v[0])) }
    /// Re-certify the bound from a K reading: X lies in [K*M, K*M + M - 1]. Never loosens the bound.
    pub fn tighten(&self, a: &Lift) -> Lift {
        let m = BigUint::from(self.lanes[0]);
        let hi = self.derive_k_bounded(a) * &m + (&m - 1u32);
        Lift { v: a.v.clone(), bound: if hi < a.bound { hi } else { a.bound.clone() }, factors: a.factors.clone() }
    }

    // ------------------------- signed -------------------------
    pub fn lift_signed(&self, x: i64) -> Result<SLift, LiftError> {
        let b = BigUint::from(x.unsigned_abs()); self.scheck(&b)?;
        let v = self.lanes.iter().map(|&p| { let r = (x as i128).rem_euclid(p as i128); r as u64 }).collect();
        Ok(SLift { v, bound: b, factors: Factors::new() })
    }
    pub fn sadd(&self, a: &SLift, b: &SLift) -> Result<SLift, LiftError> {
        let bound = &a.bound + &b.bound; self.scheck(&bound)?;
        Ok(SLift { v: self.lanewise(&a.v, &b.v, addmod), bound, factors: meet(&a.factors, &b.factors) })
    }
    pub fn ssub(&self, a: &SLift, b: &SLift) -> Result<SLift, LiftError> {
        let bound = &a.bound + &b.bound; self.scheck(&bound)?;
        Ok(SLift { v: self.lanewise(&a.v, &b.v, submod), bound, factors: meet(&a.factors, &b.factors) })
    }
    pub fn smul(&self, a: &SLift, b: &SLift) -> Result<SLift, LiftError> {
        let bound = &a.bound * &b.bound; self.scheck(&bound)?;
        let f = join(&a.factors, &b.factors);
        Ok(SLift { v: self.lanewise(&a.v, &b.v, mulmod), bound, factors: f })
    }
    pub fn sneg(&self, a: &SLift) -> SLift {
        SLift { v: a.v.iter().zip(&self.lanes).map(|(&x, &p)| submod(0, x, p)).collect(), bound: a.bound.clone(), factors: a.factors.clone() }
    }
    pub fn smul_const(&self, a: &SLift, d: u64) -> Result<SLift, LiftError> {
        let bound = &a.bound * d; self.scheck(&bound)?;
        let mut f = a.factors.clone();
        if d > 1 && self.lanes.iter().all(|&p| gcd(d, p) == 1) { let e = f.entry(d).or_insert(0); *e = e.saturating_add(1); }
        Ok(SLift { v: (0..self.lanes.len()).map(|i| mulmod(a.v[i], d % self.lanes[i], self.lanes[i])).collect(), bound, factors: f })
    }
    pub fn sdiv_exact(&self, a: &SLift, d: u64) -> Result<SLift, LiftError> {
        let (v, bound, f) = self.divide(&a.v, &a.bound, &a.factors, d)?; Ok(SLift { v, bound, factors: f })
    }
    /// (K, r) of T = S + B, B a common bias with 2B < W and B >= |S|.
    fn biased(&self, a: &SLift, b: &BigUint) -> (BigUint, u64) {
        let c = self.const_lanes(b);
        let t = self.lanewise(&a.v, &c, addmod);
        (self.derive_k_lanes(&t), t[0])
    }
    /// Order of two signed values through a common bias; never refuses (both satisfy 2U < W).
    pub fn scmp(&self, a: &SLift, b: &SLift) -> Ordering {
        let bias = if a.bound >= b.bound { a.bound.clone() } else { b.bound.clone() };
        self.biased(a, &bias).cmp(&self.biased(b, &bias))
    }
    /// Sign of S: compare T = S + U with the constant U (its (K, r) is bookkeeping, not a reading).
    pub fn sign(&self, a: &SLift) -> Ordering {
        let m = BigUint::from(self.lanes[0]);
        self.biased(a, &a.bound).cmp(&(&a.bound / &m, lo(&(&a.bound % &m))))
    }
    pub fn stighten(&self, a: &SLift) -> SLift {
        let m = BigUint::from(self.lanes[0]);
        let (k, _) = self.biased(a, &a.bound);
        let t_lo = BigInt::from(k * &m); let t_hi = &t_lo + BigInt::from(&m - 1u32);
        let u = BigInt::from(a.bound.clone());
        let (s_lo, s_hi) = (t_lo - &u, t_hi - &u);
        let (ml, mh) = (s_lo.magnitude().clone(), s_hi.magnitude().clone());
        let nb = if ml >= mh { ml } else { mh };
        SLift { v: a.v.clone(), bound: if nb < a.bound { nb } else { a.bound.clone() }, factors: a.factors.clone() }
    }
}

enum Op { Add, Mul, MulConst(u64) }

/// Unsigned registers sharing one frame. Under pressure it first tightens bounds (K readings),
/// and only then grows the basis.
pub struct Machine { kernel: Kernel, regs: Vec<Lift>, max_anchors: usize, growths: u64, tightens: u64, tighten_on: bool }
impl Machine {
    pub fn new(shell: u64, anchors: &[u64], n_regs: usize, max_anchors: usize) -> Result<Machine, LiftError> {
        let kernel = Kernel::new(shell, anchors)?;
        let regs = (0..n_regs).map(|_| kernel.lift(0)).collect::<Result<Vec<_>, _>>()?;
        Ok(Machine { kernel, regs, max_anchors, growths: 0, tightens: 0, tighten_on: true })
    }
    pub fn set_tighten(&mut self, on: bool) { self.tighten_on = on; }
    pub fn reserve_divisors(&mut self, ds: &[u64]) -> Result<(), LiftError> { self.kernel.reserve_divisors(ds) }
    pub fn kernel(&self) -> &Kernel { &self.kernel }
    pub fn reg(&self, i: usize) -> &Lift { &self.regs[i] }
    pub fn growths(&self) -> u64 { self.growths }
    pub fn tightens(&self) -> u64 { self.tightens }
    pub fn load(&mut self, i: usize, x: u64) -> Result<(), LiftError> { self.regs[i] = self.kernel.lift(x)?; Ok(()) }
    pub fn grow(&mut self) -> Result<(), LiftError> {
        if self.kernel.anchors() >= self.max_anchors {
            return Err(LiftError::Capacity { need_bits: self.kernel.window.bits() + 1, window_bits: self.kernel.window.bits() });
        }
        let live: Vec<u64> = self.regs.iter().flat_map(|r| r.factors.keys().copied()).collect();
        let p = self.kernel.pick_coprime(&live)?;
        let shell = self.kernel.lanes[0];
        let ks: Vec<BigUint> = self.regs.iter().map(|r| self.kernel.derive_k(r)).collect();
        for (r, k) in self.regs.iter_mut().zip(ks.iter()) { r.v.push(addmod(r.v[0] % p, mulmod(lo(&(k % p)), shell % p, p), p)); }
        self.kernel.push_lane(p)?; self.growths += 1; Ok(())
    }
    fn need(&self, op: &Op, a: usize, b: usize) -> BigUint {
        match op { Op::Add => &self.regs[a].bound + &self.regs[b].bound, Op::Mul => &self.regs[a].bound * &self.regs[b].bound, Op::MulConst(d) => &self.regs[a].bound * *d }
    }
    fn fit(&mut self, op: Op, a: usize, b: usize) -> Result<(), LiftError> {
        let mut tightened = false;
        loop {
            if self.need(&op, a, b) < self.kernel.window { return Ok(()); }
            if self.tighten_on && !tightened {
                tightened = true;
                let ia = [a, b];
                for &i in &ia { self.regs[i] = self.kernel.tighten(&self.regs[i]); }
                self.tightens += 1; continue;
            }
            self.grow()?;
        }
    }
    pub fn add(&mut self, dst: usize, a: usize, b: usize) -> Result<(), LiftError> { self.fit(Op::Add, a, b)?; self.regs[dst] = self.kernel.add(&self.regs[a], &self.regs[b])?; Ok(()) }
    pub fn mul(&mut self, dst: usize, a: usize, b: usize) -> Result<(), LiftError> { self.fit(Op::Mul, a, b)?; self.regs[dst] = self.kernel.mul(&self.regs[a], &self.regs[b])?; Ok(()) }
    pub fn sub(&mut self, dst: usize, a: usize, b: usize) -> Result<(), LiftError> { self.regs[dst] = self.kernel.sub(&self.regs[a], &self.regs[b])?; Ok(()) }
    pub fn mul_const(&mut self, dst: usize, a: usize, d: u64) -> Result<(), LiftError> { self.fit(Op::MulConst(d), a, a)?; self.regs[dst] = self.kernel.mul_const(&self.regs[a], d)?; Ok(()) }
    pub fn div_exact(&mut self, dst: usize, a: usize, d: u64) -> Result<(), LiftError> { self.regs[dst] = self.kernel.div_exact(&self.regs[a], d)?; Ok(()) }
    pub fn cmp(&self, a: usize, b: usize) -> Ordering { self.kernel.cmp(&self.regs[a], &self.regs[b]) }
}

/// Signed registers sharing one frame, same pressure policy (tighten, then grow).
pub struct SMachine { kernel: Kernel, regs: Vec<SLift>, max_anchors: usize, growths: u64, tightens: u64, tighten_on: bool }
impl SMachine {
    pub fn new(shell: u64, anchors: &[u64], n_regs: usize, max_anchors: usize) -> Result<SMachine, LiftError> {
        let kernel = Kernel::new(shell, anchors)?;
        let regs = (0..n_regs).map(|_| kernel.lift_signed(0)).collect::<Result<Vec<_>, _>>()?;
        Ok(SMachine { kernel, regs, max_anchors, growths: 0, tightens: 0, tighten_on: true })
    }
    pub fn set_tighten(&mut self, on: bool) { self.tighten_on = on; }
    pub fn reserve_divisors(&mut self, ds: &[u64]) -> Result<(), LiftError> { self.kernel.reserve_divisors(ds) }
    pub fn kernel(&self) -> &Kernel { &self.kernel }
    pub fn reg(&self, i: usize) -> &SLift { &self.regs[i] }
    pub fn growths(&self) -> u64 { self.growths }
    pub fn tightens(&self) -> u64 { self.tightens }
    pub fn load(&mut self, i: usize, x: i64) -> Result<(), LiftError> { self.regs[i] = self.kernel.lift_signed(x)?; Ok(()) }
    pub fn grow(&mut self) -> Result<(), LiftError> {
        if self.kernel.anchors() >= self.max_anchors {
            return Err(LiftError::Capacity { need_bits: self.kernel.window.bits() + 1, window_bits: self.kernel.window.bits() });
        }
        let live: Vec<u64> = self.regs.iter().flat_map(|r| r.factors.keys().copied()).collect();
        let p = self.kernel.pick_coprime(&live)?;
        let shell = self.kernel.lanes[0];
        // for each S: T = S + U is nonnegative and inside the window; project T to the new lane, subtract U
        let proj: Vec<u64> = self.regs.iter().map(|r| {
            let (k, rt) = self.kernel.biased(r, &r.bound);
            let tp = addmod(rt % p, mulmod(lo(&(&k % p)), shell % p, p), p);
            submod(tp, lo(&(&r.bound % p)), p)
        }).collect();
        for (r, x) in self.regs.iter_mut().zip(proj) { r.v.push(x); }
        self.kernel.push_lane(p)?; self.growths += 1; Ok(())
    }
    fn need(&self, op: &Op, a: usize, b: usize) -> BigUint {
        let (ua, ub) = (&self.regs[a].bound, &self.regs[b].bound);
        let u = match op { Op::Add => ua + ub, Op::Mul => ua * ub, Op::MulConst(d) => ua * *d };
        u * 2u32
    }
    fn fit(&mut self, op: Op, a: usize, b: usize) -> Result<(), LiftError> {
        let mut tightened = false;
        loop {
            if self.need(&op, a, b) < self.kernel.window { return Ok(()); }
            if self.tighten_on && !tightened {
                tightened = true;
                for &i in &[a, b] { self.regs[i] = self.kernel.stighten(&self.regs[i]); }
                self.tightens += 1; continue;
            }
            self.grow()?;
        }
    }
    pub fn add(&mut self, dst: usize, a: usize, b: usize) -> Result<(), LiftError> { self.fit(Op::Add, a, b)?; self.regs[dst] = self.kernel.sadd(&self.regs[a], &self.regs[b])?; Ok(()) }
    pub fn sub(&mut self, dst: usize, a: usize, b: usize) -> Result<(), LiftError> { self.fit(Op::Add, a, b)?; self.regs[dst] = self.kernel.ssub(&self.regs[a], &self.regs[b])?; Ok(()) }
    pub fn mul(&mut self, dst: usize, a: usize, b: usize) -> Result<(), LiftError> { self.fit(Op::Mul, a, b)?; self.regs[dst] = self.kernel.smul(&self.regs[a], &self.regs[b])?; Ok(()) }
    pub fn neg(&mut self, dst: usize, a: usize) { self.regs[dst] = self.kernel.sneg(&self.regs[a]); }
    pub fn mul_const(&mut self, dst: usize, a: usize, d: u64) -> Result<(), LiftError> { self.fit(Op::MulConst(d), a, a)?; self.regs[dst] = self.kernel.smul_const(&self.regs[a], d)?; Ok(()) }
    pub fn div_exact(&mut self, dst: usize, a: usize, d: u64) -> Result<(), LiftError> { self.regs[dst] = self.kernel.sdiv_exact(&self.regs[a], d)?; Ok(()) }
    pub fn sign(&self, a: usize) -> Ordering { self.kernel.sign(&self.regs[a]) }
    pub fn cmp(&self, a: usize, b: usize) -> Ordering { self.kernel.scmp(&self.regs[a], &self.regs[b]) }
}
