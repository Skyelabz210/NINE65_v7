// Toy but COMPLETE public BFV refresh: exact integers only, no floats.
// Source ct (Q_in, key s sparse, t=p) -> output ct (Q_in, key s, t=p), no secret key used by the evaluator.
// Pipeline: rounded components a_i=round(p^2 c_i/Q_in) mod p^2 ; encrypted W = a0 + a1*s = p*m + eps (|eps|<=B)
//  (BK = encryption of s under outer key S', plaintext modulus p^2) ; C2S by Galois ; digit poly F(W)=eps ;
//  p*m = W - F(W) ; S2C by Galois ; view as t=p ; mod-switch Q'->Q_in ; key-switch S'->s.
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{One, Signed, ToPrimitive, Zero};

const N: usize = 16;
const P: i64 = 97;
const P2: i64 = P * P;
const H: usize = 4;
const B: i64 = 3;
type Poly = Vec<BigInt>;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, q: &BigInt) -> BigInt {
        let mut x = BigInt::zero();
        for _ in 0..(q.bits() / 64 + 2) { x = (x << 64u32) + BigInt::from(self.next()); }
        x.mod_floor(q)
    }
    fn small(&mut self, b: i64) -> i64 { (self.next() % (2 * b as u64 + 1)) as i64 - b }
}
fn bi(x: i64) -> BigInt { BigInt::from(x) }
fn div_round(a: &BigInt, b: &BigInt) -> BigInt { (a * BigInt::from(2) + b).div_floor(&(b * BigInt::from(2))) }
fn center(x: &BigInt, q: &BigInt) -> BigInt { let r = x.mod_floor(q); if &r * 2 > *q { r - q } else { r } }
fn zero() -> Poly { vec![BigInt::zero(); N] }
fn pmul_z(a: &Poly, b: &Poly) -> Poly {
    let mut r = zero();
    for i in 0..N { for j in 0..N {
        let v = &a[i] * &b[j];
        if i + j < N { r[i + j] += v } else { r[i + j - N] -= v }
    } }
    r
}
fn padd(a: &Poly, b: &Poly, q: &BigInt) -> Poly { a.iter().zip(b).map(|(x, y)| (x + y).mod_floor(q)).collect() }
fn psub(a: &Poly, b: &Poly, q: &BigInt) -> Poly { a.iter().zip(b).map(|(x, y)| (x - y).mod_floor(q)).collect() }
fn pred(a: &Poly, q: &BigInt) -> Poly { a.iter().map(|x| x.mod_floor(q)).collect() }
fn aut(a: &Poly, g: usize) -> Poly {
    let mut r = zero();
    for i in 0..N { let k = (i * g) % (2 * N); if k < N { r[k] += &a[i] } else { r[k - N] -= &a[i] } }
    r
}
#[derive(Clone)] struct Ct { c0: Poly, c1: Poly }
struct Ctx { q: BigInt, t: BigInt, delta: BigInt }
impl Ctx { fn new(q: BigInt, t: i64) -> Self { let t = bi(t); let delta = &q / &t; Ctx { q, t, delta } } }
fn noise_poly(rng: &mut Rng) -> Poly { (0..N).map(|_| bi(rng.small(8))).collect() }
fn enc(cx: &Ctx, s: &Poly, m: &Poly, rng: &mut Rng) -> Ct {
    let a: Poly = (0..N).map(|_| rng.below(&cx.q)).collect();
    let e = noise_poly(rng);
    let as_ = pmul_z(&a, s);
    let c0 = (0..N).map(|i| (-&as_[i] + &e[i] + &cx.delta * &m[i]).mod_floor(&cx.q)).collect();
    Ct { c0, c1: a }
}
fn phase(cx: &Ctx, s: &Poly, ct: &Ct) -> Poly {
    let p = pmul_z(&ct.c1, s);
    (0..N).map(|i| center(&(&ct.c0[i] + &p[i]), &cx.q)).collect()
}
fn dec(cx: &Ctx, s: &Poly, ct: &Ct) -> Poly {
    phase(cx, s, ct).iter().map(|v| div_round(&(&cx.t * v), &cx.q).mod_floor(&cx.t)).collect()
}
fn noise_bits(cx: &Ctx, s: &Poly, ct: &Ct, m: &Poly) -> u64 {
    let ph = phase(cx, s, ct);
    ph.iter().zip(m).map(|(v, mm)| center(&(v - &cx.delta * mm), &cx.q).abs().bits()).max().unwrap()
}
struct Ksk { k: Vec<(Poly, Poly)>, w: u32 }
fn gen_ksk(cx: &Ctx, from: &Poly, to: &Poly, w: u32, rng: &mut Rng) -> Ksk {
    let nd = (cx.q.bits() as u32 + w - 1) / w;
    let k = (0..nd).map(|i| {
        let a: Poly = (0..N).map(|_| rng.below(&cx.q)).collect();
        let e = noise_poly(rng);
        let as_ = pmul_z(&a, to);
        let sh = BigInt::one() << (w * i);
        let k0 = (0..N).map(|j| (-&as_[j] + &e[j] + &sh * &from[j]).mod_floor(&cx.q)).collect();
        (k0, a)
    }).collect();
    Ksk { k, w }
}
fn apply_ksk(cx: &Ctx, ks: &Ksk, base0: &Poly, x: &Poly) -> Ct {
    let mask = (BigInt::one() << ks.w) - 1;
    let mut c0 = pred(base0, &cx.q);
    let mut c1 = zero();
    let xr = pred(x, &cx.q);
    for (i, (k0, k1)) in ks.k.iter().enumerate() {
        let dig: Poly = xr.iter().map(|v| (v >> (ks.w as usize * i)) & &mask).collect();
        c0 = padd(&c0, &pred(&pmul_z(&dig, k0), &cx.q), &cx.q);
        c1 = padd(&c1, &pred(&pmul_z(&dig, k1), &cx.q), &cx.q);
    }
    Ct { c0, c1 }
}
fn ct_add(cx: &Ctx, a: &Ct, b: &Ct) -> Ct { Ct { c0: padd(&a.c0, &b.c0, &cx.q), c1: padd(&a.c1, &b.c1, &cx.q) } }
fn ct_sub(cx: &Ctx, a: &Ct, b: &Ct) -> Ct { Ct { c0: psub(&a.c0, &b.c0, &cx.q), c1: psub(&a.c1, &b.c1, &cx.q) } }
fn plain_mul(cx: &Ctx, a: &Ct, p: &[i64]) -> Ct {
    let pp: Poly = p.iter().map(|&v| bi(v)).collect();
    Ct { c0: pred(&pmul_z(&a.c0, &pp), &cx.q), c1: pred(&pmul_z(&a.c1, &pp), &cx.q) }
}
fn add_plain(cx: &Ctx, a: &Ct, p: &[i64]) -> Ct {
    let pp: Poly = p.iter().map(|&v| &cx.delta * bi(v)).collect();
    Ct { c0: padd(&a.c0, &pp, &cx.q), c1: a.c1.clone() }
}
fn ct_mul(cx: &Ctx, x: &Ct, y: &Ct, rlk: &Ksk) -> Ct {
    let cen = |p: &Poly| -> Poly { p.iter().map(|v| center(v, &cx.q)).collect() };
    let (x0, x1, y0, y1) = (cen(&x.c0), cen(&x.c1), cen(&y.c0), cen(&y.c1));
    let sc = |p: Poly| -> Poly { p.iter().map(|v| div_round(&(&cx.t * v), &cx.q).mod_floor(&cx.q)).collect() };
    let d0 = sc(pmul_z(&x0, &y0));
    let d1 = sc(padd_z(&pmul_z(&x0, &y1), &pmul_z(&x1, &y0)));
    let d2 = sc(pmul_z(&x1, &y1));
    apply_ksk(cx, rlk, &padd(&d0, &zero(), &cx.q), &d2).add_c1(cx, &d1)
}
fn padd_z(a: &Poly, b: &Poly) -> Poly { a.iter().zip(b).map(|(x, y)| x + y).collect() }
impl Ct { fn add_c1(mut self, cx: &Ctx, d1: &Poly) -> Ct { self.c1 = padd(&self.c1, d1, &cx.q); self } }

// ---------- slot machinery over Z_{p^2} ----------
fn mulm(a: i64, b: i64) -> i64 { ((a as i128 * b as i128).rem_euclid(P2 as i128)) as i64 }
fn powm(mut a: i64, mut e: u64) -> i64 { let mut r = 1; a = a.rem_euclid(P2); while e > 0 { if e & 1 == 1 { r = mulm(r, a) } a = mulm(a, a); e >>= 1 } r }
fn inv_unit(a: i64) -> i64 { powm(a, (P * (P - 1) - 1) as u64) }
struct Slots { z: Vec<i64>, ninv: i64 }
impl Slots {
    fn new() -> Self {
        let mut x = 2;
        loop {
            let y = powm(x, (P * (P - 1) / (2 * N as i64)) as u64);
            if powm(y, N as u64) == P2 - 1 {
                let z = (0..2 * N as u64).map(|e| powm(y, e)).collect();
                return Slots { z, ninv: inv_unit(N as i64) };
            }
            x += 1;
        }
    }
    fn zp(&self, e: i64) -> i64 { self.z[e.rem_euclid(2 * N as i64) as usize] }
    fn encode(&self, v: &[i64]) -> Vec<i64> {
        (0..N as i64).map(|c| { let mut s = 0i64; for k in 0..N as i64 { s = (s + mulm(v[k as usize].rem_euclid(P2), self.zp(-(2 * k + 1) * c))) % P2 } mulm(s, self.ninv) }).collect()
    }
    fn decode(&self, p: &[i64]) -> Vec<i64> {
        (0..N as i64).map(|k| { let mut s = 0i64; for c in 0..N as i64 { s = (s + mulm(p[c as usize].rem_euclid(P2), self.zp((2 * k + 1) * c))) % P2 } s }).collect()
    }
    // C2S: poly Z -> poly with slot k' = coeff k' of Z ; d_g slot k' = ninv * zeta^{-(2k'+1) g k'}
    fn c2s_diag(&self, g: i64) -> Vec<i64> {
        let v: Vec<i64> = (0..N as i64).map(|k| mulm(self.ninv, self.zp(-(2 * k + 1) * g * k))).collect();
        self.encode(&v)
    }
    // S2C: poly P with slots v -> poly with coeffs v ; c_g slot k' = zeta^{(2k'+1) kk}, kk=((g(2k'+1) mod 2N)-1)/2
    fn s2c_diag(&self, g: i64) -> Vec<i64> {
        let v: Vec<i64> = (0..N as i64).map(|k| { let kk = ((g * (2 * k + 1)).rem_euclid(2 * N as i64) - 1) / 2; self.zp((2 * k + 1) * kk) }).collect();
        self.encode(&v)
    }
}
fn centered_i(v: i64) -> i64 { let r = v.rem_euclid(P2); if r * 2 > P2 { r - P2 } else { r } }

// ---------- digit polynomial F (ascending, mod p^2) ----------
fn construct_f() -> Vec<i64> {
    let mm = |a: &Vec<i64>, b: &Vec<i64>, m: i64| { let mut o = vec![0i64; a.len() + b.len() - 1]; for (i, x) in a.iter().enumerate() { for (j, y) in b.iter().enumerate() { o[i + j] = (o[i + j] + x * y).rem_euclid(m) } } o };
    let ev = |c: &Vec<i64>, x: i64, m: i64| { let mut o = 0i64; for &k in c.iter().rev() { o = (o * x + k).rem_euclid(m) } o };
    let mut g = vec![1i64];
    for r in -B..=B { g = mm(&g, &vec![(-r).rem_euclid(P2), 1], P2); }
    let mut h = vec![0i64; g.len() - 1];
    for r in -B..=B {
        let mut q = vec![0i64; g.len() - 1];
        let l = q.len() - 1; q[l] = g[l + 1].rem_euclid(P);
        for i in (0..l).rev() { q[i] = (g[i + 1] + r * q[i + 1]).rem_euclid(P); }
        let d = ev(&q, r, P);
        let mut inv = 1i64; for _ in 0..(P - 2) { inv = inv * d % P } // d^(p-2)
        for (i, c) in q.iter().enumerate() { h[i] = (h[i] + c * inv % P * inv).rem_euclid(P); }
    }
    let gh = mm(&g, &h, P2);
    let mut f: Vec<i64> = gh.iter().map(|c| (-c).rem_euclid(P2)).collect();
    f[1] = (f[1] + 1).rem_euclid(P2);
    while f.len() > 1 && *f.last().unwrap() == 0 { f.pop(); }
    f
}
fn main() {
    let t0 = std::time::Instant::now();
    let mut rng = Rng(0x4352_414d_2d31 ^ std::env::args().nth(1).and_then(|a| a.parse::<u64>().ok()).unwrap_or(0).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    // digit polynomial exhaustive check
    let f = construct_f();
    for r in -B..=B { for m in 0..P {
        let w = (r + P * m).rem_euclid(P2);
        let mut o = 0i64; for &c in f.iter().rev() { o = (o * w + c).rem_euclid(P2) }
        assert_eq!(centered_i(o), r);
    } }
    println!("digit polynomial: degree {} verified on all {} domain points", f.len() - 1, (2 * B + 1) * P);
    let slots = Slots::new();
    // source
    let qin = BigInt::from(P) << 40u32;
    let src = Ctx::new(qin.clone(), P);
    let mut s: Poly = zero(); let mut placed = 0;
    while placed < H { let i = (rng.next() % N as u64) as usize; if s[i].is_zero() { s[i] = bi(if rng.next() & 1 == 0 { 1 } else { -1 }); placed += 1 } }
    let m: Poly = (0..N).map(|_| bi((rng.next() % P as u64) as i64)).collect();
    let mut ct = enc(&src, &s, &m, &mut rng);
    // stress input noise: add e_extra = Delta/(4p)*... to c0 coefficient 0 and 1
    let extra = &src.delta / (BigInt::from(4 * P));
    ct.c0[0] = (&ct.c0[0] + &extra).mod_floor(&src.q);
    ct.c0[1] = (&ct.c0[1] - &extra).mod_floor(&src.q);
    let nb_in = noise_bits(&src, &s, &ct, &m);
    assert_eq!(dec(&src, &s, &ct), m);
    // outer ring
    let kbits = 900u32;
    let qout = BigInt::from(P2) << kbits;
    let out = Ctx::new(qout.clone(), P2);
    let s2: Poly = (0..N).map(|_| bi(rng.small(1))).collect();
    let s2sq = pred(&pmul_z(&s2, &s2), &out.q);
    let w = 32u32;
    let rlk = gen_ksk(&out, &s2sq, &s2, w, &mut rng);
    let gks: Vec<(usize, Ksk)> = (1..2 * N).step_by(2).filter(|&g| g != 1).map(|g| (g, gen_ksk(&out, &aut(&s2, g), &s2, w, &mut rng))).collect();
    // bootstrapping key: encryption of s (plaintext mod p^2) under S'
    let sp: Poly = s.iter().map(|v| v.mod_floor(&bi(P2))).collect();
    let bk = enc(&out, &s2, &sp, &mut rng);
    // evaluator-only from here: uses ct, bk, rlk, gks, ret key (no s, no s2)
    let a: [Vec<i64>; 2] = [&ct.c0, &ct.c1].map(|c| c.iter().map(|v| div_round(&(bi(P2) * v), &src.q).mod_floor(&bi(P2)).to_i64().unwrap()).collect());
    let z = plain_mul(&out, &bk, &a[1]); // plaintext a1*s
    let galois = |ct: &Ct, diag: &dyn Fn(i64) -> Vec<i64>| -> Ct {
        let mut acc: Option<Ct> = None;
        for g in (1..2 * N).step_by(2) {
            let sw = if g == 1 { ct.clone() } else {
                let (_, ks) = gks.iter().find(|(gg, _)| *gg == g).unwrap();
                apply_ksk(&out, ks, &aut(&ct.c0, g), &aut(&ct.c1, g))
            };
            let term = plain_mul(&out, &sw, &diag(g as i64));
            acc = Some(match acc { None => term, Some(x) => ct_add(&out, &x, &term) });
        }
        acc.unwrap()
    };
    let cw = galois(&z, &|g| slots.c2s_diag(g).iter().map(|&v| centered_i(v)).collect());
    let a0slots = slots.encode(&a[0]);
    let cw = add_plain(&out, &cw, &a0slots.iter().map(|&v| centered_i(v)).collect::<Vec<_>>());
    // diagnostic (observer): W slots = p*m + eps
    let wdec: Poly = dec(&out, &s2, &cw);
    let wslots = slots.decode(&wdec.iter().map(|v| v.to_i64().unwrap()).collect::<Vec<_>>());
    let mut max_eps = 0i64;
    for j in 0..N { let eps = centered_i(wslots[j] - P * m[j].to_i64().unwrap()); max_eps = max_eps.max(eps.abs()); assert!(eps.abs() <= B); }
    println!("observer: W = p*m + eps with max|eps|={} (B={}) after encrypted C2S", max_eps, B);
    // digit extraction: Horner
    let mut acc = Ct { c0: { let mut p = zero(); p[0] = (&out.delta * bi(centered_i(f[f.len() - 1]))).mod_floor(&out.q); p }, c1: zero() };
    for k in (0..f.len() - 1).rev() {
        acc = ct_mul(&out, &acc, &cw, &rlk);
        let mut cst = vec![0i64; N]; cst[0] = centered_i(f[k]);
        acc = add_plain(&out, &acc, &cst);
    }
    let cpm = ct_sub(&out, &cw, &acc); // slots = p*m
    let cs = galois(&cpm, &|g| slots.s2c_diag(g).iter().map(|&v| centered_i(v)).collect()); // coeffs = p*m mod p^2
    let pm: Poly = m.iter().map(|v| v * P).collect();
    assert_eq!(dec(&out, &s2, &cs), pm.iter().map(|v| v.mod_floor(&bi(P2))).collect::<Poly>());
    println!("observer: encrypted digit extraction + S2C gives plaintext p*m exactly; outer noise bits = {}", noise_bits(&out, &s2, &cs, &pm.iter().map(|v| v.mod_floor(&bi(P2))).collect()));
    // view as t=p, switch modulus to Q_in
    let ms = |p: &Poly| -> Poly { p.iter().map(|v| div_round(&(v * &qin), &qout).mod_floor(&qin)).collect() };
    let swc = Ct { c0: ms(&cs.c0), c1: ms(&cs.c1) };
    // return key switch S' -> s at Q_in
    let ret = gen_ksk(&src, &pred(&s2, &qin), &s, 8, &mut rng);
    let fin = apply_ksk(&src, &ret, &swc.c0, &swc.c1);
    let back = dec(&src, &s, &fin);
    assert_eq!(back, m);
    let nb_out = noise_bits(&src, &s, &fin, &m);
    println!("REFRESH EXACT: all {} coefficients recovered under original key at original modulus", N);
    println!("input noise bits {} (budget {} bits)  ->  output noise bits {}", nb_in, (&src.delta / BigInt::from(2)).bits(), nb_out);
    // multiplication after refresh sanity: relin at source level and square
    println!("elapsed {:?}", t0.elapsed());
}
