// Where does the combine first matter? Random program, 31-bit lanes vs one 64-bit anchor.
use certified_lift::*;
use num_bigint::BigUint;
struct Rng(u64);
impl Rng { fn next(&mut self) -> u64 { let mut x = self.0; x ^= x >> 12; x ^= x << 25; x ^= x >> 27; self.0 = x; x.wrapping_mul(0x2545F4914F6CDD1D) }
           fn below(&mut self, n: u64) -> u64 { self.next() % n } }
fn run(name: &str, shell: u64, anchors: &[u64], cap: usize, seed: u64) {
    const DIVS: [u64; 8] = [3, 5, 7, 11, 13, 17, 19, 23];
    let mut m = Machine::new(shell, anchors, 8, cap).unwrap();
    let mut rng = Rng(seed);
    for i in 0..8 { m.load(i, 1 + rng.below(1 << 20)).unwrap(); }
    let (mut refusals, mut cmps) = (0u64, 0u64);
    let steps = 20_000u64;
    for _ in 0..steps {
        let (a, b, d) = (rng.below(8) as usize, rng.below(8) as usize, rng.below(8) as usize);
        let op = rng.below(100);
        let r = if op < 25 { m.add(d, a, b) } else if op < 50 { m.mul(d, a, b) }
            else if op < 62 { match m.sub(d, a, b) { Err(LiftError::Underflow) => Ok(()), r => r } }
            else if op < 80 { m.cmp(a, b); cmps += 1; Ok(()) }
            else if op < 90 { m.mul_const(d, a, DIVS[rng.below(8) as usize]) }
            else { match m.div_exact(d, a, DIVS[rng.below(8) as usize]) { Err(LiftError::UnknownDivisor(_)) => Ok(()), r => r } };
        if let Err(LiftError::Capacity { .. }) = r { refusals += 1; m.load(d, 1 + rng.below(1 << 20)).unwrap(); }
    }
    let (kd, kc) = m.kernel().counters();
    let w: BigUint = m.kernel().window().clone();
    println!("{name:<28} cap={cap:<3} final anchors={:<3} window={:<5}b  growths={:<3} tightens={:<5} refusals={:<5} K reads={:<6} combines={}", m.kernel().anchors(), w.bits(), m.growths(), m.tightens(), refusals, kd, kc);
}
fn main() {
    let s31 = 2147483647u64; let a31 = [2147483629u64];
    let s64 = 18446744073709551557u64; let a64 = [18446744073709551533u64];
    for &seed in &[1u64, 2, 3] {
        println!("-- seed {seed}");
        run("31-bit lanes, no growth", s31, &a31, 1, seed);
        run("64-bit lanes, no growth", s64, &a64, 1, seed);
        run("31-bit lanes, growth<=64", s31, &a31, 64, seed);
        run("64-bit lanes, growth<=64", s64, &a64, 64, seed);
    }
}
