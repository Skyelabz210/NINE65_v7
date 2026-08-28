//! Safe-Basis composite lanes driven through the REAL KElimination API
//! (not a re-implementation), after removing the primality guard.
use nine65::arithmetic::k_elimination::KElimination;

fn bits(x: u128) -> u32 { if x == 0 {0} else {128 - x.leading_zeros()} }

fn run(label: &str, alpha: u64, beta: u64, rounds: u32) {
    let ke = match KElimination::try_new(&[alpha], &[beta]) {
        Ok(k) => k,
        Err(e) => { println!("  {label}\n     REJECTED: {e:?}"); return; }
    };
    let (a, b) = (alpha as u128, beta as u128);
    let cap = a * b;
    let (mut ok, mut bad) = (0u32, 0u32);
    let mut x: u128 = 0xDEADBEEFCAFEBABE;
    for _ in 0..rounds {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let xv = x % cap;
        if ke.extract_k(xv % a, xv % b) == xv / a { ok += 1 } else { bad += 1 }
    }
    // also exercise exact_divide, the operation the FHE rescale actually uses
    let mut dok = 0u32; let mut dbad = 0u32;
    for d in [2u64, 3, 5, 7, 11, 13] {
        for i in 1..500u128 {
            let v = (i * 7919) % (cap / 4);
            let vd = v - (v % d as u128);          // make it exactly divisible
            let got = ke.exact_divide(vd % a, vd % b, d);
            if got == vd / d as u128 { dok += 1 } else { dbad += 1 }
        }
    }
    println!("  {label}");
    println!("     alpha {:>3}b  beta {:>3}b  capacity {:>3}b", bits(a), bits(b), bits(cap));
    println!("     extract_k    {ok}/{}  mismatches {bad}", ok + bad);
    println!("     exact_divide {dok}/{}  mismatches {dbad}", dok + dbad);
}

fn main() {
    println!("=== Safe-Basis COMPOSITE lanes through the real KElimination API ===\n");
    run("M=2^20*3^12*5^8   A=7^10*11^6*13^5",
        (2u128.pow(20)*3u128.pow(12)*5u128.pow(8)) as u64,
        (7u128.pow(10)*11u128.pow(6)*13u128.pow(5)) as u64, 20000);
    run("M=2^40*3^4*5^4    A=7^6*11^4*13^8",
        (2u128.pow(40)*3u128.pow(4)*5u128.pow(4)) as u64,
        (7u128.pow(6)*11u128.pow(4)*13u128.pow(8)) as u64, 20000);
    run("M=2^25*3^12*5^8   A=7^7*11^5*13^5",
        (2u128.pow(25)*3u128.pow(12)*5u128.pow(8)) as u64,
        (7u128.pow(7)*11u128.pow(5)*13u128.pow(5)) as u64, 20000);
    let m = (2u128.pow(20)*3u128.pow(8)*5u128.pow(5)*7u128.pow(4)) as u64;
    run("adjacency A = M+1  (M=2^20*3^8*5^5*7^4)", m, m + 1, 20000);
    println!();
    run("control: shipped prime lane 998244353 / 4611686018427387847",
        998244353, 4611686018427387847, 20000);
}
