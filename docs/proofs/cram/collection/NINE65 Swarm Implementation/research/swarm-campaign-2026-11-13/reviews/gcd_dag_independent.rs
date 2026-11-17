//! Independent executable test of the actual Boolean GCD DAG.
//! Compile from a copied source in the same directory (see command log).
#[path = "integer_division_circuit_review_copy.rs"]
mod circuit;

fn gcd_by_common_divisors(a: u64, b: u64) -> u64 {
    if a == 0 { return b; }
    if b == 0 { return a; }
    (1..=a.min(b)).rev().find(|d| a % d == 0 && b % d == 0).unwrap()
}

fn run(c: &circuit::Circuit, a: u64, b: u64) -> u64 {
    let mut values: Vec<bool> = Vec::with_capacity(c.nodes.len());
    for (index, node) in c.nodes.iter().enumerate() {
        for input in node.inputs() {
            assert!(input < index, "topological order");
        }
        let value = match *node {
            circuit::Node::Constant(v) => v,
            circuit::Node::Input(first, i) => ((if first { a } else { b }) >> i) & 1 == 1,
            circuit::Node::Not(x) => !values[x],
            circuit::Node::And(x, y) => values[x] && values[y],
            circuit::Node::Xor(x, y) => values[x] != values[y],
            circuit::Node::DisjointOr(x, y) => {
                assert!(!(values[x] && values[y]), "disjointness obligation");
                values[x] || values[y]
            }
            circuit::Node::Select(k, x, y) => if values[k] { values[x] } else { values[y] },
        };
        values.push(value);
    }
    assert!(values[c.zero]);
    assert!(c.remainder.is_empty());
    c.quotient.iter().enumerate().fold(0, |v,(i,&wire)| v | (u64::from(values[wire]) << i))
}

fn main() {
    let mut pairs = 0usize;
    for width in 1..=8 {
        let c = circuit::Circuit::gcd(width, width);
        for a in 0..1u64 << width {
            for b in 0..1u64 << width {
                assert_eq!(run(&c,a,b), gcd_by_common_divisors(a,b), "width={width}, a={a}, b={b}");
                pairs += 1;
            }
        }
        println!("width {width}: {} gates, {} pairs PASS",c.nodes.len(),1usize << (2*width));
    }
    let mut unequal = 0usize;
    for (aw,bw) in [(1,8),(8,1),(3,7),(7,3),(5,6),(6,5)] {
        let c = circuit::Circuit::gcd(aw,bw);
        for a in 0..1u64 << aw {
            for b in 0..1u64 << bw {
                assert_eq!(run(&c,a,b),gcd_by_common_divisors(a,b));
                unequal += 1;
            }
        }
    }
    let mut direct = 0usize;
    for aw in 1..=4 {
        for bw in 1..=4 {
            let c = circuit::Circuit::gcd_small_table(aw,bw);
            for a in 0..1u64 << aw {
                for b in 0..1u64 << bw {
                    assert_eq!(run(&c,a,b),gcd_by_common_divisors(a,b),"direct aw={aw}, bw={bw}, a={a}, b={b}");
                    direct += 1;
                }
            }
        }
    }
    println!("PASS: {pairs} equal-width plus {unequal} unequal-width fixed-Euclid and {direct} direct-table actual DAG evaluations");
}
