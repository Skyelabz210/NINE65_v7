// Cost of the unchanged compiler at the reviewed NINE65 source snapshot.
#[path = "/workspace/NINE65_v7/crates/nine65/src/ops/integer_division_circuit.rs"]
mod circuit;
fn main() {
    for width in [1, 2, 3, 4, 5, 8, 16, 32, 64] {
        let c = circuit::Circuit::new(width, width);
        let products = c.nodes.iter().filter(|n| matches!(n, circuit::Node::And(..) | circuit::Node::Xor(..) | circuit::Node::Select(..))).count();
        println!("width={width} gates={} ciphertext_products={products}", c.nodes.len());
        if width == 4 { assert_eq!((c.nodes.len(), products), (761, 287)); }
    }
}
