//! Public DAG operation counts. This does not evaluate ciphertexts.
#[path = "../../../crates/nine65/src/ops/integer_division_circuit.rs"]
mod circuit;

fn main() {
    println!("[");
    let mut first = true;
    for width in 1..=8 {
        for strategy in ["fixed_euclid", "small_truth_table"] {
            if strategy == "small_truth_table" && width > 4 {
                continue;
            }
            let dag = if strategy == "fixed_euclid" {
                circuit::Circuit::gcd(width, width)
            } else {
                circuit::Circuit::gcd_small_table(width, width)
            };
            let mut depths = Vec::new();
            let mut products = 0;
            for node in &dag.nodes {
                let depth = node.inputs().iter().map(|&i| depths[i]).max().unwrap_or(0);
                let product = matches!(
                    node,
                    circuit::Node::And(..) | circuit::Node::Xor(..) | circuit::Node::Select(..)
                );
                products += usize::from(product);
                depths.push(depth + usize::from(product));
            }
            let depth = dag.quotient.iter().map(|&i| depths[i]).max().unwrap_or(0);
            if !first {
                println!(",");
            }
            first = false;
            print!("  {{\"strategy\":\"{strategy}\",\"width\":{width},\"rounds\":{},\"nodes\":{},\"products\":{products},\"product_depth\":{depth}}}",
                 if strategy == "fixed_euclid" {2*width} else {0}, dag.nodes.len());
        }
    }
    println!("\n]");
}
