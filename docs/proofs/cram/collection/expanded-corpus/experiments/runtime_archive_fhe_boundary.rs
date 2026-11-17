#[path = "../archives/14-Crate-12/arith.rs"] mod arith;
#[path = "../archives/14-Crate-12/operators.rs"] mod operators;
#[path = "../archives/14-Crate-12/garner.rs"] mod garner;
#[path = "../archives/14-Crate-12/topology.rs"] mod topology;
#[path = "../archives/14-Crate-12/engine.rs"] mod engine;
#[path = "../archives/14-Crate-12/fhe.rs"] mod fhe;

fn main() {
    let mut demo = fhe::Nine65Engine::new();
    let ct = demo.encrypt(42);
    assert_eq!(ct.message.residues, garner::decompose(42, &demo.cram.topology.primes()));
    let (got, bootstraps, ops) = demo.evaluate_unlimited_depth(1, &[(false, 1); 5]);
    println!("source=Crate-12/fhe.rs, initial=1, additions=5, expected=6, got={got}, bootstraps={bootstraps}, operations={ops}");
    assert_eq!(got, 0);
    println!("Confirmed: this archived simulator substitutes encrypt(0) after failed noise inversion. This is not the current NINE65 encrypted backend.");
}
