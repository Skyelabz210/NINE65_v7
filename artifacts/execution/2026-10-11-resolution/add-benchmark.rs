#![allow(dead_code)]
#[path = "k_elim.rs"]
mod k_elim;
#[path = "dyn_crt.rs"]
mod dyn_crt;
#[path = "recumbent.rs"]
mod recumbent;

use dyn_crt::{reconstruction_count, reset_reconstruction_count, WindingCRT};
use recumbent::Recumbent;
use std::hint::black_box;
use std::time::Instant;

fn main() {
    const CHAINS: u64 = 10_000;
    let winding: Vec<_> = (1..=30).map(WindingCRT::from_i128).collect();
    let recumbent: Vec<_> = (1..=30).map(Recumbent::from_i128).collect();
    reset_reconstruction_count();
    let start = Instant::now();
    for _ in 0..CHAINS {
        let mut acc = WindingCRT::zero();
        for input in &winding {
            acc = black_box(acc).add(black_box(input));
        }
        assert_eq!(black_box(acc.to_i128()), Some(465));
    }
    let ns = start.elapsed().as_nanos();
    let count = reconstruction_count();
    println!("{{\"carrier\":\"WindingCRT\",\"chains\":{CHAINS},\"adds_per_chain\":30,\"elapsed_ns\":{ns},\"reconstructions\":{count},\"expected_value\":465}}");
    reset_reconstruction_count();
    let start = Instant::now();
    for _ in 0..CHAINS {
        let mut acc = Recumbent::zero();
        for input in &recumbent {
            acc = black_box(acc).add(black_box(input));
        }
        assert_eq!(black_box(acc.reconstruct()), Some(465));
    }
    let ns = start.elapsed().as_nanos();
    let count = reconstruction_count();
    println!("{{\"carrier\":\"Recumbent\",\"chains\":{CHAINS},\"adds_per_chain\":30,\"elapsed_ns\":{ns},\"reconstructions\":{count},\"expected_value\":465}}");
}
