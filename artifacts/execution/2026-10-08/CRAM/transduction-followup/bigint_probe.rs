use exact_transcendentals::k_elim::{modd,mulmod,mod_inv};
use std::io::{self, BufRead};
fn main() {
    for line in io::stdin().lock().lines() {
        let v: Vec<i128> = line.unwrap().split_whitespace().map(|s|s.parse().unwrap()).collect();
        let inv = mod_inv(v[0],v[2]).map(|x|x.to_string()).unwrap_or_else(||"none".into());
        println!("{} {} {}",modd(v[0],v[2]),mulmod(v[0],v[1],v[2]),inv);
    }
}
