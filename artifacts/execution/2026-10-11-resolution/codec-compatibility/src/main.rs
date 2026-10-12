extern crate bincode as bincode_next;

#[derive(bincode::Encode, bincode::Decode, Debug, PartialEq)]
struct Poly {
    main: Vec<Vec<u64>>,
    anchor: Vec<Vec<u64>>,
    n: usize,
}

#[derive(bincode::Encode, bincode::Decode, Debug, PartialEq)]
struct Ciphertext {
    c0: Poly,
    c1: Poly,
    level: usize,
}

fn main() {
    let values = vec![0u64, 250, 251, 65535, 65536, u32::MAX as u64, u64::MAX];
    for value in [-1i128, 0, 1, i128::MIN, i128::MAX] {
        let fixture = (values.clone(), value, Some(value), true);
        let old = bincode_old::encode_to_vec(&fixture, bincode_old::config::standard()).unwrap();
        let new = bincode::encode_to_vec(&fixture, bincode::config::standard()).unwrap();
        assert_eq!(old, new);
        let (decoded, used): ((Vec<u64>, i128, Option<i128>, bool), usize) =
            bincode::decode_from_slice(&old, bincode::config::standard()).unwrap();
        assert_eq!(decoded, fixture);
        assert_eq!(used, old.len());
    }
    let main = vec![vec![0, 250], vec![251, 65536]];
    let anchor = vec![vec![65535, u64::MAX]];
    let fields = (main.clone(), anchor.clone(), 2usize);
    let old = bincode_old::encode_to_vec((&fields, &fields, 2usize), bincode_old::config::standard()).unwrap();
    let ct = Ciphertext {
        c0: Poly { main: main.clone(), anchor: anchor.clone(), n: 2 },
        c1: Poly { main, anchor, n: 2 },
        level: 2,
    };
    let new = bincode::encode_to_vec(&ct, bincode::config::standard()).unwrap();
    assert_eq!(new, old);
    let (decoded, used): (Ciphertext, usize) =
        bincode::decode_from_slice(&old, bincode::config::standard()).unwrap();
    assert_eq!(decoded, ct);
    assert_eq!(used, old.len());
    println!("bincode 2.0.1 / bincode-next 2.1.0: 6 fixtures match; ciphertext golden = {old:?}");
}
