//! Unsigned restoring division as a value-independent Boolean circuit.
//! Wires are Boolean by construction; no ciphertext or secret is inspected.

use std::collections::BTreeMap;

pub(super) type Wire = usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Node {
    Constant(bool),
    Input(bool, usize), // true: numerator, false: denominator; little-endian bit
    Not(Wire),
    And(Wire, Wire),
    Xor(Wire, Wire),
    DisjointOr(Wire, Wire),
    Select(Wire, Wire, Wire), // condition, true value, false value
}

impl Node {
    pub(super) fn inputs(self) -> Vec<Wire> {
        match self {
            Self::Constant(_) | Self::Input(_, _) => vec![],
            Self::Not(a) => vec![a],
            Self::And(a, b) | Self::Xor(a, b) | Self::DisjointOr(a, b) => vec![a, b],
            Self::Select(c, a, b) => vec![c, a, b],
        }
    }
}

pub(super) struct Circuit {
    pub(super) nodes: Vec<Node>,
    pub(super) quotient: Vec<Wire>,
    pub(super) remainder: Vec<Wire>,
    pub(super) zero: Wire,
}

struct Builder {
    nodes: Vec<Node>,
    memo: BTreeMap<Node, Wire>,
}

impl Builder {
    fn new() -> Self {
        Self {
            nodes: vec![Node::Constant(false), Node::Constant(true)],
            memo: BTreeMap::new(),
        }
    }
    fn push(&mut self, node: Node) -> Wire {
        if let Some(&wire) = self.memo.get(&node) {
            return wire;
        }
        let wire = self.nodes.len();
        self.nodes.push(node);
        self.memo.insert(node, wire);
        wire
    }
    fn not(&mut self, a: Wire) -> Wire {
        match self.nodes[a] {
            Node::Constant(value) => usize::from(!value),
            Node::Not(inner) => inner,
            _ => self.push(Node::Not(a)),
        }
    }
    fn and(&mut self, a: Wire, b: Wire) -> Wire {
        if a == 0 || b == 0 {
            0
        } else if a == b || b == 1 {
            a
        } else if a == 1 {
            b
        } else {
            self.push(Node::And(a.min(b), a.max(b)))
        }
    }
    fn xor(&mut self, a: Wire, b: Wire) -> Wire {
        if a == b {
            0
        } else if b == 0 {
            a
        } else if a == 0 {
            b
        } else if a == 1 {
            self.not(b)
        } else if b == 1 {
            self.not(a)
        } else {
            self.push(Node::Xor(a.min(b), a.max(b)))
        }
    }
    fn disjoint_or(&mut self, a: Wire, b: Wire) -> Wire {
        if a == 0 {
            b
        } else if b == 0 {
            a
        } else {
            self.push(Node::DisjointOr(a.min(b), a.max(b)))
        }
    }
    fn select(&mut self, c: Wire, yes: Wire, no: Wire) -> Wire {
        if c == 1 || yes == no {
            yes
        } else if c == 0 {
            no
        } else {
            self.push(Node::Select(c, yes, no))
        }
    }
    fn product(&mut self, bits: &[Wire]) -> Wire {
        match bits.len() {
            0 => 1,
            1 => bits[0],
            n => {
                let a = self.product(&bits[..n / 2]);
                let b = self.product(&bits[n / 2..]);
                self.and(a, b)
            }
        }
    }
}

impl Circuit {
    /// Compile the final GCD consumer directly for small public widths. All
    /// table indices and Euclidean reductions below are public constants.
    /// No ciphertext value is inspected or used to address the table.
    pub(super) fn gcd_small_table(a_width: usize, b_width: usize) -> Self {
        assert!((1..=4).contains(&a_width));
        assert!((1..=4).contains(&b_width));
        let width = a_width.max(b_width);
        let mut builder = Builder::new();
        let mut selectors = |first: bool, size: usize| {
            let bits: Vec<_> = (0..size)
                .map(|i| builder.push(Node::Input(first, i)))
                .collect();
            (0usize..1 << size)
                .map(|value| {
                    let factors: Vec<_> = bits
                        .iter()
                        .enumerate()
                        .map(|(i, &bit)| {
                            if value >> i & 1 == 1 {
                                bit
                            } else {
                                builder.not(bit)
                            }
                        })
                        .collect();
                    builder.product(&factors)
                })
                .collect::<Vec<_>>()
        };
        let first = selectors(true, a_width);
        let second = selectors(false, b_width);
        let mut answer = vec![0; width];
        for (a, &aw) in first.iter().enumerate() {
            for (b, &bw) in second.iter().enumerate() {
                let (mut x, mut y) = (a, b);
                // Public indices only; 2w is an exact finite compiler bound.
                for _ in 0..2 * width {
                    if y != 0 {
                        (x, y) = (y, x % y);
                    }
                }
                let term = builder.and(aw, bw);
                for (i, bit) in answer.iter_mut().enumerate() {
                    if x >> i & 1 == 1 {
                        *bit = builder.disjoint_or(*bit, term);
                    }
                }
            }
        }
        let mut result = Self {
            nodes: builder.nodes,
            quotient: answer,
            remainder: vec![],
            zero: 1,
        };
        result.remove_dead_nodes();
        result
    }

    /// Fixed-schedule unsigned Euclid. `quotient` holds the GCD; the other
    /// outputs are empty/true and are private adapter details. The input
    /// widths are public. No input value controls circuit construction.
    pub(super) fn gcd(a_width: usize, b_width: usize) -> Self {
        assert!((1..=8).contains(&a_width));
        assert!((1..=8).contains(&b_width));
        let width = a_width.max(b_width);
        let mut builder = Builder::new();
        let mut a: Vec<_> = (0..a_width)
            .map(|i| builder.push(Node::Input(true, i)))
            .collect();
        let mut b: Vec<_> = (0..b_width)
            .map(|i| builder.push(Node::Input(false, i)))
            .collect();
        a.resize(width, 0);
        b.resize(width, 0);
        let divider = Self::new(width, width);
        for _ in 0..2 * width {
            let mut wires = Vec::with_capacity(divider.nodes.len());
            for &node in &divider.nodes {
                let wire = match node {
                    Node::Constant(value) => usize::from(value),
                    Node::Input(first, i) => {
                        if first {
                            a[i]
                        } else {
                            b[i]
                        }
                    }
                    Node::Not(x) => builder.not(wires[x]),
                    Node::And(x, y) => builder.and(wires[x], wires[y]),
                    Node::Xor(x, y) => builder.xor(wires[x], wires[y]),
                    Node::DisjointOr(x, y) => builder.disjoint_or(wires[x], wires[y]),
                    Node::Select(c, x, y) => builder.select(wires[c], wires[x], wires[y]),
                };
                wires.push(wire);
            }
            let zero = wires[divider.zero];
            let next_a = a
                .iter()
                .zip(&b)
                .map(|(&x, &y)| builder.select(zero, x, y))
                .collect();
            let next_b = divider
                .remainder
                .iter()
                .map(|&r| builder.select(zero, 0, wires[r]))
                .collect();
            a = next_a;
            b = next_b;
        }
        let mut result = Self {
            nodes: builder.nodes,
            quotient: a,
            remainder: vec![],
            zero: 1,
        };
        result.remove_dead_nodes();
        result
    }

    pub(super) fn new(numerator_width: usize, denominator_width: usize) -> Self {
        // A public truth table lowers depth for small words. Larger words use
        // the quadratic-size restoring circuit, never an exponential table.
        let mut circuit = if numerator_width.max(denominator_width) <= 4 {
            Self::small_table(numerator_width, denominator_width)
        } else {
            Self::restoring(numerator_width, denominator_width)
        };
        circuit.remove_dead_nodes();
        circuit
    }

    fn small_table(numerator_width: usize, denominator_width: usize) -> Self {
        assert!((1..=4).contains(&numerator_width));
        assert!((1..=4).contains(&denominator_width));
        let mut b = Builder::new();
        let mut selectors = |numerator: bool, width: usize| {
            let bits: Vec<_> = (0..width)
                .map(|i| b.push(Node::Input(numerator, i)))
                .collect();
            (0usize..1 << width)
                .map(|value| {
                    let factors: Vec<_> = bits
                        .iter()
                        .enumerate()
                        .map(|(i, &bit)| {
                            if (value >> i) & 1 == 1 {
                                bit
                            } else {
                                b.not(bit)
                            }
                        })
                        .collect();
                    b.product(&factors)
                })
                .collect::<Vec<_>>()
        };
        let ns = selectors(true, numerator_width);
        let ds = selectors(false, denominator_width);
        let mut quotient = vec![0; numerator_width];
        let mut remainder = vec![0; numerator_width];
        for (n, &nw) in ns.iter().enumerate() {
            for (d, &dw) in ds.iter().enumerate() {
                let term = b.and(nw, dw);
                // Only public candidate indices are divided at compilation.
                // No encrypted value is decrypted, divided or used to index.
                let (q, r) = if d == 0 { (0, n) } else { (n / d, n % d) };
                for i in 0..numerator_width {
                    if (q >> i) & 1 != 0 {
                        quotient[i] = b.disjoint_or(quotient[i], term);
                    }
                    if (r >> i) & 1 != 0 {
                        remainder[i] = b.disjoint_or(remainder[i], term);
                    }
                }
            }
        }
        Self {
            nodes: b.nodes,
            quotient,
            remainder,
            zero: ds[0],
        }
    }

    fn remove_dead_nodes(&mut self) {
        let mut live = vec![false; self.nodes.len()];
        let mut pending: Vec<_> = self
            .quotient
            .iter()
            .chain(&self.remainder)
            .copied()
            .collect();
        pending.push(self.zero);
        while let Some(wire) = pending.pop() {
            if !live[wire] {
                live[wire] = true;
                pending.extend(self.nodes[wire].inputs());
            }
        }
        let mut mapping = vec![0; self.nodes.len()];
        let mut nodes = Vec::new();
        for (wire, &node) in self.nodes.iter().enumerate() {
            if !live[wire] {
                continue;
            }
            let node = match node {
                Node::Not(a) => Node::Not(mapping[a]),
                Node::And(a, b) => Node::And(mapping[a], mapping[b]),
                Node::Xor(a, b) => Node::Xor(mapping[a], mapping[b]),
                Node::DisjointOr(a, b) => Node::DisjointOr(mapping[a], mapping[b]),
                Node::Select(c, a, b) => Node::Select(mapping[c], mapping[a], mapping[b]),
                other => other,
            };
            mapping[wire] = nodes.len();
            nodes.push(node);
        }
        for wire in self
            .quotient
            .iter_mut()
            .chain(&mut self.remainder)
            .chain(std::iter::once(&mut self.zero))
        {
            *wire = mapping[*wire];
        }
        self.nodes = nodes;
    }

    pub(super) fn restoring(numerator_width: usize, denominator_width: usize) -> Self {
        assert!((1..=64).contains(&numerator_width));
        assert!((1..=64).contains(&denominator_width));
        let mut b = Builder::new();
        let numerator: Vec<_> = (0..numerator_width)
            .map(|i| b.push(Node::Input(true, i)))
            .collect();
        let mut denominator: Vec<_> = (0..denominator_width)
            .map(|i| b.push(Node::Input(false, i)))
            .collect();
        let inverted: Vec<_> = denominator.iter().map(|&bit| b.not(bit)).collect();
        let zero = b.product(&inverted);
        let nonzero = b.not(zero);
        let width = numerator_width.max(denominator_width) + 1;
        denominator.resize(width, 0);
        let mut remainder = vec![0; width];
        let mut quotient = vec![0; numerator_width];
        for i in (0..numerator_width).rev() {
            remainder.rotate_right(1);
            remainder[0] = numerator[i];
            let mut difference = Vec::with_capacity(width);
            let mut borrow = 0;
            for (&a, &d) in remainder.iter().zip(&denominator) {
                let parity = b.xor(a, d);
                difference.push(b.xor(parity, borrow));
                let not_a = b.not(a);
                let generate = b.and(not_a, d);
                let equal = b.not(parity);
                let propagate = b.and(equal, borrow);
                // generate requires a!=d; propagate requires a==d.
                borrow = b.disjoint_or(generate, propagate);
            }
            let take = b.not(borrow);
            for (r, diff) in remainder.iter_mut().zip(difference) {
                *r = b.select(take, diff, *r);
            }
            quotient[i] = b.and(take, nonzero);
        }
        remainder.truncate(numerator_width);
        Self {
            nodes: b.nodes,
            quotient,
            remainder,
            zero,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(circuit: &Circuit, numerator: u64, denominator: u64) -> (u64, u64, bool) {
        let mut values: Vec<bool> = Vec::new();
        for &node in &circuit.nodes {
            let value = match node {
                Node::Constant(v) => v,
                Node::Input(a, bit) => ((if a { numerator } else { denominator }) >> bit) & 1 != 0,
                Node::Not(a) => !values[a],
                Node::And(a, b) => values[a] & values[b],
                Node::Xor(a, b) => values[a] ^ values[b],
                Node::DisjointOr(a, b) => {
                    assert!(!(values[a] && values[b]));
                    values[a] | values[b]
                }
                Node::Select(c, a, b) => values[if values[c] { a } else { b }],
            };
            values.push(value);
        }
        let decode = |bits: &[Wire]| {
            bits.iter()
                .enumerate()
                .fold(0, |a, (i, &w)| a | ((values[w] as u64) << i))
        };
        (
            decode(&circuit.quotient),
            decode(&circuit.remainder),
            values[circuit.zero],
        )
    }

    #[test]
    fn gcd_circuit_exhaustive_small_unequal_widths() {
        fn expected(mut a: u64, mut b: u64) -> u64 {
            while b != 0 {
                (a, b) = (b, a % b);
            }
            a
        }
        for aw in 1..=4 {
            for bw in 1..=4 {
                for circuit in [Circuit::gcd(aw, bw), Circuit::gcd_small_table(aw, bw)] {
                    for a in 0..1 << aw {
                        for b in 0..1 << bw {
                            assert_eq!(run(&circuit, a, b), (expected(a, b), 0, true));
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn gcd_circuit_eight_bit_boundaries_and_seeded_cases() {
        let circuit = Circuit::gcd(8, 8);
        let mut cases = vec![
            (0, 0),
            (0, 255),
            (255, 0),
            (255, 255),
            (144, 233),
            (233, 144),
            (192, 128),
            (17, 255),
        ];
        let mut seed = 0x6cd65u64;
        for _ in 0..64 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let a = seed & 255;
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            cases.push((a, seed & 255));
        }
        for (a, b) in cases {
            let (mut x, mut y) = (a, b);
            while y != 0 {
                (x, y) = (y, x % y);
            }
            assert_eq!(run(&circuit, a, b).0, x, "gcd({a},{b})");
        }
    }

    #[test]
    fn fixed_euclid_round_bound_exhaustive_through_eight_bits() {
        let mut cases = 0;
        for width in 1..=8 {
            for a in 0u64..1 << width {
                for b in 0u64..1 << width {
                    let (mut expected, mut divisor) = (a, b);
                    while divisor != 0 {
                        (expected, divisor) = (divisor, expected % divisor);
                    }
                    let (mut x, mut y) = (a, b);
                    for _ in 0..2 * width {
                        if y != 0 {
                            (x, y) = (y, x % y);
                        }
                    }
                    assert_eq!((x, y), (expected, 0));
                    cases += 1;
                }
            }
        }
        assert_eq!(cases, 87380);
    }

    #[test]
    fn exhaustive_unsigned_division_with_unequal_widths() {
        for nw in 1..=5 {
            for dw in 1..=5 {
                for circuit in [Circuit::restoring(nw, dw), Circuit::new(nw, dw)] {
                    for n in 0..1 << nw {
                        for d in 0..1 << dw {
                            let expected = if d == 0 {
                                (0, n, true)
                            } else {
                                (n / d, n % d, false)
                            };
                            assert_eq!(run(&circuit, n, d), expected, "{n}/{d}, widths {nw}/{dw}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn full_u64_boundaries_and_random_inputs() {
        let circuit = Circuit::restoring(64, 64);
        let mut seed = 0xc001deadbeefu64;
        for n in [0, 1, u64::MAX, 1 << 63, (1 << 63) - 1] {
            for d in [0, 1, 2, 3, 17, u64::MAX, 1 << 63] {
                let expected = if d == 0 {
                    (0, n, true)
                } else {
                    (n / d, n % d, false)
                };
                assert_eq!(run(&circuit, n, d), expected);
            }
        }
        for _ in 0..128 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let n = seed;
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let d = seed;
            assert_eq!(run(&circuit, n, d), (n / d, n % d, false));
        }
    }
}
