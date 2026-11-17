# kelim — K-Elimination Primitive Library

Exact, residue-native winding recovery. **A1** (zero floating-point) · **A2** (no approximation, exact integers only).

K-Elimination recovers the floor quotient `⌊X/M⌋` from the residue pair `(X mod M, X mod A)` entirely within residue space. The single requirement is `gcd(M, A) = 1`. Primality is neither required nor implied.

## Operations

| Function | Recovers | Requires |
|----------|----------|----------|
| `k_elim` | `⌊X/M⌋ mod A` | `gcd(M,A)=1` |
| `k_elim_adjacent` | `⌊X/M⌋ mod (M+1)` — subtraction only | `A=M+1` |
| `k_elim_dual` | `⌊X/A⌋ mod M` | `gcd(M,A)=1` |
| `k_elim_gradient` | `⌊X/M⌋ mod (A/d)` | `gcd(M,A)=d>1` |
| `tower_digit` | one mixed-radix level | pairwise coprime |
| `reconstruct` | full integer X | pairwise coprime |
| `rns_less_than` | `X < Y` (branch-free) | operands in `[0, M(M+1)/2)` |

## Selector

`selector::select(M, A)` returns the cheapest valid strategy:
- `AdjacentSubtraction` when `A = M+1`
- `GeneralKElim { m_inv }` when coprime, not adjacent
- `ResolutionGradient { inv_md, d, a_over_d }` when `gcd > 1`

Constants are precomputed; in a codegen backend the choice is a compile-time constant.

## Build & test

```
cargo test --release          # 9 exhaustive/large-sample tests, all exact
cargo run --release --bin encoder_demo
```

## Encoder demonstrator

Two-gear (35/36) multi-turn absolute encoder. Absolute position over the full
1260-position supercycle from a single subtraction. Verified exact over every
position. Per readout: 1 subtraction, 1 modulo, 1 multiply, 1 add — no inverse,
no lookup, no CRT solver.
