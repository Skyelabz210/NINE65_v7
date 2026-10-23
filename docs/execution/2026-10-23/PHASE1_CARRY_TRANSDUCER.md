# Phase-1 carry transducer candidate

This freezes the three checked pieces of the public-refresh route into one
research function. It is the integer image of the missing carry. It is not an
encrypted producer, and it does not admit public refresh.

## What the function does

`scripts/phase1_carry_transducer.py` checks, in one call:

1. The pinned displaced-state counterexample from
   `displaced_state_scalar_counterexample_is_the_missing_carry`. For
   `Q=17`, `t=5`, `c0=c1=s=1`, component rounding returns 0 and the combined
   phase returns 1. The missing term is `K=round((R0+R1·s)/Q)=1`. Both
   inputs are already centered, so centering is not the repair. No pair
   `(A0,A1)` in `Z/tZ` matches the map on secrets `-1,0,1`.
2. The same identity on the pinned negacyclic pair
   `c0=(1,0)`, `c1=(1,1)`, `s=(1,-1)`, where `K=(1,0)` and `|K|≤N/2`.
3. The evaluator-only reconstruction
   `K=k49-49·c` from canonical residues `Y mod 49`, `w mod 49`, `Y mod 2`,
   and `w mod 2`. The chart oracle supplies those residues. The evaluator
   function does not receive `s` or `Z99`. Boundary carries
   `-48,-1,0,1,48` agree, as do the zero-residual points `Z99=0,1`.
4. The existing paired-chart oracle, including all source-correlated 49/2
   checks, still reports `public_refresh_admitted = false`.
5. Scale-locked re-decode at `A=121` and `A=5632` still recovers a decodable
   carry and still refuses the following dense square (159 bits and 155 bits
   against the 119-bit work modulus).

## What it does not do

The residues are not produced from a dense work ciphertext. The direct
`2^15` route and the composite route both still need that producer. The
scale-locked residual is still inside the return. Nothing in this candidate
changes `public_phase1_soundness_gate`.

```text
python3 scripts/test_phase1_carry_transducer.py
python3 scripts/phase1_carry_transducer.py
```

Issue #95 stays open.
