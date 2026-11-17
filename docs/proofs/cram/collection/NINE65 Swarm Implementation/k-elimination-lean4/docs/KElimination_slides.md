# K‑Elimination — Exact RNS Division (Formally Verified)

## Problem & Breakthrough
- RNS division historically: O(k²) via Mixed Radix Conversion, often approximate.
- K‑Elimination: closed-form overflow recovery
  - k = (vₐ − vₘ) · M⁻¹ (mod A), with gcd(M, A)=1, X ∈ [0, M·A)
  - Exact, O(k) complexity, no floating-point.

## Proof Status (Credibility)
- Lean 4: 27 theorems, 0 sorry/admit.
- Coq: 10 lemmas, 0 admitted.
- “Closed under the global context” (no hidden axioms).
- Repro:
  ```bash
  lake build
  coqc coq/K_Elimination.v   # Coq 8.20.1
  ```

## Why It Matters
- FHE: bootstrap-free rescaling (exact division), real-time pipelines.
- Parallel RNS/DSP: keep parallelism, exact division without k-tracking.
- Formal methods: dual proof assistants, reproducible builds.

## Core Proof Idea
- Key congruence: X % A = (X % M + (X / M) * M) % A.
- Multiply by M⁻¹ mod A to recover k exactly (since k < A).
- Requirements: gcd(M, A)=1, A>0, X < M·A.

## Repo & License
- Repo: https://github.com/Skyelabz210/k-elimination-lean4
- MIT license.
- Contents: KElimination.lean (Lean), coq/K_Elimination.v (Coq), docs/, FAQ.md.

## Quick Start (Reproduce)
```bash
git clone https://github.com/Skyelabz210/k-elimination-lean4.git
cd k-elimination-lean4
lake build
coqc coq/K_Elimination.v
```
- Expected: builds succeed; Coq prints closed assumptions for k_elimination_core.

## Applications & CTA
- FHE engineers: drop into rescaling/division path, benchmark.
- DSP/parallel RNS: exact division without reconstruction overhead.
- Formal methods: inspect proofs, extend to related theorems.
- Call to action: run the proofs, integrate, share benchmarks & feedback.
