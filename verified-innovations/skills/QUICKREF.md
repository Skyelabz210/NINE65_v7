# GRANDMASTER Quick Reference

## Core Principles
1. INTEGER-ONLY (no floats)
2. THEOREM-GROUNDED (Coq proofs)
3. EXACT ARITHMETIC (error = 0)
4. BOOTSTRAP-FREE (GSO-FHE)
5. DETERMINISTIC (bit-identical)
6. SECURITY-AWARE (constant-time)

## Innovation Selection

| Problem | Use Innovation |
|---------|---------------|
| Exact division | K-Elimination |
| Factor semiprime | Order Finding + K-Oracle |
| Deep FHE | GSO-FHE + Montgomery |
| Neural net in FHE | MQ-ReLU + Softmax + Pade |
| Quantum | State Compression + Enc Quantum |
| Randomness | CRT Shadow Entropy |
| Signed arithmetic | MobiusInt |
| Trigonometry | Cyclotomic Phase |

## Workflow Phases

```
0. Context → 1. Recon → 2. Analysis → 2.5. Errors
     ↓
3. Design → 4. Implement → 4.5. Integration
     ↓
5. Validate → 5.5. Debug → 6. Synthesize → 6.5. Security → 7. Iterate
```

## Key Theorems

| Innovation | Theorem |
|-----------|---------|
| K-Elimination | `k_elimination_complete` |
| Order Finding | `lagrange_bound` |
| GSO-FHE | `depth_50_achievable` |
| MQ-ReLU | `speedup_is_2000x` |
| Integer Softmax | `integer_exact` |

## Proof Location

```
/home/acid/Projects/NINE65/MANA_boosted/proofs/coq/
```

## Full Methodology

```
/home/acid/Projects/NINE65/verified-innovations/methodology/GRANDMASTER_v2.md
```
