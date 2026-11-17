# CRAM Lift, K-Elimination, and Reconstruction Inventory

## Governing source hierarchy

1. **Normative authority:** `/home/ubuntu/cram_threaded_docs/RECONCILED_NORMATIVE_KERNEL.md` and threads 1–6. These supersede conflicting historical implementation statements.
2. **Executable/formal sources:** `starlift.py`; `KElimination.lean`; `KElimination/Adjacency.lean`; Coq artifacts (source present, current environment has no Lean toolchain to compile).
3. **Architecture/application sources:** CRAM corpus chapters 06–09, A-07, and NINE65_v7 architecture/benchmark/audit materials.
4. **Historical/background sources:** standard CRT/Garner descriptions, Dual Codex alternatives, Chimera/WASSAN/physical applications. These are never elevated above the normative core without an admissibility proof.

## Lift taxonomy

| ID | Lift / coordinate | Definition / purpose | Exactness status | Capacity or domain condition | Core status |
|---|---|---|---|---|---|
| L1 | Fixed-frame canonical lift | `x = gamma_B(r) + M_B K`; `V_B=(r,K)` | bijective for fixed pairwise-coprime `B` | `K` retained as integer | CORE-PROVEN |
| L2 | Single-modulus arithmetic lift | `x = r_M(x) + M K_M(x)` | division algorithm | none if `K_M` stored | CORE-PROVEN |
| L3 | Trajectory covering lift | canonical path lift `x_t/M`; closed path winding `K_T-K_0` | exact under explicit interpolation and closure | requires time-indexed path and equal endpoint residues | CORE-CONDITIONAL |
| L4 | Constrained CRT-torus lift | winding vector `ell(M/m_i)_i` for scalar trajectory closure | exact rank-one sublattice statement | scalar trajectory, pairwise-coprime frame, closure | CORE-PROVEN |
| L5 | Generic anchor-observed lift | `kappa_A=(r_A-r_M)M^{-1} mod A = K mod A` | exact congruence | `gcd(M,A)=1`; authentic preprovisioned residues | CORE-PROVEN |
| L6 | Consecutive-pair/adjacency lift | for `(M,A)=(n,n+1)`, `K mod A=(r_n-r_{n+1}) mod A` | exact congruence | authentic pair; representative capacity required for full `K` | CORE-PROVEN |
| L7 | 36/37 StarLift | `M=36`, `A=37`, single subtraction | exact congruence; full reconstruction bounded | `0<=K<37`; equivalently `0<=x<1332` | CORE-CONDITIONAL (full recovery), CORE-PROVEN (congruence) |
| L8 | Star-number geometric lift | `S_n=6n(n-1)+1 = ring(n)+1`; `36+1=37` | arithmetic identity | defines a selected shell/anchor geometry; not itself a general reconstruction method | CORE-PROVEN identity |
| L9 | Anchor-ladder lift | `K mod C` from pairwise-coprime anchors, `C=prod A_j` | exact modular recovery | exact iff certified `0<=K<C` | CORE-CONDITIONAL |
| L10 | Overflow epoch lift | `K=QC+Khat`, update `Q` by exact Euclidean capacity carry | exact unbounded history representation | retained epoch required after capacity crossing | CORE-PROVEN |
| L11 | Recombinant CRT winding | per-lane windings and tuple winding preserve overflow history | representation design; historical CRAM claims require fixed-frame conformance | needs exact retained counter updates; no silent reconstruction | CORE-CONDITIONAL |
| L12 | Phase-lock transduction coordinate | `D_a=r_a-r_A-A*kappa_a == 0 mod a` | exact invariant for declared updates | fixed authentic anchor and update equations | CORE-CONDITIONAL |
| L13 | Input-retaining reversible lift | embed non-bijective arithmetic, e.g. `(x,y,z)->(x,y,z+x+y)` | exact reversible transition | inputs/inverse witnesses must be retained | CORE-PROVEN as pattern |
| L14 | Dual Codex magnitude (`beta`) | `alpha(X)=CRT residues`, `beta(X)=integer positional base-M magnitude` | exact if compatibility maintained | beta is explicitly stored, not inferred | ARCHITECTURAL / requires conformance alignment |
| L15 | Shadow anchor / SD-11 | fixed redundant residue and signature anchors `11^6,13,17,19` | may be an authentic check layer | `11^6` is not independent of a base containing `11`; no claim of independent CRT coordinate | CORE-CONDITIONAL as read-only check |
| L16 | FPD auxiliary-lane route | auxiliary coprime lane supports shared-factor division and specialized K-Elim | prose and empirical evidence; formal Lean outstanding | conflicts with no-runtime-DynCRT rule unless auxiliary is statically preprovisioned/authentic | BOUNDARY / REQUIRES STATIC-FRAME REFORMULATION |

## K-Elimination use inventory

| Use | Mechanism | Preconditions | Output | Status / source |
|---|---|---|---|---|
| U1: quotient observation | generic `kappa_A` | `gcd(M,A)=1`; authentic residues | `K mod A` | normative core, Thread 2 |
| U2: bounded exact magnitude | 36/37 adjacency subtraction | `0<=K<37` | full `K`, then `x=r_36+36K` | normative fast path |
| U3: certified wider magnitude | ladder CRT of `kappa_j` | pairwise-coprime anchors and `K<C` | full `K`, then base-plus-lift reconstruction | normative conditional |
| U4: unbounded trajectory state | ladder residue plus epoch | exact capacity carry retained | full `K=QC+Khat` | normative core |
| U5: coprime exact RNS division | phase differential on RNS basis | `gcd(b,M)=1`, `b|a`, fixed basis | quotient residue tuple `a/b` | CRAM Chapter 06; formal/source claimed |
| U6: FHE multiplication rescale | DualRNS exact division after tensor product | architecture-specific configuration and cryptographic correctness/noise proof | rescaled dual-track ciphertext coefficients | NINE65 active code/documentation; security/deployment remains provisional |
| U7: FHE scale-and-round / divider kernels | `ExactDivider::reconstruct_exact`, division and divmod | coefficient-level bounds and exactness preconditions | bounded integer result | benchmarked but not independent hardware synthesis proof |
| U8: scientific/NS quotient operations | advection/time-step/conservation factor division | divisor/representation-specific exactness conditions | exact quotient tuple | application claim; continuum implications remain OPEN |
| U9: FPD auxiliary reference | specialized phase differential for shared-factor divisors | `gcd(b,M)>1`, auxiliary coprime to `bM`, exact divisibility | primary-basis quotient tuple | historical CRAM method; must be static-frame safe |
| U10: phase-lock integrity checking | compare base/anchor residues with `kappa` | fixed declared relationship | zero/nonzero defect certificate | normative diagnostic only |
| U11: shadow-carrier typed operation | K-Elim acts on a value with SD-11 metadata | topology-specific type rules | typed output / verification state | non-normative until exact rule proof |
| U12: dual-codex synchronization | K-Elim on alpha, exact quotient update in beta | beta stored/compatible and division exact | synchronized alpha/beta output | architectural method, boundary from elimination-only core |

## Reconstruction pathways

| ID | Path | Formula / process | Runtime core admissibility |
|---|---|---|---|
| R1 | State-native reconstruction | `x=gamma_B(r)+M_BK` | exact representation theorem; `gamma_B` is specification/boundary oracle, not mandated hot path |
| R2 | Single-anchor 36/37 reconstruction | `K=(r_36-r_37) mod 37`; `x=r_36+36K` | admitted only with `0<=K<37` certificate |
| R3 | General consecutive-pair reconstruction | `K=(r_n-r_(n+1)) mod (n+1)`; `x=r_n+nK` | admitted only under `K<n+1` certificate |
| R4 | Generic anchor reconstruction | `K mod A=((r_A-r_M)M^{-1}) mod A`; then base-plus-lift | requires inverse + `K<A` certificate |
| R5 | Ladder reconstruction | merge anchor observations to `K mod C`, then `x=r_M+MK` | requires `K<C` certificate |
| R6 | Epoch-qualified ladder reconstruction | `K=QC+Khat`; `x=r_M+M(QC+Khat)` | supports unbounded history only if epoch is retained exactly |
| R7 | Recombinant CRT materialization | canonical residue + tracked tuple winding | conditionally aligned; requires exact winding-counter discipline |
| R8 | Direct CRT sum | `gamma_B(r)=sum r_i M_i(M_i^-1 mod m_i) mod M_B` | proof/reference/offline boundary allowed, not runtime core |
| R9 | Garner / mixed-radix | sequential CRT representative reconstruction | retired from runtime core; allowed only reference proof/test/boundary |
| R10 | Dual Codex beta export | return explicitly maintained big-integer `beta` | architectural/boundary method; must maintain alpha-beta compatibility |
| R11 | FPD quotient reconstruction | extended auxiliary calculation then primary tuple projection | conditional historic method; static preprovisioning/authenticity required under current rules |
| R12 | Exact rational result | normalized `(a,b)` pair or rejection certificate for non-divisible integer division | required alternative when `b` does not divide `a` |

## Critical corrections

- A single anchor yields only `K mod A`; it becomes the full lift only with a range certificate.
- A finite anchor ladder yields only `K mod C`; epoch state or an external bound is mandatory for unbounded executions.
- The 36/37 subtraction collapse is a consecutive-modulus specialization, not a generic property of higher star-prime anchors.
- No local K-Elimination coordinate is a Garner digit.
- A shadow prime may be an authentic fixed redundant check, but `11^6` cannot be an independent CRT coordinate when the base already contains `11`.
- Static preprovisioned anchor lanes are compatible with the core; runtime anchor emission/reprojection is not.
- The available Lean proof sources have not been recompiled in this sandbox because no Lean/Lake toolchain is installed; document claims must report source-formalization status, not current sandbox compilation success.

## Primary sources

- Threaded normative kernel and Threads 1–6.
- `Covering_Coordinates_and_Constrained_Torus_Winding..md`.
- `starlift.py`.
- `CRAMcorpus/06_k_elimination_theorem.md`, `07_recombinant_crt_winding.md`, `08_fused_piggyback_division.md`, `09_shadow_disambiguator.md`, `A-07_dual_codex_dcbigint.md`, `14_major_theorems_register.md`.
- `NINE65_v7/docs/ARCHITECTURE.md` and `benchmarks/baseline.json`.
- `k-elimination-lean4/KElimination.lean` and `KElimination/Adjacency.lean`.
