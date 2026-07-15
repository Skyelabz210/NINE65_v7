# CT-NTT and Persistent-Montgomery Audit — 2026-07-13

**Scope:** source-level arithmetic and address-schedule review on `hardening/beyond-100-app-platform`.

## Findings before remediation

1. `ntt_fft.rs` used data-dependent branches for butterfly modular addition and subtraction.
2. Public coefficient `add`, `sub`, and `neg` methods in the same engine also branched on coefficient values.
3. `PersistentMontgomery` used data-dependent branches in REDC final reduction, add, subtract, negation, and exponentiation.
4. `NTTEngineFFT::try_new` checked root compatibility but did not explicitly enforce the CLASS-F prime requirement.
5. The side-channel document described Montgomery/K-Elimination hardening as complete while separately listing CT-NTT as future work; that wording was internally inconsistent.

## Source remediation

### NTT FFT

- The constructor now invokes the canonical deterministic u64 primality validator.
- Composite NTT moduli are rejected even when `q - 1` is divisible by `2N`.
- Butterfly add/sub route through `MontgomeryContext::montgomery_add` and `montgomery_sub`.
- Public coefficient add/sub/neg use the same branchless primitives.
- Local branchy `mont_add` and `mont_sub` implementations were removed.
- Primitive-root search and modular inverse remain variable-time setup operations over public parameters.
- Bit-reversal swapping depends only on public indices.
- Shadow-capture branching depends only on the public instrumentation option.

### Persistent Montgomery

- The context now enforces the actual CLASS-R requirements: odd modulus, greater than one, and below `2^63` for the selected one-subtraction arithmetic bounds.
- Primality is not imposed. An odd composite modulus test verifies ring-level multiplication/addition/subtraction.
- REDC final reduction, add, subtract, and negation are branchless.
- Exponentiation uses a fixed 64-iteration Montgomery ladder.
- The inverse convenience method remains explicitly field-only and its zero/nonzero `Option` result is a visible validity boundary. It is not used outside the module.

## Prime and basis checks

The current main NTT prime catalog and named-profile prime lanes were independently rechecked with deterministic u64 Miller–Rabin during this audit. All inspected values passed. The code now repeats the prime check at NTT construction instead of relying solely on catalog provenance.

The distinction is enforced:

- NTT computation lanes: CLASS-F, primality required.
- Persistent Montgomery ring arithmetic: CLASS-R, odd coprime modulus sufficient.
- K-Elimination/anchor operations: CLASS-R with coprimality and range proofs.

## Exact-integer verification added

- NTT round-trip, negacyclic multiplication, and schoolbook differential tests.
- NTT rejection test for composite but root-compatible-looking modulus `65`.
- Branchless coefficient add/sub/neg equivalence tests.
- Persistent Montgomery round-trip, multiplication, chain, fixed-iteration power, and ring-operation tests.
- Exhaustive odd composite modulus `15` ring test.
- Source gate `scripts/check_ct_ntt_source.py`.
- Public butterfly schedules for `N = 8, 16, 1024` are generated without data input; the expected butterfly counts are `12`, `32`, and `5120`.

## Evidence limits

This audit does **not** establish a universal constant-time claim. Remaining gates:

1. compile the exact source under pinned compiler/target flags;
2. inspect generated IR and disassembly;
3. capture address traces on supported targets;
4. verify twiddle-table cache-line placement or document the deployment assumption;
5. run fixed-vs-random integer-cycle timing diagnostics;
6. assess speculative-execution, scheduler, SMT, power, and EM channels;
7. rerun after compiler, target, or arithmetic changes.

Until those gates pass, the approved statement is:

> The reviewed NTT and Persistent-Montgomery source paths use public address schedules and branchless coefficient arithmetic, with compiler and hardware side-channel closure pending.
