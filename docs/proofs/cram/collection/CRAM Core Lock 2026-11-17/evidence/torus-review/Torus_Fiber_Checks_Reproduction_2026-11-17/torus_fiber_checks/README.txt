Torus-Fiber Grammar: first computational checks (17 Nov 2026). Integer/rational only; no floating point.
  exact_checks.py   C1 tropical theta argmin, C2 Ramanujan 385 congruence, C3 Dresden prime-set null model (F6), C4 exact Ollivier-Ricci on lane graphs (F3)
  kbench.rs         F7 primitive: redundant-modulus K readout vs Garner over k ~62-bit lanes (rustc -O kbench.rs). Cross-checked against an independent modulus.
  *_output.txt      outputs of the runs reported
  strict_int_audit.py   integer-only audit used on the Python files; the Rust file was audited with a regex for f32/f64/float literals/.sqrt/.powf
Timings are single-core, shared machine: expect noise of tens of percent between runs.
