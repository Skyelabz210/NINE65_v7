# One Safe Basis root, arbitrary dependent sister trays

Date: 2026-10-20. Baseline: `128cbc16655c5f038dbc20502f74531d60895217`.

Owner clarification: there is **one** intact Safe Basis root. Subsequent
trays may use arbitrary moduli and are phase-related through the root's 2
and 11 roles. They do not each become another Safe Basis, nor do they need
to be pairwise-coprime with the root or with every other target view.

## What is already in the repository

`crates/exact_transcendentals/src/chimera.rs` contains `TRITRAY`, a catalogue
of composite carriers, including `shadow_bridge=77`,
`boundary_saturation=221`, `ramanujan_triple=385` and
`post_boundary_band=4199`. Its catalogue is not a restriction on all valid
dependent target moduli. The existing arbitrary-target projection contract
is in `lifted_transduction.rs`; it does not by itself supply encrypted lift
evidence or authenticate a source state.

`cram_ct.rs` declares the `2 -> 11` Shadow edge. Its existing Shadow witness
compares a saved target residue with the current target residue. That does
not establish the complete live source/phase/transition relation, and its
clear CRT helpers must not be called as encrypted evaluators. No production
lock verifier or ciphertext protocol is changed by this experiment.

## Bounded encrypted construction

The new research capability borrows one immutable encrypted carry-composition
state. It preserves all eight S8 root outputs, and every attached tray borrows
that same root. It cannot import an independently tagged ciphertext or rebind
a tray to a new root/value state. Two parallel trays share root and phase
outputs; no second root or boot-key family is generated.
Parallel here describes the dependency layout; the reference view loop is
sequential and makes no throughput or hardware-scheduling claim.

For the additive quantity S represented by the parent experiment, define

```text
b = S mod 2
j11 = ((S mod 11) - b) * 6 mod 11
2*6 = 1 mod 11
S = b + 2*j11 mod 22.
```

Thus j11 is `floor(S/2) mod 11`, including negative S. It is a binary/Shadow
phase index, **not** the BFV refresh carry `nearest(S/Q_work)`. For addition:

```text
c2 = floor((b_left + b_right)/2)
b_out = (b_left + b_right) mod 2
j11_out = (j11_left + j11_right + c2) mod 11.
```

The parity crossing cannot be omitted: 1+1 increments the phase index.
The clear/native transition tests cover the parent's actual centered
remainder/winding composition law, not just equality of two snapshots.
This is a specified additive **reference relation**, not acceptance of the
complete heterogeneous operator fabric or the still-unaccepted S00 contract.

The evaluator derives each target from the same encrypted selectors:

```text
S mod m = (g mod m + (K mod m)*(Q_work mod m)) mod m.
```

It does not decrypt, choose a hidden row, reconstruct the wide S, or derive
the whole lift from two small residue snapshots. X and X+22 agree on the
two snapshots and the phase index but can disagree on an arbitrary target.
The parent source state and its transition relation are therefore retained.
The private borrowing capability is a local consistency mechanism, not a
cryptographic provenance/authentication protocol or production key factory.

The first attached tray uses the existing named Tritray carriers 77 and 221.
The second uses `{1,6,10,8,27,121,385,4199,6,65537}`. Modulus1, shared
factors, repeated targets, prime powers and composites all work. Their view
period is the LCM, not the raw product: `{6,10,6,1}` has period 30 and
`{11,121,121,1}` has period 121. A view period alone is not proof of the
producer's admitted hidden range.

Every output here represents its canonical target residue as an integer in
the existing BFV plaintext t=65537. Therefore this particular interface
refuses m>65537. This is an encoding limit, not a new rule that sister moduli
must belong to S8. Supporting larger encodings needs its own transition and
error certificate; no free plaintext-modulus conversion is assumed.

## Noise and admission

The factory plans all target bounds and the LCM before emitting any sister
ciphertext. Invalid/oversized moduli, foreign roots and noise overflow return
typed refusals. Native assertions verify that a mixed tray containing a
valid first target and an overflowing later target emits no partial views.

Both two-term carry signs admit both trays. After the balanced four-term
composition, target 6 has a 133-bit error bound, while target 4199 requires
142 or 143 bits. The half-scale remains 137 bits, so the mixed `{6,4199}` tray
is refused before either target is emitted. No admission check is weakened.

Attaching these read-only dependent views requires no extra ciphertext
multiplication, but their scalar combinations still amplify error and consume
storage/work. They do not reset noise, create new independent information
from overlapping factors, or add multiplication depth. The full secret-sum
circuit and production input/key/phase provenance remain unresolved.

The 2026-10-21 exact-multiply isolation identifies a concrete error that these
views cannot repair: for one native ciphertext, the centered component lift is
`P+Q*K`, and the square's extra phase term is `2*t*K*P` modulo Q. Its measured
noise-times-winding contribution is 95 bits, while the input error is 56 bits;
an identical-phase `(P,0)` control squares with 57-bit error. A tray can expose
another residue view of the same encrypted state, but it does not alter this
component lift or reset that error. The derivation and rounding-bound check
are recorded in [the digit-radius contract](../2026-10-03/DIGIT_RADIUS_CONTRACT.md).
Its follow-up oracle cancellation preserves the actual relinearized c1 and
recovers one further correct square at 96-bit error. Correcting only the
encoded-message winding term still fails at 140 bits. The required full
correction is in raw boot-phase encoding, while these trays output canonical
Delta-scaled residues in plaintext 65537; that conversion and a source-bound
encrypted correction producer remain open.

The next encoding-isolation test strengthens that requirement: even an
oracle-supplied carry encrypted with a fresh full-width mask and eta=3 CBD
error fails to recover the next native square through the raw-phase adapter.
Its 2-bit carry error becomes a 90-bit correction error before relinearization;
the following square fails at 135 bits. A compensated Delta-scale adapter
works for a zero-error clear carry control (next square correct at 109 bits),
but its encrypted counterpart already corrupts the corrected product at
128 bits. The independent probe verifies the adapters' error identities on
56,700 integer cases, including the encrypted carry's own winding term. A
sister-tray producer must therefore certify the final correction precision,
not merely the correctness of the carry residues. See the encoding-isolation
section of the linked contract for the full measurement table and limits.

## Evidence and reproduction

The fast Rust tests check 50,004 exact additive phase transitions, arbitrary
target projections, root preservation, snapshot/foreign-root rejection,
invalid encodings and LCM overflow. The independent Python probe also checks
24,579 native cases covering all 8193 allowed global carry values with three
residual positions. These are clear identities, not encrypted full-sum runs.

The existing opt-in native encrypted composition test now attaches both trays
after the two-term prefix for each sign. For each sign it checks all 8192
coefficients of 8 root outputs, 1 phase output and 12 sister outputs: 172,032
encrypted coefficient/error checks, or 344,064 for both signs. These are in
addition to the previous 49,488 checks of the parent composition/refresh/square
probe. Root preservation and all-or-nothing noise refusal are also asserted.

```sh
python3 scripts/safe_basis_sister_tray_probe.py
cargo test --locked --offline --config 'profile.test.package.nine65.opt-level=2' -j1 -p nine65 --lib sister_tray_ -- --nocapture
cargo test --locked --offline --config 'profile.test.package.nine65.opt-level=2' -j1 -p nine65 --lib precharged_composition_ -- --include-ignored --nocapture
cargo test --locked --offline -j1 -p exact_transcendentals --lib chimera::tests -- --nocapture
```

New source-bound evidence is recorded in `safe-basis-sister-trays.json` and
`safe-basis-sister-trays-tests.txt` under `artifacts/execution/2026-10-19-carry`.
Earlier composition/precharge evidence remains historical for its own source
hashes. No lint tool, CI/profile change, new ciphertext prime, or production
refresh admission is part of this change.

The [atomic-update follow-up](SAFE_BASIS_TRAY_TRANSITIONS.md) now preflights
the proposed encrypted state and all retained trays together, verifies the
2/11 transition edges, and tests refusal followed by a smaller-view retry
without resetting the source error bound.
