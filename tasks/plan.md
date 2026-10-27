# Technical packet execution — 2026-10-26

User-authorized execution of the attached correction program. Start from current
main bbfa754; preserve the audited 4bc1f0f snapshot by Git identity and SHA-256.
The existing release tracker remains issue #92. This local checklist records this
execution, and does not close or replace the release issues.

## Initial ordered work — 2026-10-26
1. Freeze the supplied packet, hash baseline files, locate named evidence, and
   reconcile every phase against current code. Verify hashes and exact arithmetic
   counterexamples. Missing artifacts remain missing, never synthesized.
2. Run the release workspace baseline and inventory actual executed targets and
   ignored tests. Install the repository-pinned Rust toolchain if needed.
3. Complete independent checked capacity metadata and CRAM witness admission.
   Verify at 128/256-bit boundaries, with focused Rust tests and release build.
4. Reset the public claim introduction and record blocked release gates. Add a
   source gate that reports existing violations, with an injection regression.
5. Port/integrate the recumbent rescale only after its source, signed-lift bound,
   general division algorithm and compatible anchor construction are available.
   Keep refresh disabled until all specified acceptance tests pass.

## Supplied-artifact findings — 2026-10-26

This block records the supplied artifacts before the commissioned implementation
below. The new bounded coefficient divider is executable; its remaining wide
BFV integration and encrypted-carry obligations are tracked in the continuation.
- Follow-up attachments now supply recumbent source and a bootstrap blueprint.
  The Rust models fail range/sign/division admission checks; the blueprint's core
  divider remains todo!(). Rejected patch and specifically named witness logs
  remain unavailable. See docs/execution/2026-10-26/SUPPLIED_MATERIALS_REVIEW.md.
- For odd prime p, gcd(p-1,p+1)=2; the proposed pairs are not a coprime anchor
  family. For p=2 the shadow modulus is 1, also invalid. Composite adjacency
  anchors also cannot be substituted into the existing prime NTT contexts.
- |K|<A does not uniquely certify a signed K from K mod A. K=-1 and K=A-1
  collide. A signed interval [L,U] with U-L<A, or a bound such as 2B<A,
  must be specified and propagated rather than inferred from residues.
- The existing BoundedResidueDivider implementation reconstructs X; the packet
  and follow-up blueprint provide no executable replacement for general rounded
  division. Exact modular division examples do not fill that contract.
- Public encrypted carry (#95) remains open independently of scalar division.
- The proposed parity implication with coprime moduli reduces to 1 | (X-Y),
  so it is not itself an error-detection proof.

These are prerequisites, not permission checkpoints. Do not promote hypotheses
into working FHE, erase failing gates, or enable refresh to satisfy the checklist.

## Implementation continuation — 2026-10-27

The user clarified that the NS implementation is a reference pattern and that
the FHE implementation is commissioned work. Missing FHE source is therefore
an implementation task, not a request for another upload. The blueprint's
mathematical construction obligations still require explicit algorithms and
verification; declarations and acceptance criteria alone do not establish them.

1. Import and repair the supplied signed CRT substrate. Preserve failing
   reproductions before the fix, full-width capacity checks, and original tests.
   Its scalar magnitude reconstruction remains a reference/boundary operation.
2. Build immutable FHE coefficient state with authentic main/anchor residues,
   analytically propagated signed intervals, checked division-event depth,
   and a debug-only independent provenance oracle.
3. Implement observed-lane exact/floor/nearest division with authentic quotient
   anchors. Develop general bounded quotient projection separately, documenting
   its global CRT-rank accumulator and testing its actual output distribution
   and inverse against the clarified emission policy.
4. Preserve the zero-noise component-rounding counterexample on both the small
   two-prime instance and the shipped secure-128 tuple. Passing this negative
   regression records the missing carry; it does not implement that carry.
5. Integrate BFV rescale/bootstrap only after the coefficient-lift, wide-bound,
   encrypted-carry and parameter contracts hold. Run the depth and chain gates
   against the implemented path. A narrower arithmetic slice is not a substitute.
6. Construct a compatible anchor family before replacing secure parameters.
   The literal adjacency pair has a common factor of two; neither changing its
   name nor weakening the coprimality gate resolves that construction obligation.

Public refresh admission requires the complete acceptance evidence on one
commit. Failed or unexecuted gates remain visible throughout implementation.

The user's subsequent policy clarification supersedes the earlier blanket
reconstruction ban: reconstruction is permitted; forbidden synthetic emissions
include Garner and mixed-radix conversions in residue compute. Independence and
reversibility must be checked on the actual operation and declared state space.
The source scanner records structural evidence separately from those properties.
The earlier reconstruction-only inventory remains historical evidence, not an
automatic rejection of every reconstruction algorithm under the clarified rule.

IID specifically refers to the declared driving variables. In the supplied
Holte carry model, use Eulerian-weighted detailed balance for statistical
reversibility; a reversible carry chain can have dependent carry states.
Whole-output joint uniformity remains an optional separately labelled diagnostic.
