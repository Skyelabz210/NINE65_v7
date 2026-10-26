# Technical packet execution — 2026-10-26

User-authorized execution of the attached correction program. Start from current
main bbfa754; preserve the audited 4bc1f0f snapshot by Git identity and SHA-256.
The existing release tracker remains issue #92. This local checklist records this
execution, and does not close or replace the release issues.

## Ordered work
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

## Blocking findings
- Follow-up attachments now supply recumbent source and a bootstrap blueprint.
  The Rust models fail range/sign/division admission checks; the blueprint's core
  divider remains todo!(). Rejected patch and specifically named witness logs
  remain unavailable. See docs/execution/2026-10-26/SUPPLIED_MATERIALS_REVIEW.md.
- For odd prime p, gcd(p-1,p+1)=2; the proposed pairs are not a coprime anchor
  family. For p=2 the shadow modulus is 1, also invalid. Composite adjacency
  anchors also cannot be substituted into the existing prime NTT contexts.
- |K|<A does not uniquely certify a signed K from K mod A. K=-1 and K=A-1
  collide. A signed interval of width at most A, or a bound such as 2B<A,
  must be specified and propagated rather than inferred from residues.
- The existing BoundedResidueDivider implementation reconstructs X; the packet
  and follow-up blueprint provide no executable replacement for general rounded
  division. Exact modular division examples do not fill that contract.
- Public encrypted carry (#95) remains open independently of scalar division.
- The proposed parity implication with coprime moduli reduces to 1 | (X-Y),
  so it is not itself an error-detection proof.

These are prerequisites, not permission checkpoints. Do not promote hypotheses
into working FHE, erase failing gates, or enable refresh to satisfy the checklist.
