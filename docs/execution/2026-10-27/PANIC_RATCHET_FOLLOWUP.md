# CI follow-up: preserve the panic ratchet

CI at `a0bb7dc` passed Exactness Focused Gates, CRAM residue-native gates,
CRAM-public gates and Application Platform Gates. Static analysis rejected one
new `unwrap` and four additional `expect` calls. This follow-up fixes that
regression without changing `scripts/panic_gate_baseline.txt`.

Rank precision uses the highest nonzero product limb without an unchecked
optional read. Setup compares exact limb products for the winding bound and
anchor prefix, avoiding fixed-width conversion failures altogether. A compile-time
target-width requirement proves that polynomial degrees fit the limb factor.
Scalar K extraction validates the anchor product and inverse together through
the existing compatibility API's refusal point; neither missing value can enter
arithmetic.

Validation: panic ratchet passes, 9 metadata tests, 16 recumbent tests and 8 rank
tests pass in debug, targeted clippy passes with warnings denied, and the
architecture/emission scans pass. Existing tests include full-u128 inverse cases
and independent quotient oracles. No full release-library rerun was performed
for this follow-up. Compressed logs and source hashes accompany this report.

Broader CI remains unsuccessful. Real refresh stops at the missing encrypted
carry gate. Fuzz Smoke reports `65292 * 65530 = 1582`, expected `1715`, in
plaintext multiplication; the timing gate reports operand-class dependence.
These are not resolved by the ratchet fix. The prior implementation report and
validation snapshot remain historical evidence for their stated code commits.
