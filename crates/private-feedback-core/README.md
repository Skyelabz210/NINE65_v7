# private-feedback-core

Reference application core for privacy-preserving adaptive feedback capture.

The crate deliberately excludes raw response text from its aggregate object. A separate classifier or local model may convert a user response into bounded fields, after which this crate:

1. validates the structured signal;
2. selects a highest-value follow-up class under a strict turn budget;
3. decomposes the fixed slots into the CRAM safe basis;
4. aggregates lane-by-lane without reconstruction.

Current safe basis:

```text
{2, 3, 5, 7, 11, 13, 17, 19}
```

The crate contains no Garner reconstruction, mixed-radix conversion, floating-point arithmetic, or method that projects a residue aggregate back to an integer. Authorized plaintext output belongs in a separate boundary component governed by `docs/SECURITY_MODE_MATRIX.md`.

This is an application-domain reference and correctness harness. The subsequent NINE65 adapter will encrypt each fixed slot or lane frame according to the selected public, edge, or protected mode.
