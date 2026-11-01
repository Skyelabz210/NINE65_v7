# Checking native producer bounds against actual ciphertext phases

The native refresh regression now measures ideal-grid error at its input,
after original-key return and after the dependent square. Every coefficient
is compared with the corresponding immutable producer-issued bound.

For a canonical phase phi and known plaintext m, the observer computes

`min(|t*phi-Q*m|, t*Q-|t*phi-Q*m|)`.

This is the centered error modulo tQ. It covers canonical negative plaintexts
without mistaking a Q winding for noise. Although native Q fits u128, tQ
does not; all scaled products and differences therefore use U512.

The test-only client reconstructs phi using direct weighted CRT. Each inverse
is computed and verified modulo its prime; coefficient products are reduced
before multiplying the cofactor. The product Q and aggregate CRT-sum capacity
are checked before u128 use. The calculation avoids the decryption/scale-round
implementation. It shares the existing reference NTT engine for lane-wise
phase convolution; it is not an independent proof of that engine.

## Negative control and API scope

The negative regression adds a public phase perturbation to an otherwise
genuine encryption while retaining its original bound. Decryption still
returns the correct plaintext, but the observer detects an error larger than
that bound. This distinguishes checking a producer envelope from checking
only plaintext correctness.

The observer and its re-export exist only under cfg(test). Public evaluators
receive no secret, measured error or observer callback. Measurements never
change admission, history or a certificate. Production ciphertext fields
remain private. Unsupported wide Q values fail the oracle's checked capacity
precondition instead of overflowing.

The small public-API three-cycle regression also executes all three observer
checks per cycle. The focused public-refresh test group passes 31 tests with
zero failures. Workspace/all-targets Clippy, formatting, status/security checks
and the panic ratchet pass. The exact negative control is additionally listed
in the research source-preparation suite.

## Native command

```sh
cargo test --locked --config profile.test.package.nine65.opt-level=2 -j2 \
  -p nine65 --lib \
  ops::public_refresh_native::native_public_refresh_current_single_cycle_with_dependent_square \
  -- --exact --ignored --nocapture --test-threads=1
```

At work degree8192 this checks 24,576 coefficient error envelopes in addition
to the existing 16,384 post-refresh/post-square plaintext comparisons. Passing
instances strengthen implementation conformance evidence; they do not prove
the noise model for all ciphertext histories or establish joint-key security.

## Accepted native witness

At source commit `2352435d625d7f36ffec41d162a8d769b84d6ab7`, the
exact native test passes one refresh and following square in 580.96 seconds,
including setup and excluding compilation. All 24,576 coefficient error
checks and 16,384 plaintext comparisons pass. Maximum observed scaled errors:

| Stage | Maximum measured V |
| --- | --- |
| Already-squared input | 762490188487606471 |
| Returned ciphertext | 1043073383 |
| Following square | 257071113810960355 |

The returned producer cap remains 122782933364666; observations do not
replace that bound. The native fixture therefore demonstrates actual error
renewal under the original key in addition to plaintext correctness. The
reference oracle recomputes the input and post-square caps independently
from the documented arithmetic model. Binary/source hashes, all integer caps
and accepted transcripts are in [the manifest](native-phase-error-evidence/manifest.json).
The deterministic fixture seed is unchanged; this is added instrumentation,
not a new independent random sample or a statistical failure estimate.
