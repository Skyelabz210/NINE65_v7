# Runtime follow-up after permissions changed

This is the current status as of 2026-10-18; the earlier gap table below is a
historical checkpoint and its C03/C04 rows are superseded by the appended
implementation result.

The earlier socket-bind restriction is resolved. With unrestricted local
execution, `cargo run --locked --offline -j1 -p fhe-service` builds and starts
the listener at `127.0.0.1:8080`. Both `GET /healthz` and `GET /v1/version`
return HTTP 200. The process remains running in the execution session.

This establishes HTTP liveness only. Main-Q ciphertext transport, immutable
noise provenance, and public-refresh admission still have the gaps described
in [the earlier gap analysis](GAP_ANALYSIS.md). No cryptographic refusal was
removed and no application code was changed in this follow-up.

Direct `git fetch origin` now succeeds and confirms that both the local base
and `origin/main` are `0ec19eb2e142f8ae86d86c747c267e65fb5f1f8e`.
The three previously unavailable archived binary paths were restored and
verified against their upstream blob hashes. The optional Rust Guide
submodule could not be cloned because its HTTPS repository requires
credentials unavailable to the local Git process. It is not a dependency of
the running HTTP binary.

The previous report and its evidence hashes remain unchanged as a historical
record of the restricted environment.

## Current service operation result

The service's former ciphertext outage is bridged for the certified scalar
main-Q subset. Handlers no longer call the refusing DualRNS serializer or use a
shared session noise budget for admission. A strict main-Q v1 transport binds
imported ciphertexts to bytes previously issued by that same session, and the
immutable wrapper preserves each operation's bound. The full offline service
suite reports 54 passed and 27 ignored; the ignores are legacy DualRNS and
heuristic-budget tests, not evidence of support on the new route.

The rebuilt service is running on `127.0.0.1:8081`; the pre-existing `:8080`
process was not interrupted. Health check passed, as did a real authenticated
HTTP flow: encrypt 6 and 7, evaluate ciphertext multiplication, decrypt 42.
The verification used throwaway local credentials and explicitly enabled the
operator-only decrypt endpoint for that local process. This does not authorize
production deployment as-is.

The evaluator and decryption client are separate Rust types, but the HTTP
session owns both. This is therefore a server-keyholder service, not an
external client-secret/public-evaluator deployment. Public refresh, full CRAM
integration, external key separation, and independent cryptographic review of
the scalar multiplication bound remain open release gates.
