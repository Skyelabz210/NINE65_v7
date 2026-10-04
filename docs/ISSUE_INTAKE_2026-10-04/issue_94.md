# Issue #94: [P1] Harden fhe-service HTTP framing: reject ambiguous lengths and preserve/disable keep-alive pipelining

- state: open
- labels: (none)
- created: 2026-08-31T07:18:37Z  updated: 2026-09-04T09:57:47Z
- url: https://github.com/Skyelabz210/NINE65_v7/issues/94

---

## Finding

`crates/fhe-service/src/http.rs` is a handwritten HTTP/1 parser with body/header caps, but several framing states are currently accepted or mishandled:

1. `Content-Length` is parsed with `.parse::<usize>().ok().unwrap_or(0)`, so an invalid/overflowing value is treated as **zero** instead of a malformed request.
2. Headers are inserted into a `HashMap`; duplicate `Content-Length` fields overwrite rather than being rejected.
3. `Transfer-Encoding` is not implemented or explicitly rejected. A chunked request can therefore be interpreted as a zero-length body.
4. `Content-Length` + `Transfer-Encoding` ambiguity is not rejected.
5. If EOF occurs before the declared body length, the parser breaks and returns the shorter body instead of a framing error.
6. The per-call read buffer is local. If a keep-alive client pipelines request B in the same socket read as request A, bytes beyond A are already consumed from the socket and then discarded when A returns; the next `read_http_request` cannot recover them.
7. `MAX_RESPONSE_BYTES` is declared but `write_http_response_with_request` does not itself enforce the cap.
8. The request line does not validate the HTTP-version token or reject extra tokens.

These are protocol-correctness and request-smuggling/desynchronization hardening issues at the service boundary.

## Required work

1. Introduce a connection-level buffered reader/framer that retains unread bytes between requests, **or** disable keep-alive/pipelining and close after every request until a correct stateful framer exists.
2. Parse `Content-Length` strictly. Missing is distinct from malformed. Overflow/negative/non-decimal -> 400.
3. Reject duplicate `Content-Length`; safest policy is reject all duplicates, even equal values.
4. Reject any unsupported `Transfer-Encoding`; always reject CL+TE combinations.
5. Require exactly the declared body length. Premature EOF -> typed parse error, never a partial valid request.
6. Validate request-line method/path/version token count and accepted HTTP versions.
7. Enforce response-size cap before writing.
8. Keep the existing header/body caps and 5-second read timeout.
9. Add a bounded maximum header count/name/value length if the byte cap alone is insufficient for parser/resource behavior.
10. No floating-point arithmetic in service metrics/bench reporting.

## Adversarial tests

Raw byte/socket tests for:
- invalid, overflowing and duplicate Content-Length,
- CL+TE and chunked TE,
- declared body longer/shorter than bytes supplied,
- two pipelined requests arriving in one write/read,
- headers exactly at/over limits,
- oversized response attempt,
- malformed/extra request-line tokens,
- timeout/slow-drip behavior.

Every malformed framing case must fail closed before authentication/handler dispatch.

## Mandatory before/after performance evidence

Benchmark parser throughput/allocations for representative authenticated requests at 0-byte, small JSON, and maximum normal ciphertext payload sizes; benchmark keep-alive sequential request throughput if retained. Record integer ns/us timings, bytes allocated if available, and exact response/status equality. Security-correct framing takes priority over raw parser speed.

## Completion condition

The service has one unambiguous message framing rule, cannot silently reinterpret malformed length/transfer headers, and never loses already-read bytes across a supported keep-alive connection.