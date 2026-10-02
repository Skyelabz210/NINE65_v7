//! HTTP request/response parsing
//!
//! Extracted from the original monolithic main.rs with body size limits (HVT-4).
//!
//! # Framing policy (issue #94)
//!
//! This is a handwritten HTTP/1 parser, not a general-purpose server. Its
//! framing rule is deliberately narrow and unambiguous rather than lenient:
//!
//! - `Content-Length` must be present-and-valid or absent; a malformed value
//!   (non-decimal, overflowing, negative-looking) is a parse error, never
//!   silently treated as zero.
//! - A duplicate `Content-Length` header — even a byte-identical repeat — is
//!   rejected. So is any `Transfer-Encoding` header (chunked transfer is not
//!   implemented) and any combination of the two.
//! - The declared body length must arrive in full; a connection that closes
//!   before that many bytes have been read is a parse error, never a
//!   silently-truncated body.
//! - Keep-alive / pipelining is not implemented: [`should_keep_alive`]
//!   always reports `false` and every response is sent with
//!   `Connection: close`, honestly reflecting that this parser has no
//!   connection-level buffer to carry unread bytes from one request into the
//!   next. `read_http_request`'s per-call buffer is dropped when it
//!   returns, so bytes belonging to a second, pipelined request that arrived
//!   in the same `read()` as the first would otherwise be silently lost
//!   rather than answered — closing after every response is the fail-closed
//!   choice until a connection-level framer exists to carry them forward.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use thiserror::Error;

/// Maximum request body size (10 MB) — prevents trivial DoS.
pub const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

/// Maximum response body size (50 MB) — prevents response amplification attacks.
pub const MAX_RESPONSE_BYTES: usize = 50 * 1024 * 1024;

/// Maximum header section size (64 KB).
const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Maximum number of header lines accepted in one request.
const MAX_HEADER_COUNT: usize = 100;

/// Maximum length of a single header name.
const MAX_HEADER_NAME_LEN: usize = 256;

/// Maximum length of a single header value.
const MAX_HEADER_VALUE_LEN: usize = 8 * 1024;

/// Fallback body substituted when a response would exceed
/// [`MAX_RESPONSE_BYTES`] — see [`write_http_response_with_request`].
const RESPONSE_TOO_LARGE_BODY: &[u8] =
    br#"{"error":{"code":"RESPONSE_TOO_LARGE","message":"response exceeds size limit"}}"#;

#[derive(Debug, Error)]
pub enum RequestParseError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("connection closed by peer")]
    ConnectionClosed,
    #[error("request headers are not valid utf-8")]
    InvalidUtf8,
    #[error("invalid request line")]
    InvalidRequestLine,
    #[error("request body too large ({0} bytes, max {1})")]
    BodyTooLarge(usize, usize),
    #[error("invalid or malformed Content-Length header")]
    InvalidContentLength,
    #[error("duplicate header: {0}")]
    DuplicateHeader(String),
    #[error("Transfer-Encoding is not supported")]
    UnsupportedTransferEncoding,
    #[error("malformed header line")]
    MalformedHeader,
    #[error("too many headers (max {0})")]
    TooManyHeaders(usize),
    #[error("header name or value too large")]
    HeaderTooLarge,
    #[error("connection closed before the declared body length was received")]
    PrematureEof,
}

#[derive(Debug)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

pub fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest, RequestParseError> {
    let mut data = Vec::with_capacity(4096);
    let mut temp = [0_u8; 4096];

    loop {
        let bytes_read = stream.read(&mut temp)?;
        if bytes_read == 0 {
            if data.is_empty() {
                return Err(RequestParseError::ConnectionClosed);
            }
            break;
        }

        data.extend_from_slice(&temp[..bytes_read]);

        if let Some(header_end) = find_header_end(&data) {
            let header_bytes = &data[..header_end];
            let header_text =
                std::str::from_utf8(header_bytes).map_err(|_| RequestParseError::InvalidUtf8)?;
            let (method, path, headers) = parse_request_head(header_text)?;

            // Transfer-Encoding is not implemented at all: reject it
            // outright rather than silently treat the body as zero-length
            // or absorb a chunked payload as if it were the raw body. This
            // also covers the Content-Length + Transfer-Encoding ambiguity
            // (request smuggling) case, since any Transfer-Encoding present
            // is rejected regardless of whether Content-Length is too.
            if headers.contains_key("transfer-encoding") {
                return Err(RequestParseError::UnsupportedTransferEncoding);
            }

            // Strict Content-Length parsing: missing is distinct from
            // malformed. `parse_request_head` already rejects duplicate
            // headers, so at most one Content-Length value reaches here.
            let content_length = match headers.get("content-length") {
                None => 0,
                Some(value) => parse_strict_content_length(value)?,
            };

            // HVT-4: reject oversized bodies before reading
            if content_length > MAX_BODY_BYTES {
                return Err(RequestParseError::BodyTooLarge(
                    content_length,
                    MAX_BODY_BYTES,
                ));
            }

            let body_start = header_end + 4;
            while data.len() < body_start + content_length {
                let bytes_read = stream.read(&mut temp)?;
                if bytes_read == 0 {
                    // The peer closed before the declared body length
                    // arrived. Silently truncating to whatever was read
                    // would hand the handler a body shorter than its
                    // Content-Length claimed — a framing error, not a
                    // smaller-but-valid request.
                    return Err(RequestParseError::PrematureEof);
                }
                data.extend_from_slice(&temp[..bytes_read]);

                // Guard against slow-drip attacks that exceed declared size
                if data.len() > body_start + MAX_BODY_BYTES {
                    return Err(RequestParseError::BodyTooLarge(
                        data.len() - body_start,
                        MAX_BODY_BYTES,
                    ));
                }
            }

            // The loop condition above guarantees `data.len() >= body_start
            // + content_length` on every path that reaches here (it either
            // held immediately or the loop filled it in; every other exit
            // is an early `return Err(..)`), so this is an exact slice, not
            // a clamped/best-effort one. Any bytes past this point (e.g. a
            // pipelined second request) are intentionally left unread here
            // — see the module doc comment on why this parser does not
            // attempt to carry them forward.
            let body_end = body_start + content_length;
            let body = data[body_start..body_end].to_vec();

            return Ok(HttpRequest {
                method,
                path,
                headers,
                body,
            });
        }

        if data.len() > MAX_HEADER_BYTES {
            return Err(RequestParseError::InvalidRequestLine);
        }
    }

    if data.is_empty() {
        Err(RequestParseError::ConnectionClosed)
    } else {
        Err(RequestParseError::InvalidRequestLine)
    }
}

/// Parse a `Content-Length` value with no leniency: optional surrounding
/// whitespace has already been trimmed by the header-line parser, so what
/// remains must be one or more ASCII digits with no sign, no separators, and
/// no leading `+`, and must fit in `usize`. `.parse::<usize>()` alone is not
/// strict enough for this: some integer `FromStr` implementations accept a
/// leading `+`, which HTTP framing must not.
fn parse_strict_content_length(value: &str) -> Result<usize, RequestParseError> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(RequestParseError::InvalidContentLength);
    }
    value
        .parse::<usize>()
        .map_err(|_| RequestParseError::InvalidContentLength)
}

fn parse_request_head(
    head: &str,
) -> Result<(String, String, HashMap<String, String>), RequestParseError> {
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(RequestParseError::InvalidRequestLine)?;

    // Exactly three whitespace-separated tokens: method, target, version.
    // Splitting further than that (e.g. a stray fourth token) is rejected
    // rather than silently ignored, and the version token is checked
    // against the two versions this parser actually speaks.
    let tokens: Vec<&str> = request_line.split_whitespace().collect();
    let [method, raw_path, version] = tokens[..] else {
        return Err(RequestParseError::InvalidRequestLine);
    };
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(RequestParseError::InvalidRequestLine);
    }
    let method = method.to_owned();
    let path = raw_path.split('?').next().unwrap_or(raw_path).to_owned();

    let mut headers = HashMap::new();
    let mut header_count = 0usize;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        header_count += 1;
        if header_count > MAX_HEADER_COUNT {
            return Err(RequestParseError::TooManyHeaders(MAX_HEADER_COUNT));
        }
        // A header line with no `:` at all is not a header this parser can
        // interpret; previously it was silently dropped, which lets a
        // caller believe an ignored line took effect. Fail closed instead.
        let Some((name, value)) = line.split_once(':') else {
            return Err(RequestParseError::MalformedHeader);
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim().to_owned();
        if name.len() > MAX_HEADER_NAME_LEN || value.len() > MAX_HEADER_VALUE_LEN {
            return Err(RequestParseError::HeaderTooLarge);
        }
        if name.is_empty() {
            return Err(RequestParseError::MalformedHeader);
        }
        // Reject duplicates outright rather than keep-first/keep-last —
        // the safest policy when a repeated header (Content-Length above
        // all) could otherwise be used to disagree with itself across
        // whatever re-parses the same bytes downstream.
        if headers.contains_key(&name) {
            return Err(RequestParseError::DuplicateHeader(name));
        }
        headers.insert(name, value);
    }

    Ok((method, path, headers))
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|window| window == b"\r\n\r\n")
}

pub fn write_http_response_with_request(
    stream: &mut TcpStream,
    response: &HttpResponse,
    request: &HttpRequest,
) -> Result<(), std::io::Error> {
    let connection_header = connection_header_for_request(request);

    // #94 item 7: `MAX_RESPONSE_BYTES` was declared but nothing actually
    // read it before writing, so a response amplified past the cap (e.g. by
    // a large batch request) would still be written to the wire in full.
    // Enforce it here, at the one place every response passes through,
    // rather than trust every caller that builds an `HttpResponse` to have
    // checked it already.
    let (status, body): (u16, &[u8]) = if response.body.len() > MAX_RESPONSE_BYTES {
        eprintln!(
            "response body {} bytes exceeds MAX_RESPONSE_BYTES {}; substituting an error response",
            response.body.len(),
            MAX_RESPONSE_BYTES
        );
        (500, RESPONSE_TOO_LARGE_BODY)
    } else {
        (response.status, response.body.as_slice())
    };
    let status_text = status_text(status);

    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n{}\r\n\r\n",
        status,
        status_text,
        response.content_type,
        body.len(),
        connection_header
    );

    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

pub fn write_http_response(
    stream: &mut TcpStream,
    response: &HttpResponse,
) -> Result<(), std::io::Error> {
    // For backward compatibility, use default close behavior when request is not available
    let dummy_request = HttpRequest {
        method: String::new(),
        path: String::new(),
        headers: HashMap::new(),
        body: Vec::new(),
    };
    write_http_response_with_request(stream, response, &dummy_request)
}

/// Determine the appropriate Connection header value based on the request
pub fn connection_header_for_request(request: &HttpRequest) -> String {
    if should_keep_alive(request) {
        "Connection: keep-alive".to_string()
    } else {
        "Connection: close".to_string()
    }
}

/// Whether this request asks for persistent connection reuse.
///
/// Always `false` (issue #94): `read_http_request`'s buffer is per-call, so
/// bytes belonging to a pipelined second request that arrived in the same
/// underlying `read()` as the first would be dropped, not answered, if this
/// connection were kept open past the first response. Honestly reporting
/// `Connection: close` and closing after every response — regardless of
/// what the client's own `Connection` header asked for — is the fail-closed
/// choice until a connection-level framer exists that can carry those bytes
/// forward into the next `read_http_request` call.
pub fn should_keep_alive(_request: &HttpRequest) -> bool {
    false
}

fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Payload Too Large",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

pub fn json_response(status: u16, body: serde_json::Value) -> HttpResponse {
    let payload = match serde_json::to_vec(&body) {
        Ok(bytes) => bytes,
        Err(_) => b"{\"error\":\"serialization_failed\"}".to_vec(),
    };

    HttpResponse {
        status,
        content_type: "application/json",
        body: payload,
    }
}

pub fn error_response(status: u16, code: &str, message: &str) -> HttpResponse {
    json_response(
        status,
        serde_json::json!({
            "error": {
                "code": code,
                "message": message,
            }
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn parse_request_head_strips_query_params() {
        let head = "GET /v1/fhe/public-key?tenant=abc HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let (method, path, headers) = parse_request_head(head).unwrap();
        assert_eq!(method, "GET");
        assert_eq!(path, "/v1/fhe/public-key");
        assert_eq!(headers.get("host").map(String::as_str), Some("localhost"));
    }

    #[test]
    fn should_keep_alive_always_false() {
        // Issue #94: pipelining/keep-alive is disabled until a
        // connection-level framer exists, regardless of what the client's
        // own Connection header asks for.
        let mut headers = HashMap::new();
        headers.insert("connection".to_owned(), "keep-alive".to_owned());
        let req = HttpRequest {
            method: "GET".to_owned(),
            path: "/healthz".to_owned(),
            headers,
            body: Vec::new(),
        };
        assert!(!should_keep_alive(&req));
        assert_eq!(connection_header_for_request(&req), "Connection: close");
    }

    #[test]
    fn should_not_keep_alive_when_close_requested() {
        let mut headers = HashMap::new();
        headers.insert("connection".to_owned(), "close".to_owned());
        let req = HttpRequest {
            method: "GET".to_owned(),
            path: "/healthz".to_owned(),
            headers,
            body: Vec::new(),
        };
        assert!(!should_keep_alive(&req));
        assert_eq!(connection_header_for_request(&req), "Connection: close");
    }

    // ------------------------------------------------------------------
    // parse_request_head: request-line and header hardening (issue #94)
    // ------------------------------------------------------------------

    #[test]
    fn rejects_request_line_with_extra_tokens() {
        let head = "GET /x HTTP/1.1 extra\r\nHost: h\r\n\r\n";
        assert!(matches!(
            parse_request_head(head),
            Err(RequestParseError::InvalidRequestLine)
        ));
    }

    #[test]
    fn rejects_request_line_with_missing_version() {
        let head = "GET /x\r\nHost: h\r\n\r\n";
        assert!(matches!(
            parse_request_head(head),
            Err(RequestParseError::InvalidRequestLine)
        ));
    }

    #[test]
    fn rejects_unknown_http_version_token() {
        let head = "GET /x HTTP/2.0\r\nHost: h\r\n\r\n";
        assert!(matches!(
            parse_request_head(head),
            Err(RequestParseError::InvalidRequestLine)
        ));
    }

    #[test]
    fn accepts_http_1_0_version_token() {
        let head = "GET /x HTTP/1.0\r\nHost: h\r\n\r\n";
        assert!(parse_request_head(head).is_ok());
    }

    #[test]
    fn rejects_duplicate_headers_even_when_identical() {
        let head = "GET /x HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n";
        assert!(matches!(
            parse_request_head(head),
            Err(RequestParseError::DuplicateHeader(name)) if name == "content-length"
        ));
    }

    #[test]
    fn rejects_header_line_with_no_colon() {
        let head = "GET /x HTTP/1.1\r\nNotAHeader\r\n\r\n";
        assert!(matches!(
            parse_request_head(head),
            Err(RequestParseError::MalformedHeader)
        ));
    }

    #[test]
    fn rejects_too_many_headers() {
        let mut head = String::from("GET /x HTTP/1.1\r\n");
        for i in 0..(MAX_HEADER_COUNT + 1) {
            head.push_str(&format!("X-Custom-{i}: v\r\n"));
        }
        head.push_str("\r\n");
        assert!(matches!(
            parse_request_head(&head),
            Err(RequestParseError::TooManyHeaders(_))
        ));
    }

    #[test]
    fn accepts_headers_exactly_at_the_count_limit() {
        let mut head = String::from("GET /x HTTP/1.1\r\n");
        for i in 0..MAX_HEADER_COUNT {
            head.push_str(&format!("X-Custom-{i}: v\r\n"));
        }
        head.push_str("\r\n");
        assert!(parse_request_head(&head).is_ok());
    }

    #[test]
    fn rejects_oversized_header_value() {
        let head = format!(
            "GET /x HTTP/1.1\r\nX-Big: {}\r\n\r\n",
            "a".repeat(MAX_HEADER_VALUE_LEN + 1)
        );
        assert!(matches!(
            parse_request_head(&head),
            Err(RequestParseError::HeaderTooLarge)
        ));
    }

    #[test]
    fn accepts_header_value_exactly_at_the_limit() {
        let head = format!(
            "GET /x HTTP/1.1\r\nX-Big: {}\r\n\r\n",
            "a".repeat(MAX_HEADER_VALUE_LEN)
        );
        assert!(parse_request_head(&head).is_ok());
    }

    // ------------------------------------------------------------------
    // Content-Length strictness (issue #94 item 1-4)
    // ------------------------------------------------------------------

    #[test]
    fn strict_content_length_accepts_plain_digits() {
        assert_eq!(parse_strict_content_length("123").unwrap(), 123);
        assert_eq!(parse_strict_content_length("0").unwrap(), 0);
    }

    #[test]
    fn strict_content_length_rejects_non_decimal() {
        for bad in ["abc", "-1", "+5", "1.5", "1e3", "0x10", " 5", "5 ", ""] {
            assert!(
                parse_strict_content_length(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn strict_content_length_rejects_overflow() {
        // One digit past u64::MAX / usize::MAX on a 64-bit target.
        let overflow = "99999999999999999999999999999999";
        assert!(parse_strict_content_length(overflow).is_err());
    }

    // ------------------------------------------------------------------
    // Full read_http_request adversarial framing tests (raw sockets)
    // ------------------------------------------------------------------

    /// Spawn a one-shot TCP listener, send `raw` from a client thread, and
    /// return what `read_http_request` produced on the accepted side.
    fn parse_raw_request(raw: &[u8]) -> Result<HttpRequest, RequestParseError> {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let raw = raw.to_vec();
        let client = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).expect("connect");
            stream.write_all(&raw).expect("write");
            // Half-close the write side so the server sees EOF once it has
            // consumed everything the test sent, instead of hanging until
            // its read timeout.
            //
            // Deliberately does NOT read a response back: `read_http_request`
            // (the function under test here) only ever reads — it never
            // writes a response itself, that is a separate function
            // (`write_http_response_with_request`) that this helper never
            // calls. An earlier version of this helper tried to read a
            // response anyway "in case a test wants it"; since nothing is
            // ever written back, that read call blocked forever, and since
            // the accept()ed `server_stream` below is not dropped until
            // after `client.join()` returns, the two sides deadlocked each
            // other on every call. Returning immediately after the shutdown
            // avoids that: the client thread has nothing left to wait on.
        });
        let (mut server_stream, _) = listener.accept().expect("accept");
        server_stream
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("timeout");
        let result = read_http_request(&mut server_stream);
        let _ = client.join();
        result
    }

    #[test]
    fn rejects_invalid_content_length_value() {
        let raw = b"POST /x HTTP/1.1\r\nContent-Length: not-a-number\r\n\r\n";
        let err = parse_raw_request(raw).expect_err("must reject malformed Content-Length");
        assert!(matches!(err, RequestParseError::InvalidContentLength));
    }

    #[test]
    fn rejects_overflowing_content_length_value() {
        let raw = b"POST /x HTTP/1.1\r\nContent-Length: 999999999999999999999999999999\r\n\r\n";
        let err = parse_raw_request(raw).expect_err("must reject overflowing Content-Length");
        assert!(matches!(err, RequestParseError::InvalidContentLength));
    }

    #[test]
    fn rejects_duplicate_content_length_headers() {
        let raw = b"POST /x HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 9\r\n\r\nhello";
        let err = parse_raw_request(raw).expect_err("must reject duplicate Content-Length");
        assert!(matches!(err, RequestParseError::DuplicateHeader(_)));
    }

    #[test]
    fn rejects_chunked_transfer_encoding() {
        let raw = b"POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let err = parse_raw_request(raw).expect_err("chunked TE must be rejected");
        assert!(matches!(
            err,
            RequestParseError::UnsupportedTransferEncoding
        ));
    }

    #[test]
    fn rejects_content_length_and_transfer_encoding_together() {
        let raw =
            b"POST /x HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello";
        let err = parse_raw_request(raw).expect_err("CL+TE combination must be rejected");
        assert!(matches!(
            err,
            RequestParseError::UnsupportedTransferEncoding
        ));
    }

    #[test]
    fn rejects_body_shorter_than_declared_content_length() {
        // Declares 100 bytes, sends 5, then the client closes its write side.
        let raw = b"POST /x HTTP/1.1\r\nContent-Length: 100\r\n\r\nhello";
        let err = parse_raw_request(raw).expect_err("premature EOF must be a parse error");
        assert!(matches!(err, RequestParseError::PrematureEof));
    }

    #[test]
    fn accepts_body_exactly_matching_declared_content_length() {
        let raw = b"POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        let request = parse_raw_request(raw).expect("exact-length body must be accepted");
        assert_eq!(request.body, b"hello");
    }

    #[test]
    fn takes_exactly_the_declared_length_when_more_bytes_follow() {
        // Content-Length is shorter than what actually arrives (e.g. a
        // second, pipelined request concatenated onto the same write). The
        // parser must take exactly the declared body and not fail, since
        // this connection is closed after this one response anyway (see
        // `should_keep_alive`) rather than misread the extra bytes as part
        // of this request.
        let raw = b"POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nhelloGET /y HTTP/1.1\r\n\r\n";
        let request =
            parse_raw_request(raw).expect("extra trailing bytes must not break this request");
        assert_eq!(request.body, b"hello");
    }

    #[test]
    fn rejects_malformed_request_line_extra_token() {
        let raw = b"GET /x HTTP/1.1 EXTRA\r\n\r\n";
        let err = parse_raw_request(raw).expect_err("extra request-line token must be rejected");
        assert!(matches!(err, RequestParseError::InvalidRequestLine));
    }

    #[test]
    fn rejects_body_over_the_max_size_cap() {
        let declared = MAX_BODY_BYTES + 1;
        let raw = format!("POST /x HTTP/1.1\r\nContent-Length: {declared}\r\n\r\n");
        let err = parse_raw_request(raw.as_bytes()).expect_err("oversized body must be rejected");
        assert!(matches!(err, RequestParseError::BodyTooLarge(_, _)));
    }

    #[test]
    fn two_pipelined_requests_in_one_write_only_answers_the_first() {
        // Exercises the exact scenario the module doc comment describes:
        // two full requests arrive in a single client write (and therefore
        // very plausibly a single server `read()`). `read_http_request`
        // must return only the first, well-formed, and must not panic or
        // corrupt state trying to also parse the second — the connection is
        // simply closed afterward (`should_keep_alive` is always false), so
        // the second request is never answered rather than mis-answered.
        let raw = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n";
        let request = parse_raw_request(raw).expect("first request must parse");
        assert_eq!(request.path, "/a");
    }

    // ------------------------------------------------------------------
    // Response-size cap enforcement (issue #94 item 7)
    // ------------------------------------------------------------------

    #[test]
    fn oversized_response_is_replaced_with_an_error_body() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let request = HttpRequest {
                method: "GET".to_owned(),
                path: "/x".to_owned(),
                headers: HashMap::new(),
                body: Vec::new(),
            };
            let oversized = HttpResponse {
                status: 200,
                content_type: "application/json",
                body: vec![b'a'; MAX_RESPONSE_BYTES + 1],
            };
            write_http_response_with_request(&mut stream, &oversized, &request)
                .expect("write must still succeed with the substituted body");
        });
        let mut client = TcpStream::connect(addr).expect("connect");
        let mut response = Vec::new();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("timeout");
        let _ = client.read_to_end(&mut response);
        server.join().expect("server thread");

        let response_text = String::from_utf8_lossy(&response);
        assert!(
            response_text.starts_with("HTTP/1.1 500"),
            "expected a substituted 500 response, got: {response_text}"
        );
        assert!(response_text.contains("RESPONSE_TOO_LARGE"));
        assert!(
            response.len() < MAX_RESPONSE_BYTES,
            "the oversized body must not have been written to the wire"
        );
    }
}
