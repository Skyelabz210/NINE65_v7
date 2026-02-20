//! HTTP request/response parsing
//!
//! Extracted from the original monolithic main.rs with body size limits (HVT-4).

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

            let content_length = headers
                .get("content-length")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);

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
                    break;
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

            let body_end = std::cmp::min(data.len(), body_start + content_length);
            let body = if body_start <= body_end {
                data[body_start..body_end].to_vec()
            } else {
                Vec::new()
            };

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

fn parse_request_head(
    head: &str,
) -> Result<(String, String, HashMap<String, String>), RequestParseError> {
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(RequestParseError::InvalidRequestLine)?;
    let mut parts = request_line.split_whitespace();

    let method = parts
        .next()
        .ok_or(RequestParseError::InvalidRequestLine)?
        .to_owned();
    let raw_path = parts.next().ok_or(RequestParseError::InvalidRequestLine)?;
    let path = raw_path.split('?').next().unwrap_or(raw_path).to_owned();

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
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
    let status_text = status_text(response.status);
    let connection_header = connection_header_for_request(request);

    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n{}\r\n\r\n",
        response.status,
        status_text,
        response.content_type,
        response.body.len(),
        connection_header
    );

    stream.write_all(header.as_bytes())?;
    stream.write_all(&response.body)?;
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

/// Determine whether this request asks for persistent connection reuse.
pub fn should_keep_alive(request: &HttpRequest) -> bool {
    if let Some(conn_header) = request.headers.get("connection") {
        let normalized = conn_header.to_ascii_lowercase();
        if normalized.contains("close") {
            return false;
        }
        if normalized.contains("keep-alive") {
            return true;
        }
    }
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

    #[test]
    fn parse_request_head_strips_query_params() {
        let head = "GET /v1/fhe/public-key?tenant=abc HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let (method, path, headers) = parse_request_head(head).unwrap();
        assert_eq!(method, "GET");
        assert_eq!(path, "/v1/fhe/public-key");
        assert_eq!(headers.get("host").map(String::as_str), Some("localhost"));
    }

    #[test]
    fn should_keep_alive_only_when_requested() {
        let mut headers = HashMap::new();
        headers.insert("connection".to_owned(), "keep-alive".to_owned());
        let req = HttpRequest {
            method: "GET".to_owned(),
            path: "/healthz".to_owned(),
            headers,
            body: Vec::new(),
        };
        assert!(should_keep_alive(&req));
        assert_eq!(
            connection_header_for_request(&req),
            "Connection: keep-alive"
        );
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
}
