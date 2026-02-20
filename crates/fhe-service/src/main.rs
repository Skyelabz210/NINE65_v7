//! FHE Microservice — HTTP boundary for the nine65 FHE engine.
//!
//! Provides a REST API for session-based FHE operations. Key material
//! never leaves the server; only ciphertexts travel over the wire.

#![deny(clippy::float_arithmetic)]

#[cfg(all(feature = "allow_insecure", not(debug_assertions)))]
compile_error!("The `allow_insecure` feature must not be used in release builds");

mod handlers;
mod http;
mod session;
mod wire;

use http::{error_response, write_http_response};
use session::{SessionStore, DEFAULT_MAX_SESSIONS};

use std::env;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

const SERVICE_NAME: &str = "fhe-service";
const DEFAULT_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: &str = "8080";

/// Maximum concurrent connections (HVT-4). Configurable via FHE_MAX_CONNECTIONS.
const DEFAULT_MAX_CONNECTIONS: usize = 256;

struct AppState {
    store: SessionStore,
    metrics: handlers::AppMetrics,
    active_connections: AtomicUsize,
    max_connections: usize,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = env::var("FHE_SERVICE_HOST").unwrap_or_else(|_| DEFAULT_HOST.to_owned());
    let port = env::var("FHE_SERVICE_PORT").unwrap_or_else(|_| DEFAULT_PORT.to_owned());
    let bind_addr = format!("{host}:{port}");

    let max_sessions: usize = env::var("FHE_MAX_SESSIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_SESSIONS);

    let max_connections: usize = env::var("FHE_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_CONNECTIONS);

    let listener = TcpListener::bind(&bind_addr)?;
    let state = Arc::new(AppState {
        store: SessionStore::new(max_sessions),
        metrics: handlers::AppMetrics::new(),
        active_connections: AtomicUsize::new(0),
        max_connections,
    });

    // Spawn a background thread to periodically reap expired sessions
    let reaper_state = Arc::clone(&state);
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60)); // Run every minute
            let removed = reaper_state.store.reap_expired_sessions();
            if removed > 0 {
                eprintln!("Reaped {} expired sessions", removed);
            }
        }
    });

    eprintln!(
        "{SERVICE_NAME} listening on {bind_addr} (max_sessions={max_sessions}, max_connections={max_connections})"
    );

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let current = state.active_connections.fetch_add(1, Ordering::Relaxed);
                if current >= state.max_connections {
                    state.active_connections.fetch_sub(1, Ordering::Relaxed);
                    // HVT-4: reject when at connection limit
                    let resp = error_response(503, "SERVICE_BUSY", "too many connections");
                    let _ = write_http_response(&mut stream, &resp);
                    continue;
                }

                let state = Arc::clone(&state);
                std::thread::spawn(move || {
                    serve_connection(&mut stream, &state);
                    state.active_connections.fetch_sub(1, Ordering::Relaxed);
                });
            }
            Err(err) => eprintln!("accept error: {err}"),
        }
    }

    Ok(())
}

fn serve_connection(stream: &mut TcpStream, state: &AppState) {
    if let Err(e) = stream.set_read_timeout(Some(Duration::from_secs(5))) {
        eprintln!("set_read_timeout: {e}");
        return;
    }

    loop {
        let request = match http::read_http_request(stream) {
            Ok(req) => req,
            Err(http::RequestParseError::ConnectionClosed) => return,
            Err(http::RequestParseError::Io(io_err))
                if matches!(
                    io_err.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                // Idle keep-alive timeout: close quietly.
                return;
            }
            Err(http::RequestParseError::BodyTooLarge(_, _)) => {
                let resp = error_response(413, "PAYLOAD_TOO_LARGE", "content-length exceeds limit");
                let _ = write_http_response(stream, &resp);
                return;
            }
            Err(err) => {
                let resp = error_response(400, "INVALID_REQUEST", "request parse error");
                let _ = write_http_response(stream, &resp);
                // Log server-side only (don't leak details to client)
                eprintln!("parse error: {err}");
                return;
            }
        };

        let keep_alive = http::should_keep_alive(&request);

        // Handle potential CSPRNG failures gracefully
        let response = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handlers::route(&request, &state.store, &state.metrics)
        }))
        .unwrap_or_else(|_| {
            // If a panic occurred (e.g., CSPRNG failure), return a 500 error
            error_response(500, "INTERNAL_ERROR", "service temporarily unavailable")
        });

        if let Err(e) = http::write_http_response_with_request(stream, &response, &request) {
            eprintln!("write error: {e}");
            return;
        }

        if !keep_alive {
            return;
        }
    }
}

pub(crate) fn unix_now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpRequest;
    use serde_json::{json, Value};
    use std::collections::HashMap;

    fn make_store() -> SessionStore {
        SessionStore::new(64)
    }

    fn make_metrics() -> handlers::AppMetrics {
        handlers::AppMetrics::new()
    }

    fn make_request(method: &str, path: &str, body: &[u8]) -> HttpRequest {
        HttpRequest {
            method: method.to_owned(),
            path: path.to_owned(),
            headers: HashMap::new(),
            body: body.to_vec(),
        }
    }

    // --- Basic routing ---

    #[test]
    fn healthz_returns_ok() {
        let store = make_store();
        let metrics = make_metrics();
        let resp = handlers::route(&make_request("GET", "/healthz", &[]), &store, &metrics);
        assert_eq!(resp.status, 200);
        let body: Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(body["status"], "ok");
    }

    #[test]
    fn version_returns_configs() {
        let store = make_store();
        let metrics = make_metrics();
        let resp = handlers::route(&make_request("GET", "/v1/version", &[]), &store, &metrics);
        assert_eq!(resp.status, 200);
        let body: Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(body["supported_configs"].is_array());
    }

    #[test]
    fn unknown_route_returns_404() {
        let store = make_store();
        let metrics = make_metrics();
        let resp = handlers::route(&make_request("GET", "/missing", &[]), &store, &metrics);
        assert_eq!(resp.status, 404);
    }

    // --- Session lifecycle ---

    #[test]
    fn create_session_returns_session_id() {
        let store = make_store();
        let metrics = make_metrics();
        let body = serde_json::to_vec(&json!({"config": "secure_128"})).unwrap();
        let resp = handlers::route(
            &make_request("POST", "/v1/sessions", &body),
            &store,
            &metrics,
        );
        assert_eq!(resp.status, 201);
        let body: Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(body["session_id"].as_str().unwrap().starts_with("sess_"));
        assert!(body["noise_budget_estimate_millibits"].as_i64().unwrap() > 0);
    }

    #[test]
    fn create_session_rejects_invalid_config() {
        let store = make_store();
        let metrics = make_metrics();
        let body = serde_json::to_vec(&json!({"config": "insecure_1"})).unwrap();
        let resp = handlers::route(
            &make_request("POST", "/v1/sessions", &body),
            &store,
            &metrics,
        );
        assert_eq!(resp.status, 400);
    }

    #[test]
    fn get_session_returns_info() {
        let store = make_store();
        let metrics = make_metrics();

        // Create
        let body = serde_json::to_vec(&json!({"config": "secure_128"})).unwrap();
        let resp = handlers::route(
            &make_request("POST", "/v1/sessions", &body),
            &store,
            &metrics,
        );
        let created: Value = serde_json::from_slice(&resp.body).unwrap();
        let sid = created["session_id"].as_str().unwrap();

        // Get
        let path = format!("/v1/sessions/{sid}");
        let resp = handlers::route(&make_request("GET", &path, &[]), &store, &metrics);
        assert_eq!(resp.status, 200);
        let info: Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(info["session_id"].as_str().unwrap(), sid);
    }

    #[test]
    fn delete_session_removes_it() {
        let store = make_store();
        let metrics = make_metrics();

        // Create
        let body = serde_json::to_vec(&json!({"config": "secure_128"})).unwrap();
        let resp = handlers::route(
            &make_request("POST", "/v1/sessions", &body),
            &store,
            &metrics,
        );
        let created: Value = serde_json::from_slice(&resp.body).unwrap();
        let sid = created["session_id"].as_str().unwrap();

        // Delete
        let path = format!("/v1/sessions/{sid}");
        let resp = handlers::route(&make_request("DELETE", &path, &[]), &store, &metrics);
        assert_eq!(resp.status, 200);

        // Get should 404
        let resp = handlers::route(&make_request("GET", &path, &[]), &store, &metrics);
        assert_eq!(resp.status, 404);
    }

    #[test]
    fn get_nonexistent_session_returns_404() {
        let store = make_store();
        let metrics = make_metrics();
        let resp = handlers::route(
            &make_request("GET", "/v1/sessions/sess_nonexistent", &[]),
            &store,
            &metrics,
        );
        assert_eq!(resp.status, 404);
    }

    // --- Max sessions enforcement ---

    #[test]
    fn max_sessions_enforced() {
        let store = SessionStore::new(2); // tiny limit
        let metrics = make_metrics();

        let body = serde_json::to_vec(&json!({"config": "secure_128"})).unwrap();

        // First two succeed
        let r1 = handlers::route(
            &make_request("POST", "/v1/sessions", &body),
            &store,
            &metrics,
        );
        assert_eq!(r1.status, 201);
        let r2 = handlers::route(
            &make_request("POST", "/v1/sessions", &body),
            &store,
            &metrics,
        );
        assert_eq!(r2.status, 201);

        // Third should fail
        let r3 = handlers::route(
            &make_request("POST", "/v1/sessions", &body),
            &store,
            &metrics,
        );
        assert_eq!(r3.status, 429);
    }

    // --- Encrypt / Decrypt roundtrip ---

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let store = make_store();
        let metrics = make_metrics();

        // Create session
        let body = serde_json::to_vec(&json!({"config": "secure_128"})).unwrap();
        let resp = handlers::route(
            &make_request("POST", "/v1/sessions", &body),
            &store,
            &metrics,
        );
        let created: Value = serde_json::from_slice(&resp.body).unwrap();
        let sid = created["session_id"].as_str().unwrap();

        // Encrypt
        let enc_body = serde_json::to_vec(&json!({"values": [42, 17]})).unwrap();
        let enc_path = format!("/v1/sessions/{sid}/encrypt");
        let resp = handlers::route(
            &make_request("POST", &enc_path, &enc_body),
            &store,
            &metrics,
        );
        assert_eq!(resp.status, 200);
        let enc_resp: Value = serde_json::from_slice(&resp.body).unwrap();
        let cts = enc_resp["ciphertexts"].as_array().unwrap();
        assert_eq!(cts.len(), 2);

        // Decrypt
        let dec_body = serde_json::to_vec(&json!({
            "ciphertexts": [cts[0].as_str().unwrap(), cts[1].as_str().unwrap()]
        }))
        .unwrap();
        let dec_path = format!("/v1/sessions/{sid}/decrypt");
        let resp = handlers::route(
            &make_request("POST", &dec_path, &dec_body),
            &store,
            &metrics,
        );
        assert_eq!(resp.status, 200);
        let dec_resp: Value = serde_json::from_slice(&resp.body).unwrap();
        let values = dec_resp["values"].as_array().unwrap();
        assert_eq!(values[0].as_u64().unwrap(), 42);
        assert_eq!(values[1].as_u64().unwrap(), 17);
    }

    // --- Homomorphic add ---

    #[test]
    fn homomorphic_add() {
        let store = make_store();
        let metrics = make_metrics();

        // Create session
        let body = serde_json::to_vec(&json!({"config": "secure_128"})).unwrap();
        let resp = handlers::route(
            &make_request("POST", "/v1/sessions", &body),
            &store,
            &metrics,
        );
        let created: Value = serde_json::from_slice(&resp.body).unwrap();
        let sid = created["session_id"].as_str().unwrap();

        // Encrypt two values
        let enc_body = serde_json::to_vec(&json!({"values": [42, 17]})).unwrap();
        let enc_path = format!("/v1/sessions/{sid}/encrypt");
        let resp = handlers::route(
            &make_request("POST", &enc_path, &enc_body),
            &store,
            &metrics,
        );
        let enc_resp: Value = serde_json::from_slice(&resp.body).unwrap();
        let ct_a = enc_resp["ciphertexts"][0].as_str().unwrap();
        let ct_b = enc_resp["ciphertexts"][1].as_str().unwrap();

        // Evaluate: add
        let eval_body = serde_json::to_vec(&json!({
            "operations": [
                {"op": "add", "inputs": [ct_a, ct_b]}
            ]
        }))
        .unwrap();
        let eval_path = format!("/v1/sessions/{sid}/evaluate");
        let resp = handlers::route(
            &make_request("POST", &eval_path, &eval_body),
            &store,
            &metrics,
        );
        assert_eq!(resp.status, 200);
        let eval_resp: Value = serde_json::from_slice(&resp.body).unwrap();
        let ct_sum = eval_resp["results"][0].as_str().unwrap();
        assert!(
            eval_resp["noise_budget_estimate_millibits"]
                .as_i64()
                .unwrap()
                > 0
        );

        // Decrypt result
        let dec_body = serde_json::to_vec(&json!({"ciphertexts": [ct_sum]})).unwrap();
        let dec_path = format!("/v1/sessions/{sid}/decrypt");
        let resp = handlers::route(
            &make_request("POST", &dec_path, &dec_body),
            &store,
            &metrics,
        );
        assert_eq!(resp.status, 200);
        let dec_resp: Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(dec_resp["values"][0].as_u64().unwrap(), 59);
    }

    // --- Homomorphic add_plain ---

    #[test]
    fn homomorphic_add_plain() {
        let store = make_store();
        let metrics = make_metrics();

        // Create session
        let body = serde_json::to_vec(&json!({"config": "secure_128"})).unwrap();
        let resp = handlers::route(
            &make_request("POST", "/v1/sessions", &body),
            &store,
            &metrics,
        );
        let created: Value = serde_json::from_slice(&resp.body).unwrap();
        let sid = created["session_id"].as_str().unwrap();

        // Encrypt
        let enc_body = serde_json::to_vec(&json!({"values": [10]})).unwrap();
        let enc_path = format!("/v1/sessions/{sid}/encrypt");
        let resp = handlers::route(
            &make_request("POST", &enc_path, &enc_body),
            &store,
            &metrics,
        );
        let enc_resp: Value = serde_json::from_slice(&resp.body).unwrap();
        let ct = enc_resp["ciphertexts"][0].as_str().unwrap();

        // Evaluate: add_plain (10 + 40 = 50)
        let eval_body = serde_json::to_vec(&json!({
            "operations": [
                {"op": "add_plain", "inputs": [ct], "scalar": 40}
            ]
        }))
        .unwrap();
        let eval_path = format!("/v1/sessions/{sid}/evaluate");
        let resp = handlers::route(
            &make_request("POST", &eval_path, &eval_body),
            &store,
            &metrics,
        );
        if resp.status != 200 {
            let err_body: Value = serde_json::from_slice(&resp.body).unwrap();
            panic!("evaluate failed ({}): {}", resp.status, err_body);
        }
        let eval_resp: Value = serde_json::from_slice(&resp.body).unwrap();
        let ct_result = eval_resp["results"][0].as_str().unwrap();

        // Decrypt
        let dec_body = serde_json::to_vec(&json!({"ciphertexts": [ct_result]})).unwrap();
        let dec_path = format!("/v1/sessions/{sid}/decrypt");
        let resp = handlers::route(
            &make_request("POST", &dec_path, &dec_body),
            &store,
            &metrics,
        );
        assert_eq!(resp.status, 200);
        let dec_resp: Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(dec_resp["values"][0].as_u64().unwrap(), 50);
    }

    // --- Noise budget tracking ---

    #[test]
    fn noise_budget_decrements() {
        let store = make_store();
        let metrics = make_metrics();

        // Create session
        let body = serde_json::to_vec(&json!({"config": "secure_128"})).unwrap();
        let resp = handlers::route(
            &make_request("POST", "/v1/sessions", &body),
            &store,
            &metrics,
        );
        let created: Value = serde_json::from_slice(&resp.body).unwrap();
        let sid = created["session_id"].as_str().unwrap();
        let initial_budget = created["noise_budget_estimate_millibits"].as_i64().unwrap();

        // Encrypt
        let enc_body = serde_json::to_vec(&json!({"values": [1, 2]})).unwrap();
        let enc_path = format!("/v1/sessions/{sid}/encrypt");
        let resp = handlers::route(
            &make_request("POST", &enc_path, &enc_body),
            &store,
            &metrics,
        );
        let enc_resp: Value = serde_json::from_slice(&resp.body).unwrap();
        let ct_a = enc_resp["ciphertexts"][0].as_str().unwrap();
        let ct_b = enc_resp["ciphertexts"][1].as_str().unwrap();

        // Perform an add
        let eval_body = serde_json::to_vec(&json!({
            "operations": [{"op": "add", "inputs": [ct_a, ct_b]}]
        }))
        .unwrap();
        let eval_path = format!("/v1/sessions/{sid}/evaluate");
        let resp = handlers::route(
            &make_request("POST", &eval_path, &eval_body),
            &store,
            &metrics,
        );
        let eval_resp: Value = serde_json::from_slice(&resp.body).unwrap();
        let budget_after = eval_resp["noise_budget_estimate_millibits"]
            .as_i64()
            .unwrap();

        assert!(
            budget_after < initial_budget,
            "budget should decrease after add: {} >= {}",
            budget_after,
            initial_budget
        );
    }

    // --- Invalid session ---

    #[test]
    fn encrypt_with_invalid_session_returns_404() {
        let store = make_store();
        let metrics = make_metrics();
        let body = serde_json::to_vec(&json!({"values": [42]})).unwrap();
        let resp = handlers::route(
            &make_request("POST", "/v1/sessions/sess_bad/encrypt", &body),
            &store,
            &metrics,
        );
        assert_eq!(resp.status, 404);
    }

    // --- Hardening: scalar range check ---

    #[test]
    fn add_plain_rejects_scalar_exceeding_plaintext_modulus() {
        let store = make_store();
        let metrics = make_metrics();

        // Create session
        let body = serde_json::to_vec(&json!({"config": "secure_128"})).unwrap();
        let resp = handlers::route(
            &make_request("POST", "/v1/sessions", &body),
            &store,
            &metrics,
        );
        let created: Value = serde_json::from_slice(&resp.body).unwrap();
        let sid = created["session_id"].as_str().unwrap();
        let t = created["params"]["t"].as_u64().unwrap();

        // Encrypt a value
        let enc_body = serde_json::to_vec(&json!({"values": [1]})).unwrap();
        let enc_path = format!("/v1/sessions/{sid}/encrypt");
        let resp = handlers::route(
            &make_request("POST", &enc_path, &enc_body),
            &store,
            &metrics,
        );
        let enc_resp: Value = serde_json::from_slice(&resp.body).unwrap();
        let ct = enc_resp["ciphertexts"][0].as_str().unwrap();

        // add_plain with scalar >= t should fail
        let eval_body = serde_json::to_vec(&json!({
            "operations": [{"op": "add_plain", "inputs": [ct], "scalar": t}]
        }))
        .unwrap();
        let eval_path = format!("/v1/sessions/{sid}/evaluate");
        let resp = handlers::route(
            &make_request("POST", &eval_path, &eval_body),
            &store,
            &metrics,
        );
        assert_eq!(resp.status, 400);
        let err: Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(
            err["error"]["code"] == "EVALUATE_FAILED",
            "unexpected error code: {}",
            err
        );
        assert!(
            err["error"]["message"] == "operation failed",
            "unexpected error message: {}",
            err
        );
    }

    // --- Hardening: encrypt error doesn't leak modulus ---

    #[test]
    fn encrypt_error_does_not_leak_plaintext_modulus() {
        let store = make_store();
        let metrics = make_metrics();

        // Create session
        let body = serde_json::to_vec(&json!({"config": "secure_128"})).unwrap();
        let resp = handlers::route(
            &make_request("POST", "/v1/sessions", &body),
            &store,
            &metrics,
        );
        let created: Value = serde_json::from_slice(&resp.body).unwrap();
        let sid = created["session_id"].as_str().unwrap();
        let t = created["params"]["t"].as_u64().unwrap();

        // Encrypt a value >= t
        let enc_body = serde_json::to_vec(&json!({"values": [t + 1]})).unwrap();
        let enc_path = format!("/v1/sessions/{sid}/encrypt");
        let resp = handlers::route(
            &make_request("POST", &enc_path, &enc_body),
            &store,
            &metrics,
        );
        assert_eq!(resp.status, 400);
        let err: Value = serde_json::from_slice(&resp.body).unwrap();
        let msg = err["error"]["message"].as_str().unwrap();
        // Error should NOT contain the actual modulus value
        assert!(
            !msg.contains(&t.to_string()),
            "error should not leak plaintext modulus value: {}",
            msg
        );
    }

    // --- Hardening: unknown evaluate operation ---

    #[test]
    fn evaluate_rejects_unknown_operation() {
        let store = make_store();
        let metrics = make_metrics();

        // Create session
        let body = serde_json::to_vec(&json!({"config": "secure_128"})).unwrap();
        let resp = handlers::route(
            &make_request("POST", "/v1/sessions", &body),
            &store,
            &metrics,
        );
        let created: Value = serde_json::from_slice(&resp.body).unwrap();
        let sid = created["session_id"].as_str().unwrap();

        // Encrypt
        let enc_body = serde_json::to_vec(&json!({"values": [1]})).unwrap();
        let enc_path = format!("/v1/sessions/{sid}/encrypt");
        let resp = handlers::route(
            &make_request("POST", &enc_path, &enc_body),
            &store,
            &metrics,
        );
        let enc_resp: Value = serde_json::from_slice(&resp.body).unwrap();
        let ct = enc_resp["ciphertexts"][0].as_str().unwrap();

        // Evaluate with unknown op
        let eval_body = serde_json::to_vec(&json!({
            "operations": [{"op": "bogus_op", "inputs": [ct]}]
        }))
        .unwrap();
        let eval_path = format!("/v1/sessions/{sid}/evaluate");
        let resp = handlers::route(
            &make_request("POST", &eval_path, &eval_body),
            &store,
            &metrics,
        );
        assert_eq!(resp.status, 400);
        let err: Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(
            err["error"]["code"] == "EVALUATE_FAILED",
            "unexpected error code: {}",
            err
        );
        assert!(
            err["error"]["message"] == "operation failed",
            "unexpected error message: {}",
            err
        );
    }

    // --- Hardening: add with wrong input count ---

    #[test]
    fn evaluate_add_rejects_wrong_input_count() {
        let store = make_store();
        let metrics = make_metrics();

        // Create session
        let body = serde_json::to_vec(&json!({"config": "secure_128"})).unwrap();
        let resp = handlers::route(
            &make_request("POST", "/v1/sessions", &body),
            &store,
            &metrics,
        );
        let created: Value = serde_json::from_slice(&resp.body).unwrap();
        let sid = created["session_id"].as_str().unwrap();

        // Encrypt
        let enc_body = serde_json::to_vec(&json!({"values": [1]})).unwrap();
        let enc_path = format!("/v1/sessions/{sid}/encrypt");
        let resp = handlers::route(
            &make_request("POST", &enc_path, &enc_body),
            &store,
            &metrics,
        );
        let enc_resp: Value = serde_json::from_slice(&resp.body).unwrap();
        let ct = enc_resp["ciphertexts"][0].as_str().unwrap();

        // add requires 2 inputs, send only 1
        let eval_body = serde_json::to_vec(&json!({
            "operations": [{"op": "add", "inputs": [ct]}]
        }))
        .unwrap();
        let eval_path = format!("/v1/sessions/{sid}/evaluate");
        let resp = handlers::route(
            &make_request("POST", &eval_path, &eval_body),
            &store,
            &metrics,
        );
        assert_eq!(resp.status, 400);
        let err: Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(
            err["error"]["code"] == "EVALUATE_FAILED",
            "unexpected error code: {}",
            err
        );
        assert!(
            err["error"]["message"] == "operation failed",
            "unexpected error message: {}",
            err
        );
    }

    // --- Hardening: decrypt errors are generic/non-leaky ---

    #[test]
    fn decrypt_error_is_generic_and_non_leaky() {
        let store = make_store();
        let metrics = make_metrics();

        // Create session
        let body = serde_json::to_vec(&json!({"config": "secure_128"})).unwrap();
        let resp = handlers::route(
            &make_request("POST", "/v1/sessions", &body),
            &store,
            &metrics,
        );
        let created: Value = serde_json::from_slice(&resp.body).unwrap();
        let sid = created["session_id"].as_str().unwrap();

        // Submit invalid base64 ciphertext
        let dec_body = serde_json::to_vec(&json!({"ciphertexts": ["%%%invalid%%%"]})).unwrap();
        let dec_path = format!("/v1/sessions/{sid}/decrypt");
        let resp = handlers::route(
            &make_request("POST", &dec_path, &dec_body),
            &store,
            &metrics,
        );
        assert_eq!(resp.status, 400);

        let err: Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(err["error"]["code"], "DECRYPT_FAILED");
        assert_eq!(err["error"]["message"], "operation failed");
    }
}
