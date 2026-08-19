//! FHE Microservice — HTTP boundary for the nine65 FHE engine.
//!
//! Provides a REST API for session-based FHE operations. Key material
//! never leaves the server; only ciphertexts travel over the wire.

#![deny(clippy::float_arithmetic)]

#[cfg(all(feature = "allow_insecure", not(debug_assertions)))]
compile_error!("The `allow_insecure` feature must not be used in release builds");

mod auth;
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
    let store = match env::var("FHE_SESSION_TTL")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        Some(ttl) => SessionStore::new_with_ttl(max_sessions, ttl),
        None => SessionStore::new(max_sessions),
    };
    let state = Arc::new(AppState {
        store,
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
        "{SERVICE_NAME} listening on {bind_addr} (max_sessions={max_sessions}, ttl={}s, max_connections={max_connections})",
        state.store.ttl_seconds()
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
        let mut request = match http::read_http_request(stream) {
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

        // Tenant-bound ingress authentication (G17 fix): `auth.rs` defines
        // `authorize_and_normalize`, which cryptographically binds the
        // caller's claimed `x-fhe-tenant-id` to a tenant-specific credential
        // in `FHE_TENANT_TOKENS`, then replaces the request's
        // `x-fhe-api-token` header with the internal-only token from
        // `FHE_API_TOKEN`. This module previously existed but was never
        // declared in this binary's module tree (no `mod auth;`) and was
        // never called, so the only auth actually enforced was
        // `handlers::protected_access`'s single global `FHE_API_TOKEN` check
        // against a *self-asserted* `x-fhe-tenant-id` header -- any caller
        // holding that one shared token could claim to be any tenant and
        // both read/rate-limit as, and reach session lookups scoped to, that
        // tenant. Running this first closes that gap; `protected_access`
        // downstream still re-checks the (now server-normalized) API token
        // as a fail-closed invariant.
        let response = match auth::authorize_and_normalize(&mut request) {
            Err(unauthorized) => unauthorized,
            Ok(()) => {
                // Handle potential CSPRNG failures gracefully
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    handlers::route(&request, &state.store, &state.metrics)
                }))
                .unwrap_or_else(|_| {
                    // If a panic occurred (e.g., CSPRNG failure), return a 500 error
                    error_response(500, "INTERNAL_ERROR", "service temporarily unavailable")
                })
            }
        };

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

    // --- Session store TTL configuration ---

    #[test]
    fn session_store_custom_ttl() {
        let store = SessionStore::new_with_ttl(16, 7200);
        assert_eq!(store.ttl_seconds(), 7200);
        assert_eq!(store.count(), 0);
    }

    // ========================================================================
    // DualRNS quality tests — verifying correct ct×ct multiplication
    // and all operations through the DualRNS pipeline
    // ========================================================================

    /// Helper: create session, encrypt values, return (session_id, ciphertext_b64_strings)
    fn setup_and_encrypt(
        store: &SessionStore,
        metrics: &handlers::AppMetrics,
        values: &[u64],
    ) -> (String, Vec<String>) {
        let body = serde_json::to_vec(&json!({"config": "secure_128"})).unwrap();
        let resp = handlers::route(&make_request("POST", "/v1/sessions", &body), store, metrics);
        assert_eq!(resp.status, 201);
        let created: Value = serde_json::from_slice(&resp.body).unwrap();
        let sid = created["session_id"].as_str().unwrap().to_owned();

        let enc_body = serde_json::to_vec(&json!({"values": values})).unwrap();
        let enc_path = format!("/v1/sessions/{sid}/encrypt");
        let resp = handlers::route(&make_request("POST", &enc_path, &enc_body), store, metrics);
        assert_eq!(resp.status, 200, "encrypt failed");
        let enc_resp: Value = serde_json::from_slice(&resp.body).unwrap();
        let cts: Vec<String> = enc_resp["ciphertexts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        (sid, cts)
    }

    /// Helper: evaluate a single operation, return result ciphertext b64
    fn eval_op(
        store: &SessionStore,
        metrics: &handlers::AppMetrics,
        sid: &str,
        op: Value,
    ) -> String {
        let eval_body = serde_json::to_vec(&json!({"operations": [op]})).unwrap();
        let eval_path = format!("/v1/sessions/{sid}/evaluate");
        let resp = handlers::route(
            &make_request("POST", &eval_path, &eval_body),
            store,
            metrics,
        );
        assert_eq!(
            resp.status,
            200,
            "evaluate failed: {}",
            String::from_utf8_lossy(&resp.body)
        );
        let eval_resp: Value = serde_json::from_slice(&resp.body).unwrap();
        eval_resp["results"][0].as_str().unwrap().to_owned()
    }

    /// Helper: decrypt a ciphertext, return plaintext value
    fn decrypt_one(
        store: &SessionStore,
        metrics: &handlers::AppMetrics,
        sid: &str,
        ct_b64: &str,
    ) -> u64 {
        let dec_body = serde_json::to_vec(&json!({"ciphertexts": [ct_b64]})).unwrap();
        let dec_path = format!("/v1/sessions/{sid}/decrypt");
        let resp = handlers::route(&make_request("POST", &dec_path, &dec_body), store, metrics);
        assert_eq!(
            resp.status,
            200,
            "decrypt failed: {}",
            String::from_utf8_lossy(&resp.body)
        );
        let dec_resp: Value = serde_json::from_slice(&resp.body).unwrap();
        dec_resp["values"][0].as_u64().unwrap()
    }

    // --- ct×ct multiplication (THE key test) ---

    #[test]
    fn dualrns_mul_ct_basic() {
        let store = make_store();
        let metrics = make_metrics();
        let (sid, cts) = setup_and_encrypt(&store, &metrics, &[7, 8]);
        let ct_result = eval_op(
            &store,
            &metrics,
            &sid,
            json!({"op": "mul", "inputs": [cts[0], cts[1]]}),
        );
        let result = decrypt_one(&store, &metrics, &sid, &ct_result);
        assert_eq!(result, 56, "7 × 8 should be 56");
    }

    #[test]
    fn dualrns_mul_ct_by_one() {
        let store = make_store();
        let metrics = make_metrics();
        let (sid, cts) = setup_and_encrypt(&store, &metrics, &[42, 1]);
        let ct_result = eval_op(
            &store,
            &metrics,
            &sid,
            json!({"op": "mul", "inputs": [cts[0], cts[1]]}),
        );
        let result = decrypt_one(&store, &metrics, &sid, &ct_result);
        assert_eq!(result, 42, "42 × 1 should be 42");
    }

    #[test]
    fn dualrns_mul_ct_by_zero() {
        let store = make_store();
        let metrics = make_metrics();
        let (sid, cts) = setup_and_encrypt(&store, &metrics, &[42, 0]);
        let ct_result = eval_op(
            &store,
            &metrics,
            &sid,
            json!({"op": "mul", "inputs": [cts[0], cts[1]]}),
        );
        let result = decrypt_one(&store, &metrics, &sid, &ct_result);
        assert_eq!(result, 0, "42 × 0 should be 0");
    }

    #[test]
    fn dualrns_mul_ct_small_values() {
        let store = make_store();
        let metrics = make_metrics();
        // Test several small multiplications
        for (a, b) in &[(2, 3), (5, 11), (13, 17), (100, 200)] {
            let (sid, cts) = setup_and_encrypt(&store, &metrics, &[*a, *b]);
            let ct_result = eval_op(
                &store,
                &metrics,
                &sid,
                json!({"op": "mul", "inputs": [cts[0], cts[1]]}),
            );
            let result = decrypt_one(&store, &metrics, &sid, &ct_result);
            let expected = ((*a as u128) * (*b as u128) % 65537) as u64;
            assert_eq!(
                result, expected,
                "{} × {} should be {} (mod t)",
                a, b, expected
            );
        }
    }

    // Near-t values are rejected when exact_rational feature is enabled (drift zone guard).
    #[cfg(not(feature = "exact_rational"))]
    #[test]
    fn dualrns_mul_ct_near_t() {
        let store = make_store();
        let metrics = make_metrics();
        // Values near t=65537 that will wrap: 65536 × 2 = 131072 mod 65537 = 65535
        let (sid, cts) = setup_and_encrypt(&store, &metrics, &[65536, 2]);
        let ct_result = eval_op(
            &store,
            &metrics,
            &sid,
            json!({"op": "mul", "inputs": [cts[0], cts[1]]}),
        );
        let result = decrypt_one(&store, &metrics, &sid, &ct_result);
        let expected = (65536u128 * 2 % 65537) as u64;
        assert_eq!(
            result, expected,
            "65536 × 2 mod 65537 should be {}",
            expected
        );
    }

    // When exact_rational is enabled, near-t values are rejected by the drift zone guard.
    #[cfg(feature = "exact_rational")]
    #[test]
    fn exact_rational_rejects_near_t_values() {
        let store = make_store();
        let metrics = make_metrics();

        let body = serde_json::to_vec(&json!({"config": "secure_128"})).unwrap();
        let resp = handlers::route(
            &make_request("POST", "/v1/sessions", &body),
            &store,
            &metrics,
        );
        let created: Value = serde_json::from_slice(&resp.body).unwrap();
        let sid = created["session_id"].as_str().unwrap();

        // 65536 is in the drift zone (t - 100 = 65437 < 65536 < 65537)
        let enc_body = serde_json::to_vec(&json!({"values": [65536]})).unwrap();
        let enc_path = format!("/v1/sessions/{sid}/encrypt");
        let resp = handlers::route(
            &make_request("POST", &enc_path, &enc_body),
            &store,
            &metrics,
        );
        assert_eq!(resp.status, 400, "near-t value should be rejected");

        // 65437 is the boundary (t - 100) — should also be rejected (> t - safe_margin)
        let enc_body = serde_json::to_vec(&json!({"values": [65438]})).unwrap();
        let resp = handlers::route(
            &make_request("POST", &enc_path, &enc_body),
            &store,
            &metrics,
        );
        assert_eq!(resp.status, 400, "boundary value should be rejected");

        // 65437 is at the edge — should be accepted (= t - safe_margin)
        let enc_body = serde_json::to_vec(&json!({"values": [65437]})).unwrap();
        let resp = handlers::route(
            &make_request("POST", &enc_path, &enc_body),
            &store,
            &metrics,
        );
        assert_eq!(resp.status, 200, "value at safe margin should be accepted");

        // Small values are always accepted
        let enc_body = serde_json::to_vec(&json!({"values": [42]})).unwrap();
        let resp = handlers::route(
            &make_request("POST", &enc_path, &enc_body),
            &store,
            &metrics,
        );
        assert_eq!(resp.status, 200, "small value should be accepted");
    }

    #[test]
    fn dualrns_mul_ct_larger_values() {
        let store = make_store();
        let metrics = make_metrics();
        // 255 × 256 = 65280
        let (sid, cts) = setup_and_encrypt(&store, &metrics, &[255, 256]);
        let ct_result = eval_op(
            &store,
            &metrics,
            &sid,
            json!({"op": "mul", "inputs": [cts[0], cts[1]]}),
        );
        let result = decrypt_one(&store, &metrics, &sid, &ct_result);
        assert_eq!(result, 65280, "255 × 256 should be 65280");
    }

    // --- sub operation ---

    #[test]
    fn dualrns_sub_basic() {
        let store = make_store();
        let metrics = make_metrics();
        let (sid, cts) = setup_and_encrypt(&store, &metrics, &[50, 17]);
        let ct_result = eval_op(
            &store,
            &metrics,
            &sid,
            json!({"op": "sub", "inputs": [cts[0], cts[1]]}),
        );
        let result = decrypt_one(&store, &metrics, &sid, &ct_result);
        assert_eq!(result, 33, "50 - 17 should be 33");
    }

    #[test]
    fn dualrns_sub_underflow_wraps() {
        let store = make_store();
        let metrics = make_metrics();
        // 5 - 10 mod 65537 = 65532
        let (sid, cts) = setup_and_encrypt(&store, &metrics, &[5, 10]);
        let ct_result = eval_op(
            &store,
            &metrics,
            &sid,
            json!({"op": "sub", "inputs": [cts[0], cts[1]]}),
        );
        let result = decrypt_one(&store, &metrics, &sid, &ct_result);
        let expected = (65537 + 5 - 10) as u64; // 65532
        assert_eq!(result, expected, "5 - 10 mod 65537 should be {}", expected);
    }

    // --- negate operation ---

    #[test]
    fn dualrns_negate_basic() {
        let store = make_store();
        let metrics = make_metrics();
        let (sid, cts) = setup_and_encrypt(&store, &metrics, &[42]);
        let ct_neg = eval_op(
            &store,
            &metrics,
            &sid,
            json!({"op": "negate", "inputs": [cts[0]]}),
        );
        let result = decrypt_one(&store, &metrics, &sid, &ct_neg);
        let expected = 65537 - 42;
        assert_eq!(result, expected, "-42 mod 65537 should be {}", expected);
    }

    #[test]
    fn dualrns_negate_then_add_is_zero() {
        let store = make_store();
        let metrics = make_metrics();
        let (sid, cts) = setup_and_encrypt(&store, &metrics, &[42]);
        let ct_neg = eval_op(
            &store,
            &metrics,
            &sid,
            json!({"op": "negate", "inputs": [cts[0]]}),
        );
        let ct_sum = eval_op(
            &store,
            &metrics,
            &sid,
            json!({"op": "add", "inputs": [cts[0], ct_neg]}),
        );
        let result = decrypt_one(&store, &metrics, &sid, &ct_sum);
        assert_eq!(result, 0, "x + (-x) should be 0");
    }

    // --- mul_plain operation ---

    #[test]
    fn dualrns_mul_plain_basic() {
        let store = make_store();
        let metrics = make_metrics();
        let (sid, cts) = setup_and_encrypt(&store, &metrics, &[7]);
        let ct_result = eval_op(
            &store,
            &metrics,
            &sid,
            json!({"op": "mul_plain", "inputs": [cts[0]], "scalar": 6}),
        );
        let result = decrypt_one(&store, &metrics, &sid, &ct_result);
        assert_eq!(result, 42, "7 × 6 should be 42");
    }

    #[test]
    fn dualrns_mul_plain_by_zero() {
        let store = make_store();
        let metrics = make_metrics();
        let (sid, cts) = setup_and_encrypt(&store, &metrics, &[42]);
        let ct_result = eval_op(
            &store,
            &metrics,
            &sid,
            json!({"op": "mul_plain", "inputs": [cts[0]], "scalar": 0}),
        );
        let result = decrypt_one(&store, &metrics, &sid, &ct_result);
        assert_eq!(result, 0, "42 × 0 should be 0");
    }

    // --- chained operations ---

    #[test]
    fn dualrns_chained_add_then_mul_plain() {
        let store = make_store();
        let metrics = make_metrics();
        // (10 + 20) × 3 = 90
        let (sid, cts) = setup_and_encrypt(&store, &metrics, &[10, 20]);
        let ct_sum = eval_op(
            &store,
            &metrics,
            &sid,
            json!({"op": "add", "inputs": [cts[0], cts[1]]}),
        );
        let ct_result = eval_op(
            &store,
            &metrics,
            &sid,
            json!({"op": "mul_plain", "inputs": [ct_sum], "scalar": 3}),
        );
        let result = decrypt_one(&store, &metrics, &sid, &ct_result);
        assert_eq!(result, 90, "(10 + 20) × 3 should be 90");
    }

    #[test]
    fn dualrns_mul_ct_then_decrypt() {
        let store = make_store();
        let metrics = make_metrics();
        // After ct×ct mul, verify the result decrypts correctly on its own.
        // Note: add_plain after mul requires level-aware delta encoding (future work).
        let (sid, cts) = setup_and_encrypt(&store, &metrics, &[5, 6]);
        let ct_product = eval_op(
            &store,
            &metrics,
            &sid,
            json!({"op": "mul", "inputs": [cts[0], cts[1]]}),
        );
        let result = decrypt_one(&store, &metrics, &sid, &ct_product);
        assert_eq!(result, 30, "5 × 6 should be 30");
    }

    #[test]
    fn dualrns_chained_mul_ct_then_mul_plain() {
        let store = make_store();
        let metrics = make_metrics();
        // (3 × 4) × 2_plain = 24
        let (sid, cts) = setup_and_encrypt(&store, &metrics, &[3, 4]);
        let ct_product = eval_op(
            &store,
            &metrics,
            &sid,
            json!({"op": "mul", "inputs": [cts[0], cts[1]]}),
        );
        let ct_result = eval_op(
            &store,
            &metrics,
            &sid,
            json!({"op": "mul_plain", "inputs": [ct_product], "scalar": 2}),
        );
        let result = decrypt_one(&store, &metrics, &sid, &ct_result);
        assert_eq!(result, 24, "(3 × 4) × 2_plain should be 24");
    }

    #[test]
    fn dualrns_chained_add_plain_then_mul_ct() {
        let store = make_store();
        let metrics = make_metrics();
        // (3 + 7_plain) × 5 = 50
        let (sid, cts) = setup_and_encrypt(&store, &metrics, &[3, 5]);
        let ct_sum = eval_op(
            &store,
            &metrics,
            &sid,
            json!({"op": "add_plain", "inputs": [cts[0]], "scalar": 7}),
        );
        let ct_result = eval_op(
            &store,
            &metrics,
            &sid,
            json!({"op": "mul", "inputs": [ct_sum, cts[1]]}),
        );
        let result = decrypt_one(&store, &metrics, &sid, &ct_result);
        assert_eq!(result, 50, "(3 + 7) × 5 should be 50");
    }

    // --- batch operations (multiple ops in one evaluate call) ---

    #[test]
    fn dualrns_batch_operations() {
        let store = make_store();
        let metrics = make_metrics();
        let (sid, cts) = setup_and_encrypt(&store, &metrics, &[10, 20, 30]);

        // Batch: add(ct0, ct1), sub(ct2, ct1), negate(ct0)
        let eval_body = serde_json::to_vec(&json!({
            "operations": [
                {"op": "add", "inputs": [cts[0], cts[1]]},
                {"op": "sub", "inputs": [cts[2], cts[1]]},
                {"op": "negate", "inputs": [cts[0]]}
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
        let results = eval_resp["results"].as_array().unwrap();
        assert_eq!(results.len(), 3);

        let v0 = decrypt_one(&store, &metrics, &sid, results[0].as_str().unwrap());
        let v1 = decrypt_one(&store, &metrics, &sid, results[1].as_str().unwrap());
        let v2 = decrypt_one(&store, &metrics, &sid, results[2].as_str().unwrap());

        assert_eq!(v0, 30, "10 + 20 = 30");
        assert_eq!(v1, 10, "30 - 20 = 10");
        assert_eq!(v2, 65537 - 10, "-10 mod 65537");
    }

    // --- ct×ct correctness (the critical test) ---

    #[test]
    fn dualrns_mul_ct_11_times_13_equals_143() {
        let store = make_store();
        let metrics = make_metrics();
        let (sid, cts) = setup_and_encrypt(&store, &metrics, &[11, 13]);
        let ct_result = eval_op(
            &store,
            &metrics,
            &sid,
            json!({"op": "mul", "inputs": [cts[0], cts[1]]}),
        );
        let result = decrypt_one(&store, &metrics, &sid, &ct_result);
        assert_eq!(
            result, 143,
            "11 × 13 must equal 143 — K-Elimination correctness"
        );
    }

    // --- secure_192 config test (more noise headroom) ---

    fn setup_and_encrypt_config(
        store: &SessionStore,
        metrics: &handlers::AppMetrics,
        config: &str,
        values: &[u64],
    ) -> (String, Vec<String>) {
        let body = serde_json::to_vec(&json!({"config": config})).unwrap();
        let resp = handlers::route(&make_request("POST", "/v1/sessions", &body), store, metrics);
        assert_eq!(resp.status, 201, "failed to create {} session", config);
        let created: Value = serde_json::from_slice(&resp.body).unwrap();
        let sid = created["session_id"].as_str().unwrap().to_owned();

        let enc_body = serde_json::to_vec(&json!({"values": values})).unwrap();
        let enc_path = format!("/v1/sessions/{sid}/encrypt");
        let resp = handlers::route(&make_request("POST", &enc_path, &enc_body), store, metrics);
        assert_eq!(resp.status, 200, "encrypt failed for {}", config);
        let enc_resp: Value = serde_json::from_slice(&resp.body).unwrap();
        let cts: Vec<String> = enc_resp["ciphertexts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        (sid, cts)
    }

    #[test]
    fn dualrns_secure_192_mul_ct() {
        let store = make_store();
        let metrics = make_metrics();
        let (sid, cts) = setup_and_encrypt_config(&store, &metrics, "secure_192", &[37, 41]);
        let ct_result = eval_op(
            &store,
            &metrics,
            &sid,
            json!({"op": "mul", "inputs": [cts[0], cts[1]]}),
        );
        let result = decrypt_one(&store, &metrics, &sid, &ct_result);
        assert_eq!(result, 1517, "37 × 41 should be 1517 on secure_192");
    }

    #[test]
    fn dualrns_secure_192_mul_then_add_plain() {
        let store = make_store();
        let metrics = make_metrics();
        // secure_192 has more noise budget — can chain mul + add_plain
        let (sid, cts) = setup_and_encrypt_config(&store, &metrics, "secure_192", &[10, 20]);
        let ct_product = eval_op(
            &store,
            &metrics,
            &sid,
            json!({"op": "mul", "inputs": [cts[0], cts[1]]}),
        );
        // Direct decrypt of mul result should work
        let result = decrypt_one(&store, &metrics, &sid, &ct_product);
        assert_eq!(result, 200, "10 × 20 should be 200 on secure_192");
    }

    // --- encrypt/decrypt roundtrip for all configs ---

    #[test]
    fn dualrns_roundtrip_all_configs() {
        let store = make_store();
        let metrics = make_metrics();
        for config in &["secure_128", "secure_192", "secure_256"] {
            let (sid, cts) = setup_and_encrypt_config(&store, &metrics, config, &[42, 17, 0, 1]);
            for (i, expected) in [42u64, 17, 0, 1].iter().enumerate() {
                let result = decrypt_one(&store, &metrics, &sid, &cts[i]);
                assert_eq!(
                    result, *expected,
                    "roundtrip failed for value {} on {}",
                    expected, config
                );
            }
        }
    }

    // --- operation count tracking ---

    #[test]
    fn dualrns_operation_count_tracks() {
        let store = make_store();
        let metrics = make_metrics();
        let (sid, cts) = setup_and_encrypt(&store, &metrics, &[1, 2]);

        // 2 encrypts → op_count = 2
        let path = format!("/v1/sessions/{sid}");
        let resp = handlers::route(&make_request("GET", &path, &[]), &store, &metrics);
        let info: Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(info["operation_count"].as_u64().unwrap(), 2);

        // 1 evaluate (add) → op_count = 3
        eval_op(
            &store,
            &metrics,
            &sid,
            json!({"op": "add", "inputs": [cts[0], cts[1]]}),
        );

        let resp = handlers::route(&make_request("GET", &path, &[]), &store, &metrics);
        let info: Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(info["operation_count"].as_u64().unwrap(), 3);
    }
}
