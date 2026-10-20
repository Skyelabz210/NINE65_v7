//! Request handlers and service-boundary policy.

use crate::http::{error_response, json_response, HttpRequest, HttpResponse, MAX_RESPONSE_BYTES};
use crate::session::SessionStore;
use crate::wire::{
    CreateSessionRequest, CreateSessionResponse, DecryptRequest, DecryptResponse, EncryptRequest,
    EncryptResponse, EvaluateRequest, EvaluateResponse, SessionInfoResponse,
};

use crate::session::SessionError;
use nine65::ops::cram_main::CramMainCiphertext;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use subtle::ConstantTimeEq;

const DEFAULT_RATE_LIMIT_PER_MINUTE: u64 = 120;
const MAX_ESTIMATED_CIPHERTEXT_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const _: () = assert!(DEFAULT_RATE_LIMIT_PER_MINUTE > 0);

#[derive(Clone, Debug)]
struct AccessContext {
    tenant_id: String,
}

#[derive(Clone, Copy, Debug)]
struct RateWindow {
    minute: u64,
    requests: u64,
}

pub struct AppMetrics {
    pub start_unix_seconds: u64,
    pub requests_total: AtomicU64,
    pub requests_failed: AtomicU64,
    rate_windows: Mutex<HashMap<String, RateWindow>>,
}

impl AppMetrics {
    pub fn new() -> Self {
        Self {
            start_unix_seconds: crate::unix_now_seconds(),
            requests_total: AtomicU64::new(0),
            requests_failed: AtomicU64::new(0),
            rate_windows: Mutex::new(HashMap::new()),
        }
    }

    fn allow_request(&self, tenant_id: &str) -> bool {
        #[cfg(test)]
        {
            let _ = tenant_id;
            true
        }

        #[cfg(not(test))]
        {
            let limit = std::env::var("FHE_RATE_LIMIT_PER_MINUTE")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|&value| value > 0)
                .unwrap_or(DEFAULT_RATE_LIMIT_PER_MINUTE);
            let minute = crate::unix_now_seconds() / 60;
            let Ok(mut windows) = self.rate_windows.lock() else {
                return false;
            };
            let window = windows.entry(tenant_id.to_owned()).or_insert(RateWindow {
                minute,
                requests: 0,
            });
            rate_limit_allows(window, minute, limit)
        }
    }
}

/// Pure per-tenant rate-limit decision for one request arriving in `minute`,
/// given the tenant's current window; advances/resets `window` in place.
///
/// Extracted out of `allow_request` so it is directly unit-testable:
/// `allow_request` itself is unconditionally `true` under `#[cfg(test)]` (so
/// tests are never flaky from rate limiting), which would otherwise make
/// `RateWindow` and this logic look unused to a `cargo test` build.
fn rate_limit_allows(window: &mut RateWindow, minute: u64, limit: u64) -> bool {
    if window.minute != minute {
        window.minute = minute;
        window.requests = 0;
    }
    if window.requests >= limit {
        return false;
    }
    window.requests += 1;
    true
}

fn token_matches(expected: Option<&str>, provided: Option<&str>) -> bool {
    let Some(expected) = expected.filter(|token| !token.is_empty()) else {
        return false;
    };
    let Some(provided) = provided else {
        return false;
    };
    let expected_digest: [u8; 32] = Sha256::digest(expected.as_bytes()).into();
    let provided_digest: [u8; 32] = Sha256::digest(provided.as_bytes()).into();
    bool::from(expected_digest.ct_eq(&provided_digest))
}

fn valid_tenant_id(tenant_id: &str) -> bool {
    !tenant_id.is_empty()
        && tenant_id.len() <= 64
        && tenant_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn protected_access(request: &HttpRequest) -> Result<AccessContext, HttpResponse> {
    #[cfg(test)]
    {
        let _ = request;
        Ok(AccessContext {
            tenant_id: "test".to_string(),
        })
    }

    #[cfg(not(test))]
    {
        let expected = std::env::var("FHE_API_TOKEN").ok();
        let provided = request.headers.get("x-fhe-api-token").map(String::as_str);
        if !token_matches(expected.as_deref(), provided) {
            return Err(error_response(
                401,
                "UNAUTHORIZED",
                "authentication required",
            ));
        }

        let Some(tenant_id) = request.headers.get("x-fhe-tenant-id") else {
            return Err(error_response(400, "TENANT_REQUIRED", "tenant id required"));
        };
        if !valid_tenant_id(tenant_id) {
            return Err(error_response(400, "INVALID_TENANT", "invalid tenant id"));
        }
        Ok(AccessContext {
            tenant_id: tenant_id.clone(),
        })
    }
}

fn decrypt_authorized_with(
    enabled: bool,
    expected_token: Option<&str>,
    provided_token: Option<&str>,
) -> bool {
    enabled && token_matches(expected_token, provided_token)
}

fn decrypt_route_authorized(request: &HttpRequest) -> bool {
    #[cfg(test)]
    {
        let _ = request;
        true
    }

    #[cfg(not(test))]
    {
        let enabled = std::env::var("FHE_ENABLE_DECRYPT").ok().as_deref() == Some("1");
        let expected = std::env::var("FHE_DECRYPT_TOKEN").ok();
        let provided = request
            .headers
            .get("x-fhe-decrypt-token")
            .map(String::as_str);
        decrypt_authorized_with(enabled, expected.as_deref(), provided)
    }
}

fn session_error_response(operation: &str, error: SessionError) -> HttpResponse {
    match error {
        SessionError::InvalidInput => error_response(400, operation, "operation failed"),
        SessionError::NoiseExhausted => error_response(
            422,
            "NOISE_EXHAUSTED",
            "certified noise bound refuses this operation",
        ),
        SessionError::Capacity => error_response(
            429,
            "SESSION_CAPACITY",
            "ciphertext registry capacity reached",
        ),
        SessionError::Operation => error_response(400, operation, "operation failed"),
    }
}

fn operator_route_authorized(request: &HttpRequest) -> bool {
    #[cfg(test)]
    {
        let _ = request;
        true
    }

    #[cfg(not(test))]
    {
        let expected = std::env::var("FHE_OPERATOR_TOKEN").ok();
        let provided = request
            .headers
            .get("x-fhe-operator-token")
            .map(String::as_str);
        token_matches(expected.as_deref(), provided)
    }
}

fn audit_action(request: &HttpRequest) -> &'static str {
    match (request.method.as_str(), request.path.as_str()) {
        ("POST", "/v1/sessions") => "session_create",
        ("GET", "/v1/metrics") => "metrics_read",
        ("DELETE", _) => "session_delete",
        ("GET", _) => "session_read",
        ("POST", path) if path.ends_with("/encrypt") => "encrypt",
        ("POST", path) if path.ends_with("/decrypt") => "decrypt",
        ("POST", path) if path.ends_with("/evaluate") => "evaluate",
        _ => "unknown",
    }
}

fn audit_event(request: &HttpRequest, tenant_id: &str, status: u16) {
    #[cfg(not(test))]
    {
        let digest = Sha256::digest(tenant_id.as_bytes());
        let tenant_tag = digest[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        eprintln!(
            "audit ts={} tenant={} action={} status={}",
            crate::unix_now_seconds(),
            tenant_tag,
            audit_action(request),
            status
        );
    }
    #[cfg(test)]
    {
        let _ = (request, tenant_id, status);
    }
}

pub fn route(request: &HttpRequest, store: &SessionStore, metrics: &AppMetrics) -> HttpResponse {
    metrics.requests_total.fetch_add(1, Ordering::Relaxed);

    let public_response = match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/healthz") => Some(handle_healthz()),
        ("GET", "/v1/version") => Some(handle_version()),
        _ => None,
    };
    if let Some(response) = public_response {
        return response;
    }

    let access = match protected_access(request) {
        Ok(access) => access,
        Err(response) => {
            metrics.requests_failed.fetch_add(1, Ordering::Relaxed);
            return response;
        }
    };

    if !metrics.allow_request(&access.tenant_id) {
        metrics.requests_failed.fetch_add(1, Ordering::Relaxed);
        let response = error_response(429, "RATE_LIMITED", "request limit exceeded");
        audit_event(request, &access.tenant_id, response.status);
        return response;
    }

    let response = match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/v1/metrics") if operator_route_authorized(request) => {
            handle_metrics(store, metrics)
        }
        ("GET", "/v1/metrics") => error_response(404, "NOT_FOUND", "unknown endpoint"),
        ("POST", "/v1/sessions") => handle_create_session(request, &access.tenant_id, store),
        ("DELETE", path) if path.starts_with("/v1/sessions/") => {
            let id = &path["/v1/sessions/".len()..];
            handle_delete_session(id, &access.tenant_id, store)
        }
        ("GET", path) if path.starts_with("/v1/sessions/") => {
            let id = path["/v1/sessions/".len()..].trim_end_matches('/');
            if id.is_empty() || id.contains('/') {
                error_response(404, "NOT_FOUND", "unknown endpoint")
            } else {
                handle_get_session(id, &access.tenant_id, store)
            }
        }
        ("POST", path) if path.ends_with("/encrypt") => {
            let id = extract_session_id(path, "/encrypt");
            handle_encrypt(request, &id, &access.tenant_id, store)
        }
        ("POST", path) if path.ends_with("/decrypt") => {
            if decrypt_route_authorized(request) {
                let id = extract_session_id(path, "/decrypt");
                handle_decrypt(request, &id, &access.tenant_id, store)
            } else {
                error_response(404, "NOT_FOUND", "unknown endpoint")
            }
        }
        ("POST", path) if path.ends_with("/evaluate") => {
            let id = extract_session_id(path, "/evaluate");
            handle_evaluate(request, &id, &access.tenant_id, store)
        }
        _ => error_response(404, "NOT_FOUND", "unknown endpoint"),
    };

    if response.status >= 400 {
        metrics.requests_failed.fetch_add(1, Ordering::Relaxed);
    }
    audit_event(request, &access.tenant_id, response.status);
    response
}

/// Extract the session id between the fixed `/v1/sessions/` prefix and the
/// route's suffix (`/encrypt`, `/decrypt`, `/evaluate`).
///
/// Uses `strip_prefix`/`strip_suffix` rather than manual byte-index slicing:
/// the previous version only checked *lengths* (`without_suffix.len() >
/// prefix.len()`) and then sliced at a fixed byte offset regardless of
/// whether `path` actually started with the literal prefix. A path that
/// doesn't start with `/v1/sessions/` but is long enough (e.g. any path
/// containing a multi-byte UTF-8 character straddling byte offset 13) could
/// slice on a non-char-boundary and panic. `catch_unwind` in `main.rs` turns
/// that into a 500 rather than a crash, but this closes it at the source: a
/// non-matching path now cleanly yields an empty id (session lookup then
/// 404s), never a panic.
fn extract_session_id(path: &str, suffix: &str) -> String {
    const PREFIX: &str = "/v1/sessions/";
    path.strip_prefix(PREFIX)
        .and_then(|rest| rest.strip_suffix(suffix))
        .unwrap_or_default()
        .to_owned()
}

fn handle_healthz() -> HttpResponse {
    json_response(
        200,
        json!({
            "status": "ok",
            "service": "fhe-service",
            "timestamp_unix": crate::unix_now_seconds(),
        }),
    )
}

fn handle_version() -> HttpResponse {
    json_response(
        200,
        json!({
            "service": "fhe-service",
            "version": env!("CARGO_PKG_VERSION"),
            "supported_configs": ["secure_128", "secure_192", "secure_256"],
            "key_model": "server_keyholder",
            "ciphertext_format": "N65Qv001",
            "ciphertext_imports": "session-issued ciphertexts only",
            "evaluation_operations": ["add", "sub", "negate", "add_plain", "mul_plain", "mul"],
            "api_authentication": "required",
            "tenant_header": "x-fhe-tenant-id",
            "decrypt_endpoint": "disabled_by_default",
        }),
    )
}

fn handle_metrics(store: &SessionStore, metrics: &AppMetrics) -> HttpResponse {
    let uptime = crate::unix_now_seconds().saturating_sub(metrics.start_unix_seconds);
    let total = metrics.requests_total.load(Ordering::Relaxed);
    let failed = metrics.requests_failed.load(Ordering::Relaxed);
    let sessions = store.count();

    let body = format!(
        "# HELP fhe_requests_total Total requests\n\
         # TYPE fhe_requests_total counter\n\
         fhe_requests_total {total}\n\
         # HELP fhe_requests_failed_total Failed requests\n\
         # TYPE fhe_requests_failed_total counter\n\
         fhe_requests_failed_total {failed}\n\
         # HELP fhe_active_sessions Active FHE sessions\n\
         # TYPE fhe_active_sessions gauge\n\
         fhe_active_sessions {sessions}\n\
         # HELP fhe_uptime_seconds Service uptime\n\
         # TYPE fhe_uptime_seconds gauge\n\
         fhe_uptime_seconds {uptime}\n",
    );

    HttpResponse {
        status: 200,
        content_type: "text/plain; version=0.0.4",
        body: body.into_bytes(),
    }
}

fn handle_create_session(
    request: &HttpRequest,
    tenant_id: &str,
    store: &SessionStore,
) -> HttpResponse {
    let req: CreateSessionRequest = match serde_json::from_slice(&request.body) {
        Ok(request) => request,
        Err(_) => return error_response(400, "INVALID_PAYLOAD", "malformed JSON"),
    };
    if let Err(message) = req.validate() {
        return error_response(400, "INVALID_PAYLOAD", message);
    }
    let session = match crate::session::Session::new_for_tenant(&req.config, tenant_id) {
        Ok(session) => session,
        Err(message) => return error_response(400, "SESSION_CREATE_FAILED", message),
    };
    let response = CreateSessionResponse {
        session_id: session.session_id.clone(),
        config: session.config_name.clone(),
        params: session.params(),
        noise_budget_estimate_millibits: session.last_budget_millibits,
    };

    match store.insert(session) {
        Ok(_) => serde_json::to_value(&response).map_or_else(
            |_| error_response(500, "INTERNAL_ERROR", "serialization failure"),
            |value| json_response(201, value),
        ),
        Err(_) => error_response(429, "MAX_SESSIONS", "too many active sessions"),
    }
}

fn handle_get_session(id: &str, tenant_id: &str, store: &SessionStore) -> HttpResponse {
    match store.with_session_for_tenant(id, tenant_id, |session| SessionInfoResponse {
        session_id: session.session_id.clone(),
        config: session.config_name.clone(),
        noise_budget_estimate_millibits: session.last_budget_millibits,
        operation_count: session.operation_count,
        created_at: session.created_at,
    }) {
        Some(info) => serde_json::to_value(&info).map_or_else(
            |_| error_response(500, "INTERNAL_ERROR", "serialization failure"),
            |value| json_response(200, value),
        ),
        None => error_response(404, "SESSION_NOT_FOUND", "session does not exist"),
    }
}

fn handle_delete_session(id: &str, tenant_id: &str, store: &SessionStore) -> HttpResponse {
    if store.remove_for_tenant(id, tenant_id) {
        json_response(200, json!({"deleted": true}))
    } else {
        error_response(404, "SESSION_NOT_FOUND", "session does not exist")
    }
}

fn handle_encrypt(
    request: &HttpRequest,
    session_id: &str,
    tenant_id: &str,
    store: &SessionStore,
) -> HttpResponse {
    let req: EncryptRequest = match serde_json::from_slice(&request.body) {
        Ok(request) => request,
        Err(_) => return error_response(400, "INVALID_PAYLOAD", "malformed JSON"),
    };
    if let Err(message) = req.validate() {
        return error_response(400, "INVALID_PAYLOAD", message);
    }
    if req
        .values
        .len()
        .saturating_mul(MAX_ESTIMATED_CIPHERTEXT_RESPONSE_BYTES)
        > MAX_RESPONSE_BYTES
    {
        return error_response(413, "PAYLOAD_TOO_LARGE", "reduce batch count");
    }

    match store.with_session_mut_for_tenant(session_id, tenant_id, |session| {
        if req.values.iter().any(|&value| value >= session.config.t) {
            return Err(SessionError::InvalidInput);
        }
        session.require_capacity(req.values.len())?;
        let mut ciphertexts = Vec::with_capacity(req.values.len());
        for &value in &req.values {
            ciphertexts.push(session.evaluator.encrypt(value)?);
        }
        let ciphertexts = session.publish_batch(&ciphertexts)?;
        Ok(EncryptResponse {
            ciphertexts,
            noise_budget_estimate_millibits: session.last_budget_millibits,
        })
    }) {
        Some(Ok(response)) => serde_json::to_value(&response).map_or_else(
            |_| error_response(500, "INTERNAL_ERROR", "serialization failure"),
            |value| json_response(200, value),
        ),
        Some(Err(error)) => session_error_response("ENCRYPT_FAILED", error),
        None => error_response(404, "SESSION_NOT_FOUND", "session does not exist"),
    }
}

fn handle_decrypt(
    request: &HttpRequest,
    session_id: &str,
    tenant_id: &str,
    store: &SessionStore,
) -> HttpResponse {
    let req: DecryptRequest = match serde_json::from_slice(&request.body) {
        Ok(request) => request,
        Err(_) => return error_response(400, "INVALID_PAYLOAD", "malformed JSON"),
    };
    if let Err(message) = req.validate() {
        return error_response(400, "INVALID_PAYLOAD", message);
    }
    if req.ciphertexts.len().saturating_mul(20) > MAX_RESPONSE_BYTES {
        return error_response(413, "PAYLOAD_TOO_LARGE", "reduce batch count");
    }

    match store.with_session_mut_for_tenant(session_id, tenant_id, |session| {
        let mut ciphertexts = Vec::with_capacity(req.ciphertexts.len());
        for encoded in &req.ciphertexts {
            ciphertexts.push(session.ct_from_b64(encoded)?);
        }
        let mut values = Vec::with_capacity(req.ciphertexts.len());
        for ciphertext in &ciphertexts {
            values.push(
                session
                    .client
                    .decrypt(ciphertext)
                    .map_err(SessionError::from)?,
            );
        }
        session.operation_count += req.ciphertexts.len() as u64;
        Ok::<DecryptResponse, SessionError>(DecryptResponse {
            values,
            noise_budget_estimate_millibits: session.last_budget_millibits,
        })
    }) {
        Some(Ok(response)) => serde_json::to_value(&response).map_or_else(
            |_| error_response(500, "INTERNAL_ERROR", "serialization failure"),
            |value| json_response(200, value),
        ),
        Some(Err(error)) => session_error_response("DECRYPT_FAILED", error),
        None => error_response(404, "SESSION_NOT_FOUND", "session does not exist"),
    }
}

fn handle_evaluate(
    request: &HttpRequest,
    session_id: &str,
    tenant_id: &str,
    store: &SessionStore,
) -> HttpResponse {
    let req: EvaluateRequest = match serde_json::from_slice(&request.body) {
        Ok(request) => request,
        Err(_) => return error_response(400, "INVALID_PAYLOAD", "malformed JSON"),
    };
    if let Err(message) = req.validate() {
        return error_response(400, "INVALID_PAYLOAD", message);
    }
    if req
        .operations
        .len()
        .saturating_mul(MAX_ESTIMATED_CIPHERTEXT_RESPONSE_BYTES)
        > MAX_RESPONSE_BYTES
    {
        return error_response(413, "PAYLOAD_TOO_LARGE", "reduce operation count");
    }
    match store.with_session_mut_for_tenant(session_id, tenant_id, |session| {
        session.require_capacity(req.operations.len())?;
        let mut results: Vec<CramMainCiphertext> = Vec::with_capacity(req.operations.len());
        for operation in &req.operations {
            let mut ciphertexts = Vec::with_capacity(operation.inputs.len());
            for encoded in &operation.inputs {
                ciphertexts.push(session.ct_from_b64(encoded)?);
            }

            let result = match operation.op.as_str() {
                "add" => {
                    if ciphertexts.len() != 2 {
                        return Err(SessionError::InvalidInput);
                    }
                    session.evaluator.add(&ciphertexts[0], &ciphertexts[1])?
                }
                "sub" => {
                    if ciphertexts.len() != 2 {
                        return Err(SessionError::InvalidInput);
                    }
                    session.evaluator.sub(&ciphertexts[0], &ciphertexts[1])?
                }
                "negate" => {
                    if ciphertexts.len() != 1 {
                        return Err(SessionError::InvalidInput);
                    }
                    session.evaluator.negate(&ciphertexts[0])?
                }
                "add_plain" => {
                    if ciphertexts.len() != 1 {
                        return Err(SessionError::InvalidInput);
                    }
                    let scalar = operation.scalar.ok_or(SessionError::InvalidInput)?;
                    session.evaluator.add_plain(&ciphertexts[0], scalar)?
                }
                "mul_plain" => {
                    if ciphertexts.len() != 1 {
                        return Err(SessionError::InvalidInput);
                    }
                    let scalar = operation.scalar.ok_or(SessionError::InvalidInput)?;
                    session.evaluator.mul_plain(&ciphertexts[0], scalar)?
                }
                "mul" => {
                    if ciphertexts.len() != 2 {
                        return Err(SessionError::InvalidInput);
                    }
                    session
                        .evaluator
                        .multiply(&ciphertexts[0], &ciphertexts[1])?
                }
                _ => return Err(SessionError::InvalidInput),
            };

            results.push(result);
        }

        let results = session.publish_batch(&results)?;
        Ok(EvaluateResponse {
            results,
            noise_budget_estimate_millibits: session.last_budget_millibits,
            operation_count: session.operation_count,
        })
    }) {
        Some(Ok(response)) => serde_json::to_value(&response).map_or_else(
            |_| error_response(500, "INTERNAL_ERROR", "serialization failure"),
            |value| json_response(200, value),
        ),
        Some(Err(error)) => session_error_response("EVALUATE_FAILED", error),
        None => error_response(404, "SESSION_NOT_FOUND", "session does not exist"),
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    #[test]
    fn token_policy_is_fail_closed() {
        assert!(!token_matches(None, Some("token")));
        assert!(!token_matches(Some(""), Some("")));
        assert!(!token_matches(Some("token"), None));
        assert!(!token_matches(Some("expected"), Some("different")));
        assert!(token_matches(Some("expected"), Some("expected")));
    }

    #[test]
    fn tenant_id_policy_is_bounded_and_ascii() {
        assert!(valid_tenant_id("tenant-01"));
        assert!(!valid_tenant_id(""));
        assert!(!valid_tenant_id("tenant/01"));
        assert!(!valid_tenant_id(&"x".repeat(65)));
    }

    #[test]
    fn decrypt_policy_is_fail_closed() {
        assert!(!decrypt_authorized_with(
            false,
            Some("token"),
            Some("token")
        ));
        assert!(!decrypt_authorized_with(true, None, Some("token")));
        assert!(!decrypt_authorized_with(true, Some("token"), None));
        assert!(!decrypt_authorized_with(
            true,
            Some("expected"),
            Some("different")
        ));
        assert!(decrypt_authorized_with(
            true,
            Some("operator-secret"),
            Some("operator-secret")
        ));
    }

    #[test]
    fn rate_limit_allows_up_to_the_limit_then_blocks_until_the_next_minute() {
        let mut window = RateWindow {
            minute: 100,
            requests: 0,
        };
        assert!(rate_limit_allows(&mut window, 100, 2));
        assert!(rate_limit_allows(&mut window, 100, 2));
        assert!(!rate_limit_allows(&mut window, 100, 2));
        // A new minute resets the window rather than carrying the block over.
        assert!(rate_limit_allows(&mut window, 101, 2));
    }

    #[test]
    fn rate_limiter_state_starts_empty_at_the_documented_default() {
        let metrics = AppMetrics::new();
        assert!(metrics
            .rate_windows
            .lock()
            .expect("rate_windows lock")
            .is_empty());
    }

    #[test]
    fn audit_action_labels_every_route() {
        let request = |method: &str, path: &str| HttpRequest {
            method: method.to_string(),
            path: path.to_string(),
            headers: HashMap::new(),
            body: Vec::new(),
        };
        assert_eq!(
            audit_action(&request("POST", "/v1/sessions")),
            "session_create"
        );
        assert_eq!(audit_action(&request("GET", "/v1/metrics")), "metrics_read");
        assert_eq!(
            audit_action(&request("DELETE", "/v1/sessions/abc")),
            "session_delete"
        );
        assert_eq!(
            audit_action(&request("GET", "/v1/sessions/abc")),
            "session_read"
        );
        assert_eq!(
            audit_action(&request("POST", "/v1/sessions/abc/encrypt")),
            "encrypt"
        );
        assert_eq!(
            audit_action(&request("POST", "/v1/sessions/abc/decrypt")),
            "decrypt"
        );
        assert_eq!(
            audit_action(&request("POST", "/v1/sessions/abc/evaluate")),
            "evaluate"
        );
        assert_eq!(audit_action(&request("PATCH", "/unknown")), "unknown");
    }
}
