//! Request handlers and service-boundary policy.

use crate::http::{error_response, json_response, HttpRequest, HttpResponse, MAX_RESPONSE_BYTES};
use crate::session::SessionStore;
use crate::wire::{
    CreateSessionRequest, CreateSessionResponse, DecryptRequest, DecryptResponse, EncryptRequest,
    EncryptResponse, EvaluateRequest, EvaluateResponse, SessionInfoResponse,
};

use nine65::noise::budget::{NoiseBudget, NoiseOpType};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use subtle::ConstantTimeEq;

const DEFAULT_RATE_LIMIT_PER_MINUTE: u64 = 120;

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
    }
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
        noise_budget_estimate_millibits: session.noise_budget.remaining_millibits(),
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
        noise_budget_estimate_millibits: session.noise_budget.remaining_millibits(),
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

    let estimated_ct_size = 4 * 1024 * 1024;
    if req.values.len().saturating_mul(estimated_ct_size) > MAX_RESPONSE_BYTES {
        return error_response(413, "PAYLOAD_TOO_LARGE", "reduce batch count");
    }

    match store.with_session_mut_for_tenant(session_id, tenant_id, |session| {
        let mut ciphertexts = Vec::with_capacity(req.values.len());
        for &value in &req.values {
            if value >= session.config.t {
                return Err("invalid value".to_owned());
            }
            session
                .noise_budget
                .consume(
                    NoiseOpType::Encrypt,
                    NoiseBudget::encrypt_cost(&session.config),
                )
                .map_err(|error| format!("noise exhausted: {error}"))?;
            let ciphertext = session
                .rns_ctx
                .encrypt_dual_secure(value, &session.dual_keys.public_key);
            ciphertexts.push(session.dual_ct_to_b64(&ciphertext)?);
        }
        session.operation_count += req.values.len() as u64;
        Ok(EncryptResponse {
            ciphertexts,
            noise_budget_estimate_millibits: session.noise_budget.remaining_millibits(),
        })
    }) {
        Some(Ok(response)) => serde_json::to_value(&response).map_or_else(
            |_| error_response(500, "INTERNAL_ERROR", "serialization failure"),
            |value| json_response(200, value),
        ),
        Some(Err(_)) => error_response(400, "ENCRYPT_FAILED", "operation failed"),
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
        let mut values = Vec::with_capacity(req.ciphertexts.len());
        for encoded in &req.ciphertexts {
            let ciphertext = session.dual_ct_from_b64(encoded)?;
            values.push(
                session
                    .rns_ctx
                    .decrypt_dual(&ciphertext, &session.dual_keys.secret_key),
            );
        }
        session.operation_count += req.ciphertexts.len() as u64;
        Ok::<DecryptResponse, String>(DecryptResponse {
            values,
            noise_budget_estimate_millibits: session.noise_budget.remaining_millibits(),
        })
    }) {
        Some(Ok(response)) => serde_json::to_value(&response).map_or_else(
            |_| error_response(500, "INTERNAL_ERROR", "serialization failure"),
            |value| json_response(200, value),
        ),
        Some(Err(_)) => error_response(400, "DECRYPT_FAILED", "operation failed"),
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
    let estimated_ct_size = 4 * 1024 * 1024;
    if req.operations.len().saturating_mul(estimated_ct_size) > MAX_RESPONSE_BYTES {
        return error_response(413, "PAYLOAD_TOO_LARGE", "reduce batch count");
    }

    match store.with_session_mut_for_tenant(session_id, tenant_id, |session| {
        let mut results = Vec::with_capacity(req.operations.len());
        for operation in &req.operations {
            let mut ciphertexts = Vec::with_capacity(operation.inputs.len());
            for encoded in &operation.inputs {
                ciphertexts.push(session.dual_ct_from_b64(encoded)?);
            }

            let result = match operation.op.as_str() {
                "add" => {
                    if ciphertexts.len() != 2 {
                        return Err("add requires two inputs".to_owned());
                    }
                    session
                        .noise_budget
                        .consume(NoiseOpType::Add, NoiseBudget::add_cost())
                        .map_err(|error| format!("noise exhausted: {error}"))?;
                    session.rns_ctx.add_dual(&ciphertexts[0], &ciphertexts[1])
                }
                "sub" => {
                    if ciphertexts.len() != 2 {
                        return Err("sub requires two inputs".to_owned());
                    }
                    session
                        .noise_budget
                        .consume(NoiseOpType::Add, NoiseBudget::add_cost())
                        .map_err(|error| format!("noise exhausted: {error}"))?;
                    session.rns_ctx.sub_dual(&ciphertexts[0], &ciphertexts[1])
                }
                "negate" => {
                    if ciphertexts.len() != 1 {
                        return Err("negate requires one input".to_owned());
                    }
                    session
                        .noise_budget
                        .consume(NoiseOpType::Add, NoiseBudget::add_cost())
                        .map_err(|error| format!("noise exhausted: {error}"))?;
                    session.rns_ctx.negate_dual(&ciphertexts[0])
                }
                "add_plain" => {
                    if ciphertexts.len() != 1 {
                        return Err("add_plain requires one input".to_owned());
                    }
                    let scalar = operation
                        .scalar
                        .ok_or_else(|| "add_plain requires scalar".to_owned())?;
                    if scalar >= session.config.t {
                        return Err("invalid scalar".to_owned());
                    }
                    session
                        .noise_budget
                        .consume(NoiseOpType::AddPlain, NoiseBudget::add_plain_cost())
                        .map_err(|error| format!("noise exhausted: {error}"))?;
                    session.rns_ctx.add_plain_dual(&ciphertexts[0], scalar)
                }
                "mul_plain" => {
                    if ciphertexts.len() != 1 {
                        return Err("mul_plain requires one input".to_owned());
                    }
                    let scalar = operation
                        .scalar
                        .ok_or_else(|| "mul_plain requires scalar".to_owned())?;
                    if scalar >= session.config.t {
                        return Err("invalid scalar".to_owned());
                    }
                    session
                        .noise_budget
                        // `mul_plain_scalar_cost`, not `mul_plain_cost`:
                        // `mul_plain_dual` builds its multiplier with
                        // `scalar_to_constant_dual_poly`, a degree-0 polynomial,
                        // so no ring expansion occurs and the `n` factor would
                        // over-charge by log2(n) — 13 bits at n=8192. See
                        // `NoiseBudget::mul_plain_scalar_cost`.
                        .consume(
                            NoiseOpType::MulPlain,
                            NoiseBudget::mul_plain_scalar_cost(scalar),
                        )
                        .map_err(|error| format!("noise exhausted: {error}"))?;
                    session.rns_ctx.mul_plain_dual(&ciphertexts[0], scalar)
                }
                "mul" => {
                    if ciphertexts.len() != 2 {
                        return Err("mul requires two inputs".to_owned());
                    }
                    session
                        .noise_budget
                        .consume(
                            NoiseOpType::MulCt,
                            NoiseBudget::mul_ct_cost(&session.config),
                        )
                        .map_err(|error| format!("noise exhausted: {error}"))?;
                    session
                        .noise_budget
                        .consume(NoiseOpType::Relin, NoiseBudget::relin_cost(&session.config))
                        .map_err(|error| format!("noise exhausted: {error}"))?;
                    // No `NoiseBudget::rescale_cost` here, deliberately.
                    //
                    // That credit belongs to an RNS prime drop. `mul_dual_public`
                    // rescales the tensor product by `Delta = M_level / t` and
                    // consumes no level, and that division is already inside
                    // `mul_ct_cost` (the FV Lemma-2 bound is stated *after* the
                    // rescaling). Charging both credited the same division twice
                    // and under-charged this untrusted-caller-facing path by
                    // ~16 bits per multiply. See `NoiseBudget::rescale_cost`.
                    session
                        .rns_ctx
                        .mul_dual_public(
                            &ciphertexts[0],
                            &ciphertexts[1],
                            &session.dual_keys.eval_key,
                        )
                        .map_err(|error| format!("mul failed: {error}"))?
                }
                _ => return Err("unknown operation".to_owned()),
            };

            results.push(session.dual_ct_to_b64(&result)?);
            session.operation_count += 1;
        }

        Ok(EvaluateResponse {
            results,
            noise_budget_estimate_millibits: session.noise_budget.remaining_millibits(),
            operation_count: session.operation_count,
        })
    }) {
        Some(Ok(response)) => serde_json::to_value(&response).map_or_else(
            |_| error_response(500, "INTERNAL_ERROR", "serialization failure"),
            |value| json_response(200, value),
        ),
        Some(Err(_)) => error_response(400, "EVALUATE_FAILED", "operation failed"),
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
}
