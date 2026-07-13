//! Request handlers — endpoint logic for FHE operations.
//!
//! All FHE computation happens here. Ciphertexts are deserialized, validated,
//! operated on via tracked exact-integer paths, and serialized back.

use crate::http::{error_response, json_response, HttpRequest, HttpResponse, MAX_RESPONSE_BYTES};
use crate::session::SessionStore;
use crate::wire::{
    CreateSessionRequest, CreateSessionResponse, DecryptRequest, DecryptResponse, EncryptRequest,
    EncryptResponse, EvaluateRequest, EvaluateResponse, SessionInfoResponse,
};

use nine65::noise::budget::{NoiseBudget, NoiseOpType};
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use subtle::ConstantTimeEq;

pub struct AppMetrics {
    pub start_unix_seconds: u64,
    pub requests_total: AtomicU64,
    pub requests_failed: AtomicU64,
}

impl AppMetrics {
    pub fn new() -> Self {
        Self {
            start_unix_seconds: crate::unix_now_seconds(),
            requests_total: AtomicU64::new(0),
            requests_failed: AtomicU64::new(0),
        }
    }
}

/// Pure policy function used by the production route and unit tests.
/// Both explicit enablement and a configured matching token are mandatory.
fn decrypt_authorized_with(
    enabled: bool,
    expected_token: Option<&str>,
    provided_token: Option<&str>,
) -> bool {
    if !enabled {
        return false;
    }
    let Some(expected) = expected_token.filter(|token| !token.is_empty()) else {
        return false;
    };
    let Some(provided) = provided_token else {
        return false;
    };
    bool::from(provided.as_bytes().ct_eq(expected.as_bytes()))
}

fn decrypt_route_authorized(request: &HttpRequest) -> bool {
    // Existing unit tests exercise encrypt/decrypt round trips inside the process.
    // Production builds always use the fail-closed environment/header policy.
    #[cfg(test)]
    {
        let _ = request;
        true
    }

    #[cfg(not(test))]
    {
        let enabled = std::env::var("FHE_ENABLE_DECRYPT")
            .ok()
            .as_deref()
            == Some("1");
        let expected = std::env::var("FHE_DECRYPT_TOKEN").ok();
        let provided = request
            .headers
            .get("x-fhe-decrypt-token")
            .map(String::as_str);
        decrypt_authorized_with(enabled, expected.as_deref(), provided)
    }
}

/// Route request to the appropriate handler.
pub fn route(request: &HttpRequest, store: &SessionStore, metrics: &AppMetrics) -> HttpResponse {
    metrics.requests_total.fetch_add(1, Ordering::Relaxed);

    let result = match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/healthz") => handle_healthz(store),
        ("GET", "/v1/version") => handle_version(),
        ("GET", "/v1/metrics") => handle_metrics(store, metrics),
        ("POST", "/v1/sessions") => handle_create_session(request, store),
        ("DELETE", path) if path.starts_with("/v1/sessions/") => {
            let id = &path["/v1/sessions/".len()..];
            handle_delete_session(id, store)
        }
        ("GET", path) if path.starts_with("/v1/sessions/") && !path.contains("/encrypt") => {
            let id = path["/v1/sessions/".len()..].trim_end_matches('/');
            if id.contains('/') {
                error_response(404, "NOT_FOUND", "unknown endpoint")
            } else {
                handle_get_session(id, store)
            }
        }
        ("POST", path) if path.ends_with("/encrypt") => {
            let id = extract_session_id(path, "/encrypt");
            handle_encrypt(request, &id, store)
        }
        ("POST", path) if path.ends_with("/decrypt") => {
            if decrypt_route_authorized(request) {
                let id = extract_session_id(path, "/decrypt");
                handle_decrypt(request, &id, store)
            } else {
                // Conceal the existence of the oracle when operator policy is absent.
                error_response(404, "NOT_FOUND", "unknown endpoint")
            }
        }
        ("POST", path) if path.ends_with("/evaluate") => {
            let id = extract_session_id(path, "/evaluate");
            handle_evaluate(request, &id, store)
        }
        _ => error_response(404, "NOT_FOUND", "unknown endpoint"),
    };

    if result.status >= 400 {
        metrics.requests_failed.fetch_add(1, Ordering::Relaxed);
    }

    result
}

fn extract_session_id(path: &str, suffix: &str) -> String {
    let without_suffix = &path[..path.len() - suffix.len()];
    let prefix = "/v1/sessions/";
    if without_suffix.len() > prefix.len() {
        without_suffix[prefix.len()..].to_owned()
    } else {
        String::new()
    }
}

fn handle_healthz(store: &SessionStore) -> HttpResponse {
    json_response(
        200,
        json!({
            "status": "ok",
            "service": "fhe-service",
            "active_sessions": store.count(),
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

fn handle_create_session(request: &HttpRequest, store: &SessionStore) -> HttpResponse {
    let req: CreateSessionRequest = match serde_json::from_slice(&request.body) {
        Ok(r) => r,
        Err(_) => return error_response(400, "INVALID_PAYLOAD", "malformed JSON"),
    };

    if let Err(msg) = req.validate() {
        return error_response(400, "INVALID_PAYLOAD", msg);
    }

    let session = match crate::session::Session::new(&req.config) {
        Ok(s) => s,
        Err(msg) => return error_response(400, "SESSION_CREATE_FAILED", msg),
    };

    let resp = CreateSessionResponse {
        session_id: session.session_id.clone(),
        config: session.config_name.clone(),
        params: session.params(),
        noise_budget_estimate_millibits: session.noise_budget.remaining_millibits(),
    };

    match store.insert(session) {
        Ok(_) => match serde_json::to_value(&resp) {
            Ok(v) => json_response(201, v),
            Err(_) => error_response(500, "INTERNAL_ERROR", "serialization failure"),
        },
        Err(_) => error_response(429, "MAX_SESSIONS", "too many active sessions"),
    }
}

fn handle_get_session(id: &str, store: &SessionStore) -> HttpResponse {
    match store.with_session(id, |s| SessionInfoResponse {
        session_id: s.session_id.clone(),
        config: s.config_name.clone(),
        noise_budget_estimate_millibits: s.noise_budget.remaining_millibits(),
        operation_count: s.operation_count,
        created_at: s.created_at,
    }) {
        Some(info) => match serde_json::to_value(&info) {
            Ok(v) => json_response(200, v),
            Err(_) => error_response(500, "INTERNAL_ERROR", "serialization failure"),
        },
        None => error_response(404, "SESSION_NOT_FOUND", "session does not exist"),
    }
}

fn handle_delete_session(id: &str, store: &SessionStore) -> HttpResponse {
    if store.remove(id) {
        json_response(200, json!({"deleted": true}))
    } else {
        error_response(404, "SESSION_NOT_FOUND", "session does not exist")
    }
}

fn handle_encrypt(request: &HttpRequest, session_id: &str, store: &SessionStore) -> HttpResponse {
    let req: EncryptRequest = match serde_json::from_slice(&request.body) {
        Ok(r) => r,
        Err(_) => return error_response(400, "INVALID_PAYLOAD", "malformed JSON"),
    };

    if let Err(msg) = req.validate() {
        return error_response(400, "INVALID_PAYLOAD", msg);
    }

    let estimated_ct_size = 4 * 1024 * 1024;
    let estimated_response_size = req.values.len() * estimated_ct_size;
    if estimated_response_size > MAX_RESPONSE_BYTES {
        return error_response(
            413,
            "PAYLOAD_TOO_LARGE",
            "estimated response size would exceed maximum response size; reduce batch count",
        );
    }

    match store.with_session_mut(session_id, |session| {
        let mut ciphertexts = Vec::with_capacity(req.values.len());
        for &v in &req.values {
            if v >= session.config.t {
                return Err("invalid value".to_owned());
            }
            #[cfg(feature = "exact_rational")]
            {
                let safe_margin = 100_u64;
                if v > session.config.t.saturating_sub(safe_margin) && v < session.config.t {
                    return Err("invalid value".to_owned());
                }
            }
            session
                .noise_budget
                .consume(
                    NoiseOpType::Encrypt,
                    NoiseBudget::encrypt_cost(&session.config),
                )
                .map_err(|e| format!("noise exhausted: {e}"))?;
            let ct = session
                .rns_ctx
                .encrypt_dual_secure(v, &session.dual_keys.public_key);
            ciphertexts.push(session.dual_ct_to_b64(&ct)?);
        }

        session.operation_count += req.values.len() as u64;
        Ok(EncryptResponse {
            ciphertexts,
            noise_budget_estimate_millibits: session.noise_budget.remaining_millibits(),
        })
    }) {
        Some(Ok(resp)) => match serde_json::to_value(&resp) {
            Ok(v) => json_response(200, v),
            Err(_) => error_response(500, "INTERNAL_ERROR", "serialization failure"),
        },
        Some(Err(msg)) => error_response(400, "ENCRYPT_FAILED", &msg),
        None => error_response(404, "SESSION_NOT_FOUND", "session does not exist"),
    }
}

fn handle_decrypt(request: &HttpRequest, session_id: &str, store: &SessionStore) -> HttpResponse {
    let req: DecryptRequest = match serde_json::from_slice(&request.body) {
        Ok(r) => r,
        Err(_) => return error_response(400, "INVALID_PAYLOAD", "malformed JSON"),
    };

    if let Err(msg) = req.validate() {
        return error_response(400, "INVALID_PAYLOAD", msg);
    }

    let estimated_response_size = req.ciphertexts.len() * 20;
    if estimated_response_size > MAX_RESPONSE_BYTES {
        return error_response(
            413,
            "PAYLOAD_TOO_LARGE",
            "estimated response size would exceed maximum response size; reduce batch count",
        );
    }

    match store.with_session_mut(session_id, |session| -> Result<DecryptResponse, String> {
        let mut values = Vec::with_capacity(req.ciphertexts.len());
        for ct_b64 in &req.ciphertexts {
            let ct = session.dual_ct_from_b64(ct_b64)?;
            values.push(
                session
                    .rns_ctx
                    .decrypt_dual(&ct, &session.dual_keys.secret_key),
            );
        }
        session.operation_count += req.ciphertexts.len() as u64;
        Ok(DecryptResponse {
            values,
            noise_budget_estimate_millibits: session.noise_budget.remaining_millibits(),
        })
    }) {
        Some(Ok(resp)) => match serde_json::to_value(&resp) {
            Ok(v) => json_response(200, v),
            Err(_) => error_response(500, "INTERNAL_ERROR", "serialization failure"),
        },
        Some(Err(msg)) => {
            eprintln!("decrypt operation failed: {msg}");
            error_response(400, "DECRYPT_FAILED", "operation failed")
        }
        None => error_response(404, "SESSION_NOT_FOUND", "session does not exist"),
    }
}

fn handle_evaluate(request: &HttpRequest, session_id: &str, store: &SessionStore) -> HttpResponse {
    let req: EvaluateRequest = match serde_json::from_slice(&request.body) {
        Ok(r) => r,
        Err(_) => return error_response(400, "INVALID_PAYLOAD", "malformed JSON"),
    };

    if let Err(msg) = req.validate() {
        return error_response(400, "INVALID_PAYLOAD", msg);
    }

    let estimated_ct_size = 4 * 1024 * 1024;
    let estimated_response_size = req.operations.len() * estimated_ct_size;
    if estimated_response_size > MAX_RESPONSE_BYTES {
        return error_response(
            413,
            "PAYLOAD_TOO_LARGE",
            "estimated response size would exceed maximum response size; reduce batch count",
        );
    }

    match store.with_session_mut(session_id, |session| {
        let mut results = Vec::with_capacity(req.operations.len());

        for op in &req.operations {
            let mut cts = Vec::with_capacity(op.inputs.len());
            for input_b64 in &op.inputs {
                cts.push(session.dual_ct_from_b64(input_b64)?);
            }

            let result_ct = match op.op.as_str() {
                "add" => {
                    if cts.len() != 2 {
                        return Err("add requires exactly 2 inputs".to_owned());
                    }
                    session
                        .noise_budget
                        .consume(NoiseOpType::Add, NoiseBudget::add_cost())
                        .map_err(|e| format!("noise exhausted: {e}"))?;
                    session.rns_ctx.add_dual(&cts[0], &cts[1])
                }
                "sub" => {
                    if cts.len() != 2 {
                        return Err("sub requires exactly 2 inputs".to_owned());
                    }
                    session
                        .noise_budget
                        .consume(NoiseOpType::Add, NoiseBudget::add_cost())
                        .map_err(|e| format!("noise exhausted: {e}"))?;
                    session.rns_ctx.sub_dual(&cts[0], &cts[1])
                }
                "negate" => {
                    if cts.len() != 1 {
                        return Err("negate requires exactly 1 input".to_owned());
                    }
                    session
                        .noise_budget
                        .consume(NoiseOpType::Add, NoiseBudget::add_cost())
                        .map_err(|e| format!("noise exhausted: {e}"))?;
                    session.rns_ctx.negate_dual(&cts[0])
                }
                "add_plain" => {
                    if cts.len() != 1 {
                        return Err("add_plain requires exactly 1 input".to_owned());
                    }
                    let scalar = op
                        .scalar
                        .ok_or_else(|| "add_plain requires scalar".to_owned())?;
                    if scalar >= session.config.t {
                        return Err("invalid scalar".to_owned());
                    }
                    session
                        .noise_budget
                        .consume(NoiseOpType::AddPlain, NoiseBudget::add_plain_cost())
                        .map_err(|e| format!("noise exhausted: {e}"))?;
                    session.rns_ctx.add_plain_dual(&cts[0], scalar)
                }
                "mul_plain" => {
                    if cts.len() != 1 {
                        return Err("mul_plain requires exactly 1 input".to_owned());
                    }
                    let scalar = op
                        .scalar
                        .ok_or_else(|| "mul_plain requires scalar".to_owned())?;
                    if scalar >= session.config.t {
                        return Err("invalid scalar".to_owned());
                    }
                    session
                        .noise_budget
                        .consume(
                            NoiseOpType::MulPlain,
                            NoiseBudget::mul_plain_cost(&session.config),
                        )
                        .map_err(|e| format!("noise exhausted: {e}"))?;
                    session.rns_ctx.mul_plain_dual(&cts[0], scalar)
                }
                "mul" => {
                    if cts.len() != 2 {
                        return Err("mul requires exactly 2 inputs".to_owned());
                    }
                    session
                        .noise_budget
                        .consume(
                            NoiseOpType::MulCt,
                            NoiseBudget::mul_ct_cost(&session.config),
                        )
                        .map_err(|e| format!("noise exhausted: {e}"))?;
                    session
                        .noise_budget
                        .consume(NoiseOpType::Relin, NoiseBudget::relin_cost(&session.config))
                        .map_err(|e| format!("noise exhausted: {e}"))?;
                    session
                        .noise_budget
                        .consume(
                            NoiseOpType::Rescale,
                            NoiseBudget::rescale_cost(&session.config),
                        )
                        .map_err(|e| format!("noise exhausted: {e}"))?;
                    session
                        .rns_ctx
                        .mul_dual_public(&cts[0], &cts[1], &session.dual_keys.eval_key)
                        .map_err(|e| format!("mul failed: {e}"))?
                }
                other => return Err(format!("unknown operation: {other}")),
            };

            results.push(session.dual_ct_to_b64(&result_ct)?);
            session.operation_count += 1;
        }

        Ok(EvaluateResponse {
            results,
            noise_budget_estimate_millibits: session.noise_budget.remaining_millibits(),
            operation_count: session.operation_count,
        })
    }) {
        Some(Ok(resp)) => match serde_json::to_value(&resp) {
            Ok(v) => json_response(200, v),
            Err(_) => error_response(500, "INTERNAL_ERROR", "serialization failure"),
        },
        Some(Err(msg)) => {
            eprintln!("evaluate operation failed: {msg}");
            error_response(400, "EVALUATE_FAILED", "operation failed")
        }
        None => error_response(404, "SESSION_NOT_FOUND", "session does not exist"),
    }
}

#[cfg(test)]
mod policy_tests {
    use super::decrypt_authorized_with;

    #[test]
    fn decrypt_policy_is_fail_closed() {
        assert!(!decrypt_authorized_with(false, Some("token"), Some("token")));
        assert!(!decrypt_authorized_with(true, None, Some("token")));
        assert!(!decrypt_authorized_with(true, Some(""), Some("")));
        assert!(!decrypt_authorized_with(true, Some("token"), None));
        assert!(!decrypt_authorized_with(
            true,
            Some("expected"),
            Some("different")
        ));
    }

    #[test]
    fn decrypt_policy_accepts_only_exact_token() {
        assert!(decrypt_authorized_with(
            true,
            Some("operator-secret"),
            Some("operator-secret")
        ));
    }
}
