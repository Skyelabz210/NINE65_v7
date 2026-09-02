//! Tenant-bound ingress authentication.
//!
//! External callers present a tenant-specific token. After validation, the
//! request token is replaced with an internal router token that is never shared
//! with tenants. This keeps the handler policy fail-closed while cryptographically
//! binding the claimed tenant identifier to its configured credential.

use crate::http::{error_response, HttpRequest, HttpResponse};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const TENANT_HEADER: &str = "x-fhe-tenant-id";
const API_TOKEN_HEADER: &str = "x-fhe-api-token";

fn token_matches(expected: &str, provided: &str) -> bool {
    if expected.is_empty() || provided.is_empty() {
        return false;
    }
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

/// Resolve exactly one tenant token from a semicolon-separated mapping:
/// `tenant-a=secret-a;tenant-b=secret-b`.
///
/// Malformed entries, empty values, or duplicate tenant entries fail closed.
fn token_for_tenant<'a>(mapping: &'a str, tenant_id: &str) -> Option<&'a str> {
    let mut matched = None;
    for entry in mapping.split(';').filter(|entry| !entry.is_empty()) {
        let (configured_tenant, token) = entry.split_once('=')?;
        if !valid_tenant_id(configured_tenant) || token.is_empty() {
            return None;
        }
        if configured_tenant == tenant_id {
            if matched.is_some() {
                return None;
            }
            matched = Some(token);
        }
    }
    matched
}

fn is_public_route(request: &HttpRequest) -> bool {
    request.method == "GET" && matches!(request.path.as_str(), "/healthz" | "/v1/version")
}

/// Authenticate a tenant at the network ingress and normalize the request for
/// the internal handler policy.
pub fn authorize_and_normalize(request: &mut HttpRequest) -> Result<(), HttpResponse> {
    if is_public_route(request) {
        return Ok(());
    }

    let tenant_id = request
        .headers
        .get(TENANT_HEADER)
        .ok_or_else(|| error_response(400, "TENANT_REQUIRED", "tenant id required"))?;
    if !valid_tenant_id(tenant_id) {
        return Err(error_response(400, "INVALID_TENANT", "invalid tenant id"));
    }

    let provided = request
        .headers
        .get(API_TOKEN_HEADER)
        .ok_or_else(|| error_response(401, "UNAUTHORIZED", "authentication required"))?;
    let mapping = std::env::var("FHE_TENANT_TOKENS")
        .map_err(|_| error_response(503, "AUTH_NOT_CONFIGURED", "service unavailable"))?;
    let expected = token_for_tenant(&mapping, tenant_id)
        .ok_or_else(|| error_response(401, "UNAUTHORIZED", "authentication required"))?;
    if !token_matches(expected, provided) {
        return Err(error_response(
            401,
            "UNAUTHORIZED",
            "authentication required",
        ));
    }

    let internal = std::env::var("FHE_API_TOKEN")
        .ok()
        .filter(|token| !token.is_empty())
        .ok_or_else(|| error_response(503, "AUTH_NOT_CONFIGURED", "service unavailable"))?;
    request
        .headers
        .insert(API_TOKEN_HEADER.to_string(), internal);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_mapping_is_exact_and_duplicate_safe() {
        let mapping = "tenant-a=alpha;tenant-b=beta";
        assert_eq!(token_for_tenant(mapping, "tenant-a"), Some("alpha"));
        assert_eq!(token_for_tenant(mapping, "tenant-b"), Some("beta"));
        assert_eq!(token_for_tenant(mapping, "tenant-c"), None);
        assert_eq!(token_for_tenant("tenant-a=x;tenant-a=y", "tenant-a"), None);
        assert_eq!(token_for_tenant("tenant/a=x", "tenant/a"), None);
    }

    #[test]
    fn digest_comparison_is_exact() {
        assert!(token_matches("alpha", "alpha"));
        assert!(!token_matches("alpha", "alph"));
        assert!(!token_matches("alpha", "beta"));
        assert!(!token_matches("", ""));
    }
}
