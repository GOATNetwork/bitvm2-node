use crate::api::response::ErrorResponse;
use crate::config::TrustedApiKeys;
use axum::Json;
use axum::http::{HeaderMap, StatusCode};
use proof_builder::api_auth::{
    AUTH_NONCE_HEADER, AUTH_PUBLIC_KEY_HEADER, AUTH_SIGNATURE_HEADER, AUTH_TIMESTAMP_HEADER,
    AUTH_WINDOW_SECS, ProofBuilderAuthRole, normalize_public_key,
    verify_proof_builder_request_signature,
};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

type AuthResult<T> = Result<T, (StatusCode, Json<ErrorResponse>)>;

pub(crate) struct RequestAuthorizer {
    trusted_operator_keys: HashSet<secp256k1::XOnlyPublicKey>,
    trusted_watchtower_keys: HashSet<secp256k1::XOnlyPublicKey>,
    accepted_nonces: Mutex<HashMap<(String, String), i64>>,
}

impl RequestAuthorizer {
    /// Creates a request authorizer from validated role-specific public keys.
    pub(crate) fn new(keys: TrustedApiKeys) -> Self {
        Self {
            trusted_operator_keys: keys.operator,
            trusted_watchtower_keys: keys.watchtower,
            accepted_nonces: Mutex::new(HashMap::new()),
        }
    }

    /// Authenticates and authorizes a request for one Proof Builder role.
    pub(crate) fn authorize<B: Serialize>(
        &self,
        headers: &HeaderMap,
        role: ProofBuilderAuthRole,
        method: &str,
        path: &str,
        body: &B,
        claimed_watchtower_public_key: Option<&str>,
    ) -> AuthResult<()> {
        let timestamp = required_header(headers, AUTH_TIMESTAMP_HEADER)?;
        let nonce = required_header(headers, AUTH_NONCE_HEADER)?;
        let signer_value = required_header(headers, AUTH_PUBLIC_KEY_HEADER)?;
        let signature = required_header(headers, AUTH_SIGNATURE_HEADER)?;
        let signer = normalize_public_key(signer_value)
            .map_err(|_| unauthorized("invalid signer public key"))?;

        let trusted = match role {
            ProofBuilderAuthRole::Operator => &self.trusted_operator_keys,
            ProofBuilderAuthRole::Watchtower => &self.trusted_watchtower_keys,
        };
        if !trusted.contains(&signer) {
            return Err(forbidden("signer is not trusted for this role"));
        }

        if let Some(claimed_public_key) = claimed_watchtower_public_key {
            let claimed = normalize_public_key(claimed_public_key)
                .map_err(|_| forbidden("invalid watchtower public key"))?;
            if claimed != signer {
                return Err(forbidden("watchtower signer does not match request public key"));
            }
        }

        verify_proof_builder_request_signature(
            role, method, path, timestamp, nonce, &signer, signature, body,
        )
        .map_err(|_| unauthorized("invalid request signature"))?;
        self.record_nonce(&signer.to_string(), nonce)?;
        Ok(())
    }

    /// Atomically rejects a nonce already accepted from the same signer.
    fn record_nonce(&self, signer: &str, nonce: &str) -> AuthResult<()> {
        let now = current_time_secs();
        let mut accepted_nonces = self
            .accepted_nonces
            .lock()
            .map_err(|_| internal_error("authentication replay cache is unavailable"))?;
        accepted_nonces.retain(|_, accepted_at| now - *accepted_at <= AUTH_WINDOW_SECS);
        if accepted_nonces.insert((signer.to_string(), nonce.to_string()), now).is_some() {
            return Err(unauthorized("request nonce has already been used"));
        }
        Ok(())
    }
}

/// Reads one required UTF-8 authentication header.
fn required_header<'a>(headers: &'a HeaderMap, name: &str) -> AuthResult<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| unauthorized(&format!("missing or invalid {name} header")))
}

/// Builds a 401 response for missing or invalid authentication credentials.
fn unauthorized(message: &str) -> (StatusCode, Json<ErrorResponse>) {
    auth_error(StatusCode::UNAUTHORIZED, message)
}

/// Builds a 403 response for an authenticated identity without the required role or ownership.
fn forbidden(message: &str) -> (StatusCode, Json<ErrorResponse>) {
    auth_error(StatusCode::FORBIDDEN, message)
}

/// Builds a 500 response when the local authentication state cannot be used safely.
fn internal_error(message: &str) -> (StatusCode, Json<ErrorResponse>) {
    auth_error(StatusCode::INTERNAL_SERVER_ERROR, message)
}

/// Builds the common JSON error returned by the Proof Builder authentication boundary.
fn auth_error(status: StatusCode, message: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            error: "PROOF_BUILDER_AUTH_ERROR".to_string(),
            message: message.into(),
        }),
    )
}

/// Returns the current Unix time used to expire replay-cache entries.
fn current_time_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use proof_builder::api_auth::{ProofBuilderAuthHeaders, sign_proof_builder_request};
    use secp256k1::{Keypair, SECP256K1};
    use serde::Serialize;

    #[derive(Serialize)]
    struct TestBody {
        public_key: String,
        value: u64,
    }

    fn keypair(seed: u8) -> Keypair {
        Keypair::from_seckey_slice(SECP256K1, &[seed; 32]).unwrap()
    }

    fn headers(values: &ProofBuilderAuthHeaders) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in values.to_header_pairs() {
            headers.insert(name.parse::<axum::http::HeaderName>().unwrap(), value.parse().unwrap());
        }
        headers
    }

    fn authorizer(operator: &Keypair, watchtower: &Keypair) -> RequestAuthorizer {
        RequestAuthorizer::new(TrustedApiKeys {
            operator: HashSet::from([operator.x_only_public_key().0]),
            watchtower: HashSet::from([watchtower.x_only_public_key().0]),
        })
    }

    #[test]
    fn accepts_trusted_signer_once_and_rejects_replay() {
        let operator = keypair(7);
        let watchtower = keypair(9);
        let authorizer = authorizer(&operator, &watchtower);
        let body = TestBody { public_key: operator.public_key().to_string(), value: 1 };
        let signed = sign_proof_builder_request(
            &operator,
            ProofBuilderAuthRole::Operator,
            "POST",
            "/v1/proofs/operator_proofs",
            &body,
        )
        .unwrap();
        let headers = headers(&signed);

        assert!(
            authorizer
                .authorize(
                    &headers,
                    ProofBuilderAuthRole::Operator,
                    "POST",
                    "/v1/proofs/operator_proofs",
                    &body,
                    None,
                )
                .is_ok()
        );
        assert_eq!(
            authorizer
                .authorize(
                    &headers,
                    ProofBuilderAuthRole::Operator,
                    "POST",
                    "/v1/proofs/operator_proofs",
                    &body,
                    None,
                )
                .unwrap_err()
                .0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn rejects_cross_role_and_mismatched_watchtower_identity() {
        let operator = keypair(7);
        let watchtower = keypair(9);
        let other_watchtower = keypair(11);
        let authorizer = authorizer(&operator, &watchtower);
        let operator_body = TestBody { public_key: watchtower.public_key().to_string(), value: 1 };
        let cross_role = sign_proof_builder_request(
            &watchtower,
            ProofBuilderAuthRole::Operator,
            "POST",
            "/v1/proofs/operator_proofs",
            &operator_body,
        )
        .unwrap();
        assert_eq!(
            authorizer
                .authorize(
                    &headers(&cross_role),
                    ProofBuilderAuthRole::Operator,
                    "POST",
                    "/v1/proofs/operator_proofs",
                    &operator_body,
                    None,
                )
                .unwrap_err()
                .0,
            StatusCode::FORBIDDEN
        );

        let watchtower_body =
            TestBody { public_key: other_watchtower.public_key().to_string(), value: 1 };
        let signed = sign_proof_builder_request(
            &watchtower,
            ProofBuilderAuthRole::Watchtower,
            "POST",
            "/v1/proofs/watchtower_proofs",
            &watchtower_body,
        )
        .unwrap();
        assert_eq!(
            authorizer
                .authorize(
                    &headers(&signed),
                    ProofBuilderAuthRole::Watchtower,
                    "POST",
                    "/v1/proofs/watchtower_proofs",
                    &watchtower_body,
                    Some(&watchtower_body.public_key),
                )
                .unwrap_err()
                .0,
            StatusCode::FORBIDDEN
        );
    }
}
