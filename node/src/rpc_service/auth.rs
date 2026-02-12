use crate::env::get_bitvm_key;
use crate::rpc_service::response::ErrorResponse;
use axum::Json;
use http::{HeaderMap, StatusCode};
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, Message, SECP256K1};
use sha2::{Digest, Sha256};

pub const AUTH_TIMESTAMP_HEADER: &str = "x-auth-timestamp";
pub const AUTH_SIGNATURE_HEADER: &str = "x-auth-signature";
const AUTH_WINDOW_SECS: i64 = 300;
const AUTH_DOMAIN: &[u8] = b"bitvm2-auth";

/// Verify that the request carries a valid Schnorr signature produced by the
/// same `BITVM_SECRET` this node is configured with.
///
/// Expected headers:
///   - `X-Auth-Timestamp`: current unix epoch seconds (string)
///   - `X-Auth-Signature`: hex-encoded 64-byte Schnorr signature of
///     `SHA256(b"bitvm2-auth" || timestamp_str)`
pub fn verify_request_auth(headers: &HeaderMap) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let timestamp_str = headers
        .get(AUTH_TIMESTAMP_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| auth_error("missing X-Auth-Timestamp header"))?;

    let signature_hex = headers
        .get(AUTH_SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| auth_error("missing X-Auth-Signature header"))?;

    // Check timestamp freshness
    let timestamp: i64 = timestamp_str.parse().map_err(|_| auth_error("invalid timestamp"))?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
        as i64;
    if (now - timestamp).abs() > AUTH_WINDOW_SECS {
        return Err(auth_error("timestamp expired"));
    }

    // Reconstruct message hash
    let mut hasher = Sha256::new();
    hasher.update(AUTH_DOMAIN);
    hasher.update(timestamp_str.as_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    let msg = Message::from_digest(hash);

    // Decode signature
    let sig_bytes =
        hex::decode(signature_hex).map_err(|_| auth_error("invalid signature hex encoding"))?;
    let signature =
        Signature::from_slice(&sig_bytes).map_err(|_| auth_error("invalid signature format"))?;

    // Get node's x-only public key from BITVM_SECRET
    let keypair =
        get_bitvm_key().map_err(|_| auth_error("server key configuration error (BITVM_SECRET)"))?;
    let (x_only_pubkey, _) = keypair.x_only_public_key();

    // Verify
    SECP256K1
        .verify_schnorr(&signature, &msg, &x_only_pubkey)
        .map_err(|_| auth_error("signature verification failed"))?;

    Ok(())
}

/// Build the `(x-auth-timestamp, x-auth-signature)` header values for a request.
///
/// Signs `SHA256(b"bitvm2-auth" || timestamp_str)` with the provided keypair using
/// Schnorr and returns `(timestamp_str, hex_signature)`.
pub fn sign_request_auth(keypair: &Keypair) -> (String, String) {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();

    let mut hasher = Sha256::new();
    hasher.update(AUTH_DOMAIN);
    hasher.update(timestamp.as_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    let msg = Message::from_digest(hash);

    let signature = SECP256K1.sign_schnorr(&msg, keypair);
    (timestamp, hex::encode(signature.as_ref()))
}

fn auth_error(msg: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorResponse { error: "AUTH_ERROR".to_string(), message: msg.to_string() }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;

    fn make_headers(timestamp: &str, signature: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(AUTH_TIMESTAMP_HEADER, timestamp.parse().unwrap());
        headers.insert(AUTH_SIGNATURE_HEADER, signature.parse().unwrap());
        headers
    }

    fn test_keypair() -> Keypair {
        // Fixed 32-byte secret for deterministic tests
        let secret = [0x42u8; 32];
        Keypair::from_seckey_slice(SECP256K1, &secret).unwrap()
    }

    #[test]
    fn sign_then_verify_ok() {
        let keypair = test_keypair();
        unsafe {
            std::env::set_var("BITVM_SECRET", hex::encode(keypair.secret_key().secret_bytes()))
        };

        let (ts, sig) = sign_request_auth(&keypair);
        let headers = make_headers(&ts, &sig);
        assert!(verify_request_auth(&headers).is_ok());
    }

    #[test]
    fn verify_missing_timestamp_fails() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTH_SIGNATURE_HEADER, "aabbcc".parse().unwrap());
        let err = verify_request_auth(&headers).unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn verify_missing_signature_fails() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTH_TIMESTAMP_HEADER, "1234567890".parse().unwrap());
        let err = verify_request_auth(&headers).unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn verify_expired_timestamp_fails() {
        let keypair = test_keypair();
        unsafe {
            std::env::set_var("BITVM_SECRET", hex::encode(keypair.secret_key().secret_bytes()))
        };

        // Timestamp 10 minutes in the past
        let old_ts =
            (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
                - 600)
                .to_string();

        let mut hasher = Sha256::new();
        hasher.update(AUTH_DOMAIN);
        hasher.update(old_ts.as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        let msg = Message::from_digest(hash);
        let sig = SECP256K1.sign_schnorr(&msg, &keypair);

        let headers = make_headers(&old_ts, &hex::encode(sig.as_ref()));
        let err = verify_request_auth(&headers).unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn verify_wrong_signature_fails() {
        let keypair = test_keypair();
        unsafe {
            std::env::set_var("BITVM_SECRET", hex::encode(keypair.secret_key().secret_bytes()))
        };

        let (ts, _) = sign_request_auth(&keypair);
        // Corrupt the signature
        let bad_sig = "ff".repeat(64);
        let headers = make_headers(&ts, &bad_sig);
        let err = verify_request_auth(&headers).unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }
}
