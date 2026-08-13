mod auth;
pub(crate) mod metrics_service;
mod proof_handler;
mod response;
pub(crate) mod routes;
mod validation;

use crate::api::auth::RequestAuthorizer;
use crate::api::metrics_service::{ApiMetricsState, metrics_handler, metrics_middleware};
use crate::api::proof_handler::{
    get_chain_proof_task_desc, get_operator_proof_task_desc, post_operator_proof_task,
    post_watchtower_proof_task, update_operator_proof_task_timeout,
    update_watchtower_proof_task_timeout,
};
use crate::config::TrustedApiKeys;
use axum::http::{Method, StatusCode};
use axum::routing::{get, post};
use axum::{Router, middleware};
use std::sync::Arc;
use store::localdb::LocalDB;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tower_http::cors::{Any, CorsLayer};

struct ApiState {
    pub local_db: LocalDB,
    pub metrics_state: ApiMetricsState,
    pub auth: RequestAuthorizer,
}

impl ApiState {
    /// Creates shared API state from the database, metrics, and trusted caller keys.
    fn new(
        local_db: LocalDB,
        metrics_state: ApiMetricsState,
        trusted_api_keys: TrustedApiKeys,
    ) -> Arc<ApiState> {
        Arc::new(ApiState {
            local_db,
            metrics_state,
            auth: RequestAuthorizer::new(trusted_api_keys),
        })
    }
}
pub(crate) async fn serve(
    addr: String,
    local_db: LocalDB,
    metrics_state: ApiMetricsState,
    trusted_api_keys: TrustedApiKeys,
    cancellation_token: CancellationToken,
) -> anyhow::Result<String> {
    let api_state = ApiState::new(local_db, metrics_state, trusted_api_keys);
    let instrumented_routes = Router::new()
        .route(routes::ROOT, get(root))
        .route(routes::v1::PROOFS_CHAIN_PROOFS_DESC, get(get_chain_proof_task_desc))
        .route(routes::v1::PROOFS_WATCHTOWER_PROOF, post(post_watchtower_proof_task))
        .route(
            routes::v1::PROOFS_WATCHTOWER_PROOF_TIMEOUT,
            post(update_watchtower_proof_task_timeout),
        )
        .route(routes::v1::PROOFS_OPERATOR_PROOF, post(post_operator_proof_task))
        .route(routes::v1::PROOFS_OPERATOR_PROOF_TIMEOUT, post(update_operator_proof_task_timeout))
        .route(routes::v1::PROOFS_OPERATOR_PROOF_DESC, get(get_operator_proof_task_desc))
        .fallback(|| async { StatusCode::NOT_FOUND })
        .layer(middleware::from_fn_with_state(api_state.clone(), metrics_middleware));
    let server = Router::new()
        .route(routes::METRICS, get(metrics_handler))
        .merge(instrumented_routes)
        .layer(CorsLayer::new().allow_headers(Any).allow_origin(Any).allow_methods(vec![
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ]))
        .with_state(api_state);
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("RPC listening on {}", listener.local_addr()?);
    tokio::select! {
        result = axum::serve(listener, server) => {
            match result {
                Ok(_) => Ok("RPC server finished normally".to_string()),
                Err(e) => {
                    tracing::error!("RPC server error: {}", e);
                    Err(anyhow::anyhow!("RPC server error: {e}"))
                }
            }
        }
        _ = cancellation_token.cancelled() => {
            tracing::info!("RPC service received shutdown signal");
            Ok("rpc_shutdown".to_string())
        }
    }
}
async fn root() -> &'static str {
    "Hello, World!"
}

#[cfg(test)]
mod tests {
    use super::*;
    use proof_builder::api_auth::{
        ProofBuilderAuthHeaders, ProofBuilderAuthRole, sign_proof_builder_request,
    };
    use proof_builder::{
        OperatorProofRequest, OperatorProofTimeoutUpdateRequest, WatchtowerProofRequest,
        WatchtowerProofTimeoutUpdateRequest,
    };
    use secp256k1::{Keypair, SECP256K1};
    use std::collections::HashSet;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn available_addr() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().to_string()
    }

    async fn get(addr: &str, path: &str) -> anyhow::Result<String> {
        let mut stream = tokio::net::TcpStream::connect(addr).await?;
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        Ok(String::from_utf8(response)?)
    }

    async fn post(
        addr: &str,
        path: &str,
        body: &str,
        auth: Option<&ProofBuilderAuthHeaders>,
    ) -> anyhow::Result<String> {
        let mut stream = tokio::net::TcpStream::connect(addr).await?;
        let auth_headers = auth
            .map(|auth| {
                auth.to_header_pairs()
                    .into_iter()
                    .map(|(name, value)| format!("{name}: {value}\r\n"))
                    .collect::<String>()
            })
            .unwrap_or_default();
        stream
            .write_all(
                format!(
                    "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{auth_headers}Connection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        Ok(String::from_utf8(response)?)
    }

    fn keypair(seed: u8) -> Keypair {
        Keypair::from_seckey_slice(SECP256K1, &[seed; 32]).unwrap()
    }

    fn trusted_api_keys(operator: &Keypair, watchtower: &Keypair) -> TrustedApiKeys {
        TrustedApiKeys {
            operator: HashSet::from([operator.x_only_public_key().0]),
            watchtower: HashSet::from([watchtower.x_only_public_key().0]),
        }
    }

    #[tokio::test]
    async fn metrics_use_route_templates_and_exclude_scrapes() -> anyhow::Result<()> {
        let addr = available_addr();
        let cancellation_token = CancellationToken::new();
        let server_token = cancellation_token.clone();
        let server = tokio::spawn(serve(
            addr.clone(),
            store::create_local_db("sqlite::memory:").await,
            ApiMetricsState::new(),
            trusted_api_keys(&keypair(7), &keypair(9)),
            server_token,
        ));
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        assert!(get(&addr, "/").await?.starts_with("HTTP/1.1 200"));
        assert!(get(&addr, "/missing").await?.starts_with("HTTP/1.1 404"));
        let first_scrape = get(&addr, "/metrics").await?;
        let second_scrape = get(&addr, "/metrics").await?;

        assert!(
            first_scrape
                .contains("http_requests_total{method=\"GET\",route=\"/\",status=\"200\"} 1")
        );
        assert!(
            first_scrape.contains(
                "http_requests_total{method=\"GET\",route=\"unmatched\",status=\"404\"} 1"
            )
        );
        assert!(first_scrape.contains("http_requests_in_flight 0"));
        assert!(!first_scrape.contains("route=\"/metrics\""));
        assert!(!second_scrape.contains("route=\"/metrics\""));

        cancellation_token.cancel();
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn operator_and_watchtower_task_routes_enforce_role_authentication() -> anyhow::Result<()>
    {
        let operator = keypair(7);
        let watchtower = keypair(9);
        let other_watchtower = keypair(11);
        let addr = available_addr();
        let cancellation_token = CancellationToken::new();
        let server_token = cancellation_token.clone();
        let server = tokio::spawn(serve(
            addr.clone(),
            store::create_local_db("sqlite::memory:").await,
            ApiMetricsState::new(),
            trusted_api_keys(&operator, &watchtower),
            server_token,
        ));
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let instance_id = "00112233-4455-6677-8899-aabbccddeeff".to_string();
        let graph_id = "11112233-4455-6677-8899-aabbccddeeff".to_string();
        let operator_submit = OperatorProofRequest {
            instance_id: instance_id.clone(),
            graph_id: graph_id.clone(),
            operator_committed_blockhash: "11".repeat(32),
            execution_layer_block_number: 1,
            watchtower_challenge_txids: vec![],
            included_watchtowers: vec![],
            watchtower_challenge_init_txid: "22".repeat(32),
            watchtower_challenge_pubkeys: vec![],
        };
        let operator_submit_body = serde_json::to_string(&operator_submit)?;
        assert!(
            post(&addr, routes::v1::PROOFS_OPERATOR_PROOF, &operator_submit_body, None,)
                .await?
                .starts_with("HTTP/1.1 401")
        );
        let operator_submit_auth = sign_proof_builder_request(
            &operator,
            ProofBuilderAuthRole::Operator,
            "POST",
            routes::v1::PROOFS_OPERATOR_PROOF,
            &operator_submit,
        )?;
        assert!(
            post(
                &addr,
                routes::v1::PROOFS_OPERATOR_PROOF,
                &operator_submit_body,
                Some(&operator_submit_auth),
            )
            .await?
            .starts_with("HTTP/1.1 200")
        );

        let operator_timeout = OperatorProofTimeoutUpdateRequest {
            instance_id: instance_id.clone(),
            graph_id: graph_id.clone(),
        };
        let operator_timeout_body = serde_json::to_string(&operator_timeout)?;
        let wrong_role_auth = sign_proof_builder_request(
            &watchtower,
            ProofBuilderAuthRole::Operator,
            "POST",
            routes::v1::PROOFS_OPERATOR_PROOF_TIMEOUT,
            &operator_timeout,
        )?;
        assert!(
            post(
                &addr,
                routes::v1::PROOFS_OPERATOR_PROOF_TIMEOUT,
                &operator_timeout_body,
                Some(&wrong_role_auth),
            )
            .await?
            .starts_with("HTTP/1.1 403")
        );
        let operator_timeout_auth = sign_proof_builder_request(
            &operator,
            ProofBuilderAuthRole::Operator,
            "POST",
            routes::v1::PROOFS_OPERATOR_PROOF_TIMEOUT,
            &operator_timeout,
        )?;
        let operator_timeout_response = post(
            &addr,
            routes::v1::PROOFS_OPERATOR_PROOF_TIMEOUT,
            &operator_timeout_body,
            Some(&operator_timeout_auth),
        )
        .await?;
        assert!(operator_timeout_response.starts_with("HTTP/1.1 200"));
        assert!(operator_timeout_response.contains("1 rows affected"));

        let watchtower_submit = WatchtowerProofRequest {
            instance_id: instance_id.clone(),
            graph_id: graph_id.clone(),
            public_key: watchtower.public_key().to_string(),
            challenge_init_txid: "33".repeat(32),
            execution_layer_block_number: 1,
        };
        let watchtower_submit_body = serde_json::to_string(&watchtower_submit)?;
        let watchtower_submit_auth = sign_proof_builder_request(
            &watchtower,
            ProofBuilderAuthRole::Watchtower,
            "POST",
            routes::v1::PROOFS_WATCHTOWER_PROOF,
            &watchtower_submit,
        )?;
        assert!(
            post(
                &addr,
                routes::v1::PROOFS_WATCHTOWER_PROOF,
                &watchtower_submit_body,
                Some(&watchtower_submit_auth),
            )
            .await?
            .starts_with("HTTP/1.1 200")
        );

        let watchtower_timeout = WatchtowerProofTimeoutUpdateRequest {
            instance_id,
            graph_id,
            public_key: watchtower.public_key().to_string(),
        };
        let watchtower_timeout_body = serde_json::to_string(&watchtower_timeout)?;
        let watchtower_timeout_auth = sign_proof_builder_request(
            &watchtower,
            ProofBuilderAuthRole::Watchtower,
            "POST",
            routes::v1::PROOFS_WATCHTOWER_PROOF_TIMEOUT,
            &watchtower_timeout,
        )?;
        let watchtower_timeout_response = post(
            &addr,
            routes::v1::PROOFS_WATCHTOWER_PROOF_TIMEOUT,
            &watchtower_timeout_body,
            Some(&watchtower_timeout_auth),
        )
        .await?;
        assert!(watchtower_timeout_response.starts_with("HTTP/1.1 200"));
        assert!(watchtower_timeout_response.contains("1 rows affected"));

        let mismatched_timeout = WatchtowerProofTimeoutUpdateRequest {
            public_key: other_watchtower.public_key().to_string(),
            ..watchtower_timeout
        };
        let mismatched_timeout_body = serde_json::to_string(&mismatched_timeout)?;
        let mismatched_timeout_auth = sign_proof_builder_request(
            &watchtower,
            ProofBuilderAuthRole::Watchtower,
            "POST",
            routes::v1::PROOFS_WATCHTOWER_PROOF_TIMEOUT,
            &mismatched_timeout,
        )?;
        assert!(
            post(
                &addr,
                routes::v1::PROOFS_WATCHTOWER_PROOF_TIMEOUT,
                &mismatched_timeout_body,
                Some(&mismatched_timeout_auth),
            )
            .await?
            .starts_with("HTTP/1.1 403")
        );

        cancellation_token.cancel();
        server.await??;
        Ok(())
    }
}
