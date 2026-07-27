pub(crate) mod metrics_service;
mod proof_handler;
mod response;
pub(crate) mod routes;
mod validation;

use crate::api::metrics_service::{ApiMetricsState, metrics_handler, metrics_middleware};
use crate::api::proof_handler::{
    get_chain_proof_task_desc, get_operator_proof_task_desc, post_operator_proof_task,
    post_watchtower_proof_task, update_operator_proof_task_timeout,
    update_watchtower_proof_task_timeout,
};
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
}

impl ApiState {
    /// Creates shared API state from the database and metrics registry.
    fn new(local_db: LocalDB, metrics_state: ApiMetricsState) -> Arc<ApiState> {
        Arc::new(ApiState { local_db, metrics_state })
    }
}
pub(crate) async fn serve(
    addr: String,
    local_db: LocalDB,
    metrics_state: ApiMetricsState,
    cancellation_token: CancellationToken,
) -> anyhow::Result<String> {
    let api_state = ApiState::new(local_db, metrics_state);
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

    #[tokio::test]
    async fn metrics_use_route_templates_and_exclude_scrapes() -> anyhow::Result<()> {
        let addr = available_addr();
        let cancellation_token = CancellationToken::new();
        let server_token = cancellation_token.clone();
        let server = tokio::spawn(serve(
            addr.clone(),
            store::create_local_db("sqlite::memory:").await,
            ApiMetricsState::new(),
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
}
