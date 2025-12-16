mod metrics_service;
mod proof_handler;
mod proofs;
mod response;
pub(crate) mod routes;
mod validation;

use crate::api::metrics_service::{ApiMetricsState, metrics_handler, metrics_middleware};
use crate::api::proof_handler::{
    get_chain_proof_task, post_operator_proof_task, post_watchtower_proof_task,
};
use axum::routing::{get, post};
use axum::{Router, middleware};
use std::sync::Arc;
use store::localdb::LocalDB;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

struct ApiState {
    pub local_db: LocalDB,
    pub metrics_state: ApiMetricsState,
}

impl ApiState {
    pub(crate) async fn create_arc_app_state(local_db: LocalDB) -> anyhow::Result<Arc<ApiState>> {
        let metrics_state = ApiMetricsState::new();
        Ok(Arc::new(ApiState { local_db, metrics_state }))
    }
}
pub(crate) async fn serve(
    addr: String,
    local_db: LocalDB,
    cancellation_token: CancellationToken,
) -> anyhow::Result<String> {
    let api_state = ApiState::create_arc_app_state(local_db).await?;
    let server = Router::new()
        .route(routes::ROOT, get(root))
        .route(routes::METRICS, get(metrics_handler))
        .route(routes::v1::CHAIN_PROOFS_BASE, get(get_chain_proof_task))
        .route(routes::v1::NODES_WATCHTOWER_BASE, post(post_watchtower_proof_task))
        .route(routes::v1::NODES_OPERATOR_BASE, post(post_operator_proof_task))
        .route(routes::METRICS, get(metrics_handler))
        .layer(middleware::from_fn_with_state(api_state.clone(), metrics_middleware))
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
