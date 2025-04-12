mod bitvm2;
mod handler;
mod node;

use crate::metrics_service::{MetricsState, metrics_handler, metrics_middleware};
use crate::rpc_service::handler::{
    bitvm2_handler::*,
    node_handler::{create_node, get_nodes},
};
use axum::body::Body;
use axum::body::to_bytes;
use axum::extract::{Request, State};
use axum::handler::Handler;
use axum::response::Response;
use axum::routing::put;
use axum::{
    Router, middleware,
    response::IntoResponse,
    routing::{get, post},
};
use http::HeaderMap;
use libp2p::core::Transport;
use prometheus_client::encoding::text::encode;
use prometheus_client::registry::Registry;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};
use store::localdb::LocalDB;
use tokio::net::TcpListener;
use tower_http::classify::ServerErrorsFailureClass;
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use tracing::{Level, Value};
#[inline(always)]
pub fn current_time_secs() -> i64 {
    std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

#[derive(Clone)]
pub struct AppState {
    pub local_db: LocalDB,
    pub metrics_state: MetricsState,
}

/// Serve the Multiaddr we are listening on and the host files.
// basic handler that responds with a static string
async fn root() -> &'static str {
    "Hello, World!"
}

///Business
///
///1.bridge-in:
///- front end call `bridge_in_tx_prepare`. step1 & step2.1.
///- backend action:
///     - call `create_graph` at step2.2;
///     - call `graph_presign` at step 2.3;
///     - call `peg_btc_mint` at step 3.
///- front end call `get_instance` to get the latest informationGet the latest information about bridge-in
///
///2.graph_overview: `graph_list` support
///
///3.node_overview:  `get_nodes` support
///
///4.instance,graph query  and update by api: `get_instance`, `get_graph`, `update_instance`,`update_graph`
///
///
pub(crate) async fn serve(addr: String, db_path: String, registry: Arc<Mutex<Registry>>) {
    let local_db = LocalDB::new(&format!("sqlite:{db_path}"), true).await;
    local_db.migrate().await;
    let metrics_state = MetricsState::new(registry);
    let app_state = Arc::new(AppState { local_db, metrics_state });
    let server = Router::new()
        .route("/", get(root))
        .route("/v1/nodes", post(create_node))
        .route("/v1/nodes", get(get_nodes))
        .route("/v1/instances", get(get_instances_with_query_params))
        .route("/v1/instances", post(create_instance))
        .route("/v1/instances/{:id}", get(get_instance))
        .route("/v1/instances/{:id}", put(update_instance))
        .route("/v1/instances/action/bridge_in_tx_prepare", post(bridge_in_tx_prepare))
        .route("/v1/instances/{:id}/bridge_in/peg_gtc_mint", post(peg_btc_mint))
        .route("/v1/graphs", post(create_graph))
        .route("/v1/graphs/{:id}", get(get_graph))
        .route("/v1/graphs/{:id}", put(update_graph))
        .route("/v1/graphs", get(graph_list))
        .route("/v1/graphs/{:id}/presign", post(graph_presign))
        .route("/v1/graphs/presign_check", post(graph_presign_check))
        .route("/metrics", get(metrics_handler))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_request(|request: &Request<Body>, _span: &tracing::Span| {
                    tracing::info!(
                        "API Request: {} {}, {:?}, Headers: {:?}, Content-Type: {:?}",
                        request.method(),
                        request.uri(),
                        request.version(),
                        request.headers(),
                        request.headers().get("content-type")
                    );
                })
                .on_response(
                    |response: &Response<Body>, latency: Duration, _span: &tracing::Span| {
                        tracing::info!(
                            "API Response: - Status: {} - Latency: {:?}",
                            response.status(),
                            latency
                        );
                    },
                )
                .on_failure(
                    |error: ServerErrorsFailureClass, _latency: Duration, _span: &tracing::Span| {
                        tracing::error!("API Error: {:?}", error);
                    },
                ),
        )
        .layer(middleware::from_fn_with_state(app_state.clone(), metrics_middleware))
        .with_state(app_state);

    let listener = TcpListener::bind(addr).await.unwrap();
    tracing::info!("RPC listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, server).await.unwrap();
}
#[cfg(test)]
mod tests {
    use crate::rpc_service;
    use prometheus_client::registry::Registry;
    use serde_json::json;
    use std::sync::{Arc, Mutex};
    use tracing::info;
    use tracing_subscriber::EnvFilter;

    const LISTEN_ADDRESS: &str = "127.0.0.1:8900";
    const TMEP_DB_PATH: &str = "/tmp/.bitvm2-node.db";

    fn init_tracing() {
        let _ = tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).try_init();
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn test_node() -> Result<(), Box<dyn std::error::Error>> {
        init_tracing();
        tokio::spawn(rpc_service::serve(
            LISTEN_ADDRESS.to_string(),
            TMEP_DB_PATH.to_string(),
            Arc::new(Mutex::new(Registry::default())),
        ));
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{}/v1/nodes", LISTEN_ADDRESS))
            .json(&json!({
                "peer_id": "ffc54e9cf37d9f87e",
                "actor": "Committee"
            }))
            .send()
            .await?;
        info!("{:?}", resp);
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        info!("Post Response: {}", res_body);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_nodes() -> Result<(), Box<dyn std::error::Error>> {
        init_tracing();
        tokio::spawn(rpc_service::serve(
            LISTEN_ADDRESS.to_string(),
            TMEP_DB_PATH.to_string(),
            Arc::new(Mutex::new(Registry::default())),
        ));
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{}/v1/nodes?actor=OPERATOR&offset=5&limit=5", LISTEN_ADDRESS))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        println!("Post Response: {}", res_body);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_bridge_in_tx_prepare() -> Result<(), Box<dyn std::error::Error>> {
        init_tracing();
        tokio::spawn(rpc_service::serve(
            LISTEN_ADDRESS.to_string(),
            TMEP_DB_PATH.to_string(),
            Arc::new(Mutex::new(Registry::default())),
        ));
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{}/v1/instances/action/bridge_in_tx_prepare", LISTEN_ADDRESS))
            .json(&json!({
                "instance_id": "3baa703537ef",
                "network": "test3",
                "amount": 10000,
                "fee_rate": 80,
                "utxo": [
                    {
                        "txid": "ffc54e9cf37d9f87ebaa703537e93e20caece862d9bc1c463c487583905ec49c",
                        "vout": 0,
                        "value": 10000
                    }
                ],
                "from": "tb1qsyngu9wf2x46tlexhpjl4nugv0zxmgezsx5erl",
                "to": "tb1qkrhp3khxam3hj2kl9y77m2uctj2hkyh248chkp"
            }))
            .send()
            .await?;
        tracing::info!("{:?}", resp);
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        tracing::info!("Post Response: {}", res_body);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_get_instance() -> Result<(), Box<dyn std::error::Error>> {
        init_tracing();
        tokio::spawn(rpc_service::serve(
            LISTEN_ADDRESS.to_string(),
            TMEP_DB_PATH.to_string(),
            Arc::new(Mutex::new(Registry::default())),
        ));
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{}/v1/instances/ffc54e9cf37d9f87e2222", LISTEN_ADDRESS))
            .send()
            .await
            .expect("");
        assert!(resp.status().is_success());
        let res_body = resp.text().await.unwrap();
        tracing::info!("Post Response: {}", res_body);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_get_instances_with_query_params() -> Result<(), Box<dyn std::error::Error>> {
        init_tracing();
        tokio::spawn(rpc_service::serve(
            LISTEN_ADDRESS.to_string(),
            TMEP_DB_PATH.to_string(),
            Arc::new(Mutex::new(Registry::default())),
        ));
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{}/v1/instances?user_address=miJ19RACTc7Sow64gbznCnCz3p4Ey2NP18&offset=1&limit=5", LISTEN_ADDRESS))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        tracing::info!("Post Response: {}", res_body);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_peg_btc_mint() -> Result<(), Box<dyn std::error::Error>> {
        init_tracing();
        tokio::spawn(rpc_service::serve(
            LISTEN_ADDRESS.to_string(),
            TMEP_DB_PATH.to_string(),
            Arc::new(Mutex::new(Registry::default())),
        ));
        let client = reqwest::Client::new();
        let resp = client
            .post(format!(
                "http://{}/v1/instances/ffc54e9cf37d9f87e/bridge_in/peg_gtc_mint",
                LISTEN_ADDRESS
            ))
            .json(&json!({
                "graph_ids":[
                    "ffc54e9cf37d9f11",
                    "aaa7583905ec49c",
                    "bbc7ebaa703537e93"
                ],
                "pegin_txid": "58de965c464696560fdee91d039da6d49ef7770f30ef07d892e21d8a80a16c2c"
            }))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        tracing::info!("Post Response: {}", res_body);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_bridge_out_tx_prepare() -> Result<(), Box<dyn std::error::Error>> {
        init_tracing();
        tokio::spawn(rpc_service::serve(
            LISTEN_ADDRESS.to_string(),
            TMEP_DB_PATH.to_string(),
            Arc::new(Mutex::new(Registry::default())),
        ));
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{}/v1/instances/action/bridge_out_tx_prepare", LISTEN_ADDRESS))
            .json(&json!({
                "instance_id": "ddsd",
                "operator": "operator_test"
            }))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        tracing::info!("Post Response: {}", res_body);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_create_graph() -> Result<(), Box<dyn std::error::Error>> {
        init_tracing();
        tokio::spawn(rpc_service::serve(
            LISTEN_ADDRESS.to_string(),
            TMEP_DB_PATH.to_string(),
            Arc::new(Mutex::new(Registry::default())),
        ));
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{}/v1/graphs", LISTEN_ADDRESS))
            .json(&json!({
              "instance_id": "111",
                "graph_id": "333baa703537ef",
            }))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        tracing::info!("Post Response: {}", res_body);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_get_graphs() -> Result<(), Box<dyn std::error::Error>> {
        init_tracing();
        tokio::spawn(rpc_service::serve(
            LISTEN_ADDRESS.to_string(),
            TMEP_DB_PATH.to_string(),
            Arc::new(Mutex::new(Registry::default())),
        ));
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{}/v1/graphs?offset=0&limit=5", LISTEN_ADDRESS))
            .json(&json!({
                "status": "OperatorPresigned",
                "operator": "ffc54e9cf37d9f87e1111",
                "pegin_txid":"123123"
            }))
            .send()
            .await?;
        // assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        tracing::info!("Post Response: {}", res_body);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_get_graph() -> Result<(), Box<dyn std::error::Error>> {
        init_tracing();
        tokio::spawn(rpc_service::serve(
            LISTEN_ADDRESS.to_string(),
            TMEP_DB_PATH.to_string(),
            Arc::new(Mutex::new(Registry::default())),
        ));
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{}/v1/graphs/aaa7583905ec49c", LISTEN_ADDRESS))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        tracing::info!("Post Response: {}", res_body);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_graph_presign() -> Result<(), Box<dyn std::error::Error>> {
        init_tracing();
        tokio::spawn(rpc_service::serve(
            LISTEN_ADDRESS.to_string(),
            TMEP_DB_PATH.to_string(),
            Arc::new(Mutex::new(Registry::default())),
        ));
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{}/v1/graphs/aaa7583905ec49c/presign", LISTEN_ADDRESS))
            .json(&json!({
                "instance_id": "1baa703537ef",
                "graph_ipfs_base_url":"https://ipfs.io/ipfs/QmXxwbk8eA2bmKBy7YEjm5w1zKiG7g6ebF1JYfqWvnLnhH"
            }))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        tracing::info!("Post Response: {}", res_body);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_graph_presign_check() -> Result<(), Box<dyn std::error::Error>> {
        init_tracing();
        tokio::spawn(rpc_service::serve(
            LISTEN_ADDRESS.to_string(),
            TMEP_DB_PATH.to_string(),
            Arc::new(Mutex::new(Registry::default())),
        ));
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{}/v1/graphs/presign_check", LISTEN_ADDRESS))
            .json(&json!(
                {
                   "instance_id": "7583905ec49c",
                }
            ))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        info!("Post Response: {}", res_body);
        Ok(())
    }
}
