mod bitvm2;

pub use bitvm2::BridgeInTransactionPreparerRequest;
use std::str::FromStr;
mod handler;
mod node;

use crate::metrics_service::{MetricsState, metrics_handler, metrics_middleware};
use crate::rpc_service::handler::{
    bitvm2_handler::*,
    node_handler::*,
};
use axum::body::Body;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::put;
use axum::{
    Router, middleware,
    routing::{get, post},
};
use bitvm2_lib::actors::Actor;
use http::{HeaderMap, StatusCode};
use http_body_util::BodyExt;
use prometheus_client::registry::Registry;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};
use store::localdb::LocalDB;
use tokio::net::TcpListener;
use tower_http::classify::ServerErrorsFailureClass;
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use tracing::Level;

#[inline(always)]
pub fn current_time_secs() -> i64 {
    std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

#[derive(Clone)]
pub struct AppState {
    pub local_db: LocalDB,
    pub metrics_state: MetricsState,
    pub actor: Actor,
    pub peer_id: String,
}

impl AppState {
    pub async fn create_arc_app_state(
        db_path: String,
        registry: Arc<Mutex<Registry>>,
    ) -> anyhow::Result<Arc<AppState>> {
        let local_db = LocalDB::new(&format!("sqlite:{db_path}"), true).await;
        local_db.migrate().await;
        let metrics_state = MetricsState::new(registry);
        let actor =
            Actor::from_str(std::env::var("ACTOR").unwrap_or("Challenger".to_string()).as_str())
                .expect("failed to get actor ");
        let peer_id = std::env::var("PEER_ID").unwrap_or("Self".to_string());
        Ok(Arc::new(AppState { local_db, metrics_state, actor, peer_id }))
    }
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
pub(crate) async fn serve(
    addr: String,
    db_path: String,
    registry: Arc<Mutex<Registry>>,
) -> anyhow::Result<()> {
    let app_state = AppState::create_arc_app_state(db_path, registry).await?;
    let server = Router::new()
        .route("/", get(root))
        .route("/v1/nodes", post(create_node))
        .route("/v1/nodes", get(get_nodes))
        .route("/v1/nodes/overview", get(get_nodes_overview))
        .route("/v1/instance_settings", get(instance_settings))
        .route("/v1/instances", get(get_instances_with_query_params))
        .route("/v1/instances", post(create_instance))
        .route("/v1/instances/{:id}", get(get_instance))
        .route("/v1/instances/{:id}", put(update_instance))
        .route("/v1/instances/action/bridge_in_tx_prepare", post(bridge_in_tx_prepare))
        .route("/v1/instances/{:id}/bridge_in/peg_gtc_mint", post(peg_btc_mint))
        .route("/v1/instances/overview", get(get_instances_overview))
        .route("/v1/graphs", post(create_graph))
        .route("/v1/graphs/{:id}", get(get_graph))
        .route("/v1/graphs/{:id}", put(update_graph))
        .route("/v1/graphs", get(get_graphs))
        .route("/v1/graphs/{:id}/presign", post(graph_presign))
        .route("/v1/graphs/presign_check", post(graph_presign_check))
        .route("/metrics", get(metrics_handler))
        .layer(middleware::from_fn(print_req_and_resp_detail))
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
    Ok(())
}

/// This method introduces performance overhead and is temporarily used for debugging with the frontend.
/// It will be removed afterwards.
async fn print_req_and_resp_detail(
    _headers: HeaderMap,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let mut print_str = format!(
        "API Request: method:{}, uri:{}, content_type:{:?}, body:",
        req.method(),
        req.uri(),
        req.headers().get("content-type")
    );
    let (parts, body) = req.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    if !bytes.is_empty() {
        print_str = format!("{} {}", print_str, String::from_utf8_lossy(&bytes));
    }
    tracing::info!("{}", print_str);
    let req = Request::from_parts(parts, axum::body::Body::from(bytes));
    let resp = next.run(req).await;

    let mut print_str = format!("API Response: status:{}, body:", resp.status(),);
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    if !bytes.is_empty() {
        print_str = format!("{} {}", print_str, String::from_utf8_lossy(&bytes));
    }
    tracing::info!("{}", print_str);
    Ok(Response::from_parts(parts, axum::body::Body::from(bytes)))
}

#[cfg(test)]
mod tests {
    use crate::rpc_service;
    use prometheus_client::registry::Registry;
    use serde_json::json;
    use std::sync::{Arc, Mutex};
    use tracing::info;
    use tracing_subscriber::EnvFilter;
    use uuid::Uuid;

    const LISTEN_ADDRESS: &str = "127.0.0.1:8900";
    const TMEP_DB_PATH: &str = "/tmp/.bitvm2-node.db";

    fn init_tracing() {
        let _ = tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).try_init();
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn test_nodes_api() -> Result<(), Box<dyn std::error::Error>> {
        init_tracing();
        tokio::spawn(rpc_service::serve(
            LISTEN_ADDRESS.to_string(),
            TMEP_DB_PATH.to_string(),
            Arc::new(Mutex::new(Registry::default())),
        ));
        let client = reqwest::Client::new();

        info!("=====>test api: create node");
        let resp = client
            .post(format!("http://{}/v1/nodes", LISTEN_ADDRESS))
            .json(&json!({
                "peer_id": "ffc54e9ssscf37d9f87e",
                "actor": "Challenger",
                "btc_pub_key": "aaa58dsss965c464696560fdee91d039da6",
                "goat_addr": "58de965c464696560fdee91d039da6d49ef7770f30ef0"
            }))
            .send()
            .await?;
        info!("{:?}", resp);
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        info!("Post Response: {}", res_body);

        info!("=====>test api: get nodes");
        let resp = client
            .get(format!(
               "http://{}/v1/nodes?actor=Committee&status=Offline&offset=0&limit=5",
                LISTEN_ADDRESS
            ))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        info!("Post Response: {}", res_body);

        info!("=====>test api: get nodes overview");
        let resp = client
            .get(format!("http://{}/v1/nodes/overview", LISTEN_ADDRESS))
            .send()
            .await?;
        info!("{:?}", resp);
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        info!("Post Response: {}", res_body);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_bitvm2_api() -> Result<(), Box<dyn std::error::Error>> {
        init_tracing();
        tokio::spawn(rpc_service::serve(
            LISTEN_ADDRESS.to_string(),
            TMEP_DB_PATH.to_string(),
            Arc::new(Mutex::new(Registry::default())),
        ));
        info!("=====>test api: test_bridge_in_tx_prepare");
        let instance_id = Uuid::new_v4().to_string();
        let graph_id = Uuid::new_v4().to_string();
        let from_addr = "tb1qsyngu9wf2x46tlexhpjl4nugv0zxmgezsx5erl";
        let pegin_tx = "58de965c464696560fdee91d039da6d49ef7770f30ef07d892e21d8a80a16c2c";
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{}/v1/instances/action/bridge_in_tx_prepare", LISTEN_ADDRESS))
            .json(&json!({
                "instance_id": instance_id,
                "network": "testnet",
                "amount": 15000,
                "fee_rate": 80,
                "utxo": [
                    {
                        "txid": "ffc54e9cf37d9f87ebaa703537e93e20caece862d9bc1c463c487583905ec49c",
                        "vout": 0,
                        "value": 10000
                    },
                    {
                        "txid": "ffc54e9cf37d9f87ebaa703537e93e20caece862d9bc1c463c487583905ec49c",
                        "vout": 1,
                        "value": 20000
                    }
                ],
                "from": from_addr,
                "to": "E887312c0595a10aC88e32ebb8e9F660Ad9aB7F7"
            }))
            .send()
            .await?;
        info!("{:?}", resp);
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        info!("Post Response: {}", res_body);

        info!("=====>test api: get_instances");
        let resp = client
            .get(format!("http://{}/v1/instances/{}", LISTEN_ADDRESS, instance_id))
            .send()
            .await
            .expect("");
        assert!(resp.status().is_success());
        let res_body = resp.text().await.unwrap();
        info!("Post Response: {}", res_body);

        info!("=====>test api: get_instances_with_query_params");
        let resp = client
            .get(format!(
                "http://{}/v1/instances?from_addr={}&offset=0&limit=5",
                LISTEN_ADDRESS, from_addr
            ))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        info!("Post Response: {}", res_body);

        info!("=====>test api: instance overview");
        let resp = client
            .get(format!(
                "http://{}/v1/instances/overview",
                LISTEN_ADDRESS,
            ))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        info!("Post Response: {}", res_body);

        info!("=====>test api: create_graph");
        let resp = client
            .post(format!("http://{}/v1/graphs", LISTEN_ADDRESS))
            .json(&json!({
              "instance_id": instance_id,
                "graph_id": graph_id,
            }))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        info!("Post Response: {}", res_body);

        info!("=====>test api: peg_btc_mint");
        let resp = client
            .post(format!(
                "http://{}/v1/instances/{}/bridge_in/peg_gtc_mint",
                LISTEN_ADDRESS, instance_id
            ))
            .json(&json!({
                "graph_ids":[
                   graph_id
                ],
                "pegin_txid": pegin_tx
            }))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        info!("Post Response: {}", res_body);

        let graph_state = "OperatorPresigned";
        info!("=====>test api:update_graphs");
        let resp = client
            .put(format!("http://{}/v1/graphs/{}", LISTEN_ADDRESS, graph_id))
            .json(&json!({
                "graph":{
                    "graph_id": graph_id,
                    "instance_id": instance_id,
                    "graph_ipfs_base_url": "",
                    "pegin_txid": pegin_tx,
                    "amount": 1000,
                    "created_at": 1000000,
                    "updated_at": 1000000,
                    "status": graph_state,
                    "operator": "dddsdsdsdsdss"
                }
            }))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        info!("Post Response: {}", res_body);

        info!("=====>test api:get_graphs_list");
        let resp = client
            .get(format!("http://{}/v1/graphs?offset=0&limit=5", LISTEN_ADDRESS))
            .json(&json!({
                "status": graph_state,
                "pegin_txid":pegin_tx
            }))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        info!("Post Response: {}", res_body);

        info!("=====>test api:get_graph");
        let resp =
            client.get(format!("http://{}/v1/graphs/{}", LISTEN_ADDRESS, graph_id)).send().await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        info!("Post Response: {}", res_body);

        info!("=====>test api:graph_presign");
        let resp = client
            .post(format!("http://{}/v1/graphs/{}/presign", LISTEN_ADDRESS, graph_id))
            .json(&json!({
                "instance_id": instance_id,
                "graph_ipfs_base_url":"https://ipfs.io/ipfs/QmXxwbk8eA2bmKBy7YEjm5w1zKiG7g6ebF1JYfqWvnLnhH"
            }))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        info!("Post Response: {}", res_body);

        info!("=====>test api:graph_presign_check");
        let resp = client
            .post(format!("http://{}/v1/graphs/presign_check", LISTEN_ADDRESS))
            .json(&json!(
                {
                   "instance_id": instance_id,
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
