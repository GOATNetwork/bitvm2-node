mod bitvm2;

mod handler;
mod node;
pub(crate) mod proof;
pub mod routes;
pub use bitvm2::UTXO;

use crate::client::BTCClient;
use crate::env::get_network;
use crate::metrics_service::{MetricsState, metrics_handler, metrics_middleware};
use crate::rpc_service::handler::proof_handler::{
    get_groth16_proof, get_proof, get_proofs, get_proofs_overview,
};
use crate::rpc_service::handler::{bitvm2_handler::*, node_handler::*};
use axum::body::Body;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::put;
use axum::{
    Router, middleware,
    routing::{get, post},
};
pub use bitvm2::P2pUserData;
use bitvm2_lib::actors::Actor;
use http::{HeaderMap, Method, StatusCode};
use http_body_util::BodyExt;
use prometheus_client::registry::Registry;
use reqwest::Client;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};
use store::localdb::LocalDB;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tower_http::classify::ServerErrorsFailureClass;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use tracing::Level;

#[inline(always)]
pub fn current_time_secs() -> i64 {
    std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

pub struct AppState {
    pub local_db: LocalDB,
    pub btc_client: BTCClient,
    pub metrics_state: MetricsState,
    pub actor: Actor,
    pub peer_id: String,
    pub client: Client,
}

impl AppState {
    pub async fn create_arc_app_state(
        local_db: LocalDB,
        actor: Actor,
        peer_id: String,
        registry: Arc<Mutex<Registry>>,
    ) -> anyhow::Result<Arc<AppState>> {
        // let local_db = create_local_db(db_path).await;
        let btc_client = BTCClient::new(None, get_network());
        let metrics_state = MetricsState::new(registry);
        let client = Client::new();
        Ok(Arc::new(AppState { local_db, btc_client, metrics_state, actor, peer_id, client }))
    }
}

/// Serve the Multiaddr we are listening on and the host files.
// basic handler that responds with a static string
async fn root() -> &'static str {
    "Hello, World!"
}

pub async fn serve(
    addr: String,
    local_db: LocalDB,
    actor: Actor,
    peer_id: String,
    registry: Arc<Mutex<Registry>>,
    cancellation_token: CancellationToken,
) -> anyhow::Result<String> {
    let app_state = AppState::create_arc_app_state(local_db, actor, peer_id, registry).await?;
    let server = Router::new()
        .route(routes::ROOT, get(root))
        .route(routes::v1::NODES_BASE, post(create_node))
        .route(routes::v1::NODES_BASE, get(get_nodes))
        .route(routes::v1::NODES_BY_ID, get(get_node))
        .route(routes::v1::NODES_OVERVIEW, get(get_nodes_overview))
        .route(routes::v1::INSTANCES_SETTINGS, get(instance_settings))
        .route(routes::v1::INSTANCES_BASE, get(get_instances))
        .route(routes::v1::INSTANCES_BASE, post(create_instance))
        .route(routes::v1::INSTANCES_BY_ID, get(get_instance))
        .route(routes::v1::INSTANCES_BY_ID, put(update_instance))
        .route(routes::v1::INSTANCES_ACTION_BRIDGE_IN, post(bridge_in_tx_prepare))
        .route(routes::v1::INSTANCES_OVERVIEW, get(get_instances_overview))
        .route(routes::v1::GRAPHS_BY_ID, get(get_graph))
        .route(routes::v1::GRAPHS_BY_ID, put(update_graph))
        .route(routes::v1::GRAPHS_BASE, get(get_graphs))
        .route(routes::v1::GRAPHS_PRESIGN_CHECK, get(graph_presign_check))
        .route(routes::v1::GRAPHS_TXN_BY_ID, get(get_graph_txn))
        .route(routes::v1::GRAPHS_TX_BY_ID, get(get_graph_tx))
        .route(routes::v1::PROOFS_BASE, get(get_proofs))
        .route(routes::v1::PROOFS_BY_BLOCK_NUMBER, get(get_proof))
        .route(routes::v1::PROOFS_GROTH16_BY_BLOCK_NUMBER, get(get_groth16_proof))
        .route(routes::v1::PROOFS_OVERVIEW, get(get_proofs_overview))
        .route(routes::METRICS, get(metrics_handler))
        .layer(middleware::from_fn(print_req_and_resp_detail))
        .layer(CorsLayer::new().allow_headers(Any).allow_origin(Any).allow_methods(vec![
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ]))
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

    tokio::select! {
        result = axum::serve(listener, server) => {
            match result {
                Ok(_) => Ok("RPC server finished normally".to_string()),
                Err(e) => {
                    tracing::error!("RPC server error: {}", e);
                    Err(anyhow::anyhow!("RPC server error: {}", e))
                }
            }
        }
        _ = cancellation_token.cancelled() => {
            tracing::info!("RPC service received shutdown signal");
            Ok("rpc_shutdown".to_string())
        }
    }
}

/// This method introduces performance overhead and is temporarily used for debugging with the frontend.
/// It will be removed afterwards.
async fn print_req_and_resp_detail(
    _headers: HeaderMap,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // TODO remove after the service stabilizes.
    let mut print_str = format!(
        "API Request: method:{}, uri:{}, content_type:{:?}, body:",
        req.method(),
        req.uri(),
        req.headers().get("content-type")
    );
    let (parts, body) = req.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    if !bytes.is_empty() {
        print_str = format!("{print_str} {}", String::from_utf8_lossy(&bytes));
    }
    tracing::debug!("{}", print_str);
    let req = Request::from_parts(parts, axum::body::Body::from(bytes));
    let resp = next.run(req).await;

    let mut print_str = format!("API Response: status:{}, body:", resp.status(),);
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    if !bytes.is_empty() {
        print_str = format!("{print_str} {}", String::from_utf8_lossy(&bytes));
    }
    tracing::debug!("{}", print_str);
    Ok(Response::from_parts(parts, axum::body::Body::from(bytes)))
}

#[cfg(test)]
mod tests {
    use crate::client::create_local_db;
    use crate::env::{
        ENV_GOAT_CHAIN_URL, ENV_GOAT_GATEWAY_CONTRACT_ADDRESS, ENV_PROOF_SEVER_URL, IpfsTxName,
    };
    use crate::rpc_service::bitvm2::UTXO;
    use crate::rpc_service::{self, Actor, routes};
    use crate::utils::{
        generate_local_key, generate_random_bytes, get_graph, get_rand_btc_address_p2pkh,
        get_rand_btc_address_p2wpkh, get_rand_goat_address, store_graph, temp_file,
        update_graph_fields,
    };
    use bitcoin::Network;
    use bitvm2_lib::types::Bitvm2Graph;
    use http::Method;
    use prometheus_client::registry::Registry;
    use reqwest::Client;
    use serde::Deserialize;
    use serde_json::{Value, json};
    use std::fs;
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use store::{GoatTxProveStatus, GoatTxRecord, GoatTxType, GraphStatus};
    use tokio::time::sleep;
    use tokio_util::sync::CancellationToken;
    use tracing::info;
    use tracing_subscriber::EnvFilter;
    use uuid::Uuid;

    struct ApiTestItem {
        pub tag: String,
        pub url: String,
        pub json_payload: Option<Value>,
        pub method: Method,
        pub expe_res: bool,
    }

    impl ApiTestItem {
        async fn do_test(&self, client: &Client) -> anyhow::Result<()> {
            info!("Start test api: {}", self.tag);
            let mut request_builder = match self.method {
                Method::POST => client.post(self.url.clone()),
                Method::GET => client.get(self.url.clone()),
                Method::PUT => client.put(self.url.clone()),
                Method::DELETE => client.delete(self.url.clone()),
                _ => {
                    return Err(anyhow::anyhow!("wrong method"));
                }
            };
            if let Some(json_payload) = self.json_payload.clone() {
                request_builder = request_builder.json(&json_payload);
            }

            let resp = request_builder.send().await?;
            assert_eq!(resp.status().is_success(), self.expe_res);
            Ok(())
        }
    }

    async fn do_batch_tests(
        batch_tag: &str,
        client: &Client,
        items: &[ApiTestItem],
    ) -> anyhow::Result<()> {
        info!("Start batch test:{batch_tag}");
        for item in items {
            item.do_test(client).await?;
        }
        info!("Finish batch test:{batch_tag}");
        Ok(())
    }
    fn init(remote_proof_server: Option<String>) {
        unsafe {
            std::env::set_var("RUST_LOG", "info");
            std::env::set_var(ENV_GOAT_CHAIN_URL, "https://rpc.testnet3.goat.network");
            std::env::set_var(
                ENV_GOAT_GATEWAY_CONTRACT_ADDRESS,
                "0xeD8AeeD334fA446FA03Aa00B28aFf02FA8aC02df",
            );
            if let Some(remote_proof_server) = remote_proof_server {
                std::env::set_var(ENV_PROOF_SEVER_URL, remote_proof_server);
            }
        }
        let _ = tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).try_init();
    }

    fn available_addr() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().to_string()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_nodes_api() -> Result<(), Box<dyn std::error::Error>> {
        init(None);
        let addr = available_addr();
        let actor = Actor::Challenger;
        let local_key = generate_local_key();
        let peer_id = local_key.public().to_peer_id().to_string();
        let pub_key = hex::encode(generate_random_bytes(33));
        let goat_addr = format!("0x{}", hex::encode(generate_random_bytes(20)));
        let local_db = create_local_db(&temp_file()).await;
        tokio::spawn(rpc_service::serve(
            addr.clone(),
            local_db,
            actor.clone(),
            peer_id.clone(),
            Arc::new(Mutex::new(Registry::default())),
            CancellationToken::new(),
        ));
        sleep(Duration::from_secs(1)).await;
        let client = Client::new();
        let api_test_items = [
            ApiTestItem {
                tag: format!("{} crate node", routes::v1::NODES_BASE),
                url: format!("http://{addr}{}", routes::v1::NODES_BASE),
                json_payload: Some(json!({
                    "peer_id": peer_id,
                    "actor": actor.to_string(),
                    "btc_pub_key": pub_key,
                    "goat_addr": goat_addr,
                    "socket_addr":"127.0.0.1:8080",
                    "reward": 0,
                })),
                method: Method::POST,
                expe_res: true,
            },
            ApiTestItem {
                tag: format!("{} get node", routes::v1::NODES_BASE),
                url: format!("http://{addr}{}/{peer_id}", routes::v1::NODES_BASE),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
            },
            ApiTestItem {
                tag: format!("{} get nodes", routes::v1::NODES_BASE),
                url: format!(
                    "http://{addr}{}?actor={actor}&status=Online&offset=0&limit=5",
                    routes::v1::NODES_BASE
                ),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
            },
            ApiTestItem {
                tag: routes::v1::NODES_OVERVIEW.to_string(),
                url: format!("http://{addr}{}", routes::v1::NODES_OVERVIEW),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
            },
        ];
        do_batch_tests("node apis", &client, &api_test_items).await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_bitvm2_api() -> Result<(), Box<dyn std::error::Error>> {
        init(None);
        let addr = available_addr();
        let actor = Actor::Challenger;
        let local_key = generate_local_key();
        let peer_id = local_key.public().to_peer_id().to_string();
        let local_db = create_local_db(&temp_file()).await;
        tokio::spawn(rpc_service::serve(
            addr.clone(),
            local_db.clone(),
            actor.clone(),
            peer_id.clone(),
            Arc::new(Mutex::new(Registry::default())),
            CancellationToken::new(),
        ));
        sleep(Duration::from_secs(1)).await;
        let instance_id_0 = Uuid::new_v4().to_string();
        let instance_id_1 = Uuid::new_v4().to_string();
        let graph_id_0 = Uuid::new_v4().to_string();
        let graph_id_1 = Uuid::new_v4();
        let from_addr = get_rand_btc_address_p2wpkh(Network::Testnet);
        let client = reqwest::Client::new();
        info!("load_test_graph");
        let bitvm2_graph: Bitvm2Graph = load_test_bitvm2_graph();
        store_graph(
            &local_db,
            Uuid::from_str(&instance_id_0)?,
            graph_id_1,
            &bitvm2_graph,
            Some(GraphStatus::Disprove.to_string()),
        )
        .await?;
        let graph = get_graph(&local_db, Some(Uuid::from_str(&instance_id_0)?), graph_id_1).await?;
        update_graph_fields(&local_db, graph_id_1, None, None, graph.kickoff_txid, None, None)
            .await?;
        let pub_key = bitvm2_graph.parameters.operator_pubkey.to_string();
        let mut api_test_items = vec![
            ApiTestItem {
                tag: routes::v1::NODES_BASE.to_string(),
                url: format!("http://{addr}{}", routes::v1::NODES_BASE),
                json_payload: Some(json!({
                    "peer_id": peer_id,
                    "actor": actor.to_string(),
                    "btc_pub_key": pub_key,
                    "goat_addr": get_rand_goat_address(),
                    "socket_addr":"127.0.0.1:8080",
                    "reward": 0,
                })),
                method: Method::POST,
                expe_res: true,
            },
            ApiTestItem {
                tag: routes::v1::INSTANCES_SETTINGS.to_string(),
                url: format!("http://{addr}{}", routes::v1::INSTANCES_SETTINGS),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
            },
            ApiTestItem {
                tag: routes::v1::INSTANCES_ACTION_BRIDGE_IN.to_string(),
                url: format!("http://{addr}{}", routes::v1::INSTANCES_ACTION_BRIDGE_IN),
                json_payload: Some(json!({
                    "instance_id": instance_id_0,
                    "network": "testnet",
                    "amount": 1500000000,
                    "fee_rate": 8,
                    "utxo": [
                        {
                            "txid": hex::encode(generate_random_bytes(32)),
                            "vout": 0,
                            "value": 1000000000
                        },
                        {
                            "txid": hex::encode(generate_random_bytes(32)),
                            "vout": 1,
                            "value": 2000000000
                        }
                    ],
                    "from": from_addr,
                    "to": format!("0x{}", hex::encode(generate_random_bytes(20)))
                })),
                method: Method::POST,
                expe_res: true,
            },
            ApiTestItem {
                tag: format!("{} input wrong btc address", routes::v1::INSTANCES_ACTION_BRIDGE_IN),
                url: format!("http://{addr}{}", routes::v1::INSTANCES_ACTION_BRIDGE_IN),
                json_payload: Some(json!({
                    "instance_id": Uuid::new_v4().to_string(),
                    "network": "testnet",
                    "amount": 15000,
                    "fee_rate": 80,
                    "utxo": [
                        {
                            "txid": hex::encode(generate_random_bytes(32)),
                            "vout": 0,
                            "value": 10000
                        },
                        {
                            "txid": hex::encode(generate_random_bytes(32)),
                            "vout": 1,
                            "value": 20000
                        }
                    ],
                    "from": get_rand_btc_address_p2pkh(Network::Testnet),
                    "to": format!("0x{}", hex::encode(generate_random_bytes(20)))
                })),
                method: Method::POST,
                expe_res: false,
            },
            ApiTestItem {
                tag: format!("{} input wrong goat address", routes::v1::INSTANCES_ACTION_BRIDGE_IN),
                url: format!("http://{addr}{}", routes::v1::INSTANCES_ACTION_BRIDGE_IN),
                json_payload: Some(json!({
                    "instance_id": Uuid::new_v4().to_string(),
                    "network": "testnet",
                    "amount": 15000,
                    "fee_rate": 80,
                    "utxo": [
                        {
                            "txid": hex::encode(generate_random_bytes(32)),
                            "vout": 0,
                            "value": 10000
                        },
                        {
                            "txid": hex::encode(generate_random_bytes(32)),
                            "vout": 1,
                            "value": 20000
                        }
                    ],
                    "from": from_addr,
                    "to": format!("0x{}", get_rand_btc_address_p2pkh(Network::Testnet)),
                })),
                method: Method::POST,
                expe_res: false,
            },
            ApiTestItem {
                tag: format!("{} input wrong value", routes::v1::INSTANCES_ACTION_BRIDGE_IN),
                url: format!("http://{addr}{}", routes::v1::INSTANCES_ACTION_BRIDGE_IN),
                json_payload: Some(json!({
                    "instance_id": Uuid::new_v4().to_string(),
                    "network": "testnet",
                    "amount": 35000,
                    "fee_rate": 80,
                    "utxo": [
                        {
                            "txid": hex::encode(generate_random_bytes(32)),
                            "vout": 0,
                            "value": 10000
                        },
                        {
                            "txid": hex::encode(generate_random_bytes(32)),
                            "vout": 1,
                            "value": 20000
                        }
                    ],
                    "from": from_addr,
                    "to":format!("0x{}", hex::encode(generate_random_bytes(20))),
                })),
                method: Method::POST,
                expe_res: false,
            },
            ApiTestItem {
                tag: format!(
                    "{} input wrong instance_id (repeat)",
                    routes::v1::INSTANCES_ACTION_BRIDGE_IN
                ),
                url: format!("http://{addr}{}", routes::v1::INSTANCES_ACTION_BRIDGE_IN),
                json_payload: Some(json!({
                    "instance_id": instance_id_0,
                    "network": "testnet",
                    "amount": 10000,
                    "fee_rate": 80,
                    "utxo": [
                        {
                            "txid": hex::encode(generate_random_bytes(32)),
                            "vout": 0,
                            "value": 10000
                        },
                        {
                            "txid": hex::encode(generate_random_bytes(32)),
                            "vout": 1,
                            "value": 20000
                        }
                    ],
                    "from": from_addr,
                    "to":format!("0x{}", hex::encode(generate_random_bytes(20))),
                })),
                method: Method::POST,
                expe_res: false,
            },
            ApiTestItem {
                tag: format!("{} create instance", routes::v1::INSTANCES_BASE),
                url: format!("http://{addr}{}", routes::v1::INSTANCES_BASE),
                json_payload: Some(json!({
                   "instance":{
                    "instance_id": instance_id_1,
                    "network": "testnet",
                    "bridge_path": 0,
                    "from_addr": get_rand_btc_address_p2wpkh(Network::Testnet),
                    "to_addr": get_rand_goat_address(),
                    "amount": 20000,
                    "status": "Committed",
                    "goat_txid": hex::encode(generate_random_bytes(32)),
                    "btc_txid": "",
                    "input_uxtos":"",
                    "fee": 1000,
                    "created_at":  SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
                    "updated_at":  SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
                }
                })),
                method: Method::POST,
                expe_res: true,
            },
            ApiTestItem {
                tag: format!("{} update instance", routes::v1::INSTANCES_BASE),
                url: format!("http://{addr}{}/{instance_id_1}", routes::v1::INSTANCES_BASE),
                json_payload: Some(json!({
                   "instance":{
                    "instance_id": instance_id_1,
                    "network": "testnet",
                    "bridge_path": 0,
                    "from_addr": get_rand_btc_address_p2wpkh(Network::Testnet),
                    "to_addr": get_rand_goat_address(),
                    "amount": 80000,
                    "status": "Presigned",
                    "goat_txid": hex::encode(generate_random_bytes(32)),
                    "btc_txid": "18f553006e17b0adc291a75f48e77687cdd58e0049bb4a976d69e5358ba3f59b",
                    "pegin_txid": "18f553006e17b0adc291a75f48e77687cdd58e0049bb4a976d69e5358ba3f59b",
                    "input_uxtos": serde_json::to_string(&[UTXO { txid: "".to_string(), vout: 0, value: 0 }]).unwrap(),
                    "fee": 2000,
                    "created_at": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
                    "updated_at": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
                }
                })),
                method: Method::PUT,
                expe_res: true,
            },
            ApiTestItem {
                tag: format!(
                    "{} update instance: wrong instance_id not match",
                    routes::v1::INSTANCES_BASE
                ),
                url: format!("http://{addr}{}/{instance_id_1}", routes::v1::INSTANCES_BASE),
                json_payload: Some(json!({
                   "instance":{
                    "instance_id": Uuid::new_v4(),
                    "network": "testnet",
                    "bridge_path": 0,
                    "from_addr": get_rand_btc_address_p2wpkh(Network::Testnet),
                    "to_addr": get_rand_goat_address(),
                    "amount": 80000,
                    "status": "Presigned",
                    "goat_txid": hex::encode(generate_random_bytes(32)),
                    "btc_txid": "18f553006e17b0adc291a75f48e77687cdd58e0049bb4a976d69e5358ba3f59b",
                    "pegin_txid": "18f553006e17b0adc291a75f48e77687cdd58e0049bb4a976d69e5358ba3f59b",
                    "input_uxtos": serde_json::to_string(&[UTXO { txid: "".to_string(), vout: 0, value: 0 }]).unwrap(),
                    "fee": 2000,
                    "created_at": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
                    "updated_at": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
                }
                })),
                method: Method::PUT,
                expe_res: false,
            },
            ApiTestItem {
                tag: format!("{} get instance", routes::v1::INSTANCES_BASE),
                url: format!("http://{addr}{}/{instance_id_1}", routes::v1::INSTANCES_BASE),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
            },
            ApiTestItem {
                tag: format!("{} get instance: wrong instance_id", routes::v1::INSTANCES_BASE),
                url: format!("http://{addr}{}/{}", routes::v1::INSTANCES_BASE, Uuid::new_v4()),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
            },
            ApiTestItem {
                tag: format!("{} get instances", routes::v1::INSTANCES_BASE),
                url: format!(
                    "http://{addr}{}?from_addr={from_addr}&offset=0&limit=5",
                    routes::v1::INSTANCES_BASE
                ),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
            },
            ApiTestItem {
                tag: format!("{} get instances: wrong from addr", routes::v1::INSTANCES_BASE),
                url: format!(
                    "http://{addr}{}?from_addr={}&offset=0&limit=5",
                    routes::v1::INSTANCES_BASE,
                    get_rand_btc_address_p2wpkh(Network::Testnet),
                ),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
            },
            ApiTestItem {
                tag: routes::v1::INSTANCES_OVERVIEW.to_string(),
                url: format!("http://{addr}{}", routes::v1::INSTANCES_OVERVIEW),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
            },
            ApiTestItem {
                tag: format!("{} update or insert graph", routes::v1::GRAPHS_BASE),
                url: format!("http://{addr}{}/{graph_id_0}", routes::v1::GRAPHS_BASE),
                json_payload: Some(json!({
                  "graph":{
                    "graph_id": graph_id_0,
                    "instance_id": instance_id_0,
                    "graph_ipfs_base_url": "",
                    "pegin_txid": hex::encode(generate_random_bytes(32)),
                    "amount": 1000,
                    "created_at": 1000000,
                    "updated_at": 1000000,
                    "status": "OperatorPresigned",
                    "bridge_out_start_at":1000000,
                    "bridge_out_to_addr": "",
                    "bridge_out_from_addr":"",
                    "zkm_version":"v1.1.0",
                    "operator":pub_key.to_string()
                }
                })),
                method: Method::PUT,
                expe_res: true,
            },
            ApiTestItem {
                tag: format!(
                    "{} update or insert graph, graph_id not match",
                    routes::v1::GRAPHS_BASE
                ),
                url: format!("http://{addr}{}/{}", routes::v1::GRAPHS_BASE, Uuid::new_v4()),
                json_payload: Some(json!({
                  "graph":{
                    "graph_id": graph_id_0,
                    "instance_id": instance_id_0,
                    "graph_ipfs_base_url": "",
                    "pegin_txid": hex::encode(generate_random_bytes(32)),
                    "amount": 1000,
                    "created_at": 1000000,
                    "updated_at": 1000000,
                    "status": "OperatorPresigned",
                    "bridge_out_start_at":1000000,
                    "bridge_out_to_addr": "",
                    "bridge_out_from_addr":"",
                    "zkm_version":"v1.1.0",
                    "operator":pub_key.to_string()
                }
                })),
                method: Method::PUT,
                expe_res: false,
            },
            ApiTestItem {
                tag: format!("{} get graph by id", routes::v1::GRAPHS_BASE),
                url: format!("http://{addr}{}/{graph_id_0}", routes::v1::GRAPHS_BASE),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
            },
            ApiTestItem {
                tag: format!("{} get graph by id wrong id", routes::v1::GRAPHS_BASE),
                url: format!("http://{addr}{}/{}", routes::v1::GRAPHS_BASE, Uuid::new_v4()),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
            },
            ApiTestItem {
                tag: format!("{} get graphs", routes::v1::GRAPHS_BASE),
                url: format!("http://{addr}{}?offset=0&limit=10", routes::v1::GRAPHS_BASE),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
            },
            ApiTestItem {
                tag: format!("{} get graphs", routes::v1::GRAPHS_BASE),
                url: format!(
                    "http://{addr}{}?status=Asserting&offset=0&limit=10",
                    routes::v1::GRAPHS_BASE
                ),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
            },
            ApiTestItem {
                tag: format!("{} get graphs check", routes::v1::GRAPHS_PRESIGN_CHECK),
                url: format!(
                    "http://{addr}{}?instance_id={instance_id_0}",
                    routes::v1::GRAPHS_PRESIGN_CHECK
                ),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
            },
            ApiTestItem {
                tag: format!(
                    "{} get graphs check wrong instance_id",
                    routes::v1::GRAPHS_PRESIGN_CHECK
                ),
                url: format!(
                    "http://{addr}{}?instance_id={}",
                    routes::v1::GRAPHS_PRESIGN_CHECK,
                    Uuid::new_v4()
                ),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
            },
            ApiTestItem {
                tag: format!("{} get txn", routes::v1::GRAPHS_BASE),
                url: format!("http://{addr}{}/{graph_id_1}/txn", routes::v1::GRAPHS_BASE),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
            },
            ApiTestItem {
                tag: format!("{} get txn, raw data is null", routes::v1::GRAPHS_BASE),
                url: format!("http://{addr}{}/{graph_id_0}/txn", routes::v1::GRAPHS_BASE),
                json_payload: None,
                method: Method::GET,
                expe_res: false,
            },
            ApiTestItem {
                tag: format!("{} get txn, wrong graph_id", routes::v1::GRAPHS_BASE),
                url: format!("http://{addr}{}/{}/txn", routes::v1::GRAPHS_BASE, Uuid::new_v4()),
                json_payload: None,
                method: Method::GET,
                expe_res: false,
            },
        ];

        for tx_name in [
            IpfsTxName::Pegin.as_str(),
            IpfsTxName::Kickoff.as_str(),
            IpfsTxName::AssertCommit0.as_str(),
            IpfsTxName::AssertCommit1.as_str(),
            IpfsTxName::AssertCommit2.as_str(),
            IpfsTxName::AssertCommit3.as_str(),
            IpfsTxName::AssertInit.as_str(),
            IpfsTxName::AssertFinal.as_str(),
            IpfsTxName::Challenge.as_str(),
            IpfsTxName::Take1.as_str(),
            IpfsTxName::Take2.as_str(),
            IpfsTxName::Disprove.as_str(),
        ] {
            api_test_items.push(ApiTestItem {
                tag: format!("{} get {tx_name} tx", routes::v1::GRAPHS_BASE),
                url: format!(
                    "http://{addr}{}/{graph_id_1}/tx?tx_name={tx_name}",
                    routes::v1::GRAPHS_BASE
                ),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
            });
        }
        api_test_items.push(ApiTestItem {
            tag: format!("{} get tx fail as wrong tx_name ", routes::v1::GRAPHS_BASE),
            url: format!(
                "http://{addr}{}/{graph_id_1}/tx?tx_name=testfor",
                routes::v1::GRAPHS_BASE
            ),
            json_payload: None,
            method: Method::GET,
            expe_res: false,
        });
        api_test_items.push(ApiTestItem {
            tag: format!("{} get tx fail as wrong graph id", routes::v1::GRAPHS_BASE),
            url: format!(
                "http://{addr}{}/{}/tx?tx_name=assert-commit2.hex",
                routes::v1::GRAPHS_BASE,
                Uuid::new_v4(),
            ),
            json_payload: None,
            method: Method::GET,
            expe_res: false,
        });
        do_batch_tests("bitvm2 apis", &client, &api_test_items).await?;
        Ok(())
    }

    fn load_test_bitvm2_graph() -> Bitvm2Graph {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("tests_data/test_bitvm2_graph.json");
        serde_json::from_str(
            &fs::read_to_string(&path).expect("fail to read test bitvm_graph.json"),
        )
        .unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_proof_api() -> Result<(), Box<dyn std::error::Error>> {
        let addr_operator = available_addr();
        let addr_relayer = available_addr();
        init(Some(addr_operator.clone()));
        info!("Start relayer server");
        let relayer = Actor::Relayer;
        let relayer_peer_id = generate_local_key().public().to_peer_id().to_string();
        let relayer_local_db = create_local_db(&temp_file()).await;
        tokio::spawn(rpc_service::serve(
            addr_relayer.clone(),
            relayer_local_db,
            relayer,
            relayer_peer_id,
            Arc::new(Mutex::new(Registry::default())),
            CancellationToken::new(),
        ));

        info!("Start operator server");
        let operator = Actor::Operator;
        let operator_peer_id = generate_local_key().public().to_peer_id().to_string();
        let operator_local_db = create_local_db(&temp_file()).await;
        tokio::spawn(rpc_service::serve(
            addr_operator.clone(),
            operator_local_db.clone(),
            operator,
            operator_peer_id,
            Arc::new(Mutex::new(Registry::default())),
            CancellationToken::new(),
        ));

        let (mut start_block, end_block) = (100, 106);
        let proving_time = 200_i64;
        let groth16_block_number = end_block - 1;
        let graph_id = Uuid::new_v4();
        info!("init  proof data");
        loop {
            let mut storage_processor = operator_local_db.acquire().await?;
            storage_processor.create_block_proving_task(start_block, "queued".to_string()).await?;
            storage_processor.create_aggregation_task(start_block, "queued".to_string()).await?;
            storage_processor
                .create_groth16_task(
                    start_block,
                    start_block,
                    format!("{start_block}"),
                    "queued".to_string(),
                )
                .await?;
            if start_block == end_block {
                break;
            }
            tokio::time::sleep(Duration::from_millis(proving_time as u64)).await;

            storage_processor
                .update_block_proved(
                    start_block,
                    proving_time,
                    10000,
                    &[],
                    &[],
                    "verifier_id".to_string(),
                    "v1.0.0",
                    "proved".to_string(),
                )
                .await?;
            storage_processor
                .update_aggregation_succ(
                    start_block,
                    proving_time,
                    10000,
                    &[],
                    &[],
                    "verifier_id".to_string(),
                    "v1.0.0",
                    "proved".to_string(),
                )
                .await?;

            if start_block == groth16_block_number {
                let proof_info = get_proof_info();
                storage_processor
                    .update_groth16_succ(
                        start_block,
                        0,
                        proving_time,
                        10000,
                        &hex::decode(proof_info.proof).unwrap(),
                        &hex::decode(proof_info.public_value).unwrap(),
                        proof_info.verifier_id.clone(),
                        &proof_info.zkm_version,
                        "proved".to_string(),
                    )
                    .await?;
                storage_processor
                    .create_verifier_key(
                        &proof_info.zkm_version,
                        &hex::decode(proof_info.verifier_key).unwrap(),
                    )
                    .await?;
                storage_processor
                    .create_or_update_goat_tx_record(&GoatTxRecord {
                        instance_id: Uuid::new_v4(),
                        graph_id,
                        tx_type: GoatTxType::ProceedWithdraw.to_string(),
                        tx_hash: "".to_string(),
                        height: groth16_block_number,
                        is_local: false,
                        prove_status: GoatTxProveStatus::Proved.to_string(),
                        extra: None,
                        created_at: 0,
                    })
                    .await?;
            }
            start_block += 1;
        }

        sleep(Duration::from_secs(1)).await;
        let client = reqwest::Client::new();

        let api_test_items = [
            ApiTestItem {
                tag: format!("{} through operator", routes::v1::PROOFS_OVERVIEW),
                url: format!("http://{addr_operator}{}", routes::v1::PROOFS_OVERVIEW),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
            },
            ApiTestItem {
                tag: format!("{} through relayer", routes::v1::PROOFS_OVERVIEW),
                url: format!("http://{addr_relayer}{}", routes::v1::PROOFS_OVERVIEW),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
            },
            ApiTestItem {
                tag: format!(
                    "{} get proof by block_number through operator",
                    routes::v1::PROOFS_BASE
                ),
                url: format!(
                    "http://{addr_operator}{}/{groth16_block_number}",
                    routes::v1::PROOFS_BASE
                ),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
            },
            ApiTestItem {
                tag: format!(
                    "{} get proof by block_number through relayer",
                    routes::v1::PROOFS_BASE
                ),
                url: format!(
                    "http://{addr_relayer}{}/{groth16_block_number}",
                    routes::v1::PROOFS_BASE
                ),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
            },
            ApiTestItem {
                tag: format!("{} get proofs  through operator", routes::v1::PROOFS_BASE),
                url: format!(
                    "http://{addr_operator}{}?block_number={groth16_block_number}",
                    routes::v1::PROOFS_BASE
                ),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
            },
            ApiTestItem {
                tag: format!("{} get proofs through relayer", routes::v1::PROOFS_BASE),
                url: format!(
                    "http://{addr_relayer}{}?block_number={groth16_block_number}",
                    routes::v1::PROOFS_BASE
                ),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
            },
            ApiTestItem {
                tag: format!("{} get proofs by graph_id", routes::v1::PROOFS_BASE),
                url: format!(
                    "http://{addr_operator}{}?graph_id={graph_id}",
                    routes::v1::PROOFS_BASE
                ),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
            },
            ApiTestItem {
                tag: format!("{} get proofs fail as wrong input", routes::v1::PROOFS_BASE),
                url: format!("http://{addr_relayer}{}?block_range=6", routes::v1::PROOFS_BASE),
                json_payload: None,
                method: Method::GET,
                expe_res: false,
            },
            ApiTestItem {
                tag: format!("{} get proofs fail  as wrong input", routes::v1::PROOFS_BASE),
                url: format!(
                    "http://{addr_relayer}{}?graph_id={}",
                    routes::v1::PROOFS_BASE,
                    Uuid::new_v4()
                ),
                json_payload: None,
                method: Method::GET,
                expe_res: false,
            },
            ApiTestItem {
                tag: format!("{} get groth16 proof through operator", routes::v1::PROOFS_BASE),
                url: format!(
                    "http://{addr_operator}{}/{groth16_block_number}",
                    routes::v1::PROOFS_GROTH16_BASE
                ),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
            },
            ApiTestItem {
                tag: format!("{} get groth16 proof through relayer", routes::v1::PROOFS_BASE),
                url: format!(
                    "http://{addr_relayer}{}/{groth16_block_number}",
                    routes::v1::PROOFS_GROTH16_BASE
                ),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
            },
        ];
        do_batch_tests("node apis", &client, &api_test_items).await?;
        Ok(())
    }

    #[derive(Clone, Debug, Deserialize)]
    struct ProofInfo {
        pub proof: String,
        pub public_value: String,
        pub zkm_version: String,
        pub verifier_id: String,
        pub verifier_key: String,
    }

    fn get_proof_info() -> ProofInfo {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("tests_data/test_proof_v1.1.0.json");
        serde_json::from_str(
            &fs::read_to_string(&path).expect("fail to read test proof_v1.1.0.json"),
        )
        .unwrap()
    }
}
