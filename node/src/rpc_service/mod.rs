mod bitvm2;
mod cors_config;
pub mod handler;
mod node;
pub(crate) mod proof;
mod response;
pub mod routes;
pub mod validation;

use crate::env::{get_goat_network, get_network, goat_config_from_env};
use crate::metrics_service::{MetricsState, metrics_handler, metrics_middleware};
use crate::rpc_service::cors_config::CorsConfig;
use crate::rpc_service::handler::{
    bridge_in_request_tag, get_commit_chain_blocks_desc, get_graph, get_graph_neighbor_ids,
    get_graph_tx, get_graph_txn, get_graphs, get_header_chain_blocks_desc, get_instance,
    get_instances, get_instances_overview, get_node, get_nodes, get_nodes_overview, get_proof,
    get_ready_to_kickoff_graph, get_unsigned_pegin_txn, instance_settings,
};
use axum::body::Body;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::put;
use axum::{Router, middleware, routing::get};
use bitvm2_lib::actors::Actor;
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
use client::http_client::async_client::HttpAsyncClient;
use http::{HeaderMap, StatusCode};
use http_body_util::BodyExt;
use prometheus_client::registry::Registry;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};
use store::localdb::LocalDB;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tower_http::classify::ServerErrorsFailureClass;
use tower_http::cors::CorsLayer;
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use tracing::Level;

#[inline(always)]
pub fn current_time_secs() -> i64 {
    std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

/// Create secure CORS layer
pub fn create_secure_cors_layer() -> CorsLayer {
    let cors_config = CorsConfig::from_env();

    // Validate configuration security
    let warnings = cors_config.validate_security();
    for warning in warnings {
        tracing::warn!("CORS security warning: {}", warning);
    }

    cors_config.create_cors_layer()
}

pub struct AppState {
    pub local_db: LocalDB,
    pub btc_client: BTCClient,
    pub goat_client: GOATClient,
    pub http_client: HttpAsyncClient,
    pub metrics_state: MetricsState,
    pub actor: Actor,
    pub peer_id: String,
}

impl AppState {
    pub async fn create_arc_app_state(
        local_db: LocalDB,
        actor: Actor,
        peer_id: String,
        registry: Arc<Mutex<Registry>>,
    ) -> anyhow::Result<Arc<AppState>> {
        let btc_client = BTCClient::new(get_network(), None);
        let goat_client = GOATClient::new(goat_config_from_env().await, get_goat_network());
        let metrics_state = MetricsState::new(registry);
        let http_client = HttpAsyncClient::new(None);
        Ok(Arc::new(AppState {
            local_db,
            btc_client,
            goat_client,
            metrics_state,
            actor,
            peer_id,
            http_client,
        }))
    }
}

/// Root path handler
///
/// Returns a simple welcome message for health checks and basic connection testing.
///
/// # Returns
///
/// - `200 OK`: Returns welcome message
///
/// # Example
///
/// ```http
/// GET /
/// ```
///
/// Response example: "Hello World"
///
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
        .route(routes::v1::NODES_BASE, get(get_nodes))
        .route(routes::v1::NODES_BY_ID, get(get_node))
        .route(routes::v1::NODES_OVERVIEW, get(get_nodes_overview))
        .route(routes::v1::INSTANCES_SETTINGS, get(instance_settings))
        .route(routes::v1::INSTANCES_BRIDGE_IN_REQUEST_TAG, put(bridge_in_request_tag))
        .route(routes::v1::INSTANCES_BASE, get(get_instances))
        .route(routes::v1::INSTANCES_BY_ID, get(get_instance))
        .route(routes::v1::INSTANCES_OVERVIEW, get(get_instances_overview))
        .route(routes::v1::INSTANCES_UNSIGNED_PEGIN_TXN, get(get_unsigned_pegin_txn))
        .route(routes::v1::GRAPHS_BY_ID, get(get_graph))
        .route(routes::v1::GRAPHS_BASE, get(get_graphs))
        .route(routes::v1::GRAPHS_READY_TO_KICKOFF, get(get_ready_to_kickoff_graph))
        .route(routes::v1::GRAPHS_TXN_BY_ID, get(get_graph_txn))
        .route(routes::v1::GRAPHS_TX_BY_ID, get(get_graph_tx))
        .route(routes::v1::GRAPHS_NEIGHBOR_IDS, get(get_graph_neighbor_ids))
        .route(routes::v1::PROOFS_BLOCKS_HEADER_CHAIN_DESC, get(get_header_chain_blocks_desc))
        .route(routes::v1::PROOFS_BLOCKS_COMMIT_CHAIN_CHAIN_DESC, get(get_commit_chain_blocks_desc))
        .route(routes::v1::PROOFS_BASE, get(get_proof))
        .route(routes::METRICS, get(metrics_handler))
        .layer(middleware::from_fn(print_req_and_resp_detail))
        .layer(create_secure_cors_layer())
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
    use crate::env::{
        ENV_GOAT_CHAIN_URL, ENV_GOAT_GATEWAY_CONTRACT_ADDRESS, ENV_PROOF_SEVER_URL, get_network,
    };
    use crate::rpc_service::bitvm2::{
        BRIDGE_IN_AMOUNTS, GraphGetResponse, GraphListResponse, InstanceGetResponse,
        InstanceListResponse, InstanceOverviewResponse, InstanceSettingResponse,
    };
    use crate::rpc_service::node::{NodeListResponse, NodeOverViewResponse};
    use crate::rpc_service::{self, Actor, current_time_secs, routes};
    use crate::utils::{
        generate_local_key, generate_random_bytes, get_rand_btc_address_p2wpkh,
        get_rand_goat_address, temp_file,
    };
    use bitvm2_lib::types::Bitvm2Graph;
    use client::Utxo;
    use http::Method;
    use prometheus_client::registry::Registry;
    use reqwest::Client;
    use secp256k1::Secp256k1;
    use serde_json::{Value, json};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use store::localdb::LocalDB;
    use store::{Graph, GraphStatus, Instance, InstanceBridgeInStatus, Node, create_local_db};
    use tokio::time::sleep;
    use tokio_util::sync::CancellationToken;
    use tracing::{error, info};
    use tracing_subscriber::EnvFilter;
    use uuid::Uuid;

    struct ApiTestItem {
        pub tag: String,
        pub url: String,
        pub json_payload: Option<Value>,
        pub method: Method,
        pub expe_res: bool,
        pub resp_validation: Option<Box<dyn Fn(String) -> bool>>,
    }

    impl ApiTestItem {
        async fn do_test(&self, client: &Client) -> anyhow::Result<()> {
            eprintln!("Start test api: {}", self.tag);
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
            let actual_status = resp.status().is_success();
            if actual_status != self.expe_res {
                let data = resp.text().await?;
                eprintln!(
                    "Test api '{}' failed: expected status {}, got {}, resp: {data}",
                    self.tag, self.expe_res, actual_status
                );
                error!(
                    "Test api '{}' failed: expected status {}, got {}, resp: {data}",
                    self.tag, self.expe_res, actual_status
                );
                return Err(anyhow::anyhow!(
                    "Test failed: expected status {}, got {}",
                    self.expe_res,
                    actual_status
                ));
            }

            if let Some(validate_fn) = &self.resp_validation {
                let text = resp.text().await?;
                if !validate_fn(text) {
                    eprintln!("Test api '{}' fail validate_fn", self.tag);
                    error!("Test api '{}' fail validate_fn", self.tag);
                    return Err(anyhow::anyhow!("Test api '{}' fail validate_fn", self.tag));
                }
            }

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

    async fn init_nodes_data(local_db: &LocalDB, nodes: &[Node]) -> anyhow::Result<()> {
        let mut tx = local_db.start_transaction().await?;
        for node in nodes {
            tx.upsert_node(node).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn init_instance_graph_data(
        local_db: &LocalDB,
        instances: &[Instance],
        graphs: &[Graph],
    ) -> anyhow::Result<()> {
        let mut tx = local_db.start_transaction().await?;
        for instance in instances {
            tx.upsert_instance(instance).await?;
        }
        for graph in graphs {
            tx.upsert_graph(graph).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_nodes_api() -> Result<(), Box<dyn std::error::Error>> {
        init(None);
        let addr = available_addr();
        let mut nodes = Vec::<Node>::new();
        let (_, public_key) = Secp256k1::new().generate_keypair(&mut rand::thread_rng());
        let pub_key = public_key.to_string();
        let actor = Actor::Challenger;
        nodes.push(Node {
            peer_id: generate_local_key().public().to_peer_id().to_string(),
            actor: actor.to_string(),
            node_name: "ZKM".to_string(),
            goat_addr: get_rand_goat_address(),
            btc_pub_key: pub_key.clone(),
            socket_addr: "".to_string(),
            reward: 0,
            service_fee_rate: 0.0,
            available_peg_btc: 0,
            updated_at: current_time_secs(),
            created_at: current_time_secs(),
        });
        let goat_addr = get_rand_goat_address();
        nodes.push(Node {
            peer_id: generate_local_key().public().to_peer_id().to_string(),
            actor: Actor::Committee.to_string(),
            node_name: "ZKM".to_string(),
            goat_addr: goat_addr.clone(),
            btc_pub_key: pub_key.clone(),
            socket_addr: "".to_string(),
            reward: 0,
            service_fee_rate: 0.0,
            available_peg_btc: 0,
            updated_at: current_time_secs(),
            created_at: current_time_secs(),
        });

        let local_db = create_local_db(&temp_file()).await;
        init_nodes_data(&local_db, &nodes).await?;
        tokio::spawn(rpc_service::serve(
            addr.clone(),
            local_db,
            Actor::Challenger,
            generate_local_key().public().to_peer_id().to_string(),
            Arc::new(Mutex::new(Registry::default())),
            CancellationToken::new(),
        ));
        sleep(Duration::from_secs(1)).await;
        let api_test_items = [
            ApiTestItem {
                tag: format!("{} get node", routes::v1::NODES_BASE),
                url: format!("http://{addr}{}?actor={}", routes::v1::NODES_BASE, actor),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
                resp_validation: Some(Box::new(|text| -> bool {
                    matches!(
                        serde_json::from_str::<NodeListResponse>(&text),
                        Ok(node_resp) if node_resp.nodes.len() == 1
                    )
                })),
            },
            ApiTestItem {
                tag: format!("{} get node overview", routes::v1::NODES_OVERVIEW),
                url: format!("http://{addr}{}", routes::v1::NODES_OVERVIEW),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
                resp_validation: Some(Box::new(|text| -> bool {
                    matches!(
                        serde_json::from_str::<NodeOverViewResponse>(&text),
                        Ok(node_overview) if node_overview.nodes_overview.online_challengers == 1 &&
                        node_overview.nodes_overview.online_committees == 1
                    )
                })),
            },
        ];
        do_batch_tests("node apis", &Client::new(), &api_test_items).await?;
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
        let bridge_in_instance_id = Uuid::new_v4();
        let bridge_in_from = get_rand_btc_address_p2wpkh(get_network());
        let bridge_in_to = get_rand_goat_address();
        let bridge_in_amount = 20000000;
        let utxo: Vec<Utxo> = vec![Utxo {
            txid: generate_random_bytes(32).try_into().unwrap(),
            vout: 1,
            amount_sats: bridge_in_amount as u64,
        }];
        let mut instances = Vec::<Instance>::new();
        let mut graphs = Vec::<Graph>::new();
        instances.push(Instance {
            instance_id: bridge_in_instance_id,
            is_bridge_in: true,
            network: get_network().to_string(),
            from_addr: bridge_in_from.clone(),
            to_addr: bridge_in_to.clone(),
            amount: bridge_in_amount,
            fees: Default::default(),
            input_utxos: serde_json::to_string(&utxo).unwrap(),
            status: InstanceBridgeInStatus::RelayerL2Minted.to_string(),
            goat_tx_hash: format!("0x{}", hex::encode(generate_random_bytes(32))),
            goat_tx_height: 1000,
            user_xonly_pubkey: Default::default(),
            user_change_addr: get_rand_btc_address_p2wpkh(get_network()),
            user_refund_addr: get_rand_btc_address_p2wpkh(get_network()),
            btc_txid: None,
            btc_height: 0,
            pegin_confirm_txid: None,
            pegin_cancel_txid: None,
            committees_answers: Default::default(),
            pegin_data_tx_hash: format!("0x{}", hex::encode(generate_random_bytes(32))),
            parameters: None,
            status_updated_at: current_time_secs(),
            created_at: current_time_secs(),
            updated_at: current_time_secs(),
        });

        instances.push(Instance {
            instance_id: Uuid::new_v4(),
            is_bridge_in: true,
            network: get_network().to_string(),
            from_addr: bridge_in_from.clone(),
            to_addr: bridge_in_to.clone(),
            amount: bridge_in_amount,
            fees: Default::default(),
            input_utxos: serde_json::to_string(&utxo).unwrap(),
            status: InstanceBridgeInStatus::RelayerL1Broadcasted.to_string(),
            goat_tx_hash: format!("0x{}", hex::encode(generate_random_bytes(32))),
            goat_tx_height: 1000,
            user_xonly_pubkey: Default::default(),
            user_change_addr: get_rand_btc_address_p2wpkh(get_network()),
            user_refund_addr: get_rand_btc_address_p2wpkh(get_network()),
            btc_txid: None,
            btc_height: 0,
            pegin_confirm_txid: None,
            pegin_cancel_txid: None,
            committees_answers: Default::default(),
            pegin_data_tx_hash: format!("0x{}", hex::encode(generate_random_bytes(32))),
            parameters: None,
            status_updated_at: current_time_secs(),
            created_at: current_time_secs(),
            updated_at: current_time_secs(),
        });
        let graph_id = Uuid::new_v4();
        let graph_status = GraphStatus::OperatorTake1.to_string();
        let graph_to = get_rand_btc_address_p2wpkh(get_network());
        let graph_from = get_rand_goat_address();

        graphs.push(Graph {
            graph_id,
            instance_id: bridge_in_instance_id,
            kickoff_index: 0,
            from_addr: graph_from.clone(),
            to_addr: graph_to.clone(),
            graph_ipfs_base_url: "".to_string(),
            amount: bridge_in_amount,
            challenge_amount: bridge_in_amount,
            status: graph_status.clone(),
            sub_status: "".to_string(),
            operator_pubkey: "".to_string(),
            next_prekickoff: None,
            cur_prekickoff_txid: None,
            force_skip_kickoff_txid: None,
            quick_challenge_txid: None,
            challenge_incomplete_kickoff_txid: None,
            pegin_txid: None,
            kickoff_txid: None,
            take1_txid: None,
            challenge_txid: None,
            take2_txid: None,
            disprove_txid: None,
            watchtower_challenge_init_txid: None,
            watchtower_challenge_timeout_txids: vec![],
            nack_txids: vec![],
            blockhash_commit_timeout_txid: None,
            assert_init_txid: None,
            assert_commit_timeout_txids: vec![],
            init_withdraw_tx_hash: Some(format!("0x{}", hex::encode(generate_random_bytes(32)))),
            bridge_out_start_at: current_time_secs() + 100,
            zkm_version: "zkm_0.1.0".to_string(),
            status_updated_at: current_time_secs(),
            created_at: current_time_secs(),
            updated_at: current_time_secs(),
        });
        graphs.push(Graph {
            graph_id: Uuid::new_v4(),
            instance_id: bridge_in_instance_id,
            kickoff_index: 0,
            from_addr: graph_from.clone(),
            to_addr: graph_to.clone(),
            graph_ipfs_base_url: "".to_string(),
            amount: bridge_in_amount,
            challenge_amount: bridge_in_amount,
            status: GraphStatus::CommitteePresigned.to_string(),
            sub_status: "".to_string(),
            operator_pubkey: "".to_string(),
            next_prekickoff: None,
            cur_prekickoff_txid: None,
            force_skip_kickoff_txid: None,
            quick_challenge_txid: None,
            challenge_incomplete_kickoff_txid: None,
            pegin_txid: None,
            kickoff_txid: None,
            take1_txid: None,
            challenge_txid: None,
            take2_txid: None,
            disprove_txid: None,
            watchtower_challenge_init_txid: None,
            watchtower_challenge_timeout_txids: vec![],
            nack_txids: vec![],
            blockhash_commit_timeout_txid: None,
            assert_init_txid: None,
            assert_commit_timeout_txids: vec![],
            init_withdraw_tx_hash: None,
            bridge_out_start_at: 0,
            zkm_version: "zkm_0.1.0".to_string(),
            status_updated_at: current_time_secs(),
            created_at: current_time_secs(),
            updated_at: current_time_secs(),
        });

        init_instance_graph_data(&local_db, &instances, &graphs).await?;

        tokio::spawn(rpc_service::serve(
            addr.clone(),
            local_db.clone(),
            actor.clone(),
            peer_id.clone(),
            Arc::new(Mutex::new(Registry::default())),
            CancellationToken::new(),
        ));
        sleep(Duration::from_secs(1)).await;

        let bridge_in_request_tag_id = Uuid::new_v4();

        let target_instance_id = bridge_in_instance_id;
        let api_test_items = vec![
            ApiTestItem {
                tag: routes::v1::INSTANCES_SETTINGS.to_string(),
                url: format!("http://{addr}{}", routes::v1::INSTANCES_SETTINGS),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
                resp_validation: Some(Box::new(|text| -> bool {
                    matches!(
                        serde_json::from_str::<InstanceSettingResponse>(&text),
                        Ok(instances_setting) if instances_setting.bridge_in_amount == BRIDGE_IN_AMOUNTS.to_vec()
                    )
                })),
            },
            ApiTestItem {
                tag: routes::v1::INSTANCES_BRIDGE_IN_REQUEST_TAG.to_string(),
                url: format!("http://{addr}{}", routes::v1::INSTANCES_BRIDGE_IN_REQUEST_TAG),
                json_payload: Some(json!({
                    "instance_id": bridge_in_request_tag_id,
                    "network": "testnet",
                    "bridge_request_tx_hash":  format!("0x{}", hex::encode(generate_random_bytes(32))),
                    "from_addr": get_rand_btc_address_p2wpkh(get_network()),
                    "to_addr": format!("0x{}", hex::encode(generate_random_bytes(20)))
                })),
                method: Method::PUT,
                expe_res: true,
                resp_validation: None,
            },
            ApiTestItem {
                tag: format!("{} for bridge in request tag", routes::v1::INSTANCES_BY_ID),
                url: format!(
                    "http://{addr}{}/{}",
                    routes::v1::INSTANCES_BASE,
                    bridge_in_request_tag_id
                ),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
                resp_validation: Some(Box::new(move |text| -> bool {
                    if let Ok(instance_res) = serde_json::from_str::<InstanceGetResponse>(&text)
                        && let Some(instance_wrap) = instance_res.instance_wrap
                        && instance_wrap.instance.instance_id.eq(&bridge_in_request_tag_id)
                    {
                        true
                    } else {
                        false
                    }
                })),
            },
            ApiTestItem {
                tag: routes::v1::INSTANCES_BY_ID.to_string(),
                url: format!(
                    "http://{addr}{}/{}",
                    routes::v1::INSTANCES_BASE,
                    bridge_in_instance_id
                ),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
                resp_validation: Some(Box::new(move |text| -> bool {
                    if let Ok(instance_res) = serde_json::from_str::<InstanceGetResponse>(&text)
                        && let Some(instance_wrap) = instance_res.instance_wrap
                        && instance_wrap.instance.instance_id.eq(&target_instance_id)
                    {
                        true
                    } else {
                        false
                    }
                })),
            },
            ApiTestItem {
                tag: format!("{} get instances", routes::v1::INSTANCES_BASE),
                url: format!(
                    "http://{addr}{}?is_bridge_in=true&from_addr={}",
                    routes::v1::INSTANCES_BASE,
                    bridge_in_from,
                ),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
                resp_validation: Some(Box::new(|text| -> bool {
                    matches!(
                        serde_json::from_str::<InstanceListResponse>(&text),
                        Ok(instance_list) if instance_list.total == 2
                    )
                })),
            },
            ApiTestItem {
                tag: format!("{} info", routes::v1::INSTANCES_OVERVIEW),
                url: format!("http://{addr}{}", routes::v1::INSTANCES_OVERVIEW,),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
                resp_validation: Some(Box::new(move |text| -> bool {
                    matches!(
                        serde_json::from_str::<InstanceOverviewResponse>(&text),
                        Ok(instance_overview) if instance_overview.instances_overview.total_bridge_in_amount == bridge_in_amount
                    )
                })),
            },
            ApiTestItem {
                tag: format!("{} info", routes::v1::GRAPHS_BY_ID),
                url: format!("http://{addr}{}/{}", routes::v1::GRAPHS_BASE, graph_id),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
                resp_validation: Some(Box::new(move |text| -> bool {
                    if let Ok(graph_res) = serde_json::from_str::<GraphGetResponse>(&text)
                        && let Some(graph) = graph_res.graph
                        && graph.graph_id == graph_id
                    {
                        true
                    } else {
                        false
                    }
                })),
            },
            ApiTestItem {
                tag: format!("{} get graphs info", routes::v1::GRAPHS_BASE),
                url: format!(
                    "http://{addr}{}?status={}&from_addr={}&graph_id={}",
                    routes::v1::GRAPHS_BASE,
                    graph_status,
                    graph_from,
                    graph_id
                ),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
                resp_validation: Some(Box::new(move |text| -> bool {
                    matches!(
                        serde_json::from_str::<GraphListResponse>(&text),
                        Ok(graph_list) if graph_list.total == 1
                    )
                })),
            },
        ];
        do_batch_tests("bitvm2 apis", &Client::new(), &api_test_items).await?;
        Ok(())
    }

    #[allow(dead_code)]
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
        let addr = available_addr();
        info!("Start api server");
        let committee = Actor::Committee;
        let committee_peer_id = generate_local_key().public().to_peer_id().to_string();
        let local_db = create_local_db(&temp_file()).await;
        tokio::spawn(rpc_service::serve(
            addr.clone(),
            local_db,
            committee,
            committee_peer_id,
            Arc::new(Mutex::new(Registry::default())),
            CancellationToken::new(),
        ));
        sleep(Duration::from_secs(1)).await;
        let client = reqwest::Client::new();

        let api_test_items = [ApiTestItem {
            tag: format!("{} get proofs desc", routes::v1::PROOFS_BLOCKS_HEADER_CHAIN_DESC),
            url: format!(
                "http://{addr}{}?proof_type=header_chain",
                routes::v1::PROOFS_BLOCKS_HEADER_CHAIN_DESC
            ),
            json_payload: None,
            method: Method::GET,
            expe_res: true,
            resp_validation: None,
        }];
        do_batch_tests("node apis", &client, &api_test_items).await?;
        Ok(())
    }
}
