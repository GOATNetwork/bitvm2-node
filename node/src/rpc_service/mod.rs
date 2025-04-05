mod bitvm2;
mod handler;
mod node;

use axum::{
    Router,
    response::IntoResponse,
    routing::{get, post},
};
use futures::StreamExt;
use libp2p::core::Transport;
use std::sync::Arc;
use store::localdb::LocalDB;

use crate::rpc_service::handler::{
    bitvm2_handler::*,
    node_handler::{create_node, get_nodes},
};
use axum::routing::put;
use std::time::UNIX_EPOCH;
use tokio::net::TcpListener;

#[inline(always)]
pub fn current_time_secs() -> u64 {
    std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
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
///2.bridge-out
///- front end create hash time lock tx at goat chain. step 1;
///- front end call `bridge_out_tx_prepare` to request locking btc assert. step 2
///- front end call `bridge_out_user_claim` to unlock btc assert. step 3
///- backend send btc tx(unlock btc assert) and unlock goat assert. step 4
///
///3.graph_overview: `graph_list` support
///
///4.node_overview:  `get_nodes` support
///
///5.instance,graph query by id: `get_instance`, `get_graph`
///
pub(crate) async fn serve(addr: String, db_path: String) {
    let localdb = Arc::new(LocalDB::new(&format!("sqlite:{db_path}"), true).await);
    let server = Router::new()
        .route("/", get(root))
        .route("/v1/nodes", post(create_node))
        .route("/v1/nodes", get(get_nodes))
        .route("/v1/instances", get(get_instances_with_query_params))
        .route("/v1/instances/{:id}", get(get_instance))
        .route("/v1/instances/action/bridge_in_tx_prepare", post(bridge_in_tx_prepare))
        .route("/v1/instances/{:id}/bridge_in/peg_gtc_mint", post(peg_btc_mint))
        .route("/v1/instances/action/bridge_out_tx_prepare", post(bridge_out_tx_prepare))
        .route("/v1/instances/{:id}/bridge_out/user_claim", post(bridge_out_user_claim))
        .route("/v1/graphs", post(create_graph))
        .route("/v1/graphs/{:id}", get(get_graph))
        .route("/v1/graphs", get(graph_list))
        .route("/v1/graphs/{:id}/presign", post(graph_presign))
        .route("/v1/graphs/presign_check", post(graph_presign_check))
        .with_state(localdb);

    let listener = TcpListener::bind(addr).await.unwrap();
    println!("RPC listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, server).await.unwrap();
}

#[cfg(test)]
mod tests {
    use crate::rpc_service;
    use serde_json::json;
    const LISTEN_ADDRESS: &str = "127.0.0.1:8080";
    const TMEP_DB_PATH: &str = "sqlite:/tmp/.bitvm2-node.db";

    #[tokio::test(flavor = "multi_thread")]
    async fn test_node() -> Result<(), Box<dyn std::error::Error>> {
        tokio::spawn(rpc_service::serve(LISTEN_ADDRESS.to_string(), TMEP_DB_PATH.to_string()));
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{}/v1/nodes",LISTEN_ADDRESS ))
            .json(&json!({
                "peer_id": "ffc54e9cf37d9f87e",
                "actor": "Committee"
            }))
            .send()
            .await?;
        println!("{:?}", resp);
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        println!("Post Response: {}", res_body);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_nodes() -> Result<(), Box<dyn std::error::Error>> {
        tokio::spawn(rpc_service::serve(LISTEN_ADDRESS.to_string(), TMEP_DB_PATH.to_string()));
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{}/v1/nodes?actor=OPERATOR&offset=5&limit=5",LISTEN_ADDRESS ))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        println!("Post Response: {}", res_body);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_bridge_in_tx_prepare() -> Result<(), Box<dyn std::error::Error>> {
        tokio::spawn(rpc_service::serve(LISTEN_ADDRESS.to_string(), TMEP_DB_PATH.to_string()));
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{}/v1/instances/action/bridge_in_tx_prepare",LISTEN_ADDRESS ))
            .json(&json!({
                "instance_id": "ffc54e9cf37d9f87e",
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
        println!("{:?}", resp);
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        println!("Post Response: {}", res_body);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_get_instance() -> Result<(), Box<dyn std::error::Error>> {
        tokio::spawn(rpc_service::serve(LISTEN_ADDRESS.to_string(), TMEP_DB_PATH.to_string()));
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{}/v1/instances/ffc54e9cf37d9f87e2222",LISTEN_ADDRESS ))
            .send()
            .await
            .expect("");
        assert!(resp.status().is_success());
        let res_body = resp.text().await.unwrap();
        println!("Post Response: {}", res_body);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_get_instances_with_query_params() -> Result<(), Box<dyn std::error::Error>> {
        tokio::spawn(rpc_service::serve(LISTEN_ADDRESS.to_string(), TMEP_DB_PATH.to_string()));
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{}/v1/instances?user_address=miJ19RACTc7Sow64gbznCnCz3p4Ey2NP18&offset=1&limit=5",LISTEN_ADDRESS ))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        println!("Post Response: {}", res_body);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_peg_btc_mint() -> Result<(), Box<dyn std::error::Error>> {
        tokio::spawn(rpc_service::serve(LISTEN_ADDRESS.to_string(), TMEP_DB_PATH.to_string()));
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{}/v1/instances/ffc54e9cf37d9f87e2222/bridge_in/peg_gtc_mint",LISTEN_ADDRESS ))
            .json(&json!({
                "graph_id":[
                    "ffc54e9cf37d9f87e1111",
                    "ffc54e9cf37d9f87e3333"
                ],
                "pegin_txid": "58de965c464696560fdee91d039da6d49ef7770f30ef07d892e21d8a80a16c2c"
            }))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        println!("Post Response: {}", res_body);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_bridge_out_tx_prepare() -> Result<(), Box<dyn std::error::Error>> {
        tokio::spawn(rpc_service::serve(LISTEN_ADDRESS.to_string(), TMEP_DB_PATH.to_string()));
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{}/v1/instances/action/bridge_out_tx_prepare",LISTEN_ADDRESS ))
            .json(&json!({
                "instance_id": "ffc54e9cf37d9f87e2222",
                "pegout_txid":"58de965c464696560fdee91d039da6d49ef7770f30ef07d892e21d8a80a16c2c",
                "operator": "operator_test"
            }))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        println!("Post Response: {}", res_body);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_bridge_out_user_claim() -> Result<(), Box<dyn std::error::Error>> {
        tokio::spawn(rpc_service::serve(LISTEN_ADDRESS.to_string(), TMEP_DB_PATH.to_string()));
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{}/v1/instances/ffc54e9cf37d9f87e2222/bridge_out/user_claim",LISTEN_ADDRESS ))
            .json(&json!({
                "pegout_txid":"58de965c464696560fdee91d039da6d49ef7770f30ef07d892e21d8a80a16c2c",
                "signed_claim_txn": "58de965c464696560fdee91d039da6d49ef7770f30ef07d892e21d8a80a16c2c58de965c464696560fdee91d039da6d49ef7770f30ef07d892e21d8a80a16c2c"
            }))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        println!("Post Response: {}", res_body);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_create_graph() -> Result<(), Box<dyn std::error::Error>> {
        tokio::spawn(rpc_service::serve(LISTEN_ADDRESS.to_string(), TMEP_DB_PATH.to_string()));
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{}/v1/graphs",LISTEN_ADDRESS ))
            .json(&json!({
              "instance_id": "ffc54e9cf37d9f87e2222",
                "graph_id": "ffc54e9cf37d9f87e1111",
            }))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        println!("Post Response: {}", res_body);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_get_graphs() -> Result<(), Box<dyn std::error::Error>> {
        tokio::spawn(rpc_service::serve(LISTEN_ADDRESS.to_string(), TMEP_DB_PATH.to_string()));
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{}/v1/graphs?offset=1&limit=5",LISTEN_ADDRESS ))
            .json(&json!({
                "status": "OperatorPresigned",
                "operator": "ffc54e9cf37d9f87e1111",
                "pegin_txid":"58de965c464696560fdee91d039da6d49ef7770f30ef07d892e21d8a80a16c2c"
            }))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        println!("Post Response: {}", res_body);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_get_graph() -> Result<(), Box<dyn std::error::Error>> {
        tokio::spawn(rpc_service::serve(LISTEN_ADDRESS.to_string(), TMEP_DB_PATH.to_string()));
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{}/v1/graphs/ffc54e9cf37d9f87e1111",LISTEN_ADDRESS ))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        println!("Post Response: {}", res_body);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_graph_presign() -> Result<(), Box<dyn std::error::Error>> {
        tokio::spawn(rpc_service::serve(LISTEN_ADDRESS.to_string(), TMEP_DB_PATH.to_string()));
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{}/v1/graphs/ffc54e9cf37d9f87e1111/presign",LISTEN_ADDRESS ))
            .json(&json!({
                "instance_id": "ffc54e9cf37d9f87e1111",
                "graph_ipfs_base_url":"https://ipfs.io/ipfs/QmXxwbk8eA2bmKBy7YEjm5w1zKiG7g6ebF1JYfqWvnLnhH"
            }))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        println!("Post Response: {}", res_body);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_graph_presign_check() -> Result<(), Box<dyn std::error::Error>> {
        tokio::spawn(rpc_service::serve(LISTEN_ADDRESS.to_string(), TMEP_DB_PATH.to_string()));
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{}/v1/graphs/presign_check",LISTEN_ADDRESS ))
            .json(&json!(
                {
                   "instance_id": "ffc54e9cf37d9f87e1111",
                }
            ))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        println!("Post Response: {}", res_body);
        Ok(())
    }
}
