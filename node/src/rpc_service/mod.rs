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
    node_handler::{node_list, update_node},
};
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

pub(crate) async fn serve(addr: String, db_path: String) {
    let localdb = Arc::new(LocalDB::new(&format!("sqlite:{db_path}"), true).await);
    let server = Router::new()
        .route("/", get(root))
        .route("/node", post(update_node))
        .route("/nodeList", post(node_list))
        .route("/instances", post(create_instance))
        .route("/graphGenerate", post(graph_generate))
        .route("/graphPresign", post(graph_presign))
        .route("/graphPresignCheck", post(graph_presign_check))
        .route("/pegGtcMint", post(peg_btc_mint))
        .route("/bridgeOutTxPrepare", post(bridge_out_tx_prepare))
        .route("/bridgeOutUserClaim", post(bridge_out_user_claim))
        .route("/userInstanceList", post(user_instance_list))
        .route("/getInstance", post(get_instance))
        .route("/graphList", post(graph_list))
        .with_state(localdb);

    let listener = TcpListener::bind(addr).await.unwrap();
    println!("RPC listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, server).await.unwrap();
}

#[cfg(test)]
mod test {
    use crate::rpc_service;
    use serde_json::json;
    use std::time::Duration;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_node() -> Result<(), Box<dyn std::error::Error>> {
        tokio::spawn(rpc_service::serve("127.0.0.1:8080".to_string()));
        let client = reqwest::Client::new();
        let resp = client
            .post("http://127.0.0.1:8080/node")
            .json(&json!({
                "peer_id": "ffc54e9cf37d9f87e",
                "role": "COMMITTEE"
            }))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        println!("Post Response: {}", res_body);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_node_list() -> Result<(), Box<dyn std::error::Error>> {
        tokio::spawn(rpc_service::serve("127.0.0.1:8080".to_string()));
        let client = reqwest::Client::new();
        let resp = client
            .post("http://127.0.0.1:8080/nodeList")
            .json(&json!({
                "role": "COMMITTEE",
                "offset": 0,
                "limit": 5
            }))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        println!("Post Response: {}", res_body);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_instance() -> Result<(), Box<dyn std::error::Error>> {
        tokio::spawn(rpc_service::serve("127.0.0.1:8080".to_string()));
        let client = reqwest::Client::new();
        let resp = client
            .post("http://127.0.0.1:8080/instances")
            .json(&json!({
                "instance_id": "ffc54e9cf37d9f87e",
                "network": "test3",
                "bridge_path": "pBTC <-> tBTC",
                "amount": 10000,
                "fee_rate": 80,
                "utxo": [
                    {
                        "txid": "ffc54e9cf37d9f87ebaa703537e93e20caece862d9bc1c463c487583905ec49c",
                        "vout": 0
                    }
                ],
                "from": "tb1qsyngu9wf2x46tlexhpjl4nugv0zxmgezsx5erl",
                "to": "tb1qkrhp3khxam3hj2kl9y77m2uctj2hkyh248chkp"
            }))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        println!("Post Response: {}", res_body);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_graph_generate() -> Result<(), Box<dyn std::error::Error>> {
        tokio::spawn(rpc_service::serve("127.0.0.1:8080".to_string()));
        let client = reqwest::Client::new();
        let resp = client
            .post("http://127.0.0.1:8080/graphGenerate")
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
    async fn test_graph_presign() -> Result<(), Box<dyn std::error::Error>> {
        tokio::spawn(rpc_service::serve("127.0.0.1:8080".to_string()));
        let client = reqwest::Client::new();
        let resp = client
            .post("http://127.0.0.1:8080/graphPresign")
            .json(&json!({
                "instance_id": "ffc54e9cf37d9f87e2222",
                "graph_id": "ffc54e9cf37d9f87e1111",
                "graph_ipfs_base_url":"https://ipfs.io/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco"
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
        tokio::spawn(rpc_service::serve("127.0.0.1:8080".to_string()));
        let client = reqwest::Client::new();
        let resp = client
            .post("http://127.0.0.1:8080/graphPresignCheck")
            .json(&json!({
                "instance_id": "ffc54e9cf37d9f87e2222",
            }))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        println!("Post Response: {}", res_body);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_peg_btc_mint() -> Result<(), Box<dyn std::error::Error>> {
        tokio::spawn(rpc_service::serve("127.0.0.1:8080".to_string()));
        let client = reqwest::Client::new();
        let resp = client
            .post("http://127.0.0.1:8080/pegGtcMint")
            .json(&json!({
                "instance_id": "ffc54e9cf37d9f87e2222",
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
        tokio::spawn(rpc_service::serve("127.0.0.1:8080".to_string()));
        let client = reqwest::Client::new();
        let resp = client
            .post("http://127.0.0.1:8080/bridgeOutTxPrepare")
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
        tokio::spawn(rpc_service::serve("127.0.0.1:8080".to_string()));
        let client = reqwest::Client::new();
        let resp = client
            .post("http://127.0.0.1:8080/bridgeOutUserClaim")
            .json(&json!({
                "instance_id": "ffc54e9cf37d9f87e2222",
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
    async fn test_get_instance() -> Result<(), Box<dyn std::error::Error>> {
        tokio::spawn(rpc_service::serve("127.0.0.1:8080".to_string()));
        let client = reqwest::Client::new();
        let resp = client
            .post("http://127.0.0.1:8080/userInstanceList")
            .json(&json!({
                "user_address": "miJ19RACTc7Sow64gbznCnCz3p4Ey2NP18",
                "offset":1,
                "limit": 5
            }))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let res_body = resp.text().await?;
        println!("Post Response: {}", res_body);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_user_instances() -> Result<(), Box<dyn std::error::Error>> {
        tokio::spawn(rpc_service::serve("127.0.0.1:8080".to_string()));
        let client = reqwest::Client::new();
        let resp = client
            .post("http://127.0.0.1:8080/getInstance")
            .json(&json!({
                "instance_id": "ffc54e9cf37d9f87e2222"
            }))
            .send()
            .await
            .expect("");
        println!("{:?}", resp);
        assert!(resp.status().is_success());
        let res_body = resp.text().await.unwrap();
        println!("Post Response: {}", res_body);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_graph_list() -> Result<(), Box<dyn std::error::Error>> {
        tokio::spawn(rpc_service::serve("127.0.0.1:8080".to_string()));
        let client = reqwest::Client::new();
        let resp = client
            .post("http://127.0.0.1:8080/graphList")
            .json(&json!({
                "role": "user_test",
                "status": "OperatorPresigned",
                "operator": "Operatortest",
                "pegin_txid": "a73308fecf906f436583b30f8fd6ac56265fba90efb3f788d7c2d18b1ecfd8aa",
                "offset": 0,
                "limit": 5,
            }))
            .send()
            .await
            .expect("");
        println!("{:?}", resp);
        assert!(resp.status().is_success());
        let res_body = resp.text().await.unwrap();
        println!("Post Response: {}", res_body);
        Ok(())
    }
}
