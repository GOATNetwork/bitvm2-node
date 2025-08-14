use store::localdb::LocalDB;
pub mod goat_chain;
pub mod graph_query;
pub mod btc_chain;

pub async fn create_local_db(db_path: &str) -> LocalDB {
    let local_db = LocalDB::new(&format!("sqlite:{db_path}"), true).await;
    local_db.migrate().await;
    local_db
}


#[derive(Clone)]
pub struct GraphQueryClient {
    client: reqwest::Client,
    subgraph_url: String,
}

impl GraphQueryClient {
    pub fn new(subgraph_url: String) -> Self {
        let client = reqwest::Client::new();
        Self { client, subgraph_url }
    }
    pub async fn execute_query(&self, query: &str) -> anyhow::Result<serde_json::Value> {
        let response = self
            .client
            .post(&self.subgraph_url)
            .json(&serde_json::json!({
                "query": query
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;
        Ok(response["data"].clone())
    }
}

#[cfg(test)]
mod tests {
    use crate::client::goat_chain::{GOATClient, GoatInitConfig, GoatNetwork};
    use bitcoin::hashes::Hash;
    use bitcoin::{Network, Txid};
    use std::str::FromStr;
    use crate::client::btc_chain::BTCClient;

    #[tokio::test]
    async fn test_spv_check() {
        let global_init_config = GoatInitConfig::from_env_for_test();
        //  let local_db = LocalDB::new(&format!("sqlite:{db_path}"), true).await;
        let btc_client = BTCClient::new(None, Network::Testnet);
        let goat_client = GOATClient::new(global_init_config, GoatNetwork::Test);
        let tx_id =
            Txid::from_str("cd557f6656051531ab53d08a43524330b39344bb98b710461450feda4ff4b231")
                .expect("decode txid");

        let (root, proof_info, _) =
            btc_client.get_bitc_merkle_proof(&tx_id).await.expect("call merkle proof");
        let root = root.to_byte_array().map(|v| v);
        let proof: Vec<[u8; 32]> =
            proof_info.merkle.iter().map(|v| v.to_byte_array().map(|v| v)).collect();
        let res = goat_client
            .verify_merkle_proof(&root, &proof, &tx_id.to_byte_array(), proof_info.pos as u64)
            .await
            .expect("get result");
        assert!(res);
    }
}
