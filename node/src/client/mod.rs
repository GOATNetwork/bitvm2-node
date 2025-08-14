use anyhow::bail;
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash;
use bitcoin::{Address as BtcAddress, Transaction, TxMerkleNode, Txid};
use bitcoin::{Block, Network};
use esplora_client::{AsyncClient, Builder, MerkleProof, Utxo};
use store::localdb::LocalDB;

pub mod esplora;
pub mod goat_chain;
pub mod graph_query;

use crate::client::esplora::get_esplora_url;

pub async fn create_local_db(db_path: &str) -> LocalDB {
    let local_db = LocalDB::new(&format!("sqlite:{db_path}"), true).await;
    local_db.migrate().await;
    local_db
}

/// Esplora client and interfaces
pub struct BTCClient {
    /// FIXME: make it private
    pub esplora: AsyncClient,
    pub network: Network,
}

impl BTCClient {
    pub fn new(esplora_url: Option<&str>, network: Network) -> Self {
        BTCClient {
            esplora: Builder::new(esplora_url.unwrap_or(get_esplora_url(network)))
                .build_async()
                .expect("Could not build esplora client"),
            network,
        }
    }

    pub async fn fetch_btc_block(&self, block_height: u32) -> anyhow::Result<Block> {
        let block_hash = self.esplora.get_block_hash(block_height).await?;
        self.esplora.get_block_by_hash(&block_hash).await?.ok_or(anyhow::format_err!(
            "failed to fetch block at :{} hash:{}",
            block_height,
            block_hash.to_string()
        ))
    }

    pub async fn fetch_btc_address_utxos(&self, address: BtcAddress) -> anyhow::Result<Vec<Utxo>> {
        Ok(self.esplora.get_address_utxo(address).await?)
    }

    pub async fn get_bitc_merkle_proof(
        &self,
        tx_id: &Txid,
    ) -> anyhow::Result<(TxMerkleNode, MerkleProof, Vec<u8>)> {
        let proof = self.esplora.get_merkle_proof(tx_id).await?;
        if let Some(proof) = proof {
            let block_hash = self.esplora.get_block_hash(proof.block_height).await?;
            let header = self.esplora.get_header_by_hash(&block_hash).await?;
            let raw_header = serialize(&header);
            return Ok((header.merkle_root, proof, raw_header));
        }

        bail!("get {} merkle proof is none", tx_id)
    }

    pub async fn fetch_btc_tx(
        &self,
        tx_id: &Txid,
    ) -> Result<Transaction, Box<dyn std::error::Error>> {
        self.esplora.get_tx(tx_id).await?.ok_or(format!("{tx_id} is not on chain").into())
    }

    pub async fn get_btc_tx_proof_info(
        &self,
        tx_id: &Txid,
    ) -> anyhow::Result<([u8; 32], Vec<[u8; 32]>, [u8; 32], u64, u64, Vec<u8>)> {
        let (root, proof_info, raw_header) = self.get_bitc_merkle_proof(tx_id).await?;
        let proof: Vec<[u8; 32]> = proof_info.merkle.iter().map(|v| v.to_byte_array()).collect();
        let leaf = tx_id.to_byte_array();
        Ok((
            root.to_byte_array(),
            proof,
            leaf,
            proof_info.block_height as u64,
            proof_info.pos as u64,
            raw_header,
        ))
    }
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
    use crate::client::BTCClient;
    use crate::client::goat_chain::{GOATClient, GoatInitConfig, GoatNetwork};
    use bitcoin::hashes::Hash;
    use bitcoin::{Network, Txid};
    use std::str::FromStr;

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
