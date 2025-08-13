use crate::client::chain::chain_adaptor::{
    BitcoinTx, BitcoinTxProof, GoatNetwork, GraphData, PeginData, WithdrawData, WithdrawStatus,
    get_chain_adaptor,
};
use crate::client::chain::evmchain::EvmChain;
use crate::client::chain::goat_adaptor::GoatInitConfig;
use crate::client::esplora::get_esplora_url;
use crate::env::GATEWAY_RATE_MULTIPLIER;
use crate::utils::get_stake_amount;
use alloy::rpc::types::TransactionReceipt;
use anyhow::bail;
use bitcoin::consensus::encode::{deserialize_hex, serialize};
use bitcoin::hashes::Hash;
use bitcoin::{Address as BtcAddress, PublicKey, Transaction, TxMerkleNode, Txid};
use bitcoin::{Block, Network};
use esplora_client::{AsyncClient, Builder, MerkleProof, Utxo};
use std::str::FromStr;
use store::Graph;
use store::localdb::LocalDB;
use uuid::Uuid;

pub mod chain;
pub mod esplora;
pub mod graph_query;

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

pub struct GOATClient {
    pub chain_service: EvmChain,
}

impl GOATClient {
    pub fn new(goat_init_config: GoatInitConfig, goat_network: GoatNetwork) -> Self {
        GOATClient {
            chain_service: EvmChain::new(get_chain_adaptor(goat_network, goat_init_config, None)),
        }
    }
    pub async fn verify_merkle_proof(
        &self,
        root: &[u8; 32],
        proof: &[[u8; 32]],
        leaf: &[u8; 32],
        index: u64,
    ) -> anyhow::Result<bool> {
        let res = self.chain_service.adaptor.verify_merkle_proof(root, proof, leaf, index).await?;
        Ok(res)
    }

    pub async fn pegin_tx_used(&self, tx_id: &[u8; 32]) -> anyhow::Result<bool> {
        self.chain_service.adaptor.pegin_tx_used(tx_id).await
    }

    pub async fn get_pegin_data(&self, instance_id: &Uuid) -> anyhow::Result<PeginData> {
        self.chain_service.adaptor.get_pegin_data(instance_id).await
    }
    pub async fn is_operator_withdraw(&self, graph_id: &Uuid) -> anyhow::Result<bool> {
        self.chain_service.adaptor.is_operator_withdraw(graph_id).await
    }
    pub async fn get_graph_data(&self, graph_id: &Uuid) -> anyhow::Result<GraphData> {
        self.chain_service.adaptor.get_graph_data(graph_id).await
    }
    pub async fn get_withdraw_data(&self, graph_id: &Uuid) -> anyhow::Result<WithdrawData> {
        self.chain_service.adaptor.get_withdraw_data(graph_id).await
    }

    pub async fn get_block_hash(&self, height: u64) -> anyhow::Result<[u8; 32]> {
        self.chain_service.adaptor.get_btc_block_hash(height).await
    }

    pub async fn get_initialized_ids(&self) -> anyhow::Result<Vec<(Uuid, Uuid)>> {
        self.chain_service.adaptor.get_initialized_ids().await
    }

    pub async fn process_withdraw(
        &self,
        btc_client: &BTCClient,
        graph_id: &Uuid,
        tx: &bitcoin::Transaction,
    ) -> anyhow::Result<String> {
        let operator_data = self.get_graph_data(graph_id).await?;
        let tx_id_on_line = Txid::from_slice(&operator_data.kickoff_txid)?;
        let (_root, proof, _leaf, height, index, raw_header) = self
            .check_withdraw_actions_and_get_proof(
                btc_client,
                "withdraw",
                graph_id,
                &tx.compute_txid(),
                &tx_id_on_line,
                Some(WithdrawStatus::Initialized),
            )
            .await?;
        let raw_kickoff_tx = tx_reconstruct(tx);
        self.chain_service
            .adaptor
            .process_withdraw(
                graph_id,
                &raw_kickoff_tx,
                &BitcoinTxProof { raw_header, height, proof, index },
            )
            .await
    }
    pub async fn finish_withdraw_happy_path(
        &self,
        btc_client: &BTCClient,
        graph_id: &Uuid,
        tx: &bitcoin::Transaction,
    ) -> anyhow::Result<String> {
        let operator_data = self.get_graph_data(graph_id).await?;
        let tx_id_on_line = Txid::from_slice(&operator_data.take1_txid)?;
        let (_root, proof, _leaf, height, index, raw_header) = self
            .check_withdraw_actions_and_get_proof(
                btc_client,
                "take1",
                graph_id,
                &tx.compute_txid(),
                &tx_id_on_line,
                Some(WithdrawStatus::Processing),
            )
            .await?;
        let raw_take1_tx = tx_reconstruct(tx);
        self.chain_service
            .adaptor
            .finish_withdraw_happy_path(
                graph_id,
                &raw_take1_tx,
                &BitcoinTxProof { raw_header, height, proof, index },
            )
            .await
    }

    pub async fn finish_withdraw_unhappy_path(
        &self,
        btc_client: &BTCClient,
        graph_id: &Uuid,
        tx: &bitcoin::Transaction,
    ) -> anyhow::Result<String> {
        let operator_data = self.get_graph_data(graph_id).await?;
        let tx_id_on_line = Txid::from_slice(&operator_data.take2_txid)?;
        let (_root, proof, _leaf, height, index, raw_header) = self
            .check_withdraw_actions_and_get_proof(
                btc_client,
                "take2",
                graph_id,
                &tx.compute_txid(),
                &tx_id_on_line,
                Some(WithdrawStatus::Processing),
            )
            .await?;
        let raw_take2_tx = tx_reconstruct(tx);
        self.chain_service
            .adaptor
            .finish_withdraw_unhappy_path(
                graph_id,
                &raw_take2_tx,
                &BitcoinTxProof { raw_header, height, proof, index },
            )
            .await
    }

    pub async fn finish_withdraw_disproved(
        &self,
        btc_client: &BTCClient,
        graph_id: &Uuid,
        disprove_tx: &Transaction,
        challenge_tx: &Transaction,
    ) -> anyhow::Result<String> {
        let (_root, proof, _leaf, height, index, raw_header) = self
            .check_withdraw_actions_and_get_proof(
                btc_client,
                "disprove",
                graph_id,
                &disprove_tx.compute_txid(),
                &disprove_tx.compute_txid(),
                Some(WithdrawStatus::Disproved),
            )
            .await?;
        let raw_disprove_tx = tx_reconstruct(disprove_tx);
        let disprove_proof = BitcoinTxProof { raw_header, height, proof, index };
        let (_root, proof, _leaf, height, index, raw_header) = self
            .check_withdraw_actions_and_get_proof(
                btc_client,
                "challenge",
                graph_id,
                &challenge_tx.compute_txid(),
                &challenge_tx.compute_txid(),
                None,
            )
            .await?;
        let raw_challenge_tx = tx_reconstruct(challenge_tx);
        let challenge_proof = BitcoinTxProof { raw_header, height, proof, index };
        self.chain_service
            .adaptor
            .finish_withdraw_disproved(
                graph_id,
                &raw_disprove_tx,
                &disprove_proof,
                &raw_challenge_tx,
                &challenge_proof,
            )
            .await
    }

    pub async fn post_pegin_data(
        &self,
        btc_client: &BTCClient,
        instance_id: &Uuid,
        tx: &bitcoin::Transaction,
    ) -> anyhow::Result<String> {
        let tx_id = tx.compute_txid();
        tracing::info!("post_pegin_data instance_id:{instance_id}, pegin_tx:{}", tx_id.to_string());
        let mut pegin_txid_posted =
            self.chain_service.adaptor.get_pegin_data(instance_id).await?.pegin_txid;
        if pegin_txid_posted != [0_u8; 32] {
            pegin_txid_posted.reverse();
            tracing::warn!(
                "instance_id:{instance_id} pegin tx already posted, posted:{}",
                hex::encode(pegin_txid_posted)
            );
            bail!(
                "instance_id:{instance_id} pegin tx already posted:{}",
                hex::encode(pegin_txid_posted)
            );
        }

        if self.chain_service.adaptor.pegin_tx_used(&tx_id.to_byte_array()).await? {
            tracing::warn!("instance_id:{instance_id} this pegin tx has already been posted");
            bail!("instance_id:{instance_id} this pegin tx has already been posted");
        }
        let (root, proof, _leaf, height, index, raw_header) =
            btc_client.get_btc_tx_proof_info(&tx_id).await?;

        let (block_hash, merkle_root) =
            self.chain_service.adaptor.parse_btc_block_header(&raw_header).await?;
        let block_hash_online = self.get_block_hash(height).await?;
        if block_hash_online != block_hash {
            tracing::warn!(
                "instance_id:{instance_id}  root mismatch, from chain:{},  in contract:{}",
                hex::encode(block_hash),
                hex::encode(block_hash_online)
            );
            bail!(
                "instance_id:{instance_id}  root mismatch, from chain:{},  in contract:{}",
                hex::encode(block_hash),
                hex::encode(block_hash_online)
            );
        }

        if merkle_root != root {
            tracing::warn!(
                "instance_id:{instance_id} invalid header encoder merkle_root not equal: decode: {},  generate:{}",
                hex::encode(merkle_root),
                hex::encode(root)
            );
            bail!(
                "instance_id:{instance_id} invalid header encoder merkle_root not equal: decode: {},  generate:{}",
                hex::encode(merkle_root),
                hex::encode(root)
            );
        }
        // check proof
        if !self.verify_merkle_proof(&merkle_root, &proof, &tx_id.to_byte_array(), index).await? {
            tracing::warn!("instance_id:{instance_id} check proof failed");
            bail!("instance_id:{instance_id} check proof failed");
        }
        let pegin_amount_sats = tx.output[0].value.to_sat();
        let (min_pegin_fee_sats, pegin_fee_rate) =
            self.chain_service.adaptor.get_pegin_fee_check_info().await?;
        let pegin_fee_sats =
            min_pegin_fee_sats + pegin_amount_sats * pegin_fee_rate / GATEWAY_RATE_MULTIPLIER;
        if pegin_fee_sats >= pegin_amount_sats {
            tracing::warn!(
                "instance_id:{instance_id} pegin amount:{pegin_amount_sats} cannot cover fee:{pegin_fee_sats}"
            );
            bail!(
                "instance_id:{instance_id} pegin amount:{pegin_amount_sats} cannot cover fee:{pegin_fee_sats}"
            );
        }

        let raw_pegin_tx = tx_reconstruct(tx);
        self.chain_service
            .adaptor
            .post_pegin_data(
                instance_id,
                &raw_pegin_tx,
                &BitcoinTxProof { raw_header, height, proof, index },
            )
            .await
    }

    pub async fn post_operate_data(
        &self,
        instance_id: &Uuid,
        graph_id: &Uuid,
        graph: &Graph,
        committee_signs: &[u8],
    ) -> anyhow::Result<String> {
        tracing::info!("post_operate_data instance_id:{}, graph_id:{}", instance_id, graph_id);
        let operator_data = cast_graph_to_graph_data(graph)?;
        let operator_data_online = self.get_graph_data(graph_id).await?;
        if operator_data_online.pegin_txid != [0_u8; 32] {
            tracing::warn!(
                "instance_id:{instance_id} graph_id {graph_id} operator data already posted",
            );
            bail!("instance_id:{instance_id} graph_id {graph_id} operator data already posted");
        }

        let pegin_data = self.get_pegin_data(instance_id).await?;
        if pegin_data.pegin_txid != operator_data.pegin_txid {
            tracing::warn!(
                "instance_id:{instance_id} graph_id {graph_id} operator data pegin txid mismatch, exp:{},  act:{}",
                hex::encode(pegin_data.pegin_txid),
                hex::encode(operator_data.pegin_txid),
            );
            bail!(
                "instance_id:{instance_id} graph_id {graph_id} operator data pegin txid mismatch, exp:{},  act:{}",
                hex::encode(pegin_data.pegin_txid),
                hex::encode(operator_data.pegin_txid),
            );
        }

        let (min_stake_sats, stake_rate) =
            self.chain_service.adaptor.get_stake_amount_check_info().await?;

        let min_stake_for_pegin =
            min_stake_sats + pegin_data.pegin_amount_sats * stake_rate / GATEWAY_RATE_MULTIPLIER;

        if operator_data.stake_amount_sats < min_stake_for_pegin {
            tracing::warn!(
                "instance_id:{instance_id} graph_id {graph_id} operator data insufficient stake amount, staking:{}, min:{min_stake_for_pegin}",
                operator_data.stake_amount_sats,
            );
            bail!(
                "instance_id:{instance_id} graph_id {graph_id} operator data insufficient stake amount, staking:{}, min:{min_stake_for_pegin}",
                operator_data.stake_amount_sats,
            );
        }

        self.chain_service
            .adaptor
            .post_graph_data(instance_id, graph_id, &operator_data, committee_signs)
            .await
    }

    async fn check_withdraw_actions_and_get_proof(
        &self,
        btc_client: &BTCClient,
        tag: &str,
        graph_id: &Uuid,
        tx_act: &Txid,
        tx_id_on_line: &Txid,
        required_status: Option<WithdrawStatus>,
    ) -> anyhow::Result<([u8; 32], Vec<[u8; 32]>, [u8; 32], u64, u64, Vec<u8>)> {
        // check tx id match
        if tx_id_on_line.ne(tx_act) {
            tracing::warn!(
                "graph:{} at {} mismatch, exp:{},  act:{}",
                tag,
                graph_id,
                tx_id_on_line.to_string(),
                tx_act.to_string()
            );
            bail!(
                "graph:{} at {} txid mismatch, exp:{},  act:{}",
                tag,
                graph_id,
                tx_id_on_line.to_string(),
                tx_act.to_string()
            );
        }

        // check withdraw status
        if let Some(status) = required_status {
            let withdraw_data = self.get_withdraw_data(graph_id).await?;
            if withdraw_data.status == WithdrawStatus::Disproved {
                tracing::warn!("graph:{} at {} stage already disproved", tag, graph_id);
                bail!("graph:{} at {} stagealready disproved", tag, graph_id);
            } else if withdraw_data.status != status {
                tracing::warn!(
                    "graph:{} at {} stage not match, exp: {status}, act: {}",
                    tag,
                    graph_id,
                    withdraw_data.status
                );
                bail!(
                    "graph:{} at {} stage not match, exp: {status}, act: {}",
                    tag,
                    graph_id,
                    withdraw_data.status
                );
            }
        }
        // check hash in btc chain and spv contract
        let (root, proof, leaf, height, index, raw_header) =
            btc_client.get_btc_tx_proof_info(tx_act).await?;

        let (block_hash, merkle_root) =
            self.chain_service.adaptor.parse_btc_block_header(&raw_header).await?;
        let block_hash_online = self.get_block_hash(height).await?;
        if block_hash_online != block_hash {
            tracing::warn!(
                "graph_id:{} at: {} root mismatch, from chain:{},  in contract:{}",
                graph_id,
                tag,
                hex::encode(block_hash),
                hex::encode(block_hash_online)
            );
            bail!(
                "graph_id:{} at :{} root mismatch, from chain:{},  in contract:{}",
                graph_id,
                tag,
                hex::encode(block_hash),
                hex::encode(block_hash_online)
            );
        }

        if merkle_root != root {
            tracing::warn!(
                "graph_id:{} at: {} invalid header encoder merkle_root not equal: decode: {},  generate:{}",
                graph_id,
                tag,
                hex::encode(merkle_root),
                hex::encode(root)
            );
            bail!(
                "graph_id:{} at :{}  invalid header encoder merkle_root not equal: decode: {},  generate:{}",
                graph_id,
                tag,
                hex::encode(merkle_root),
                hex::encode(root)
            );
        }

        // check proof
        if !self.verify_merkle_proof(&merkle_root, &proof, &tx_act.to_byte_array(), index).await? {
            tracing::warn!("graph:{} at {} verify_merkle_proof failed ", tag, graph_id,);
            bail!("graph:{} at {} verify_merkle_proof failed ", tag, graph_id,);
        }

        Ok((root, proof.to_vec(), leaf, height, index, raw_header.to_vec()))
    }

    pub async fn get_tx_receipt(
        &self,
        tx_hash: &str,
    ) -> anyhow::Result<Option<TransactionReceipt>> {
        self.chain_service.adaptor.get_tx_receipt(tx_hash).await
    }
}

pub fn tx_reconstruct(tx: &bitcoin::Transaction) -> BitcoinTx {
    BitcoinTx {
        version: tx.version.0 as u32,
        lock_time: tx.lock_time.to_consensus_u32(),
        input_vector: bitcoin::consensus::serialize(&tx.input),
        output_vector: bitcoin::consensus::serialize(&tx.output),
    }
}

pub fn cast_graph_to_graph_data(graph: &Graph) -> anyhow::Result<GraphData> {
    if graph.take1_txid.is_none()
        || graph.assert_init_txid.is_none()
        || graph.assert_commit_txids.is_none()
        || graph.assert_final_txid.is_none()
        || graph.take2_txid.is_none()
    {
        tracing::warn!("grap {}, has none field", graph.graph_id);
        bail!("grap {}, has none field", graph.graph_id);
    }

    // TODO Update
    let pubkey_vec = PublicKey::from_str(&graph.operator)?.to_bytes();

    Ok(GraphData {
        stake_amount_sats: get_stake_amount(graph.amount as u64).to_sat(),
        operator_pubkey_prefix: pubkey_vec[0],
        operator_pubkey: pubkey_vec[1..33].try_into()?,
        pegin_txid: deserialize_hex(&graph.pegin_txid)?,
        kickoff_txid: deserialize_hex(&graph.kickoff_txid.clone().unwrap())?,
        take1_txid: deserialize_hex(&graph.take1_txid.clone().unwrap())?,
        take2_txid: deserialize_hex(&graph.take2_txid.clone().unwrap())?,
        assert_timeout_txid: [0_u8; 32],
        commit_timout_txid: [0_u8; 32],
        nack_txids: vec![],
    })
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
    use crate::client::chain::chain_adaptor::GoatNetwork;
    use crate::client::chain::goat_adaptor::GoatInitConfig;
    use crate::client::{BTCClient, GOATClient};
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
