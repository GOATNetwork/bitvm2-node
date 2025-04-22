use crate::chain::chain::Chain;
use crate::chain::chain_adaptor::{
    ChainAdaptor, GoatNetwork, OperatorData, PeginData, WithdrawData, get_chain_adaptor,
};
use crate::chain::goat_adaptor::GoatInitConfig;
use crate::esplora::get_esplora_url;
use anyhow::format_err;
use bitcoin::hashes::Hash;
use bitcoin::{Address as BtcAddress, TxMerkleNode, Txid};
use bitcoin::{Block, Network};
use esplora_client::{AsyncClient, Builder, MerkleProof, Utxo};
use store::localdb::LocalDB;
use uuid::Uuid;

pub struct BitVM2Client {
    pub local_db: LocalDB,
    pub esplora: AsyncClient,
    pub btc_network: Network,
    pub chain_service: Chain,
}

impl BitVM2Client {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        db_path: String,
        esplora_url: Option<&str>,
        btc_network: Network,
        goat_network: GoatNetwork,
        goat_config: Option<GoatInitConfig>,
    ) -> Self {
        let local_db = LocalDB::new(&format!("sqlite:{db_path}"), true).await;
        local_db.migrate().await;
        Self {
            local_db,
            esplora: Builder::new(esplora_url.unwrap_or(get_esplora_url(btc_network)))
                .build_async()
                .expect("Could not build esplora client"),
            btc_network,
            chain_service: Chain::new(get_chain_adaptor(goat_network, goat_config, None)),
        }
    }

    pub async fn fetch_btc_block(&self, block_height: u32) -> anyhow::Result<Block> {
        let block_hash = self.esplora.get_block_hash(block_height).await?;
        Ok(self.esplora.get_block_by_hash(&block_hash).await?.ok_or(anyhow::format_err!(
            "failed to fetch block at :{} hash:{}",
            block_height,
            block_hash.to_string()
        ))?)
    }

    pub async fn fetch_btc_address_utxos(&self, address: BtcAddress) -> anyhow::Result<Vec<Utxo>> {
        Ok(self.esplora.get_address_utxo(address).await?)
    }

    pub async fn get_bitc_merkle_proof(
        &self,
        tx_id: &Txid,
    ) -> anyhow::Result<(TxMerkleNode, MerkleProof)> {
        let proof = self.esplora.get_merkle_proof(tx_id).await?;
        if let Some(proof) = proof {
            let block_hash = self.esplora.get_block_hash(proof.block_height).await?;
            let header = self.esplora.get_header_by_hash(&block_hash).await?;
            return Ok((header.merkle_root, proof));
        }

        Err(format_err!("get {} merkle proof is none", tx_id))
    }

    pub async fn verify_merkle_proof(
        &self,
        tx_id: &Txid,
        root: &TxMerkleNode,
        proof_info: &MerkleProof,
    ) -> anyhow::Result<bool> {
        let root = root.to_byte_array().map(|v| v);
        let poof: Vec<[u8; 32]> =
            proof_info.merkle.iter().map(|v| v.to_byte_array().map(|v| v)).collect();
        let res = self
            .chain_service
            .adaptor
            .verify_merkle_proof(
                &root,
                &poof,
                &tx_id.to_byte_array().map(|v| v),
                proof_info.pos as u64,
            )
            .await?;
        Ok(res)
    }

    pub async fn pegin_tx_used(&self, tx_id: &[u8; 32]) -> anyhow::Result<bool> {
        self.chain_service.adaptor.pegin_tx_used(tx_id).await
    }

    pub async fn get_pegin_data(&self, instance_id: Uuid) -> anyhow::Result<PeginData> {
        self.chain_service.adaptor.get_pegin_data(instance_id).await
    }
    pub async fn is_operator_withdraw(&self, graph_id: Uuid) -> anyhow::Result<bool> {
        self.chain_service.adaptor.is_operator_withdraw(graph_id).await
    }
    pub async fn get_operator_data(&self, graph_id: Uuid) -> anyhow::Result<OperatorData> {
        self.chain_service.adaptor.get_operator_data(graph_id).await
    }
}
