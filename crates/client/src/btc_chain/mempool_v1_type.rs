use crate::btc_chain::esplora_bitcoin_adaptor::get_esplora_url;
use bitcoin::{BlockHash, Network};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct V1Block {
    pub height: u64,
    pub timestamp: u64,
    pub tx_count: u64,
    pub size: u64,
    pub extras: V1BlockExtras,
    // pub id: String,
    // pub version: u64,
    // pub bits: u64,
    // pub nonce: u64,
    // pub difficulty: f64,
    // pub merkle_root: String,
    // pub weight: u64,
    // pub previousblockhash: Option<String>,
    // pub mediantime: u64,
    // #[serde(default)]
    // pub stale: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct V1BlockExtras {
    #[serde(rename = "totalFees")]
    pub total_fees: u64,
    #[serde(rename = "medianFee")]
    pub median_fee: u64,
    #[serde(rename = "feeRange")]
    pub fee_range: Vec<f64>,
    // pub reward: u64,
    // pub pool: V1PoolInfo,
    // #[serde(rename = "avgFee")]
    // pub avg_fee: u64,
    // #[serde(rename = "avgFeeRate")]
    // pub avg_fee_rate: u64,
    // #[serde(rename = "coinbaseRaw")]
    // pub coinbase_raw: String,
    // #[serde(rename = "coinbaseAddress")]
    // pub coinbase_address: Option<String>,
    // #[serde(rename = "coinbaseAddresses")]
    // pub coinbase_addresses: Vec<String>,
    // #[serde(rename = "coinbaseSignature")]
    // pub coinbase_signature: String,
    // #[serde(rename = "coinbaseSignatureAscii")]
    // pub coinbase_signature_ascii: String,
    // #[serde(rename = "avgTxSize")]
    // pub avg_tx_size: f64,
    // #[serde(rename = "totalInputs")]
    // pub total_inputs: u64,
    // #[serde(rename = "totalOutputs")]
    // pub total_outputs: u64,
    // #[serde(rename = "totalOutputAmt")]
    // pub total_output_amt: u64,
    // #[serde(rename = "medianFeeAmt", default)]
    // pub median_fee_amt: Option<u64>,
    // #[serde(rename = "feePercentiles", default)]
    // pub fee_percentiles: Option<Vec<f64>>,
    // #[serde(rename = "segwitTotalTxs")]
    // pub segwit_total_txs: u64,
    // #[serde(rename = "segwitTotalSize")]
    // pub segwit_total_size: u64,
    // #[serde(rename = "segwitTotalWeight")]
    // pub segwit_total_weight: u64,
    // pub header: String,
    // #[serde(rename = "utxoSetChange")]
    // pub utxo_set_change: u64,
    // #[serde(rename = "utxoSetSize")]
    // pub utxo_set_size: Option<u64>,
    // #[serde(rename = "totalInputAmt")]
    // pub total_input_amt: Option<u64>,
    // #[serde(rename = "virtualSize")]
    // pub virtual_size: f64,
    // #[serde(rename = "firstSeen")]
    // pub first_seen: Option<u64>,
    // pub orphans: Vec<u64>,
    // #[serde(rename = "matchRate")]
    // pub match_rate: Option<f64>,
    // #[serde(rename = "expectedFees")]
    // pub expected_fees: Option<u64>,
    // #[serde(rename = "expectedWeight")]
    // pub expected_weight: Option<u64>,
    // #[serde(default)]
    // pub similarity: Option<f64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct V1PoolInfo {
    pub id: u64,
    pub name: String,
    pub slug: String,
    #[serde(rename = "minerNames")]
    pub miner_names: Option<Vec<String>>,
}

pub type V1Blocks = Vec<V1Block>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MempoolBlock {
    #[serde(rename = "blockSize")]
    pub block_size: u64,
    #[serde(rename = "blockVSize")]
    pub block_v_size: f64,
    #[serde(rename = "nTx")]
    pub n_tx: u64,
    #[serde(rename = "medianFee")]
    pub median_fee: u64,
    #[serde(rename = "feeRange")]
    pub fee_range: Vec<f64>,
    #[serde(rename = "totalFees")]
    pub total_fees: u64,
}

pub type MempoolBlocks = Vec<MempoolBlock>;

pub fn get_v1_block_url(network: Network, block_hash: BlockHash) -> String {
    let base_url = get_esplora_url(network);
    format!("{base_url}/v1/block/{block_hash}")
}

pub fn get_v1_blocks_url(network: Network, block_height: Option<u64>) -> String {
    let base_url = get_esplora_url(network);
    let path =
        block_height.map(|h| format!("/v1/blocks/{h}")).unwrap_or_else(|| "/v1/blocks".to_string());
    format!("{base_url}{path}")
}

pub fn get_v1_mempool_blocks_url(network: Network) -> String {
    format!("{}/v1/fees/mempool-blocks", get_esplora_url(network))
}
