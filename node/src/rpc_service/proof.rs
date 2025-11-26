use client::btc_chain::mempool_v1_type::V1Block;
use serde::{Deserialize, Serialize};
use store::ProofStatus;
use strum::{Display, EnumString};

#[derive(Debug, Deserialize)]
pub struct BtcBlockDescQueryParams {
    #[allow(dead_code)]
    pub proof_type: ProofType,
    pub start_height: Option<u64>, //desc order
    #[serde(default = "default_block_desc_range")]
    pub range: u32,
}
fn default_block_desc_range() -> u32 {
    15
}

#[derive(Debug, Serialize)]
pub struct BtcBlockDesc {
    pub height: u64,
    pub median_fee: u64,
    pub fee_range: Vec<f64>,
    pub total_fees: u64,
    pub size: u64,
    pub tx_count: u64,
    pub timestamp: u64,
    pub proof_status: ProofStatus,
}

impl From<V1Block> for BtcBlockDesc {
    fn from(value: V1Block) -> Self {
        BtcBlockDesc {
            height: value.height,
            median_fee: value.extras.median_fee,
            fee_range: value.extras.fee_range,
            total_fees: value.extras.total_fees,
            size: value.size,
            tx_count: value.tx_count,
            timestamp: value.timestamp,
            proof_status: ProofStatus::Pending,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct BtcBlockDescListResponse {
    pub blocks_desc: Vec<BtcBlockDesc>,
    pub start: u64, // desc order
    pub range: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Display, EnumString)]
#[serde(rename_all = "snake_case")]
pub enum ProofType {
    #[strum(serialize = "header_chain")]
    HeaderChain,
    #[strum(serialize = "commit_chain")]
    CommitChain,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProofDesc {
    pub block_number: i64,
    pub proof_type: ProofType,
    pub state: String,
    pub proving_cycles: i64,
    pub proving_time: i64,
    pub contain_blocks: String,
    pub total_time_to_proof: i64,
    pub proof_size: f64,
    pub zkm_version: String,
    pub pub_inputs: String,
    pub started_at: i64,
    pub updated_at: i64,
}
#[derive(Debug, Deserialize)]
pub struct ProofsQueryParams {
    #[allow(dead_code)]
    pub height: i64,
    #[allow(dead_code)]
    pub proof_type: ProofType,
}

#[derive(Debug, Serialize)]
pub struct ProofResponse {
    pub proof: Option<ProofDesc>,
}
