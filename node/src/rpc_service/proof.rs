use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

#[derive(Debug, Deserialize)]
pub struct BtcBlockDescQueryParams {
    #[allow(dead_code)]
    pub start_height: Option<i64>, //desc order
    #[allow(dead_code)]
    pub offset: Option<u32>,
    #[serde(default = "default_block_desc_limit")]
    #[allow(dead_code)]
    pub limit: Option<u32>,
}
fn default_block_desc_limit() -> Option<u32> {
    Some(6)
}

#[derive(Debug, Serialize)]
pub struct BtcBlockDesc {
    pub height: i64,
    pub median_fee: f64,
    pub fee_range: Vec<f64>,
    pub total_fees: f64,
    pub tx_count: i64,
    pub timestamp: u64,
}

#[derive(Debug, Serialize)]
pub struct BtcBlockDescListResponse {
    pub blocks_desc: Vec<BtcBlockDesc>,
    pub start: i64, // desc order
    pub range: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Display, EnumString)]
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
