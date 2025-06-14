use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct ProofsQueryParams {
    pub block_number: Option<i64>,
    #[serde(default = "default_block_range")]
    pub block_range: i64,
    pub graph_id: Option<String>,
}

fn default_block_range() -> i64 {
    5
}

#[derive(Debug, Serialize)]
pub struct ProofItem {
    pub block_number: i64,
    pub state: String,
    pub proving_time: i64,
    pub total_time_to_proof: i64,
    pub proof_size: i64,
    pub zkm_version: String,
    pub started_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Serialize)]
pub struct Proofs {
    pub block_number: i64,
    pub block_proofs: Vec<ProofItem>,
    pub aggregation_proofs: Vec<ProofItem>,
    pub groth16_proofs: Vec<ProofItem>,
}

#[derive(Debug, Serialize)]
pub struct ProofsOverview {
    pub total_blocks: i64,
    pub avg_block_proof: i64,
    pub avg_aggregation_proof: i64,
    pub avg_groth16_proof: i64,
}
