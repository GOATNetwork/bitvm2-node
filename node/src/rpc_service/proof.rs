use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct ProofsQueryParams {
    #[serde(default = "default_block_range")]
    pub block_range: i64,
}

fn default_block_range() -> i64 {
    5
}

#[derive(Debug, Serialize)]
pub struct ProofItem {
    pub block_number: i64,
    pub proof_state: String,
    pub pure_proof_cast: i64,
    pub started_at: i64,
    pub ended_at: i64,
}

#[derive(Debug, Serialize)]
pub struct Proofs {
    pub block_number: i64,
    pub block_proofs: Vec<ProofItem>,
    pub aggregation_proofs: Vec<ProofItem>,
    pub groth16_proofs: Vec<ProofItem>,
}
