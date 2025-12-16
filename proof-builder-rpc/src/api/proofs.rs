use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub(super) struct ChainProofDescRequest {
    pub height: Option<i64>,
    pub proof_type: String,
}

#[derive(Debug, Serialize, Default)]
pub(super) struct ChainProofDesc {
    pub block_start: i64,
    pub block_end: i64,
    pub proof_type: String,
    pub state: String,
    pub proving_cycles: i64,
    pub proving_time: i64,
    pub total_time_to_proof: i64,
    pub proof_size: f64,
    pub zkm_version: String,
    pub pub_values: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Serialize, Default)]
pub(super) struct ChainProofDescResponse {
    pub proof_desc : Option<ChainProofDesc>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct OperatorProofRequest {
    pub instance_id: String,
    pub graph_id: String,
    pub execution_layer_block_number: i64,
}

#[derive(Debug, Serialize)]
pub(super) struct OperatorProofResponse {}

#[derive(Debug, Deserialize)]
pub(super) struct WatchtowerProofRequest {
    pub instance_id: String,
    pub graph_id: String,
    pub public_key: String,
    pub challenge_txid: String,
    pub challenge_init_txid: String,
    pub execution_layer_block_number: i64,
}

#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub(super) struct WatchtowerProofResponse {}
