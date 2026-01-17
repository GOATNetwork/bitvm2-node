use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

#[derive(Clone, Debug, Serialize, Deserialize, Display, EnumString)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::enum_variant_names)]
pub enum ProofType {
    #[strum(serialize = "header_chain")]
    HeaderChain,
    #[strum(serialize = "commit_chain")]
    CommitChain,
    #[strum(serialize = "state_chain")]
    StateChain,
}

#[derive(Debug, Deserialize)]
pub struct ChainProofDescRequest {
    pub height: Option<i64>,
    pub proof_type: ProofType,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ProofDesc {
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
    pub prev_proof_number: Option<i64>,
    pub next_proof_number: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct OperatorProofDescRequest {
    pub instance_id: String,
    pub graph_id: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ProofDescResponse {
    pub proof_desc: Option<ProofDesc>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OperatorProofRequest {
    pub instance_id: String,
    pub graph_id: String,
    pub blockhash_commit_txid: String,
    pub execution_layer_block_number: i64,
    pub watchtower_challenge_txids: Vec<String>,
    pub included_watchtowers: Vec<bool>,
    pub watchtower_challenge_init_txid: String,
    pub watchtower_challenge_pubkeys: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofData {
    pub proof: Vec<u8>,
    pub vk: String,
    pub public_inputs: Vec<u8>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct OperatorProofResponse {
    pub proof_data: Option<ProofData>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WatchtowerProofRequest {
    pub instance_id: String,
    pub graph_id: String,
    pub public_key: String,
    // it's updated by operators and used for generating operator proof.
    pub challenge_txid: String,
    pub challenge_init_txid: String,
    pub execution_layer_block_number: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WatchtowerProofResponse {
    pub proof_data: Option<ProofData>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OperatorProofTimeoutUpdateRequest {
    pub instance_id: String,
    pub graph_id: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct OperatorProofTimeoutUpdateResponse {
    pub instance_id: String,
    pub graph_id: String,
    pub data: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WatchtowerProofTimeoutUpdateRequest {
    pub instance_id: String,
    pub graph_id: String,
    pub public_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WatchtowerProofTimeoutUpdateResponse {
    pub instance_id: String,
    pub graph_id: String,
    pub public_key: String,
    pub data: Option<String>,
    pub error: Option<String>,
}
