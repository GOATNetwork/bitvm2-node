use serde::{Deserialize, Serialize};
use std::fs;
use strum::{Display, EnumString};

const HEADER_CHAIN_NAME: &str = "header-chain";
const COMMIT_CHAIN_NAME: &str = "commit-chain";
const STATE_CHAIN_NAME: &str = "state-chain";
#[derive(Clone, Debug, Serialize, Deserialize, Display, EnumString)]
#[serde(rename_all = "snake_case")]
pub(super) enum ProofType {
    #[strum(serialize = "header_chain")]
    HeaderChain,
    #[strum(serialize = "commit_chain")]
    CommitChain,
    #[strum(serialize = "state_chain")]
    StateChain,
}

impl ProofType {
    pub(super) fn get_chain_name(&self) -> &'static str {
        match self {
            ProofType::HeaderChain => HEADER_CHAIN_NAME,
            ProofType::CommitChain => COMMIT_CHAIN_NAME,
            ProofType::StateChain => STATE_CHAIN_NAME,
        }
    }
}
#[derive(Debug, Deserialize)]
pub(super) struct ChainProofDescRequest {
    pub height: Option<i64>,
    pub proof_type: ProofType,
}
#[derive(Debug, Serialize, Deserialize, Default)]
pub(super) struct ProofDesc {
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
pub(super) struct OperatorProofDescRequest {
    pub instance_id: String,
    pub graph_id: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub(super) struct ProofDescResponse {
    pub proof_desc: Option<ProofDesc>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct OperatorProofRequest {
    pub instance_id: String,
    pub graph_id: String,
    pub execution_layer_block_number: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct ProofData {
    pub proof: Vec<u8>,
    pub groth16_vk: Vec<u8>,
    pub public_inputs: Vec<u8>,
}

impl ProofData {
    pub(super) fn load_proof_data(path: &str) -> Self {
        Self {
            proof: fs::read(format!("{path}.proof.bin")).unwrap_or_default(),
            groth16_vk: fs::read(format!("{path}.vk.bin")).unwrap_or_default(),
            public_inputs: fs::read(format!("{path}.public_inputs.bin")).unwrap_or_default(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct OperatorProofResponse {
    pub proof_data: Option<ProofData>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct WatchtowerProofRequest {
    pub instance_id: String,
    pub graph_id: String,
    pub public_key: String,
    pub challenge_txid: String,
    pub challenge_init_txid: String,
    pub execution_layer_block_number: i64,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub(super) struct WatchtowerProofResponse {
    pub proof_data: Option<ProofData>,
    pub error: Option<String>,
}
