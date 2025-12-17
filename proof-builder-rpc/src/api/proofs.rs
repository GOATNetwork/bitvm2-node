use serde::{Deserialize, Serialize};
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

#[derive(Debug, Serialize, Deserialize, Default)]
pub(super) struct ChainProofDescResponse {
    pub proof_desc: Option<ChainProofDesc>,
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
