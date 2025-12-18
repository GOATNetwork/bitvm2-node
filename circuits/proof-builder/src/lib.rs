use anyhow::Result;
use bitcoin::{Block, ScriptBuf, Transaction, TxOut};
use commit_chain::CircuitCommit;
use header_chain::{CircuitBlockHeader, CircuitTransaction};
use state_chain::CircuitStateBlock;
use thiserror::Error;
use zkm_sdk::{ProverClient, ZKMProofWithPublicValues};
use zkm_sdk::{ZKMProvingKey, ZKMVerifyingKey};

#[derive(Debug, Clone)]
pub enum ProofRequest {
    HeaderChainProofRequest {
        init_input: bool,
        input_proof: String,
        output_proof: String,
        start: usize,
        batch_size: usize,
        total_block_headers: Vec<CircuitBlockHeader>,
    },
    CommitChainProofRequest {
        commit_info: String,
        commits: Vec<CircuitCommit>,
        init_input: bool,
        input_proof: String,
        output_proof: String,
    },
    StateChainProofRequest {
        init_input: bool,
        input_proof: String,
        output_proof: String,
        batch_size: u64,
        start: u64,
        l2_contract_address: String,
        blocks: Vec<CircuitStateBlock>,
    },
    WatchtowerProofRequest {
        genesis_sequencer_commit_txid: String,
        latest_sequencer_commit_txid: String,
        header_chain_input_proof: String,
        commit_chain_input_proof: String,
        state_chain_input_proof: String,
        output: String,
        target_block: Block,
        block_pos: u32,
        latest_sequencer_commit_tx: Transaction,
    },
    OperatorProofRequest {
        included_watchtowers: String,
        graph_id: [u8; 16],
        genesis_sequencer_commit_txid: String,
        header_chain_input_proof: String,
        commit_chain_input_proof: String,
        state_chain_input_proof: String,
        execution_layer_block_number: u64,
        output: String,
        target_block: Block,
        block_pos: u32,
        operator_latest_sequencer_commit_txn: Transaction,
        watchtower_challenge_txns: Vec<CircuitTransaction>,
        watchtower_challenge_txn_prev_outs: Vec<TxOut>,
        watchtower_challenge_txn_prev_indices: Vec<usize>,
        watchtower_challenge_txn_pubkeys: Vec<bitcoin::secp256k1::PublicKey>,
        watchtower_challenge_txn_scripts: Vec<ScriptBuf>,
    },
}

#[derive(Error, Debug, Clone)]
pub enum ProofError {
    #[error("Retry after {0} seconds")]
    InputNotReady(u64),
    #[error("File {0} not found")]
    FileNotExit(String),
}

pub trait ProofBuilder {
    fn client(&self) -> &ProverClient;
    fn pk(&self) -> &ZKMProvingKey;
    fn vk(&self) -> &ZKMVerifyingKey;

    fn build_proof(&self, ctx: &ProofRequest) -> Result<(Vec<u8>, ZKMProofWithPublicValues, u64)>;

    fn save_proof(
        &self,
        ctx: &ProofRequest,
        input: &[u8],
        cycles: u64,
        proof: ZKMProofWithPublicValues,
    ) -> anyhow::Result<()>;

    fn name() -> String;
}

pub trait LongRunning {
    fn rotate(&self) -> Self;
}

#[derive(Debug, Default)]
pub struct OnDemandTask {
    pub latest_sequencer_commit_txid: String,
    pub header_chain_input_proof: String,
    pub commit_chain_input_proof: String,
    pub state_chain_input_proof: String,

    pub watchtower_challenge_init_txid: Option<String>,
    pub watchtower_challenge_txids: Option<Vec<String>>,
    pub watchtower_public_keys: Option<Vec<String>>,
}
