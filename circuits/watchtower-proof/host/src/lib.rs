#![feature(trim_prefix_suffix)]
//! Generate watchtower proof
//!
use borsh::BorshDeserialize;
use header_chain::{CircuitBlockHeader, HeaderChainCircuitInput, HeaderChainPrevProofType};
use zkm_sdk::{
    HashableKey, Prover, ProverClient, ZKMProof, ZKMProofKind, ZKMProofWithPublicValues, ZKMStdin,
    include_elf,
};

use bitcoin::{Block, Network, Transaction, Txid, hashes::Hash};
use bitcoin_light_client_circuit::build_spv;
use commit_chain::{CommitChainCircuitInput, CommitChainPrevProofType};
use sha2::{Digest, Sha256};
use state_chain::{StateChainCircuitInput, StateChainPrevProofType};
use std::str::FromStr;
use std::sync::OnceLock;
static ELF_ID: OnceLock<String> = OnceLock::new();

/// A program that aggregates the proofs of the simple program.
use proof_builder::{Context, LongRunning, ProofBuilder, ProofRequest};

use clap::Parser;
use std::fs;
// The arguments for the cli.
#[derive(Debug, Clone, Parser, serde::Deserialize, serde::Serialize)]
pub struct Args {
    #[arg(long, default_value_t = true)]
    pub enable: bool,

    #[arg(long, default_value = "http://127.0.0.1:3002")]
    pub esplora_url: String,

    #[clap(long, env)]
    pub genesis_sequencer_commit_txid: String,

    #[clap(long, env)]
    pub latest_sequencer_commit_txid: String,

    #[clap(long, env, short)]
    pub header_chain_input_proof: String,

    #[clap(long, env, short)]
    pub commit_chain_input_proof: String,

    #[clap(long, env, short)]
    pub state_chain_input_proof: String,

    #[clap(long, env)]
    pub output: String,

    #[clap(long, env, default_value_t = 0)]
    pub index: usize,
}

impl LongRunning for Args {
    fn rotate(&self) -> Self {
        let mut next_args = self.clone();
        next_args.index = self.index + 1;
        next_args
    }
}

pub async fn fetch_target_block(
    esplora_url: &str,
    latest_sequencer_commit_txid: &str,
) -> anyhow::Result<(u32, Block, Transaction)> {
    let network = Network::Regtest;
    let btc_client = client::btc_chain::BTCClient::new(network, Some(&esplora_url));
    let latest_sequencer_commit_txid = Txid::from_str(latest_sequencer_commit_txid).unwrap();

    let latest_sequencer_commit_tx =
        btc_client.get_tx(&latest_sequencer_commit_txid).await.unwrap().unwrap();
    // TODO: replace it by `get_raw_transaction_info`
    let tx_merkle_proof =
        btc_client.get_merkle_proof(&latest_sequencer_commit_txid).await.unwrap().unwrap();

    let block_pos = tx_merkle_proof.block_height;
    tracing::info!("block height: {block_pos}");
    let target_block = btc_client.get_block_by_height(block_pos).await.unwrap();
    Ok((block_pos, target_block, latest_sequencer_commit_tx))
}

/// A program that aggregates the proofs of the simple program.
pub const WATCHTOWER: &[u8] = include_elf!("guest");
pub struct WatchtowerProofBuilder {
    client: ProverClient,
    proving_key: zkm_sdk::ZKMProvingKey,
    verifying_key: zkm_sdk::ZKMVerifyingKey,
}

impl WatchtowerProofBuilder {
    pub fn new() -> Self {
        let client = ProverClient::new();
        let (proving_key, verifying_key) = client.setup(WATCHTOWER);
        Self { client, proving_key, verifying_key }
    }
}

impl ProofBuilder for WatchtowerProofBuilder {
    fn client(&self) -> &zkm_sdk::ProverClient {
        &self.client
    }

    fn pk(&self) -> &zkm_sdk::ZKMProvingKey {
        &self.proving_key
    }

    fn vk(&self) -> &zkm_sdk::ZKMVerifyingKey {
        &self.verifying_key
    }

    fn name() -> String {
        "watchtower-chain".to_string()
    }

    fn build_proof(
        &self,
        ctx: &Context,
    ) -> anyhow::Result<(Vec<u8>, ZKMProofWithPublicValues, u64)> {
        let ProofRequest::WatchtowerProofRequest {
            ref header_chain_input_proof,
            ref commit_chain_input_proof,
            ref state_chain_input_proof,
            ref latest_sequencer_commit_txid,
            ref genesis_sequencer_commit_txid,
            ref target_block,
            ref block_pos,
            ref latest_sequencer_commit_tx,
            ..
        } = ctx.request
        else {
            anyhow::bail!("Invalid proof request type");
        };

        // --- header chain --- //
        let bytes = std::fs::read(&format!("{}.in", header_chain_input_proof)).unwrap();
        let mut header_chain_input: HeaderChainCircuitInput = bincode::deserialize(&bytes).unwrap();

        let proof_bytes =
            fs::read(&header_chain_input_proof).expect("Failed to read input proof file");
        let proof: ZKMProofWithPublicValues =
            bincode::deserialize(&proof_bytes).expect("failed to deserialize the proof");
        header_chain_input.pv_hash = proof.public_values.hash().try_into().unwrap();

        let ZKMProof::Compressed(header_compressed_proof) = proof.proof else { panic!() };
        let bytes = std::fs::read(&format!("{}.vk", header_chain_input_proof)).unwrap();
        let header_chain_vk: zkm_sdk::ZKMVerifyingKey = bincode::deserialize(&bytes).unwrap();
        //assert_eq!(header_chain_output.vk_hash, header_chain_vk.hash_u32());

        // --- commit chain --- //
        let bytes = std::fs::read(&format!("{}.in", commit_chain_input_proof)).unwrap();
        let mut commit_chain_input: CommitChainCircuitInput = bincode::deserialize(&bytes).unwrap();

        // Set the previous proof type based on input_proof argument
        let proof_bytes =
            fs::read(&commit_chain_input_proof).expect("Failed to read input proof file");
        let proof: ZKMProofWithPublicValues =
            bincode::deserialize(&proof_bytes).expect("failed to deserialize the proof");

        //let commit_chain_output: CommitChainCircuitOutput = proof.public_values.read();
        commit_chain_input.pv_hash = proof.public_values.hash().try_into().unwrap();

        let ZKMProof::Compressed(commit_compressed_proof) = proof.proof else { panic!() };

        let bytes = std::fs::read(&format!("{}.vk", commit_chain_input_proof)).unwrap();
        let commit_chain_vk: zkm_sdk::ZKMVerifyingKey = bincode::deserialize(&bytes).unwrap();
        //assert_eq!(commit_chain_output.vk_hash, commit_chain_vk.hash_u32());

        // --- state chain --- //
        let bytes = std::fs::read(&format!("{}.in", state_chain_input_proof)).unwrap();
        let mut state_chain_input: StateChainCircuitInput = bincode::deserialize(&bytes).unwrap();

        // Set the previous proof type based on input_proof argument
        let proof_bytes =
            fs::read(&state_chain_input_proof).expect("Failed to read input proof file");
        let proof: ZKMProofWithPublicValues =
            bincode::deserialize(&proof_bytes).expect("failed to deserialize the proof");

        state_chain_input.pv_hash = proof.public_values.hash().try_into().unwrap();
        let ZKMProof::Compressed(state_compressed_proof) = proof.proof else { panic!() };
        let bytes = std::fs::read(&format!("{}.vk", state_chain_input_proof)).unwrap();
        let state_chain_vk: zkm_sdk::ZKMVerifyingKey = bincode::deserialize(&bytes).unwrap();
        // --- spv --- //
        let genesis_sequencer_commit_txid = Txid::from_str(&genesis_sequencer_commit_txid).unwrap();
        let latest_sequencer_commit_txid = Txid::from_str(&latest_sequencer_commit_txid).unwrap();
        /*
        let tx = btc_client.get_tx(&latest_sequencer_commit_txid).await.unwrap().unwrap();
        // TODO: replace it by `get_raw_transaction_info`
        let tx_merkle_proof =
            btc_client.get_merkle_proof(&latest_sequencer_commit_txid).await.unwrap().unwrap();
        let block_pos = tx_merkle_proof.block_height;
        tracing::info!("block height: {block_pos}");
        let target_block = btc_client.get_block_by_height(block_pos).await.unwrap();
        */

        let bitcoin_block_headers = {
            let headers: Vec<u8> = std::fs::read(&format!("{header_chain_input_proof}.blocks"))?;
            headers
                .chunks(80)
                .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
                .collect::<Vec<CircuitBlockHeader>>()
        };
        tracing::info!("block headers: {:?}", bitcoin_block_headers.len());
        let found = bitcoin_block_headers
            .iter()
            .position(|h| h.compute_block_hash() == *target_block.block_hash().as_byte_array());
        tracing::info!("block found: {:?}", found);

        tracing::info!("construct spv");
        let spv = build_spv(
            latest_sequencer_commit_tx,
            *block_pos,
            target_block.clone(),
            &bitcoin_block_headers,
        );

        // Generate the proofs.
        let (proof, cycles) = tracing::info_span!("generate proof").in_scope(|| {
            let mut stdin = ZKMStdin::new();
            stdin.write(&genesis_sequencer_commit_txid.to_byte_array());
            stdin.write(&latest_sequencer_commit_txid.to_byte_array());
            stdin.write(&header_chain_input);
            stdin.write(&commit_chain_input);
            stdin.write(&state_chain_input);
            stdin.write(&spv);

            if commit_chain_input.prev_proof != CommitChainPrevProofType::GenesisBlock {
                stdin.write_proof(*commit_compressed_proof, commit_chain_vk.vk);
            } else {
                tracing::info!("skip writing commit chain proof");
            }

            if header_chain_input.prev_proof != HeaderChainPrevProofType::GenesisBlock {
                stdin.write_proof(*header_compressed_proof, header_chain_vk.vk);
            } else {
                tracing::info!("skip writing header chain proof");
            }

            if state_chain_input.prev_proof != StateChainPrevProofType::GenesisBlock {
                stdin.write_proof(*state_compressed_proof, state_chain_vk.vk);
            } else {
                tracing::info!("skip writing consensus chain proof");
            }

            let elf_id = if ELF_ID.get().is_none() {
                ELF_ID.set(hex::encode(Sha256::digest(&self.proving_key.elf))).unwrap();
                None
            } else {
                Some(ELF_ID.get().unwrap().clone())
            };
            tracing::info!("elf id: {:?}", elf_id);

            self.client
                .prove_with_cycles(&self.proving_key, &stdin, ZKMProofKind::Groth16, elf_id)
                .expect("proving failed")
        });

        Ok((vec![], proof, cycles))
    }

    fn save_proof(
        &self,
        ctx: &Context,
        _input: &[u8],
        _cycles: u64,
        proof: ZKMProofWithPublicValues,
    ) -> anyhow::Result<()> {
        let ProofRequest::WatchtowerProofRequest { ref output, .. } = ctx.request else {
            anyhow::bail!("invalid context");
        };
        std::fs::write(&format!("{}.proof.bin", output), proof.bytes()).unwrap();
        std::fs::write(&format!("{}.public_inputs.bin", output), proof.public_values.to_vec())
            .unwrap();
        std::fs::write(&format!("{}.vk_hash.bin", output), self.verifying_key.bytes32()).unwrap();
        Ok(())
    }

    fn is_long_running(&self) -> bool {
        false
    }
}
