//! Generate operator proof
use alloy_primitives::U256;
use anyhow::Context;
use ark_serialize::CanonicalSerialize;
use bitcoin::{
    Network, ScriptBuf, Transaction, TxOut, Txid,
    hashes::Hash,
    secp256k1::{PublicKey, XOnlyPublicKey},
};
use bitcoin_light_client_circuit::build_spv;
use bitcoin_script::script;
use borsh::BorshDeserialize;
use client::btc_chain::BTCClient;
use commit_chain::{CommitChainCircuitInput, CommitChainPrevProofType};
use header_chain::{
    CircuitBlockHeader, CircuitTransaction, HeaderChainCircuitInput, HeaderChainPrevProofType,
};
use proof_builder::{LongRunning, ProofBuilder, ProofRequest};
use state_chain::{StateChainCircuitInput, StateChainPrevProofType};
use std::str::FromStr;
use zkm_sdk::{
    HashableKey, Prover, ProverClient, ZKMProofKind, ZKMProofWithPublicValues, ZKMStdin,
    include_elf,
};
use zkm_verifier::{GROTH16_VK_BYTES, convert_ark};

use clap::Parser;
/// The arguments for the cli.
#[derive(Debug, Clone, Parser, serde::Deserialize, serde::Serialize)]
pub struct Args {
    #[arg(long, default_value_t = true)]
    pub enable: bool,

    #[arg(long, env, default_value = "http://127.0.0.1:3002")]
    pub esplora_url: String,

    #[arg(long, env, default_value_t = Network::Regtest)]
    pub bitcoin_network: Network,

    #[clap(long, env)]
    pub included_watchtowers: String,

    #[clap(long, env)]
    pub graph_id: String,

    #[clap(long, env)]
    pub latest_sequencer_commit_txid: String,

    #[clap(long, env)]
    pub genesis_sequencer_commit_txid: String,

    #[clap(long, env, short)]
    pub header_chain_input_proof: String,

    #[clap(long, env, short)]
    pub commit_chain_input_proof: String,

    #[clap(long, env, short)]
    pub state_chain_input_proof: String,

    #[clap(long, env, short)]
    pub execution_layer_block_number: u64,

    #[clap(long, env, short)]
    pub watchtower_challenge_txids: String,

    #[clap(long, env, short)]
    pub watchtower_public_keys: String,

    #[clap(long, env, short)]
    pub watchtower_challenge_init_txid: String,

    #[clap(long, env, default_value = "commit-proof.bin")]
    pub output: String,
}

impl LongRunning for Args {
    fn rotate(&self) -> Self {
        self.clone()
    }
}

/// A program that aggregates the proofs of the simple program.
const OPERATOR: &[u8] = include_elf!("guest");

use std::fs;

use sha2::{Digest, Sha256};
use std::sync::OnceLock;
static ELF_ID: OnceLock<String> = OnceLock::new();

pub async fn fetch_target_block_and_watchtower_tx(
    esplora_url: &str,
    latest_sequencer_commit_txid: &str,
    watchtower_challenge_init_txid: &String,
    watchtower_challenge_txids: &str,
    watchtower_public_keys: &str,
    bitcoin_network: Network,
) -> anyhow::Result<(
    u32,
    bitcoin::Block,
    bitcoin::Transaction,
    Vec<CircuitTransaction>,
    Vec<TxOut>,
    Vec<usize>,
    Vec<bitcoin::secp256k1::PublicKey>,
    Vec<ScriptBuf>,
)> {
    let watchtower_challenge_txids: Vec<&str> = watchtower_challenge_txids.split(",").collect();
    let watchtower_public_keys: Vec<&str> = watchtower_public_keys.split(",").collect();
    let btc_client = BTCClient::new(bitcoin_network, Some(&esplora_url));
    let latest_sequencer_commit_txid = Txid::from_str(&latest_sequencer_commit_txid).unwrap();
    let operator_latest_sequencer_commit_txn =
        btc_client.get_tx(&latest_sequencer_commit_txid).await.unwrap().unwrap();

    // TODO: replace it by `get_raw_transaction_info`
    let tx_merkle_proof =
        btc_client.get_merkle_proof(&latest_sequencer_commit_txid).await.unwrap().unwrap();

    let block_pos = tx_merkle_proof.block_height;
    tracing::info!("block height: {block_pos}");
    let target_block = btc_client.get_block_by_height(block_pos).await.unwrap();

    // --- watchtower_challenge_txns --- //
    let mut watchtower_challenge_txns = Vec::new();
    let mut watchtower_challenge_txn_prev_outs: Vec<TxOut> = Vec::new();
    let mut watchtower_challenge_txn_prev_indices: Vec<usize> = Vec::new();
    let mut watchtower_challenge_txn_pubkeys = Vec::new();
    let mut watchtower_challenge_txn_scripts: Vec<ScriptBuf> = Vec::new();

    let watchtower_challlenge_init_txn: Transaction =
        btc_client.get_tx(&watchtower_challenge_init_txid.parse().unwrap()).await.unwrap().unwrap();

    for (id, pk) in watchtower_challenge_txids.iter().zip(watchtower_public_keys.iter()) {
        tracing::info!("txid: {}, pk: {}", id, pk);
        let txid = id.parse().unwrap();
        let txn = btc_client.get_tx(&txid).await.unwrap().unwrap();
        // get prev outs
        // FIXME: update the index
        let index = txn.input[0].previous_output.vout as usize;
        watchtower_challenge_txn_prev_outs
            .push(watchtower_challlenge_init_txn.output[index].clone());
        watchtower_challenge_txn_prev_indices.push(index);

        let public_key = PublicKey::from_str(pk).unwrap();
        watchtower_challenge_txn_pubkeys.push(public_key.clone());
        watchtower_challenge_txns.push(CircuitTransaction(txn));

        // https://github.com/GOATNetwork/BitVM/blob/GA/goat/src/transactions/watchtower_challenge.rs#L45
        // generate_pay_to_pubkey_taproot_script
        let watchtower_challenge_txn_script: ScriptBuf = {
            let public_key: XOnlyPublicKey = public_key.into();
            script! {
                { public_key }
                OP_CHECKSIG
            }
            .compile()
        };
        watchtower_challenge_txn_scripts.push(watchtower_challenge_txn_script);
    }

    Ok((
        block_pos,
        target_block,
        operator_latest_sequencer_commit_txn,
        watchtower_challenge_txns,
        watchtower_challenge_txn_prev_outs,
        watchtower_challenge_txn_prev_indices,
        watchtower_challenge_txn_pubkeys,
        watchtower_challenge_txn_scripts,
    ))
}
pub struct OperatorProofBuilder {
    client: ProverClient,
    proving_key: zkm_sdk::ZKMProvingKey,
    verifying_key: zkm_sdk::ZKMVerifyingKey,
    // database handle
}

impl OperatorProofBuilder {
    pub fn new() -> Self {
        let client = ProverClient::new();
        let (proving_key, verifying_key) = client.setup(OPERATOR);
        Self { client, proving_key, verifying_key }
    }
}

impl ProofBuilder for OperatorProofBuilder {
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
        "operator-chain".to_string()
    }

    #[tracing::instrument(level = "info", skip(self))]
    fn build_proof(
        &self,
        ctx: &ProofRequest,
    ) -> anyhow::Result<(Vec<u8>, ZKMProofWithPublicValues, u64, f32)> {
        let ProofRequest::OperatorProofRequest {
            included_watchtowers,
            graph_id,
            header_chain_input_proof,
            commit_chain_input_proof,
            state_chain_input_proof,
            genesis_sequencer_commit_txid,
            target_block,
            block_pos,
            operator_latest_sequencer_commit_txn,

            watchtower_challenge_txns,
            watchtower_challenge_txn_prev_outs,
            watchtower_challenge_txn_prev_indices,
            watchtower_challenge_txn_pubkeys,
            watchtower_challenge_txn_scripts,
            ..
        } = ctx
        else {
            anyhow::bail!("Invalid proof request type");
        };

        // --- header chain --- //
        let header_chain_input = {
            let zkm_public_values =
                fs::read(&format!("{}.public_inputs.bin", header_chain_input_proof)).unwrap();
            let zkm_proof = fs::read(header_chain_input_proof)
                .context("Failed to read input proof file")
                .unwrap();
            let zkm_vk_hash =
                fs::read(&format!("{}.vk_hash.bin", header_chain_input_proof)).unwrap();
            let prev_output = zkm_sdk::ZKMPublicValues::from(&zkm_public_values).read();
            let prev_proof = HeaderChainPrevProofType::PrevProof(prev_output);

            HeaderChainCircuitInput {
                prev_proof,
                zkm_proof,
                zkm_public_values,
                zkm_vk_hash,
                block_headers: vec![],
            }
        };

        // --- commit chain --- //
        let commit_chain_input = {
            let zkm_public_values =
                fs::read(&format!("{}.public_inputs.bin", commit_chain_input_proof)).unwrap();
            let zkm_proof = fs::read(commit_chain_input_proof)
                .context("Failed to read input proof file")
                .unwrap();
            let zkm_vk_hash =
                fs::read(&format!("{}.vk_hash.bin", commit_chain_input_proof)).unwrap();
            let prev_output = zkm_sdk::ZKMPublicValues::from(&zkm_public_values).read();
            let prev_proof = CommitChainPrevProofType::PrevProof(prev_output);
            CommitChainCircuitInput {
                prev_proof,
                zkm_proof,
                zkm_public_values,
                zkm_vk_hash,
                commits: vec![],
            }
        };

        // --- state chain --- //
        let state_chain_input = {
            let zkm_proof = fs::read(state_chain_input_proof)
                .context("Failed to read input proof file")
                .unwrap();
            let zkm_public_values =
                fs::read(&format!("{}.public_inputs.bin", state_chain_input_proof)).unwrap();
            let zkm_vk_hash =
                fs::read(&format!("{}.vk_hash.bin", state_chain_input_proof)).unwrap();
            let prev_output = zkm_sdk::ZKMPublicValues::from(&zkm_public_values).read();
            let prev_proof = StateChainPrevProofType::PrevProof(prev_output);
            StateChainCircuitInput {
                prev_proof,
                zkm_proof,
                zkm_public_values,
                zkm_vk_hash,
                blocks: vec![],
            }
        };

        // --- spv --- //
        //let latest_sequencer_commit_txid = Txid::from_str(&latest_sequencer_commit_txid).unwrap();

        let operator_genesis_sequencer_commit_txid =
            Txid::from_str(&genesis_sequencer_commit_txid)?;

        let bitcoin_block_headers = {
            let headers: Vec<u8> = std::fs::read(&format!("{header_chain_input_proof}.blocks"))
                .context("read header chain blocks error")?;
            headers
                .chunks(80)
                .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
                .collect::<Vec<CircuitBlockHeader>>()
        };

        let found = bitcoin_block_headers
            .iter()
            .position(|h| h.compute_block_hash() == *target_block.block_hash().as_byte_array());
        tracing::info!("block found: {:?}", found);
        if found.is_none() {
            anyhow::bail!(
                "Latest sequencer set commitment tx is not included in header chain blocks"
            );
        }

        tracing::info!("block headers: {:?}", bitcoin_block_headers.len());
        tracing::info!("construct spv");
        let spv = build_spv(
            &operator_latest_sequencer_commit_txn,
            *block_pos,
            target_block.clone(),
            &bitcoin_block_headers,
        );

        //let eth_client_execution_input: EthClientExecutorInput =
        //    fetch_exection_layer_block(&args).await;
        //println!(
        //    "el block hash: {}",
        //    eth_client_execution_input.current_block.header.hash_slow().to_string()
        //);

        // Generate the proofs
        let (proof, cycles, proving_time) = tracing::info_span!("generate proof").in_scope(
            || -> anyhow::Result<(ZKMProofWithPublicValues, u64, f32)> {
                let mut stdin = ZKMStdin::new();

                let included_watchtowers: U256 = U256::from_str(&included_watchtowers).unwrap();
                stdin.write(&included_watchtowers);

                stdin.write(&graph_id);

                stdin.write(&operator_genesis_sequencer_commit_txid.to_byte_array());
                stdin.write(&operator_latest_sequencer_commit_txn);

                stdin.write(&watchtower_challenge_txns);
                stdin.write(&watchtower_challenge_txn_pubkeys);
                stdin.write(&watchtower_challenge_txn_scripts);
                stdin.write(&watchtower_challenge_txn_prev_outs);
                stdin.write(&watchtower_challenge_txn_prev_indices);

                stdin.write(&header_chain_input);
                stdin.write(&commit_chain_input);
                stdin.write(&state_chain_input);
                stdin.write(&spv);

                let elf_id = if ELF_ID.get().is_none() {
                    ELF_ID
                        .set(hex::encode(Sha256::digest(&self.proving_key.elf)))
                        .map_err(anyhow::Error::msg)?;
                    None
                } else {
                    Some(ELF_ID.get().unwrap().clone())
                };
                tracing::info!("elf id: {:?}", elf_id);

                let proving_start = tokio::time::Instant::now();
                let (proof, cycles) = self.client.prove_with_cycles(
                    &self.proving_key,
                    &stdin,
                    ZKMProofKind::Groth16,
                    elf_id,
                )?;
                let proving_duration = proving_start.elapsed().as_secs_f32() * 1000.0;
                Ok((proof, cycles, proving_duration))
            },
        )?;
        Ok((vec![], proof, cycles, proving_time))
    }

    fn save_proof(
        &self,
        ctx: &ProofRequest,
        _input: &[u8],
        _cycles: u64,
        proof: ZKMProofWithPublicValues,
    ) -> anyhow::Result<(String, usize)> {
        let ProofRequest::OperatorProofRequest { output, .. } = ctx else {
            anyhow::bail!("invalid context");
        };
        //fs::write(&args.output, bincode::serialize(&proof).unwrap()).unwrap();
        //fs::write(&format!("{}.vk", args.output), bincode::serialize(&proof_vk).unwrap()).unwrap();
        //println!("Generate proof successfully, proof: {:?}", proof);

        let groth16_vk = &GROTH16_VK_BYTES;
        let ark_proof = convert_ark(&proof, self.verifying_key.bytes32().as_ref(), groth16_vk)?;

        let mut writer = std::fs::File::create(format!("{}", output))?;
        let proof_size = ark_proof.proof.serialized_size(ark_serialize::Compress::Yes);
        ark_proof.proof.serialize_compressed(&mut writer)?;

        let mut writer = std::fs::File::create(format!("{}.vk.bin", output))?;
        ark_proof.groth16_vk.serialize_compressed(&mut writer)?;

        let mut writer = std::fs::File::create(format!("{}.public_inputs.bin", output))?;
        ark_proof.public_inputs.serialize_compressed(&mut writer)?;

        let content = std::fs::read(format!("{}.public_inputs.bin", output))
            .context("failed to read public inputs")?;
        let public_value_hex = hex::encode(content);

        tracing::info!("Generate proof successfully, Ark proof: {:?}", ark_proof);
        Ok((public_value_hex, proof_size))
    }
}
