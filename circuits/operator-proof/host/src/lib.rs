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
use header_chain::CircuitTransaction;
use header_chain::{CircuitBlockHeader, HeaderChainCircuitInput, HeaderChainPrevProofType};
use proof_builder::{LongRunning, ProofBuilder, ProofRequest};
use state_chain::{StateChainCircuitInput, StateChainPrevProofType};
use std::str::FromStr;
use zkm_sdk::{
    HashableKey, Prover, ProverClient, ZKMProof, ZKMProofKind, ZKMProofWithPublicValues, ZKMStdin,
    include_elf,
};
use zkm_verifier::{GROTH16_VK_BYTES, convert_ark};

use clap::Parser;
/// The arguments for the cli.
#[derive(Debug, Clone, Parser, serde::Deserialize, serde::Serialize)]
pub struct Args {
    #[arg(long, default_value_t = true)]
    pub enable: bool,

    #[arg(long, default_value = "http://127.0.0.1:3002")]
    pub esplora_url: String,

    #[arg(long, default_value_t = Network::Regtest)]
    pub btc_network: Network,

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
    btc_network: Network,
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
    let btc_client = BTCClient::new(btc_network, Some(&esplora_url));
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

    fn build_proof(
        &self,
        ctx: &ProofRequest,
    ) -> anyhow::Result<(Vec<u8>, ZKMProofWithPublicValues, u64)> {
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
        let bytes = std::fs::read(&format!("{}.in", header_chain_input_proof))
            .context("read header chain in error")?;
        let mut header_chain_input: HeaderChainCircuitInput = bincode::deserialize(&bytes)?;

        let proof_bytes =
            fs::read(&header_chain_input_proof).context("Failed to read input proof file")?;
        let proof: ZKMProofWithPublicValues = bincode::deserialize(&proof_bytes)?;
        header_chain_input.pv_hash = proof.public_values.hash().try_into().unwrap();

        let ZKMProof::Compressed(header_compressed_proof) = proof.proof else { panic!() };
        let bytes =
            std::fs::read(&format!("{}.vk", header_chain_input_proof)).context("read vk error")?;
        let header_chain_vk: zkm_sdk::ZKMVerifyingKey = bincode::deserialize(&bytes)?;
        //assert_eq!(header_chain_output.vk_hash, header_chain_vk.hash_u32());

        // --- commit chain --- //
        let bytes = std::fs::read(&format!("{}.in", commit_chain_input_proof))
            .context("read commit chain in error")?;
        let mut commit_chain_input: CommitChainCircuitInput = bincode::deserialize(&bytes)?;

        // Set the previous proof type based on input_proof argument
        let proof_bytes =
            fs::read(&commit_chain_input_proof).context("Failed to read input proof file")?;
        let proof: ZKMProofWithPublicValues = bincode::deserialize(&proof_bytes)?;

        //let commit_chain_output: CommitChainCircuitOutput = proof.public_values.read();
        commit_chain_input.pv_hash = proof.public_values.hash().try_into().unwrap();

        let ZKMProof::Compressed(commit_compressed_proof) = proof.proof else { panic!() };

        let bytes = std::fs::read(&format!("{}.vk", commit_chain_input_proof))
            .context("read statechain vk error")?;
        let commit_chain_vk: zkm_sdk::ZKMVerifyingKey = bincode::deserialize(&bytes)?;
        //assert_eq!(commit_chain_output.vk_hash, commit_chain_vk.hash_u32());

        // --- state chain --- //
        let bytes = std::fs::read(&format!("{}.in", state_chain_input_proof))
            .context("read state chain in error")?;
        let mut state_chain_input: StateChainCircuitInput = bincode::deserialize(&bytes)?;

        // Set the previous proof type based on input_proof argument
        let proof_bytes =
            fs::read(&state_chain_input_proof).context("Failed to read input proof file")?;
        let proof: ZKMProofWithPublicValues = bincode::deserialize(&proof_bytes)?;

        state_chain_input.pv_hash = proof.public_values.hash().try_into().unwrap();
        let ZKMProof::Compressed(state_compressed_proof) = proof.proof else { panic!() };
        let bytes = std::fs::read(&format!("{}.vk", state_chain_input_proof))
            .context("read state chain vk error")?;
        let state_chain_vk: zkm_sdk::ZKMVerifyingKey = bincode::deserialize(&bytes)?;
        // --- spv --- //
        //let latest_sequencer_commit_txid = Txid::from_str(&latest_sequencer_commit_txid).unwrap();

        let operator_genesis_sequencer_commit_txid =
            Txid::from_str(&genesis_sequencer_commit_txid)?;
        /*
        let operator_latest_sequencer_commit_txn =
            btc_client.get_tx(&latest_sequencer_commit_txid).await.unwrap().unwrap();
        //println!("operator_latest_seqeuncer_commit_txn: {:?}", operator_latest_sequencer_commit_txn);

        // TODO: replace it by `get_raw_transaction_info`
        let tx_merkle_proof =
            btc_client.get_merkle_proof(&latest_sequencer_commit_txid).await.unwrap().unwrap();
        let block_pos = tx_merkle_proof.block_height;
        tracing::info!("block height: {block_pos}");
        let target_block = btc_client.get_block_by_height(block_pos).await.unwrap();
        */

        let bitcoin_block_headers = {
            let headers: Vec<u8> = std::fs::read(&format!("{header_chain_input_proof}.blocks"))
                .context("read header chain blocks error")?;
            headers
                .chunks(80)
                .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
                .collect::<Vec<CircuitBlockHeader>>()
        };
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
        let (proof, cycles) = tracing::info_span!("generate proof").in_scope(
            || -> anyhow::Result<(ZKMProofWithPublicValues, u64)> {
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

                if commit_chain_input.prev_proof != CommitChainPrevProofType::GenesisBlock {
                    stdin.write_proof(*commit_compressed_proof, commit_chain_vk.vk);
                } else {
                    tracing::info!("Skip writing commit chain proof");
                }

                if header_chain_input.prev_proof != HeaderChainPrevProofType::GenesisBlock {
                    stdin.write_proof(*header_compressed_proof, header_chain_vk.vk);
                } else {
                    tracing::info!("Skip writing header chain proof");
                }

                if state_chain_input.prev_proof != StateChainPrevProofType::GenesisBlock {
                    stdin.write_proof(*state_compressed_proof, state_chain_vk.vk);
                } else {
                    tracing::info!("Skip writing state chain proof");
                }

                let elf_id = if ELF_ID.get().is_none() {
                    ELF_ID
                        .set(hex::encode(Sha256::digest(&self.proving_key.elf)))
                        .map_err(anyhow::Error::msg)?;
                    None
                } else {
                    Some(ELF_ID.get().unwrap().clone())
                };
                tracing::info!("elf id: {:?}", elf_id);

                Ok(self.client.prove_with_cycles(
                    &self.proving_key,
                    &stdin,
                    ZKMProofKind::Groth16,
                    elf_id,
                )?)
            },
        )?;
        Ok((vec![], proof, cycles))
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
