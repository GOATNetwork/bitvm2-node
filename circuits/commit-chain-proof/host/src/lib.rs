use bitcoin::{Network, Txid, hashes::Hash, secp256k1::PublicKey};
use client::btc_chain::BTCClient;
use commit_chain::*;
use proof_builder::{LongRunning, ProofBuilder, ProofRequest};
use std::str::FromStr;
use zkm_sdk::{
    HashableKey, Prover, ProverClient, ZKMProof, ZKMProofKind, ZKMProofWithPublicValues, ZKMStdin,
    include_elf,
};

use sha2::{Digest, Sha256};
use std::sync::OnceLock;
static ELF_ID: OnceLock<String> = OnceLock::new();
use anyhow::Context;

/// A program that aggregates the proofs of the simple program.
const COMMIT_CHAIN: &[u8] = include_elf!("guest");

use std::fs;

use clap::Parser;
/// The arguments for the cli.
#[derive(Debug, Clone, Parser, serde::Deserialize, serde::Serialize)]
pub struct Args {
    #[arg(long, default_value_t = true)]
    pub enable: bool,

    #[arg(long, default_value_t = Network::Regtest)]
    pub btc_network: Network,

    #[arg(long, default_value = "http://127.0.0.1:3002")]
    pub esplora_url: String,

    #[arg(long, env)]
    pub commit_info: String,

    #[arg(long, default_value = "commits.bin")]
    pub commits: String,

    #[clap(long, env, default_value_t = 1)]
    pub batch_size: usize,

    #[clap(long, env, default_value_t = 0)]
    pub start: usize,

    #[clap(long, env, default_value_t = false)]
    pub init_input: bool,

    #[clap(long, env, default_value = "input.bin")]
    pub input_proof: String,

    #[clap(long, env, default_value = "output.bin")]
    pub output_proof: String,
}

impl LongRunning for Args {
    fn rotate(&self) -> Self {
        let mut next_args = self.clone();
        next_args.input_proof = self.output_proof.clone();
        next_args.init_input = false;
        next_args.start = self.start + self.batch_size;
        next_args.output_proof = format!(
            "{}/{}-{}.bin",
            std::path::Path::new(&self.output_proof).parent().unwrap().to_str().unwrap(),
            next_args.start,
            self.batch_size
        );
        next_args.commit_info = format!(
            "{}/commit_info.json.{}",
            std::path::Path::new(&self.output_proof).parent().unwrap().to_str().unwrap(),
            next_args.start,
        );
        next_args
    }
}

pub async fn fetch_commit_chain(
    esplora_url: &str,
    commit_info_file: &str,
    commits_file: &str,
    start: usize,
    batch_size: usize,
    network: Network,
) -> anyhow::Result<Vec<CircuitCommit>> {
    let btc_client = BTCClient::new(network, Some(&esplora_url));

    let rdr = std::fs::File::open(commit_info_file).context("read error")?;
    let ci: CommitInfo = serde_json::from_reader(rdr)?;
    // NOTE: we support one commit-info per commit file currently
    assert_eq!(batch_size, 1);

    let mut commits: Vec<CircuitCommit> = vec![];
    for _i in start..start + batch_size {
        let txid = Txid::from_str(&ci.txid)?;
        let commit_txn = btc_client.get_tx(&txid).await?.unwrap();
        let proof = btc_client.get_merkle_proof_extend(&txid).await?;
        let block_height = proof.height as u32;

        let op_return_data = extract_op_return_data(&commit_txn.output);
        let mut sequencer_set_hash: [u8; 32] = [0u8; 32];
        sequencer_set_hash.copy_from_slice(&op_return_data);

        if let tendermint::Hash::Sha256(expected_hash) = sequencer_hash(&ci.sequencers) {
            assert_eq!(expected_hash, sequencer_set_hash);
        } else {
            panic!("Invalid sequencer set hash");
        }

        let publisher_public_keys = ci
            .publisher_public_keys
            .iter()
            .map(|compressed_pk| PublicKey::from_str(compressed_pk).unwrap())
            .collect();
        tracing::info!("sequencer_hash: {:?}", sequencer_hash(&ci.sequencers));
        let commit = CircuitCommit {
            commit_txn,
            sequencers: ci.sequencers.clone(),
            publisher_public_keys,
            threshold: ci.threshold,
            genesis_txid: Txid::from_str(&ci.genesis_txid)?.as_raw_hash().to_byte_array(),
            block_height,
        };
        commits.push(commit);
    }
    std::fs::write(&commits_file, serde_json::to_vec(&commits)?)
        .expect(&format!("write {commits_file} error"));
    Ok(commits)
}

/// A program that aggregates the proofs of the simple program.
pub struct CommitChainProofBuilder {
    client: ProverClient,
    proving_key: zkm_sdk::ZKMProvingKey,
    verifying_key: zkm_sdk::ZKMVerifyingKey,
}

impl CommitChainProofBuilder {
    pub fn new() -> Self {
        let client = ProverClient::new();
        let (proving_key, verifying_key) = client.setup(COMMIT_CHAIN);
        Self { client, proving_key, verifying_key }
    }
}

impl ProofBuilder for CommitChainProofBuilder {
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
        "commit-chain".to_string()
    }

    fn build_proof(
        &self,
        ctx: &proof_builder::ProofRequest,
    ) -> anyhow::Result<(Vec<u8>, ZKMProofWithPublicValues, u64, f32)> {
        let ProofRequest::CommitChainProofRequest { init_input, input_proof, commits, .. } = ctx
        else {
            anyhow::bail!("Invalid proof request type");
        };

        let vk_hash = self.verifying_key.hash_u32();
        // Set the previous proof type based on input_proof argument
        let prev_receipt = if *init_input {
            None
        } else {
            let proof_bytes = fs::read(input_proof).context("Failed to read input proof file")?;
            let proof: ZKMProofWithPublicValues = bincode::deserialize(&proof_bytes)?;
            Some(proof)
        };
        let (prev_proof, pv_hash) = match prev_receipt.clone() {
            Some(mut receipt) => {
                let request = receipt.public_values.read();
                let pv_hash: [u8; 32] = receipt.public_values.hash().try_into().unwrap();
                (CommitChainPrevProofType::PrevProof(request), pv_hash)
            }
            None => (CommitChainPrevProofType::GenesisBlock, [0u8; 32]),
        };

        let input: CommitChainCircuitInput =
            CommitChainCircuitInput { vk_hash, pv_hash, prev_proof, commits: commits.to_vec() };

        //let output = commit_chain_circuit(input.clone());
        //tracing::info!("Commit chain circuit output: {:?}", output);
        // Generate the proofs.
        let (proof, cycles, proving_time) = tracing::info_span!("generate proof").in_scope(
            || -> anyhow::Result<(ZKMProofWithPublicValues, u64, f32)> {
                let mut stdin = ZKMStdin::new();
                stdin.write(&input);

                if let Some(proof) = prev_receipt {
                    let ZKMProof::Compressed(compressed_proof) = proof.proof else { panic!() };
                    stdin.write_proof(*compressed_proof, self.verifying_key.vk.clone());
                    tracing::info!("Write prev proof into stdin");
                } else {
                    tracing::info!("Skip writing proof for genesis commit");
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
                let proving_start = tokio::time::Instant::now();
                let (proof, cycles) = self.client.prove_with_cycles(
                    &self.proving_key,
                    &stdin,
                    ZKMProofKind::Compressed,
                    elf_id,
                )?;
                let proving_duration = proving_start.elapsed().as_secs_f32() * 1000.0;
                Ok((proof, cycles, proving_duration))
            },
        )?;

        tracing::info!("Commit chain proof cycles: {}", cycles);

        if let Err(e) = self.client.verify(&proof, &self.verifying_key) {
            panic!("{}", e);
        }

        let input = bincode::serialize(&input)?;
        Ok((input, proof, cycles, proving_time))
    }

    fn save_proof(
        &self,
        ctx: &proof_builder::ProofRequest,
        input: &[u8],
        _cycles: u64,
        proof: ZKMProofWithPublicValues,
    ) -> anyhow::Result<(String, usize)> {
        let ProofRequest::CommitChainProofRequest { output_proof, .. } = ctx else {
            anyhow::bail!("Invalid commit chain input");
        };
        fs::write(&output_proof, bincode::serialize(&proof)?)?;
        let public_value_hex = hex::encode(proof.public_values.as_slice());
        let proof_size = proof.bytes().len();
        fs::write(&format!("{}.vk", output_proof), bincode::serialize(&self.verifying_key)?)?;
        fs::write(&format!("{}.in", output_proof), input)?;
        tracing::info!("Generate proof successfully, proof: {:?}", proof);
        Ok((public_value_hex, proof_size))
    }
}
