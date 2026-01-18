use bitcoin::{Network, Txid, hashes::Hash, secp256k1::PublicKey};
use client::btc_chain::BTCClient;
use commit_chain::*;
use proof_builder::{LongRunning, ProofBuilder, ProofRequest};
use std::str::FromStr;
use zkm_sdk::{
    HashableKey, Prover, ProverClient, ZKMProofKind, ZKMProofWithPublicValues, ZKMStdin,
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

    #[arg(long, env, default_value_t = Network::Regtest)]
    pub bitcoin_network: Network,

    #[arg(long, env, default_value = "http://127.0.0.1:3002")]
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
        next_args.commits = format!("{}.commits", next_args.input_proof);
        next_args
    }
}

pub async fn fetch_commit_chain(
    esplora_url: &str,
    commit_info_file: &str,
    commits_file: &str,
    network: Network,
) -> anyhow::Result<Vec<CircuitCommit>> {
    let btc_client = BTCClient::new(network, Some(&esplora_url));

    tracing::info!(
        "Fetching commit chain, commit_info_file: {}, commits_file: {}",
        commit_info_file,
        commits_file
    );
    let rdr = std::fs::File::open(commit_info_file).context(&("read error"))?;
    let ci: CommitInfo = serde_json::from_reader(rdr)?;
    let mut commits: Vec<CircuitCommit> = vec![];
    let txid = Txid::from_str(&ci.txid)?;
    let commit_txn = btc_client.get_tx_status(&txid).await?;
    let block_height = commit_txn.block_height.unwrap();
    let commit_txn = btc_client.get_tx(&txid).await?.unwrap();

    let op_return_data = extract_op_return_data(&commit_txn.output);
    let mut sequencer_set_hash: [u8; 32] = [0u8; 32];
    sequencer_set_hash.copy_from_slice(&op_return_data[0..32]);

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

    #[tracing::instrument(level = "info", skip(self))]
    fn build_proof(
        &self,
        ctx: &proof_builder::ProofRequest,
    ) -> anyhow::Result<(Vec<u8>, ZKMProofWithPublicValues, u64, f32)> {
        let ProofRequest::CommitChainProofRequest { init_input, input_proof, commits, .. } = ctx
        else {
            anyhow::bail!("Invalid proof request type");
        };

        //let mut zkm_vk_hash = self.verifying_key.hash_u32();
        // Set the previous proof type based on input_proof argument
        let prev_receipt = if *init_input {
            None
        } else {
            let public_inputs = fs::read(&format!("{}.public_inputs.bin", input_proof))
                .context("Read public input")?;
            //let prev: CommitChainCircuitOutput = serde_json::from_slice(&public_inputs).unwrap();
            Some(public_inputs)
        };
        let (prev_proof, zkm_proof, zkm_public_values, zkm_vk_hash) = match prev_receipt.clone() {
            Some(public_inputs) => {
                let proof_bytes =
                    fs::read(input_proof).context("Failed to read input proof file")?;
                let zkm_vk_hash =
                    fs::read(&format!("{}.vk_hash.bin", input_proof)).context("Read vk hash")?;
                let prev_output: CommitChainCircuitOutput =
                    zkm_sdk::ZKMPublicValues::from(&public_inputs).read();
                (
                    CommitChainPrevProofType::PrevProof(prev_output),
                    proof_bytes,
                    public_inputs,
                    zkm_vk_hash.to_vec(),
                )
            }
            None => (CommitChainPrevProofType::GenesisBlock, Vec::new(), Vec::new(), Vec::new()),
        };

        let input: CommitChainCircuitInput = CommitChainCircuitInput {
            zkm_vk_hash,
            zkm_proof,
            prev_proof,
            commits: commits.to_vec(),
            zkm_public_values,
        };

        //let output = commit_chain_circuit(input.clone());
        //tracing::info!("Commit chain circuit output: {:?}", output);
        // Generate the proofs.
        let (proof, cycles, proving_time) = tracing::info_span!("generate proof").in_scope(
            || -> anyhow::Result<(ZKMProofWithPublicValues, u64, f32)> {
                let mut stdin = ZKMStdin::new();
                stdin.write(&input);

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
        _input: &[u8],
        _cycles: u64,
        proof: ZKMProofWithPublicValues,
    ) -> anyhow::Result<(String, usize)> {
        let ProofRequest::CommitChainProofRequest { output_proof, .. } = ctx else {
            anyhow::bail!("Invalid commit chain input");
        };
        //fs::write(&output_proof, bincode::serialize(&proof)?)?;
        //let public_value_hex = hex::encode(proof.public_values.as_slice());
        //let proof_size = proof.bytes().len();
        //fs::write(&format!("{}.vk", output_proof), bincode::serialize(&self.verifying_key)?)?;
        //fs::write(&format!("{}.in", output_proof), input)?;
        //tracing::info!("Generate proof successfully, proof: {:?}", proof);
        //Ok((public_value_hex, proof_size))

        std::fs::write(&format!("{}", output_proof), proof.bytes())?;
        let public_value_hex = hex::encode(proof.public_values.to_vec());
        let proof_size = proof.bytes().len();
        std::fs::write(
            &format!("{}.public_inputs.bin", output_proof),
            proof.public_values.to_vec(),
        )?;
        std::fs::write(&format!("{}.vk_hash.bin", output_proof), self.verifying_key.bytes32())?;
        Ok((public_value_hex, proof_size))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use tracing::info;

    #[test]
    #[ignore = "local test"]
    fn test_parse_commit_chain_proof() {
        let proof_path = "/home/ubuntu/data/proof-builder-rpc/circuits/data/commit-chain/10-1.bin.public_inputs.bin";
        let proof_bytes = std::fs::read(proof_path).unwrap();
        let mut pis = zkm_sdk::ZKMPublicValues::from(&proof_bytes);
        let public_input: CommitChainCircuitOutput = pis.read();
        let hash = sequencer_hash(&public_input.chain_state.sequencers);
        println!("proof: {public_input:?}, hash : {:?}", hash);

        //let input_path = "/home/ubuntu/data/proof-builder-rpc/circuits/data/commit-chain/commit_info.json.8";
        let input_path = "/home/ubuntu/data/stephen/bitvm2-node/circuits/data/commit-chain/commit_info.json.latest";
        let input_bytes = std::fs::read(input_path).unwrap();
        let commit_info: CommitInfo = serde_json::from_slice(&input_bytes).unwrap();
        info!("commit info: {:?}", commit_info);
        let hash_expected = sequencer_hash(&commit_info.sequencers);
        info!("hash expected: {:?}", hash_expected);
        assert_eq!(hash, hash_expected);
    }
}
