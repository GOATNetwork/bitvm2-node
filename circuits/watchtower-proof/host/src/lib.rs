#![feature(trim_prefix_suffix)]
//! Generate watchtower proof
use anyhow::Context;
use bincode::deserialize;
use borsh::BorshDeserialize;
use commit_chain::{CommitChainCircuitInput, CommitChainPrevProofType};
use header_chain::{
    BlockHeaderCircuitOutput, CircuitBlockHeader, HeaderChainCircuitInput, HeaderChainPrevProofType,
};
use zkm_sdk::{
    HashableKey, Prover, ProverClient, ZKMProofKind, ZKMProofWithPublicValues, ZKMStdin,
    include_elf,
};

use bitcoin::{Block, Network, Transaction, Txid, hashes::Hash};
use bitcoin_light_client_circuit::{
    WatchtowerAttestationInputs, build_spv, load_unique_part_stark_vk_witnesses,
    part_stark_vk_attestation_dir,
};
use sha2::{Digest, Sha256};
use state_chain::{StateChainCircuitInput, StateChainCircuitOutput, StateChainPrevProofType};
use std::str::FromStr;
use std::sync::OnceLock;
static ELF_ID: OnceLock<String> = OnceLock::new();

use proof_builder::{LongRunning, ProofBuilder, ProofRequest};

use clap::Parser;
use serde::de::DeserializeOwned;
use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use zkm_verifier::Groth16Verifier;

// The arguments for the cli.
#[derive(Debug, Clone, Parser, serde::Deserialize, serde::Serialize)]
pub struct Args {
    #[arg(long, default_value_t = true)]
    pub enable: bool,

    #[arg(long, env, default_value = "http://127.0.0.1:3002")]
    pub esplora_url: String,

    #[arg(long, env, default_value_t = Network::Regtest)]
    pub bitcoin_network: Network,

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
}

impl LongRunning for Args {
    fn rotate(&self) -> Self {
        self.clone()
    }
}

pub async fn fetch_target_block(
    esplora_url: &str,
    latest_sequencer_commit_txid: &str,
    bitcoin_network: Network,
) -> anyhow::Result<(u32, Block, Transaction)> {
    let btc_client = client::btc_chain::BTCClient::new(bitcoin_network, Some(&esplora_url));
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

fn load_proof_public_output<T: DeserializeOwned>(proof_path: &str) -> anyhow::Result<T> {
    let public_inputs = fs::read(format!("{proof_path}.public_inputs.bin"))
        .context("Failed to read public inputs")?;
    deserialize(&public_inputs).context("Failed to decode proof public outputs")
}

fn load_part_stark_vk(zkm_version: &str) -> anyhow::Result<Vec<u8>> {
    catch_unwind(AssertUnwindSafe(|| Groth16Verifier::get_part_stark_vk(zkm_version).to_vec()))
        .map_err(|_| anyhow::anyhow!("Failed to load part_stark_vk for zkm_version {zkm_version}"))
}

/// Collect both the version-derived verifier key and the recursive inner verifier key
/// for header/state subproofs so witness loading survives Ziren upgrades.
fn collect_requested_part_stark_vks(
    header_chain_input: &HeaderChainCircuitInput,
    header_chain_output: &BlockHeaderCircuitOutput,
    state_chain_input: &StateChainCircuitInput,
    state_chain_output: &StateChainCircuitOutput,
) -> anyhow::Result<Vec<Vec<u8>>> {
    Ok(vec![
        load_part_stark_vk(&header_chain_input.zkm_version)?,
        header_chain_output.part_stark_vk.clone(),
        load_part_stark_vk(&state_chain_input.zkm_version)?,
        state_chain_output.part_stark_vk.clone(),
    ])
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

    #[tracing::instrument(level = "info", skip(self, ctx))]
    fn build_proof(
        &self,
        ctx: &ProofRequest,
    ) -> anyhow::Result<(Vec<u8>, ZKMProofWithPublicValues, u64, f32)> {
        let ProofRequest::WatchtowerProofRequest {
            header_chain_input_proof,
            commit_chain_input_proof,
            state_chain_input_proof,
            latest_sequencer_commit_txid,
            genesis_sequencer_commit_txid,
            target_block,
            block_pos,
            latest_sequencer_commit_tx,
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
            let version_path = format!("{header_chain_input_proof}.zkm_version.bin");
            let zkm_version = fs::read(&version_path)
                .with_context(|| format!("failed to read zkm_version file '{version_path}'"))
                .and_then(|raw_zkm_version| {
                    String::from_utf8(raw_zkm_version).with_context(|| {
                        format!("invalid UTF-8 in zkm_version file '{version_path}'")
                    })
                })?;

            HeaderChainCircuitInput {
                prev_proof: HeaderChainPrevProofType::GenesisBlock, // unused
                zkm_proof,
                zkm_public_values,
                zkm_vk_hash,
                zkm_version,
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
            let version_path = format!("{commit_chain_input_proof}.zkm_version.bin");
            let zkm_version = fs::read(&version_path)
                .with_context(|| format!("failed to read zkm_version file '{version_path}'"))
                .and_then(|raw_zkm_version| {
                    String::from_utf8(raw_zkm_version).with_context(|| {
                        format!("invalid UTF-8 in zkm_version file '{version_path}'")
                    })
                })?;
            CommitChainCircuitInput {
                prev_proof: CommitChainPrevProofType::GenesisBlock, // unused
                zkm_proof,
                zkm_public_values,
                zkm_vk_hash,
                zkm_version,
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
            let version_path = format!("{state_chain_input_proof}.zkm_version.bin");
            let zkm_version = fs::read(&version_path)
                .with_context(|| format!("failed to read zkm_version file '{version_path}'"))
                .and_then(|raw_zkm_version| {
                    String::from_utf8(raw_zkm_version).with_context(|| {
                        format!("invalid UTF-8 in zkm_version file '{version_path}'")
                    })
                })?;
            StateChainCircuitInput {
                prev_proof: StateChainPrevProofType::GenesisBlock, // unused
                zkm_proof,
                zkm_public_values,
                zkm_vk_hash,
                zkm_version,
                blocks: vec![],
            }
        };
        let header_chain_output: BlockHeaderCircuitOutput =
            load_proof_public_output(header_chain_input_proof)?;
        let state_chain_output: StateChainCircuitOutput =
            load_proof_public_output(state_chain_input_proof)?;
        let attestation_dir = part_stark_vk_attestation_dir();
        let requested_part_stark_vks = collect_requested_part_stark_vks(
            &header_chain_input,
            &header_chain_output,
            &state_chain_input,
            &state_chain_output,
        )?;
        let (unique_witnesses, _) =
            load_unique_part_stark_vk_witnesses(&attestation_dir, &requested_part_stark_vks)
                .map_err(anyhow::Error::msg)?;
        let attestation_inputs = WatchtowerAttestationInputs { unique_witnesses };

        // --- spv --- //
        let genesis_sequencer_commit_txid = Txid::from_str(&genesis_sequencer_commit_txid)?;
        let latest_sequencer_commit_txid = Txid::from_str(&latest_sequencer_commit_txid)?;
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
        if found.is_none() {
            anyhow::bail!(
                "Latest sequencer set commitment tx is not included in header chain blocks"
            );
        }

        tracing::info!("construct spv");
        let spv = build_spv(
            latest_sequencer_commit_tx,
            *block_pos,
            target_block.clone(),
            &bitcoin_block_headers,
        );

        // Generate the proofs.
        let (proof, cycles, proving_time) = tracing::info_span!("generate proof").in_scope(
            || -> anyhow::Result<(ZKMProofWithPublicValues, u64, f32)> {
                let mut stdin = ZKMStdin::new();
                stdin.write(&genesis_sequencer_commit_txid.to_byte_array());
                stdin.write(&latest_sequencer_commit_txid.to_byte_array());
                stdin.write(&header_chain_input);
                stdin.write(&commit_chain_input);
                stdin.write(&state_chain_input);
                stdin.write(&attestation_inputs);
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
        let ProofRequest::WatchtowerProofRequest { output, .. } = ctx else {
            anyhow::bail!("invalid context");
        };
        std::fs::write(&format!("{}", output), proof.bytes())?;
        let public_value_hex = hex::encode(proof.public_values.to_vec());
        let proof_size = proof.bytes().len();
        let zkm_version = proof.zkm_version.clone();
        let proof_part_stark_vk = load_part_stark_vk(&zkm_version)?;
        std::fs::write(&format!("{}.public_inputs.bin", output), proof.public_values.to_vec())?;
        std::fs::write(&format!("{}.vk_hash.bin", output), self.verifying_key.bytes32())?;
        std::fs::write(&format!("{}.zkm_version.bin", output), zkm_version)?;
        std::fs::write(&format!("{}.proof_part_stark_vk.bin", output), proof_part_stark_vk)?;
        Ok((public_value_hex, proof_size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header_input(zkm_version: &str) -> HeaderChainCircuitInput {
        HeaderChainCircuitInput {
            prev_proof: HeaderChainPrevProofType::GenesisBlock,
            zkm_proof: vec![],
            zkm_public_values: vec![],
            zkm_vk_hash: vec![],
            zkm_version: zkm_version.to_string(),
            block_headers: vec![],
        }
    }

    fn sample_state_input(zkm_version: &str) -> StateChainCircuitInput {
        StateChainCircuitInput {
            prev_proof: StateChainPrevProofType::GenesisBlock,
            zkm_proof: vec![],
            zkm_public_values: vec![],
            zkm_vk_hash: vec![],
            zkm_version: zkm_version.to_string(),
            blocks: vec![],
        }
    }

    fn sample_header_output(part_stark_vk: Vec<u8>) -> BlockHeaderCircuitOutput {
        BlockHeaderCircuitOutput { chain_state: header_chain::ChainState::new(), part_stark_vk }
    }

    fn sample_state_output(part_stark_vk: Vec<u8>) -> StateChainCircuitOutput {
        StateChainCircuitOutput {
            chain_state: state_chain::StateChainState::new(0, [0u8; 32], Vec::new()),
            part_stark_vk,
        }
    }

    #[test]
    fn test_collect_requested_part_stark_vks_includes_outer_and_inner_versions() {
        let old_vk = load_part_stark_vk("v1.2.4").unwrap();
        let new_vk = load_part_stark_vk("v1.2.5").unwrap();

        let requested = collect_requested_part_stark_vks(
            &sample_header_input("v1.2.5"),
            &sample_header_output(old_vk.clone()),
            &sample_state_input("v1.2.5"),
            &sample_state_output(old_vk.clone()),
        )
        .unwrap();

        assert_eq!(requested, vec![new_vk.clone(), old_vk.clone(), new_vk, old_vk]);
    }
}
