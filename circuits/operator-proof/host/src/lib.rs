//! Generate operator proof
use alloy_primitives::U256;
use anyhow::Context;
use bitcoin::{
    BlockHash, Network, ScriptBuf, Transaction, TxOut, Txid,
    hashes::Hash,
    secp256k1::{PublicKey, XOnlyPublicKey},
};
use borsh::BorshDeserialize;
use client::btc_chain::BTCClient;
use commit_chain::{
    CommitChainCircuitInput, CommitChainPrevProofType, extract_data_from_commitment_outputs,
};
use header_chain::{
    BlockHeaderCircuitOutput, CircuitBlockHeader, HeaderChainCircuitInput, HeaderChainPrevProofType,
};
use proof_builder::{LongRunning, ProofBuilder, ProofRequest};
use state_chain::{StateChainCircuitInput, StateChainCircuitOutput, StateChainPrevProofType};
use std::str::FromStr;
use util::get_btc_block_confirms;
use zkm_sdk::{
    HashableKey, Prover, ProverClient, ZKMProofKind, ZKMProofWithPublicValues, ZKMStdin,
    include_elf,
};
use zkm_verifier::Groth16Verifier;

use bincode::deserialize;
use bitcoin_light_client_circuit::{
    OperatorAttestationInputs, build_spv, load_unique_part_stark_vk_witnesses,
    parse_watchtower_commitment, part_stark_vk_attestation_dir,
};
use bitcoin_script::script;
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
    pub operator_committed_blockhash: String,

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

use serde::de::DeserializeOwned;
use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};

use sha2::{Digest, Sha256};
use std::sync::OnceLock;
static ELF_ID: OnceLock<String> = OnceLock::new();

pub async fn fetch_target_block_and_watchtower_tx(
    esplora_url: &str,
    latest_sequencer_commit_txid: &str,
    operator_committed_blockhash: &str,
    watchtower_challenge_init_txid: &String,
    watchtower_challenge_txids: &str,
    watchtower_public_keys: &str,
    bitcoin_network: Network,
) -> anyhow::Result<(
    u32,
    bitcoin::Block,
    BlockHash,
    Transaction,
    Vec<Transaction>,
    Vec<TxOut>,
    Vec<PublicKey>,
    Vec<ScriptBuf>,
)> {
    let watchtower_challenge_txids: Vec<&str> = watchtower_challenge_txids.split(",").collect();
    let watchtower_public_keys: Vec<&str> = watchtower_public_keys.split(",").collect();
    let btc_client = BTCClient::new(bitcoin_network, Some(&esplora_url));

    let latest_sequencer_commit_txid = Txid::from_str(&latest_sequencer_commit_txid)?;
    let operator_latest_sequencer_commit_txn =
        match btc_client.get_tx(&latest_sequencer_commit_txid).await? {
            Some(tx) => tx,
            None => anyhow::bail!(
                "Failed to fetch latest sequencer commit txn: {}",
                latest_sequencer_commit_txid
            ),
        };
    let tx_status = btc_client.get_tx_status(&latest_sequencer_commit_txid).await?;
    let block_pos_ss_commit = match tx_status.block_height {
        Some(height) => height as u32,
        None => anyhow::bail!(
            "Latest sequencer commit txn is not confirmed yet: {}",
            latest_sequencer_commit_txid
        ),
    };
    tracing::info!("block height of latest ss commit txid: {block_pos_ss_commit}");
    let target_block_ss_commit = btc_client.get_block_by_height(block_pos_ss_commit).await?;

    let operator_committed_blockhash = BlockHash::from_str(operator_committed_blockhash)?;
    let target_block_operator_blockhash =
        match btc_client.get_block_by_hash(&operator_committed_blockhash).await? {
            Some(block) => block,
            None => anyhow::bail!(
                "Failed to fetch operator committed blockhash: {}",
                operator_committed_blockhash
            ),
        };
    let block_pos_operator_committed_blockhash =
        target_block_operator_blockhash.bip34_block_height()? as u32;

    // estimate if the target blocks have been proved.
    let tip_block = btc_client.get_height().await?;
    let delay_blocks = get_btc_block_confirms(btc_client.network());
    if block_pos_ss_commit + delay_blocks >= tip_block
        || block_pos_operator_committed_blockhash + delay_blocks >= tip_block
    {
        anyhow::bail!(
            "Target block is not confirmed enough, tip: {}, ss commit block: {}, operator blockhash commit block: {}, delay_blocks: {}",
            tip_block,
            block_pos_ss_commit,
            block_pos_operator_committed_blockhash,
            delay_blocks
        );
    }

    // --- watchtower_challenge_txns --- //
    let mut watchtower_challenge_txns = Vec::new();
    let mut watchtower_challenge_txn_prev_outs: Vec<TxOut> = Vec::new();
    let mut watchtower_challenge_txn_pubkeys = Vec::new();
    let mut watchtower_challenge_txn_scripts: Vec<ScriptBuf> = Vec::new();

    let watchtower_challlenge_init_txn: Transaction =
        match btc_client.get_tx(&watchtower_challenge_init_txid.parse().unwrap()).await? {
            Some(tx) => tx,
            None => anyhow::bail!(
                "Failed to fetch watchtower challenge init txn: {}",
                watchtower_challenge_init_txid
            ),
        };

    for (id, pk) in watchtower_challenge_txids.iter().zip(watchtower_public_keys.iter()) {
        tracing::info!("txid: {}, pk: {}", id, pk);
        let txid = id.parse()?;
        let txn = match btc_client.get_tx(&txid).await? {
            Some(tx) => tx,
            None => anyhow::bail!("Failed to fetch watchtower challenge txn: {}", id),
        };
        // get prev outs
        // FIXME: update the index
        let index = txn.input[0].previous_output.vout as usize;
        watchtower_challenge_txn_prev_outs
            .push(watchtower_challlenge_init_txn.output[index].clone());

        let public_key = PublicKey::from_str(pk).unwrap();
        watchtower_challenge_txn_pubkeys.push(public_key.clone());
        watchtower_challenge_txns.push(txn);

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
        block_pos_ss_commit,
        target_block_ss_commit,
        operator_committed_blockhash,
        operator_latest_sequencer_commit_txn,
        watchtower_challenge_txns,
        watchtower_challenge_txn_prev_outs,
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

fn load_proof_public_output<T: DeserializeOwned>(proof_path: &str) -> anyhow::Result<T> {
    let public_inputs = fs::read(format!("{proof_path}.public_inputs.bin"))
        .context("Failed to read public inputs")?;
    deserialize(&public_inputs).context("Failed to decode proof public outputs")
}

fn extract_watchtower_part_stark_vk(tx: &Transaction) -> Option<Vec<u8>> {
    let commitment = extract_data_from_commitment_outputs(&tx.output);
    let (_, _, _, _, proof_part_stark_vk) = parse_watchtower_commitment(&commitment).ok()?;
    Some(proof_part_stark_vk)
}

fn load_part_stark_vk(zkm_version: &str) -> anyhow::Result<Vec<u8>> {
    catch_unwind(AssertUnwindSafe(|| Groth16Verifier::get_part_stark_vk(zkm_version).to_vec()))
        .map_err(|_| anyhow::anyhow!("Failed to load part_stark_vk for zkm_version {zkm_version}"))
}

/// Collect both the version-derived verifier key and the recursive inner verifier key
/// for header/state subproofs, plus each watchtower proof verifier key from commitments.
fn collect_requested_part_stark_vks(
    header_chain_input: &HeaderChainCircuitInput,
    header_chain_output: &BlockHeaderCircuitOutput,
    state_chain_input: &StateChainCircuitInput,
    state_chain_output: &StateChainCircuitOutput,
    watchtower_challenge_txns: &[Transaction],
) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut requested_part_stark_vks = vec![
        load_part_stark_vk(&header_chain_input.zkm_version)?,
        header_chain_output.part_stark_vk.clone(),
        load_part_stark_vk(&state_chain_input.zkm_version)?,
        state_chain_output.part_stark_vk.clone(),
    ];
    for tx in watchtower_challenge_txns {
        if let Some(part_stark_vk) = extract_watchtower_part_stark_vk(tx) {
            requested_part_stark_vks.push(part_stark_vk);
        }
    }
    Ok(requested_part_stark_vks)
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

    #[tracing::instrument(level = "info", skip(self, ctx))]
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

            target_block_ss_commit,
            block_pos_ss_commit,
            operator_latest_sequencer_commit_txn,

            operator_committed_blockhash,

            watchtower_challenge_txns,
            watchtower_challenge_txn_prev_outs,
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
        let requested_part_stark_vks = collect_requested_part_stark_vks(
            &header_chain_input,
            &header_chain_output,
            &state_chain_input,
            &state_chain_output,
            watchtower_challenge_txns,
        )?;
        let attestation_dir = part_stark_vk_attestation_dir();
        let (unique_witnesses, _) =
            load_unique_part_stark_vk_witnesses(&attestation_dir, &requested_part_stark_vks)
                .map_err(anyhow::Error::msg)?;
        let attestation_inputs = OperatorAttestationInputs { unique_witnesses };

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

        let found = bitcoin_block_headers.iter().position(|h| {
            h.compute_block_hash() == *target_block_ss_commit.block_hash().as_byte_array()
        });
        tracing::info!("block found: {:?}", found);
        if found.is_none() {
            anyhow::bail!(
                "Latest sequencer set commitment tx is not included in header chain blocks"
            );
        }

        tracing::info!("block headers: {:?}", bitcoin_block_headers.len());
        tracing::info!(
            "construct spv for ss commit, {}",
            operator_latest_sequencer_commit_txn.compute_txid()
        );
        let spv_ss_commit = build_spv(
            &operator_latest_sequencer_commit_txn,
            *block_pos_ss_commit,
            target_block_ss_commit.clone(),
            &bitcoin_block_headers,
        );

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

                stdin.write(&header_chain_input);
                stdin.write(&commit_chain_input);
                stdin.write(&state_chain_input);
                stdin.write(&attestation_inputs);
                stdin.write(&spv_ss_commit);
                stdin.write(&operator_committed_blockhash.to_byte_array());

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
        let public_value_hex = hex::encode(proof.public_values.to_vec());
        let proof_size = proof.bytes().len();
        let zkm_version = proof.zkm_version.clone();
        std::fs::write(&format!("{}.public_inputs.bin", output), proof.public_values.to_vec())?;
        std::fs::write(&format!("{}.vk_hash.bin", output), self.verifying_key.bytes32())?;
        std::fs::write(&format!("{}.zkm_version.bin", output), zkm_version)?;
        let proof = bincode::serialize(&proof).unwrap();
        std::fs::write(&format!("{}", output), proof)?;
        Ok((public_value_hex, proof_size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Bn254;

    use ark_groth16::{Groth16, r1cs_to_qap::LibsnarkReduction};
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use zkm_verifier::{Groth16Verifier, IMM_GROTH16_VK_BYTES, convert_ark_imm_wrap_vk};

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
    fn test_collect_requested_part_stark_vks_includes_outer_inner_and_watchtower_keys() {
        let old_vk = load_part_stark_vk("v1.2.4").unwrap();
        let new_vk = load_part_stark_vk("v1.2.5").unwrap();

        let graph_id = [7u8; 16];
        let proof = vec![3u8; 260];
        let public_inputs = vec![9u8; 36];
        let vk_hash = "ab".repeat(33);
        let watchtower_comm = bitcoin_light_client_circuit::build_watchtower_commitment(
            &graph_id,
            &proof,
            &public_inputs,
            &vk_hash,
            &new_vk,
        )
        .unwrap();
        let watchtower_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: bitcoin::Amount::ZERO,
                script_pubkey: bitcoin::ScriptBuf::new_op_return(watchtower_comm.as_ref()),
            }],
        };

        let requested = collect_requested_part_stark_vks(
            &sample_header_input("v1.2.5"),
            &sample_header_output(old_vk.clone()),
            &sample_state_input("v1.2.5"),
            &sample_state_output(old_vk.clone()),
            &[watchtower_tx],
        )
        .unwrap();

        assert_eq!(requested, vec![new_vk.clone(), old_vk.clone(), new_vk.clone(), old_vk, new_vk]);
    }

    #[tokio::test]
    #[ignore = "local test"]
    async fn test_parse_operator_proof() {
        let proof_path = "/home/ubuntu/data/proof-builder-rpc/circuits/data/operator/3c2917b82fe14ef7b8cc8bef3ecd700f.bin";
        let proof_bytes = std::fs::read(proof_path).unwrap();
        let vk_bytes = fs::read(format!("{proof_path}.vk_hash.bin")).unwrap();

        let proof: ZKMProofWithPublicValues = bincode::deserialize(&proof_bytes).unwrap();

        let a: bitcoin_light_client_circuit::OperatorPublicOutputs =
            proof.public_values.clone().read();
        println!(
            "block hash: {:?}, constant: {:?}, included map: {:?}",
            hex::encode(a.btc_best_block_hash),
            hex::encode(a.constant),
            U256::from_le_bytes(a.included_watchtowers)
        );

        let vk_hash = String::from_utf8(vk_bytes).unwrap();
        let part_stark_vk = catch_unwind(AssertUnwindSafe(|| {
            Groth16Verifier::get_part_stark_vk(&proof.zkm_version)
        }))
        .map_err(|_| {
            anyhow::anyhow!("Failed to load part_stark_vk for zkm_version {}", proof.zkm_version)
        })
        .unwrap();
        let ark_proof =
            convert_ark_imm_wrap_vk(&proof, &vk_hash, &IMM_GROTH16_VK_BYTES, part_stark_vk)
                .unwrap();

        // Verify the arkworks proof.
        let ok = Groth16::<Bn254, LibsnarkReduction>::verify_proof(
            &ark_proof.groth16_vk,
            &ark_proof.proof,
            &ark_proof.public_inputs,
        )
        .unwrap();
        assert!(ok);
    }
}
