//! Generate header chain proof
//! Example:
//! ```
//! export BITCOIN_NETWORK=regtest
//! RUST_LOG=debug cargo run -r -- --latest-sequencer-commit-txid 7b5fde8cc49a0afe1bfd6534d63d3549d4b03394dab978642db866b74f6fa62c --header-chain-input-proof ../../header-chain-proof/host/0-10.bin --commit-chain-input-proof ../../commit-chain-proof/host/compressed.bin --output "output.bin"
//! RUST_LOG=debug cargo run -r -- --latest-sequencer-commit-txid b3634687ec158f4b72608d1021cab3e8789742fbef0cf2f381cdaf1820d13a41 --header-chain-input-proof ../../header-chain-proof/host/0-10.bin --commit-chain-input-proof ../../commit-chain-proof/host/compressed2.bin --output "output.bin"
//! ```
use ark_serialize::{CanonicalSerialize, CanonicalSerializeHashExt};
use client::btc_chain::BTCClient;
use header_chain::{HeaderChainCircuitInput, HeaderChainPrevProofType};
use zkm_sdk::{
    HashableKey, ProverClient, ZKMProof, ZKMProofWithPublicValues, ZKMStdin, include_elf,
};

use bitcoin::{Network, Txid, hashes::Hash};
use bitcoin_light_client::{CommitChainCircuitInput, CommitChainPrevProofType, build_spv};
use std::str::FromStr;
use zkm_verifier::{GROTH16_VK_BYTES, convert_ark, load_ark_groth16_verifying_key_from_bytes};

/// A program that aggregates the proofs of the simple program.
const WTACHTOWER: &[u8] = include_elf!("guest");

use clap::Parser;
use std::fs;

// The arguments for the cli.
#[derive(Debug, Clone, Parser)]
pub struct Args {
    #[arg(long, default_value = "http://127.0.0.1:3002")]
    esplora_url: String,

    #[clap(long, env)]
    latest_sequencer_commit_txid: String,

    #[clap(long, env, short)]
    header_chain_input_proof: String,

    #[clap(long, env, short)]
    commit_chain_input_proof: String,

    #[clap(long, env, default_value = "compressed.bin")]
    output: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    // Setup the logger.
    zkm_sdk::utils::setup_logger();

    // Initialize the proving client.
    let client = ProverClient::new();

    // Setup the proving and verifying keys.
    let (watchtower_proof_pk, watchtower_proof_vk) = client.setup(WTACHTOWER);

    // --- header chain --- //
    let bytes = std::fs::read(&format!("{}.in", args.header_chain_input_proof)).unwrap();
    let mut header_chain_input: HeaderChainCircuitInput = bincode::deserialize(&bytes).unwrap();

    let proof_bytes =
        fs::read(&args.header_chain_input_proof).expect("Failed to read input proof file");
    let proof: ZKMProofWithPublicValues =
        bincode::deserialize(&proof_bytes).expect("failed to deserialize the proof");
    header_chain_input.pv_hash = proof.public_values.hash().try_into().unwrap();

    let ZKMProof::Compressed(header_compressed_proof) = proof.proof else { panic!() };
    let bytes = std::fs::read(&format!("{}.vk", args.header_chain_input_proof)).unwrap();
    let header_chain_vk: zkm_sdk::ZKMVerifyingKey = bincode::deserialize(&bytes).unwrap();
    //assert_eq!(header_chain_output.vk_hash, header_chain_vk.hash_u32());

    // --- commit chain --- //
    let bytes = std::fs::read(&format!("{}.in", args.commit_chain_input_proof)).unwrap();
    let mut commit_chain_input: CommitChainCircuitInput = bincode::deserialize(&bytes).unwrap();

    // Set the previous proof type based on input_proof argument
    let proof_bytes =
        fs::read(&args.commit_chain_input_proof).expect("Failed to read input proof file");
    let proof: ZKMProofWithPublicValues =
        bincode::deserialize(&proof_bytes).expect("failed to deserialize the proof");

    //let commit_chain_output: CommitChainCircuitOutput = proof.public_values.read();
    commit_chain_input.pv_hash = proof.public_values.hash().try_into().unwrap();

    let ZKMProof::Compressed(commit_compressed_proof) = proof.proof else { panic!() };

    let bytes = std::fs::read(&format!("{}.vk", args.commit_chain_input_proof)).unwrap();
    let commit_chain_vk: zkm_sdk::ZKMVerifyingKey = bincode::deserialize(&bytes).unwrap();
    //assert_eq!(commit_chain_output.vk_hash, commit_chain_vk.hash_u32());

    // --- spv --- //
    let network = Network::Regtest;
    let btc_client = BTCClient::new(network.into(), Some(&args.esplora_url));
    let latest_sequencer_commit_txid = Txid::from_str(&args.latest_sequencer_commit_txid).unwrap();

    let tx = btc_client.fetch_btc_tx(&latest_sequencer_commit_txid).await.unwrap();
    // TODO: replace it by `get_raw_transaction_info`
    let tx_merkle_proof =
        btc_client.get_btc_merkle_proof(&latest_sequencer_commit_txid).await.unwrap();
    let block_pos = tx_merkle_proof.1.block_height;
    println!("block height: {block_pos}");
    let target_block = btc_client.get_btc_block(block_pos).await.unwrap();

    println!("construct spv");
    let spv = build_spv(&tx, block_pos, target_block, &header_chain_input);

    // Generate the proofs.
    let mut proof = tracing::info_span!("generate proof").in_scope(|| {
        let mut stdin = ZKMStdin::new();
        stdin.write(&latest_sequencer_commit_txid.to_byte_array());
        stdin.write(&header_chain_input);
        stdin.write(&commit_chain_input);
        stdin.write(&spv);

        if header_chain_input.prev_proof != HeaderChainPrevProofType::GenesisBlock {
            stdin.write_proof(*header_compressed_proof, header_chain_vk.vk);
        } else {
            println!("skip writing header chain proof");
        }

        if commit_chain_input.prev_proof != CommitChainPrevProofType::GenesisBlock {
            stdin.write_proof(*commit_compressed_proof, commit_chain_vk.vk);
        } else {
            println!("skip writing commit chain proof");
        }

        client.prove(&watchtower_proof_pk, stdin).groth16().run().expect("proving failed")
    });

    let total_work: [u8; 32] = proof.public_values.read();
    println!("total work: {total_work:?}");

    let groth16_vk = &GROTH16_VK_BYTES;
    let ark_proof =
        convert_ark(&proof, watchtower_proof_vk.bytes32().as_ref(), groth16_vk).unwrap();

    let mut writer = std::fs::File::create(format!("{}.proof.bin", args.output)).unwrap();
    ark_proof.proof.serialize_compressed(&mut writer).unwrap();

    let mut writer = std::fs::File::create(format!("{}.vk.bin", args.output)).unwrap();
    ark_proof.groth16_vk.serialize_compressed(&mut writer).unwrap();

    let mut writer = std::fs::File::create(format!("{}.public_inputs.bin", args.output)).unwrap();
    ark_proof.public_inputs.serialize_compressed(&mut writer).unwrap();

    println!("Generate proof successfully, Ark proof: {:?}", ark_proof);
}
