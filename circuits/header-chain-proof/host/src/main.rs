//! Generate header chain proof
//! Example:
//!     export BITCOIN_NETWORK=regtest
//!     Genesis:        RUST_LOG=debug cargo run -r -- --start 0 --batch-size 278 --init-input --output-proof "0-10.bin"
//!     Regular blocks: RUST_LOG=debug cargo run -r -- --start 278 --batch-size 20 --input-proof "0-10.bin" --output-proof "10-20.bin"
use bitcoin::Network;
use borsh::{BorshDeserialize, BorshSerialize};
use client::btc_chain::BTCClient;
use header_chain::{
    BlockHeaderCircuitOutput, CircuitBlockHeader, HeaderChainCircuitInput, HeaderChainPrevProofType,
};
use zkm_sdk::{
    HashableKey, ProverClient, ZKMProof, ZKMProofWithPublicValues, ZKMStdin, include_elf,
};

/// A program that aggregates the proofs of the simple program.
const HEADER_CHAIN: &[u8] = include_elf!("guest");

use clap::Parser;
use std::{
    fs,
    io::{Read, Seek},
};

/// The arguments for the cli.
#[derive(Debug, Clone, Parser)]
pub struct Args {
    #[arg(long, default_value = "http://127.0.0.1:3002")]
    esplora_url: String,

    #[clap(long, env, default_value_t = 4)]
    batch_size: usize,

    #[clap(long, env, default_value_t = 0)]
    start: usize,

    #[clap(long, env, default_value_t = false)]
    init_input: bool,

    #[clap(long, env, default_value = "block_headers.bin")]
    block_headers: String,

    #[clap(long, env, default_value = "input_proof.bin")]
    input_proof: String,

    #[clap(long, env, default_value = "output_proof.bin")]
    output_proof: String,

    #[clap(long, default_value_t = false)]
    force_fetch: bool,
}

async fn fetch_header_chain(args: &Args) -> Vec<CircuitBlockHeader> {
    let network = Network::Regtest;
    let btc_client = BTCClient::new(network.into(), Some(&args.esplora_url));

    let mut writer = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&args.block_headers)
        .unwrap();

    let mut headers: Vec<u8> = Vec::new();
    writer.read_to_end(&mut headers).unwrap();

    let mut block_headers: Vec<_> = headers
        .chunks(80)
        .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
        .collect::<Vec<CircuitBlockHeader>>();

    if args.force_fetch {
        block_headers.truncate(args.start);
    }
    assert!(block_headers.len() == args.start, "Invalid starting block number");

    writer.seek(std::io::SeekFrom::Start((block_headers.len() * 80) as u64)).unwrap();

    for i in args.start..(args.start + args.batch_size) {
        let block = btc_client.get_btc_block(i as u32).await.unwrap();
        println!("block_id {i}: {}", block.block_hash().to_string());
        let header: header_chain::CircuitBlockHeader = block.header.into();
        block_headers.push(header.clone());
        header.serialize(&mut writer).unwrap();
    }
    writer.set_len((block_headers.len() * 80) as u64).unwrap();
    block_headers
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    println!("args: {:?}", args);
    // Setup the logger.
    zkm_sdk::utils::setup_logger();

    let total_block_headers = fetch_header_chain(&args).await;

    // Initialize the proving client.
    let client = ProverClient::new();

    // Setup the proving and verifying keys.
    let (header_chain_proof_pk, header_chain_proof_vk) = client.setup(HEADER_CHAIN);

    let vk_hash = header_chain_proof_vk.hash_u32();
    let mut start = 0;
    // Set the previous proof type based on input_proof argument
    let prev_receipt = if args.init_input {
        None
    } else {
        let proof_bytes = fs::read(&args.input_proof).expect("Failed to read input proof file");
        let proof: ZKMProofWithPublicValues =
            bincode::deserialize(&proof_bytes).expect("failed to deserialize the proof");
        Some(proof)
    };
    let (prev_proof, pv_hash) = match prev_receipt.clone() {
        Some(mut receipt) => {
            let prev_output: BlockHeaderCircuitOutput = receipt.public_values.read();
            start = prev_output.chain_state.block_height as usize + 1;
            let pv_hash: [u8; 32] = receipt.public_values.hash().try_into().unwrap();
            (HeaderChainPrevProofType::PrevProof(prev_output), pv_hash)
        }
        None => (HeaderChainPrevProofType::GenesisBlock, [0u8; 32]),
    };
    println!(
        "header-chain length: {}, start: {}, batch_size: {}",
        total_block_headers.len(),
        start,
        args.batch_size
    );

    let block_headers = (&total_block_headers[args.start..args.start + args.batch_size]).to_vec();
    let input: HeaderChainCircuitInput =
        HeaderChainCircuitInput { vk_hash, prev_proof, pv_hash, block_headers };

    // Generate the proofs.
    let proof = tracing::info_span!("generate proof").in_scope(|| {
        let mut stdin = ZKMStdin::new();
        stdin.write(&input);
        if let Some(proof) = prev_receipt {
            println!("Generate proof from block {}", start);
            let ZKMProof::Compressed(compressed_proof) = proof.proof else { panic!() };
            stdin.write_proof(*compressed_proof, header_chain_proof_vk.vk.clone());
        } else {
            println!("Generate proof from genesis block");
        }
        client.prove(&header_chain_proof_pk, stdin).compressed().run().expect("proving failed")
    });

    fs::write(&args.output_proof, bincode::serialize(&proof).unwrap()).unwrap();
    fs::write(
        &format!("{}.vk", args.output_proof),
        bincode::serialize(&header_chain_proof_vk).unwrap(),
    )
    .unwrap();
    fs::write(&format!("{}.in", args.output_proof), bincode::serialize(&input).unwrap()).unwrap();
    println!("Generate proof successfully, proof: {:?}", proof);
}
