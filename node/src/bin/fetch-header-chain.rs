//! Fetch block info for circuit
//! Example:
//! ```
//!     cargo run -r --bin fetch-header-chain -- --start 0 --batch-size 11 --output /tmp/first_11_blocks.bin
//! ```
use anyhow::Chain;
use axum::routing::head;
use base64::write;
use bitcoin::block;
use bitcoin::{
    Network, PublicKey, TapSighashType, Transaction, TxOut, XOnlyPublicKey,
    consensus::encode::deserialize_hex,
};
use bitvm2_noded::client::btc_chain::BTCClient;
use borsh::{BorshDeserialize, BorshSerialize};
use clap::Parser;
use header_chain::{ChainState, CircuitBlockHeader};
use std::io::Write;

/// Send kickoff without call initWithdraw on L2, this action should trigger disprove.
#[derive(Parser, Debug)]
#[command(name = "fake-kickoff")]
#[command(
    about = "Test disprove",
    long_about = "Send kickoff without call initWithdraw on L2, this action should trigger disprove."
)]
struct Args {
    /// graph id
    #[arg(long)]
    start: u32,

    /// operator node bitvm secret key
    #[arg(long)]
    batch_size: u32,

    #[arg(long, default_value = "")]
    network: String,

    #[arg(long)]
    output: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let network = Network::Testnet;
    let btc_client = BTCClient::new(network.into(), None);

    let mut block_headers = vec![];
    let mut writer = std::fs::File::create(&args.output).unwrap();
    for i in args.start..(args.start + args.batch_size) {
        let block = btc_client.fetch_btc_block(i).await.unwrap();
        println!("block_id: {}", block.block_hash().to_string());
        let header: header_chain::CircuitBlockHeader = block.header.into();
        block_headers.push(header.clone());
        header.serialize(&mut writer).unwrap();
    }

    // let output = header_chain::BlockHeaderCircuitOutput {
    //     method_id: [0u32; 8],
    //     chain_state: {
    //         let mut chain_state = ChainState::new();
    //         chain_state.apply_blocks(block_headers.clone());
    //         chain_state
    //     }
    // };

    // let headers = bitcoin_light_client::HEADERS
    //         .chunks(80)
    //         .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
    //         .collect::<Vec<CircuitBlockHeader>>();
    // assert_eq!(block_headers[0], headers[0]);
}
