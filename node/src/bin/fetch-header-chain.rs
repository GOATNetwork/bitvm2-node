//! Fetch block info for circuit
//! Example:
//! ```
//!     cargo run -r --bin fetch-header-chain -- --start 0 --batch-size 100 --output ./tests_data/first_100_blocks.bin
//! ```
use bitcoin::Network;
use bitvm2_noded::client::btc_chain::BTCClient;
use borsh::BorshSerialize;
use clap::Parser;

/// Send kickoff without call initWithdraw on L2, this action should trigger disprove.
#[derive(Parser, Debug)]
#[command(name = "fetch-header-chain")]
#[command(about = "Command fetch-header-chain")]
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
