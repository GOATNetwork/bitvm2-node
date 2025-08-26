// use store::ipfs::IPFS;
use bitcoin::Network;
use bitvm2_noded::client::btc_chain::BTCClient;
use bitvm2_noded::{
    env::{ENV_ACTOR, ENV_BITVM_SECRET, IpfsTxName},
    utils::{broadcast_tx, tx_on_chain},
};
use clap::Parser;

/// Send kickoff without call initWithdraw on L2, this action should trigger disprove.
#[derive(Parser, Debug)]
#[command(name = "sequencer-set-publish")]
#[command(about = "Publish sequencer set to Bitcoin", long_about = "")]
struct Args {
    /// graph id
    #[arg(long)]
    graph: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let network = Network::Testnet;
    let btc_client = BTCClient::new(None, network);
}
