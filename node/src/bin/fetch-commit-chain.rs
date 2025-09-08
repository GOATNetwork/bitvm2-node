//! Fetch block info for circuit
//! Example:
//! ```
//!    cargo run -r --bin fetch-commit-chain -- --output ./tests_data/commits.bin --input ./tests_data/commit_info.json
//! ```
use std::str::FromStr;

use bitcoin::{Network, Txid, secp256k1::PublicKey};
use bitcoin_light_client::*;
use bitvm2_noded::client::btc_chain::BTCClient;
use clap::Parser;

/// Send kickoff without call initWithdraw on L2, this action should trigger disprove.
#[derive(Parser, Debug)]
#[command(name = "fetch-commit-chain")]
#[command(about = "Command fetch-commit-chain")]
struct Args {
    #[arg(long, default_value = "regtest")]
    network: String,

    #[arg(long, default_value = "http://127.0.0.1:3002")]
    esplora_url: String,

    #[arg(long, default_value = "./tests_data/commit_info.json")]
    input: String,

    #[arg(long)]
    output: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let network = Network::Regtest;
    let btc_client = BTCClient::new(network.into(), Some(&args.esplora_url));

    let mut commits: Vec<CircuitCommit> = vec![];

    let rdr = std::fs::File::open(&args.input).unwrap();
    let commit_info: Vec<CommitInfo> = serde_json::from_reader(rdr).unwrap();
    for ci in &commit_info {
        let tx = btc_client.get_tx(&Txid::from_str(&ci.txid).unwrap()).await.unwrap().unwrap();

        let op_return_data = bitcoin_light_client::extract_op_return_data(&tx);
        let mut sequencer_set_hash: [u8; 32] = [0u8; 32];
        sequencer_set_hash.copy_from_slice(&op_return_data[0]);

        let publisher_public_keys = ci
            .publisher_public_keys
            .iter()
            .map(|compressed_pk| PublicKey::from_str(compressed_pk).unwrap())
            .collect();
        let commit = CircuitCommit {
            commit_txn: tx,
            sequencer_set_hash,
            publisher_public_keys,
            threshold: ci.threshold,
        };
        commits.push(commit.clone());
    }
    std::fs::write(&args.output, serde_json::to_vec(&commits).unwrap()).unwrap();
}
