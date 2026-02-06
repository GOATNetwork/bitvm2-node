//! challenge: broadcast a Challenge transaction for a graph.
//!
//! Purpose:
//! - Read a finalized graph from the local DB, rebuild the full BitVM2 graph,
//!   and broadcast the Challenge transaction on Bitcoin.
//!
//! Env:
//! - BITVM_SECRET: node BTC key (hex or seed:...) for signing and fee inputs
//! - GOAT_PRIVATE_KEY or GOAT_ADDRESS: EVM identity for OP_RETURN
//! - BITCOIN_NETWORK: bitcoin | testnet | testnet4 | signet | regtest
//! - GOAT_CHAIN_URL: GoatNetwork RPC URL (if required by client helpers)
//! - GOAT_GATEWAY_CONTRACT_ADDRESS: Gateway contract address (if required by helpers)
//!
//! Args:
//! - --db-path: local SQLite path (e.g., sqlite:/tmp/bitvm2-node.db)
//! - --instance-id / --graph-id: target graph
//! - --esplora-url: optional Esplora override
//!
//! Example:
//! - cargo run -p bitvm2-noded --bin challenge -- \
//!   db-path sqlite:/tmp/bitvm2-node.db \
//!   --instance-id <uuid> \
//!   --graph-id <uuid>

use anyhow::{Context, Result};
use bitvm2_lib::types::Bitvm2Graph;
use bitvm2_noded::env::get_network;
use clap::Parser;
use client::btc_chain::BTCClient;
use dotenv::dotenv;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use bitvm2_noded::utils::get_graph;
use bitvm2_noded::utils::send_challenge_tx;
use store::create_local_db;

#[derive(Debug, Parser)]
#[command(
    name = "send-challenge",
    version,
    about = "Broadcast a Challenge transaction for a graph (reads graph from local DB)",
    long_about = "Broadcast a Challenge transaction for a graph (reads graph from local DB).\n\nENV required:\n  - BITVM_SECRET: node BTC key (hex) or seed:...\n  - GOAT_PRIVATE_KEY or GOAT_ADDRESS: challenger EVM identity for OP_RETURN\n  - BITCOIN_NETWORK: bitcoin | testnet | signet | regtest (default: testnet)"
)]
struct Args {
    /// Instance UUID of the graph (for sanity; not used for lookup strictly)
    #[arg(long)]
    instance_id: Uuid,

    /// Graph UUID to challenge
    #[arg(long)]
    graph_id: Uuid,

    /// Local Sqlite database file path
    #[arg(long, default_value = "sqlite:/tmp/bitvm2-node.db")]
    db_path: String,

    /// Esplora base URL (optional override for Bitcoin RPC via Esplora)
    #[arg(long, default_value = "https://mempool.space/testnet4/api")]
    esplora_url: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    let _ = tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).try_init();

    let args = Args::parse();
    let network = get_network();
    let btc_client = BTCClient::new(network, Some(&args.esplora_url));

    // Open local DB and load graph
    let local_db = create_local_db(&args.db_path).await;
    let simple =
        get_graph(&local_db, args.instance_id, args.graph_id).await?.with_context(|| {
            format!("graph {} not found in local DB at {}", args.graph_id, args.db_path)
        })?;
    let graph = Bitvm2Graph::from_simplified(&simple)
        .context("failed to rebuild full graph from simplified data in DB")?;

    let txid = send_challenge_tx(&btc_client, &graph).await?;
    println!("Challenge tx broadcasted: {txid}");
    Ok(())
}
