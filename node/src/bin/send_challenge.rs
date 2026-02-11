//! challenge: broadcast a Challenge transaction for a graph via the node API.
//!
//! Purpose:
//! - Call the node's send-challenge API endpoint to broadcast the Challenge
//!   transaction on Bitcoin. No direct DB access is needed.
//!
//! Env:
//! - (Environment variables like BITVM_SECRET, GOAT_PRIVATE_KEY, etc. are
//!   required on the **node** side, not on this client.)
//!
//! Args:
//! - --api-url: node API base URL (default: http://localhost:8080)
//! - --graph-id: target graph UUID
//!
//! Example:
//! - cargo run -p bitvm2-noded --bin challenge -- \
//!   --api-url http://localhost:8080 \
//!   --graph-id <uuid>

use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;

#[derive(Debug, Parser)]
#[command(
    name = "send-challenge",
    version,
    about = "Broadcast a Challenge transaction for a graph (via node API)",
    long_about = "Broadcast a Challenge transaction for a graph via the node's REST API.\n\nThe node must be running and reachable at the given --api-url."
)]
struct Args {
    /// Graph UUID to challenge
    #[arg(long)]
    graph_id: uuid::Uuid,

    /// Node API base URL
    #[arg(long, default_value = "http://localhost:8080")]
    api_url: String,
}

#[derive(Debug, Deserialize)]
struct SendChallengeResponse {
    challenge_txid: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let url = format!(
        "{}/v1/graphs/{}/send-challenge",
        args.api_url.trim_end_matches('/'),
        args.graph_id
    );

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .send()
        .await
        .with_context(|| format!("failed to reach node API at {url}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("API returned {status}: {body}");
    }

    let body: SendChallengeResponse = resp.json().await.context("failed to parse API response")?;
    println!("Challenge tx broadcasted: {}", body.challenge_txid);
    Ok(())
}
