//! send-rbf: Replace-By-Fee helper (rebuild and rebroadcast).
//!
//! Purpose:
//! - Rebuild a stuck transaction using the same inputs (`--vin txid:vout`) and
//!   bump the absolute fee. Inputs must belong to the node's P2WSH address
//!   derived from `BITVM_SECRET`. Outputs are consolidated to a single address.
//!
//! Env:
//! - BITVM_SECRET: node BTC private key
//! - BITCOIN_NETWORK: bitcoin | testnet | testnet4 | signet | regtest (optional)
//!
//! Example:
//! - cargo run -p bitvm2-noded --bin send-rbf -- \
//!   --vin <txid>:0 \
//!   --vin <txid>:1 \
//!   --fee-amount 10000 \
//!   --to-address <addr>

use std::fmt;
use std::str::FromStr;

use anyhow::{Context, Result, anyhow, bail};
use bitcoin::absolute::LockTime;
use bitcoin::{
    Address, Amount, EcdsaSighashType, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Txid, Witness,
};
use clap::Parser;
use client::btc_chain::BTCClient;
use dotenv::dotenv;
use goat::transactions::base::Input;
use tracing_subscriber::EnvFilter;

use bitvm2_noded::env::{DUST_AMOUNT, get_bitvm_key, get_network};
use bitvm2_noded::utils::{broadcast_tx, node_p2wsh_address, node_sign};

const DEFAULT_RBF_SEQUENCE: u32 = 0xFFFF_FFFD;

#[derive(Debug, Parser)]
#[command(
    name = "send-rbf",
    about = "Build and broadcast a replacement transaction",
    long_about = "Build and broadcast a replacement transaction using the node's BTC key."
)]
struct Args {
    /// Inputs to reuse, formatted as TXID:VOUT (can be repeated)
    #[arg(long = "vin", required = true)]
    vins: Vec<VinArg>,

    /// Optional destination address (defaults to node's P2WSH address)
    #[arg(long = "to-address")]
    to_address: Option<String>,

    /// Target fee amount in sats
    #[arg(long = "fee-amount")]
    fee_amount: u64,

    /// Optional esplora base URL override
    #[arg(long, default_value = "https://mempool.space/testnet4/api")]
    esplora_url: String,
}

#[derive(Clone, Debug)]
struct VinArg {
    txid: Txid,
    vout: u32,
}

impl FromStr for VinArg {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let (txid_str, vout_str) = s
            .split_once(':')
            .ok_or_else(|| "vin must be formatted as <txid>:<vout>".to_string())?;
        let txid =
            Txid::from_str(txid_str).map_err(|e| format!("invalid txid '{txid_str}': {e}"))?;
        let vout =
            vout_str.parse::<u32>().map_err(|e| format!("invalid vout '{vout_str}': {e}"))?;
        Ok(Self { txid, vout })
    }
}

impl fmt::Display for VinArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.txid, self.vout)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    let _ = tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).try_init();

    let args = Args::parse();
    let network = get_network();
    let btc_client = BTCClient::new(network, Some(&args.esplora_url));

    let node_keypair = get_bitvm_key()?;
    let node_address = node_p2wsh_address(network, &node_keypair.public_key().into());
    let destination_address = match &args.to_address {
        Some(addr) => Address::from_str(addr)
            .context("failed to parse destination address")?
            .require_network(network)
            .context("destination address network mismatch")?,
        None => node_address.clone(),
    };

    let expected_script = node_address.script_pubkey();
    let inputs = resolve_inputs(&btc_client, &args.vins, &expected_script, network).await?;

    let mut tx = build_skeleton_tx(&inputs, &destination_address)?;

    let fee_sat = args.fee_amount;
    let total_input = inputs.iter().map(|i| i.amount).sum::<Amount>();
    let total_input_sat = total_input.to_sat();
    if fee_sat >= total_input_sat {
        bail!(
            "fee {fee_sat} sats exceeds or equals total input {total_input_sat} sats; add more inputs"
        );
    }
    let output_value_sat = total_input_sat - fee_sat;
    if output_value_sat < DUST_AMOUNT {
        bail!(
            "remaining output {output_value_sat} sats would be dust (< {DUST_AMOUNT}); select more inputs"
        );
    }
    tx.output[0].value = Amount::from_sat(output_value_sat);

    for (idx, input) in inputs.iter().enumerate() {
        node_sign(&mut tx, idx, input.amount, EcdsaSighashType::All, &node_keypair)?;
    }

    let txid = tx.compute_txid();
    broadcast_tx(&btc_client, &tx).await?;
    println!(
        "Broadcasted replacement tx {txid}. Inputs: {} | fee={} sats",
        args.vins.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(", "),
        fee_sat
    );
    Ok(())
}

async fn resolve_inputs(
    btc_client: &BTCClient,
    vins: &[VinArg],
    expected_script: &ScriptBuf,
    network: Network,
) -> Result<Vec<Input>> {
    let mut resolved = Vec::with_capacity(vins.len());
    for vin in vins {
        let tx = btc_client
            .get_tx(&vin.txid)
            .await?
            .with_context(|| format!("transaction {} not found on {network:?}", vin.txid))?;
        let txout = tx
            .output
            .get(vin.vout as usize)
            .ok_or_else(|| anyhow!("tx {} has no vout {}", vin.txid, vin.vout))?;
        if &txout.script_pubkey != expected_script {
            bail!(
                "input {vin} does not belong to the node P2WSH address; unsupported script {:#?}",
                txout.script_pubkey
            );
        }
        resolved.push(Input {
            outpoint: OutPoint { txid: vin.txid, vout: vin.vout },
            amount: txout.value,
        });
    }
    Ok(resolved)
}

fn build_skeleton_tx(inputs: &[Input], destination: &Address) -> Result<Transaction> {
    let mut txins = Vec::with_capacity(inputs.len());
    for input in inputs {
        txins.push(TxIn {
            previous_output: input.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_consensus(DEFAULT_RBF_SEQUENCE),
            witness: Witness::default(),
        });
    }

    let txouts = vec![TxOut { value: Amount::ZERO, script_pubkey: destination.script_pubkey() }];

    Ok(Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: LockTime::ZERO,
        input: txins,
        output: txouts,
    })
}
