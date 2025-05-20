use bitcoin::{Network, Transaction, consensus::encode::deserialize_hex};
use bitvm2_lib::keys::ChallengerMasterKey;
use bitvm2_noded::client::BTCClient;
use bitvm2_noded::{
    env::{ENV_ACTOR, ENV_BITVM_SECRET, IpfsTxName},
    utils::{complete_and_broadcast_challenge_tx, outpoint_available, tx_on_chain},
};
use clap::Parser;
use goat::contexts::base::generate_keys_from_secret;
use store::ipfs::IPFS;

/// Send challenge when kickoff is valid, this action should trigger take2.
#[derive(Parser, Debug)]
#[command(name = "fake-challenge")]
#[command(
    about = "Test take2",
    long_about = "Send challenge when kickoff is valid, this action should trigger take2."
)]
struct Args {
    /// operator node bitvm secret key
    #[arg(long)]
    secret: String,

    /// ipfs rpc server url
    #[arg(long, default_value = "http://44.229.236.82:5001")]
    ipfs_url: String,

    /// ipfs cid for bitvm2 txns's dir
    #[arg(long)]
    txns_cid: String,
}

async fn get_tx_from_ipfs(
    ipfs: &IPFS,
    base_url: &str,
    tx_name: IpfsTxName,
) -> Result<Transaction, Box<dyn std::error::Error>> {
    let tx_url = [base_url, "/", tx_name.as_str()].concat();
    let tx_hex = ipfs.cat(&tx_url).await?;
    Ok(deserialize_hex(&tx_hex)?)
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let ipfs = IPFS::new(&args.ipfs_url);
    let btc_client = BTCClient::new(None, Network::Testnet);
    unsafe {
        std::env::set_var(ENV_ACTOR, "Challenger");
        std::env::set_var(ENV_BITVM_SECRET, &args.secret);
    }
    let network = Network::Testnet;
    let (keypair, _) = generate_keys_from_secret(network, &args.secret);
    let (base_url, master_key) = (args.txns_cid, ChallengerMasterKey::new(keypair));
    let kickoff_txid =
        get_tx_from_ipfs(&ipfs, &base_url, IpfsTxName::Kickoff).await.unwrap().compute_txid();
    if !tx_on_chain(&btc_client, &kickoff_txid).await.unwrap() {
        println!("Error: kickoff tx not broadcasted!");
        return;
    }
    if !outpoint_available(&btc_client, &kickoff_txid, 1).await.unwrap() {
        println!("Error: challenge/take1 already sent!");
        return;
    }
    let challenge_tx = get_tx_from_ipfs(&ipfs, &base_url, IpfsTxName::Challenge).await.unwrap();
    let challenge_txid =
        complete_and_broadcast_challenge_tx(&btc_client, master_key.master_keypair(), challenge_tx)
            .await
            .unwrap();
    println!("challenge sent {challenge_txid}");
}
