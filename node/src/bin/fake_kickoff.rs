use bitcoin::{
    Network, PublicKey, TapSighashType, Transaction, TxOut, XOnlyPublicKey,
    consensus::encode::deserialize_hex,
};
use bitvm::signatures::signing_winternitz::{WinternitzSigningInputs, generate_winternitz_witness};
use bitvm2_lib::keys::OperatorMasterKey;
use bitvm2_noded::client::btc_chain::BTCClient;
use bitvm2_noded::{
    env::{ENV_ACTOR, ENV_BITVM_SECRET, IpfsTxName},
    utils::{broadcast_tx, tx_on_chain},
};
use clap::Parser;
use goat::{
    commitments::CommitmentMessageId,
    connectors::{base::TaprootConnector, connector_6::Connector6},
    contexts::base::generate_keys_from_secret,
    transactions::signing::{
        generate_taproot_leaf_schnorr_signature, populate_taproot_input_witness,
    },
};
use std::str::FromStr;
use store::ipfs::IPFS;
use uuid::Uuid;

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
    graph: String,

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
    let network = Network::Testnet;
    let btc_client = BTCClient::new(None, network);
    unsafe {
        std::env::set_var(ENV_ACTOR, "Operator");
        std::env::set_var(ENV_BITVM_SECRET, &args.secret);
    }
    let (keypair, _) = generate_keys_from_secret(network, &args.secret);
    let (base_url, graph_id, master_key) =
        (args.txns_cid, Uuid::from_str(&args.graph).unwrap(), OperatorMasterKey::new(keypair));
    let mut kickoff = get_tx_from_ipfs(&ipfs, &base_url, IpfsTxName::Kickoff).await.unwrap();
    if tx_on_chain(&btc_client, &kickoff.compute_txid()).await.unwrap() {
        println!("Error: kickoff already sent!");
        return;
    };
    let (operator_wots_seckeys, operator_wots_pubkeys) =
        master_key.wots_keypair_for_graph(graph_id);
    let operator_pubkey: PublicKey = master_key.keypair_for_graph(graph_id).public_key().into();
    let kickoff_wots_commitment_keys =
        CommitmentMessageId::pubkey_map_for_kickoff(&operator_wots_pubkeys.0);
    let connector_6 = Connector6::new(
        network,
        &XOnlyPublicKey::from(operator_pubkey),
        &kickoff_wots_commitment_keys,
    );
    let input_index = 0;
    let script = connector_6.generate_taproot_leaf_script(0);
    let taproot_spend_info = connector_6.generate_taproot_spend_info();
    let input_value = btc_client
        .get_tx(&kickoff.input[0].previous_output.txid)
        .await
        .unwrap()
        .unwrap()
        .output[0]
        .value;
    let prev_outs = vec![TxOut {
        value: input_value,
        script_pubkey: connector_6.generate_taproot_address().script_pubkey(),
    }];
    let evm_txid_inputs = WinternitzSigningInputs {
        message: [0; 32].as_ref(),
        signing_key: &operator_wots_seckeys.0[0],
    };
    let mut unlock_data: Vec<Vec<u8>> = Vec::new();
    // get schnorr signature
    let schnorr_signature = generate_taproot_leaf_schnorr_signature(
        &mut kickoff,
        &prev_outs,
        input_index,
        TapSighashType::All,
        &script,
        &master_key.keypair_for_graph(graph_id),
    );
    unlock_data.push(schnorr_signature.to_vec());
    // get winternitz signature for evm withdraw txid
    unlock_data.extend(generate_winternitz_witness(&evm_txid_inputs).to_vec());
    populate_taproot_input_witness(
        &mut kickoff,
        input_index,
        &taproot_spend_info,
        &script,
        unlock_data,
    );
    broadcast_tx(&btc_client, &kickoff).await.unwrap();
    println!("kickoff sent {}", kickoff.compute_txid());
}
