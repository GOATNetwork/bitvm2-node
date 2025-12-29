//! Create and sign a sequencer set publish transaction.
//!   * Publish sequencer set commitment to Bitcoin
//!
//! Launch the local bitcoin regtest node with:
//! ```sh
//! cd ../scripts
//! docker-compose -f docker-compose.yml up -d
//! ```
use bitcoin::CompressedPublicKey;
use bitcoin::{
    Address, Amount, OutPoint, PrivateKey, PublicKey, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Txid, Witness, absolute::LockTime, hashes::Hash, key::Keypair, transaction::Version,
};
use bitvm2_noded::env::{
    ENV_GOAT_SEQUENCER_SET_MULTI_SIG_VERIFIER_ADDRESS,
    ENV_GOAT_SEQUENCER_SET_PUBLISHER_CONTRACT_ADDRESS, get_goat_address_from_env, get_network,
};
use bitvm2_noded::utils::broadcast_tx;
use bitvm2_noded::utils::wait_tx_confirmation;
use bitvm2_noded::utils::{node_p2wsh_address, node_sign};
use clap::{Parser, Subcommand};
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
use client::goat_chain::GoatInitConfig;
use client::goat_chain::SequencerSetUpdateWitness;
use dotenv::dotenv;
use tracing_subscriber::EnvFilter;

use cbft_rpc::{fetch_cbft_validator_info, fetch_validators};

use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin_light_client_circuit::{
    /*create_dummy_publisher_keys,*/ create_fee_tx, create_sequencer_update_partial_tx,
    decode_eth_address, estimate_tx_vbytes,
};
use commit_chain::{CommitInfo, create_sequencer_update_script, finalize, sign_raw};
use tendermint::validator::Info;

use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::str::FromStr;

pub fn decode_btc_public_keys(pubkey: &str) -> Result<secp256k1::PublicKey, String> {
    secp256k1::PublicKey::from_str(pubkey.trim())
        .map_err(|e| format!("Invalid bitcoin public key: {pubkey}, err: {e:?}"))
}

#[derive(Parser, Debug)]
#[command(name = "sequencer-set-publisher", version, about)]
struct Args {
    #[command(subcommand)]
    command: Commands,

    /// Local bitcoin testnet
    #[arg(long, env, default_value = "http://127.0.0.1:3002")]
    esplora_url: String,

    #[arg(long, env, default_value = "https://rpc.testnet3.goat.network")]
    goat_rpc_url: String,

    #[clap(long, env, default_value = "https://cosmos.testnet3.goat.network/")]
    cosmos_rpc_url: String,

    #[arg(long, env, default_value_t = 2, env = "FEE_RATE")]
    fee_rate: u64, // sat/vbyte

    #[arg(long, env, env = "GOAT_EVM_PRVKEY")]
    goat_evm_prvkey: Option<String>,

    #[arg(long, env = "OUTPUT_FILE", default_value = "output.data")]
    output_file: String,
}

#[derive(Default, Serialize, Deserialize)]
struct OutputData {
    funding_input: Option<OutPoint>,
    fee_tx: Option<OutPoint>,
    update_connector: Option<OutPoint>,
}
impl OutputData {
    fn merge(&mut self, other: OutputData) {
        if other.fee_tx.is_some() {
            self.fee_tx = other.fee_tx;
        }
        if other.funding_input.is_some() {
            self.funding_input = other.funding_input;
        }
        if other.update_connector.is_some() {
            self.update_connector = other.update_connector;
        }
    }
}

async fn save_commit_info(
    output_file: &str,
    btc_public_keys: &[secp256k1::PublicKey],
    sequencers: Vec<Info>,
    init_genesis: bool,
    commit_info_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let file = std::fs::File::open(output_file)?;
    let output: OutputData = serde_json::from_reader(file).unwrap();

    let txid = &output.update_connector.unwrap().txid.to_string();
    let genesis_txid = if !init_genesis {
        std::fs::read_to_string(format!("{output_file}.genesis")).unwrap()
    } else {
        std::fs::write(format!("{output_file}.genesis"), txid).unwrap();
        txid.clone()
    };
    let commit_info = CommitInfo {
        txid: txid.clone(),
        threshold: (btc_public_keys.len() * 2).div_ceil(3) as u16,
        publisher_public_keys: btc_public_keys.iter().map(|pubkey| pubkey.to_string()).collect(),
        genesis_txid,
        sequencers: sequencers.iter().cloned().map(|v| v.into()).collect(),
    };

    let commit_info = serde_json::to_string(&commit_info).unwrap();
    Ok(std::fs::write(commit_info_file, commit_info)?)
}

fn save_output(input: OutputData, output_file: &str) {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(output_file)
        .unwrap();

    let mut buf = vec![];
    let old_output = file.read_to_end(&mut buf).unwrap();
    drop(file);
    let output = {
        if old_output > 0 {
            let mut output: OutputData = serde_json::from_slice(&buf).unwrap();
            output.merge(input);
            output
        } else {
            input
        }
    };
    std::fs::write(output_file, serde_json::to_string_pretty(&output).unwrap()).unwrap();
}

#[derive(Subcommand, Debug)]
enum Commands {
    Fund {
        #[arg(long, env = "FUND_BTC_KEY_WIF")]
        fund_btc_key_wif: Option<String>,
        #[arg(long, env = "BTC_PUBLIC_KEYS", value_delimiter = ',', value_parser = decode_btc_public_keys)]
        btc_public_keys: Vec<secp256k1::PublicKey>,
    },
    SignSeq {
        #[arg(long, env = "OWNER_BTC_KEY_WIF")]
        owner_btc_key_wif: Option<String>,
        #[arg(long)]
        goat_block_number: u64,
        #[arg(long, env = "PUBLISHER_BTC_PUBKEYS", value_delimiter = ',', value_parser = decode_btc_public_keys)]
        publisher_btc_pubkeys: Vec<secp256k1::PublicKey>,
        #[arg(long, env = "NEXT_PUBLISHER_BTC_PUBKEYS", value_delimiter = ',', value_parser = decode_btc_public_keys)]
        next_publisher_btc_pubkeys: Vec<secp256k1::PublicKey>,
    },
    PushSeq {
        #[arg(long, env = "OWNER_BTC_KEY_WIF")]
        owner_btc_key_wif: Option<String>,
        #[arg(long)]
        goat_block_number: u64,
        #[arg(long, env = "PUBLISHER_BTC_PUBKEYS", value_delimiter = ',', value_parser = decode_btc_public_keys)]
        publisher_btc_pubkeys: Vec<secp256k1::PublicKey>,
        #[arg(long, env = "NEXT_PUBLISHER_BTC_PUBKEYS", value_delimiter = ',', value_parser = decode_btc_public_keys)]
        next_publisher_btc_pubkeys: Vec<secp256k1::PublicKey>,
        #[arg(long, default_value_t = false)]
        init_genesis: bool,
        #[arg(long)]
        commit_info: String,
    },
    Payfee {
        #[arg(long, env = "FUND_BTC_KEY_WIF")]
        fund_btc_key_wif: Option<String>,
        #[arg(long, env = "OWNER_BTC_KEY_WIF")]
        owner_btc_key_wif: Option<String>,
        #[arg(long)]
        funding_input_txid: Option<String>,
        #[arg(long)]
        funding_input_vout: Option<u32>,
        #[arg(long, env = "GOAT_EVM_ADDRESS", value_parser = decode_eth_address)]
        goat_evm_address: [u8; 20],
        #[arg(long)]
        total: u32,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    //let dummy_publisher_keys: Vec<_> = create_dummy_publisher_keys(5);
    //println!("dummy keys: {:?}", dummy_publisher_keys);
    dotenv().ok();
    let _ = tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).try_init();
    let args = Args::parse();
    println!("args: {args:?}");
    let (btc_client, goat_client) = init_clients(&args).await?;

    let output_file = &args.output_file;
    let cached_data = std::fs::read(output_file);
    let cached_output: OutputData = match cached_data {
        Ok(data) => serde_json::from_slice(&data).unwrap_or_else(|e| {
            eprintln!("Failed to parse output file (possibly schema change), using default: {e:?}");
            OutputData::default()
        }),
        _ => OutputData::default(),
    };

    match args.command {
        Commands::Fund { fund_btc_key_wif, btc_public_keys } => {
            action_fund_publishers(
                &btc_client,
                fund_btc_key_wif,
                btc_public_keys,
                &args.output_file,
            )
            .await
        }
        Commands::Payfee {
            fund_btc_key_wif,
            owner_btc_key_wif,
            funding_input_txid,
            funding_input_vout,
            goat_evm_address,
            total,
        } => {
            let funding_input = match (funding_input_txid, funding_input_vout) {
                (Some(txid), Some(vout)) => {
                    Some(OutPoint::new(Txid::from_str(&txid).unwrap(), vout))
                }
                _ => None,
            };
            action_push_fee_tx(
                &btc_client,
                fund_btc_key_wif,
                owner_btc_key_wif,
                total,
                args.fee_rate,
                funding_input,
                goat_evm_address,
                output_file,
            )
            .await
        }
        Commands::SignSeq {
            owner_btc_key_wif,
            goat_block_number,
            publisher_btc_pubkeys,
            next_publisher_btc_pubkeys,
        } => {
            let (sequencer_set_hash, _) =
                fetch_cbft_validator_info(&args.cosmos_rpc_url, goat_block_number).await?;

            let fee_tx = cached_output.fee_tx.unwrap();
            let update_connector = cached_output.update_connector;

            action_sign_sequencer_set_update(
                &btc_client,
                &goat_client,
                owner_btc_key_wif,
                publisher_btc_pubkeys,
                next_publisher_btc_pubkeys,
                args.fee_rate,
                fee_tx,
                update_connector,
                sequencer_set_hash,
                goat_block_number,
            )
            .await
        }
        Commands::PushSeq {
            owner_btc_key_wif,
            goat_block_number,
            publisher_btc_pubkeys,
            next_publisher_btc_pubkeys,
            init_genesis,
            commit_info,
        } => {
            let (sequencer_set_hash, cosmos_block_number) =
                fetch_cbft_validator_info(&args.cosmos_rpc_url, goat_block_number).await?;
            let sequencers = fetch_validators(&args.cosmos_rpc_url, cosmos_block_number).await?;
            let fee_tx = cached_output.fee_tx.unwrap();
            let update_connector = cached_output.update_connector;

            action_push_sequencer_set_update(
                &btc_client,
                &goat_client,
                owner_btc_key_wif,
                publisher_btc_pubkeys.clone(),
                next_publisher_btc_pubkeys,
                args.fee_rate,
                fee_tx,
                update_connector,
                goat_block_number,
                sequencer_set_hash,
                output_file,
            )
            .await?;
            match save_commit_info(
                &args.output_file,
                &publisher_btc_pubkeys,
                sequencers,
                init_genesis,
                &commit_info,
            )
            .await
            {
                Err(e) => {
                    println!("Failed to save commit info: {e}, commit_info: {commit_info}");
                    Ok(())
                }
                _ => Ok(()),
            }
        }
    }
}

async fn push_fee_tx(
    fee_tx: &mut Transaction,
    input_value: Amount,
    private_key: &PrivateKey,
    btc_client: &BTCClient,
) -> Result<Txid, Box<dyn std::error::Error>> {
    let secp = secp256k1::Secp256k1::new();
    // sign the fee tx
    node_sign(
        fee_tx,
        0,
        input_value,
        EcdsaSighashType::All,
        &Keypair::from_secret_key(&secp, &private_key.inner),
    )?;
    println!("Fee txid: {:#?}", fee_tx.compute_txid());
    broadcast_tx(btc_client, fee_tx).await?;
    wait_tx_confirmation(btc_client, &fee_tx.compute_txid(), 3, 1000).await?;
    println!("Fee tx confirmed");
    Ok(fee_tx.compute_txid())
}

#[allow(clippy::too_many_arguments)]
async fn push_sequencer_set_publish_tx(
    owner_p2wpkh: &Address,
    owner_private_key: &PrivateKey,
    update_connector_value: Option<Amount>,
    replenish_fee_connector_value: Option<Amount>,
    btc_client: &BTCClient,
    sequencer_set_publish_tx: &mut Transaction,
    redeem_script: &ScriptBuf,
    publisher_sigs: Vec<Vec<u8>>,
) -> Result<Txid, Box<dyn std::error::Error>> {
    let secp = secp256k1::Secp256k1::new();
    let sig_hash_type = EcdsaSighashType::AllPlusAnyoneCanPay;
    let mut input_index = 0;
    if update_connector_value.is_some() {
        println!("Standard spending flow for sequencer set publish tx");
        input_index += 1;
        finalize(sequencer_set_publish_tx, publisher_sigs, redeem_script)?;
    }

    // Sign the replenish fee input (P2WPKH)
    let signer_pkh = owner_p2wpkh
        .witness_program()
        .expect("addr")
        .program() // 20 bytes = hash160(pubkey)
        .to_owned();
    let script_code =
        ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::from_slice(signer_pkh.as_bytes())?);

    let mut cache = SighashCache::new(&mut *sequencer_set_publish_tx);
    let sighash = cache
        .p2wsh_signature_hash(
            input_index,
            &script_code,
            replenish_fee_connector_value.unwrap(),
            sig_hash_type,
        )
        .unwrap();
    let msg = Message::from_digest_slice(&sighash[..]).unwrap();

    let sig = secp.sign_ecdsa(&msg, &owner_private_key.inner);
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(sig_hash_type as u8);

    println!("Publisher {}'s signature: {}", owner_p2wpkh, hex::encode(&sig_bytes));
    sequencer_set_publish_tx.input[input_index].witness =
        Witness::from(vec![sig_bytes, owner_private_key.public_key(&secp).to_bytes()]);

    println!("Sequencer set publish txid: {:#?}", sequencer_set_publish_tx.compute_txid());
    println!("Sequencer set publish: {sequencer_set_publish_tx:#?}");
    broadcast_tx(btc_client, sequencer_set_publish_tx).await?;
    wait_tx_confirmation(btc_client, &sequencer_set_publish_tx.compute_txid(), 3, 1000).await?;
    println!("Sequencer set publish tx confirmed");
    Ok(sequencer_set_publish_tx.compute_txid())
}

async fn init_clients(args: &Args) -> Result<(BTCClient, GOATClient), anyhow::Error> {
    let network = get_network();
    let btc_client = BTCClient::new(network, Some(&args.esplora_url));
    let config = GoatInitConfig::new("https://rpc.testnet3.goat.network".parse::<Url>()?)
        .await?
        .with_sequencer_set_publisher_address(get_goat_address_from_env(
            ENV_GOAT_SEQUENCER_SET_PUBLISHER_CONTRACT_ADDRESS,
        ))
        .with_multi_sig_verifier_address(get_goat_address_from_env(
            ENV_GOAT_SEQUENCER_SET_MULTI_SIG_VERIFIER_ADDRESS,
        ))
        .with_private_key(args.goat_evm_prvkey.clone());
    let goat_client = GOATClient::new(config, client::goat_chain::GoatNetwork::Test);
    Ok((btc_client, goat_client))
}

#[tracing::instrument(skip(goat_client))]
async fn update_sequencer_set_on_goat(
    goat_client: &GOATClient,
    goat_block_number: u64,
    sig_hash: [u8; 32],
    btc_pub_key: [u8; 33],
    btc_sig: [u8; 64],
) -> Result<(), Box<dyn std::error::Error>> {
    let sequencer_set = SequencerSetUpdateWitness {
        sig_hash,
        btc_pub_key: btc_pub_key.to_vec(),
        btc_sig: btc_sig.to_vec(),
    };
    let txid = goat_client.ss_update_sequencer_set(goat_block_number, sequencer_set).await?;
    println!("Txid: {txid}");
    Ok(())
}

/// Submit sequencer set commitment
#[allow(clippy::too_many_arguments)]
async fn action_push_sequencer_set_update(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    owner_btc_key_wif: Option<String>,
    btc_public_keys: Vec<secp256k1::PublicKey>,
    next_btc_public_keys: Vec<secp256k1::PublicKey>,
    fee_rate: u64,
    fee_tx_outpoint: OutPoint,
    update_connector: Option<OutPoint>,
    goat_block_number: u64,
    sequencer_set_hash: [u8; 32],
    output_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let witnesses = goat_client.ss_get_sequencer_set_update_witness(goat_block_number).await?;
    let mut sigs: Vec<_> = witnesses
        .iter()
        .filter(|x| {
            btc_public_keys.contains(&secp256k1::PublicKey::from_slice(&x.btc_pub_key).unwrap())
        })
        .map(|x| {
            let sig = secp256k1::ecdsa::Signature::from_compact(&x.btc_sig).expect("Invalid sig");
            let mut sig_bytes = sig.serialize_der().to_vec();
            sig_bytes.push(EcdsaSighashType::AllPlusAnyoneCanPay as u8);
            sig_bytes
        })
        .collect();
    let total = btc_public_keys.len();
    let threshold = (2 * total).div_ceil(3);

    sigs.resize(threshold, vec![]);

    let total = next_btc_public_keys.len();
    let next_threshold = (2 * total).div_ceil(3);

    let relayer_fee = Amount::from_sat(500);

    let redeem_script = create_sequencer_update_script(&btc_public_keys, threshold);
    let next_redeem_script = create_sequencer_update_script(&next_btc_public_keys, next_threshold);
    let next_update_connector_address = Address::p2wsh(&next_redeem_script, btc_client.network());

    let replenish_fee = Amount::from_sat(fee_rate)
        * estimate_tx_vbytes(&[(threshold as u32, total as u32)], &[("p2wsh", 3)], 73) as u64
        + relayer_fee;

    println!("replenish fee: {replenish_fee:?}");
    println!("sigs: {sigs:?}");
    // read public key and threshold from smart contract, which is consistency with btc_public_keys
    let fee_tx = btc_client.get_tx(&fee_tx_outpoint.txid).await?.expect("fee tx doesn't exist");

    // update the sequencer set publish tx with multisig signatures
    let (update_connector, update_connector_value, replenish_fee_connector_value) =
        match &update_connector {
            Some(update_connector) => {
                let tmp_tx = btc_client.get_tx(&update_connector.txid).await?.unwrap();
                (
                    Some(*update_connector),
                    Some(tmp_tx.output[update_connector.vout as usize].value),
                    Some(fee_tx.output[fee_tx_outpoint.vout as usize].value),
                )
            }
            None => (None, None, Some(replenish_fee)),
        };

    // Skip construction of the genesis tx
    let mut sequencer_set_publish_tx = create_sequencer_update_partial_tx(
        sequencer_set_hash,
        &update_connector,
        &Some(fee_tx_outpoint),
        next_update_connector_address.clone(),
        relayer_fee,
    )?;

    let secp = secp256k1::Secp256k1::new();
    let owner_private_key = PrivateKey::from_wif(owner_btc_key_wif.as_ref().unwrap())?;
    let owner_p2wpkh = Address::p2wpkh(
        &CompressedPublicKey::from_private_key(&secp, &owner_private_key)?,
        btc_client.network(),
    );

    let txid = push_sequencer_set_publish_tx(
        &owner_p2wpkh,
        &owner_private_key,
        update_connector_value,
        replenish_fee_connector_value,
        btc_client,
        &mut sequencer_set_publish_tx,
        &redeem_script,
        sigs,
    )
    .await?;

    let output =
        OutputData { update_connector: Some(OutPoint::new(txid, 0)), ..Default::default() };
    save_output(output, output_file);

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn action_sign_sequencer_set_update(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    owner_btc_key_wif: Option<String>,
    btc_public_keys: Vec<secp256k1::PublicKey>,
    next_btc_public_keys: Vec<secp256k1::PublicKey>,
    fee_rate: u64,
    fee_tx_outpoint: OutPoint,
    update_connector: Option<OutPoint>,
    sequencer_set_hash: [u8; 32],
    goat_block_number: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let total = btc_public_keys.len();
    let threshold = (2 * total).div_ceil(3);
    let next_total = next_btc_public_keys.len();
    let next_threshold = (2 * next_total).div_ceil(3);

    let relayer_fee = Amount::from_sat(500);

    let redeem_script = create_sequencer_update_script(&btc_public_keys, threshold);
    let next_redeem_script = create_sequencer_update_script(&next_btc_public_keys, next_threshold);
    let next_update_connector_address = Address::p2wsh(&next_redeem_script, btc_client.network());

    let replenish_fee = Amount::from_sat(fee_rate)
        * estimate_tx_vbytes(&[(threshold as u32, total as u32)], &[("p2wsh", 3)], 73) as u64
        + relayer_fee;

    let fee_tx = btc_client.get_tx(&fee_tx_outpoint.txid).await?.expect("fee tx doesn't exist");
    let (update_connector, _update_connector_value, _replenish_fee_connector_value) =
        match &update_connector {
            Some(update_connector) => {
                let tmp_tx = btc_client.get_tx(&update_connector.txid).await?.unwrap();
                (
                    Some(*update_connector),
                    Some(tmp_tx.output[update_connector.vout as usize].value),
                    Some(fee_tx.output[fee_tx_outpoint.vout as usize].value),
                )
            }
            None => (None, None, Some(replenish_fee)),
        };

    let mut sequencer_set_publish_tx = create_sequencer_update_partial_tx(
        sequencer_set_hash,
        &update_connector,
        &Some(fee_tx_outpoint),
        next_update_connector_address.clone(),
        relayer_fee,
    )?;

    let owner_private_key = PrivateKey::from_wif(owner_btc_key_wif.as_ref().unwrap())?;

    let fee_tx = btc_client.get_tx(&fee_tx_outpoint.txid).await?.expect("fee tx doesn't exist");

    let (update_connector_value, _replenish_fee_connector_value) = match &update_connector {
        None => (None, Some(replenish_fee)),
        Some(update_connector) => {
            // digest the previous commit tx's output utxo
            let (_update_connector, update_connector_value) = {
                let tmp_tx = btc_client.get_tx(&update_connector.txid).await?.unwrap();
                (Some(*update_connector), tmp_tx.output[update_connector.vout as usize].value)
            };
            (Some(update_connector_value), Some(fee_tx.output[0].value))
        }
    };

    println!("update_connector_value: {update_connector_value:?}");
    println!("replenish_fee_connector_value: {_replenish_fee_connector_value:?}");
    let sig_hash_type = EcdsaSighashType::AllPlusAnyoneCanPay;
    // if this is not the genesis commit tx
    if let Some(update_connector_value_) = update_connector_value {
        println!("Standard spending flow for sequencer set publish tx");
        let (sig, msg) = sign_raw(
            &mut sequencer_set_publish_tx,
            &owner_private_key.inner,
            &redeem_script,
            update_connector_value_,
            sig_hash_type,
        )?;

        let secp = secp256k1::Secp256k1::new();
        update_sequencer_set_on_goat(
            goat_client,
            goat_block_number,
            msg[..].try_into().unwrap(),
            owner_private_key.public_key(&secp).to_bytes().try_into().unwrap(),
            sig,
        )
        .await?;
    }
    Ok(())
}

/// Push fee tx
#[allow(clippy::too_many_arguments)]
async fn action_push_fee_tx(
    btc_client: &BTCClient,
    fund_btc_key_wif: Option<String>,
    owner_btc_key_wif: Option<String>,
    total: u32,
    fee_rate: u64,
    funding_input: Option<OutPoint>,
    goat_evm_address: [u8; 20],
    output_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let threshold = (2 * total).div_ceil(3);
    let secp = secp256k1::Secp256k1::new();
    let relayer_fee = Amount::from_sat(500);
    let replenish_fee = Amount::from_sat(fee_rate)
        * estimate_tx_vbytes(&[(threshold, total)], &[("p2wsh", 3)], 73) as u64
        + relayer_fee;

    let feepayer_private_key = PrivateKey::from_wif(fund_btc_key_wif.as_ref().unwrap())?;

    // TODO: can be public key
    let owner_private_key = PrivateKey::from_wif(owner_btc_key_wif.as_ref().unwrap())?;
    let funder_address = node_p2wsh_address(
        btc_client.network(),
        &PublicKey::from_private_key(&secp, &feepayer_private_key),
    );
    let owner_p2wpkh = Address::p2wpkh(
        &CompressedPublicKey::from_private_key(&secp, &owner_private_key)?,
        btc_client.network(),
    );

    let (first_input_utxo, first_input_value) = if let Some(funding_input) = funding_input {
        let tmp_tx = btc_client.get_tx(&funding_input.txid).await?.unwrap();
        (funding_input, tmp_tx.output[funding_input.vout as usize].value)
    } else {
        // use the first UTXO from regtest address
        let utxos = btc_client.get_address_utxo(funder_address.clone()).await?;
        let utxo = utxos.into_iter().find(|u| u.value > replenish_fee).expect("No UTXO found");
        (OutPoint::new(utxo.txid, utxo.vout), utxo.value)
    };
    println!("fee UTXOs: {first_input_utxo:#?}, value: {first_input_value}");

    let mut fee_tx = create_fee_tx(
        &goat_evm_address,
        &first_input_utxo,
        first_input_value,
        replenish_fee,
        owner_p2wpkh,
        funder_address,
        relayer_fee,
    )?;
    let txid =
        push_fee_tx(&mut fee_tx, first_input_value, &feepayer_private_key, btc_client).await?;

    let output = OutputData { fee_tx: Some(OutPoint::new(txid, 0)), ..Default::default() };
    save_output(output, output_file);
    Ok(())
}

/// fund publisher, debug only
async fn action_fund_publishers(
    btc_client: &BTCClient,
    fund_btc_key_wif: Option<String>,
    btc_public_keys: Vec<secp256k1::PublicKey>,
    output_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // read public key and threshold from smart contract, which is consistency with btc_public_keys
    //let publisher_keys: Vec<_> = create_dummy_publisher_keys(total);
    let funder_private_key = PrivateKey::from_wif(&fund_btc_key_wif.unwrap())?;
    let txn = fund_publishers(&funder_private_key, btc_public_keys, btc_client).await?;

    let output =
        OutputData { funding_input: Some(OutPoint::new(txn.0, txn.1)), ..Default::default() };
    save_output(output, output_file);
    Ok(())
}

async fn fund_publishers(
    fund_private_key: &PrivateKey,
    publishers: Vec<secp256k1::PublicKey>,
    btc_client: &BTCClient,
) -> Result<(Txid, u32), Box<dyn std::error::Error>> {
    println!("network: {:?}", btc_client.network());
    let secp = Secp256k1::new();
    let from_address = node_p2wsh_address(
        btc_client.network(),
        &PublicKey::from_private_key(&secp, fund_private_key),
    );
    println!("Funding publishers from address: {from_address}");
    let utxos = btc_client.get_address_utxo(from_address.clone()).await?;
    println!("utxo: {utxos:?}");
    assert!(!utxos.is_empty(), "No UTXO found to fund publishers");

    let mut total_value = 0;
    for utxo in &utxos {
        total_value += utxo.value.to_sat();
    }

    println!("Funding publishers from {from_address} with total UTXO value: {total_value}");

    let fee = Amount::from_sat(4000);
    let to_value = 20000; // each publisher get 20000 sat 

    let mut txins = Vec::new();
    for utxo in &utxos {
        txins.push(TxIn {
            previous_output: OutPoint { txid: utxo.txid, vout: utxo.vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        });
    }

    let mut txouts = Vec::new();
    let mut current_tx_vout = 0;
    for (i, pk) in publishers.iter().enumerate() {
        let address = Address::p2wpkh(&CompressedPublicKey(*pk), btc_client.network());
        txouts.push(TxOut {
            value: Amount::from_sat(to_value),
            script_pubkey: address.script_pubkey(),
        });
        if PublicKey::from_private_key(&secp, fund_private_key) == (*pk).into() {
            current_tx_vout = i;
        }
    }

    let change_value = total_value - to_value * publishers.len() as u64 - fee.to_sat();
    if change_value > 546 {
        txouts.push(TxOut {
            value: Amount::from_sat(change_value),
            script_pubkey: from_address.script_pubkey(),
        });
    }

    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: txins,
        output: txouts,
    };

    for (i, utxo) in utxos.iter().enumerate().take(tx.input.len()) {
        node_sign(
            &mut tx,
            i,
            utxo.value,
            EcdsaSighashType::All,
            &Keypair::from_secret_key(&secp, &fund_private_key.inner),
        )?;
    }

    println!("Funding txid: {:#?}", tx.compute_txid());
    broadcast_tx(btc_client, &tx).await?;
    assert!(
        wait_tx_confirmation(btc_client, &tx.compute_txid(), 3, 1000).await?,
        "Funding tx not confirmed"
    );
    Ok((tx.compute_txid(), current_tx_vout as u32))
}
