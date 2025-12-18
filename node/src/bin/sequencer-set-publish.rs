//! Create and sign a sequencer set publish transaction.
//!   * Publish sequencer set commitment to Bitcoin
//!   * Update publishers on GOAT
//!
//! Launch the local bitcoin regtest node with:
//! ```sh
//! cd ../scripts
//! docker-compose -f docker-compose.yml up -d
//! ```
use alloy::primitives::{Address as EvmAddress, B256, U256, utils::keccak256};
use alloy::signers::Signer;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolValue;
use bitcoin::CompressedPublicKey;
use bitcoin::{
    Address, Amount, Network, OutPoint, PrivateKey, PublicKey, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness, absolute::LockTime, hashes::Hash, key::Keypair,
    transaction::Version,
};
use bitvm2_noded::env::{
    ENV_GOAT_SEQUENCER_SET_MULTI_SIG_VERIFIER_ADDRESS,
    ENV_GOAT_SEQUENCER_SET_PUBLISHER_CONTRACT_ADDRESS, get_goat_address_from_env, get_network,
};
use bitvm2_noded::utils::broadcast_tx;
use bitvm2_noded::utils::wait_tx_confirmation;
use bitvm2_noded::utils::{node_p2wsh_address, node_sign};
use clap::{Parser, Subcommand};
use client::SequencerSet;
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
use client::goat_chain::GoatInitConfig;
use dotenv::dotenv;
use tracing_subscriber::EnvFilter;

use cbft_rpc::{fetch_cbft_validator_info, fetch_validators};
use commit_chain::CommitInfo;

use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin_light_client_circuit::{
    /*create_dummy_publisher_keys,*/ create_fee_tx, create_sequencer_update_partial_tx,
    decode_eth_address, estimate_tx_vbytes,
};
use commit_chain::{create_sequencer_update_script, finalize, sign_partial};
use tendermint::validator::Info;

use hex::FromHex;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::str::FromStr;
use util::hex_parse;

pub fn decode_eth_address_object(addr: &str) -> Result<EvmAddress, String> {
    let addr = addr.trim();
    EvmAddress::from_str(addr).map_err(|_| format!("Invalid Ethereum address: {addr}"))
}

#[derive(Parser)]
#[command(name = "sequencer-set-publisher", version, about)]
struct Args {
    #[command(subcommand)]
    command: Commands,

    /// Local bitcoin testnet
    #[arg(long, default_value = "http://127.0.0.1:3002")]
    esplora_url: String,

    #[arg(long, default_value = "https://rpc.testnet3.goat.network")]
    goat_rpc_url: String,

    #[clap(long, env, default_value = "https://cosmos.testnet3.goat.network/")]
    pub cosmos_rpc_url: String,

    #[arg(long, default_value_t = 2, env = "FEE_RATE")]
    fee_rate: u64, // sat/vbyte

    #[arg(long, env = "GOAT_EVM_PRVKEY")]
    goat_evm_prvkey: Option<String>,

    #[arg(long, env = "PUBLISHERS", value_delimiter = ',', value_parser = decode_eth_address_object)]
    publishers: Vec<EvmAddress>,

    #[arg(long, env = "OUTPUT_FILE", default_value = "output.data")]
    output_file: String,
}

#[derive(Default, Serialize, Deserialize)]
struct OutputData {
    funding_input_txid: Option<String>,
    funding_input_vout: Option<u32>,

    fee_txid: Option<String>,
    fee_tx_vout: Option<u32>,

    update_connector_txid: Option<String>,
    update_connector_vout: Option<u32>,

    p2wsh_sig_hash: Option<String>,
    sigs: Vec<String>,
    publisher_sigs: Vec<String>,
}
impl OutputData {
    fn merge(&mut self, other: OutputData) {
        if other.fee_txid.is_some() {
            self.fee_txid = other.fee_txid;
        }
        if other.fee_tx_vout.is_some() {
            self.fee_tx_vout = other.fee_tx_vout;
        }
        if other.funding_input_txid.is_some() {
            self.funding_input_txid = other.funding_input_txid;
        }
        if other.funding_input_vout.is_some() {
            self.funding_input_vout = other.funding_input_vout;
        }
        if other.update_connector_txid.is_some() {
            self.update_connector_txid = other.update_connector_txid;
        }
        if other.update_connector_vout.is_some() {
            self.update_connector_vout = other.update_connector_vout;
        }
        if other.p2wsh_sig_hash.is_some() {
            self.p2wsh_sig_hash = other.p2wsh_sig_hash;
        }

        self.sigs.extend(other.sigs);
        self.publisher_sigs.extend(other.publisher_sigs);
    }
}

async fn save_commit_info(
    goat_client: &GOATClient,
    output_file: &str,
    publishers: &[EvmAddress],
    sequencers: Vec<Info>,
    init_genesis: bool,
    commit_info_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let file = std::fs::File::open(output_file)?;
    let output: OutputData = serde_json::from_reader(file)?;
    let btc_public_keys = fetch_publishers(goat_client, publishers).await?;

    let txid = &output.update_connector_txid.unwrap();
    let genesis_txid = if !init_genesis {
        std::fs::read_to_string("{output_file}.genesis")?
    } else {
        std::fs::write(format!("{output_file}.genesis"), txid)?;
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

fn save_output(input: OutputData, output_file: &str, clean_sigs: bool) {
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
            if clean_sigs {
                output.sigs.clear();
                output.publisher_sigs.clear();
            }
            output.merge(input);
            output
        } else {
            input
        }
    };
    std::fs::write(output_file, serde_json::to_string_pretty(&output).unwrap()).unwrap();
}

#[derive(Subcommand)]
enum Commands {
    Fund {
        #[arg(long, env = "FUND_BTC_KEY_WIF")]
        fund_btc_key_wif: Option<String>,
    },
    SignSeq {
        #[arg(long, env = "OWNER_BTC_KEY_WIF")]
        owner_btc_key_wif: Option<String>,
        #[arg(long)]
        goat_block_number: u64,
        #[arg(long, env = "NEXT_PUBLISHERS", value_delimiter = ',', value_parser = decode_eth_address_object)]
        next_publishers: Vec<EvmAddress>,
        #[arg(long)]
        clean_sigs: bool,
    },
    PushSeq {
        #[arg(long, env = "OWNER_BTC_KEY_WIF")]
        owner_btc_key_wif: Option<String>,
        #[arg(long)]
        goat_block_number: u64,
        #[arg(long, env = "NEXT_PUBLISHERS", value_delimiter = ',', value_parser = decode_eth_address_object)]
        next_publishers: Vec<EvmAddress>,
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
    },
    SignPub {
        #[arg(long, env = "NEXT_PUBLISHERS", value_delimiter = ',', value_parser = decode_eth_address_object)]
        next_publishers: Vec<EvmAddress>,
    },
    UpdateSeqSet {
        #[arg(long, env = "NEXT_PUBLISHERS", value_delimiter = ',', value_parser = decode_eth_address_object)]
        next_publishers: Vec<EvmAddress>,
        #[arg(long)]
        goat_block_number: u64,
    },
    PushPub {
        #[arg(long, env = "NEXT_PUBLISHERS", value_delimiter = ',', value_parser = decode_eth_address_object)]
        next_publishers: Vec<EvmAddress>,

        #[arg(long, env = "NEXT_PUBLISHER_BTC_PUBKEYS", value_delimiter = ',', value_parser = |x: &str| Vec::from_hex(x).map_err(|e| e.to_string()))]
        next_publisher_btc_pubkeys: Vec<Vec<u8>>,
        #[arg(long)]
        goat_block_number: u64,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    //let dummy_publisher_keys: Vec<_> = create_dummy_publisher_keys(5);
    //println!("dummy keys: {:?}", dummy_publisher_keys);
    dotenv().ok();
    let _ = tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).try_init();
    let args = Args::parse();
    let (btc_client, goat_client) = init_clients(&args).await?;

    let output_file = &args.output_file;
    let cached_data = std::fs::read(output_file);
    let cached_output: OutputData = match cached_data {
        Ok(data) => serde_json::from_slice(&data).unwrap(),
        _ => OutputData::default(),
    };

    let p2wsh_sig_hash = match cached_output.p2wsh_sig_hash {
        Some(s) => Some(hex_parse::<32>(&s)?),
        None => None,
    };

    match args.command {
        Commands::Fund { fund_btc_key_wif } => {
            action_fund_publishers(
                &btc_client,
                &goat_client,
                args.publishers,
                fund_btc_key_wif,
                output_file,
            )
            .await
        }
        Commands::Payfee {
            fund_btc_key_wif,
            owner_btc_key_wif,
            funding_input_txid,
            funding_input_vout,
            goat_evm_address,
        } => {
            action_push_fee_tx(
                &btc_client,
                &goat_client,
                args.publishers.clone(),
                fund_btc_key_wif,
                owner_btc_key_wif,
                args.fee_rate,
                funding_input_txid,
                funding_input_vout,
                goat_evm_address,
                output_file,
            )
            .await
        }
        Commands::SignSeq { owner_btc_key_wif, goat_block_number, next_publishers, clean_sigs } => {
            let (sequencer_set_hash, _) =
                fetch_cbft_validator_info(&args.cosmos_rpc_url, goat_block_number).await?;

            let (fee_txid, fee_tx_vout) =
                (cached_output.fee_txid.clone(), cached_output.fee_tx_vout.unwrap());
            let (update_connector_txid, update_connector_vout) =
                (cached_output.update_connector_txid.clone(), cached_output.update_connector_vout);

            if clean_sigs {
                let output = OutputData::default();
                save_output(output, output_file, true);
            }
            action_sign_sequencer_set_update(
                &btc_client,
                &goat_client,
                owner_btc_key_wif,
                args.publishers.clone(),
                next_publishers,
                args.fee_rate,
                fee_txid,
                fee_tx_vout,
                update_connector_txid,
                update_connector_vout,
                sequencer_set_hash,
                output_file,
            )
            .await
        }
        Commands::PushSeq {
            owner_btc_key_wif,
            goat_block_number,
            next_publishers,
            init_genesis,
            commit_info,
        } => {
            let (sequencer_set_hash, cosmos_block_number) =
                fetch_cbft_validator_info(&args.cosmos_rpc_url, goat_block_number).await?;
            let sequencers = fetch_validators(&args.cosmos_rpc_url, cosmos_block_number).await?;
            let (fee_txid, fee_tx_vout) =
                (cached_output.fee_txid.clone(), cached_output.fee_tx_vout.unwrap());
            let (update_connector_txid, update_connector_vout) =
                (cached_output.update_connector_txid.clone(), cached_output.update_connector_vout);
            action_push_sequencer_set_update(
                &btc_client,
                &goat_client,
                owner_btc_key_wif,
                args.publishers.clone(),
                next_publishers,
                args.fee_rate,
                fee_txid,
                fee_tx_vout,
                update_connector_txid,
                update_connector_vout,
                cached_output.sigs,
                sequencer_set_hash,
                output_file,
            )
            .await?;
            match save_commit_info(
                &goat_client,
                &args.output_file,
                &args.publishers,
                sequencers,
                init_genesis,
                &commit_info,
            )
            .await
            {
                Err(e) => {
                    println!("Failed to save commit info: {e}");
                    Ok(())
                }
                _ => Ok(()),
            }
        }
        Commands::UpdateSeqSet { next_publishers, goat_block_number } => {
            // fetch validator set from cosmos
            let (sequence_set_hash, _) =
                fetch_cbft_validator_info(&args.cosmos_rpc_url, goat_block_number).await?;

            action_update_sequencer_set_on_goat(
                &btc_client,
                &goat_client,
                args.goat_evm_prvkey,
                args.publishers,
                next_publishers,
                sequence_set_hash,
                p2wsh_sig_hash,
                goat_block_number,
            )
            .await
        }
        Commands::SignPub { next_publishers } => {
            action_sign_publisher_update_on_goat(
                &btc_client,
                &goat_client,
                args.goat_evm_prvkey,
                next_publishers,
                output_file,
            )
            .await
        }
        Commands::PushPub { goat_block_number, next_publishers, next_publisher_btc_pubkeys } => {
            action_push_publisher_update_on_goat(
                &btc_client,
                &goat_client,
                next_publishers,
                next_publisher_btc_pubkeys,
                cached_output.publisher_sigs,
                goat_block_number,
            )
            .await
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
    publisher_sigs: Vec<Vec<u8>>,
    update_connector_value: Option<Amount>,
    replenish_fee_connector_value: Option<Amount>,
    btc_client: &BTCClient,
    sequencer_set_publish_tx: &mut Transaction,
    redeem_script: &ScriptBuf,
) -> Result<Txid, Box<dyn std::error::Error>> {
    let secp = secp256k1::Secp256k1::new();
    let sig_hash_type = EcdsaSighashType::AllPlusAnyoneCanPay;
    let mut input_index = 0;
    if let Some(value) = update_connector_value {
        println!("Standard spending flow for sequencer set publish tx");
        let (sig, _) = sign_partial(
            sequencer_set_publish_tx,
            &owner_private_key.inner,
            redeem_script,
            value,
            sig_hash_type,
        )
        .unwrap();
        input_index += 1;
        // TODO: should sort the sigs by public key
        let mut sigs = vec![sig];
        sigs.extend_from_slice(&publisher_sigs);
        finalize(sequencer_set_publish_tx, sigs, redeem_script)?;
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

// https://explorer.testnet3.goat.network/address/0x00c042C4D5D913277CE16611a2ce6e9003554aD5?tab=read_write_contract
async fn fetch_publishers(
    goat_client: &GOATClient,
    addresses: &[EvmAddress],
) -> Result<Vec<secp256k1::PublicKey>, anyhow::Error> {
    let mut pubkeys = Vec::new();
    for address in addresses {
        let pubkey = goat_client.seq_set_pub_get_publisher_public_keys(*address).await?;
        let btc_pubkey = secp256k1::PublicKey::from_slice(pubkey.as_ref())?;
        pubkeys.push(btc_pubkey);
    }
    Ok(pubkeys)
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

#[allow(clippy::too_many_arguments)]
async fn action_update_sequencer_set_on_goat(
    _btc_client: &BTCClient,
    goat_client: &GOATClient,
    goat_evm_prvkey: Option<String>,
    publishers: Vec<EvmAddress>,
    next_publishers: Vec<EvmAddress>,
    sequencer_set_hash: [u8; 32],
    p2wsh_sig_hash: Option<[u8; 32]>,
    goat_block_number: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    // FIXME: we must use abi_encode instead of abi_encode_packed here.
    let packed = publishers.iter().map(EvmAddress::abi_encode).collect::<Vec<Vec<u8>>>().concat();
    let publishers_hash = keccak256(&packed);

    let packed =
        next_publishers.iter().map(EvmAddress::abi_encode).collect::<Vec<Vec<u8>>>().concat();
    let next_publishers_hash = keccak256(&packed);

    let sequencer_set = SequencerSet {
        sequencer_set_hash,
        publishers_hash: *publishers_hash,
        next_publishers_hash: *next_publishers_hash,
        p2wsh_sig_hash: *p2wsh_sig_hash.as_ref().unwrap(),
        goat_block_number,
    };
    // sign p2wsh_sig_hash
    let sign = {
        let signer = PrivateKeySigner::from_str(goat_evm_prvkey.as_ref().unwrap())?;
        signer.sign_hash(&B256::from_slice(&sequencer_set.p2wsh_sig_hash)).await?
    };

    let txid = goat_client.seq_set_pub_update_sequencer_set(&sequencer_set, &sign).await?;
    println!("Txid: {txid}");
    Ok(())
}

/// Sign publisher update tx
async fn action_sign_publisher_update_on_goat(
    _btc_client: &BTCClient,
    goat_client: &GOATClient,
    goat_evm_prvkey: Option<String>,
    next_publishers: Vec<EvmAddress>,
    output_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use alloy::sol;
    sol! {
        struct OwnersUpdate {
            uint256 nonce;
            address[] newOwners;
            uint256 newRequired;
        }
    }

    let signer = PrivateKeySigner::from_str(goat_evm_prvkey.as_ref().unwrap())?;
    //    bytes32 digest = keccak256(
    //        abi.encode(nonce, newOwners, newRequired)
    //    );
    let nonce = goat_client.seq_set_pub_multi_sig_verifier_get_nonce().await?;
    let new_required: U256 = U256::from((next_publishers.len() * 2).div_ceil(3));
    println!("new required: {new_required}, nonce: {nonce}");
    let packed = {
        let update = OwnersUpdate { nonce, newOwners: next_publishers, newRequired: new_required };
        update.abi_encode_packed()
    };

    println!("hash {:?}", hex::encode(&packed));
    let sig_hash = keccak256(packed);
    println!("sig_hash {sig_hash:?}");
    let sign = signer.sign_hash(&sig_hash).await?;
    println!("Signature: {sign}");

    let mut output = OutputData::default();
    output.publisher_sigs.push(hex::encode(sign.as_bytes()));
    save_output(output, output_file, false);
    Ok(())
}

/// Push publishers tx
async fn action_push_publisher_update_on_goat(
    _btc_client: &BTCClient,
    goat_client: &GOATClient,
    new_publishers: Vec<EvmAddress>,
    new_publisher_btc_pubkeys: Vec<Vec<u8>>,
    sigs: Vec<String>,
    goat_block_number: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("sigs: {sigs:?}");
    let signatures: Vec<Vec<u8>> = sigs.iter().map(|sig| hex::decode(sig).unwrap()).collect();
    assert_eq!(new_publishers.len(), new_publisher_btc_pubkeys.len());
    let txid = goat_client
        .seq_set_pub_update_publisher_set(
            new_publishers,
            &new_publisher_btc_pubkeys,
            &signatures,
            U256::from(goat_block_number),
        )
        .await?;
    println!("publisher update txid: {txid}");
    Ok(())
}

/// Submit sequencer set commitment
#[allow(clippy::too_many_arguments)]
async fn action_push_sequencer_set_update(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    owner_btc_key_wif: Option<String>,
    publishers: Vec<EvmAddress>,
    next_publishers: Vec<EvmAddress>,
    fee_rate: u64,
    fee_txid: Option<String>,
    fee_tx_vout: u32,
    update_connector_txid: Option<String>,
    update_connector_vout: Option<u32>,
    sigs: Vec<String>,
    sequencer_set_hash: [u8; 32],
    output_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let btc_public_keys = fetch_publishers(goat_client, &publishers).await?;
    let next_btc_public_keys = fetch_publishers(goat_client, &next_publishers).await?;
    println!("btc pubkeys: {next_btc_public_keys:?}");

    let total = btc_public_keys.len();
    let threshold = (2 * total).div_ceil(3);

    let total = next_btc_public_keys.len();
    let next_threshold = (2 * total).div_ceil(3);

    let relayer_fee = Amount::from_sat(500);
    let network = get_network();

    let redeem_script = create_sequencer_update_script(&btc_public_keys, threshold);
    let next_redeem_script = create_sequencer_update_script(&next_btc_public_keys, next_threshold);
    let next_update_connector_address = Address::p2wsh(&next_redeem_script, network);

    let replenish_fee = Amount::from_sat(fee_rate)
        * estimate_tx_vbytes(&[(threshold as u32, total as u32)], &[("p2wsh", 3)], 73) as u64
        + relayer_fee;

    println!("replenish fee: {replenish_fee:?}");
    println!("sigs: {sigs:?}");
    // read public key and threshold from smart contract, which is consistency with btc_public_keys
    let fee_tx = btc_client
        .get_tx(&fee_txid.as_ref().unwrap().parse()?)
        .await?
        .expect("fee tx doesn't exist");

    // update the sequencer set publish tx with multisig signatures
    let (update_connector, update_connector_value, replenish_fee_connector_value) =
        match &update_connector_txid {
            Some(update_connector_txid) => {
                let tmp_txid = Txid::from_str(update_connector_txid).unwrap();
                let tmp_tx = btc_client.get_tx(&tmp_txid).await?.unwrap();
                let tmp_vout = update_connector_vout.unwrap();
                (
                    Some(OutPoint::new(tmp_txid, tmp_vout)),
                    Some(tmp_tx.output[tmp_vout as usize].value),
                    Some(fee_tx.output[fee_tx_vout as usize].value),
                )
            }
            None => (None, None, Some(replenish_fee)),
        };

    // Skip construction of the genesis tx
    let mut sequencer_set_publish_tx = create_sequencer_update_partial_tx(
        sequencer_set_hash,
        &update_connector,
        &Some(OutPoint { txid: fee_tx.compute_txid(), vout: fee_tx_vout }),
        next_update_connector_address.clone(),
        relayer_fee,
    )?;

    let secp = secp256k1::Secp256k1::new();
    let owner_private_key = PrivateKey::from_wif(owner_btc_key_wif.as_ref().unwrap())?;
    let owner_p2wpkh = Address::p2wpkh(
        &CompressedPublicKey::from_private_key(&secp, &owner_private_key)?,
        network,
    );
    let sigs = sigs.into_iter().map(|x| hex::decode(x).unwrap()).collect();

    let txid = push_sequencer_set_publish_tx(
        &owner_p2wpkh,
        &owner_private_key,
        sigs,
        update_connector_value,
        replenish_fee_connector_value,
        btc_client,
        &mut sequencer_set_publish_tx,
        &redeem_script,
    )
    .await?;

    let output = OutputData {
        update_connector_txid: Some(txid.to_string()),
        update_connector_vout: Some(0),
        ..Default::default()
    };
    save_output(output, output_file, false);

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn action_sign_sequencer_set_update(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    owner_btc_key_wif: Option<String>,
    publishers: Vec<EvmAddress>,
    next_publishers: Vec<EvmAddress>,
    fee_rate: u64,
    fee_txid: Option<String>,
    fee_tx_vout: u32,
    update_connector_txid: Option<String>,
    update_connector_vout: Option<u32>,
    sequencer_set_hash: [u8; 32],
    output_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let network = get_network();
    // read public key and threshold from smart contract, which is consistency with btc_public_keys
    let btc_public_keys = fetch_publishers(goat_client, &publishers).await?;
    let next_btc_public_keys = fetch_publishers(goat_client, &next_publishers).await?;
    //println!("btc pubkeys: {btc_public_keys:?}");

    let total = btc_public_keys.len();
    let threshold = (2 * total).div_ceil(3);
    let total = next_btc_public_keys.len();
    let next_threshold = (2 * total).div_ceil(3);

    let relayer_fee = Amount::from_sat(500);

    let redeem_script = create_sequencer_update_script(&btc_public_keys, threshold);
    let next_redeem_script = create_sequencer_update_script(&next_btc_public_keys, next_threshold);
    let next_update_connector_address = Address::p2wsh(&next_redeem_script, network);

    let replenish_fee = Amount::from_sat(fee_rate)
        * estimate_tx_vbytes(&[(threshold as u32, total as u32)], &[("p2wsh", 3)], 73) as u64
        + relayer_fee;

    let fee_tx = btc_client
        .get_tx(&fee_txid.as_ref().unwrap().parse()?)
        .await?
        .expect("fee tx doesn't exist");
    // update the sequencer set publish tx with multisig signatures
    let (update_connector, _update_connector_value, _replenish_fee_connector_value) =
        match &update_connector_txid {
            Some(update_connector_txid) => {
                let tmp_txid = Txid::from_str(update_connector_txid).unwrap();
                let tmp_tx = btc_client.get_tx(&tmp_txid).await?.unwrap();
                let tmp_vout = update_connector_vout.unwrap();
                (
                    Some(OutPoint::new(tmp_txid, tmp_vout)),
                    Some(tmp_tx.output[tmp_vout as usize].value),
                    Some(fee_tx.output[fee_tx_vout as usize].value),
                )
            }
            None => (None, None, Some(replenish_fee)),
        };

    let mut sequencer_set_publish_tx = create_sequencer_update_partial_tx(
        sequencer_set_hash,
        &update_connector,
        &Some(OutPoint { txid: fee_tx.compute_txid(), vout: fee_tx_vout }),
        next_update_connector_address.clone(),
        relayer_fee,
    )?;

    let owner_private_key = PrivateKey::from_wif(owner_btc_key_wif.as_ref().unwrap())?;

    let fee_tx = btc_client
        .get_tx(&fee_txid.as_ref().unwrap().parse()?)
        .await?
        .expect("fee tx doesn't exist");

    let (update_connector_value, _replenish_fee_connector_value) = match &update_connector_txid {
        None => (None, Some(replenish_fee)),
        Some(update_connector_txid) => {
            // digest the previous commit tx's output utxo
            let (_update_connector, update_connector_value) = {
                let tmp_txid = update_connector_txid.parse()?;
                let tmp_tx = btc_client.get_tx(&tmp_txid).await?.unwrap();
                (
                    Some(OutPoint::new(tmp_txid, update_connector_vout.unwrap())),
                    tmp_tx.output[update_connector_vout.unwrap() as usize].value,
                )
            };
            (Some(update_connector_value), Some(fee_tx.output[0].value))
        }
    };

    println!("update_connector_value: {update_connector_value:?}");
    println!("replenish_fee_connector_value: {_replenish_fee_connector_value:?}");
    let sig_hash_type = EcdsaSighashType::AllPlusAnyoneCanPay;
    // if this is not the genesis commit tx
    if update_connector_value.is_some() {
        println!("Standard spending flow for sequencer set publish tx");
        let (sig, msg) = sign_partial(
            &mut sequencer_set_publish_tx,
            &owner_private_key.inner,
            &redeem_script,
            update_connector_value.unwrap(),
            sig_hash_type,
        )?;
        let secp = secp256k1::Secp256k1::new();
        println!(
            "sig:\n {}: \"{}\"",
            PublicKey::from_private_key(&secp, &owner_private_key),
            hex::encode(&sig)
        );

        let mut output = OutputData::default();
        output.sigs.push(hex::encode(&sig));
        output.p2wsh_sig_hash = Some(hex::encode(&msg[..]));
        save_output(output, output_file, false);
    }
    Ok(())
}

/// Push fee tx
#[allow(clippy::too_many_arguments)]
async fn action_push_fee_tx(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    publishers: Vec<EvmAddress>,
    fund_btc_key_wif: Option<String>,
    owner_btc_key_wif: Option<String>,
    fee_rate: u64,
    funding_input_txid: Option<String>,
    funding_input_vout: Option<u32>,
    goat_evm_address: [u8; 20],
    output_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let btc_public_keys = fetch_publishers(goat_client, &publishers).await?;
    let total = btc_public_keys.len();
    let threshold = (2 * total).div_ceil(3);

    // read public key and threshold from smart contract, which is consistency with btc_public_keys
    let secp = secp256k1::Secp256k1::new();
    let network = get_network();
    let relayer_fee = Amount::from_sat(500);
    let replenish_fee = Amount::from_sat(fee_rate)
        * estimate_tx_vbytes(&[(threshold as u32, total as u32)], &[("p2wsh", 3)], 73) as u64
        + relayer_fee;

    let feepayer_private_key = PrivateKey::from_wif(fund_btc_key_wif.as_ref().unwrap())?;

    // TODO: can be public key
    let owner_private_key = PrivateKey::from_wif(owner_btc_key_wif.as_ref().unwrap())?;
    let funder_address =
        node_p2wsh_address(network, &PublicKey::from_private_key(&secp, &feepayer_private_key));
    let owner_p2wpkh = Address::p2wpkh(
        &CompressedPublicKey::from_private_key(&secp, &owner_private_key)?,
        network,
    );

    let (first_input_utxo, first_input_value) = if let (Some(txid_str), Some(vout)) =
        (&funding_input_txid, funding_input_vout)
    {
        let tmp_tx = btc_client.get_tx(&Txid::from_str(txid_str).unwrap()).await?.unwrap();
        (OutPoint::new(Txid::from_str(txid_str).unwrap(), vout), tmp_tx.output[vout as usize].value)
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

    let output =
        OutputData { fee_txid: Some(txid.to_string()), fee_tx_vout: Some(0), ..Default::default() };
    save_output(output, output_file, false);

    Ok(())
}

/// fund publisher, debug only
async fn action_fund_publishers(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    publishers: Vec<EvmAddress>,
    fund_btc_key_wif: Option<String>,
    output_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let network = get_network();
    let btc_public_keys = fetch_publishers(goat_client, &publishers).await?;

    // read public key and threshold from smart contract, which is consistency with btc_public_keys
    //let publisher_keys: Vec<_> = create_dummy_publisher_keys(total);
    let funder_private_key = PrivateKey::from_wif(&fund_btc_key_wif.unwrap())?;
    let txn = fund_publishers(&funder_private_key, btc_public_keys, btc_client, network).await?;

    let output = OutputData {
        funding_input_txid: Some(txn.0.to_string()),
        funding_input_vout: Some(txn.1),
        ..Default::default()
    };
    save_output(output, output_file, false);
    Ok(())
}

async fn fund_publishers(
    fund_private_key: &PrivateKey,
    publishers: Vec<secp256k1::PublicKey>,
    btc_client: &BTCClient,
    network: Network,
) -> Result<(Txid, u32), Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let from_address =
        node_p2wsh_address(network, &PublicKey::from_private_key(&secp, fund_private_key));
    println!("Funding publishers from address: {from_address}");
    let utxos = btc_client.get_address_utxo(from_address.clone()).await?;
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
        let address = Address::p2wpkh(&CompressedPublicKey(*pk), network);
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
