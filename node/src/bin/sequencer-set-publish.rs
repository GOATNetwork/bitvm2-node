//! Create and sign a sequencer set publish transaction.
//!   * Publish sequencer set commitment to Bitcoin
//!   * Update publishers on GOAT
//!
//! Launch the local bitcoin regtest node with:
//! ```sh
//! cd ../scripts
//! docker-compose -f docker-compose.yml up -d
//! ```
//! Run the sequencer set publish transaction with
//! ```sh
//!     GOAT_EVM_ADDRESS=0x8943545177806ED17B9F23F0a21ee5948eCaa776
//!     GOAT_SEQUENCER_SET_PUBLISHER_CONTRACT_ADDRESS=0xEE0fCB8E5cCAD0b4197BAabd633333886f5C364d
//!     FUND_BTC_KEY_WIF=cSWNzrM1CjFt1VZNBV7qTTr1t2fmZUgaQe2FL4jyFQRgTtrYp8Y5
//!     OWNER_BTC_KEY_WIF=cSWNzrM1CjFt1VZNBV7qTTr1t2fmZUgaQe2FL4jyFQRgTtrYp8Y5
//!     PUBLISHERS=0xcC1Bd124EA962Dd3e6f10F814FB6C4493CEA6d27,0x0b71c9fc399e7FE424f3c22d872735F32550eC09,0x55C55d24bBef5d79918270Af9366b97fC0C7AC7b,0xeBBa6C3BE7Dc14FAeB1c2547cF43D4ad6aD46Ef4,0xa0F88c27B535615A8D8808c6023986a540161021 
//!     NEXTPUBLISHERS=0xcC1Bd124EA962Dd3e6f10F814FB6C4493CEA6d27,0x0b71c9fc399e7FE424f3c22d872735F32550eC09,0x55C55d24bBef5d79918270Af9366b97fC0C7AC7b 
//! 
//!     # fund
//!     cargo run --bin sequencer-set-publish -- --owner-btc-key-wif cMceqPhHedrhbcR9eXgzmfWy7kRqLyAxMYwFT6ABDWsiwUp9Nsq9 --action fund
//!     # pay fee
//!     cargo run --bin sequencer-set-publish -- --owner-btc-key-wif cMceqPhHedrhbcR9eXgzmfWy7kRqLyAxMYwFT6ABDWsiwUp9Nsq9 --action payfee
//!     # push first commit tx, and record the txid, 415da708d361f5b0aab1542643b73565fa063871a7d23dbb215278160d1a2b0c
//!     cargo run --bin sequencer-set-publish -- --owner-btc-key-wif cMceqPhHedrhbcR9eXgzmfWy7kRqLyAxMYwFT6ABDWsiwUp9Nsq9 --action push-seq --fee-txid 3f062b488d7677b4bdf6ff67ec6c6a540ce80a388c470e3b081ded5a700d4ca5  --fee-tx-vout 0 
//!      
//!     # pay fee: 7c6ddfa28021e8fbc80572a45317cc613e89fbdd70226819af57d197e2767dc5
//!     cargo run --bin sequencer-set-publish -- --owner-btc-key-wif cMceqPhHedrhbcR9eXgzmfWy7kRqLyAxMYwFT6ABDWsiwUp9Nsq9 --action payfee
//!     
//!     # sign commit tx by >= 2/3 publishers, the final publisher will sign when pushing.
//!     cargo run --bin sequencer-set-publish -- --owner-btc-key-wif cMec2DGaTXkYJYfi7x3ZGjRXkeqmAvYAoWzMAcWj5fdLaqudWsNi --update-connector-txid 415da708d361f5b0aab1542643b73565fa063871a7d23dbb215278160d1a2b0c --update-connector-vout 0 --action sign-seq --fee-txid 7c6ddfa28021e8fbc80572a45317cc613e89fbdd70226819af57d197e2767dc5 --fee-tx-vout 0
//!     cargo run --bin sequencer-set-publish -- --owner-btc-key-wif cMgZD2qsGReP1UvGbNQ7moL6PZFgzsuPFV3St8sGwpNxED4hqkEM --update-connector-txid 415da708d361f5b0aab1542643b73565fa063871a7d23dbb215278160d1a2b0c --update-connector-vout 0 --action sign-seq --fee-txid 7c6ddfa28021e8fbc80572a45317cc613e89fbdd70226819af57d197e2767dc5 --fee-tx-vout 0
//!     cargo run --bin sequencer-set-publish -- --owner-btc-key-wif cMiWPrRA5KYDiRAq4nkgGsEf2TfcpqGbhT6YbfDpoy8ZsaAHiDeo --update-connector-txid 415da708d361f5b0aab1542643b73565fa063871a7d23dbb215278160d1a2b0c --update-connector-vout 0 --action sign-seq --fee-txid 7c6ddfa28021e8fbc80572a45317cc613e89fbdd70226819af57d197e2767dc5 --fee-tx-vout 0
//! 
//!     # push the next commit tx by multi-signatures
//!     cargo run --bin sequencer-set-publish -- --owner-btc-key-wif cMceqPhHedrhbcR9eXgzmfWy7kRqLyAxMYwFT6ABDWsiwUp9Nsq9 --update-connector-txid 415da708d361f5b0aab1542643b73565fa063871a7d23dbb215278160d1a2b0c --update-connector-vout 0 --action push-seq --sigs 3044022023a0f4f70fec9145ab509b6947c718654ae63b67a940c7beaa72d39efb97ffa402205fa36ad3269c5fe61d26cc9e5ea04da12915a2a6dc831ee4d177cf25da773acc81,3044022023a0f4f70fec9145ab509b6947c718654ae63b67a940c7beaa72d39efb97ffa402205fa36ad3269c5fe61d26cc9e5ea04da12915a2a6dc831ee4d177cf25da773acc81,3044022023a0f4f70fec9145ab509b6947c718654ae63b67a940c7beaa72d39efb97ffa402205fa36ad3269c5fe61d26cc9e5ea04da12915a2a6dc831ee4d177cf25da773acc81 --fee-txid 7c6ddfa28021e8fbc80572a45317cc613e89fbdd70226819af57d197e2767dc5 --fee-tx-vout 0 
//! ```
//! The key wif is used only for test.
//!
use alloy::primitives::{keccak256, Address as EvmAddress, B256, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy::sol_types::{SolValue};
use bitcoin::CompressedPublicKey;
use bitcoin::{
    Address, Amount, Network, OutPoint, PrivateKey, PublicKey, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness, absolute::LockTime, hashes::Hash, key::Keypair,
    transaction::Version,
};
use bitvm2_noded::utils::broadcast_tx;
use bitvm2_noded::utils::wait_tx_confirmation;
use bitvm2_noded::utils::{node_p2wsh_address, node_sign};
use clap::{Parser, ValueEnum, Subcommand};
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
use client::goat_chain::GoatInitConfig;
use client::SequencerSet;
use dotenv::dotenv;

use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin_light_client::{
    create_fee_tx, create_sequencer_update_partial_tx,
    create_sequencer_update_script, decode_eth_address, estimate_tx_vbytes, finalize, sign_partial,
};
use std::str::FromStr;

pub fn decode_eth_address_object(addr: &str) -> Result<EvmAddress, String> {
    let addr = addr.trim();
    EvmAddress::from_str(addr).map_err(|_| format!("Invalid Ethereum address: {addr}"))
}

pub fn hex_parse(s: &str) -> Result<[u8; 32], String> {
    use hex::FromHex;
    let b = Vec::from_hex(s).map_err(|e| e.to_string())?;
    b.try_into().map_err(|_| "len must be 32".to_string())
}

#[derive(Debug, Clone, ValueEnum)]
enum Action {
    SignSeq,
    SignPub,
    UpdateSeqSet,
    PushSeq,
    PushPub,
    Payfee,
    Fund,
}

/// Send kickoff without call initWithdraw on L2, this action should trigger disprove.
#[derive(Parser, Debug)]
#[command(name = "sequencer-set-publish")]
#[command(about = "Publish sequencer set on Bitcoin")]
struct Args {
    #[arg(long, value_enum)]
    action: Action,

    /// Local bitcoin testnet
    #[arg(long, default_value = "http://127.0.0.1:3002")]
    esplora_url: String,

    #[arg(long, default_value = "https://rpc.testnet3.goat.network")]
    goat_rpc_url: String,

    /// Funding tx
    #[arg(long)]
    funding_input_txid: Option<String>,
    #[arg(long)]
    funding_input_vout: Option<u32>,

    #[arg(long, default_value_t = 1, env = "FEE_RATE")]
    fee_rate: u64, // sat/vbyte

    #[arg(long)]
    update_connector_txid: Option<String>,
    #[arg(long)]
    update_connector_vout: Option<u32>,

    #[arg(long)]
    fee_txid: Option<String>,
    #[arg(long, default_value_t = 0)]
    fee_tx_vout: u32,

    #[arg(long, env = "FUND_BTC_KEY_WIF")]
    fund_btc_key_wif: Option<String>,
    #[arg(long, env = "OWNER_BTC_KEY_WIF")]
    owner_btc_key_wif: Option<String>,

    #[arg(long, env = "GOAT_EVM_ADDRESS", value_parser = decode_eth_address)]
    goat_evm_address: [u8; 20],

    #[arg(long, env = "GOAT_EVM_PRVKEY", default_value = "0xbb094981331d23f14f6fec3749c2bc6effa582d52a0c92c6b257809d89d37ab6")]
    goat_evm_prvkey: Option<String>,

    #[arg(long, env = "PUBLISHERS", value_delimiter = ',', value_parser = decode_eth_address_object)]
    publishers: Vec<EvmAddress>,

    #[arg(long, env = "NEXTPUBLISHERS", value_delimiter = ',', value_parser = decode_eth_address_object)]
    next_publishers: Vec<EvmAddress>,

    /// Hex-encoded signatures from other publishers, if not provided, only create partial tx and print the signature
    #[arg(long, env = "SIGS", value_delimiter = ',')]
    sigs: Option<Vec<String>>,

    #[arg(long, env = "SEQUENCER_SET_HASH", value_parser = hex_parse)]
    sequencer_set_hash: Option<[u8; 32]>,

    #[arg(long, env = "NEXT_SEQUENCER_SET_HASH", value_parser = hex_parse)]
    next_sequencer_set_hash: Option<[u8; 32]>,

    #[arg(long, env = "NEXT_SEQUENCER_SET_HASH", value_parser = hex_parse)]
    p2wsh_sig_hash: Option<[u8; 32]>,

    #[arg(long)]
    goat_block_number: Option<u64>,

    #[arg(long)]
    output: Option<String>
}

#[derive(Parser)]
#[command(name = "sequencer-set-publisher", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long)]
    output: Option<String>
}

#[derive(Subcommand)]
enum Commands {
    Fund {
        #[arg(long, env = "PUBLISHERS", value_delimiter = ',', value_parser = decode_eth_address_object)]
        publishers: Vec<EvmAddress>,
    },
    Publish {
        #[arg(long)]
        data: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    //let dummy_publisher_keys: Vec<_> = create_dummy_publisher_keys(5);
    //println!("dummy keys: {:?}", dummy_publisher_keys);
    dotenv().ok();
    let args = Args::parse();
    let (btc_client, goat_client) = init_clients(&args)?;

    match args.action {
        Action::Fund => action_fund_publishers(&args, &btc_client, &goat_client).await,
        Action::Payfee => action_push_fee_tx(&args, &btc_client, &goat_client).await,
        Action::SignSeq => action_sign_sequencer_set_update(&args, &btc_client, &goat_client).await,
        Action::PushSeq => action_push_sequencer_set_update(&args, &btc_client, &goat_client).await,
        Action::UpdateSeqSet => action_update_sequencer_set(&args, &btc_client, &goat_client).await,
        Action::SignPub => action_sign_publisher_update(&args, &btc_client, &goat_client).await,
        Action::PushPub => action_push_publisher_update(&args, &btc_client, &goat_client).await,
    }
}

async fn push_fee_tx(
    fee_tx: &mut Transaction,
    input_value: Amount,
    private_key: &PrivateKey,
    btc_client: &BTCClient,
) -> Result<(), Box<dyn std::error::Error>> {
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
    broadcast_tx(&btc_client, &fee_tx).await?;
    wait_tx_confirmation(&btc_client, &fee_tx.compute_txid(), 3, 1000).await?;
    println!("Fee tx confirmed");
    Ok(())
}

async fn push_sequencer_set_publish_tx(
    owner_p2wpkh: &Address,
    owner_private_key: &PrivateKey,
    publisher_sigs: Vec<Vec<u8>>,
    update_connector_value: Option<Amount>,
    replenish_fee_connector_value: Option<Amount>,
    btc_client: &BTCClient,
    sequencer_set_publish_tx: &mut Transaction,
    redeem_script: &ScriptBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let secp = secp256k1::Secp256k1::new();
    let sig_hash_type = EcdsaSighashType::AllPlusAnyoneCanPay;
    let mut input_index = 0;
    if update_connector_value.is_some() {
        println!("Standard spending flow for sequencer set publish tx");
        let sig = sign_partial(
            sequencer_set_publish_tx,
            &owner_private_key.inner,
            &redeem_script,
            update_connector_value.unwrap(),
            sig_hash_type,
        )
        .unwrap();
        input_index += 1;
        let mut sigs = vec![sig];
        sigs.extend_from_slice(&publisher_sigs);
        finalize(sequencer_set_publish_tx, sigs, &redeem_script)?;
    }

    // Sign the replenish fee input (P2WPKH)
    let signer_pkh = owner_p2wpkh
        .witness_program()
        .expect("addr")
        .program() // 20 bytes = hash160(pubkey)
        .to_owned();
    let script_code =
        ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::from_slice(signer_pkh.as_bytes())?);

    println!("Sequencer set publish: {:#?}", sequencer_set_publish_tx);
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
    println!("Sequencer set publish: {:#?}", sequencer_set_publish_tx);
    broadcast_tx(&btc_client, &sequencer_set_publish_tx).await?;
    wait_tx_confirmation(&btc_client, &sequencer_set_publish_tx.compute_txid(), 3, 1000).await?;
    println!("Sequencer set publish tx confirmed");
    Ok(())
}

// https://explorer.testnet3.goat.network/address/0x00c042C4D5D913277CE16611a2ce6e9003554aD5?tab=read_write_contract
async fn fetch_publishers(
    goat_client: &GOATClient,
    addresses: &[EvmAddress],
) -> Result<Vec<secp256k1::PublicKey>, anyhow::Error> {
    let mut pubkeys = Vec::new();
    for address in addresses {
        let pubkey = goat_client.seq_set_pub_get_publisher_public_keys(*address).await?;
        println!("{pubkey:?}");
        let btc_pubkey = secp256k1::PublicKey::from_slice(pubkey.as_ref())?;
        pubkeys.push(btc_pubkey);
    }
    Ok(pubkeys)
}

async fn fetch_commitment(goat_client: &GOATClient, height: U256) -> Result<[u8; 32], anyhow::Error> {
    let commitment = goat_client.seq_set_pub_calc_commitment(height).await?;
    Ok(commitment.into())
}

fn init_clients(args: &Args) -> Result<(BTCClient, GOATClient), anyhow::Error> {
    let network = Network::Regtest;
    let btc_client = BTCClient::new(network.into(), Some(&args.esplora_url));

    let mut config = GoatInitConfig::from_env_for_test();
    config.private_key = args.goat_evm_prvkey.clone();

    let goat_client =
        GOATClient::new(config, client::goat_chain::GoatNetwork::Test);
    Ok((btc_client, goat_client))
}

async fn action_update_sequencer_set(args: &Args, _btc_client: &BTCClient, goat_client: &GOATClient) -> Result<(), Box<dyn std::error::Error>> {
    // Todo: Fetch validator_hash and next_validator_hash from cosmos 
    let packed = args.publishers.iter().map(|publisher| EvmAddress::abi_encode(publisher)).collect::<Vec<Vec<u8>>>().concat();
    let publishers_hash = keccak256(&packed);

    let packed = args.next_publishers.iter().map(|publisher| EvmAddress::abi_encode(publisher)).collect::<Vec<Vec<u8>>>().concat();
    let next_publishers_hash = keccak256(&packed);

    let sequencer_set = SequencerSet { 
        sequencer_set_hash: args.sequencer_set_hash.as_ref().unwrap().clone(),
        next_sequencer_set_hash: args.next_sequencer_set_hash.as_ref().unwrap().clone(),

        publishers_hash: *publishers_hash,
        next_publishers_hash: *next_publishers_hash,

        p2wsh_sig_hash: args.p2wsh_sig_hash.as_ref().unwrap().clone(), 
        goat_block_number: args.goat_block_number.unwrap(), 
    };
    // sign p2wsh_sig_hash
    let sign = {
        let signer = PrivateKeySigner::from_str(args.goat_evm_prvkey.as_ref().unwrap())?;
        signer.sign_hash(&B256::from_slice(&sequencer_set.p2wsh_sig_hash)).await?
    };

    let txid = goat_client.seq_set_pub_update_sequencer_set(&sequencer_set, &sign).await?;
    println!("Txid: {txid}");
    Ok(())
}

/// Sign publisher update tx
async fn action_sign_publisher_update(
    args: &Args,
    _btc_client: &BTCClient,
    goat_client: &GOATClient,
) -> Result<(), Box<dyn std::error::Error>> {
    let signer = PrivateKeySigner::from_str(args.goat_evm_prvkey.as_ref().unwrap())?;
    //    bytes32 digest = keccak256(
    //        abi.encode(nonce, newOwners, newRequired, prevCmt, p2wshSigHash)
    //    );
    let nonce = goat_client.seq_set_pub_multi_sig_verifier_get_nonce().await?; 

    let new_publishers = &args.next_publishers;

    let new_publishers_packed = {
        let items: Vec<Vec<u8>> = new_publishers.iter().map(|publisher| EvmAddress::abi_encode(publisher)).collect();
        items.concat()
    };
    let new_required: U256 = U256::from((2 + new_publishers.len() * 2) / 3);

    let packed = vec![
        U256::abi_encode(&nonce),
        new_publishers_packed,
        U256::abi_encode(&new_required),
    ].concat();
    let sig_hash = keccak256(packed);

    // sign p2wsh_sig_hash
    let sign = signer.sign_hash(&B256::from_slice(&sig_hash.as_ref())).await?;
    println!("Signature: {sign}");
    Ok(())
}

/// Push publishers tx
async fn action_push_publisher_update(
    args: &Args,
    _btc_client: &BTCClient,
    goat_client: &GOATClient,
) -> Result<(), Box<dyn std::error::Error>> {
    let new_publishers = &args.publishers;
    let new_publisher_btc_pubkeys = [];

    let signatures: Vec<Vec<u8>> = args.sigs.as_ref().unwrap().iter().map(|sig| {
        hex::decode(sig).unwrap()
    }).collect();
    let txid = goat_client
        .seq_set_pub_update_publisher_set(
            new_publishers.clone(),
            &new_publisher_btc_pubkeys,
            &signatures,
            U256::from(args.goat_block_number.unwrap()),
        )
        .await?;
    println!("publisher update txid: {txid}");
    Ok(())
}

/// Submit sequencer set commitment
async fn action_push_sequencer_set_update(
    args: &Args,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
) -> Result<(), Box<dyn std::error::Error>> {
    let btc_public_keys = fetch_publishers(&goat_client, &args.publishers).await?;
    //println!("btc pubkeys: {btc_public_keys:?}");
    let total = btc_public_keys.len();
    let threshold = (2 * total + 2) / 3;
    let relayer_fee = Amount::from_sat(500);
    let network = Network::Regtest;

    let redeem_script = create_sequencer_update_script(&btc_public_keys, threshold);
    let next_update_connector_address = Address::p2wsh(&redeem_script, network);

    let replenish_fee = Amount::from_sat(args.fee_rate)
        * estimate_tx_vbytes(&[(threshold as u32, total as u32)], &[("p2wsh", 3)], 73) as u64
        + relayer_fee;

    println!("replenish fee: {replenish_fee:?}");
    println!("sigs: {:?}", args.sigs);
    let commitment = fetch_commitment(&goat_client, U256::from(args.goat_block_number.unwrap())).await?;


    // read public key and threshold from smart contract, which is consistency with btc_public_keys
    //let publisher_keys: Vec<_> = create_dummy_publisher_keys(total);
    let fee_tx = btc_client
        .get_tx(&args.fee_txid.as_ref().unwrap().parse()?)
        .await?
        .expect("fee tx doesn't exist");

    // update the sequencer set publish tx with multisig signatures
    let (update_connector, update_connector_value, replenish_fee_connector_value) = match &args.update_connector_txid {
        Some(update_connector_txid) =>  {
            let tmp_txid = Txid::from_str(update_connector_txid).unwrap();
            let tmp_tx = btc_client.get_tx(&tmp_txid).await?.unwrap();
            let tmp_vout = args.update_connector_vout.unwrap();
            (
                Some(OutPoint::new(tmp_txid, tmp_vout)),
                Some(tmp_tx.output[tmp_vout as usize].value),
                Some(fee_tx.output[args.fee_tx_vout as usize].value),
            )
        }
        None => (None, None, Some(replenish_fee))
    };


    // Skip construction of the genesis tx
    let mut sequencer_set_publish_tx = create_sequencer_update_partial_tx(
        commitment.clone(),
        &update_connector,
        &Some(OutPoint { txid: fee_tx.compute_txid(), vout: args.fee_tx_vout }),
        next_update_connector_address.clone(),
        relayer_fee,
    )?;

    let secp = secp256k1::Secp256k1::new();
    let owner_private_key = PrivateKey::from_wif(args.owner_btc_key_wif.as_ref().unwrap())?;
    let owner_p2wpkh = Address::p2wpkh(
        &CompressedPublicKey::from_private_key(&secp, &owner_private_key)?,
        network,
    );
    let sigs = match &args.sigs {
        Some(sigs) => sigs.into_iter().map(|x| hex::decode(x).unwrap()).collect(),
        None => vec![],
    };
   
    push_sequencer_set_publish_tx(
        &owner_p2wpkh,
        &owner_private_key,
        sigs,
        update_connector_value,
        replenish_fee_connector_value,
        &btc_client,
        &mut sequencer_set_publish_tx,
        &redeem_script,
    )
    .await?;
    Ok(())
}

async fn action_sign_sequencer_set_update(
    args: &Args,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
) -> Result<(), Box<dyn std::error::Error>> {
    let network = Network::Regtest;
    // read public key and threshold from smart contract, which is consistency with btc_public_keys
    //let publisher_keys: Vec<_> = create_dummy_publisher_keys(total);
    let btc_public_keys = fetch_publishers(&goat_client, &args.publishers).await?;
    //println!("btc pubkeys: {btc_public_keys:?}");

    let total = btc_public_keys.len();
    let threshold = (2 * total + 2) / 3;
    let relayer_fee = Amount::from_sat(500);

    let redeem_script = create_sequencer_update_script(&btc_public_keys, threshold);
    let next_update_connector_address = Address::p2wsh(&redeem_script, network);

    let replenish_fee = Amount::from_sat(args.fee_rate)
        * estimate_tx_vbytes(&[(threshold as u32, total as u32)], &[("p2wsh", 3)], 73) as u64
        + relayer_fee;

    // fetch the commitment from given block number
    let commitment = fetch_commitment(goat_client, U256::from(args.goat_block_number.unwrap())).await?;

    let fee_tx = btc_client
        .get_tx(&args.fee_txid.as_ref().unwrap().parse()?)
        .await?
        .expect("fee tx doesn't exist");
    // update the sequencer set publish tx with multisig signatures
    let (update_connector, _update_connector_value, _replenish_fee_connector_value) = match &args.update_connector_txid {
        Some(update_connector_txid) =>  {
            let tmp_txid = Txid::from_str(update_connector_txid).unwrap();
            let tmp_tx = btc_client.get_tx(&tmp_txid).await?.unwrap();
            let tmp_vout = args.update_connector_vout.unwrap();
            (
                Some(OutPoint::new(tmp_txid, tmp_vout)),
                Some(tmp_tx.output[tmp_vout as usize].value),
                Some(fee_tx.output[args.fee_tx_vout as usize].value),
            )
        }
        None => (None, None, Some(replenish_fee))
    };

    let mut sequencer_set_publish_tx = create_sequencer_update_partial_tx(
        commitment.clone(),
        &update_connector,
        &Some(OutPoint { txid: fee_tx.compute_txid(), vout: args.fee_tx_vout }),
        next_update_connector_address.clone(),
        relayer_fee,
    )?;

    let owner_private_key = PrivateKey::from_wif(args.owner_btc_key_wif.as_ref().unwrap())?;

    let fee_tx = btc_client
        .get_tx(&args.fee_txid.as_ref().unwrap().parse()?)
        .await?
        .expect("fee tx doesn't exist");

    let (update_connector_value, _replenish_fee_connector_value) = match &args.update_connector_txid
    {
        None => (None, Some(replenish_fee)),
        Some(update_connector_txid) => {
            // digest the previous commit tx's output utxo 
            let (_update_connector, update_connector_value) = {
                let tmp_txid = update_connector_txid.parse()?;
                let tmp_tx = btc_client.get_tx(&tmp_txid).await?.unwrap();
                (
                    Some(OutPoint::new(tmp_txid, args.update_connector_vout.unwrap().clone())),
                    tmp_tx.output[args.update_connector_vout.unwrap() as usize].value,
                )
            };
            (Some(update_connector_value), Some(fee_tx.output[0].value))
        }
    };

    let sig_hash_type = EcdsaSighashType::AllPlusAnyoneCanPay;
    // if this is not the genesis commit tx
    if update_connector_value.is_some() {
        println!("Standard spending flow for sequencer set publish tx");
        let sig = sign_partial(
            &mut sequencer_set_publish_tx,
            &owner_private_key.inner,
            &redeem_script,
            update_connector_value.unwrap(),
            sig_hash_type,
        )?;
        let secp = secp256k1::Secp256k1::new();
        println!("sig:\n {}: \"{}\"", PublicKey::from_private_key(&secp, &owner_private_key) ,hex::encode(&sig));
    }
    Ok(())
}

/// Push fee tx
async fn action_push_fee_tx(
    args: &Args,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
) -> Result<(), Box<dyn std::error::Error>> {
    let btc_public_keys = fetch_publishers(&goat_client, &args.publishers).await?;
    let total = btc_public_keys.len();
    let threshold = (2 * total + 2) / 3;

    // read public key and threshold from smart contract, which is consistency with btc_public_keys
    let secp = secp256k1::Secp256k1::new();
    let network = Network::Regtest;
    let relayer_fee = Amount::from_sat(500);
    let replenish_fee = Amount::from_sat(args.fee_rate)
        * estimate_tx_vbytes(&[(threshold as u32, total as u32)], &[("p2wsh", 3)], 73) as u64
        + relayer_fee;

    let feepayer_private_key = PrivateKey::from_wif(args.fund_btc_key_wif.as_ref().unwrap())?;

    // TODO: can be public key
    let owner_private_key = PrivateKey::from_wif(args.owner_btc_key_wif.as_ref().unwrap())?;
    let funder_address =
        node_p2wsh_address(network, &PublicKey::from_private_key(&secp, &feepayer_private_key));
    let owner_p2wpkh = Address::p2wpkh(
        &CompressedPublicKey::from_private_key(&secp, &owner_private_key)?,
        network,
    );

    let (first_input_utxo, first_input_value) = if args.funding_input_txid.is_some()
        && args.funding_input_vout.is_some()
    {
        let tmp_tx = btc_client
            .get_tx(&Txid::from_str(&args.funding_input_txid.clone().unwrap()).unwrap())
            .await?
            .unwrap();
        (
            OutPoint::new(
                Txid::from_str(&args.funding_input_txid.clone().unwrap()).unwrap(),
                args.funding_input_vout.unwrap(),
            ),
            tmp_tx.output[args.funding_input_vout.unwrap() as usize].value,
        )
    } else {
        // use the first UTXO from regtest address
        let utxos = btc_client.get_address_utxo(funder_address.clone()).await?;
        let utxo =
            utxos.into_iter().filter(|u| u.value > replenish_fee).next().expect("No UTXO found");
        (OutPoint::new(utxo.txid, utxo.vout), utxo.value)
    };
    println!("fee UTXOs: {:#?}, value: {}", first_input_utxo, first_input_value);

    let mut fee_tx = create_fee_tx(
        &args.goat_evm_address,
        &first_input_utxo,
        first_input_value,
        replenish_fee.clone(),
        owner_p2wpkh,
        funder_address,
        relayer_fee.clone(),
    )?;
    push_fee_tx(&mut fee_tx, first_input_value, &feepayer_private_key, &btc_client).await?;
    Ok(())
}

/// fund publisher, debug only
async fn action_fund_publishers(
    args: &Args,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
) -> Result<(), Box<dyn std::error::Error>> {
    let network = Network::Regtest;
    let btc_public_keys = fetch_publishers(&goat_client, &args.publishers).await?;

    // read public key and threshold from smart contract, which is consistency with btc_public_keys
    //let publisher_keys: Vec<_> = create_dummy_publisher_keys(total);
    let funder_private_key = PrivateKey::from_wif(args.fund_btc_key_wif.as_ref().unwrap())?;
    fund_publishers(
        &funder_private_key,
        //publisher_keys.iter().map(|(sk, _)| *sk).collect(),
        btc_public_keys,
        &btc_client,
        network,
    )
    .await?;
    Ok(())
}

async fn fund_publishers(
    private_key: &PrivateKey,
    publishers: Vec<secp256k1::PublicKey>,
    btc_client: &BTCClient,
    network: Network,
) -> Result<(), Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let from_address =
        node_p2wsh_address(network, &PublicKey::from_private_key(&secp, private_key));
    println!("Funding publishers from address: {}", from_address);
    let utxos = btc_client.get_address_utxo(from_address.clone()).await?;
    assert!(utxos.len() > 0, "No UTXO found to fund publishers");

    let mut total_value = 0;
    for utxo in &utxos {
        total_value += utxo.value.to_sat();
    }

    println!("Funding publishers from {} with total UTXO value: {}", from_address, total_value);

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
    for pk in &publishers {
        let address = Address::p2wpkh(&CompressedPublicKey(*pk), network);
        txouts.push(TxOut {
            value: Amount::from_sat(to_value),
            script_pubkey: address.script_pubkey(),
        });
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

    for i in 0..tx.input.len() {
        node_sign(
            &mut tx,
            i,
            utxos[i].value,
            EcdsaSighashType::All,
            &Keypair::from_secret_key(&secp, &private_key.inner),
        )?;
    }

    println!("Funding txid: {:#?}", tx.compute_txid());
    broadcast_tx(btc_client, &tx).await?;
    assert!(
        wait_tx_confirmation(btc_client, &tx.compute_txid(), 3, 1000).await?,
        "Funding tx not confirmed"
    );
    Ok(())
}
