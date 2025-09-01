//! Create and sign a sequencer set publish transaction.
//!
//! Launch the local bitcoin regtest node with:
//! ```sh
//! cd ../scripts
//! docker-compose -f docker-compose.yml up -d
//! ```
//! Run the sequencer set publish transaction with
//! ```sh
//!     GOAT_EVM_ADDRESS=0x8943545177806ED17B9F23F0a21ee5948eCaa776
//!     GOAT_SEQUENCER_SET_PUBLISHER_CONTRACT_ADDRESS=0x8943545177806ED17B9F23F0a21ee5948eCaa776
//!     FEE_PAYER_BTC_KEY_WIF=cSWNzrM1CjFt1VZNBV7qTTr1t2fmZUgaQe2FL4jyFQRgTtrYp8Y5
//!     cargo run --bin sequencer-set-publish
//! ```
//! The key wif is used only for test.
//!
use bitcoin::CompressedPublicKey;
use bitcoin::Network;
use bitcoin::absolute::LockTime;
use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::script::Builder;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, OutPoint, PrivateKey, PublicKey, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Txid, Witness, key::Keypair,
};
use bitvm2_noded::client::btc_chain::BTCClient;
use bitvm2_noded::utils::broadcast_tx;
use bitvm2_noded::utils::wait_tx_confirmation;
use bitvm2_noded::utils::{node_p2wsh_address, node_sign};
use clap::Parser;
use dotenv::dotenv;
use hex::FromHex;
use rand::seq::IteratorRandom;
use rand::thread_rng;

use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use secp256k1::{Message, Secp256k1, SecretKey};
use std::str::FromStr;

/// Send kickoff without call initWithdraw on L2, this action should trigger disprove.
#[derive(Parser, Debug)]
#[command(name = "sequencer-set-publish")]
#[command(about = "Publish sequencer set on Bitcoin")]
struct Args {
    /// Local bitcoin testnet
    #[arg(long, default_value = "http://127.0.0.1:3002")]
    esplora_url: String,

    #[arg(long)]
    input_txid: Option<String>,
    #[arg(long)]
    input_vout: Option<u32>,

    #[arg(long, default_value_t = 1, env = "FEE_RATE")]
    fee_rate: u64, // sat/vbyte

    #[arg(long)]
    update_connector_txid: Option<String>,
    #[arg(long)]
    update_connector_vout: Option<u32>,

    #[arg(long, default_value = "")]
    comet_bft_rpc: String,

    #[arg(long, env = "FEE_PAYER_BTC_KEY_WIF")]
    feepayer_btc_key_wif: Option<String>,

    #[arg(long, env = "GOAT_EVM_ADDRESS", value_parser = decode_eth_address)]
    goat_evm_address: [u8; 20],

    #[arg(long, env = "GOAT_SEQUENCER_SET_PUBLISHER_CONTRACT_ADDRESS")]
    goat_sequencer_set_publisher_contract_address: String,

    /// Hex-encoded signatures from other publishers, if not provided, only create partial tx and print the signature
    #[arg(long)]
    sigs: Option<Vec<String>>,

    #[arg(long, value_parser = parse_commitment, default_value = "")]
    commitment: [u8; 32],
}

fn decode_eth_address(addr: &str) -> Result<[u8; 20], hex::FromHexError> {
    // Strip 0x if it exists
    let addr = addr.strip_prefix("0x").unwrap_or(addr);
    // Decode into Vec<u8>
    let bytes = Vec::from_hex(addr)?;

    // Ensure it's 20 bytes
    let arr: [u8; 20] = bytes.try_into().expect("Ethereum address must be 20 bytes");
    Ok(arr)
}

// return [0u8; 32] from hex string if s is empty
fn parse_commitment(s: &str) -> Result<[u8; 32], String> {
    if s.is_empty() {
        return Ok([0u8; 32]);
    }
    let bytes = hex::decode(s).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("Commitment must be 32 bytes, got {}", bytes.len()));
    }
    Ok(bytes.try_into().unwrap()) // safe because we checked length
}

/// Return script length L for a standard m-of-n multisig script with compressed pubkeys.
pub fn multisig_script_len(n: u32) -> u32 {
    // <m>(1) + n * (push(33)=1 + 33) + <n>(1) + OP_CHECKMULTISIG(1)
    1 + n * 34 + 1 + 1
}

/// Estimate vbytes for a P2WSH m-of-n input (SegWit v0), rounding up.
pub fn p2wsh_input_vbytes(m: u32, n: u32, siglen: u32) -> u32 {
    let l = multisig_script_len(n);
    // witness = 1(count) + 1(dummy) + m*(1+siglen) + (1 + L)
    let witness_bytes = 1 + 1 + m * (1 + siglen) + (1 + l);
    let weight = 4 * 41 + witness_bytes; // base 41 bytes
    (weight + 3) / 4 // ceil(weight/4)
}

/// Common siglen is ~73 incl. sighash byte.
pub fn estimate_tx_vbytes(
    inputs: &[(u32, u32)],           // list of (m, n) P2WSH inputs
    outputs: &[(&'static str, u32)], // ("p2wpkh"|"p2wsh"|"p2tr"|"p2pkh", count)
    siglen: u32,
) -> u32 {
    let mut v = 10; // overhead
    for &(m, n) in inputs {
        v += p2wsh_input_vbytes(m, n, siglen);
    }
    for &(ty, count) in outputs {
        let size = match ty {
            "p2wpkh" => 31,
            "p2wsh" => 43,
            "p2tr" => 43,
            "p2pkh" => 34,
            _ => panic!("unknown output type"),
        };
        v += size * count;
    }
    v
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
    feepayer_p2wpkh: &Address,
    private_key: &PrivateKey,
    publisher_keys: &Vec<(secp256k1::SecretKey, secp256k1::PublicKey)>,
    threshold: u32,
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
        // sign update connector by multiple signers
        let mut rng = thread_rng();
        let mut pks: Vec<_> =
            (0..publisher_keys.len()).choose_multiple(&mut rng, threshold as usize);
        pks.sort_unstable();
        let pks: Vec<_> = pks.iter().map(|i| publisher_keys[*i]).collect();

        let sigs = pks
            .iter()
            .map(|(sk, _)| {
                sign_partial(
                    sequencer_set_publish_tx,
                    sk,
                    &redeem_script,
                    update_connector_value.unwrap(),
                    sig_hash_type,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        input_index += 1;
        finalize(sequencer_set_publish_tx, sigs, &redeem_script)?;
    }

    if replenish_fee_connector_value.is_some() {
        // Sign the replenish fee input (P2WPKH)
        let signer_pkh = feepayer_p2wpkh
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

        let sig = secp.sign_ecdsa(&msg, &private_key.inner);
        let mut sig_bytes = sig.serialize_der().to_vec();
        sig_bytes.push(sig_hash_type as u8);

        sequencer_set_publish_tx.input[input_index].witness =
            Witness::from(vec![sig_bytes, private_key.public_key(&secp).to_bytes()]);
    }

    println!("Sequencer set publish txid: {:#?}", sequencer_set_publish_tx.compute_txid());
    broadcast_tx(&btc_client, &sequencer_set_publish_tx).await?;
    wait_tx_confirmation(&btc_client, &sequencer_set_publish_tx.compute_txid(), 3, 1000).await?;
    println!("Sequencer set publish tx confirmed");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    let mut args = Args::parse();
    let network = Network::Regtest;
    let secp = secp256k1::Secp256k1::new();
    let btc_client = BTCClient::new(network.into(), Some(&args.esplora_url));
    let feepayer_private_key = PrivateKey::from_wif(args.feepayer_btc_key_wif.as_ref().unwrap())?;
    let owner_address =
        node_p2wsh_address(network, &PublicKey::from_private_key(&secp, &feepayer_private_key));
    let feepayer_p2wpkh = Address::p2wpkh(
        &CompressedPublicKey::from_private_key(&secp, &feepayer_private_key)?,
        network,
    );

    let relayer_fee = Amount::from_sat(500);
    let threshold = 3;
    let total = 5;

    // TODO: read public key and threshold from smart contract
    let publisher_keys: Vec<_> = create_dummy_publisher_keys(total);
    let public_keys: Vec<secp256k1::PublicKey> = publisher_keys.iter().map(|(_, pk)| *pk).collect();

    fund_dummy_publishers(
        &feepayer_private_key,
        publisher_keys.iter().map(|(sk, _)| *sk).collect(),
        &btc_client,
        network,
    )
    .await?;

    let redeem_script = create_sequencer_update_script(&public_keys, threshold, total);
    let next_update_connector_address = Address::p2wsh(&redeem_script, network);

    let replenish_fee = Amount::from_sat(args.fee_rate)
        * estimate_tx_vbytes(&[(threshold, total)], &[("p2wsh", 3)], 73) as u64
        + relayer_fee;

    let (first_input_utxo, first_input_value) = if args.input_txid.is_some()
        && args.input_vout.is_some()
    {
        let tmp_tx = btc_client
            .get_tx(&Txid::from_str(&args.input_txid.clone().unwrap()).unwrap())
            .await?
            .unwrap();
        (
            OutPoint::new(
                Txid::from_str(&args.input_txid.clone().unwrap()).unwrap(),
                args.input_vout.unwrap(),
            ),
            tmp_tx.output[args.input_vout.unwrap() as usize].value,
        )
    } else {
        // use the first UTXO from regtest address
        let utxos = btc_client.get_address_utxo(owner_address.clone()).await?;
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
        feepayer_p2wpkh.clone(),
        owner_address.clone(),
        relayer_fee.clone(),
    )?;
    push_fee_tx(&mut fee_tx, first_input_value, &feepayer_private_key, &btc_client).await?;

    // Skip construction of the genesis tx
    let mut sequencer_set_publish_tx = create_sequencer_update_partial_tx(
        args.commitment.clone(),
        &None,
        &Some(OutPoint { txid: fee_tx.compute_txid(), vout: 0 }),
        next_update_connector_address.clone(),
        relayer_fee,
    )?;

    push_sequencer_set_publish_tx(
        &feepayer_p2wpkh,
        &feepayer_private_key,
        &publisher_keys,
        threshold,
        None,
        Some(replenish_fee),
        &btc_client,
        &mut sequencer_set_publish_tx,
        &redeem_script,
    )
    .await?;

    println!("Run standard spending flow for sequencer set publish tx");
    args.update_connector_txid = Some(sequencer_set_publish_tx.compute_txid().to_string());
    args.update_connector_vout = Some(0);

    let (input_utxo, input_value) = if args.input_txid.is_some() && args.input_vout.is_some() {
        let tmp_tx = btc_client
            .get_tx(&Txid::from_str(&args.input_txid.clone().unwrap()).unwrap())
            .await?
            .unwrap();
        (
            OutPoint::new(
                Txid::from_str(&args.input_txid.clone().unwrap()).unwrap(),
                args.input_vout.unwrap(),
            ),
            tmp_tx.output[args.input_vout.unwrap() as usize].value,
        )
    } else {
        // use the first UTXO from regtest address
        let utxos = btc_client.get_address_utxo(owner_address.clone()).await?;
        let utxo =
            utxos.into_iter().filter(|u| u.value > replenish_fee).next().expect("No UTXO found");
        (OutPoint::new(utxo.txid, utxo.vout), utxo.value)
    };
    println!("Second fee UTXOs: {:#?}, value: {}", input_utxo, input_value);

    let mut fee_tx = create_fee_tx(
        &args.goat_evm_address,
        &input_utxo,
        input_value,
        replenish_fee.clone(),
        feepayer_p2wpkh.clone(),
        owner_address.clone(),
        relayer_fee.clone(),
    )?;
    push_fee_tx(&mut fee_tx, input_value, &feepayer_private_key, &btc_client).await?;

    // update the sequencer set publish tx with multisig signatures
    let (update_connector, update_connector_value) = {
        let tmp_txid = Txid::from_str(args.update_connector_txid.as_ref().unwrap()).unwrap();
        let tmp_tx = btc_client.get_tx(&tmp_txid).await?.unwrap();
        (
            Some(OutPoint::new(tmp_txid, args.update_connector_vout.unwrap().clone())),
            tmp_tx.output[args.update_connector_vout.unwrap() as usize].value,
        )
    };

    let mut sequencer_set_publish_tx = create_sequencer_update_partial_tx(
        args.commitment.clone(),
        &update_connector,
        &Some(OutPoint { txid: fee_tx.compute_txid(), vout: 0 }),
        next_update_connector_address,
        relayer_fee,
    )?;

    push_sequencer_set_publish_tx(
        &feepayer_p2wpkh,
        &feepayer_private_key,
        &publisher_keys,
        threshold,
        Some(update_connector_value),
        Some(fee_tx.output[0].value),
        &btc_client,
        &mut sequencer_set_publish_tx,
        &redeem_script,
    )
    .await?;

    Ok(())
}

fn create_dummy_publisher_keys(total: u32) -> Vec<(secp256k1::SecretKey, secp256k1::PublicKey)> {
    let secp = Secp256k1::new();

    let mut keys = Vec::new();

    for i in 0..total {
        let sk = SecretKey::from_slice(&[i as u8 + 1; 32]).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        keys.push((sk, pk));
    }
    keys
}

async fn fund_dummy_publishers(
    private_key: &PrivateKey,
    publishers: Vec<secp256k1::SecretKey>,
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

    let fee = Amount::from_sat(1000);
    let to_value = 20000; // each publisher get 2000 sat 

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
    for sk in &publishers {
        let pk = secp256k1::PublicKey::from_secret_key(&secp, sk);
        let address = Address::p2wpkh(&CompressedPublicKey(pk), network);
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

/// `create_fee_tx` create a fee payment tx for `sequencer_update_tx`.
///  
pub(crate) fn create_fee_tx(
    evm_address: &[u8; 20],
    input: &OutPoint,
    input_value: Amount,
    replennish_fee: Amount,
    destination: Address,
    change: Address,
    relayer_fee: Amount,
) -> Result<Transaction, Box<dyn std::error::Error>> {
    let script = Builder::new().push_opcode(OP_RETURN).push_slice(evm_address).into_script();

    let change_value = input_value - replennish_fee - relayer_fee;

    let txin = TxIn {
        previous_output: input.clone(),
        script_sig: ScriptBuf::new(), // empty for P2WSH
        sequence: Sequence::MAX,
        witness: Witness::default(), // to be filled after signing
    };

    let txout_fee = TxOut { value: replennish_fee, script_pubkey: destination.script_pubkey() };

    // make TxOut with 0 satoshis
    let txout_op_return = TxOut { value: Amount::ZERO, script_pubkey: script };

    let txout_change = TxOut { value: change_value, script_pubkey: change.script_pubkey() };

    Ok(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![txin],
        output: vec![txout_fee, txout_op_return, txout_change],
    })
}

pub(crate) fn create_sequencer_update_script(
    public_keys: &[secp256k1::PublicKey],
    threshold: u32,
    total: u32,
) -> ScriptBuf {
    assert!(
        total as usize == public_keys.len(),
        "Total number of public keys must match the length of public_keys"
    );
    assert!(
        threshold <= total,
        "Threshold must be less than or equal to total number of public keys"
    );
    let mut redeem_script = Builder::new().push_int(threshold as i64);
    for pk in public_keys {
        redeem_script = redeem_script.push_slice(&pk.serialize());
    }
    redeem_script.push_int(public_keys.len() as i64).push_opcode(OP_CHECKMULTISIG).into_script()
}

pub(crate) fn create_sequencer_update_partial_tx(
    commitment: [u8; 32],
    update_connector: &Option<OutPoint>,
    replenish_fee_connector: &Option<OutPoint>,
    next_update_connector: Address,
    relayer_fee: Amount,
) -> Result<Transaction, Box<dyn std::error::Error>> {
    let txout_next_connector =
        TxOut { value: relayer_fee, script_pubkey: next_update_connector.script_pubkey() };

    let script = Builder::new().push_opcode(OP_RETURN).push_slice(commitment).into_script();

    // make TxOut with 0 satoshis
    let txout_op_return = TxOut { value: Amount::ZERO, script_pubkey: script };

    let mut input = Vec::new();
    if let Some(uc) = update_connector {
        let txin_connector = TxIn {
            previous_output: uc.clone(),
            script_sig: ScriptBuf::new(), // empty for P2WSH
            sequence: Sequence::MAX,
            witness: Witness::default(), // to be filled after signing
        };
        input.push(txin_connector);
    }
    if let Some(rfc) = replenish_fee_connector {
        let txin_replenish_fee_connector = TxIn {
            previous_output: rfc.clone(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(), // to be filled after signing
        };
        input.push(txin_replenish_fee_connector);
    };

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input,
        output: vec![txout_next_connector, txout_op_return],
    };
    Ok(tx)
}

pub fn sign_partial(
    tx: &mut Transaction,
    seckey: &SecretKey,
    redeem_script: &ScriptBuf,
    amount: Amount,
    sig_hash_type: EcdsaSighashType,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let mut cache = SighashCache::new(tx);
    let sighash = cache.p2wsh_signature_hash(0, &redeem_script, amount, sig_hash_type)?;
    let msg = Message::from_digest_slice(&sighash[..])?;
    let mut sig = secp.sign_ecdsa(&msg, seckey).serialize_der().to_vec();
    sig.push(sig_hash_type as u8);
    Ok(sig)
}

pub fn finalize(
    tx: &mut Transaction,
    sigs: Vec<Vec<u8>>,
    redeem_script: &ScriptBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut wtns = vec![vec![]];
    for i in 0..sigs.len() {
        wtns.push(sigs[i].clone());
    }
    wtns.push(redeem_script.to_bytes()); // the redeem script itself
    tx.input[0].witness = Witness::from(wtns);
    Ok(())
}
