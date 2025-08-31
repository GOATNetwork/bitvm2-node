use bitcoin::psbt::Output;
// use store::ipfs::IPFS;
use bitcoin::absolute::LockTime;
use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::script::Builder;
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, Network, OutPoint, PrivateKey, Script, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Txid, Witness, address::NetworkChecked,
};
use bitvm2_noded::client::btc_chain::BTCClient;
use bitvm2_noded::env::get_network;
use bitvm2_noded::{
    env::{ENV_ACTOR, ENV_BITVM_SECRET, IpfsTxName},
    utils::{broadcast_tx, tx_on_chain},
};
use clap::Parser;

use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use goat::commitments;
use secp256k1::{Message, Secp256k1, SecretKey};
use std::str::FromStr;

/// Send kickoff without call initWithdraw on L2, this action should trigger disprove.
#[derive(Parser, Debug)]
#[command(name = "sequencer-set-publish")]
#[command(about = "Publish sequencer set to Bitcoin", long_about = "")]
struct Args {
    #[arg(long)]
    input_txid: String,
    #[arg(long)]
    input_vout: u32,

    #[arg(long)]
    update_connector_txid: String,
    #[arg(long)]
    update_connector_vout: u32,

    #[arg(long, default_value = "")]
    comet_bft_rpc: String,

    #[arg(long, env = "BTC_KEY_WIF")]
    btc_key_wif: Option<String>,

    #[arg(long, env = "GOAT_EVM_ADDRESS")]
    goat_evm_address: String,

    #[arg(long)]
    goat_sequencer_set_publisher_contract_address: String,

    /// Sign the transaction, if `false`, sign and finalize the transaction
    #[arg(long, default_value = "true")]
    sign_only: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let network = get_network();
    let btc_client = BTCClient::new(None, network);
    let seckey = PrivateKey::from_wif(&args.btc_key_wif.unwrap())?.inner;

    // TODO: read public key and threshold from smart contract
    let public_keys: Vec<secp256k1::PublicKey> = vec![];
    let threshold = 3;
    let redeem_script = create_sequencer_update_script(&public_keys, threshold);
    let input_utxo = OutPoint::new(Txid::from_str(&args.input_txid).unwrap(), args.input_vout);
    // TODO
    let replenish_fee = Amount::from_sat(1000);
    let destination = Address::from_str("").unwrap().require_network(network).unwrap();
    let change = Address::from_str("").unwrap().require_network(network).unwrap();

    let evm_address: [u8; 20] = hex::decode(args.goat_evm_address).unwrap().try_into().unwrap();

    let fee_tx =
        create_fee_tx(&evm_address, &input_utxo, replenish_fee, destination.clone(), change)?;

    let commitment = [0u8; 32];
    let update_connector = OutPoint::new(
        Txid::from_str(&args.update_connector_txid).unwrap(),
        args.update_connector_vout,
    );
    let amount = Amount::from_sat(0);

    let next_update_connector = destination;

    let mut sequencer_set_publish_tx = create_sequencer_update_partial_tx(
        commitment,
        &update_connector,
        &OutPoint { txid: fee_tx.compute_txid(), vout: 0 },
        amount.clone(),
        next_update_connector,
    )?;

    let sig = sign_partial(&mut sequencer_set_publish_tx, &seckey, &redeem_script, amount)?;

    println!("Signature: {:?}", hex::encode(sig));
    Ok(())
}

/// `create_fee_tx` create a fee payment tx for `sequencer_update_tx`.
///  
pub(crate) fn create_fee_tx(
    evm_address: &[u8; 20],
    input: &OutPoint,
    replennish_fee: Amount,
    destination: Address,
    change: Address,
) -> Result<Transaction, Box<dyn std::error::Error>> {
    let script = Builder::new()
        .push_opcode(bitcoin::blockdata::opcodes::all::OP_RETURN)
        .push_slice(evm_address)
        .into_script();

    let txin = TxIn {
        previous_output: input.clone(),
        script_sig: ScriptBuf::new(), // empty for P2WSH
        sequence: Sequence::from_consensus(0xffffffff),
        witness: Witness::new(), // to be filled after signing
    };

    let txout_fee = TxOut { value: replennish_fee, script_pubkey: destination.script_pubkey() };

    // make TxOut with 0 satoshis
    let txout_op_return = TxOut { value: Amount::from_sat(0), script_pubkey: script };

    let txout_change = TxOut { value: replennish_fee, script_pubkey: change.script_pubkey() };

    Ok(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![txin],
        output: vec![txout_fee, txout_op_return, txout_change],
    })
}

pub(crate) fn create_sequencer_update_script(
    public_keys: &[secp256k1::PublicKey],
    threshold: u16,
) -> ScriptBuf {
    let mut redeem_script = Builder::new().push_int(threshold as i64);
    for pk in public_keys {
        redeem_script = redeem_script.push_slice(&pk.serialize());
    }
    redeem_script
        .push_int(public_keys.len() as i64)
        .push_opcode(bitcoin::blockdata::opcodes::all::OP_CHECKMULTISIG)
        .into_script()
}

pub(crate) fn create_sequencer_update_partial_tx(
    commitment: [u8; 32],
    update_connector: &OutPoint,
    replenish_fee: &OutPoint,
    amount: Amount,
    next_update_connector: Address,
) -> Result<Transaction, Box<dyn std::error::Error>> {
    let outpoint = OutPoint { txid: update_connector.txid, vout: update_connector.vout };

    let txin_connector = TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::new(), // empty for P2WSH
        sequence: Sequence::from_consensus(0xffffffff),
        witness: Witness::new(), // to be filled after signing
    };
    let txin_replenish_fee = TxIn {
        previous_output: replenish_fee.clone(),
        script_sig: ScriptBuf::new(),
        sequence: Sequence::from_consensus(0xffffffff),
        witness: Witness::new(), // to be filled after signing
    };

    let txout_next_connector =
        TxOut { value: amount, script_pubkey: next_update_connector.script_pubkey() };

    let script = Builder::new()
        .push_opcode(bitcoin::blockdata::opcodes::all::OP_RETURN)
        .push_slice(commitment)
        .into_script();

    // make TxOut with 0 satoshis
    let txout_op_return = TxOut { value: Amount::from_sat(0), script_pubkey: script };

    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![txin_connector, txin_replenish_fee],
        output: vec![txout_next_connector, txout_op_return],
    };
    Ok(tx)
}

pub fn sign_partial(
    tx: &mut Transaction,
    seckey: &SecretKey,
    redeem_script: &ScriptBuf,
    amount: Amount,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let mut cache = SighashCache::new(tx);
    let sighash =
        cache.p2wsh_signature_hash(0, &redeem_script, amount, EcdsaSighashType::All).unwrap();
    let msg = Message::from_digest_slice(&sighash[..]).unwrap();
    let mut sig = secp.sign_ecdsa(&msg, seckey).serialize_der().to_vec();
    sig.push(EcdsaSighashType::AllPlusAnyoneCanPay as u8);
    Ok(sig)
}

pub fn finalize(
    tx: &mut Transaction,
    sigs: Vec<String>,
    redeem_script: &ScriptBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut wtns = vec![vec![]];
    for i in 0..sigs.len() {
        wtns.push(hex::decode(sigs[i].clone())?);
    }
    wtns.push(redeem_script.to_bytes()); // the redeem script itself
    tx.input[0].witness = Witness::from(wtns);
    Ok(())
}
