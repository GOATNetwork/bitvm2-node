use bitcoin::PublicKey;
// use store::ipfs::IPFS;
use bitvm2_noded::client::btc_chain::BTCClient;
use bitvm2_noded::{
    env::{ENV_ACTOR, ENV_BITVM_SECRET, IpfsTxName},
    utils::{broadcast_tx, tx_on_chain},
};
use clap::Parser;
use bitcoin::absolute::LockTime;
use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::script::Builder;
use bitcoin::transaction::Version;
use bitcoin::{
    address::NetworkChecked, Address, Amount, Network, OutPoint, PrivateKey, Script, ScriptBuf,
    Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};

use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use std::str::FromStr;
use bitcoin::sighash::{SighashCache, EcdsaSighashType};

/// Send kickoff without call initWithdraw on L2, this action should trigger disprove.
#[derive(Parser, Debug)]
#[command(name = "sequencer-set-publish")]
#[command(
    about = "Publish sequencer set to Bitcoin",
    long_about = ""
)]
struct Args {
    /// graph id
    #[arg(long)]
    graph: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let network = Network::Testnet;
    let btc_client = BTCClient::new(None, network);
}

/// `create_fee_tx` create a fee payment tx for `sequencer_update_tx`.
///  
pub (crate) fn create_fee_tx(l2_address: &str, ) -> Result<Transaction, Box<dyn std::error::Error>> {
    todo!()
}

pub(crate) fn create_sequencer_update_script(public_keys: &[secp256k1::PublicKey], threshold: u16) -> ScriptBuf {
    let mut redeem_script = Builder::new()
        .push_int(threshold as i64);
    for pk in public_keys {
        redeem_script = redeem_script.push_slice(&pk.serialize());
    }
    redeem_script.push_int(public_keys.len() as i64) 
        .push_opcode(bitcoin::blockdata::opcodes::all::OP_CHECKMULTISIG)
        .into_script()
}

pub(crate) fn create_sequencer_update_partial_tx(commitment: [u8; 32], update_connector: &OutPoint, amount: Amount, next_update_connector: Address) -> Result<Transaction, Box<dyn std::error::Error>> {
    let mut tx = build_spending_tx(
        update_connector.txid,
        update_connector.vout,
        next_update_connector,
        amount - Amount::from_sat(146),
    );

    // // Sign manually (2-of-3)
    // let mut cache = SighashCache::new(&mut tx);
    // let sighash = cache.p2wsh_signature_hash(0, &redeem_script, utxo.amount, EcdsaSighashType::All).unwrap();
    // let msg = Message::from_digest_slice(&sighash[..]).unwrap();
    // let sig = secp.sign_ecdsa(&msg, &seckey1);
    // let mut sig1 = sig.serialize_der().to_vec();
    // sig1.push(EcdsaSighashType::All as u8);
    // let sig = secp.sign_ecdsa(&msg, &seckey2);
    // let mut sig2 = sig.serialize_der().to_vec();
    // sig2.push(EcdsaSighashType::All as u8);

    // tx.input[0].witness = Witness::from(vec![
    //     vec![],
    //     sig1,
    //     sig2,
    //     redeem_script.to_bytes(), // the redeem script itself
    // ]);

    Ok(tx)
}

fn build_spending_tx(
    input_txid: Txid,
    input_vout: u32,
    destination: Address,
    amount_sat: Amount,
) -> Transaction {
    let outpoint = OutPoint {
        txid: input_txid,
        vout: input_vout,
    };

    let txin = TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::new(), // empty for P2WSH
        sequence: Sequence::from_consensus(0xffffffff),
        witness: Witness::new(), // to be filled after signing
    };

    let txout = TxOut {
        value: amount_sat,
        script_pubkey: destination.script_pubkey(),
    };

    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![txin],
        output: vec![txout],
    }
}