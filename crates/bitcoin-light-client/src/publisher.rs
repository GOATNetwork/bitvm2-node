use std::error::Error;

use bitcoin::absolute::LockTime;
use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::script::Builder;
use bitcoin::transaction::Version;
use bitcoin::{Address, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use hex::FromHex;

use bitcoin::secp256k1::{
    Message, PublicKey, Secp256k1, SecretKey, ecdsa::Signature as EcdsaSignature,
};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};

pub fn decode_eth_address(addr: &str) -> Result<[u8; 20], hex::FromHexError> {
    // Strip 0x if it exists
    let addr = addr.strip_prefix("0x").unwrap_or(addr);
    // Decode into Vec<u8>
    let bytes = Vec::from_hex(addr)?;

    // Ensure it's 20 bytes
    let arr: [u8; 20] = bytes.try_into().expect("Ethereum address must be 20 bytes");
    Ok(arr)
}

// return [0u8; 32] from hex string if s is empty
pub fn parse_commitment(s: &str) -> Result<[u8; 32], String> {
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

pub fn create_dummy_publisher_keys(total: usize) -> Vec<(SecretKey, PublicKey)> {
    let secp = Secp256k1::new();

    let mut keys = Vec::new();

    for i in 0..total {
        let sk = SecretKey::from_slice(&[i as u8 + 1; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        keys.push((sk, pk));
    }
    println!("Publisher public key:");
    keys.iter().for_each(|(_, pk)| println!("{}\n", pk.to_string()));
    keys
}

/// `create_fee_tx` create a fee payment tx for `sequencer_update_tx`.
///  
pub fn create_fee_tx(
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

pub fn create_sequencer_update_script(public_keys: &[PublicKey], threshold: u16) -> ScriptBuf {
    let total = public_keys.len();
    assert!(
        threshold as usize <= total,
        "Threshold must be less than or equal to total number of public keys"
    );
    let mut redeem_script = Builder::new().push_int(threshold as i64);
    for pk in public_keys {
        redeem_script = redeem_script.push_slice(&pk.serialize());
    }
    redeem_script.push_int(public_keys.len() as i64).push_opcode(OP_CHECKMULTISIG).into_script()
}

pub fn create_sequencer_update_partial_tx(
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

/// Verify P2WSH multisig witness (CHECKMULTISIG behavior).
/// - `tx` is the spending transaction
/// - `input_index` is the input to verify
/// - `prevout` is the TxOut being spent (needed for amount + script_pubkey)
/// - `redeem_script` is the script that must equal the last witness element
/// - `pubkeys` is the n pubkeys in the redeem script in script order
/// - `threshold` is m (required signatures)
pub fn verify_p2wsh_multisig_witness(
    tx: &Transaction,
    input_index: usize,
    prevout: &TxOut,
    redeem_script: &ScriptBuf,
    pubkeys: &[PublicKey],
    threshold: usize,
) -> Result<bool, Box<dyn Error>> {
    // Basic checks
    let secp = Secp256k1::verification_only();
    let txin = &tx.input[input_index];
    let witness: &Witness = &txin.witness;

    // Expect witness: [<empty>, sig1, sig2, ..., redeem_script_bytes]
    if witness.len() < 2 {
        return Err("witness too short".into());
    }

    // Last stack item must equal redeem_script
    let last: &[u8] = &witness[witness.len() - 1];
    if last != redeem_script.as_bytes() {
        return Err("redeem_script mismatch with witness last element".into());
    }

    // Extract signatures (skip first dummy element, skip last redeem_script)
    let raw_sigs: Vec<&[u8]> = witness
        .iter()
        .skip(1)
        .take(witness.len() - 2) // exclude last (redeem_script)
        .map(|v| v)
        .collect();

    if raw_sigs.is_empty() {
        return Ok(false); // no signatures provided
    }

    // Parse each signature: DER (r,s) + 1-byte sighash flag.
    // We'll keep a vec of (sig, sighash_flag) for verification.
    let mut parsed_sigs: Vec<(EcdsaSignature, EcdsaSighashType)> =
        Vec::with_capacity(raw_sigs.len());
    for (i, raw) in raw_sigs.iter().enumerate() {
        if raw.len() < 1 {
            return Err(format!("signature[{}] too short", i).into());
        }
        let flag = raw[raw.len() - 1];
        let sighash_ty = EcdsaSighashType::from_consensus(flag as u32);
        let der = &raw[..raw.len() - 1];
        let sig = EcdsaSignature::from_der(der)
            .map_err(|e| format!("invalid DER signature at index {}: {}", i, e))?;
        parsed_sigs.push((sig, sighash_ty));
    }

    // We'll need to compute sighash per signature (it depends on sighash flag).
    // Use a SighashCache on the tx. For P2WSH we call p2wsh_signature_hash.
    let mut cache = SighashCache::new(tx);

    // Now implement CHECKMULTISIG matching:
    // iterate pubkeys in order, and try to match the *current* signature.
    let mut sig_idx = 0usize;
    let mut matched = 0usize;

    for pk in pubkeys.iter() {
        if sig_idx >= parsed_sigs.len() {
            break; // no more signatures to match
        }

        // For the current signature, compute the sighash according to its flag.
        let (ref sig, sighash_ty) = parsed_sigs[sig_idx];

        // Compute the p2wsh sighash for this signature (signature's own sighash type)
        let sighash =
            cache.p2wsh_signature_hash(input_index, redeem_script, prevout.value, sighash_ty)?;

        let msg = Message::from_digest_slice(&sighash[..])
            .map_err(|e| format!("bad message from sighash: {}", e))?;

        // Try verify current signature against this pubkey
        match secp.verify_ecdsa(&msg, sig, pk) {
            Ok(_) => {
                // matched: consume this signature and advance
                matched += 1;
                sig_idx += 1;
                if matched >= threshold {
                    break;
                }
            }
            Err(_) => {
                // no match: try next pubkey (do NOT advance sig_idx)
                continue;
            }
        }
    }

    Ok(matched >= threshold)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Network, hashes::Hash};

    #[test]
    fn test_verify_p2wsh_multisig_witness() {
        // === Step 1: generate key pairs ===
        let keys = create_dummy_publisher_keys(3);
        let pubkeys: Vec<PublicKey> = keys.iter().map(|(_, pk)| *pk).collect();

        let threshold = 2;

        // === Step 2: create redeem_script ===
        let redeem_script = create_sequencer_update_script(&pubkeys, threshold);

        // === Step 3: create prevout (P2WSH output) ===
        let script_pubkey = ScriptBuf::new_p2wsh(&redeem_script.wscript_hash());
        let prev_value = Amount::from_sat(100_000);
        let prevout = TxOut { value: prev_value, script_pubkey };

        // Fake OutPoint
        let prev_outpoint =
            OutPoint { txid: bitcoin::Txid::from_byte_array([0u8; 32].into()), vout: 0 };

        // === Step 4: construct spending tx ===
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: prev_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(99_000),
                script_pubkey: {
                    let btc_pk0 = bitcoin::PublicKey::from(pubkeys[0]);
                    Address::p2pkh(&btc_pk0, Network::Testnet).script_pubkey()
                },
            }],
        };

        // === Step 5: sign by 2 private keys ===
        let sig1 =
            sign_partial(&mut tx, &keys[0].0, &redeem_script, prev_value, EcdsaSighashType::All)
                .unwrap();

        let sig2 =
            sign_partial(&mut tx, &keys[1].0, &redeem_script, prev_value, EcdsaSighashType::All)
                .unwrap();

        // === Step 6: finalize witness ===
        finalize(&mut tx, vec![sig1, sig2], &redeem_script).unwrap();

        // === Step 7: verify ===
        let ok = verify_p2wsh_multisig_witness(
            &tx,
            0,
            &prevout,
            &redeem_script,
            &pubkeys,
            threshold as usize,
        )
        .unwrap();

        assert!(ok, "2-of-3 multisig witness should verify");
    }
}
