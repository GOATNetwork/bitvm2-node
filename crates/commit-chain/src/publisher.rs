use std::error::Error;

use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::script::Builder;
use bitcoin::{Amount, ScriptBuf, Transaction, TxOut, Witness};

use bitcoin::secp256k1::{
    Message, PublicKey, Secp256k1, SecretKey, ecdsa::Signature as EcdsaSignature,
};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};

pub fn create_sequencer_update_script(public_keys: &[PublicKey], threshold: usize) -> ScriptBuf {
    let total = public_keys.len();
    println!("Multi sig: {threshold} of {total}");
    assert!(
        threshold <= total,
        "Threshold must be less than or equal to total number of public keys"
    );
    let mut redeem_script = Builder::new().push_int(threshold as i64);
    for pk in public_keys {
        redeem_script = redeem_script.push_slice(pk.serialize());
    }
    redeem_script.push_int(public_keys.len() as i64).push_opcode(OP_CHECKMULTISIG).into_script()
}

pub fn sign_partial(
    tx: &mut Transaction,
    seckey: &SecretKey,
    redeem_script: &ScriptBuf,
    amount: Amount,
    sig_hash_type: EcdsaSighashType,
) -> Result<(Vec<u8>, bitcoin::secp256k1::Message), Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let mut cache = SighashCache::new(tx);
    let sighash = cache.p2wsh_signature_hash(0, redeem_script, amount, sig_hash_type)?;
    let msg = Message::from_digest_slice(&sighash[..])?;
    let mut sig = secp.sign_ecdsa(&msg, seckey).serialize_der().to_vec();
    sig.push(sig_hash_type as u8);
    Ok((sig, msg))
}

pub fn finalize(
    tx: &mut Transaction,
    sigs: Vec<Vec<u8>>,
    redeem_script: &ScriptBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut wtns = vec![vec![]];
    for sig in &sigs {
        wtns.push(sig.clone());
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
        .collect();

    if raw_sigs.is_empty() {
        return Ok(false); // no signatures provided
    }

    // Parse each signature: DER (r,s) + 1-byte sighash flag.
    // We'll keep a vec of (sig, sighash_flag) for verification.
    let mut parsed_sigs: Vec<(EcdsaSignature, EcdsaSighashType)> =
        Vec::with_capacity(raw_sigs.len());
    for (i, raw) in raw_sigs.iter().enumerate() {
        if raw.is_empty() {
            return Err(format!("signature[{i}] too short").into());
        }
        let flag = raw[raw.len() - 1];
        let sighash_ty = EcdsaSighashType::from_consensus(flag as u32);
        let der = &raw[..raw.len() - 1];
        let sig = EcdsaSignature::from_der(der)
            .map_err(|e| format!("invalid DER signature at index {i}: {e:?}"))?;
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
            .map_err(|e| format!("bad message from sighash: {e:?}"))?;

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
