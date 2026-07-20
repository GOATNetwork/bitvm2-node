pub use tendermint_light_client_verifier::{
    ProdVerifier, Verdict, Verifier,
    options::Options,
    types::{Header, LightBlock, ValidatorSet},
};

use bitcoin::{
    Script, ScriptBuf, Transaction, TxOut,
    key::Keypair,
    secp256k1::{Message as EcdsaMessage, PublicKey, Secp256k1, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, Signature as TaprootSignature, TapLeafHash},
};

/// Generate Taproot script-path's Schnorr signature
#[allow(dead_code)]
fn generate_taproot_leaf_schnorr_signature(
    tx: &mut Transaction,
    prev_outs: &[TxOut],
    input_index: usize,
    sighash_type: TapSighashType,
    script: &Script,
    keypair: &Keypair,
) -> TaprootSignature {
    let leaf_hash = TapLeafHash::from_script(script, LeafVersion::TapScript);
    let secp = Secp256k1::new();

    let sighash = SighashCache::new(tx)
        .taproot_script_spend_signature_hash(
            input_index,
            &Prevouts::All(prev_outs),
            leaf_hash,
            sighash_type,
        )
        .expect("Failed to construct sighash");

    let msg = EcdsaMessage::from(sighash);
    let sig = secp.sign_schnorr_no_aux_rand(&msg, keypair);

    TaprootSignature { signature: sig, sighash_type }
}

/// Verify Schnorr signature
///
pub fn verify_taproot_leaf_schnorr_signature(
    script: &ScriptBuf,
    spending_tx: &Transaction,
    prev_index: usize,
    prev_out: &TxOut,
    pubkey: &PublicKey,
    sig: &TaprootSignature,
) -> Result<(), Box<dyn std::error::Error>> {
    if sig.sighash_type != TapSighashType::AllPlusAnyoneCanPay {
        return Err("Invalid sig type".into());
    }
    let secp = Secp256k1::verification_only();
    let leaf_hash = TapLeafHash::from_script(script, LeafVersion::TapScript);
    let internal_xonly: XOnlyPublicKey = (*pubkey).into();
    let sighash = match SighashCache::new(spending_tx).taproot_script_spend_signature_hash(
        0,
        //&Prevouts::All(&[prev_out.clone()]),
        &Prevouts::One(prev_index, prev_out.clone()),
        leaf_hash,
        TapSighashType::AllPlusAnyoneCanPay,
    ) {
        Ok(sighash) => sighash,
        _ => return Err("Invalid sig hash".into()),
    };
    let msg = EcdsaMessage::from(sighash);

    Ok(secp.verify_schnorr(&sig.signature, &msg, &internal_xonly)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoin::{
        Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        blockdata::script::Builder,
        consensus::encode::serialize,
        key::Keypair,
        secp256k1::{Secp256k1, XOnlyPublicKey},
        sighash::TapSighashType,
        taproot::{LeafVersion, TaprootBuilder},
    };
    use bitcoin::{ScriptBuf, hashes::Hash};
    use rand::rngs::OsRng;

    #[test]
    fn test_taproot_script_path_end_to_end_with_verification() {
        let secp = Secp256k1::new();
        let keypair = Keypair::new(&secp, &mut OsRng);
        let (internal_xonly, _) = XOnlyPublicKey::from_keypair(&keypair);

        // 2. Create Tapscript: <pubkey> OP_CHECKSIG
        let script = Builder::new()
            .push_x_only_key(&internal_xonly)
            .push_opcode(bitcoin::blockdata::opcodes::all::OP_CHECKSIG)
            .into_script();

        // 3. Construct Taproot (script path)
        let builder = TaprootBuilder::new().add_leaf(0, script.clone()).expect("taproot builder");
        let taproot_info = builder.finalize(&secp, internal_xonly).expect("finalize taproot");
        let output_key = taproot_info.output_key();

        // 4. Construct prevout (UTXO)
        let prev_txid = Txid::from_byte_array([1u8; 32]); // fake txid
        let prev_vout = 0;
        let prev_value = Amount::from_sat(50_000);

        let prev_out = TxOut {
            value: prev_value,
            script_pubkey: bitcoin::Address::p2tr_tweaked(output_key, bitcoin::Network::Testnet)
                .script_pubkey(),
        };

        // 5. Create the spending txn
        let mut spending_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: prev_txid, vout: prev_vout },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::new_op_return([0x6a]),
            }],
        };

        // 6. Generate Schnorr signature
        let sig = generate_taproot_leaf_schnorr_signature(
            &mut spending_tx,
            std::slice::from_ref(&prev_out),
            0,
            TapSighashType::AllPlusAnyoneCanPay,
            &script,
            &keypair,
        );

        // 7. Verify the signature
        verify_taproot_leaf_schnorr_signature(
            &script,
            &spending_tx,
            0,
            &prev_out,
            &keypair.public_key(),
            &sig,
        )
        .unwrap();
        println!("Schnorr signature verified successfully!");

        // 8. Construct control block + witness
        let control_block = taproot_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("control block");

        spending_tx.input[0].witness =
            Witness::from(vec![sig.to_vec(), script.into_bytes(), control_block.serialize()]);

        println!("Final spending tx hex = {}", hex::encode(serialize(&spending_tx)));
    }
}
