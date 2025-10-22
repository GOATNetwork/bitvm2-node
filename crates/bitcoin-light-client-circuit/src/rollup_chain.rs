use alloy_primitives::hex;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as b64;
use core::time::Duration;
use cosmos_sdk_proto::cosmos::tx::v1beta1::{TxBody, TxRaw};
use prost::Message;
use sha2::{Digest, Sha256};
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

use crate::proto::ExecutionPayload;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/goat.goat.v1.rs"));
}

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

fn merkle_leaf_hash(leaf: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(leaf);
    h.finalize().into()
}

fn merkle_inner_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

fn largest_power_of_two_less_than(n: usize) -> usize {
    let mut k = 1usize;
    while (k << 1) < n {
        k <<= 1;
    }
    k
}

fn compute_merkle_root(items: &[[u8; 32]]) -> [u8; 32] {
    match items.len() {
        0 => Sha256::digest([]).into(),
        1 => merkle_leaf_hash(&items[0]),
        n => {
            let k = largest_power_of_two_less_than(n);
            let left = compute_merkle_root(&items[..k]);
            let right = compute_merkle_root(&items[k..]);
            merkle_inner_node_hash(&left, &right)
        }
    }
}

fn merkle_root_from_base64_txns(txns_b64: &[String]) -> [u8; 32] {
    let tx_hashes: Vec<[u8; 32]> = txns_b64
        .iter()
        .map(|s| {
            let raw = b64.decode(s).expect("bad base64 tx");
            Sha256::digest(&raw).into()
        })
        .collect();

    compute_merkle_root(&tx_hashes)
}

/// Verify consensus blocks
pub fn verify_validator_set(light_block_1: LightBlock, light_block_2: LightBlock) {
    // Normally we could just do this to read in the LightBlocks, but bincode doesn't work with
    // LightBlock. This is likely a bug in tendermint-rs.
    // let light_block_1 = zkm_zkvm::io::read::<LightBlock>();
    // let light_block_2 = zkm_zkvm::io::read::<LightBlock>();

    println!("LightBlock1 number of validators: {}", light_block_1.validators.validators().len());
    println!("LightBlock2 number of validators: {}", light_block_2.validators.validators().len());

    // println!("cycle-tracker-start: header hash");
    // let header_hash_1 = light_block_1.signed_header.header.hash();
    // let header_hash_2 = light_block_2.signed_header.header.hash();
    // println!("cycle-tracker-end: header hash");

    // println!("cycle-tracker-start: public input headers");
    // zkm_zkvm::io::commit_slice(header_hash_1.as_bytes());
    // zkm_zkvm::io::commit_slice(header_hash_2.as_bytes());
    // println!("cycle-tracker-end: public input headers");

    println!("cycle-tracker-start: hash committee");
    assert_eq!(
        light_block_1.next_validators.hash(),
        light_block_1.as_trusted_state().next_validators_hash
    );
    println!("cycle-tracker-end: hash committee");

    println!("cycle-tracker-start: verify");
    let vp = ProdVerifier::default();
    let opt = Options {
        trust_threshold: Default::default(),
        trusting_period: Duration::from_secs(500),
        clock_drift: Default::default(),
    };
    let verify_time = light_block_2.time() + Duration::from_secs(20);
    let verdict = vp.verify_update_header(
        light_block_2.as_untrusted_state(),
        light_block_1.as_trusted_state(),
        &opt,
        verify_time.unwrap(),
    );
    println!("cycle-tracker-end: verify");

    // println!("cycle-tracker-start: public inputs verdict");
    // let verdict_encoded = serde_cbor::to_vec(&verdict).unwrap();
    // zkm_zkvm::io::commit_slice(verdict_encoded.as_slice());
    // println!("cycle-tracker-end: public inputs verdict");

    match verdict {
        Verdict::Success => {
            println!("success");
        }
        v => panic!("expected success, got: {v:?}"),
    }
}

/// Verify the last block's validator set's commitment
pub fn verify_validator_set_hash(commitment: [u8; 32], block: LightBlock) {
    let validators = block.validators;
    let code = bincode::serialize(&validators).unwrap();
    let expected_hash = sha2::Sha256::digest(&code);
    assert_eq!(commitment.to_vec(), expected_hash.to_vec());
}

// we can not move it to commit-chain-rpc since it'll get non-std involved.
pub fn parse_cosmos_payload(tx_b64: &str) -> Option<ExecutionPayload> {
    let txns_b64 = b64.decode(tx_b64).unwrap();
    let tx = TxRaw::decode(&*txns_b64).unwrap();
    let tx_body = TxBody::decode(&tx.body_bytes[..]).unwrap();

    // check consistance of GOAT block hash
    if !tx_body.messages.is_empty() {
        let first_message = &tx_body.messages[0];
        // https://github.com/GOATNetwork/goat/blob/main/proto/goat/goat/v1/tx.proto#L25
        let type_url = first_message.type_url.as_str();
        assert_eq!(type_url, "/goat.goat.v1.MsgNewEthBlock");
        let payload = proto::MsgNewEthBlock::decode(&first_message.value[..]).unwrap();
        let payload = payload.payload.unwrap();
        // check GOAT block hash and number
        println!("hash: {}, {}", hex::encode(&payload.block_hash), &payload.block_number);
        // FIXME: do the hash check
        // assert_eq!(hex::encode(payload.block_hash), goat_block_hash);
        return Some(payload);
    };
    None
}

pub fn verify_el_block_from_consensus(
    goat_block_number: u64,
    _goat_block_hash: &str,
    txs: &[String],
    actual_data_hash: [u8; 32],
) {
    if let Some(payload) = parse_cosmos_payload(&txs[0]) {
        assert_eq!(payload.block_number, goat_block_number);
    }

    // check data hash
    //let excepted_data_hash = light_block.signed_header.header.data_hash.unwrap();
    //println!("excepted data hash: {:?}", excepted_data_hash);

    let computed_data_hash = merkle_root_from_base64_txns(txs);
    println!("data hash: {:?}", hex::encode(computed_data_hash));

    assert_eq!(actual_data_hash, computed_data_hash);
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

    pub const LB_1_JSON: &str = include_str!("../samples/light_block_5756784.json");
    pub const LB_2_JSON: &str = include_str!("../samples/light_block_5756785.json");

    pub const LB_1_JSON_TXNS: &str = include_str!("../samples/light_block_5756784.json.txns");
    pub const LB_2_JSON_TXNS: &str = include_str!("../samples/light_block_5756785.json.txns");

    #[test]
    pub fn test_verify_validator_set() {
        let light_block_1 = serde_json::from_str::<LightBlock>(LB_1_JSON).unwrap();
        let light_block_2 = serde_json::from_str::<LightBlock>(LB_2_JSON).unwrap();
        verify_validator_set(light_block_1, light_block_2.clone());

        let hash = [
            18, 247, 168, 227, 210, 80, 16, 178, 3, 220, 54, 235, 129, 28, 126, 13, 58, 194, 168,
            218, 165, 61, 79, 106, 31, 128, 1, 8, 181, 199, 39, 44,
        ];
        verify_validator_set_hash(hash, light_block_2);
    }

    #[test]
    pub fn test_verify_goat_block() {
        // curl "http://127.0.0.1:26657/block?height=5756784" | jq .result.block.data
        let consensus_txns: Vec<String> = serde_json::from_str(&LB_1_JSON_TXNS).unwrap();
        // loght block 5756784
        let light_block_1 = serde_json::from_str::<LightBlock>(LB_1_JSON).unwrap();

        verify_el_block_from_consensus(
            5756298,
            "f51b3d69d25631e34b91c0f043bd30deb00c25eb63b4d45a1433fbcb3e9c494a",
            &consensus_txns,
            light_block_1.signed_header.header.data_hash.unwrap().as_bytes().try_into().unwrap(),
        );

        //
        let light_block_2 = serde_json::from_str::<LightBlock>(LB_2_JSON).unwrap();
        // curl "http://127.0.0.1:26657/block?height=5756785" | jq .result.block.data
        let consensus_txns: Vec<String> = serde_json::from_str(&LB_2_JSON_TXNS).unwrap();
        verify_el_block_from_consensus(
            5756299,
            "56473094ffd5bc070446fdbaaf2b443b9beffb82dded0e053eb6b25c7d60be0b",
            &consensus_txns,
            light_block_2.signed_header.header.data_hash.unwrap().as_bytes().try_into().unwrap(),
        );
    }

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
                script_pubkey: ScriptBuf::new_op_return(&[0x6a]),
            }],
        };

        // 6. Generate Schnorr signature
        let sig = generate_taproot_leaf_schnorr_signature(
            &mut spending_tx,
            &[prev_out.clone()],
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
