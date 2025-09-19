use alloy_primitives::hex;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as b64;
use core::time::Duration;
use cosmos_sdk_proto::cosmos::tx::v1beta1::{TxBody, TxRaw};
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::u16;
pub use tendermint_light_client_verifier::{
    ProdVerifier, Verdict, Verifier,
    options::Options,
    types::{LightBlock, ValidatorSet},
};

use bitcoin::{
    Script, ScriptBuf, Transaction, TxOut, Witness,
    key::Keypair,
    secp256k1::{Message as EcdsaMessage, PublicKey, Secp256k1, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, Signature as TaprootSignature, TapLeafHash},
};

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/goat.goat.v1.rs"));
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct CommitInfo {
    pub threshold: u16,
    pub publisher_public_keys: Vec<String>,
    pub txid: String,
}

fn build_dummy_tx() -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    }
}

/// The input proof of the commit chain circuit.
/// The proof can be either None (implying the beginning) or a Succinct proof.
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub enum CommitChainPrevProofType {
    GenesisBlock,
    PrevProof(CommitChainCircuitOutput),
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct CircuitCommit {
    pub commit_txn: Transaction,
    pub sequencer_set_hash: [u8; 32],
    pub publisher_public_keys: Vec<PublicKey>,
    pub threshold: u16,
}

/// The latest seqeuncer set
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct CommitChainState {
    pub block_height: u64,
    pub commit_txn: Transaction,
    pub sequencer_set_hash: [u8; 32],
    pub publisher_public_keys: Vec<PublicKey>,
    pub threshold: u16,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct CommitChainCircuitOutput {
    pub vk_hash: [u32; 8],
    pub chain_state: CommitChainState,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct CommitChainCircuitInput {
    pub vk_hash: [u32; 8],
    pub pv_hash: [u8; 32],
    pub prev_proof: CommitChainPrevProofType,
    pub commits: Vec<CircuitCommit>,
}

impl CommitChainState {
    pub fn new() -> Self {
        CommitChainState {
            block_height: u64::MAX,
            commit_txn: build_dummy_tx(),
            sequencer_set_hash: [0u8; 32],
            publisher_public_keys: vec![],
            threshold: u16::MAX,
        }
    }

    pub fn apply_commit(&mut self, commits: Vec<CircuitCommit>) {
        let mut prev_sequencer_set_hash = self.sequencer_set_hash.clone();
        let mut prev_commit_txn = self.commit_txn.clone();
        let mut prev_publisher_public_keys: Vec<PublicKey> = vec![];
        let mut prev_threshold: u16 = u16::MAX;
        for commit in &commits {
            let latest_commit_txn_with_wtns = &commit.commit_txn;
            println!("commit tx: {:?}", latest_commit_txn_with_wtns.compute_txid());
            let latest_sequencer_set_hash = &commit.sequencer_set_hash;
            let publisher_public_keys = &commit.publisher_public_keys;
            let threshold = commit.threshold;

            let prev_commit_txid = prev_commit_txn.compute_txid();
            println!("prev commit txid: {}, {:?}", prev_commit_txid.to_string(), prev_commit_txn);
            // calculate the commitment of prev sequencer set and check the equivalent
            let expected_prev_commit = extract_op_return_data(&prev_commit_txn);
            println!(
                "expected prev commit: {:?}\n{:?}",
                expected_prev_commit, prev_sequencer_set_hash
            );
            assert_eq!(prev_sequencer_set_hash[..], expected_prev_commit);

            // calculate the commitment of latest sequencer set and check the equivalent
            let expected_latest_commit = extract_op_return_data(&latest_commit_txn_with_wtns);
            assert_eq!(latest_sequencer_set_hash[..], expected_latest_commit);

            // check the latest txn's prev out is equals to the output of prev_txn
            let update_connector = &latest_commit_txn_with_wtns.input[0];
            // FIXME: more graceful way to do this?
            if prev_commit_txid != build_dummy_tx().compute_txid()
                && self.publisher_public_keys.is_empty()
            {
                assert_eq!(update_connector.previous_output.txid, prev_commit_txid);
                assert_eq!(update_connector.previous_output.vout, 0);
                // check the latest publishing txn's signature is signed by prev publishers
                let prevout = &prev_commit_txn.output[0];
                let redeem_script = crate::create_sequencer_update_script(
                    &publisher_public_keys[..],
                    threshold as usize,
                );
                crate::publisher::verify_p2wsh_multisig_witness(
                    &latest_commit_txn_with_wtns,
                    0,
                    prevout,
                    &redeem_script,
                    &publisher_public_keys,
                    threshold as usize,
                )
                .unwrap();
            }

            prev_sequencer_set_hash = latest_sequencer_set_hash.clone();

            // remove witness
            prev_commit_txn = latest_commit_txn_with_wtns.clone();
            prev_commit_txn.input.iter_mut().for_each(|input| {
                input.witness = Witness::new();
            });

            prev_publisher_public_keys = publisher_public_keys.clone();
            prev_threshold = threshold;
        }
        self.sequencer_set_hash = prev_sequencer_set_hash;
        self.commit_txn = prev_commit_txn;
        self.publisher_public_keys = prev_publisher_public_keys;
        self.threshold = prev_threshold;
    }
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
        &Prevouts::All(&[prev_out.clone()]),
        leaf_hash,
        TapSighashType::AllPlusAnyoneCanPay,
    ) {
        Ok(sighash) => sighash,
        _ => return Err("Invalid sig hash".into()),
    };
    let msg = EcdsaMessage::from(sighash);

    Ok(secp.verify_schnorr(&sig.signature, &msg, &internal_xonly)?)
}

pub fn extract_op_return_data(tx: &Transaction) -> Vec<u8> {
    let mut results = Vec::new();
    for output in &tx.output {
        let script = &output.script_pubkey;
        // Parse instructions from the script
        let mut instructions = script.instructions();
        // First instruction should be OP_RETURN
        if let Some(Ok(bitcoin::script::Instruction::Op(op))) = instructions.next() {
            if op == bitcoin::opcodes::all::OP_RETURN {
                // Next should be pushed data
                if let Some(Ok(bitcoin::script::Instruction::PushBytes(data))) = instructions.next()
                {
                    results = data.as_bytes().to_vec();
                }
            }
        }
    }
    if results.len() == 0 {
        results = [0u8; 32].to_vec();
    }
    results
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
        0 => Sha256::digest(&[]).into(),
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
        v => panic!("expected success, got: {:?}", v),
    }
}

/// Verify the last block's validator set's commitment
pub fn verify_validator_set_hash(commitment: [u8; 32], block: LightBlock) {
    let validators = block.validators;
    let code = bincode::serialize(&validators).unwrap();
    let expected_hash = sha2::Sha256::digest(&code);
    assert_eq!(commitment.to_vec(), expected_hash.to_vec());
}

pub fn verify_el_block_from_consensus(
    goat_block_number: u64,
    goat_block_hash: &str,
    txs: &[String],
    light_block: LightBlock,
) {
    let txns_b64 = b64.decode(&txs[0]).unwrap();
    let tx = TxRaw::decode(&*txns_b64).unwrap();
    let tx_body = TxBody::decode(&tx.body_bytes[..]).unwrap();

    // check consistance of GOAT block hash
    tx_body.messages.iter().for_each(|msg| {
        // https://github.com/GOATNetwork/goat/blob/main/proto/goat/goat/v1/tx.proto#L25
        let type_url = msg.type_url.as_str();
        assert_eq!(type_url, "/goat.goat.v1.MsgNewEthBlock");
        let payload = proto::MsgNewEthBlock::decode(&msg.value[..]).unwrap();
        let payload = payload.payload.unwrap();
        // check GOAT block hash and number
        assert_eq!(hex::encode(payload.block_hash), goat_block_hash);
        assert_eq!(payload.block_number, goat_block_number);
    });

    // check data hash
    let excepted_data_hash = light_block.signed_header.header.data_hash.unwrap();
    println!("excepted data hash: {:?}", excepted_data_hash);

    let computed_data_hash = merkle_root_from_base64_txns(&txs);
    println!("data hash: {:?}", hex::encode(computed_data_hash));

    assert_eq!(excepted_data_hash.as_bytes(), computed_data_hash,);
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
        let txs = [
          "CqAFCpgFChwvZ29hdC5nb2F0LnYxLk1zZ05ld0V0aEJsb2NrEvcECitnb2F0MTgycXRqYXkzYWE3d21keHQ1ZTdzbHIwcDM1M2pxem1lcTgwZ3psEscECiD6E/2JfdnZ272/jl2Nd8NBHtfbvn4SiGhu7S/9jsmakRIUOoC5dJHvfO20y6Z9D43hjSMgC3kaIOJPdlDlbeg71hluZ09uOMvwxZuqP15KuhtAHyq6VC4HIiBW6B8XG8xVpv+DReaSwPhuW0jgG5lsrcABYi+142O0ISqAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAyIIRREr2RSzJRaTI6ozeR7i1QBpY4dgtz1RV3rPL9plraOIqr3wJAgIenDlDzvfzEBlohAFboHxcbzFWm/4NF5pLA+G5bSOAbmWytwAFiL7XjY7QhYgE3aiD1Gz1p0lYx40uRwPBDvTDesAwl62O01FoUM/vLPpxJSnogWN8swwiadFH3kYI0wChXf1ycHI/5sH9gaxyExyJ2TO/CASkAitVXAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABjwrt8CElsKUgpGCh8vY29zbW9zLmNyeXB0by5zZWNwMjU2azEuUHViS2V5EiMKIQNXXvEYcWJhQUIc6Y5NyPYyqg2YX1wGfKWOLUGCTCyryRIECgIIARjsyEESBRCAwtcvGkC5ghb4xi1rS8d9+AhRHjFPbaVxYRtSOD5WqPKFNimDHzruhgeScjLbcTeOfmfbpEK602jZdhWXF1aREHcplEU5".to_string()
        ];

        // loght block 5756784
        let light_block_1 = serde_json::from_str::<LightBlock>(LB_1_JSON).unwrap();

        verify_el_block_from_consensus(
            5756298,
            "f51b3d69d25631e34b91c0f043bd30deb00c25eb63b4d45a1433fbcb3e9c494a",
            &txs,
            light_block_1,
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
