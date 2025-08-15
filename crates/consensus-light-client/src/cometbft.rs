use base64::Engine;
use base64::engine::general_purpose::STANDARD as b64;
use core::time::Duration;
use cosmos_sdk_proto::cosmos::tx::v1beta1::{TxBody, TxRaw};
use prost::Message;
use sha2::{Digest, Sha256};
use tendermint_light_client_verifier::{
    ProdVerifier, Verdict, Verifier, options::Options, types::LightBlock,
};

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/goat.goat.v1.rs"));
}

fn tmhash(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn leaf_hash(leaf: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(leaf);
    h.finalize().into()
}

fn inner_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

fn split_point(n: usize) -> usize {
    let mut k = 1usize;
    while (k << 1) < n {
        k <<= 1;
    }
    k
}

fn merkle_root(items: &[[u8; 32]]) -> [u8; 32] {
    match items.len() {
        0 => tmhash(&[]),
        1 => leaf_hash(&items[0]),
        n => {
            let k = split_point(n);
            let left = merkle_root(&items[..k]);
            let right = merkle_root(&items[k..]);
            inner_hash(&left, &right)
        }
    }
}

fn data_hash_from_txs_b64(txs_b64: &[String]) -> [u8; 32] {
    let tx_hashes: Vec<[u8; 32]> = txs_b64
        .iter()
        .map(|s| {
            let raw = b64.decode(s).expect("bad base64 tx");
            tmhash(&raw)
        })
        .collect();

    merkle_root(&tx_hashes)
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

pub fn verify_goat_block(
    goat_block_number: u64,
    goat_block_hash: &str,
    txs: &[String],
    light_block: LightBlock,
) {
    let txs_b64 = b64.decode(&txs[0]).unwrap();
    let tx = TxRaw::decode(&*txs_b64).unwrap();
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

    let computed_data_hash = data_hash_from_txs_b64(&txs);
    println!("data hash: {:?}", hex::encode(computed_data_hash));

    assert_eq!(excepted_data_hash.as_bytes(), computed_data_hash,);
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const LB_1_JSON: &str = include_str!("samples/light_block_5756784.json");
    pub const LB_2_JSON: &str = include_str!("samples/light_block_5756785.json");

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

        verify_goat_block(
            5756298,
            "f51b3d69d25631e34b91c0f043bd30deb00c25eb63b4d45a1433fbcb3e9c494a",
            &txs,
            light_block_1,
        );
    }
}
