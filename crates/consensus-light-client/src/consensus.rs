use core::time::Duration;
use tendermint_light_client_verifier::{
    options::Options, types::LightBlock, ProdVerifier, Verdict, Verifier
};
use sha2::Digest;

/// Verify consensus blocks
pub fn verify_blocks(light_block_1: LightBlock, light_block_2: LightBlock) {
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

#[cfg(test)]
mod tests {
    use super::*;

    pub const LB_1_JSON: &str = include_str!("samples/light_block_1.json");
    pub const LB_2_JSON: &str = include_str!("samples/light_block_2.json");

    #[test]
    pub fn test_verify_block() {
        let light_block_1 = serde_json::from_str::<LightBlock>(LB_1_JSON).unwrap();
        let light_block_2 = serde_json::from_str::<LightBlock>(LB_2_JSON).unwrap();
        verify_blocks(light_block_1, light_block_2.clone());

        let hash = [18, 247, 168, 227, 210, 80, 16, 178, 3, 220, 54, 235, 129, 28, 126, 13, 58, 194, 168, 218, 165, 61, 79, 106, 31, 128, 1, 8, 181, 199, 39, 44]; 
        verify_validator_set_hash(hash, light_block_2);
    }
}