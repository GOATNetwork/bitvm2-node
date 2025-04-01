use bitvm::treepp::*;
use bitvm::chunk::api::{
    api_generate_partial_script, api_generate_full_tapscripts,
    generate_signatures_lit,
    NUM_PUBS, NUM_HASH, NUM_U256
};
use bitvm::signatures::{
    wots_api::{wots256, wots_hash},
    signing_winternitz::{
        WinternitzPublicKey, WinternitzSecret, LOG_D,
    },
    winternitz::Parameters, 
};
use goat::commitments::{NUM_KICKOFF, KICKOFF_MSG_SIZE};
use sha2::{Sha256, Digest};
use crate::types::{
    WotsSecretKeys, WotsPublicKeys, Groth16WotsPublicKeys,
    VerifyingKey, Groth16Proof, PublicInputs, Groth16WotsSignatures,
};

pub fn generate_wots_keys(seed: &str) -> (WotsSecretKeys, WotsPublicKeys) {
    let secrets = wots_seed_to_secrets(seed);
    let pubkeys = wots_secrets_to_pubkeys(&secrets);
    (secrets, pubkeys)
}

pub fn wots_secrets_to_pubkeys(secrets: &WotsSecretKeys) -> WotsPublicKeys {
    let mut pubins = vec![];
    for i in 0..NUM_PUBS {
        pubins.push(wots256::generate_public_key(&secrets.1[i]));
    }
    let mut fq_arr = vec![];
    for i in 0..NUM_U256 {
        let p256 = wots256::generate_public_key(&secrets.1[i+NUM_PUBS]);
        fq_arr.push(p256);
    }
    let mut h_arr = vec![];
    for i in 0..NUM_HASH {
        let p160 = wots_hash::generate_public_key(&secrets.1[i+NUM_PUBS+NUM_U256]);
        h_arr.push(p160);
    }
    let g16_wotspubkey: Groth16WotsPublicKeys = (
        pubins.try_into().unwrap(),
        fq_arr.try_into().unwrap(),
        h_arr.try_into().unwrap(),
    );

    let mut kickoff_wotspubkey = vec![];
    for i in 0..NUM_KICKOFF {
        kickoff_wotspubkey.push(WinternitzPublicKey::from(&secrets.0[i]));
    }

    (
        kickoff_wotspubkey.try_into().unwrap_or_else(|_e| panic!("kickoff bitcom key number not match")), 
        g16_wotspubkey,
    )
}

pub fn wots_seed_to_secrets(seed: &str) -> WotsSecretKeys {
    fn sha256(input: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input);
        format!("{:x}", hasher.finalize())
    }
    fn sha256_with_id(input: &str, idx: usize) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input);
        sha256(&format!("{:x}{:04x}", hasher.finalize(), idx))
    }
    
    let seed_hash = sha256(seed);
    let g16_wotsseckey = (0..NUM_PUBS+NUM_U256+NUM_HASH)
        .map(|idx| {
            let sec_i = sha256_with_id(&seed_hash, 1);
            let sec_i = sha256_with_id(&sec_i, idx);
            format!("{sec_i}{:04x}{:04x}", 1, idx)
        })
        .collect::<Vec<String>>()
        .try_into().unwrap();
    
    let kickoff_wotsseckey = (0..NUM_KICKOFF)
        .map(|idx| {
            let sec_i = sha256_with_id(&seed_hash, 0);
            let sec_i = sha256_with_id(&sec_i, idx);
            let sec_str = format!("{sec_i}{:04x}{:04x}", 0, idx);
            let parameters = Parameters::new_by_bit_length(KICKOFF_MSG_SIZE[idx] as u32 * 8, LOG_D);
            WinternitzSecret::from_string(&sec_str, &parameters)
        })
        .collect::<Vec<WinternitzSecret>>()
        .try_into().unwrap_or_else(|_e| panic!("kickoff bitcom key number not match"));
    (kickoff_wotsseckey, g16_wotsseckey)
}

pub fn generate_partial_scripts(ark_vkey: &VerifyingKey) -> Vec<Script> {
    api_generate_partial_script(ark_vkey)
}

pub fn generate_disprove_scripts(partial_scripts: &Vec<Script>, wots_pubkeys: &WotsPublicKeys) -> Vec<Script> {
    api_generate_full_tapscripts(wots_pubkeys.1, partial_scripts)
} 

pub fn sign_proof(ark_vkey: &VerifyingKey, ark_proof: Groth16Proof, ark_pubin: PublicInputs, wots_sec: &WotsSecretKeys) -> Groth16WotsSignatures {
    generate_signatures_lit(ark_proof, ark_pubin, &ark_vkey, wots_sec.1.to_vec()).unwrap()
}

