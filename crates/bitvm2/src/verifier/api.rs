use bitvm::treepp::*;
use bitvm::chunk::api::{validate_assertions, NUM_TAPS};
use crate::types::{
    WotsPublicKeys, VerifyingKey, Groth16WotsSignatures,
};

pub fn verify_proof(
    ark_vkey: &VerifyingKey, 
    proof_sigs: Groth16WotsSignatures,
    disprove_scripts: &[Script;NUM_TAPS], 
    wots_pubkeys: &WotsPublicKeys,
) -> Option<(usize, Script)> {
    validate_assertions(&ark_vkey, proof_sigs, wots_pubkeys.1, disprove_scripts)
}


