use bitcoin::{key::Keypair, hex::FromHex};
use musig2::{secp256k1::schnorr::Signature, PubNonce, SecNonce};
use sha2::{Sha256, Digest};
use goat::transactions::pre_signed_musig2::get_nonce_message;

pub const PRE_SIGN_NUM: usize = 5;

pub fn generate_keypair_from_seed(seed: String) -> Keypair {
    let keypair_secret = sha256(&format!("{seed}/master"));
    Keypair::from_seckey_str_global(&keypair_secret).unwrap()
}

pub fn generate_nonce_from_seed(seed: String, graph_index: usize, signer_keypair: Keypair) -> [(SecNonce, PubNonce, Signature); PRE_SIGN_NUM] {
    let graph_seed = sha256_with_id(&seed, graph_index);
    let mut res = vec![];
    for i in 0..PRE_SIGN_NUM {
        let nonce_seed = sha256_with_id(&graph_seed, i);
        let nonce_seed = <[u8; 32]>::from_hex(&nonce_seed).unwrap();
        let sec_nonce = SecNonce::build(nonce_seed).build();
        let pub_nonce = sec_nonce.public_nonce();
        let nonce_signature = signer_keypair.sign_schnorr(get_nonce_message(&pub_nonce));
        res.push((sec_nonce, pub_nonce, nonce_signature));
    }
    res.try_into().unwrap()
}

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

