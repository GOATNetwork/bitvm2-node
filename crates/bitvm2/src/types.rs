use bitvm::chunk::api::{
    PublicKeys, NUM_PUBS, NUM_HASH, NUM_U256, Signatures,
};
use bitvm::signatures::signing_winternitz::{WinternitzPublicKey, WinternitzSecret};
use goat::commitments::NUM_KICKOFF;
use rand::{distributions::Alphanumeric, Rng};

pub type VerifyingKey = ark_groth16::VerifyingKey<ark_bn254::Bn254>;
pub type Groth16Proof = ark_groth16::Proof<ark_bn254::Bn254>;
pub type PublicInputs = Vec<ark_bn254::Fr>;

pub type Groth16WotsSignatures = Signatures;

const NUM_SIGS: usize = NUM_PUBS + NUM_HASH + NUM_U256;
pub type KickoffWotsSecretKeys = [WinternitzSecret; NUM_KICKOFF];
pub type Groth16WotsSecretKeys = [String; NUM_SIGS];
pub type WotsSecretKeys = (
    KickoffWotsSecretKeys,
    Groth16WotsSecretKeys,
);

pub type Groth16WotsPublicKeys = PublicKeys;
pub type KickoffWotsPublicKeys = [WinternitzPublicKey; NUM_KICKOFF];
pub type WotsPublicKeys = (
    KickoffWotsPublicKeys,
    Groth16WotsPublicKeys,
);

pub fn random_string(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}
