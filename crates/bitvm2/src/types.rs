use bitcoin::{Address, Amount, Network, PublicKey, XOnlyPublicKey};
use bitvm::chunk::api::{
    PublicKeys as ApiWotsPublicKeys, NUM_PUBS, NUM_HASH, NUM_U256, Signatures as ApiWotsSignatures,
};
use bitvm::signatures::signing_winternitz::{WinternitzPublicKey, WinternitzSecret};
use rand::{distributions::Alphanumeric, Rng};
use goat::commitments::NUM_KICKOFF;
use goat::transactions::{
    base::Input,
    peg_in::peg_in::PegInTransaction,
    peg_out_confirm::PreKickoffTransaction,
    kick_off::KickOffTransaction,
    take_1::Take1Transaction,
    challenge::ChallengeTransaction,
    assert::assert_initial::AssertInitialTransaction,
    assert::assert_commit::AssertCommitTransactionSet,
    assert::assert_final::AssertFinalTransaction,
    take_2::Take2Transaction,
    disprove::DisproveTransaction,
};

pub type VerifyingKey = ark_groth16::VerifyingKey<ark_bn254::Bn254>;
pub type Groth16Proof = ark_groth16::Proof<ark_bn254::Bn254>;
pub type PublicInputs = Vec<ark_bn254::Fr>;

pub type Groth16WotsSignatures = ApiWotsSignatures;

const NUM_SIGS: usize = NUM_PUBS + NUM_HASH + NUM_U256;
pub type KickoffWotsSecretKeys = [WinternitzSecret; NUM_KICKOFF];
pub type Groth16WotsSecretKeys = [String; NUM_SIGS];
pub type WotsSecretKeys = (
    KickoffWotsSecretKeys,
    Groth16WotsSecretKeys,
);

pub type Groth16WotsPublicKeys = ApiWotsPublicKeys;
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

pub struct Bitvm2Parameters {
    pub network: Network,
    pub depositor_evm_address: [u8; 20],
    pub pegin_amount: Amount,
    pub stake_amount: Amount,
    pub challenge_amount: Amount,
    pub committee_taproot_pubkey: XOnlyPublicKey,
    pub operator_pubkey: PublicKey,
    pub operator_wots_pubkeys: WotsPublicKeys,
}

pub struct Bitvm2Graph {
    pub operator_pre_signed: bool,
    pub committee_pre_signed: bool,
    pub parameters: Bitvm2Parameters,
    pub pegin: PegInTransaction,
    pub pre_kickoff: PreKickoffTransaction,
    pub kickoff: KickOffTransaction,
    pub take1: Take1Transaction,
    pub challenge: ChallengeTransaction,
    pub assert_init: AssertInitialTransaction,
    pub assert_commit: AssertCommitTransactionSet,
    pub assert_final: AssertFinalTransaction,
    pub take2: Take2Transaction,
    pub disprove: DisproveTransaction,
}

pub struct CustomInputs {
    pub inputs: Vec<Input>,
    /// stake amount / pegin_amount
    pub input_amount: Amount, 
    pub fee_amount: Amount,
    pub change_address: Address,
}

pub type Error = String;
