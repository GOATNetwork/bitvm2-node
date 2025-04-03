use bitcoin::TapNodeHash;
use bitcoin::{Address, Amount, Network, PublicKey, XOnlyPublicKey, key::Keypair, PrivateKey};
use bitvm::chunk::api::{
    PublicKeys as ApiWotsPublicKeys, NUM_PUBS, NUM_HASH, NUM_U256, Signatures as ApiWotsSignatures,
};
use bitvm::signatures::signing_winternitz::{WinternitzPublicKey, WinternitzSecret};
use goat::contexts::base::BaseContext;
use goat::contexts::operator::OperatorContext;
use goat::contexts::verifier::VerifierContext;
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
use serde::{Serialize, Deserialize};
use secp256k1::SECP256K1;

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

#[derive(Serialize, Deserialize, Clone)]
pub struct Bitvm2Parameters {
    pub network: Network,
    pub depositor_evm_address: [u8; 20],
    pub pegin_amount: Amount,
    pub stake_amount: Amount,
    pub challenge_amount: Amount,
    pub committee_pubkeys: Vec<PublicKey>,
    pub committee_agg_pubkey: PublicKey,
    pub operator_pubkey: PublicKey,
    // pub operator_wots_pubkeys: WotsPublicKeys,
}

impl Bitvm2Parameters {
    pub fn get_verifier_context(
        &self,
        committee_member_keypair: Keypair,
    ) -> VerifierContext {
        let network = self.network;
        let committee_public_key = self.committee_agg_pubkey;
        let committee_taproot_public_key = XOnlyPublicKey::from(committee_public_key);
        let private_key = PrivateKey::new(committee_member_keypair.secret_key(), network);
        let committee_member_public_key = PublicKey::from_private_key(SECP256K1, &private_key);
        VerifierContext {
            network,
            verifier_keypair: committee_member_keypair,
            verifier_public_key: committee_member_public_key,
            n_of_n_public_keys: self.committee_pubkeys.clone(),
            n_of_n_public_key: committee_public_key,
            n_of_n_taproot_public_key: committee_taproot_public_key,
        }
    }

    pub fn get_operator_context(
        &self,
        operator_keypair: Keypair,
    ) -> OperatorContext {
        let network = self.network;
        let operator_public_key = self.operator_pubkey;
        let operator_taproot_public_key = XOnlyPublicKey::from(operator_public_key);
        let committee_public_key = self.committee_agg_pubkey;
        let committee_taproot_public_key = XOnlyPublicKey::from(committee_public_key);
        OperatorContext {
            network,
            operator_keypair,
            operator_public_key,
            operator_taproot_public_key,
        
            n_of_n_public_keys: self.committee_pubkeys.clone(),
            n_of_n_public_key: committee_public_key,
            n_of_n_taproot_public_key: committee_taproot_public_key,
        }
    }

    pub fn get_base_context(
        &self,
    ) -> BaseBitvmContext {
        let network = self.network;
        let n_of_n_public_keys = self.committee_pubkeys.clone();
        let n_of_n_public_key = self.committee_agg_pubkey;
        let n_of_n_taproot_public_key = XOnlyPublicKey::from(n_of_n_public_key);
        BaseBitvmContext { 
            network, 
            n_of_n_public_keys, 
            n_of_n_public_key, 
            n_of_n_taproot_public_key,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Bitvm2Graph {
    pub(crate) operator_pre_signed: bool,
    pub(crate) committee_pre_signed: bool,
    pub parameters: Bitvm2Parameters,
    pub connector_c_taproot_merkle_root: TapNodeHash,
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

impl Bitvm2Graph {
    pub fn operator_pre_signed(&self) -> bool {
        self.operator_pre_signed
    }
    pub fn committee_pre_signed(&self) -> bool {
        self.committee_pre_signed
    }
}

pub struct CustomInputs {
    pub inputs: Vec<Input>,
    /// stake amount / pegin_amount
    pub input_amount: Amount, 
    pub fee_amount: Amount,
    pub change_address: Address,
}

pub type Error = String;

pub struct BaseBitvmContext {
    pub network: Network,
    pub n_of_n_public_keys: Vec<PublicKey>,
    pub n_of_n_public_key: PublicKey,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,

}

impl BaseContext for BaseBitvmContext {
    fn network(&self) -> Network { self.network }
    fn n_of_n_public_keys(&self) -> &Vec<PublicKey> { &self.n_of_n_public_keys }
    fn n_of_n_public_key(&self) -> &PublicKey { &self.n_of_n_public_key }
    fn n_of_n_taproot_public_key(&self) -> &XOnlyPublicKey { &self.n_of_n_taproot_public_key }
}

