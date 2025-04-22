use super::{
    committee::{generate_keypair_from_seed, generate_nonce_from_seed, COMMITTEE_PRE_SIGN_NUM},
    operator::generate_wots_keys,
    types::{WotsPublicKeys, WotsSecretKeys},
};
use bitcoin::key::Keypair;
use musig2::{secp256k1::schnorr::Signature, PubNonce, SecNonce};
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn derive_secret(master_key: &Keypair, domain: &Vec<u8>) -> String {
    let secret_key = master_key.secret_key();
    let mut hasher = Sha256::new();
    hasher.update(secret_key.secret_bytes());
    hasher.update(domain);
    format!("{:x}", hasher.finalize())
}

pub struct NodeMasterKey(Keypair);
impl NodeMasterKey {
    pub fn new(inner: Keypair) -> Self {
        NodeMasterKey(inner)
    }
    pub fn master_keypair(&self) -> Keypair {
        self.0
    }
}

pub struct CommitteeMasterKey(Keypair);
impl CommitteeMasterKey {
    pub fn new(inner: Keypair) -> Self {
        CommitteeMasterKey(inner)
    }
    pub fn master_keypair(&self) -> Keypair {
        NodeMasterKey(self.0).master_keypair()
    }
    pub fn keypair_for_instance(&self, instance_id: Uuid) -> Keypair {
        let domain =
            vec![b"committee_bitvm_key".to_vec(), instance_id.as_bytes().to_vec()].concat();
        let instance_seed = derive_secret(&self.0, &domain);
        generate_keypair_from_seed(instance_seed)
    }
    pub fn nonces_for_graph(
        &self,
        instance_id: Uuid,
        graph_id: Uuid,
    ) -> [(SecNonce, PubNonce, Signature); COMMITTEE_PRE_SIGN_NUM] {
        let domain = vec![
            b"committee_bitvm_nonces".to_vec(),
            instance_id.as_bytes().to_vec(),
            graph_id.as_bytes().to_vec(),
        ]
        .concat();
        let nonce_seed = derive_secret(&self.0, &domain);
        let signer_keypair = self.keypair_for_instance(instance_id);
        generate_nonce_from_seed(nonce_seed, graph_id.as_u128() as usize, signer_keypair)
    }
}

pub struct OperatorMasterKey(Keypair);
impl OperatorMasterKey {
    pub fn new(inner: Keypair) -> Self {
        OperatorMasterKey(inner)
    }
    pub fn master_keypair(&self) -> Keypair {
        NodeMasterKey(self.0).master_keypair()
    }
    pub fn keypair_for_graph(&self, _graph_id: Uuid) -> Keypair {
        self.master_keypair()
    }
    pub fn wots_keypair_for_graph(&self, graph_id: Uuid) -> (WotsSecretKeys, WotsPublicKeys) {
        let domain =
            vec![b"operator_bitvm_wots_key".to_vec(), graph_id.as_bytes().to_vec()].concat();
        let wot_seed = derive_secret(&self.0, &domain);
        generate_wots_keys(&wot_seed)
    }
}

pub struct ChallengerMasterKey(Keypair);
impl ChallengerMasterKey {
    pub fn new(inner: Keypair) -> Self {
        ChallengerMasterKey(inner)
    }
    pub fn master_keypair(&self) -> Keypair {
        NodeMasterKey(self.0).master_keypair()
    }
}
