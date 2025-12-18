use serde::{Deserialize, Serialize};
use tendermint::validator::{Info, ProposerPriority};
use tendermint::{PublicKey as TPublicKey, account};
pub use tendermint_light_client_verifier::{
    ProdVerifier, Verdict, Verifier,
    options::Options,
    types::{Hash, ValidatorSet},
};

use bitcoin::{Transaction, TxOut, Witness, secp256k1::PublicKey};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct CommitInfo {
    pub threshold: u16,
    pub publisher_public_keys: Vec<String>,
    pub txid: String,
    pub genesis_txid: String,
    pub sequencers: Vec<SequencerInfo>,
}

pub(crate) fn build_dummy_tx() -> Transaction {
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
    pub genesis_txid: [u8; 32],
    pub publisher_public_keys: Vec<PublicKey>,
    pub threshold: u16,
    pub sequencers: Vec<SequencerInfo>,
    pub block_height: u32, // Bitcoin block height of current commitment
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct SequencerInfo {
    /// Validator account address
    pub address: String,
    /// Validator public key
    pub pub_key: Vec<u8>,
    pub power: u64,
    /// Validator name
    pub name: Option<String>,
}

impl From<SequencerInfo> for Info {
    fn from(val: SequencerInfo) -> Self {
        Info {
            address: account::Id::try_from(hex::decode(&val.address).unwrap()).unwrap(),
            pub_key: TPublicKey::from_raw_secp256k1(&val.pub_key).unwrap(),
            power: val.power.try_into().unwrap(),
            name: val.name,
            proposer_priority: ProposerPriority::default(),
        }
    }
}

impl From<Info> for SequencerInfo {
    fn from(info: Info) -> Self {
        SequencerInfo {
            address: hex::encode(info.address.as_bytes()),
            pub_key: info.pub_key.to_bytes(),
            power: info.power.value(),
            name: info.name,
        }
    }
}

/// The latest seqeuncer set
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct CommitChainState {
    pub block_height: u32,
    pub commit_txn: Transaction,
    pub genesis_txid: [u8; 32],
    pub sequencers: Vec<SequencerInfo>,
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

pub fn sequencer_hash(sequencers: &[SequencerInfo]) -> Hash {
    let sequencer_set =
        ValidatorSet::without_proposer(sequencers.iter().cloned().map(|s| s.into()).collect());
    sequencer_set.hash()
}

impl CommitChainState {
    pub fn new(genesis_txid: [u8; 32], commit_txn: Transaction) -> Self {
        CommitChainState {
            block_height: u32::MAX,
            commit_txn,
            genesis_txid,
            sequencers: Vec::new(),
            publisher_public_keys: vec![],
            threshold: u16::MAX,
        }
    }

    pub fn apply_commit(&mut self, commits: Vec<CircuitCommit>) {
        let mut prev_sequencers = &self.sequencers;
        let mut prev_commit_txn = self.commit_txn.clone();
        let mut prev_publisher_public_keys: Vec<PublicKey> = vec![];
        let mut prev_threshold: u16 = u16::MAX;
        let mut commit_block_height: u32 = self.block_height;
        for commit in &commits {
            let latest_commit_txn_with_wtns = &commit.commit_txn;
            println!("commit tx: {:?}", latest_commit_txn_with_wtns.compute_txid());
            let latest_sequencers = &commit.sequencers;
            let publisher_public_keys = &commit.publisher_public_keys;
            let threshold = commit.threshold;

            assert_eq!(commit.genesis_txid, self.genesis_txid);

            let prev_commit_txid = prev_commit_txn.compute_txid();
            println!("prev commit txid: {prev_commit_txid}, {prev_commit_txn:?}");
            // calculate the commitment of prev sequencer set and check the equivalent
            if !prev_sequencers.is_empty() {
                let expected_prev_commit = extract_op_return_data(&prev_commit_txn.output);
                if let Hash::Sha256(prev_sequencer_set_hash) = sequencer_hash(prev_sequencers) {
                    println!(
                        "expected prev commit: {expected_prev_commit:?}, {prev_sequencer_set_hash:?}"
                    );
                    assert_eq!(prev_sequencer_set_hash[..], expected_prev_commit);
                } else {
                    panic!("Invalid prev sequencer set hash");
                }
            }

            // calculate the commitment of latest sequencer set and check the equivalent
            let expected_latest_commit =
                extract_op_return_data(&latest_commit_txn_with_wtns.output);
            if let Hash::Sha256(latest_sequencer_set_hash) = sequencer_hash(latest_sequencers) {
                assert_eq!(latest_sequencer_set_hash[..], expected_latest_commit);
            } else {
                panic!("Invalid latest sequencer set hash");
            }

            // check the latest txn's prev out is equals to the output of prev_txn
            let update_connector = &latest_commit_txn_with_wtns.input[0];
            if !prev_sequencers.is_empty() {
                assert_eq!(update_connector.previous_output.txid, prev_commit_txid);
                assert_eq!(update_connector.previous_output.vout, 0);
                // check the latest publishing txn's signature is signed by prev publishers
                let prevout = &prev_commit_txn.output[0];
                let redeem_script = crate::create_sequencer_update_script(
                    &publisher_public_keys[..],
                    threshold as usize,
                );
                crate::publisher::verify_p2wsh_multisig_witness(
                    latest_commit_txn_with_wtns,
                    0,
                    prevout,
                    &redeem_script,
                    publisher_public_keys,
                    threshold as usize,
                )
                .unwrap();
            }
            prev_sequencers = latest_sequencers;

            // remove witness
            prev_commit_txn = latest_commit_txn_with_wtns.clone();
            prev_commit_txn.input.iter_mut().for_each(|input| {
                input.witness = Witness::new();
            });

            prev_publisher_public_keys = publisher_public_keys.clone();
            prev_threshold = threshold;
            commit_block_height = commit.block_height;
        }
        self.sequencers = prev_sequencers.clone();
        self.commit_txn = prev_commit_txn;
        self.publisher_public_keys = prev_publisher_public_keys;
        self.threshold = prev_threshold;
        self.block_height = commit_block_height;
    }
}

pub fn extract_data_from_commitment_outputs(txouts: &[TxOut]) -> Vec<u8> {
    let mut data = vec![];
    for txout in txouts {
        let script = &txout.script_pubkey;
        let instructions = script.instructions_minimal().collect::<Result<Vec<_>, _>>().unwrap();
        if let bitcoin::blockdata::script::Instruction::PushBytes(bytes) = &instructions[1] {
            data.extend_from_slice(bytes.as_bytes());
        }
        if let bitcoin::script::Instruction::Op(op) = instructions[0]
            && op == bitcoin::opcodes::all::OP_RETURN
        {
            break;
        }
    }
    data
}

pub fn extract_op_return_data(tx_output: &[TxOut]) -> Vec<u8> {
    let mut results = Vec::new();
    for output in tx_output {
        let script = &output.script_pubkey;
        // Parse instructions from the script
        let mut instructions = script.instructions();
        // First instruction should be OP_RETURN
        if let Some(Ok(bitcoin::script::Instruction::Op(op))) = instructions.next()
            && op == bitcoin::opcodes::all::OP_RETURN
        {
            // Next should be pushed data
            if let Some(Ok(bitcoin::script::Instruction::PushBytes(data))) = instructions.next() {
                results = data.as_bytes().to_vec();
            }
        }
    }
    if results.is_empty() {
        results = [0u8; 32].to_vec();
    }
    results
}
