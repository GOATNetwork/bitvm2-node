use serde::{Deserialize, Serialize};
pub use tendermint_light_client_verifier::{
    ProdVerifier, Verdict, Verifier,
    options::Options,
    types::{LightBlock, ValidatorSet},
};

use bitcoin::{Transaction, TxOut, Witness, secp256k1::PublicKey};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct CommitInfo {
    pub threshold: u16,
    pub publisher_public_keys: Vec<String>,
    pub txid: String,
    pub genesis_txid: String,
}

fn build_dummy_tx() -> Transaction {
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
    pub sequencer_set_hash: [u8; 32],
    pub publisher_public_keys: Vec<PublicKey>,
    pub threshold: u16,
}

/// The latest seqeuncer set
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct CommitChainState {
    pub block_height: u64,
    pub commit_txn: Transaction,
    pub genesis_txid: [u8; 32],
    pub sequencer_set_hash: [u8; 32],
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

impl Default for CommitChainState {
    fn default() -> Self {
        Self::new()
    }
}

impl CommitChainState {
    pub fn new() -> Self {
        CommitChainState {
            block_height: u64::MAX,
            commit_txn: build_dummy_tx(),
            genesis_txid: [0u8; 32],
            sequencer_set_hash: [0u8; 32],
            publisher_public_keys: vec![],
            threshold: u16::MAX,
        }
    }

    pub fn apply_commit(&mut self, commits: Vec<CircuitCommit>) {
        let mut prev_sequencer_set_hash = self.sequencer_set_hash;
        let mut prev_commit_txn = self.commit_txn.clone();
        let mut prev_publisher_public_keys: Vec<PublicKey> = vec![];
        let mut prev_threshold: u16 = u16::MAX;
        for commit in &commits {
            let latest_commit_txn_with_wtns = &commit.commit_txn;
            println!("commit tx: {:?}", latest_commit_txn_with_wtns.compute_txid());
            let latest_sequencer_set_hash = &commit.sequencer_set_hash;
            let publisher_public_keys = &commit.publisher_public_keys;
            let threshold = commit.threshold;

            if self.genesis_txid == [0u8; 32] {
                self.genesis_txid = commit.genesis_txid;
            }
            assert_eq!(commit.genesis_txid, self.genesis_txid);

            let prev_commit_txid = prev_commit_txn.compute_txid();
            println!("prev commit txid: {prev_commit_txid}, {prev_commit_txn:?}");
            // calculate the commitment of prev sequencer set and check the equivalent
            let expected_prev_commit = extract_op_return_data(&prev_commit_txn.output);
            println!("expected prev commit: {expected_prev_commit:?}\n{prev_sequencer_set_hash:?}");
            assert_eq!(prev_sequencer_set_hash[..], expected_prev_commit);

            // calculate the commitment of latest sequencer set and check the equivalent
            let expected_latest_commit =
                extract_op_return_data(&latest_commit_txn_with_wtns.output);
            assert_eq!(latest_sequencer_set_hash[..], expected_latest_commit);

            // check the latest txn's prev out is equals to the output of prev_txn
            let update_connector = &latest_commit_txn_with_wtns.input[0];
            // FIXME: more graceful way to do this?
            if prev_commit_txid != build_dummy_tx().compute_txid()
                && self.publisher_public_keys.is_empty()
            {
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
            prev_sequencer_set_hash = *latest_sequencer_set_hash;

            // remove witness
            prev_commit_txn = latest_commit_txn_with_wtns.clone();
            prev_commit_txn.input.iter_mut().for_each(|input| {
                input.witness = Witness::new();
            });

            prev_publisher_public_keys = publisher_public_keys.clone();
            prev_threshold = threshold;
        }
        self.sequencer_set_hash = prev_sequencer_set_hash;
        self.commit_txn = prev_commit_txn;
        self.publisher_public_keys = prev_publisher_public_keys;
        self.threshold = prev_threshold;
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
