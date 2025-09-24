mod publisher;
pub use publisher::*;
mod commit_chain;
pub use commit_chain::*;

use bitcoin::Block;
use bitcoin::Transaction;
use header_chain::BitcoinMerkleTree;
use header_chain::CircuitBlockHeader;
use header_chain::MMRHost;
use header_chain::verify_merkle_proof;

use alloy_primitives::Address;
use alloy_primitives::hex;
use alloy_primitives::utils::keccak256;
use alloy_primitives::{B256, U128, U256};
use header_chain::{
    BlockHeaderCircuitOutput, ChainState, CircuitTransaction, HeaderChainCircuitInput,
    HeaderChainPrevProofType, SPV,
};
use revm_database_interface::DatabaseRef;
use zkm_verifier::Groth16Verifier;

use bitcoin::{ScriptBuf, TxOut, Txid, hashes::Hash, secp256k1::PublicKey};
pub use guest_executor::io::EthClientExecutorInput;
use guest_executor::io::WitnessInput;

// https://github.com/KSlashh/bitvm2-L2-contracts/blob/design/src/Gateway.sol#L150
fn verify_el_withdraw_tx(
    l2_contract_address: Address,
    base_slot: U256,
    key: U128,
    input: &EthClientExecutorInput,
) -> U256 {
    let mut data = [0u8; 64];
    let mut base = base_slot.to_be_bytes::<32>();
    data[0..32].copy_from_slice(&mut base);
    let mut k = key.to_be_bytes::<32>();
    data[32..].copy_from_slice(&mut k);
    let offset: U256 = U256::ZERO;
    let mut k = offset.to_be_bytes::<32>();
    data[64..].copy_from_slice(&mut k);
    let slot_id = B256::from(keccak256(data));

    let sealed_headers: Vec<_> = input.sealed_headers().collect();
    let triedb = input.witness_db(&sealed_headers).unwrap();
    triedb.storage_ref(l2_contract_address, slot_id.into()).unwrap()
}

/// The main entry point of the header chain circuit.
pub fn header_chain_circuit(input: HeaderChainCircuitInput) -> BlockHeaderCircuitOutput {
    // println!("Detected network: {:?}", NETWORK_TYPE);
    // println!("NETWORK_CONSTANTS: {:?}", NETWORK_CONSTANTS);
    let mut chain_state = match input.prev_proof {
        HeaderChainPrevProofType::GenesisBlock => ChainState::new(),
        HeaderChainPrevProofType::PrevProof(prev_proof) => {
            println!("verify header chain of prev proof");
            assert_eq!(prev_proof.vk_hash, input.vk_hash);
            zkm_zkvm::lib::verify::verify_zkm_proof(&input.vk_hash, &input.pv_hash);
            prev_proof.chain_state
        }
    };

    chain_state.apply_blocks(input.block_headers);
    BlockHeaderCircuitOutput { vk_hash: input.vk_hash, chain_state }
}

pub fn commit_chain_circuit(input: CommitChainCircuitInput) -> CommitChainCircuitOutput {
    let mut chain_state = match input.prev_proof {
        CommitChainPrevProofType::GenesisBlock => CommitChainState::new(),
        CommitChainPrevProofType::PrevProof(prev_proof) => {
            println!("verify commit chain of prev proof");
            assert_eq!(prev_proof.vk_hash, input.vk_hash);
            zkm_zkvm::lib::verify::verify_zkm_proof(&input.vk_hash, &input.pv_hash);
            prev_proof.chain_state
        }
    };

    chain_state.apply_commit(input.commits);
    CommitChainCircuitOutput { vk_hash: input.vk_hash, chain_state }
}

// FIXME: check genesis commit txn
pub fn generate_watchtower_proof(
    latest_sequencer_commit_txid: [u8; 32],
    header_chain: HeaderChainCircuitInput,
    commit_chain: CommitChainCircuitInput,
    spv: SPV,
) -> ([u8; 32], [u8; 32]) {
    println!("commit header, size: {}", commit_chain.commits.len());
    // verify latest_sequencer_commit is valid:
    //   * Check both latest_sequencer_commit_txid and genesis_sequencer_commit_txid are in all_sequencer_commit_txids (which is a private input)
    //   * Check latest_sequencer_commit_txid is derived from genesis_sequencer_commit_txid
    let commit_header_chain_output = commit_chain_circuit(commit_chain);
    assert_eq!(
        commit_header_chain_output.chain_state.commit_txn.compute_txid(),
        Txid::from_byte_array(latest_sequencer_commit_txid)
    );

    println!("header chain");
    // verify header_chain is valid
    let btc_header_chain_output = header_chain_circuit(header_chain);

    // verify that the latest_sequecner_commit_tx is in the header chain
    println!("SPV");
    assert!(spv.verify(&btc_header_chain_output.chain_state.block_hashes_mmr));

    println!("commit public inputs");
    // commit public inputs
    (btc_header_chain_output.chain_state.total_work, latest_sequencer_commit_txid)
}

fn u256_to_bits(u: U256) -> [bool; 256] {
    let mut bits = [false; 256];
    for i in 0..256 {
        bits[i] = u.bit(i); // U256 provides `.bit(n)` method
    }
    bits
}

// calculate operator public input:  https://github.com/ProjectZKM/Ziren/blob/main/crates/sdk/src/utils.rs#L42
pub fn generate_operator_proof(
    included_watchtowers: U256,
    graph_id: [u8; 16],
    operator_latest_sequencer_commit_txn: CircuitTransaction,

    consensus_blocks: LightBlock,
    eth_client_execution_input: EthClientExecutorInput,

    watchtower_challenge_txns: Vec<CircuitTransaction>,
    watchtower_challenge_txn_pubkey: Vec<PublicKey>,
    watchtower_challenge_txn_script: ScriptBuf,
    watchtower_challenge_txn_prev_outs: Vec<TxOut>,

    operator_header_chain: HeaderChainCircuitInput,
    commit_chain: CommitChainCircuitInput,
    spv: SPV,
    l2_contract_address: Address,
    base_slot: U256,
) -> [u8; 32] {
    // hardcode

    //latest_sequencer_commit_tx: &CircuitTransaction,
    // extract consensus block height
    let operator_commitment = &extract_op_return_data(&operator_latest_sequencer_commit_txn.0)[..];
    let mut bh_bytes = [0u8; 32];
    bh_bytes.copy_from_slice(&operator_commitment[0..32]);
    let operator_consensus_block_height = U256::from_be_bytes(bh_bytes);

    // https://github.com/KSlashh/BitVM/blob/v2/goat/src/transactions/watchtower_challenge.rs#L128

    // verify operator_header_chain is valid
    // operator_head_chain.latest_blockhash = latest_operator_blockhash
    let btc_header_chain_output = header_chain_circuit(operator_header_chain.clone());
    let operator_total_work = btc_header_chain_output.chain_state.total_work;

    // verify operator_latest_sequencer_commit_txid is valid, and on operator head chain
    //   * Check operator_latest_sequencer_commit_txid is derived from genesis_sequencer_commit_txid
    let commit_header_chain_output = commit_chain_circuit(commit_chain.clone());
    assert_eq!(
        commit_header_chain_output.chain_state.commit_txn.compute_txid(),
        operator_latest_sequencer_commit_txn.compute_txid()
    );

    // verify that the latest_sequecner_commit_tx is in the header chain
    assert!(spv.verify(&btc_header_chain_output.chain_state.block_hashes_mmr));

    // parse included_watchtowers into bits array
    let included_watchertowers_bits = u256_to_bits(included_watchtowers);
    // For each watchtowers, if the included_watchtowers[i] is true,
    //   verify the watchtower_challenge_txns[i] is valid
    //   verify watchtower_challenge_txns[i].total_work <= operator_header_chain.total_work
    //   verify watchtower_challenge_txns[i].epoch <= operator_latest_sequencer_commit_tx.epoch
    for i in 0..watchtower_challenge_txns.len() {
        if included_watchertowers_bits[i] {
            let tx = &watchtower_challenge_txns[i];
            let prev_out = &watchtower_challenge_txn_prev_outs[i];
            let pubkey = &watchtower_challenge_txn_pubkey[i];

            // The index is 0
            let sig = bitcoin::taproot::Signature::from_slice(&tx.input[0].witness[0]).unwrap();
            // check tx signature is valid
            match crate::commit_chain::verify_taproot_leaf_schnorr_signature(
                &watchtower_challenge_txn_script,
                &tx.0,
                prev_out,
                pubkey,
                &sig,
            ) {
                Ok(_) => {}
                Err(msg) => {
                    println!("Watchtower[{i}] signature verification: {}", msg);
                    continue;
                }
            };

            // check the output contains commitment, and the commitment contains graph_id and header_chain proof
            if !is_valid_commitment_outputs(&tx.output) {
                println!("Watchtower[{i}] invalid txoutput format");
                continue;
            }
            let commitment = &extract_op_return_data(&tx)[..];
            // check first 16 bytes is graph_id
            if !commitment.starts_with(&graph_id) {
                println!("Watchtower[{i}] invalid commitment: graph id");
                continue;
            }

            // Get the header_chain Groth16 proof from commitment
            // proof size: 260bytes
            let proof = &commitment[16..16 + 260];
            // public inputs: 2 * [u8; 32].
            // TODO: how to verify the connection between public inputs and commitment?
            //  groth16 public input[1] == hash(genesis_commit_txid || watchtower_latest_commit_txid || watchtower_total work || watchtower_consensus_block_height)
            let zkm_public_values = &commitment[16 + 260..16 + 260 + 64];
            // vk hash: [u8; 32]
            let zkm_vkey_hash = &commitment[16 + 260 + 64..16 + 260 + 64 + 32];
            let zkm_vkey_hash = hex::encode(zkm_vkey_hash);
            let groth16_vk = *zkm_verifier::GROTH16_VK_BYTES;
            let result =
                Groth16Verifier::verify(proof, zkm_public_values, &zkm_vkey_hash, groth16_vk);
            if !result.is_ok() {
                println!("Watchtower[{i}] invalid commitment: head chain Groth16 proof");
                continue;
            }

            // extract ChainState
            let mut bh_bytes = [0u8; 32];
            bh_bytes.copy_from_slice(&commitment[16 + 260 + 64 + 32..16 + 260 + 64 + 32 + 32]);
            let watchtower_total_work = U256::from_be_bytes(bh_bytes);
            // check watchtower_chain_state.total_work <= operator_header_chain.total_work
            assert!(watchtower_total_work <= U256::from_be_bytes(operator_total_work));
            let mut bh_bytes = [0u8; 32];
            bh_bytes.copy_from_slice(
                &commitment[16 + 260 + 64 + 32 + 32..16 + 260 + 64 + 32 + 32 + 32],
            );
            let watchtower_consensus_block_height = U256::from_be_bytes(bh_bytes);
            // check watchtower.consensus.block_height <= consensus.block_height
            assert!(watchtower_consensus_block_height <= operator_consensus_block_height);
        }
    }

    // check the consensus block is valid by verifying the block's seqeuncer set hash are equal
    let actual_sequencer_set_hash: [u8; 32] =
        consensus_blocks.signed_header.header.validators_hash.as_bytes().try_into().unwrap();
    assert_eq!(
        actual_sequencer_set_hash,
        commit_header_chain_output.chain_state.sequencer_set_hash
    );

    // verify the goat block has been included by consensus
    let latest_el_block = &eth_client_execution_input.current_block;
    let goat_txns: Vec<String> =
        latest_el_block.body.transactions().map(|tx| hex::encode(tx.hash())).collect();

    verify_el_block_from_consensus(
        latest_el_block.header.number,
        &hex::encode(latest_el_block.header.hash_slow()),
        &goat_txns,
        consensus_blocks.clone(),
    );

    // latest_goat_block.get_graph_status(graph_status_storage_proof, graph_id) == GraphStatus.Proceeded
    // https://github.com/KSlashh/bitvm2-L2-contracts/blob/design/src/Gateway.sol#L101
    assert_eq!(
        verify_el_withdraw_tx(
            l2_contract_address,
            base_slot,
            U128::from_be_bytes(graph_id),
            &eth_client_execution_input,
        ),
        1
    ); // 1 == Processing 
    operator_total_work
}

pub fn is_valid_commitment_outputs(txouts: &[TxOut]) -> bool {
    if txouts.is_empty() {
        return false;
    }
    let last_txout = &txouts[txouts.len() - 1];
    if !last_txout.script_pubkey.is_op_return() {
        return false;
    }
    for txout in &txouts[..txouts.len() - 1] {
        if !txout.script_pubkey.is_p2wsh() {
            return false;
        }
    }
    true
}

/// Utility method for converting u32 words to bytes in big endian.
pub fn words_to_bytes_be(words: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for i in 0..8 {
        let word_bytes = words[i].to_be_bytes();
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word_bytes);
    }
    bytes
}

/// Utility method for converting u32 words from bytes in big endian.
pub fn words_from_bytes_be(bytes: &[u8; 32]) -> [u32; 8] {
    let mut words = [0u32; 8];
    for i in 0..8 {
        let chunk: [u8; 4] = bytes[i * 4..(i + 1) * 4].try_into().unwrap();
        words[i] = u32::from_be_bytes(chunk);
    }
    words
}

pub fn build_spv(
    latest_sequencer_commit_txn: &Transaction,
    target_block_pos: u32,
    target_block: Block,
    header_chain_input: &HeaderChainCircuitInput,
) -> SPV {
    let tx: CircuitTransaction = CircuitTransaction(latest_sequencer_commit_txn.clone());
    let latest_sequencer_commit_txid = tx.0.compute_txid();

    let mut mmr_native = MMRHost::new();
    for j in 0..header_chain_input.block_headers.len() {
        mmr_native.append(header_chain_input.block_headers[j].compute_block_hash());
    }

    let target_block_header: CircuitBlockHeader =
        header_chain_input.block_headers[target_block_pos as usize].clone();

    // find the target block
    let tx_pos =
        target_block.txdata.iter().position(|x| x.compute_txid() == latest_sequencer_commit_txid);
    assert!(tx_pos.is_some());
    let txid_list = target_block.txdata.iter().map(|x| x.compute_txid().to_byte_array()).collect();

    let bitcoin_merkle_tree: BitcoinMerkleTree = BitcoinMerkleTree::new(txid_list);
    let bitcoin_inclusion_proof = bitcoin_merkle_tree.generate_proof(tx_pos.unwrap() as u32);

    println!("verify merkle proof");
    if !(verify_merkle_proof(
        latest_sequencer_commit_txid.to_byte_array(),
        &bitcoin_inclusion_proof,
        bitcoin_merkle_tree.root(),
    )) {
        panic!("Can not verify merkle proof")
    }

    println!("generate proof from mmr native");

    let (_, mmr_inclusion_proof) = mmr_native.generate_proof(target_block_pos);

    println!("constuct spv");
    SPV::new(tx, bitcoin_inclusion_proof, target_block_header, mmr_inclusion_proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Amount, Transaction};

    #[test]
    fn test_words_bytes_conversion() {
        let words: [u32; 8] = [
            0x11223344, 0x55667788, 0x99aabbcc, 0xddeeff00, 0x01020304, 0xa1b2c3d4, 0xdeadbeef,
            0xabcdef01,
        ];
        let bytes = words_to_bytes_be(&words);
        let recovered = words_from_bytes_be(&bytes);
        assert_eq!(words, recovered);
    }

    #[test]
    fn test_extract_op_return() {
        // Example: construct a fake tx with OP_RETURN
        let expected_op_data = [12, 3, 4, 45];
        let script = ScriptBuf::new_op_return(&expected_op_data);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![bitcoin::TxOut { value: Amount::ZERO, script_pubkey: script }],
        };

        let op_return_data = crate::extract_op_return_data(&tx);
        assert_eq!(expected_op_data.to_vec(), op_return_data);
    }
}
