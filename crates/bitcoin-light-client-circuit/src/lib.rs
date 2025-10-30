mod utils;
use std::sync::Arc;

use alloy_primitives::B256;
use guest_executor::executor::EthClientExecutor;
pub use utils::*;
mod rollup_chain;
pub use rollup_chain::*;

use alloy_primitives::Address;
use alloy_primitives::U256;
use alloy_primitives::utils::keccak256;
use bitcoin::Block;
use bitcoin::Transaction;
use commit_chain::{
    CommitChainCircuitInput, commit_chain_circuit, extract_data_from_commitment_outputs,
};
use header_chain::{
    BitcoinMerkleTree, CircuitBlockHeader, CircuitTransaction, HeaderChainCircuitInput, MMRHost,
    SPV, header_chain_circuit, verify_merkle_proof,
};
use zkm_verifier::Groth16Verifier;

use bitcoin::{ScriptBuf, TxOut, Txid, hashes::Hash, secp256k1::PublicKey};
pub use guest_executor::io::EthClientExecutorInput;

pub const GRAPH_ID_SIZE: usize = 16;
pub const PROOF_SIZE: usize = 260;
pub const PUBLIC_INPUTS_SIZE: usize = 64;
pub const VK_HASH_SIZE: usize = 66;

// https://github.com/GOATNetwork/bitvm2-L2-contracts/blob/main/src/Gateway.sol#L192
// Get base slot:  forge inspect src/GatewayDebug.sol:GatewayDebug storage-layout
pub fn verify_el_withdraw_tx(
    l2_contract_address: Address,
    withdraw_data_map_slot: &[u8; 32],
    graph_id: &[u8; 16],
    input: EthClientExecutorInput,
    //    next_block_hash: [u8; 32],
) {
    // verify the state transition and withdraw status
    let executor = EthClientExecutor::eth(
        Arc::new((&input.genesis).try_into().unwrap()),
        input.custom_beneficiary,
    );

    let mut data = [0u8; 32 * 2];
    data[0..16].copy_from_slice(graph_id);
    data[32..].copy_from_slice(withdraw_data_map_slot);
    let slot_id = B256::from(keccak256(data));

    let (header, _) = executor
        .execute(input, Some(vec![(l2_contract_address, slot_id.into(), U256::from(1))]))
        .expect("failed to execute client");
    let block_hash = header.hash_slow();
    println!("block_hash: {block_hash:?}");
    // assert_eq!(block_hash, next_block_hash);
}

pub fn generate_watchtower_proof(
    genesis_sequencer_commit_txid: [u8; 32],
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
    assert_eq!(genesis_sequencer_commit_txid, commit_header_chain_output.chain_state.genesis_txid);

    println!("header chain: applying: {}", header_chain.block_headers.len());
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
    for (i, item) in bits.iter_mut().enumerate() {
        *item = u.bit(i); // U256 provides `.bit(n)` method
    }
    bits
}

// calculate operator public input:  https://github.com/ProjectZKM/Ziren/blob/main/crates/sdk/src/utils.rs#L42
#[allow(clippy::too_many_arguments)]
pub fn generate_operator_proof(
    included_watchtowers: U256,
    graph_id: [u8; 16],
    operator_genesis_sequencer_commit_txid: [u8; 32],
    operator_latest_sequencer_commit_txn: CircuitTransaction,

    actual_sequencer_set_hash: [u8; 32],
    actual_data_hash: [u8; 32],

    consensus_txns: Vec<String>,
    eth_client_execution_input: EthClientExecutorInput,

    watchtower_challenge_txns: Vec<CircuitTransaction>,
    watchtower_challenge_txn_pubkey: Vec<PublicKey>,
    watchtower_challenge_txn_scripts: Vec<ScriptBuf>,
    watchtower_challenge_txn_prev_outs: Vec<TxOut>,
    watchtower_challenge_txn_prev_indices: Vec<usize>,

    operator_header_chain: HeaderChainCircuitInput,
    commit_chain: CommitChainCircuitInput,
    spv: SPV,
    l2_contract_address: Address,
    base_slot: [u8; 32],
) -> [u8; 32] {
    // verify operator_latest_sequencer_commit_txid is valid, and on operator head chain
    //   * Check operator_latest_sequencer_commit_txid is derived from genesis_sequencer_commit_txid
    let commit_header_chain_output = commit_chain_circuit(commit_chain.clone());
    assert_eq!(
        commit_header_chain_output.chain_state.commit_txn.compute_txid(),
        operator_latest_sequencer_commit_txn.compute_txid()
    );
    assert_eq!(
        operator_genesis_sequencer_commit_txid,
        commit_header_chain_output.chain_state.genesis_txid
    );

    // https://github.com/KSlashh/BitVM/blob/v2/goat/src/transactions/watchtower_challenge.rs#L128
    // verify operator_header_chain is valid
    let btc_header_chain_output = header_chain_circuit(operator_header_chain.clone());
    let operator_total_work = btc_header_chain_output.chain_state.total_work;
    let operator_consensus_block_height =
        U256::from(btc_header_chain_output.chain_state.block_height);

    // verify that the latest_sequecner_commit_tx is in the header chain
    assert!(spv.verify(&btc_header_chain_output.chain_state.block_hashes_mmr));

    // parse included_watchtowers into bits array
    let included_watchertowers_bits = u256_to_bits(included_watchtowers);
    println!("included watchtowers:{included_watchertowers_bits:?}");
    // For each watchtowers, if the included_watchtowers[i] is true,
    //   verify the watchtower_challenge_txns[i] is valid
    //   verify watchtower_challenge_txns[i].total_work <= operator_header_chain.total_work
    //   verify watchtower_challenge_txns[i].epoch <= operator_latest_sequencer_commit_tx.epoch
    let mut number_of_valid_watchtower = 0;
    for i in 0..watchtower_challenge_txns.len() {
        if included_watchertowers_bits[i] {
            let tx = &watchtower_challenge_txns[i];
            println!("Verify watchtower[{i}] tx: {}, {:?}", tx.0.compute_txid(), tx.0);
            let prev_out = &watchtower_challenge_txn_prev_outs[i];
            let prev_index = watchtower_challenge_txn_prev_indices[i];
            let pubkey = &watchtower_challenge_txn_pubkey[i];

            let sig = bitcoin::taproot::Signature::from_slice(&tx.input[0].witness[0]).unwrap();
            // check tx signature is valid
            match crate::rollup_chain::verify_taproot_leaf_schnorr_signature(
                &watchtower_challenge_txn_scripts[i],
                &tx.0,
                prev_index,
                prev_out,
                pubkey,
                &sig,
            ) {
                Ok(_) => {}
                Err(msg) => {
                    println!("Watchtower[{i}] signature verification: {msg}");
                    continue;
                }
            };

            let commitment = &extract_data_from_commitment_outputs(&tx.output)[..];
            println!("commitment: {commitment:?}");
            let (parsed_graph_id, _, _, _, watchtower_total_work, watchtower_block_height) =
                match parse_watchtower_commitment(commitment) {
                    Ok(c) => c,
                    Err(err) => {
                        println!("parse commitment error {err}");
                        continue;
                    }
                };

            if parsed_graph_id != graph_id {
                println!(
                    "Watchtower[{i}] invalid commitment: graph id: parsed = {}, expected = {}",
                    hex::encode(parsed_graph_id),
                    hex::encode(graph_id)
                );
                continue;
            }

            number_of_valid_watchtower += 1;
            // extract ChainState
            // check watchtower_chain_state.total_work <= operator_header_chain.total_work
            assert!(watchtower_total_work <= U256::from_be_bytes(operator_total_work));
            // check watchtower.consensus.block_height <= consensus.block_height
            assert!(watchtower_block_height <= operator_consensus_block_height);
        }
    }

    assert!(number_of_valid_watchtower > 0);
    // check the consensus block is valid by verifying the block's seqeuncer set hash are equal
    //let actual_sequencer_set_hash: [u8; 32] =
    //    consensus_block.signed_header.header.validators_hash.as_bytes().try_into().unwrap();
    assert_eq!(
        actual_sequencer_set_hash,
        commit_header_chain_output.chain_state.sequencer_set_hash
    );

    println!("verify el block");
    // verify the goat block has been included by consensus
    let latest_el_block = &eth_client_execution_input.current_block;
    println!("mix hash: {}", latest_el_block.header.mix_hash);

    verify_el_block_from_consensus(
        latest_el_block.header.number,
        &latest_el_block.header.hash_slow().to_string(),
        &consensus_txns,
        actual_data_hash,
        //consensus_block.signed_header.header.data_hash.as_ref().unwrap().as_bytes(),
    );

    println!("verify el withdraw tx");
    // latest_goat_block.get_graph_status(graph_status_storage_proof, graph_id) == GraphStatus.Proceeded
    // https://github.com/KSlashh/bitvm2-L2-contracts/blob/design/src/Gateway.sol#L101
    // 1 == Processing
    verify_el_withdraw_tx(
        l2_contract_address,
        &base_slot,
        &graph_id, // NOTE: follow up the endian in the watchtower-challenge txn
        eth_client_execution_input,
    );
    operator_total_work
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
    block_headers: &[CircuitBlockHeader],
) -> SPV {
    let tx: CircuitTransaction = CircuitTransaction(latest_sequencer_commit_txn.clone());
    let latest_sequencer_commit_txid = tx.0.compute_txid();

    let mut mmr_native = MMRHost::new();
    for block_header in block_headers {
        mmr_native.append(block_header.compute_block_hash());
    }

    let target_block_header: CircuitBlockHeader = block_headers[target_block_pos as usize].clone();

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

pub fn build_watchtower_commitment(
    graph_id: &[u8; GRAPH_ID_SIZE],
    proof: &[u8; PROOF_SIZE],
    public_inputs: &[u8; PUBLIC_INPUTS_SIZE],
    vk_hash: &str,
    total_work: u64,
    consensus_block_height: u64,
) -> Vec<u8> {
    let mut comm = graph_id.to_vec();
    comm.extend_from_slice(proof);
    comm.extend_from_slice(public_inputs);
    comm.extend_from_slice(vk_hash.as_bytes());

    comm.extend_from_slice(U256::from(total_work).as_le_slice());
    comm.extend_from_slice(U256::from(consensus_block_height).as_le_slice());

    comm
}

pub type WatchtowerCommitmentResult =
    ([u8; GRAPH_ID_SIZE], [u8; PROOF_SIZE], [u8; PUBLIC_INPUTS_SIZE], String, U256, U256);

pub fn parse_watchtower_commitment(
    commitment: &[u8],
) -> Result<WatchtowerCommitmentResult, String> {
    let mut end = GRAPH_ID_SIZE;
    let mut graph_id = [0u8; GRAPH_ID_SIZE];
    graph_id.copy_from_slice(&commitment[0..GRAPH_ID_SIZE]);

    let mut proof = [0u8; PROOF_SIZE];
    proof.copy_from_slice(&commitment[end..end + PROOF_SIZE]);
    end += PROOF_SIZE;

    let mut zkm_public_values = [0u8; PUBLIC_INPUTS_SIZE];
    zkm_public_values.copy_from_slice(&commitment[end..end + PUBLIC_INPUTS_SIZE]);
    end += PUBLIC_INPUTS_SIZE;

    let mut zkm_vk_hash_bytes = [0u8; VK_HASH_SIZE];
    zkm_vk_hash_bytes.copy_from_slice(&commitment[end..end + VK_HASH_SIZE]);
    let zkm_vk_hash = String::from_utf8_lossy(&zkm_vk_hash_bytes[..]);

    end += VK_HASH_SIZE;

    // extract ChainState
    let mut bh_bytes = [0u8; 32];
    bh_bytes.copy_from_slice(&commitment[end..end + 32]);
    let watchtower_total_work = U256::from_le_bytes(bh_bytes);
    end += 32;

    let mut bh_bytes = [0u8; 32];
    bh_bytes.copy_from_slice(&commitment[end..end + 32]);
    let watchtower_consensus_block_height = U256::from_le_bytes(bh_bytes);

    let groth16_vk = *zkm_verifier::GROTH16_VK_BYTES;
    let result = Groth16Verifier::verify(&proof, &zkm_public_values, &zkm_vk_hash, groth16_vk);
    if result.is_err() {
        return Err("Watchtower[{i}] invalid commitment: head chain Groth16 proof".into());
    }

    Ok((
        graph_id,
        proof,
        zkm_public_values,
        zkm_vk_hash.to_string(),
        watchtower_total_work,
        watchtower_consensus_block_height,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Amount, Transaction};
    const PROOF: &[u8] = include_bytes!("../../../circuits/data/watchtower/output3.bin.proof.bin");
    const PUBLIC_INPUTS: &[u8] =
        include_bytes!("../../../circuits/data/watchtower/output3.bin.public_inputs.bin");
    const VK_HASH: &str = include_str!("../../../circuits/data/watchtower/output3.bin.vk_hash.bin");

    #[test]
    fn test_build_watchtower_commitment() {
        let graph_id = [1u8; 16];

        let total_work = 100;
        let block_height = 100;
        let comm = build_watchtower_commitment(
            &graph_id,
            &PROOF.try_into().unwrap(),
            &PUBLIC_INPUTS.try_into().unwrap(),
            VK_HASH,
            total_work,
            block_height,
        );

        let expected = parse_watchtower_commitment(&comm).unwrap();

        assert_eq!(expected.0, graph_id);
        assert_eq!(expected.1, PROOF);
        assert_eq!(expected.2, PUBLIC_INPUTS);
        assert_eq!(expected.3, VK_HASH);
        assert_eq!(expected.4, total_work);
        assert_eq!(expected.5, block_height);
    }

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

        let op_return_data = crate::extract_op_return_data(&tx.output);
        assert_eq!(expected_op_data.to_vec(), op_return_data);
    }
}
