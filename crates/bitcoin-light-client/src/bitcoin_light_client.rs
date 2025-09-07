use alloy_primitives::Address;
use alloy_primitives::hex;
use alloy_primitives::utils::keccak256;
use alloy_primitives::{B256, U128, U256};
use bitcoin::{ScriptBuf, Transaction, TxOut, secp256k1::PublicKey};
use guest_executor::executor::EthClientExecutor;
use guest_executor::io::EthClientExecutorInput;
use header_chain::{
    BlockHeaderCircuitOutput, BlockInclusionProof, ChainState, CircuitTransaction,
    HeaderChainCircuitInput, HeaderChainPrevProofType, verify_merkle_proof,
};
use revm::DatabaseRef;
use sha2::Digest;
use std::sync::Arc;
use zkm_verifier::Groth16Verifier;

use crate::verify_goat_block_from_consensus;
use bitcoin::hashes::Hash;
use tendermint_light_client_verifier::types::{LightBlock, ValidatorSet};

use crate::create_sequencer_update_script;

pub fn verify_goat_block(input: EthClientExecutorInput) -> (B256, B256, B256) {
    // Execute the block.
    let executor = EthClientExecutor::eth(
        Arc::new((&input.genesis).try_into().unwrap()),
        input.custom_beneficiary,
    );
    let (header, prev_state_root) = executor.execute(input).expect("failed to execute client");
    let block_hash = header.hash_slow();
    (block_hash, header.state_root, prev_state_root)
}

// https://github.com/KSlashh/bitvm2-L2-contracts/blob/design/src/Gateway.sol#L150
pub fn verify_withdraw_tx(
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

    let wtns_db = input.witness_db().unwrap();
    wtns_db.storage_ref(l2_contract_address, slot_id.into()).unwrap()
}

/// The main entry point of the header chain circuit.
pub fn header_chain_circuit(input: HeaderChainCircuitInput) -> BlockHeaderCircuitOutput {
    // println!("Detected network: {:?}", NETWORK_TYPE);
    // println!("NETWORK_CONSTANTS: {:?}", NETWORK_CONSTANTS);
    let mut chain_state = match input.prev_proof {
        HeaderChainPrevProofType::GenesisBlock => ChainState::new(),
        HeaderChainPrevProofType::PrevProof(prev_proof) => {
            assert_eq!(prev_proof.method_id, input.method_id);
            // FIXME
            // guest.verify(input.method_id, &prev_proof);
            let encoded = bincode::serialize(&prev_proof).unwrap();
            let pv = sha2::Sha256::digest(&encoded);
            zkm_zkvm::lib::verify::verify_zkm_proof(&input.method_id, &pv.into());
            prev_proof.chain_state
        }
    };

    chain_state.apply_blocks(input.block_headers);
    BlockHeaderCircuitOutput { method_id: input.method_id, chain_state }
}

pub fn generate_watchtower_proof(
    total_work: [u8; 32],
    latest_sequencer_commit_txid: [u8; 32],
    genesis_sequencer_commit_txid: [u8; 32],
    header_chain: HeaderChainCircuitInput,
    latest_sequencer_commit_txid_inclusion_proof: BlockInclusionProof,
    sequencer_set_commit_vk: [u32; 8],
) {
    // verify header_chain is valid
    let btc_header_chain_output = header_chain_circuit(header_chain.clone());

    // verify header_chain.total_work == total_work
    assert_eq!(btc_header_chain_output.chain_state.total_work, total_work);

    // verify latest_sequencer_commit is valid:
    //   * Check both latest_sequencer_commit_txid and genesis_sequencer_commit_txid are in all_sequencer_commit_txids (which is a private input)
    //   * Check latest_sequencer_commit_txid is derived from genesis_sequencer_commit_txid
    let encoded = bincode::serialize(&[
        genesis_sequencer_commit_txid.clone(),
        latest_sequencer_commit_txid.clone(),
    ])
    .unwrap();
    let pv = sha2::Sha256::digest(&encoded);
    zkm_zkvm::lib::verify::verify_zkm_proof(&sequencer_set_commit_vk, &pv.into());

    // verify latest_sequencer_commit is in header_chain
    verify_merkle_proof(
        latest_sequencer_commit_txid.clone(),
        &latest_sequencer_commit_txid_inclusion_proof,
        header_chain.block_headers[header_chain.block_headers.len() - 1].merkle_root.clone(),
    );

    // commit public inputs
    zkm_zkvm::io::commit(&total_work);
    zkm_zkvm::io::commit(&latest_sequencer_commit_txid);
    zkm_zkvm::io::commit(&genesis_sequencer_commit_txid);
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
    genesis_sequencer_commit_txid: [u8; 32],
    operator_latest_sequencer_commit_txn: CircuitTransaction,

    consensus_blocks: [LightBlock; 2],
    eth_client_execution_input: EthClientExecutorInput,

    watchtower_challenge_txns: Vec<CircuitTransaction>,
    watchtower_challenge_txn_script: Vec<ScriptBuf>,
    watchtower_challenge_txn_prev_out: Vec<TxOut>,
    watchtower_challenge_txn_pubkey: Vec<PublicKey>,
    watchtower_challenge_txn_sig: Vec<bitcoin::taproot::Signature>,

    operator_header_chain: HeaderChainCircuitInput,

    l2_contract_address: Address,
    base_slot: U256,

    latest_sequencer_commit_txid_inclusion_proof: BlockInclusionProof,
    sequencer_set_commit_vk: [u32; 8],
) {
    // hardcode

    //latest_sequencer_commit_tx: &CircuitTransaction,
    // extract consensus block height
    let operator_commitment =
        extract_data_from_commitment_outputs(&operator_latest_sequencer_commit_txn.0.output);
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
    let encoded = bincode::serialize(&[
        genesis_sequencer_commit_txid.clone(),
        operator_latest_sequencer_commit_txn.0.compute_txid().to_byte_array(),
    ])
    .unwrap();
    let pv = sha2::Sha256::digest(&encoded);
    zkm_zkvm::lib::verify::verify_zkm_proof(&sequencer_set_commit_vk, &pv.into());
    verify_merkle_proof(
        operator_latest_sequencer_commit_txn.0.compute_txid().to_byte_array(),
        &latest_sequencer_commit_txid_inclusion_proof,
        operator_header_chain.block_headers[operator_header_chain.block_headers.len() - 1]
            .merkle_root
            .clone(),
    );

    // parse included_watchtowers into bits array
    let included_watchertowers_bits = u256_to_bits(included_watchtowers);
    // For each watchtowers, if the included_watchtowers[i] is true,
    //   verify the watchtower_challenge_txns[i] is valid
    //   verify watchtower_challenge_txns[i].total_work <= operator_header_chain.total_work
    //   verify watchtower_challenge_txns[i].epoch <= operator_latest_sequencer_commit_tx.epoch
    for i in 0..watchtower_challenge_txns.len() {
        if included_watchertowers_bits[i] {
            let tx = &watchtower_challenge_txns[i];
            let script = &watchtower_challenge_txn_script[i];
            let prev_out = &watchtower_challenge_txn_prev_out[i];
            let pubkey = &watchtower_challenge_txn_pubkey[i];
            let sig = &watchtower_challenge_txn_sig[i];
            // check tx signature is valid
            match crate::commitment::verify_taproot_leaf_schnorr_signature(
                script, &tx.0, prev_out, pubkey, sig,
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
            let commitment = extract_data_from_commitment_outputs(&tx.output);
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

    // latest_goat_block.validators == latest_sequencer_commit_txn.validators, and the sequencers signature is valid
    // FIXME
    // verify_validator_set(consensus_blocks[0].clone(), consensus_blocks[1].clone());
    // assert!(U256::from(consensus_blocks[1].signed_header.header.height.value()) == operator_consensus_block_height);

    // verify the goat block has been included by consensus
    let latest_el_block = &eth_client_execution_input.current_block;
    let goat_txns: Vec<String> =
        latest_el_block.body.transactions().map(|tx| hex::encode(tx.hash())).collect();

    verify_goat_block_from_consensus(
        latest_el_block.header.number,
        &hex::encode(latest_el_block.header.hash_slow()),
        &goat_txns,
        consensus_blocks[1].clone(),
    );

    // latest_goat_block.get_graph_status(graph_status_storage_proof, graph_id) == GraphStatus.Proceeded
    // https://github.com/KSlashh/bitvm2-L2-contracts/blob/design/src/Gateway.sol#L101
    assert_eq!(
        verify_withdraw_tx(
            l2_contract_address,
            base_slot,
            U128::from_be_bytes(graph_id),
            &eth_client_execution_input,
        ),
        1
    ); // 1 == Processing 
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

fn extract_op_return_data(tx: &Transaction) -> Vec<Vec<u8>> {
    let mut results = Vec::new();

    for output in &tx.output {
        let script = &output.script_pubkey;
        // Parse instructions from the script
        let mut instructions = script.instructions();
        // First instruction should be OP_RETURN
        if let Some(Ok(bitcoin::script::Instruction::Op(op))) = instructions.next() {
            if op == bitcoin::opcodes::all::OP_RETURN {
                // Next should be pushed data
                if let Some(Ok(bitcoin::script::Instruction::PushBytes(data))) = instructions.next()
                {
                    results.push(data.as_bytes().to_vec());
                }
            }
        }
    }
    results
}

pub fn prove_publisher_commitment_continuality(
    prev_commit_txn: CircuitTransaction,
    prev_sequencer_set: ValidatorSet,

    latest_commit_txn_with_wtns: CircuitTransaction,
    latest_sequencer_set: ValidatorSet,

    publisher_public_keys: Vec<PublicKey>,
    threshold: usize,
) {
    let prev_commit_txid = prev_commit_txn.0.compute_txid();

    // calculate the commitment of prev sequencer set and check the equivalent
    let expected_prev_commit = extract_op_return_data(&prev_commit_txn.0);
    let prev_commit = prev_sequencer_set.hash();
    assert_eq!(prev_commit.as_bytes().to_vec(), expected_prev_commit[0]);

    // calculate the commitment of latest sequencer set and check the equivalent
    let expected_latest_commit = extract_op_return_data(&&latest_commit_txn_with_wtns.0);
    let latest_commit = latest_sequencer_set.hash();
    assert_eq!(latest_commit.as_bytes().to_vec(), expected_latest_commit[0]);

    // check the latest txn's prev out is equals to the output of prev_txn
    let update_connector = &latest_commit_txn_with_wtns.input[0];
    assert_eq!(update_connector.previous_output.txid, prev_commit_txid);
    assert_eq!(update_connector.previous_output.vout, 0);

    // check the latest publishing txn's signature is signed by prev publishers

    let prevout = &prev_commit_txn.output[0];

    let redeem_script = create_sequencer_update_script(&publisher_public_keys[..], threshold);
    crate::publisher::verify_p2wsh_multisig_witness(
        &latest_commit_txn_with_wtns,
        0,
        prevout,
        &redeem_script,
        &publisher_public_keys,
        threshold,
    )
    .unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Amount;

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

        let op_return_data = extract_op_return_data(&tx);
        assert_eq!(vec![expected_op_data.to_vec()], op_return_data);
    }
}
