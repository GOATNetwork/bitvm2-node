mod signature;
mod utils;
use alloy_primitives::U32;
pub use signature::*;
use state_chain::verify_sequencer_commit;
pub use utils::*;

use alloy_primitives::U256;
use bitcoin::Block;
use bitcoin::Transaction;
use bitcoin::hashes::{Hash, HashEngine, sha256};
use commit_chain::sequencer_hash;
use commit_chain::{
    CommitChainCircuitInput, CommitChainPrevProofType, extract_data_from_commitment_outputs,
};
use header_chain::{
    BitcoinMerkleTree, CircuitBlockHeader, CircuitTransaction, HeaderChainCircuitInput,
    HeaderChainPrevProofType, MMRHost, SPV, verify_merkle_proof,
};
use state_chain::{StateChainCircuitInput, StateChainPrevProofType};
use zkm_primitives::io::ZKMPublicValues;
use zkm_verifier::Groth16Verifier;

use bitcoin::{ScriptBuf, TxOut, Txid, secp256k1::PublicKey};
pub use guest_executor::io::EthClientExecutorInput;

pub const GRAPH_ID_SIZE: usize = 16;
pub const PROOF_SIZE: usize = 260;
pub const PUBLIC_INPUTS_SIZE: usize = 36;
pub const VK_HASH_SIZE: usize = 66;
pub const COMMITMENT_SIZE: usize = GRAPH_ID_SIZE + PROOF_SIZE + PUBLIC_INPUTS_SIZE + VK_HASH_SIZE;

pub const TOTAL_WORK_SIZE: usize = 32;
pub const CONSENSUS_BLOCK_HEIGHT_SIZE: usize = 4;

pub fn watch_longest_chain(
    genesis_sequencer_commit_txid: [u8; 32],
    latest_sequencer_commit_txid: [u8; 32],
    header_chain: HeaderChainCircuitInput,
    commit_chain: CommitChainCircuitInput,
    state_chain: StateChainCircuitInput,
    spv: SPV,
) -> ([u8; 32], u32) {
    println!("commit header, size: {}", commit_chain.commits.len());
    // verify latest_sequencer_commit is valid:
    //   * Check both latest_sequencer_commit_txid and genesis_sequencer_commit_txid are in all_sequencer_commit_txids (which is a private input)
    //   * Check latest_sequencer_commit_txid is derived from genesis_sequencer_commit_txid
    // verify the commit chain proof
    verify_proof(
        &commit_chain.zkm_proof,
        &commit_chain.zkm_public_values,
        &commit_chain.zkm_vk_hash,
    )
    .expect("Failed to verify commit chain proof");

    let prev_output = ZKMPublicValues::from(&commit_chain.zkm_public_values).read();
    let prev_proof = CommitChainPrevProofType::PrevProof(prev_output);
    let CommitChainPrevProofType::PrevProof(commit_chain_output) = &prev_proof else {
        panic!("Only PrevProof is supported in watch_longest_chain");
    };

    assert_eq!(
        commit_chain_output.chain_state.commit_txn.compute_txid(),
        Txid::from_byte_array(latest_sequencer_commit_txid)
    );
    assert_eq!(genesis_sequencer_commit_txid, commit_chain_output.chain_state.genesis_txid);

    println!("header chain: applying: {}", header_chain.block_headers.len());
    // verify header_chain is valid
    verify_proof(
        &header_chain.zkm_proof,
        &header_chain.zkm_public_values,
        &header_chain.zkm_vk_hash,
    )
    .expect("Failed to verify header chain proof");

    let prev_output = ZKMPublicValues::from(&header_chain.zkm_public_values).read();
    let prev_proof = HeaderChainPrevProofType::PrevProof(prev_output);
    let HeaderChainPrevProofType::PrevProof(btc_header_chain_output) = &prev_proof else {
        panic!("Only PrevProof is supported in watch_longest_chain");
    };
    // verify that the latest_sequecner_commit_tx is in the header chain
    println!("SPV");
    assert!(spv.verify(&btc_header_chain_output.chain_state.block_hashes_mmr));

    verify_proof(&state_chain.zkm_proof, &state_chain.zkm_public_values, &state_chain.zkm_vk_hash)
        .expect("Failed to verify state chain proof");
    let prev_output = ZKMPublicValues::from(&state_chain.zkm_public_values).read();
    let prev_proof = StateChainPrevProofType::PrevProof(prev_output);
    let StateChainPrevProofType::PrevProof(state_chain_output) = &prev_proof else {
        panic!("Only PrevProof is supported in watch_longest_chain");
    };
    // check the signature.
    let cosmos_block_bytes = &state_chain_output.chain_state.latest_cosmos_block;
    let cosmos_block: LightBlock =
        serde_json::from_slice(cosmos_block_bytes).expect("failed to deserialize light block");
    verify_sequencer_commit(&cosmos_block);

    // check the equivalence of sequencer set
    let commit_sequencer_set_hash = sequencer_hash(&commit_chain_output.chain_state.sequencers);
    let expected_seqeuencer_set_hash = cosmos_block.signed_header.header.validators_hash;
    assert_eq!(commit_sequencer_set_hash, expected_seqeuencer_set_hash);

    // check commit chain's genesis block
    let commitment =
        commit_chain::extract_op_return_data(&commit_chain_output.chain_state.commit_txn.output);
    if let tendermint::Hash::Sha256(x) = expected_seqeuencer_set_hash {
        assert_eq!(commitment[0..32], x);
    } else {
        panic!("Invalid commitment: inconsistent sequencer set hash");
    };
    assert_eq!(commitment[32..64], state_chain_output.chain_state.genesis_evm_block_hash[..]);

    println!("commit public inputs");
    // commit public inputs
    (btc_header_chain_output.chain_state.total_work, commit_chain_output.chain_state.block_height)
}

pub fn u256_to_le_bits(u: U256) -> [bool; 256] {
    let mut bits = [false; 256];
    for (i, item) in bits.iter_mut().enumerate() {
        *item = u.bit(i); // U256 provides `.bit(n)` method
    }
    bits
}

pub fn le_bits_to_u256(bits: &[bool]) -> U256 {
    let mut u = U256::ZERO;
    for (i, bit) in bits.iter().enumerate() {
        if *bit {
            u += U256::ONE << i; // Set the i-th bit if it's true
        }
    }
    u
}

// calculate operator public input:  https://github.com/ProjectZKM/Ziren/blob/main/crates/sdk/src/utils.rs#L42
#[allow(clippy::too_many_arguments)]
pub fn propose_longest_chain(
    included_watchtowers: U256,                       //pis
    graph_id: [u8; GRAPH_ID_SIZE],                    // pis
    operator_genesis_sequencer_commit_txid: [u8; 32], // pis

    watchtower_challenge_txns: Vec<Transaction>,
    watchtower_challenge_txn_pubkey: Vec<PublicKey>,
    watchtower_challenge_txn_scripts: Vec<ScriptBuf>,
    watchtower_challenge_txn_prev_outs: Vec<TxOut>,

    operator_header_chain: HeaderChainCircuitInput,
    commit_chain: CommitChainCircuitInput,
    state_chain: StateChainCircuitInput,
    spv_ss_commit: SPV,
    operator_committed_blockhash: [u8; 32],
) -> ([u8; 32], [u8; 32], [u8; 32]) {
    // verify operator_latest_sequencer_commit_txid is valid, and on operator head chain
    //   * Check operator_latest_sequencer_commit_txid is derived from genesis_sequencer_commit_txid
    verify_proof(
        &commit_chain.zkm_proof,
        &commit_chain.zkm_public_values,
        &commit_chain.zkm_vk_hash,
    )
    .expect("Failed to verify commit chain proof");
    let prev_output = ZKMPublicValues::from(&commit_chain.zkm_public_values).read();
    let prev_proof = CommitChainPrevProofType::PrevProof(prev_output);
    let CommitChainPrevProofType::PrevProof(commit_chain_output) = &prev_proof else {
        panic!("Only PrevProof is supported in propose_longest_chain");
    };
    assert_eq!(
        commit_chain_output.chain_state.commit_txn.compute_txid(),
        spv_ss_commit.transaction.0.compute_txid()
    );
    assert_eq!(
        operator_genesis_sequencer_commit_txid,
        commit_chain_output.chain_state.genesis_txid
    );

    // https://github.com/KSlashh/BitVM/blob/v2/goat/src/transactions/watchtower_challenge.rs#L128
    // verify operator_header_chain is valid
    verify_proof(
        &operator_header_chain.zkm_proof,
        &operator_header_chain.zkm_public_values,
        &operator_header_chain.zkm_vk_hash,
    )
    .expect("Failed to verify header chain proof");
    let prev_output = ZKMPublicValues::from(&operator_header_chain.zkm_public_values).read();
    let prev_proof = HeaderChainPrevProofType::PrevProof(prev_output);
    let HeaderChainPrevProofType::PrevProof(btc_header_chain_output) = &prev_proof else {
        panic!("Only PrevProof is supported in propose_longest_chain");
    };
    let operator_total_work = btc_header_chain_output.chain_state.total_work;
    let operator_consensus_block_height = U32::from(commit_chain_output.chain_state.block_height);
    // commit header chain best block hash as pis
    let btc_best_block_hash = btc_header_chain_output.chain_state.best_block_hash;

    // verify that the latest_sequecner_commit_tx is in the header chain
    assert!(spv_ss_commit.verify(&btc_header_chain_output.chain_state.block_hashes_mmr));

    // parse included_watchtowers into bits array
    let included_watchertowers_bits = u256_to_le_bits(included_watchtowers);
    println!("included watchtowers:{included_watchertowers_bits:?}");
    // For each watchtowers, if the included_watchtowers[i] is true,
    //   verify the watchtower_challenge_txns[i] is valid
    //   verify watchtower_challenge_txns[i].total_work <= operator_header_chain.total_work
    //   verify watchtower_challenge_txns[i].epoch <= operator_latest_sequencer_commit_tx.epoch
    for i in 0..watchtower_challenge_txns.len() {
        if included_watchertowers_bits[i] {
            let tx = &watchtower_challenge_txns[i];
            println!("Verify watchtower[{i}] tx: {}, {:?}", tx.compute_txid(), tx);
            let prev_out = &watchtower_challenge_txn_prev_outs[i];
            let prev_index = tx.input[0].previous_output.vout as usize;
            let pubkey = &watchtower_challenge_txn_pubkey[i];

            let sig = bitcoin::taproot::Signature::from_slice(&tx.input[0].witness[0]).unwrap();
            // check tx signature is valid
            match verify_taproot_leaf_schnorr_signature(
                &watchtower_challenge_txn_scripts[i],
                tx,
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
            println!("commitment hex: {}", hex::encode(commitment));
            let (
                parsed_graph_id,
                proof,
                public_values,
                vk,
                watchtower_total_work,
                watchtower_consensus_block_height,
            ) = match parse_watchtower_commitment(commitment) {
                Ok(c) => c,
                Err(err) => {
                    println!("Watchtower[{i}] parse commitment error, {err}");
                    continue;
                }
            };

            match verify_proof(&proof, &public_values, &vk) {
                Ok(_) => {}
                Err(err) => {
                    println!("Watchtower[{i}] invalid proof: {err}");
                    continue;
                }
            }

            if parsed_graph_id != graph_id {
                println!(
                    "Watchtower[{i}] invalid commitment: graph id: parsed = {}, expected = {}",
                    hex::encode(parsed_graph_id),
                    hex::encode(graph_id)
                );
                continue;
            }
            println!("check total work with watchtower {i}");

            // extract ChainState
            // check watchtower_chain_state.total_work <= operator_header_chain.total_work
            println!("watchtower total work: {:?}", U256::from_be_bytes(watchtower_total_work));
            println!("operator total work: {operator_total_work:?}");

            println!(
                "watchtower_consensus_block_height : {:?}",
                U32::from_le_bytes(watchtower_consensus_block_height)
            );
            println!("operator_consensus_block_height : {operator_consensus_block_height:?}");

            assert!(
                U256::from_be_bytes(watchtower_total_work)
                    <= U256::from_be_bytes(operator_total_work)
            );
            // check watchtower.consensus.block_height <= consensus.block_height
            assert!(
                U32::from_le_bytes(watchtower_consensus_block_height)
                    <= operator_consensus_block_height
            );
        }
    }

    println!("verify el block");

    verify_proof(&state_chain.zkm_proof, &state_chain.zkm_public_values, &state_chain.zkm_vk_hash)
        .expect("Failed to verify state chain proof");

    let prev_output = ZKMPublicValues::from(&state_chain.zkm_public_values).read();
    let prev_proof = StateChainPrevProofType::PrevProof(prev_output);
    let StateChainPrevProofType::PrevProof(state_chain_output) = &prev_proof else {
        panic!("Only PrevProof is supported in propose_longest_chain");
    };
    // check the signature.
    let cosmos_block_bytes = &state_chain_output.chain_state.latest_cosmos_block;
    let cosmos_block: LightBlock =
        serde_json::from_slice(cosmos_block_bytes).expect("failed to deserialize light block");
    verify_sequencer_commit(&cosmos_block);
    // check the equivalence of sequencer set
    let commit_sequencer_set_hash = sequencer_hash(&commit_chain_output.chain_state.sequencers);
    let expected_seqeuencer_set_hash = cosmos_block.signed_header.header.validators_hash;

    // check commit chain's genesis block
    let commitment =
        commit_chain::extract_op_return_data(&commit_chain_output.chain_state.commit_txn.output);
    if let tendermint::Hash::Sha256(x) = expected_seqeuencer_set_hash {
        assert_eq!(commitment[0..32], x);
    } else {
        panic!("Invalid commitment: inconsistent sequencer set hash");
    };
    assert_eq!(commitment[32..64], state_chain_output.chain_state.genesis_evm_block_hash[..]);

    assert_eq!(commit_sequencer_set_hash, expected_seqeuencer_set_hash);

    let mut is_found = false;
    for withdrawal in &state_chain_output.chain_state.withdrawals {
        if withdrawal.2.contains(&graph_id) {
            is_found = true;
            break;
        }
    }
    assert!(is_found, "Graph id {graph_id:?} is not included in current state chain");

    // (operator_total_work, included_watchtowers, graph_id, operator_genesis_sequencer_commit_txid, btc_best_block_hash)
    //(hash_operator_inputs(graph_id, operator_genesis_sequencer_commit_txid), btc_best_block_hash)
    println!("graph_id hex: {:?}", hex::encode(graph_id));
    println!(
        "operator_genesis_sequencer_commit_txid hex: {:?}",
        hex::encode(operator_genesis_sequencer_commit_txid)
    );
    let constant = hash_operator_constant(graph_id, operator_genesis_sequencer_commit_txid);
    println!("constant hex: {:?}", hex::encode(constant));

    println!("btc_best_block_hash hex: {:?}", hex::encode(btc_best_block_hash));
    println!("included_watchtowers: {:?}", hex::encode(included_watchtowers.to_le_bytes::<32>()));
    //let included = operator_header_chain
    //    .block_headers
    //    .iter()
    //    .position(|header| header.compute_block_hash() == operator_committed_blockhash);
    //assert!(included.is_some(), "operator committed blockhash is not included in header chain");
    assert!(
        operator_committed_blockhash == btc_best_block_hash,
        "operator committed blockhash is not included in header chain"
    );

    //operator_public_input
    (operator_committed_blockhash, constant, included_watchtowers.to_le_bytes::<32>())
}

pub fn hash_operator_constant(
    graph_id: [u8; GRAPH_ID_SIZE],
    operator_genesis_sequencer_commit_txid: [u8; 32],
) -> [u8; 32] {
    let mut engine = sha256::HashEngine::default();
    engine.input(&graph_id);
    engine.input(&operator_genesis_sequencer_commit_txid);
    let hash = sha256::Hash::from_engine(engine);
    *hash.as_byte_array()
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
    raw_txn: &Transaction,
    target_block_pos: u32,
    target_block: Block,
    block_headers: &[CircuitBlockHeader],
) -> SPV {
    let tx: CircuitTransaction = CircuitTransaction(raw_txn.clone());
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
) -> Vec<u8> {
    let mut comm = graph_id.to_vec();
    comm.extend_from_slice(proof);
    comm.extend_from_slice(public_inputs);
    assert_eq!(vk_hash.len(), VK_HASH_SIZE);
    comm.extend_from_slice(vk_hash.as_bytes());
    comm
}

pub type WatchtowerCommitmentResult = (
    [u8; GRAPH_ID_SIZE],
    [u8; PROOF_SIZE],
    [u8; PUBLIC_INPUTS_SIZE],
    [u8; VK_HASH_SIZE],
    [u8; TOTAL_WORK_SIZE],
    [u8; CONSENSUS_BLOCK_HEIGHT_SIZE],
);

pub fn parse_watchtower_commitment(
    commitment: &[u8],
) -> Result<WatchtowerCommitmentResult, String> {
    if commitment.len() != COMMITMENT_SIZE {
        return Err(format!(
            "invalid commitment size: {}, expected: {}",
            commitment.len(),
            COMMITMENT_SIZE
        ));
    }
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

    // extract ChainState
    let mut watchtower_total_work = [0u8; TOTAL_WORK_SIZE];
    watchtower_total_work.copy_from_slice(&zkm_public_values[0..TOTAL_WORK_SIZE]);
    let mut watchtower_consensus_block_height = [0u8; CONSENSUS_BLOCK_HEIGHT_SIZE];
    watchtower_consensus_block_height.copy_from_slice(
        &zkm_public_values[TOTAL_WORK_SIZE..TOTAL_WORK_SIZE + CONSENSUS_BLOCK_HEIGHT_SIZE],
    );

    println!("watchtower total work: {watchtower_total_work:?}");
    println!("watchtower total work: {:?}", U256::from_be_bytes(watchtower_total_work));
    println!("watchtower consensus block height: {watchtower_consensus_block_height:?}");
    println!(
        "watchtower consensus block height: {:?}",
        U32::from_le_bytes(watchtower_consensus_block_height)
    );

    Ok((
        graph_id,
        proof,
        zkm_public_values,
        zkm_vk_hash_bytes,
        watchtower_total_work,
        watchtower_consensus_block_height,
    ))
}

// Check the public values are consistent with the total work and block hash
pub fn verify_proof(
    proof: &[u8],
    zkm_public_values: &[u8],
    zkm_vk_hash: &[u8],
) -> Result<(), String> {
    let groth16_vk = *zkm_verifier::GROTH16_VK_BYTES;
    let zkm_vk_hash = String::from_utf8(zkm_vk_hash.to_vec()).map_err(|e| e.to_string())?;
    match Groth16Verifier::verify(proof, zkm_public_values, &zkm_vk_hash, groth16_vk) {
        Ok(_) => Ok(()),
        Err(err) => Err(format!("Verify Groth16 proof, err: {err:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Transaction;
    const PROOF: &[u8] = include_bytes!("../../../circuits/data/watchtower/output3.bin.proof.bin");
    const PUBLIC_INPUTS: &[u8] =
        include_bytes!("../../../circuits/data/watchtower/output3.bin.public_inputs.bin");
    const VK_HASH: &str = include_str!("../../../circuits/data/watchtower/output3.bin.vk_hash.bin");

    #[test]
    fn test_build_watchtower_commitment() {
        let graph_id = hex::decode("00112233445566778899aabbccddeeff").unwrap().try_into().unwrap();

        let total_work = 1006120;
        let block_height = 503043;
        println!("public inputs: {:?}", PUBLIC_INPUTS.len());
        println!("vk hash: {:?}", VK_HASH.len());
        let comm = build_watchtower_commitment(
            &graph_id,
            &PROOF.try_into().unwrap(),
            &PUBLIC_INPUTS.try_into().unwrap(),
            VK_HASH,
        );

        println!("comm: {:?}", comm.len());
        println!("comm hex: {:?}", hex::encode(&comm));
        let expected = parse_watchtower_commitment(&comm).unwrap();
        println!("expected: {:?}", expected);

        assert_eq!(expected.0, graph_id);
        assert_eq!(expected.1, PROOF);
        assert_eq!(expected.2, PUBLIC_INPUTS);
        assert_eq!(expected.3, VK_HASH.as_bytes());
        assert_eq!(expected.4, U256::from(total_work).to_be_bytes());
        assert_eq!(expected.5, U32::from(block_height).to_le_bytes());
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
    fn test_u256_to_le_bits() {
        use std::str::FromStr;
        // generate random u256
        let u = U256::from(rand::random::<u128>());
        let bits = u256_to_le_bits(u);
        let reconstructed = le_bits_to_u256(&bits);
        assert_eq!(u, reconstructed);

        let u_str = u.to_string();
        let u = U256::from_str(&u_str).unwrap();
        let bits = u256_to_le_bits(u);
        let reconstructed2 = le_bits_to_u256(&bits);
        assert_eq!(u, reconstructed);
        assert_eq!(u, reconstructed2);
        let reconstructed_str = reconstructed2.to_string();
        assert_eq!(u_str, reconstructed_str);
    }

    #[test]
    fn test_extract_data_from_commitment_outputs() {
        use bitcoin::consensus::encode::deserialize;
        // Testnet4 tx: 14b586e2e64e7b4b12aca96832d0703b9d218fa81e0ea84c1155a5749b28924b
        let bytes = hex::decode(
            "02000000000102c1eeed57e622af0fbb57e863a3b6284dc5ce6249804d0b6ce923bf81004188b00000000000fffffffff0679cdb8b16eebfbcd7fb4d582a20247857db4927f0f79388ba6735bdcd98f60b00000000ffffffff0c4a010000000000002200209bf28a9ccba44a0cbdd17ce6bb8262a136a08ac0088b0ec3f5ae484951f590dd4a01000000000000220020f65f87063cd8c00f539cb877d19a672b241066780a185357072e7da517286a1d4a0100000000000022002056dde473377f215234cf46258af2e2a5007a8e34206ecb438cef18906035c7384a01000000000000220020e77df8511565180c187f61ecdaf15fdc0bcd6076084a3a6823eb1e7fbb4e5af74a01000000000000220020ee98e7229e9a7ac2269cf2c493ff09f1c8b64f5116f5c3662be80640f8a11e144a01000000000000220020a2703885ba63f87d5bde5c3f085a7343e09eaef408074390d2081ff325cc6e894a0100000000000022002038e7a277db470a65c1075e58053075fe83944c621e43601f2b77e18e597c1cbe4a01000000000000220020ad89f2340414b9209003047abdf53716103ff6e71bd1f04c17055c33859124e84a010000000000002200207024bc980d3fa0d5715d859f2e036164414bbdcf0000000000000000000000004a01000000000000220020000000000000000000000938e7e6f31c23766897f6d40100307830306562643200000000000000003c6a3a353862363863396134373432343339653636393834306432306265626665346562643236393366636138323463386430623065346531366233368726980000000000220020082778653debae3a77067cc2c165ae2294c4c6984515aabe977dde1d8e39365103412853f869fd7d8a3e97fd095e6dce63be7e13b172f70e6c92b4ad968af671b3b1f72113b8d2a2a3749c02fc1241110081d8b8ba3686fc6e9b157530ba2fc41bef81222076c09522e2614dadf1471e456abf567b1756465a4133cedc7a0780b277f7e954ac41c076c09522e2614dadf1471e456abf567b1756465a4133cedc7a0780b277f7e954d391bf91c2d0eb83acda477b90f5efbfa4e4d1388e31690a6de57ff01c93f2e202473044022006feb2824f0d733e11c98ea52b0c2aaa1e6bc4c4223287959addbe2e33ebb71202203a1d4613db8eadf3e8d65e46b94e4027d3e6435a2abffd8aeefbc8bd4858f7a50123210376c09522e2614dadf1471e456abf567b1756465a4133cedc7a0780b277f7e954ac00000000"
        ).unwrap();
        let tx: Transaction = deserialize(&bytes).unwrap();

        let commitment = extract_data_from_commitment_outputs(&tx.output);
        let (
            parsed_graph_id,
            _proof,
            _public_values,
            _vk,
            _watchtower_total_work,
            _watchtower_consensus_block_height,
        ) = parse_watchtower_commitment(&commitment).unwrap();
        assert_eq!(hex::encode(parsed_graph_id), "9bf28a9ccba44a0cbdd17ce6bb8262a1");
    }
}
