use crate::types::{Bitvm2Graph, VerifyingKey};
use anyhow::{Result, bail};
use bitcoin::{Amount, ScriptBuf, Transaction, TxIn, TxOut, XOnlyPublicKey};
use bitvm::chunk::api::{
    NUM_HASH, NUM_PUBS, NUM_TAPS, NUM_U256, type_conversion_utils::RawWitness,
};
use goat::{
    connectors::{
        assert_connectors::{extract_commits_from_txin, extract_commits_from_txins},
        connector_e::ConnectorE,
    },
    disprove_scripts::{GUEST_VALIDATION_TAPS, NUM_GUEST_PUBS_ASSERT, NUM_GUEST_PUBS_EXTRA},
    scripts::generate_opreturn_script,
    transactions::{
        base::Input,
        disprove::{disprove, validate_assert},
        pre_signed::PreSignedTransaction,
        watchtower_challenge::extract_operator_preimage_from_ack_txin,
    },
};

pub fn extract_blockhash_commit_witness(
    operator_commit_blockhash_txin: &TxIn,
) -> Result<Vec<RawWitness>> {
    match extract_commits_from_txin(operator_commit_blockhash_txin, NUM_GUEST_PUBS_EXTRA, 0) {
        Ok(v) => Ok(v),
        Err(e) => bail!("Failed to extract blockhash commit witness: {}", e),
    }
}

pub fn extract_assert_commit_witness(
    operator_assert_commit_txins: Vec<TxIn>,
) -> Result<Vec<RawWitness>> {
    match extract_commits_from_txins(
        operator_assert_commit_txins,
        NUM_GUEST_PUBS_ASSERT + NUM_PUBS + NUM_U256,
        NUM_HASH,
    ) {
        Ok(v) => Ok(v),
        Err(e) => bail!("Failed to extract assert commit witness: {}", e),
    }
}

// return (if any) disprove witness
pub fn verify_operator_commits(
    operator_commit_blockhash_txin: &TxIn,
    operator_assert_commit_txins: Vec<TxIn>,
    operator_ack_txins: Vec<TxIn>,
    watchtower_num: usize,
    vk: &VerifyingKey,
    guest_validation_scripts: &[ScriptBuf; GUEST_VALIDATION_TAPS],
    proof_validation_scripts: &[ScriptBuf; NUM_TAPS],
) -> Result<Option<(RawWitness, ScriptBuf)>> {
    let mut preimages = vec![vec![]; watchtower_num];
    for txin in &operator_ack_txins {
        let watchtower_index = txin.previous_output.vout as usize / 2;
        if watchtower_index >= watchtower_num || txin.previous_output.vout % 2 != 1 {
            bail!(
                "invalid ack txin in operator_ack_txins, unexpected vout: {}",
                txin.previous_output.vout
            );
        }
        let preimage = extract_operator_preimage_from_ack_txin(txin)
            .map_err(|e| anyhow::anyhow!("Failed to extract preimage from ack txin: {}", e))?;
        preimages[watchtower_index] = preimage;
    }
    Ok(validate_assert(
        extract_blockhash_commit_witness(operator_commit_blockhash_txin)?,
        extract_assert_commit_witness(operator_assert_commit_txins)?,
        preimages,
        guest_validation_scripts,
        vk,
        proof_validation_scripts,
    ))
}

// challenge has a pre-signed SinglePlusAnyoneCanPay input and output
// get incomplete tx here, add inputs with enough amount, then broadcast it to start challnege progress
pub fn export_challenge_tx(graph: &mut Bitvm2Graph) -> Result<(Transaction, Amount)> {
    if !graph.operator_pre_signed() {
        bail!("missing pre-signatures from operator")
    };
    Ok((graph.challenge.tx().clone(), graph.challenge.challenge_amount))
}

// disprove has a huge disprove input and an optional op_return output
// get incomplete tx here, add inputs with enough amount, then broadcast it to finish challnege progress
pub fn sign_disprove(
    graph: &mut Bitvm2Graph,
    connector_e_input: &Input,
    disprove_witness: (RawWitness, ScriptBuf),
    disprove_scripts: Vec<ScriptBuf>,
    disprover_evm_address: Option<[u8; 20]>,
) -> Result<Transaction> {
    if !graph.committee_pre_signed() {
        bail!("missing pre-signatures from committee")
    };
    let network = graph.parameters.instance_parameters.network;
    let operator_pubkey = graph.parameters.operator_pubkey;
    let operator_taproot_public_key = XOnlyPublicKey::from(operator_pubkey);
    let (_, connector_e_taproot_spend_info) =
        ConnectorE::new_with_scripts(network, &operator_taproot_public_key, disprove_scripts);
    let (input_script_witness, input_lock_script) = disprove_witness;
    let disprove_txin = disprove(
        &connector_e_taproot_spend_info,
        connector_e_input,
        input_script_witness,
        input_lock_script,
    )
    .map_err(|e| anyhow::anyhow!("Failed to create disprove txin: {}", e))?;
    let mut disprove_tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![disprove_txin],
        output: vec![],
    };

    // write challenger's l2 address to an op_return output
    if let Some(disprover_evm_address) = disprover_evm_address {
        disprove_tx.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: generate_opreturn_script(disprover_evm_address.to_vec()),
        });
    }

    Ok(disprove_tx)
}

// TODO sign other transactions