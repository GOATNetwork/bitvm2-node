use crate::types::{
    Bitvm2Graph, Groth16WotsPublicKeys, Groth16WotsSignatures, VerifyingKey, WotsPublicKeys,
};
use anyhow::{Result, bail};
use bitcoin::{Address, Amount, ScriptBuf, Transaction, TxOut, XOnlyPublicKey};
use bitvm::chunk::api::{
    NUM_TAPS,
    type_conversion_utils::{RawWitness, script_to_witness, utils_signatures_from_raw_witnesses},
    validate_assertions,
};
use bitvm::treepp::*;
use goat::transactions::assert::utils::*;
use goat::transactions::{base::BaseTransaction, pre_signed::PreSignedTransaction};
use goat::{
    connectors::connector_c::{ConnectorC, get_commit_from_assert_commit_tx},
    scripts::generate_opreturn_script,
    transactions::base::DUST_AMOUNT,
};

pub fn extract_proof_sigs_from_assert_commit_txns(
    assert_commit_txns: [Transaction; COMMIT_TX_NUM],
) -> Result<Groth16WotsSignatures> {
    let raw_wits: Vec<RawWitness> =
        assert_commit_txns.iter().flat_map(get_commit_from_assert_commit_tx).collect();
    Ok(utils_signatures_from_raw_witnesses(&raw_wits))
}

// return (if any) disprove witness
pub fn verify_proof(
    ark_vkey: &VerifyingKey,
    proof_sigs: Groth16WotsSignatures,
    disprove_scripts: &[ScriptBuf; NUM_TAPS],
    wots_pubkeys: &WotsPublicKeys,
) -> Option<(usize, Script)> {
    validate_assertions(ark_vkey, proof_sigs, *wots_pubkeys.1, disprove_scripts)
}

// challenge has a pre-signed SinglePlusAnyoneCanPay input and output
// get incomplete tx here, add inputs with enough amount, then broadcast it to start challnege progress
pub fn export_challenge_tx(graph: &mut Bitvm2Graph) -> Result<(Transaction, Amount)> {
    if !graph.operator_pre_signed() {
        bail!("missing pre-signatures from operator")
    };
    Ok((graph.challenge.tx().clone(), Amount::from_sat(graph.challenge.min_crowdfunding_amount())))
}

pub fn sign_disprove(
    graph: &mut Bitvm2Graph,
    disprove_witness: (usize, Script),
    disprove_scripts_bytes: Vec<ScriptBuf>,
    assert_wots_pubkeys: &Groth16WotsPublicKeys,
    challenger_evm_address: Option<[u8; 20]>,
    reward_address: Option<Address>,
    fee_rate: f64,
) -> Result<Transaction> {
    if !graph.committee_pre_signed() {
        bail!("missing pre-signatures from committee")
    };
    let assert_wots_commitment_keys =
        convert_to_connector_c_commits_public_key(assert_wots_pubkeys);
    let connector_c = ConnectorC::new_from_scripts(
        graph.parameters.network,
        &XOnlyPublicKey::from(graph.parameters.operator_pubkey),
        assert_wots_commitment_keys,
        disprove_scripts_bytes,
    );
    graph.disprove.sign_input_1(
        &connector_c,
        disprove_witness.0 as u32,
        script_to_witness(disprove_witness.1),
    );

    // write challenger's l2 address to an op_return output
    if let Some(challenger_evm_address) = challenger_evm_address {
        graph.disprove.tx_mut().output.insert(
            1,
            TxOut {
                script_pubkey: generate_opreturn_script(challenger_evm_address.to_vec()),
                value: Amount::ZERO,
            },
        );
    }

    // add reward output
    if let Some(reward_address) = reward_address {
        graph.disprove.tx_mut().output.push(TxOut {
            script_pubkey: reward_address.script_pubkey(),
            value: Amount::from_sat(DUST_AMOUNT),
        });
        let fee_amount = Amount::from_sat(
            (graph.disprove.tx().weight().to_vbytes_ceil() as f64 * fee_rate).ceil() as u64,
        );
        let mut reward_txout = graph.disprove.tx_mut().output.pop().unwrap();
        let remaining_output_amount =
            graph.disprove.prev_outs().iter().map(|txout| txout.value).sum::<Amount>()
                - graph.disprove.tx().output.iter().map(|txout| txout.value).sum();
        if remaining_output_amount > fee_amount {
            reward_txout.value += remaining_output_amount - fee_amount;
            graph.disprove.tx_mut().output.push(reward_txout);
        }
    }

    Ok(graph.disprove.finalize())
}
