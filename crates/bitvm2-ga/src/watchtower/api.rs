use anyhow::{Result, bail};
use bitcoin::{Address, Amount, Transaction, XOnlyPublicKey, key::Keypair};
use goat::{
    connectors::watchtower_connectors::{AckConnector, WatchtowerChallengeConnector},
    transactions::{base::Input, watchtower_challenge::watchtower_challenge},
};

use crate::types::Bitvm2Graph;

pub fn estimate_watchtower_challenge_shortfall(
    _commitment_data_len: usize,
    _payer_inputs_len: usize,
) -> usize {
    // TODO
    panic!("Not implemented yet")
}

pub fn build_watchtower_challenge_tx(
    graph: &Bitvm2Graph,
    watchtower_keypair: &Keypair,
    watchtower_index: usize,
    commitment_data: &[u8],
    input_0: Input,
    payer_inputs: Vec<Input>,
    change_address: &Address,
    fee_amount: Amount,
) -> Result<Transaction> {
    if watchtower_index >= graph.parameters.watchtower_pubkeys.len() {
        bail!("Invalid watchtower index");
    }
    let network = graph.parameters.instance_parameters.network;
    let n_of_n_taproot_public_key =
        XOnlyPublicKey::from(graph.parameters.instance_parameters.committee_agg_pubkey);
    let operator_taproot_public_key = XOnlyPublicKey::from(graph.parameters.operator_pubkey);
    let watchtower_taproot_public_key =
        XOnlyPublicKey::from(graph.parameters.watchtower_pubkeys[watchtower_index]);
    let hashlock = graph.parameters.hashlocks[watchtower_index];
    let watchtower_connectors = (
        WatchtowerChallengeConnector::new(
            network,
            &operator_taproot_public_key,
            &watchtower_taproot_public_key,
        ),
        AckConnector::new(network, &n_of_n_taproot_public_key, &hashlock),
    );
    if XOnlyPublicKey::from_keypair(watchtower_keypair).0 != watchtower_taproot_public_key {
        bail!("Watchtower keypair does not match the watchtower public key");
    }
    match watchtower_challenge(
        watchtower_keypair,
        &watchtower_connectors,
        commitment_data,
        input_0,
        payer_inputs,
        change_address,
        fee_amount,
    ) {
        Ok(tx) => Ok(tx),
        Err(e) => bail!("Failed to build watchtower challenge transaction: {}", e),
    }
}
