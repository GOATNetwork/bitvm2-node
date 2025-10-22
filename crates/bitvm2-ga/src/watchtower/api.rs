use anyhow::{Result, bail};
use bitcoin::{Address, Amount, OutPoint, Transaction, XOnlyPublicKey, key::Keypair};
use goat::{
    connectors::watchtower_connectors::{AckConnector, WatchtowerChallengeConnector},
    transactions::{
        base::Input, pre_signed::PreSignedTransaction, watchtower_challenge::watchtower_challenge,
    },
};

use crate::types::Bitvm2Graph;

pub fn estimate_watchtower_challenge_vbytes(commitment_data_len: usize) -> usize {
    let base_vbytes = 120;
    let commitment_vbytes = commitment_data_len * 12 / 10; // assuming 1.2 vbytes per byte of commitment data
    base_vbytes + commitment_vbytes
}

pub fn build_watchtower_challenge_tx(
    graph: &Bitvm2Graph,
    watchtower_keypair: &Keypair,
    watchtower_index: usize,
    commitment_data: &[u8],
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
    let watchtower_challenge_connector_vout = watchtower_index * 2;
    let watchtower_challenge_connector_amount = graph
        .watchtower_challenge_init
        .tx()
        .output
        .get(watchtower_challenge_connector_vout)
        .ok_or_else(|| anyhow::anyhow!("watchtower index out of bounds"))?
        .value;
    let input_0 = Input {
        outpoint: OutPoint {
            txid: graph.watchtower_challenge_init.tx().compute_txid(),
            vout: watchtower_challenge_connector_vout as u32,
        },
        amount: watchtower_challenge_connector_amount,
    };
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
        Err(e) => bail!("Failed to build watchtower challenge transaction: {e}"),
    }
}
