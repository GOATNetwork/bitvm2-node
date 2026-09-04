use anyhow::{Result, bail};
use bitcoin::{Address, Amount, Transaction, key::Keypair};
use goat::transactions::{base::Input, watchtower_challenge::watchtower_challenge};

use crate::types::BitvmGcGraph;

pub fn estimate_watchtower_challenge_vbytes(commitment_data_len: usize) -> usize {
    120 + commitment_data_len.saturating_mul(12) / 10
}

pub fn build_watchtower_challenge_tx(
    graph: &BitvmGcGraph,
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
    let watchtower_challenge_connector = graph.watchtower_challenge_connector(watchtower_index)?;
    let input_0 = graph
        .watchtower_challenge_init
        .watchtower_connector_input(watchtower_index)
        .map_err(|e| anyhow::anyhow!("failed to get watchtower connector input: {e}"))?;

    watchtower_challenge(
        watchtower_keypair,
        &watchtower_challenge_connector,
        commitment_data,
        input_0,
        payer_inputs,
        change_address,
        fee_amount,
    )
    .map_err(|e| anyhow::anyhow!("failed to build watchtower challenge transaction: {e}"))
}
