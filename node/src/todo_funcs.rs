#![allow(dead_code, unreachable_code, unused_variables)]
use crate::env::*;
use crate::error::SpecialError;
use crate::utils::verify_graph_endorsement;
use alloy::primitives::Address as EvmAddress;
use anyhow::{Result, bail};
use bitcoin::{
    Amount, Network,
    PublicKey,
};
use bitvm2_lib::keys::OperatorMasterKey;
use bitvm2_lib::types::{
    Bitvm2Graph, SimplifiedBitvm2Graph,
};
use client::{btc_chain::BTCClient, goat_chain::GOATClient};
use goat::connectors::assert_connectors::chunk_assert_commit;
use goat::disprove_scripts::NUM_GUEST_PUBS_ASSERT;
use store::ipfs::IPFS;
use store::localdb::LocalDB;

use bitvm::chunk::api::{NUM_HASH, NUM_PUBS, NUM_U256};
use uuid::Uuid;

pub async fn get_operator_proof_blockhash(instance_id: Uuid, graph_id: Uuid) -> Result<[u8; 32]> {
    Ok([0xbbu8; 32])
}
pub async fn get_guest_constant_value(instance_id: Uuid, graph_id: Uuid) -> Result<[u8; 32]> {
    Ok([0xccu8; 32])
}

// other operations
pub fn avg_block_time_secs(network: Network) -> u64 {
    match network {
        Network::Bitcoin => 600,  // 10 minutes
        Network::Testnet => 300,  // 5 minutes
        Network::Testnet4 => 300, // 5 minutes
        Network::Regtest => 60,   // 1 minute
        Network::Signet => 60,    // 1 minute
                                   // _ => 600,                // default to 10 minutes
    }
}
pub fn assert_commmit_num() -> usize {
    let use_compact = false;
    let wots32_num = NUM_GUEST_PUBS_ASSERT + NUM_PUBS + NUM_U256;
    let wots16_num = NUM_HASH;
    chunk_assert_commit(wots32_num, wots16_num, use_compact).len()
}
pub fn min_required_operator() -> usize {
    // todo!("get min required operator number")
    1
}
pub fn min_required_watchtower() -> usize {
    // todo!("get min required watchtower number")
    1
}
pub async fn publish_graph_to_ipfs(ipfs: &IPFS, graph: &Bitvm2Graph) -> Result<String> {
    todo!("publish graph to ipfs")
}
pub async fn validate_init_graph(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    graph: &SimplifiedBitvm2Graph,
) -> Result<()> {
    // Basic structural and on-chain consistency checks for an incoming graph proposal.
    // Return SpecialError::InvalidGraph on any validation failure.
    // 1) Rebuild full graph (ensures signatures present if flags are set and tx graph is coherent)
    let full_graph = Bitvm2Graph::from_simplified(graph)
        .map_err(|e| SpecialError::InvalidGraph(format!("invalid graph structure: {e}")))?;

    // 2) Network must match local node network
    let net = get_network();
    if graph.parameters.instance_parameters.network != net {
        bail!(SpecialError::InvalidGraph(format!(
            "network mismatch: graph={:?} local={:?}",
            graph.parameters.instance_parameters.network, net
        )));
    }

    // 3) Committee pubkeys must match what's registered on GoatChain for this instance
    let instance_id = graph.parameters.instance_parameters.instance_id;
    let committee_on_chain =
        goat_client.gateway_get_committee_pubkeys(&instance_id).await.map_err(|e| {
            SpecialError::InvalidGraph(format!("failed to load committee from chain: {e}"))
        })?;
    if committee_on_chain != graph.parameters.instance_parameters.committee_pubkeys {
        bail!(SpecialError::InvalidGraph("committee pubkeys mismatch with GoatChain".to_string()));
    }

    // 4) Challenge amount and assert-commit count must match local constants
    if graph.parameters.challenge_amount != super::todo_funcs::challenge_amount() {
        bail!(SpecialError::InvalidGraph("unexpected challenge amount".to_string()));
    }
    if graph.assert_commit_num != super::todo_funcs::assert_commmit_num() {
        bail!(SpecialError::InvalidGraph("unexpected assert_commit_num".to_string()));
    }

    // 5) Watchtower config sanity: number of watchtowers should match number of hashlocks and registry size
    let watchtowers_on_chain = goat_client.committee_mana_get_watchtowers().await.map_err(|e| {
        SpecialError::InvalidGraph(format!("failed to load watchtowers from chain: {e}"))
    })?;
    if graph.parameters.watchtower_pubkeys.len() != graph.parameters.hashlocks.len() {
        bail!(SpecialError::InvalidGraph(
            "watchtower_pubkeys and hashlocks length mismatch".to_string()
        ));
    }
    // deduplicate watchtower pubkeys: reject graphs that contain duplicate watchtower entries
    {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for pk in &graph.parameters.watchtower_pubkeys {
            if !seen.insert(*pk) {
                bail!(SpecialError::InvalidGraph(
                    "duplicate watchtower pubkey in graph".to_string()
                ));
            }
        }
    }
    // allow unregistered watchtowers as long as enough registered ones exist
    let required = super::todo_funcs::min_required_watchtower();
    let valid_registered = graph
        .parameters
        .watchtower_pubkeys
        .iter()
        .filter(|pk| watchtowers_on_chain.contains(pk))
        .count();
    if valid_registered < required {
        bail!(SpecialError::InvalidGraph(format!(
            "insufficient registered watchtowers: have {valid_registered}, required {required}"
        )));
    }

    // 6) Operator stake sanity: verify operator is registered and has enough locked stake
    let op_pk_bytes = graph.parameters.operator_pubkey.to_bytes();
    let xonly: [u8; 32] = op_pk_bytes[1..33]
        .try_into()
        .map_err(|_| SpecialError::InvalidGraph("invalid operator pubkey".to_string()))?;
    let operator_addr = goat_client.stake_mana_pubkey_to_address(&xonly).await.map_err(|e| {
        SpecialError::InvalidGraph(format!("failed to query operator address: {e}"))
    })?;
    if operator_addr == [0u8; 20] {
        bail!(SpecialError::InvalidGraph("operator not registered".to_string()));
    }
    let min_stake_amount = goat_client.gateway_get_min_stake_amount().await.map_err(|e| {
        SpecialError::InvalidGraph(format!("failed to query min stake amount: {e}"))
    })?;
    let locked_stake = goat_client.stake_mana_lock_stake_of(&operator_addr).await.map_err(|e| {
        SpecialError::InvalidGraph(format!("failed to query operator locked stake: {e}"))
    })?;
    if locked_stake < min_stake_amount {
        bail!(SpecialError::InvalidGraph(format!(
            "insufficient operator stake: locked={locked_stake}, min={min_stake_amount}"
        )));
    }

    Ok(())
}
pub async fn validate_finalized_graph(
    goat_client: &GOATClient,
    graph: &SimplifiedBitvm2Graph,
    endorse_sigs: &[(PublicKey, EvmAddress, Vec<u8>)],
) -> Result<()> {
    // 1) Rebuild full graph to ensure structure is coherent and txns derivable
    let full_graph = Bitvm2Graph::from_simplified(graph)
        .map_err(|e| SpecialError::InvalidGraph(format!("invalid graph structure: {e}")))?;

    // 2) Repeat key static checks (network, committee set, counts)
    let net = get_network();
    if graph.parameters.instance_parameters.network != net {
        bail!(SpecialError::InvalidGraph(format!(
            "network mismatch: graph={:?} local={:?}",
            graph.parameters.instance_parameters.network, net
        )));
    }
    let instance_id = graph.parameters.instance_parameters.instance_id;
    let committee_on_chain =
        goat_client.gateway_get_committee_pubkeys(&instance_id).await.map_err(|e| {
            SpecialError::InvalidGraph(format!("failed to load committee from chain: {e}"))
        })?;
    if committee_on_chain != graph.parameters.instance_parameters.committee_pubkeys {
        bail!(SpecialError::InvalidGraph("committee pubkeys mismatch with GoatChain".to_string()));
    }
    if graph.parameters.watchtower_pubkeys.len() != graph.parameters.hashlocks.len() {
        bail!(SpecialError::InvalidGraph(
            "watchtower_pubkeys and hashlocks length mismatch".to_string()
        ));
    }
    if graph.parameters.challenge_amount != super::todo_funcs::challenge_amount() {
        bail!(SpecialError::InvalidGraph("unexpected challenge amount".to_string()));
    }
    if graph.assert_commit_num != super::todo_funcs::assert_commmit_num() {
        bail!(SpecialError::InvalidGraph("unexpected assert_commit_num".to_string()));
    }

    // 3) Validate endorsements: unique, from legitimate committee members, and signatures recover to the provided EVM address
    use std::collections::HashSet;
    let mut seen_committee: HashSet<PublicKey> = HashSet::new();
    let mut seen_evm: HashSet<EvmAddress> = HashSet::new();
    let pegin_data = goat_client
        .gateway_get_pegin_data(&instance_id)
        .await
        .map_err(|e| SpecialError::InvalidGraph(format!("failed to load instance data: {e}")))?;

    for (pk, evm_addr, sig) in endorse_sigs.iter() {
        // no duplicates
        if !seen_committee.insert(*pk) {
            bail!(SpecialError::InvalidGraph(
                "duplicate committee pubkey in endorsements".to_string()
            ));
        }
        if !seen_evm.insert(*evm_addr) {
            bail!(SpecialError::InvalidGraph("duplicate evm address in endorsements".to_string()));
        }

        // map pubkey -> expected evm address from GoatChain
        let mut found = false;
        for i in 0..pegin_data.committee_pubkeys.len() {
            let on_chain_pk =
                PublicKey::from_slice(&pegin_data.committee_pubkeys[i]).map_err(|e| {
                    SpecialError::InvalidGraph(format!("invalid committee pubkey on-chain: {e}"))
                })?;
            if &on_chain_pk == pk {
                found = true;
                let expected_addr = pegin_data.committee_addresses[i];
                if &expected_addr != evm_addr {
                    bail!(SpecialError::InvalidGraph("committee evm address mismatch".to_string()));
                }
                break;
            }
        }
        if !found {
            bail!(SpecialError::InvalidGraph("endorser not in committee set".to_string()));
        }

        // cryptographically verify the endorsement against the graph digest
        let ok = verify_graph_endorsement(goat_client, evm_addr, &full_graph, sig)
            .await
            .map_err(|e| {
                SpecialError::InvalidGraph(format!("failed to verify endorsement: {e}"))
            })?;
        if !ok {
            bail!(SpecialError::InvalidGraph("invalid endorsement signature".to_string()));
        }
    }

    Ok(())
}
pub fn prekickoff_replenishment_amount() -> Amount {
    Amount::from_sat(500000)
}
pub fn min_prekickoff_input_amount() -> Amount {
    Amount::from_sat(100000)
}
pub fn challenge_amount() -> Amount {
    Amount::from_sat(20000)
}
pub fn prekickoff_fee_amount(replenish_fee_inputs_num: usize) -> Amount {
    let tx_vbytes =
        PRE_KICKOFF_BASE_VBYTES + (replenish_fee_inputs_num as u64 * CHEKSIG_P2WSH_INPUT_VBYTES);
    Amount::from_sat(tx_vbytes)
}
pub async fn get_preimage(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    index: usize,
) -> Result<Vec<u8>> {
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    Ok(operator_master_key.preimage_for_graph(graph_id, index))
}
