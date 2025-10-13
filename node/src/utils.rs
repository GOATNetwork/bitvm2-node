use crate::action::{ChallengeSent, GOATMessage, GOATMessageContent, NodeInfo, send_to_peer};
use crate::env::*;
use crate::error::SpecialError;
use crate::middleware::AllBehaviours;
use crate::rpc_service::proof::Groth16ProofValue;
use crate::rpc_service::{current_time_secs, routes};
use alloy::primitives::Address as EvmAddress;
use alloy::providers::ProviderBuilder;
use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::key::Keypair;
use bitcoin::{
    Address, Amount, CompressedPublicKey, EcdsaSighashType, Network, OutPoint, PrivateKey,
    PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, XOnlyPublicKey,
};
use bitvm::treepp::*;
use bitvm2_lib::actors::Actor;
use bitvm2_lib::challenger::*;
use bitvm2_lib::committee::*;
use bitvm2_lib::keys::{ChallengerMasterKey, OperatorMasterKey, WatchtowerMasterKey};
use bitvm2_lib::operator::*;
use bitvm2_lib::types::{
    Bitvm2Graph, Bitvm2InstanceParameters, Groth16Proof, PublicInputs, UserInfo, VerifyingKey,
};
use bitvm2_lib::watchtower::*;
use client::Utxo as ClientUtxo;
use client::goat_chain::utils::{validate_committee, validate_operator, validate_relayer};
use client::goat_chain::{DisproveTxType, WithdrawStatus};
use client::graphs::graph_query::BridgeInRequestEvent;
use client::{btc_chain::BTCClient, goat_chain::GOATClient};
use esplora_client::Utxo;
use goat::contexts::base::generate_n_of_n_public_key;
use goat::scripts::{generate_burn_script_address, generate_opreturn_script};
use goat::transactions::base::Input;
use goat::transactions::pre_signed::PreSignedTransaction;
use goat::transactions::signing::populate_p2wsh_witness;
use libp2p::Swarm;
use rand::Rng;
use secp256k1::Secp256k1;

use anyhow::{Result, anyhow, bail};
use bitcoin::hashes::Hash;
use indexmap::IndexMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use store::ipfs::IPFS;
use store::localdb::{InstanceUpdate, LocalDB, StorageProcessor};
use store::{
    ByteArray32, GoatTxProceedWithdrawExtra, GoatTxProcessingStatus, GoatTxRecord, GoatTxType,
    Graph, GraphRawData, GraphStatus, Instance, InstanceStatus, Message, MessageState, Node,
    UInt64Array3,
};
use stun_client::{Attribute, Class, Client};

use crate::env;
use crate::scheduled_tasks::get_goat_message_content_type;
use bitvm2_lib::transactions::base::BaseTransaction;
use client::goat_chain::{PeginData, PeginStatus, WithdrawData};
use tracing::warn;
use uuid::Uuid;

pub mod todo_funcs {
    #![allow(dead_code, unreachable_code, unused_variables)]
    use bitvm2_lib::types::{
        Bitvm2GraphParameters, GuestInputs, PrekickoffParameters, SimplifiedBitvm2Graph,
    };
    use goat::transactions::prekickoff::PrekickoffTransaction;
    use libp2p::PeerId;
    use musig2::{PartialSignature, PubNonce};

    use super::*;

    // contract calls
    pub async fn get_pegin_data(goat_client: &GOATClient, instance_id: Uuid) -> Result<PeginData> {
        todo!("call Gateway.getPeginData(instance_id) on goat chain")
    }
    pub async fn get_withdraw_data(
        goat_client: &GOATClient,
        graph_id: &Uuid,
    ) -> Result<WithdrawData> {
        todo!("call Gateway.withdrawDataMap(graph_id) on goat chain")
    }
    pub async fn get_goat_confirmed_btc_height(goat_client: &GOATClient) -> Result<u32> {
        todo!("call bitcoinSPV.latestConfirmedHeight() on goat chain")
    }
    pub async fn get_committee_pubkeys(
        goat_client: &GOATClient,
        instance_id: Uuid,
    ) -> Result<Vec<PublicKey>> {
        // if getCommitteePubkeys reverts, return SpecialError::EvmReverted(ReasonString)
        todo!("call Gateway.getCommitteePubkeys(instance_id) on goat chain")
    }
    pub async fn answer_pegin_request(
        goat_client: &GOATClient,
        instance_id: Uuid,
        pubkey_for_instance: PublicKey,
    ) -> Result<()> {
        todo!("call Gateway.answerPeginRequest on goat chain")
    }
    pub async fn get_graph_digest(
        local_db: &LocalDB,
        goat_client: &GOATClient,
        instance_id: Uuid,
        graph_id: Uuid,
    ) -> Result<[u8; 32]> {
        todo!("call Gateway.getPostGraphDigest(instance_id, graph_id, graphData) on goat chain")
    }

    // db operations
    pub async fn get_current_prekickoff_tx(
        local_db: &LocalDB,
        operator_pubkey: &PublicKey,
    ) -> Result<Option<(u64, PrekickoffTransaction)>> {
        // return (latest_graph.nonce + 1 , latest_graph.next_prekickoff_tx)
        // return None if no graph yet
        todo!("get current graph nonce & prekickoff tx from local db")
    }
    pub async fn store_pegin_request(
        local_db: &LocalDB,
        instance_id: Uuid,
        user_info: UserInfo,
        pegin_amount: Amount,
    ) -> Result<()> {
        todo!("store instance info to local db")
    }
    pub async fn store_instance_parameters(
        local_db: &LocalDB,
        instance_params: &Bitvm2InstanceParameters,
    ) -> Result<()> {
        todo!("store instance params to local db")
    }
    pub async fn get_instance_parameters(
        local_db: &LocalDB,
        instance_id: Uuid,
    ) -> Result<Option<Bitvm2InstanceParameters>> {
        todo!("get instance params from local db")
    }
    pub async fn store_graph(local_db: &LocalDB, graph: &SimplifiedBitvm2Graph) -> Result<()> {
        todo!("store graph to local db")
    }
    pub async fn get_graph(
        local_db: &LocalDB,
        instance_id: Uuid,
        graph_id: Uuid,
    ) -> Result<Option<SimplifiedBitvm2Graph>> {
        todo!("get graph from local db")
    }
    pub async fn store_committee_pub_nonces_for_graph(
        local_db: &LocalDB,
        instance_id: Uuid,
        graph_id: Uuid,
        committee_pubkey: PublicKey,
        pub_nonces: CommitteePubNonces,
    ) -> Result<()> {
        // update if exists, insert if not exists
        todo!("store_committee_pub_nonces")
    }
    pub async fn get_committee_pub_nonces_for_graph(
        local_db: &LocalDB,
        instance_id: Uuid,
        graph_id: Uuid,
    ) -> Result<Vec<(PublicKey, CommitteePubNonces)>> {
        todo!("get_committee_pub_nonces")
    }
    pub async fn store_committee_partial_sigs_for_graph(
        local_db: &LocalDB,
        instance_id: Uuid,
        graph_id: Uuid,
        committee_pubkey: PublicKey,
        partial_sigs: CommitteePartialSignatures,
    ) -> Result<()> {
        // update if exists, insert if not exists
        todo!("store_committee_partial_sigs")
    }
    pub async fn get_committee_partial_sigs_for_graph(
        local_db: &LocalDB,
        instance_id: Uuid,
        graph_id: Uuid,
    ) -> Result<Vec<(PublicKey, CommitteePartialSignatures)>> {
        todo!("get_committee_partial_sigs")
    }
    pub async fn store_committee_endorsement_for_graph(
        local_db: &LocalDB,
        instance_id: Uuid,
        graph_id: Uuid,
        committee_pubkey: PublicKey,
        committee_evm_address: EvmAddress,
        endorse_signature: Vec<u8>,
    ) -> Result<()> {
        // update if exists, insert if not exists
        todo!("store_committee_endorsement")
    }
    pub async fn store_committee_endorsements_for_graph(
        local_db: &LocalDB,
        instance_id: Uuid,
        graph_id: Uuid,
        endorse_sigs: Vec<(PublicKey, EvmAddress, Vec<u8>)>,
    ) -> Result<()> {
        // update if exists, insert if not exists
        todo!("store_committee_endorsements")
    }
    pub async fn get_committee_endorsements_for_graph(
        local_db: &LocalDB,
        instance_id: Uuid,
        graph_id: Uuid,
    ) -> Result<Vec<(PublicKey, EvmAddress, Vec<u8>)>> {
        todo!("get_committee_endorsement")
    }
    pub async fn mark_graph_as_endorsed(
        local_db: &LocalDB,
        instance_id: Uuid,
        graph_id: Uuid,
    ) -> Result<()> {
        todo!("mark graph as endorsed")
    }
    pub async fn get_endorsed_graph_count(local_db: &LocalDB, instance_id: Uuid) -> Result<usize> {
        todo!("get number of endorsed graphs for the instance")
    }
    pub async fn store_committee_pub_nonce_for_instance(
        local_db: &LocalDB,
        instance_id: Uuid,
        committee_pubkey: PublicKey,
        pub_nonce: PubNonce,
    ) -> Result<()> {
        // update if exists, insert if not exists
        todo!("store_committee_pub_nonce")
    }
    pub async fn get_committee_pub_nonce_for_instance(
        local_db: &LocalDB,
        instance_id: Uuid,
        committee_pubkey: &PublicKey,
    ) -> Result<Option<PubNonce>> {
        todo!("get_committee_pub_nonce")
    }
    pub async fn get_committee_pub_nonces_for_instance(
        local_db: &LocalDB,
        instance_id: Uuid,
    ) -> Result<Vec<(PublicKey, PubNonce)>> {
        todo!("get_committee_pub_nonce")
    }
    pub async fn store_committee_partial_sig_for_instance(
        local_db: &LocalDB,
        instance_id: Uuid,
        committee_pubkey: PublicKey,
        partial_sigs: PartialSignature,
    ) -> Result<()> {
        // update if exists, insert if not exists
        todo!("store_committee_partial_sig")
    }
    pub async fn get_committee_partial_sigs_for_instance(
        local_db: &LocalDB,
        instance_id: Uuid,
    ) -> Result<Vec<(PublicKey, PartialSignature)>> {
        todo!("get_committee_partial_sigs")
    }
    pub async fn get_latest_pegout_finalized_graph(
        local_db: &LocalDB,
        operator_pubkey: &PublicKey,
    ) -> Result<Option<(u64, Uuid)>> {
        todo!("get latest pegout finalized graph nonce & id from local db")
    }
    pub async fn get_graph_id_by_nonce(
        local_db: &LocalDB,
        graph_nonce: u64,
        operator_pubkey: &PublicKey,
    ) -> Result<Option<(Uuid, Uuid)>> {
        todo!("get instance_id & graph_id by graph_nonce and operator_pubkey from local db")
    }

    // proof network
    pub async fn get_watchtower_proof(instance_id: Uuid, graph_id: Uuid) -> Result<Vec<u8>> {
        todo!("get watchtower proof from proof network")
    }
    pub async fn get_operator_proof_blockhash(
        instance_id: Uuid,
        graph_id: Uuid,
    ) -> Result<[u8; 32]> {
        todo!("get blockhash used for operator proof")
    }
    pub async fn get_operator_proof(
        instance_id: Uuid,
        graph_id: Uuid,
    ) -> Result<(GuestInputs, Groth16Proof, PublicInputs, VerifyingKey)> {
        todo!("get operator proof from proof network")
    }
    pub async fn get_operator_proof_vk(instance_id: Uuid, graph_id: Uuid) -> Result<VerifyingKey> {
        todo!("get vk for operator proof")
    }

    // other operations
    pub fn is_relayer() -> bool {
        todo!("check if the node is relayer")
    }
    pub fn min_required_operator() -> usize {
        todo!("get min required operator number from goat chain")
    }
    pub async fn publish_graph_to_ipfs(ipfs: &IPFS, graph: &Bitvm2Graph) -> Result<String> {
        todo!("publish graph to ipfs")
    }
    pub async fn validate_committee(
        goat_client: &GOATClient,
        peer_id: &PeerId,
        instance_id: Uuid,
        committee_pubkey: &PublicKey,
    ) -> Result<()> {
        // return SpecialError::InvalidCommittee if not valid
        todo!("validate committee's peer id & pubkey")
    }
    pub async fn validate_committee_with_evm_address(
        goat_client: &GOATClient,
        peer_id: &PeerId,
        instance_id: Uuid,
        committee_pubkey: &PublicKey,
        committee_evm_address: &EvmAddress,
    ) -> Result<()> {
        // return SpecialError::InvalidCommittee if not valid
        todo!("validate committee's peer id & pubkey & evm address")
    }
    pub async fn validate_init_graph(
        local_db: &LocalDB,
        btc_client: &BTCClient,
        goat_client: &GOATClient,
        graph: &SimplifiedBitvm2Graph,
    ) -> Result<()> {
        // return SpecialError::InvalidGraph if not valid
        todo!("check graph parameters & operator stake")
    }
    pub fn validate_finalized_graph(
        goat_client: &GOATClient,
        graph: &SimplifiedBitvm2Graph,
        endorse_sigs: &Vec<(PublicKey, EvmAddress, Vec<u8>)>,
    ) -> Result<()> {
        // return SpecialError::InvalidGraph if not valid
        todo!("verify graph & endorsement signatures")
    }
    pub fn get_node_evm_address() -> Result<EvmAddress> {
        todo!("get node's evm address")
    }
    pub fn endorse_graph(graph: &Bitvm2Graph) -> Result<Vec<u8>> {
        todo!("sign graph digest with node's evm key")
    }
    pub fn verify_graph_endorsement(
        evm_address: &EvmAddress,
        graph: &Bitvm2Graph,
        signature: &[u8],
    ) -> Result<bool> {
        todo!("check endorse signature")
    }
    pub async fn build_genesis_prekickoff_tx(
        btc_client: &BTCClient,
    ) -> Result<PrekickoffTransaction> {
        todo!("create a genesis prekickoff tx")
    }
    pub async fn build_prekickoff_params(
        btc_client: &BTCClient,
        graph_nonce: u64,
        cur_prekickoff_txn: PrekickoffTransaction,
    ) -> Result<PrekickoffParameters> {
        todo!("build prekickoff params")
    }
    pub async fn build_graph_params(
        instance_params: &Bitvm2InstanceParameters,
        prekickoff_params: &PrekickoffParameters,
    ) -> Result<Bitvm2GraphParameters> {
        todo!("build graph params")
    }
    pub async fn generate_disprove_scripts(
        instance_id: Uuid,
        graph_id: Uuid,
        graph_params: &Bitvm2GraphParameters,
    ) -> Result<Vec<ScriptBuf>> {
        todo!("generate disprove scripts for the graph")
    }
    pub async fn build_cpfp_txns(
        btc_client: &BTCClient,
        parent_tx: Transaction,
        anchor_vout: u64,
    ) -> Result<Vec<Transaction>> {
        todo!("build child txns to cpfp the parent tx")
    }
    pub async fn get_preimage(
        local_db: &LocalDB,
        instance_id: Uuid,
        graph_id: Uuid,
        index: usize,
    ) -> Result<Vec<u8>> {
        todo!("get preimage from local db (or derive it from master key?)")
    }
    pub async fn broadcast_nonstandard_tx(btc_client: &BTCClient, tx: &Transaction) -> Result<()> {
        todo!("broadcast non-standard tx")
    }
    pub async fn refresh_graph(
        local_db: &LocalDB,
        btc_client: &BTCClient,
        goat_client: &GOATClient,
        instance_id: Uuid,
        graph_id: Uuid,
    ) -> Result<(Bitvm2Graph, GraphStatus)> {
        todo!("refresh graph's status, return updated graph & status")
    }
    pub async fn refresh_insatnce(
        local_db: &LocalDB,
        btc_client: &BTCClient,
        goat_client: &GOATClient,
        instance_id: Uuid,
    ) -> Result<()> {
        todo!("refresh instance's status & all its graphs' status")
    }
}

pub async fn read_pegin_request(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    instance_id: Uuid,
) -> Result<(UserInfo, Amount)> {
    let pegin_data = todo_funcs::get_pegin_data(goat_client, instance_id).await?;
    if pegin_data.status != PeginStatus::Pending {
        bail!("Invalid PeginRequest: expired or already processed");
    }
    let network = get_network();
    let user_change_address = Address::from_str(&pegin_data.user_change_addr)
        .map_err(|e| SpecialError::InvalidPeginRequest(format!("invalid user_change_addr: {}", e)))?
        .require_network(network)
        .map_err(|e| {
            SpecialError::InvalidPeginRequest(format!("invalid user_change_addr network: {}", e))
        })?;
    let user_refund_address = Address::from_str(&pegin_data.user_refund_addr)
        .map_err(|e| SpecialError::InvalidPeginRequest(format!("invalid user_refund_addr: {}", e)))?
        .require_network(network)
        .map_err(|e| {
            SpecialError::InvalidPeginRequest(format!("invalid user_refund_addr network: {}", e))
        })?;
    let user_xonly_pubkey =
        XOnlyPublicKey::from_slice(&pegin_data.user_xonly_pubkey).map_err(|e| {
            SpecialError::InvalidPeginRequest(format!("invalid user_xonly_pubkey: {}", e))
        })?;
    let inputs: Vec<Input> = pegin_data
        .user_inputs
        .iter()
        .map(|u| Input {
            outpoint: OutPoint { txid: Txid::from_byte_array(u.txid), vout: u.vout },
            amount: Amount::from_sat(u.amount_stats),
        })
        .collect();
    // TODO: we need to run our own bitcoin node in case of downtime or ddos attack.
    for input in &inputs {
        if !outpoint_available(btc_client, &input.outpoint.txid, input.outpoint.vout.into()).await?
        {
            bail!(SpecialError::InvalidPeginRequest(format!(
                "input {}:{} is not available",
                input.outpoint.txid, input.outpoint.vout
            )));
        }
    }
    let user_info = UserInfo {
        depositor_evm_address: pegin_data.depositor_address,
        txn_fees: pegin_data.txn_fees,
        inputs,
        user_change_address,
        user_refund_address,
        user_xonly_pubkey,
    };
    Ok((user_info, Amount::from_sat(pegin_data.pegin_amount_sats)))
}

pub async fn read_instance_info_from_goat(
    goat_client: &GOATClient,
    instance_id: Uuid,
) -> Result<Bitvm2InstanceParameters> {
    let pegin_data = todo_funcs::get_pegin_data(goat_client, instance_id).await?;
    let network = get_network();
    let user_change_address = Address::from_str(&pegin_data.user_change_addr)
        .map_err(|e| SpecialError::InvalidPeginData(format!("invalid user_change_addr: {}", e)))?
        .require_network(network)
        .map_err(|e| {
            SpecialError::InvalidPeginData(format!("invalid user_change_addr network: {}", e))
        })?;
    let user_refund_address = Address::from_str(&pegin_data.user_refund_addr)
        .map_err(|e| SpecialError::InvalidPeginData(format!("invalid user_refund_addr: {}", e)))?
        .require_network(network)
        .map_err(|e| {
            SpecialError::InvalidPeginData(format!("invalid user_refund_addr network: {}", e))
        })?;
    let user_xonly_pubkey = XOnlyPublicKey::from_slice(&pegin_data.user_xonly_pubkey)
        .map_err(|e| SpecialError::InvalidPeginData(format!("invalid user_xonly_pubkey: {}", e)))?;
    let inputs: Vec<Input> = pegin_data
        .user_inputs
        .iter()
        .map(|u| Input {
            outpoint: OutPoint { txid: Txid::from_byte_array(u.txid), vout: u.vout },
            amount: Amount::from_sat(u.amount_stats),
        })
        .collect();
    let user_info = UserInfo {
        depositor_evm_address: pegin_data.depositor_address,
        txn_fees: pegin_data.txn_fees,
        inputs,
        user_change_address,
        user_refund_address,
        user_xonly_pubkey,
    };
    let committee_pubkeys = match todo_funcs::get_committee_pubkeys(goat_client, instance_id).await
    {
        Ok(pks) => pks,
        Err(e) => {
            if let Some(msg) = e.downcast_ref::<SpecialError>() {
                match msg {
                    SpecialError::EvmReverted(err_msg) => {
                        bail!(SpecialError::InvalidPeginData(format!(
                            "fail to get committee pubkeys: {}",
                            err_msg
                        )))
                    }
                    _ => bail!(e),
                }
            } else {
                bail!(e)
            }
        }
    };
    let committee_agg_pubkey = generate_n_of_n_public_key(&committee_pubkeys).0;
    Ok(Bitvm2InstanceParameters {
        network,
        instance_id,
        user_info,
        pegin_amount: Amount::from_sat(pegin_data.pegin_amount_sats),
        committee_pubkeys,
        committee_agg_pubkey,
    })
}

pub async fn is_valid_withdraw(
    client: &GOATClient,
    _instance_id: Uuid,
    graph_id: Uuid,
) -> Result<bool> {
    let withdraw_status = client.gateway_get_withdraw_data(&graph_id).await?.status;
    Ok([WithdrawStatus::Initialized, WithdrawStatus::Processing].contains(&withdraw_status))
    // TODO: Only WithdrawStatus::Processing should be considered valid,
    // here WithdrawStatus::Initialized is also treated as valid to facilitate test
    // Ok(withdraw_status == WithdrawStatus::Processing)
}

/// Checks whether the status of the graph (identified by instance ID and graph ID)
/// on the Layer 2 contract is currently `Initialized`.
pub async fn is_withdraw_initialized_on_l2(
    client: &GOATClient,
    _instance_id: Uuid,
    graph_id: Uuid,
) -> Result<bool> {
    let withdraw_status = client.gateway_get_withdraw_data(&graph_id).await?.status;
    Ok(withdraw_status == WithdrawStatus::Initialized)
}

pub async fn is_take1_timelock_expired(client: &BTCClient, kickoff_height: u32) -> Result<bool> {
    let lock_blocks = take1_timelock(get_network());
    let current_height = client.get_height().await?;
    Ok(current_height >= kickoff_height + lock_blocks)
}

pub async fn is_take2_timelock_expired(
    client: &BTCClient,
    watchtower_challenge_init_height: u32,
    assert_init_height: u32,
) -> Result<bool> {
    let lock_blocks = take2_timelocks(get_network());
    let current_height = client.get_height().await?;
    Ok(current_height >= watchtower_challenge_init_height + lock_blocks.0
        || current_height >= assert_init_height + lock_blocks.1)
}

/// Calculates the required challenge amount, which is based on the stake amount.
///
/// Formula:
/// challenge_amount = fixed_min_challenge_amount + (pegin_amount * challenge_rate)
pub fn get_challenge_amount(pegin_amount: u64) -> Amount {
    Amount::from_sat(MIN_CHALLENGE_AMOUNT + pegin_amount * CHALLENGE_RATE / RATE_MULTIPLIER)
}

/// Loads partial scripts from a local cache file.
/// If cache file does not exist, generate partial scripts by vk an cache it
pub async fn get_partial_scripts(local_db: &LocalDB) -> Result<Vec<ScriptBuf>> {
    let scripts_cache_path = SCRIPT_CACHE_FILE_NAME;
    if Path::new(scripts_cache_path).exists() {
        let file = File::open(scripts_cache_path)?;
        let reader = BufReader::new(file);
        let scripts_bytes: Vec<ScriptBuf> = bincode::deserialize_from(reader)?;
        Ok(scripts_bytes)
    } else {
        let partial_scripts = generate_partial_scripts(&get_vk(local_db).await?);
        if let Some(parent) = Path::new(scripts_cache_path).parent() {
            fs::create_dir_all(parent)?;
        };
        let file = File::create(scripts_cache_path)?;
        let writer = BufWriter::new(file);
        bincode::serialize_into(writer, &partial_scripts)?;
        Ok(partial_scripts)
    }
}

pub async fn get_fee_rate(client: &BTCClient) -> Result<f64> {
    match client.network() {
        //TODO mempool api /fee-estimates failed, fix it latter
        Network::Testnet | Network::Regtest => Ok(10.0),
        _ => {
            let res = client.get_fee_estimates().await?;
            Ok(*res.get(&DEFAULT_CONFIRMATION_TARGET).ok_or(anyhow!(
                "fee for {DEFAULT_CONFIRMATION_TARGET} confirmation target not found"
            ))?)
        }
    }
}

/// Broadcasts a raw transaction to the Bitcoin network using the mempool API.
///
/// Requirements:
/// - The mempool API URL must be configured.
/// - The transaction should already be fully signed.
pub async fn broadcast_tx(client: &BTCClient, tx: &Transaction) -> Result<()> {
    client.broadcast(tx).await?;
    Ok(())
}

pub async fn broadcast_package(client: &BTCClient, txns: &[Transaction]) -> Result<()> {
    client.broadcast_package(txns).await?;
    Ok(())
}

/// Completes and broadcasts a challenge transaction.
///
/// This involves:
/// - Selecting UTXOs with sufficient amount (may include change),
/// - Signing the transaction,
/// - Broadcasting it to the network.
///
/// Notes:
/// - The challenge node must have pre-funded a P2WSH address during startup.
pub async fn complete_and_broadcast_challenge_tx(
    client: &BTCClient,
    node_keypair: Keypair,
    challenge_tx: Transaction,
    challenge_input0_amount: Amount,
) -> Result<Txid> {
    build_sign_and_broadcast_tx(
        client,
        node_keypair,
        challenge_tx.input,
        challenge_input0_amount,
        challenge_tx.output,
    )
    .await
}

pub async fn challenger_force_skip_kickoff(
    client: &BTCClient,
    graph: &Bitvm2Graph,
) -> Result<Txid> {
    let challenger_master_key = ChallengerMasterKey::new(get_bitvm_key()?);
    let challenger_master_keypair = challenger_master_key.master_keypair();
    let challenger_receive_address =
        node_p2wsh_address(get_network(), &challenger_master_keypair.public_key().into());
    let fee_rate = get_fee_rate(client).await?;
    let (force_skip_kickoff_tx, anchor_added) =
        build_force_skip_kickoff_tx(graph, challenger_receive_address, fee_rate)?;
    if anchor_added {
        let anchor_vout = force_skip_kickoff_tx.output.len() as u64 - 1;
        let cpfp_package =
            todo_funcs::build_cpfp_txns(client, force_skip_kickoff_tx.clone(), anchor_vout).await?;
        broadcast_package(client, &cpfp_package).await?;
    } else {
        broadcast_tx(client, &force_skip_kickoff_tx).await?;
    }
    Ok(force_skip_kickoff_tx.compute_txid())
}

pub async fn challenger_quick_challenge(client: &BTCClient, graph: &Bitvm2Graph) -> Result<Txid> {
    let challenger_master_key = ChallengerMasterKey::new(get_bitvm_key()?);
    let challenger_master_keypair = challenger_master_key.master_keypair();
    let challenger_receive_address =
        node_p2wsh_address(get_network(), &challenger_master_keypair.public_key().into());
    let fee_rate = get_fee_rate(client).await?;
    let (quick_challenge_tx, anchor_added) =
        build_quick_challenge_tx(graph, challenger_receive_address, fee_rate)?;
    if anchor_added {
        let anchor_vout = quick_challenge_tx.output.len() as u64 - 1;
        let cpfp_package =
            todo_funcs::build_cpfp_txns(client, quick_challenge_tx.clone(), anchor_vout).await?;
        broadcast_package(client, &cpfp_package).await?;
    } else {
        broadcast_tx(client, &quick_challenge_tx).await?;
    }
    Ok(quick_challenge_tx.compute_txid())
}

pub async fn build_sign_and_broadcast_tx(
    client: &BTCClient,
    node_keypair: Keypair,
    txins: Vec<TxIn>,
    total_input_amount: Amount,
    txouts: Vec<TxOut>,
) -> Result<Txid> {
    let txouts = if txouts.is_empty() {
        // bitcoin network does not allow a transaction without outputs
        vec![TxOut { value: Amount::ZERO, script_pubkey: generate_opreturn_script(vec![]) }]
    } else {
        txouts
    };
    let mut tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: txins,
        output: txouts,
    };
    let fixed_inputs_num = tx.input.len();
    let total_output_amount: Amount = tx.output.iter().map(|o| o.value).sum();
    let fee_rate = get_fee_rate(client).await?;
    let node_address = node_p2wsh_address(get_network(), &node_keypair.public_key().into());
    let shortfall =
        Amount::from_sat(total_output_amount.to_sat().saturating_sub(total_input_amount.to_sat()));
    match get_proper_utxo_set(
        client,
        tx.weight().to_vbytes_ceil(),
        node_address.clone(),
        shortfall,
        fee_rate,
    )
    .await?
    {
        Some((inputs, _, change_amount)) => {
            for input in &inputs {
                tx.input.push(TxIn {
                    previous_output: input.outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::default(),
                });
            }
            if change_amount > Amount::from_sat(DUST_AMOUNT) {
                tx.output.push(TxOut {
                    script_pubkey: node_address.script_pubkey(),
                    value: change_amount,
                });
            }
            for (i, input) in inputs.iter().enumerate() {
                node_sign(
                    &mut tx,
                    i + fixed_inputs_num,
                    input.amount,
                    EcdsaSighashType::All,
                    &node_keypair,
                )?;
            }
            broadcast_tx(client, &tx).await?;
            Ok(tx.compute_txid())
        }
        None => {
            let current_balance = client
                .get_address_utxo(node_address)
                .await?
                .iter()
                .map(|u| u.value)
                .sum::<Amount>();
            bail!(SpecialError::InsufficientBalance(format!(
                "Not enough balance to complete the transaction, current_balance: {current_balance} < shortfall: {shortfall}"
            )));
        }
    }
}

/// Returns:
/// - `Ok(None)` if given address does not have enough btc,
/// - `Ok(Some((utxos, fee_amount, change_amount)))`
pub async fn get_proper_utxo_set(
    client: &BTCClient,
    base_vbytes: u64,
    address: Address,
    target_amount: Amount,
    fee_rate: f64,
) -> Result<Option<(Vec<Input>, Amount, Amount)>> {
    fn estimate_tx_vbytes(base_vbytes: u64, extra_inputs: usize, extra_outputs: usize) -> u64 {
        // p2wsh inputs/outputs
        base_vbytes
            + (extra_inputs as u64 * CHEKSIG_P2WSH_INPUT_VBYTES)
            + (extra_outputs as u64 * P2WSH_OUTPUT_VBYTES)
    }
    fn to_input(utxos: Vec<Utxo>) -> Vec<Input> {
        utxos
            .into_iter()
            .map(|utxo| Input {
                outpoint: OutPoint { txid: utxo.txid, vout: utxo.vout },
                amount: utxo.value,
            })
            .collect()
    }
    println!("get utxos from: {address}");

    let utxos = client.get_address_utxo(address).await?;
    let mut sorted_utxos = utxos;
    sorted_utxos.sort_by(|a, b| b.value.cmp(&a.value));

    let mut selected = Vec::new();
    let mut total_value = Amount::ZERO;

    for utxo in sorted_utxos.into_iter().take(MAX_CUSTOM_INPUTS) {
        selected.push(utxo.clone());
        total_value += utxo.value;

        let num_inputs = selected.len();
        let num_outputs = 1; // change
        let tx_vbytes = estimate_tx_vbytes(base_vbytes, num_inputs, num_outputs);
        let fee = Amount::from_sat((tx_vbytes as f64 * fee_rate).ceil() as u64);

        if total_value >= target_amount + fee {
            let change = total_value - target_amount - fee;
            return Ok(Some((to_input(selected), fee, change)));
        }
    }

    Ok(None)
}

pub fn node_p2wsh_script(pubkey: &PublicKey) -> ScriptBuf {
    script! {
        { *pubkey }
        OP_CHECKSIG
    }
    .compile()
}
pub fn node_p2wsh_address(network: Network, pubkey: &PublicKey) -> Address {
    Address::p2wsh(&node_p2wsh_script(pubkey), network)
}

pub fn node_sign(
    tx: &mut Transaction,
    input_index: usize,
    input_value: Amount,
    sighash_type: EcdsaSighashType,
    node_keypair: &Keypair,
) -> Result<()> {
    let node_pubkey = node_keypair.public_key();
    populate_p2wsh_witness(
        tx,
        input_index,
        sighash_type,
        &node_p2wsh_script(&node_pubkey.into()),
        input_value,
        &vec![node_keypair],
    );
    Ok(())
}

pub async fn operator_skip_graph(btc_client: &BTCClient, graph: &mut Bitvm2Graph) -> Result<()> {
    let graph_id = graph.parameters.graph_id;
    let graph_nonce = graph.parameters.graph_nonce;
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let operator_master_keypair = operator_master_key.master_keypair();
    let operator_receive_address =
        node_p2wsh_address(get_network(), &operator_master_keypair.public_key().into());
    let operator_graph_keypair = operator_master_key.keypair_for_graph(graph_id);
    let mut prekickoff_tx = operator_sign_prekickoff_input_0(operator_graph_keypair, graph)?;
    if prekickoff_tx.input.len() != 1 {
        let operator_nonce_keypair = operator_master_key.keypair_for_nonce(graph_nonce);
        for i in 1..prekickoff_tx.input.len() {
            let input_value = graph.cur_prekickoff.input_amounts[i];
            node_sign(
                &mut prekickoff_tx,
                i,
                input_value,
                bitcoin::EcdsaSighashType::All,
                &operator_nonce_keypair,
            )?;
        }
    }
    let anchor_vout = prekickoff_tx.output.len() as u64 - 1;
    let mut tx_package =
        todo_funcs::build_cpfp_txns(btc_client, prekickoff_tx, anchor_vout).await?;
    match operator_sign_skip_kickoff(
        operator_graph_keypair,
        graph,
        operator_receive_address,
        get_fee_rate(btc_client).await?,
    )? {
        Some(skip_kickoff_tx) => {
            tx_package.push(skip_kickoff_tx);
        }
        None => {}
    };
    broadcast_package(btc_client, &tx_package).await?;
    Ok(())
}

pub async fn operator_kickoff(btc_client: &BTCClient, graph: &mut Bitvm2Graph) -> Result<()> {
    let graph_id = graph.parameters.graph_id;
    let graph_nonce = graph.parameters.graph_nonce;
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let operator_graph_keypair = operator_master_key.keypair_for_graph(graph_id);
    let mut prekickoff_tx = operator_sign_prekickoff_input_0(operator_graph_keypair, graph)?;
    if prekickoff_tx.input.len() != 1 {
        let operator_nonce_keypair = operator_master_key.keypair_for_nonce(graph_nonce);
        for i in 1..prekickoff_tx.input.len() {
            let input_value = graph.cur_prekickoff.input_amounts[i];
            node_sign(
                &mut prekickoff_tx,
                i,
                input_value,
                bitcoin::EcdsaSighashType::All,
                &operator_nonce_keypair,
            )?;
        }
    }
    let anchor_vout = prekickoff_tx.output.len() as u64 - 1;
    let mut tx_package =
        todo_funcs::build_cpfp_txns(btc_client, prekickoff_tx, anchor_vout).await?;

    let kickoff_tx = operator_sign_kickoff(operator_graph_keypair, graph)?;
    let anchor_vout = kickoff_tx.output.len() as u64 - 1;
    let kickoff_cpfp_package =
        todo_funcs::build_cpfp_txns(btc_client, kickoff_tx, anchor_vout).await?;
    tx_package.extend(kickoff_cpfp_package);
    broadcast_package(btc_client, &tx_package).await?;
    Ok(())
}

pub async fn send_challenge_tx(btc_client: &BTCClient, graph: &Bitvm2Graph) -> Result<Txid> {
    let (mut challenge_tx, _) = export_challenge_tx(&graph)?;
    let challenge_keypair = ChallengerMasterKey::new(get_bitvm_key()?).master_keypair();
    let challenger_evm_address = todo_funcs::get_node_evm_address()?;
    challenge_tx.output.push(bitcoin::TxOut {
        value: Amount::ZERO,
        script_pubkey: generate_opreturn_script(challenger_evm_address.to_vec()),
    });
    build_sign_and_broadcast_tx(
        btc_client,
        challenge_keypair,
        challenge_tx.input,
        graph.kickoff.tx().output[0].value,
        challenge_tx.output,
    )
    .await
}

pub async fn send_watchtower_challenge_tx(
    btc_client: &BTCClient,
    graph: &Bitvm2Graph,
    watchtower_index: usize,
    commitment_data: Vec<u8>,
) -> Result<Txid> {
    let watchtower_keypair = WatchtowerMasterKey::new(get_bitvm_key()?).master_keypair();
    let fee_rate = get_fee_rate(btc_client).await?;
    let watchtower_challenge_tx_base_vbytes =
        estimate_watchtower_challenge_vbytes(commitment_data.len());
    let node_address = node_p2wsh_address(get_network(), &watchtower_keypair.public_key().into());
    match get_proper_utxo_set(
        btc_client,
        watchtower_challenge_tx_base_vbytes as u64,
        node_address.clone(),
        Amount::ZERO,
        fee_rate,
    )
    .await?
    {
        Some((inputs, fee_amount, _)) => {
            let mut watchtower_challenge_tx = build_watchtower_challenge_tx(
                graph,
                &watchtower_keypair,
                watchtower_index,
                &commitment_data,
                inputs.clone(),
                &node_address,
                fee_amount,
            )
            .unwrap();
            for i in 0..inputs.len() {
                node_sign(
                    &mut watchtower_challenge_tx,
                    i + 1,
                    inputs[i].amount,
                    EcdsaSighashType::All,
                    &watchtower_keypair,
                )?;
            }
            broadcast_tx(btc_client, &watchtower_challenge_tx).await?;
            Ok(watchtower_challenge_tx.compute_txid())
        }
        None => {
            let current_balance = btc_client
                .get_address_utxo(node_address)
                .await?
                .iter()
                .map(|u| u.value)
                .sum::<Amount>();
            bail!(SpecialError::InsufficientBalance(format!(
                "Not enough balance to complete the transaction, current_balance: {current_balance}"
            )));
        }
    }
}

/// Validates whether the given kickoff transaction has been confirmed on Layer 1.
pub async fn tx_on_chain(client: &BTCClient, txid: &Txid) -> Result<bool> {
    match client.get_tx(txid).await? {
        Some(_) => Ok(true),
        _ => Ok(false),
    }
}

pub async fn tx_confirmed(client: &BTCClient, txid: &Txid) -> Result<bool> {
    Ok(client.get_tx_status(txid).await?.confirmed)
}

pub async fn outpoint_available(client: &BTCClient, txid: &Txid, vout: u64) -> Result<bool> {
    match client.get_output_status(txid, vout).await? {
        Some(status) => Ok(!status.spent),
        _ => Ok(false),
    }
}

pub async fn outpoint_spent_txid(
    client: &BTCClient,
    txid: &Txid,
    vout: u64,
) -> Result<Option<Txid>> {
    match client.get_output_status(txid, vout).await? {
        Some(status) => Ok(status.txid),
        _ => Ok(None),
    }
}

pub async fn outpoint_spent_txin(
    client: &BTCClient,
    txid: &Txid,
    vout: u64,
) -> Result<Option<(Txid, u64, TxIn)>> {
    match client.get_output_status(txid, vout).await? {
        Some(status) => {
            if let Some(spent_txid) = status.txid
                && let Some(vin) = status.vin
                && let Some(spent_tx) = client.get_tx(&spent_txid).await?
            {
                Ok(spent_tx.input.get(vin as usize).cloned().map(|txin| (spent_txid, vin, txin)))
            } else {
                Ok(None)
            }
        }
        _ => Ok(None),
    }
}

/// Retrieves the Groth16 proof, public inputs, and verifying key
/// for the given graph.
///
/// These are fetched via the ProofNetwork SDK.
pub async fn get_groth16_proof(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    challenge_txid: String,
) -> Result<(Groth16Proof, PublicInputs, VerifyingKey)> {
    if cfg!(all(feature = "tests", feature = "e2e-tests")) {
        return get_test_groth16_proof();
    }

    let mut storage_processor = local_db.acquire().await?;
    if let Some(tx_record) = storage_processor
        .get_graph_goat_tx_record(&graph_id, &GoatTxType::ProceedWithdraw.to_string())
        .await?
        && let Ok((proof, pis, vk, version)) =
            groth16::get_groth16_proof(local_db, tx_record.height as u64).await
    {
        tracing::info!(
            "instance_id:{instance_id}, graph_id:{graph_id} finish get groth16 proof at version: {version}"
        );
        Ok((proof, pis, vk))
    } else {
        storage_processor
            .upsert_goat_tx_record(&GoatTxRecord {
                instance_id,
                graph_id,
                tx_type: GoatTxType::ProceedWithdraw.to_string(),
                tx_hash: "".to_string(),
                height: 0,
                is_local: false,
                processing_status: GoatTxProcessingStatus::Pending.to_string(),
                extra: Some(
                    serde_json::to_string(&GoatTxProceedWithdrawExtra { challenge_txid }).unwrap(),
                ),
                created_at: 0,
            })
            .await?;
        Err(anyhow!("instance_id:{instance_id}, graph_id:{graph_id} not ready!"))
    }
}
pub async fn get_vk(db: &LocalDB) -> Result<VerifyingKey> {
    if cfg!(all(feature = "tests", feature = "e2e-tests")) {
        return get_test_vk();
    }

    Ok(groth16::get_groth16_vk(db, &groth16::get_zkm_version()).await?)
}

pub fn get_test_groth16_proof() -> Result<(Groth16Proof, PublicInputs, VerifyingKey)> {
    let proof = hex::decode(
        "b6ef2c5aa48a2f599a13bc4d8010e4d0190aeb05ff79e21266aff8dde6353d1756191f0959c787f6dedfc0c47751aed2648775101285b9da2d6c4e912e74891f884bd672f94f4d78528fb10b5410a94b53bcef07f99952ef72b68c72a5c4ff2a3de7c314ffbf17df018a753f070448c2f698706d4c2b99bdb06f928cffe1bea0",
    )?;
    let pis = hex::decode(
        "02000000000000002000000000000000721db33a295a3b29a61c7360486e6d8346288822dc5cab652722e34d4b423d002000000000000000cfdc2f035c3699c6d17563570ea05a3d6d08302487937dd079a6b1671d484c0d",
    )?;
    let proof = goat::proof::deserialize_proof(proof);
    let pis = goat::proof::deserialize_pubin(pis);
    Ok((proof, pis, get_test_vk()?))
}

pub fn get_test_vk() -> Result<VerifyingKey> {
    let zkm_v1_vk_bytes = hex::decode(
        "e2f26dbea299f5223b646cb1fb33eadb059d9407559d7441dfd902e3a79a4d2dabb73dc17fbc13021e2471e0c08bd67d8401f52b73d6d07483794cad4778180e0c06f33bbc4c79a9cadef253a68084d382f17788f885c9afd176f7cb2f036789edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19ffdb10cf9f7e2b08673477187c33a695a397702cf22005900724518b57f92f2ce08f8dfe36ca3eff63b1743d64812936d8cab0d74c063d260e20a9a3339b2a8c0300000000000000d17e1efc51d15eef04bde8dc794edc9e5788eb7539171d3a49d970ab9215b89c9ab6c5ab119ca81927393ef29332a1d15ac5f197b878ea89a1f8f686b747011eaad636dcb52cdfd674d155ddd67d21186fbdd1c0a62ebd74dcd6ddc6784b819e",
    )?;
    Ok(goat::proof::deserialize_vk(zkm_v1_vk_bytes))
}

/// l2 support
pub async fn gateway_finish_withdraw_happy_path(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    graph_id: Uuid,
    tx: &Transaction,
) -> Result<String> {
    let tx_hash = goat_client.gateway_finish_withdraw_happy_path(btc_client, &graph_id, tx).await?;
    tracing::info!("graph_id:{} finish take1, tx_hash: {}", graph_id, tx_hash);
    Ok(tx_hash)
}
pub async fn gateway_finish_withdraw_unhappy_path(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    graph_id: Uuid,
    tx: &Transaction,
) -> Result<String> {
    let tx_hash =
        goat_client.gateway_finish_withdraw_unhappy_path(btc_client, &graph_id, tx).await?;
    tracing::info!("graph_id:{} finish take2, tx_hash: {}", graph_id, tx_hash);
    Ok(tx_hash)
}

pub async fn gateway_finish_withdraw_disproved(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    graph_id: Uuid,
    disprove_type: DisproveTxType,
    tx_index: u64,
    disprove_tx: &Transaction,
    challenge_tx: &Transaction,
) -> Result<String> {
    let tx_hash = goat_client
        .gateway_finish_withdraw_disproved(
            btc_client,
            &graph_id,
            disprove_type,
            tx_index,
            disprove_tx,
            challenge_tx,
        )
        .await?;
    tracing::info!("graph_id:{} finish disprove, tx_hash: {}", graph_id, tx_hash);
    Ok(tx_hash)
}

// will remove later
pub async fn update_graph_fields(
    _local_db: &LocalDB,
    _graph_id: Uuid,
    _status: Option<String>,
    _ipfs_base_url: Option<String>,
    _challenge_txid: Option<String>,
    _disprove_txid: Option<String>,
    _bridge_out_start_at: Option<i64>,
) -> Result<()> {
    Ok(())
}

fn generate_message_id(business_id: Uuid, msg_type: String, sub_type: Option<String>) -> String {
    match sub_type {
        Some(sub_type) => {
            format!("{business_id}_{msg_type}_{sub_type}")
        }
        None => format!("{business_id}_{msg_type}"),
    }
}
pub async fn create_message(
    storage_processor: &mut StorageProcessor<'_>,
    business_id: Uuid,
    sub_type: Option<String>,
    from_peer: String,
    actor: Actor,
    message_content: GOATMessageContent,
    weight: i64,
    lock_time: i64,
) -> Result<()> {
    let message = GOATMessage::from_typed(actor.clone(), &message_content)?;
    let msg_type = get_goat_message_content_type(&message_content).to_string();
    let message_id = generate_message_id(business_id, msg_type.clone(), sub_type);
    storage_processor
        .create_message(Message {
            message_id,
            business_id,
            actor: actor.to_string(),
            from_peer,
            msg_type,
            content: serde_json::to_vec(&message)?,
            weight,
            lock_time_until: current_time_secs() + lock_time,
            state: MessageState::Pending.to_string(),
        })
        .await?;
    Ok(())
}

/// store new graph, graph_raw_data, and update instance_id
pub async fn store_graph(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    bitvm2_graph: &Bitvm2Graph,
    status: &str,
) -> anyhow::Result<()> {
    let mut tx = local_db.start_transaction().await?;
    let kickoff_index_current = tx
        .get_operator_max_kickoff_index(&bitvm2_graph.parameters.operator_pubkey.to_string())
        .await?;
    let current_time = current_time_secs();
    let mut graph = Graph {
        graph_id,
        instance_id,
        kickoff_index: kickoff_index_current + 1,
        from_addr: "".to_string(),
        to_addr: "".to_string(),
        graph_ipfs_base_url: "".to_string(),
        amount: bitvm2_graph.parameters.instance_parameters.pegin_amount.to_sat() as i64,
        challenge_amount: bitvm2_graph.parameters.challenge_amount.to_sat() as i64,
        status: status.to_string(),
        sub_status: "".to_string(),
        operator_pubkey: bitvm2_graph.parameters.operator_pubkey.to_string(),
        cur_prekickoff_txid: Some(bitvm2_graph.cur_prekickoff.finalize().compute_txid().into()),
        next_prekickoff: Some(bitvm2_graph.next_prekickoff.finalize().compute_txid().into()),
        force_skip_kickoff_txid: Some(
            bitvm2_graph.force_skip_kickoff.finalize().compute_txid().into(),
        ),
        quick_challenge_txid: Some(bitvm2_graph.quick_challenge.finalize().compute_txid().into()),
        challenge_incomplete_kickoff_txid: Some(
            bitvm2_graph.challenge_incomplete_kickoff.finalize().compute_txid().into(),
        ),
        pegin_txid: Some(bitvm2_graph.pegin.finalize().compute_txid().into()),
        kickoff_txid: Some(bitvm2_graph.kickoff.finalize().compute_txid().into()),
        take1_txid: Some(bitvm2_graph.take1.finalize().compute_txid().into()),
        challenge_txid: None,
        take2_txid: Some(bitvm2_graph.take2.finalize().compute_txid().into()),
        disprove_txid: None,
        watchtower_challenge_init_txid: Some(
            bitvm2_graph.watchtower_challenge_init.finalize().compute_txid().into(),
        ),
        watchtower_challenge_timeout_txids: bitvm2_graph
            .watchtower_challenge_timeout_txns
            .iter()
            .map(|tx| tx.finalize().compute_txid().into())
            .collect(),
        nack_txids: bitvm2_graph
            .nack_txns
            .iter()
            .map(|tx| tx.finalize().compute_txid().into())
            .collect(),
        blockhash_commit_timeout_txid: Some(
            bitvm2_graph.blockhash_commit_timeout.finalize().compute_txid().into(),
        ),
        assert_init_txid: Some(bitvm2_graph.assert_init.finalize().compute_txid().into()),
        assert_commit_timeout_txids: bitvm2_graph
            .assert_commit_timeout_txns
            .iter()
            .map(|tx| tx.finalize().compute_txid().into())
            .collect(),
        init_withdraw_tx_hash: None,
        bridge_out_start_at: 0,
        zkm_version: groth16::get_zkm_version(),
        created_at: current_time,
        updated_at: current_time,
    };

    if let Some(node_info) =
        tx.get_node_by_btc_pub_key(&bitvm2_graph.parameters.operator_pubkey.to_string()).await?
    {
        graph.from_addr = node_info.goat_addr.clone();
        graph.to_addr =
            node_p2wsh_address(get_network(), &bitvm2_graph.parameters.operator_pubkey).to_string();
    }

    tx.upsert_graph(graph).await?;
    tx.update_instance(
        &InstanceUpdate::new(instance_id).with_status(InstanceStatus::Presigned.to_string()),
    )
    .await?;
    tx.upsert_graph_raw_data(GraphRawData {
        graph_id,
        raw_data: serde_json::to_string(&bitvm2_graph).unwrap_or_default(),
        created_at: current_time,
        updated_at: current_time,
    })
    .await?;

    tx.commit().await?;
    Ok(())
}

#[allow(dead_code)]
pub async fn update_graph(
    _local_db: &LocalDB,
    _instance_id: Uuid,
    _graph_id: Uuid,
    _graph: &Bitvm2Graph,
    _status: Option<String>,
) -> anyhow::Result<()> {
    // store_graph(local_db, instance_id, graph_id, graph, status).await
    Ok(())
}
pub async fn get_graph(
    local_db: &LocalDB,
    instance_id: Option<Uuid>,
    graph_id: Uuid,
) -> Result<Graph> {
    let mut storage_process = local_db.acquire().await?;
    let graph_op = storage_process.find_graph(&graph_id).await?;
    if graph_op.is_none() {
        tracing::warn!("graph:{} is not record in db", graph_id);
        return Err(anyhow!("graph:{graph_id} is not record in db").into());
    };
    let graph = graph_op.unwrap();
    if let Some(instance_id) = instance_id
        && graph.instance_id.ne(&instance_id)
    {
        return Err(anyhow!(
            "grap with graph_id:{graph_id} has instance_id:{} not match exp instance:{instance_id}",
            graph.instance_id,
        )
        .into());
    }
    Ok(graph)
}

pub async fn get_bitvm2_graph_from_db(
    _local_db: &LocalDB,
    _instance_id: Uuid,
    graph_id: Uuid,
) -> Result<Bitvm2Graph> {
    Err(anyhow!("graph:{graph_id} not found"))
}

pub async fn publish_graph_to_ipfs(
    _ipfs: &IPFS,
    _graph_id: Uuid,
    _graph: &Bitvm2Graph,
) -> Result<String> {
    todo!("publish_graph_to_ipfs")
}

pub async fn get_my_graph_for_instance(
    goat_client: &GOATClient,
    instance_id: Uuid,
    operator_pubkey: PublicKey,
) -> Result<Option<Uuid>> {
    let ids_vec = goat_client
        .gateway_get_instanceids_by_pubkey(&operator_pubkey.to_bytes()[1..33].try_into()?)
        .await?;
    Ok(ids_vec.iter().find(|(a, _)| *a == instance_id).map(|(_, b)| *b))
}

pub async fn get_graph_status(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<Option<GraphStatus>> {
    let mut storage_process = local_db.acquire().await?;
    let graph_op = storage_process.find_graph(&graph_id).await?;
    if graph_op.is_none() {
        return Ok(None);
    };
    let graph = graph_op.unwrap();
    if graph.instance_id.ne(&instance_id) {
        return Err(anyhow!(
            "grap with graph_id:{graph_id} has instance_id:{} not match exp instance:{instance_id}",
            graph.instance_id,
        ));
    }
    Ok(Some(
        GraphStatus::from_str(&graph.status)
            .map_err(|_| anyhow!("unknown graph status: {}", graph.status))?,
    ))
}

pub async fn update_graphs_status_by_instance_ids(
    local_db: &LocalDB,
    status: &str,
    instance_ids: &[Uuid],
) -> Result<()> {
    let mut storage_process = local_db.acquire().await?;
    storage_process.update_graphs_status_by_instance_ids(status, instance_ids).await?;
    Ok(())
}

/// Returns:
/// - `Ok(true)` tx confirmed,
/// - `Ok(false)` tx not confirmed, exceeds the maximum waiting time
pub async fn wait_tx_confirmation(
    btc_client: &BTCClient,
    txid: &Txid,
    interval: u64,
    max_wait_secs: u64,
) -> Result<bool> {
    use std::{
        thread,
        time::{Duration, Instant},
    };
    let start_time = Instant::now();
    loop {
        if start_time.elapsed().as_secs() > max_wait_secs {
            // println!("Timeout: Transaction not confirmed after {} seconds", max_wait_secs);
            return Ok(false);
        };
        // FIXME: should not use esplora directly
        match btc_client.get_tx_status(txid).await {
            Ok(status) => {
                if let Some(_height) = status.block_height {
                    // println!("Transaction confirmed in block {}", height);
                    return Ok(true);
                } else {
                    // println!("Transaction unconfirmed, polling again...");
                }
            }
            Err(e) => {
                return Err(anyhow!("Failed to fetch transaction status: {e}"));
            }
        }
        thread::sleep(Duration::from_secs(interval));
    }
}

#[allow(dead_code)]
pub async fn wait_tx_appear(
    btc_client: &BTCClient,
    txid: &Txid,
    interval: u64,
    max_wait_secs: u64,
) -> Result<bool> {
    use std::{
        thread,
        time::{Duration, Instant},
    };
    let start_time = Instant::now();
    loop {
        if start_time.elapsed().as_secs() > max_wait_secs {
            // println!("Timeout: Transaction not appear after {} seconds", max_wait_secs);
            return Ok(false);
        };
        match btc_client.get_tx(txid).await {
            Ok(tx) => {
                if tx.is_some() {
                    return Ok(true);
                }
            }
            Err(e) => {
                return Err(anyhow!("Failed to fetch transaction status: {e}"));
            }
        }
        thread::sleep(Duration::from_secs(interval));
    }
}

pub mod defer {
    pub struct Defer<F: FnOnce()> {
        cleanup: Option<F>,
    }
    impl<F: FnOnce()> Defer<F> {
        pub fn new(f: F) -> Self {
            Self { cleanup: Some(f) }
        }
        pub fn dismiss(&mut self) {
            self.cleanup = None;
        }
    }
    impl<F: FnOnce()> Drop for Defer<F> {
        fn drop(&mut self) {
            if let Some(cleanup) = self.cleanup.take() {
                cleanup();
            }
        }
    }
    #[macro_export]
    macro_rules! defer {
        ($name:ident, $cleanup:block) => {
            let mut $name = $crate::utils::defer::Defer::new(|| $cleanup);
        };
    }
    #[macro_export]
    macro_rules! dismiss_defer {
        ($name:ident) => {
            $name.dismiss();
        };
    }
}

pub async fn save_node_info(local_db: &LocalDB, node_info: &NodeInfo) -> Result<()> {
    tracing::info!("save_node_info for {}", node_info.peer_id);
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let mut storage_process = local_db.acquire().await?;
    let _ = storage_process
        .upsert_node(Node {
            peer_id: node_info.peer_id.clone(),
            actor: node_info.actor.clone(),
            goat_addr: node_info.goat_addr.clone(),
            btc_pub_key: node_info.btc_pub_key.clone(),
            socket_addr: node_info.socket_addr.clone(),
            reward: 0,
            updated_at: current_time,
            created_at: current_time,
        })
        .await;
    Ok(())
}

pub async fn save_local_info(local_db: &LocalDB) {
    let node = get_local_node_info();
    match save_node_info(local_db, &node).await {
        Ok(_) => {}
        Err(err) => tracing::error!("save local node err: {err}"),
    }
}

pub async fn update_node_timestamp(local_db: &LocalDB, peer_id: &str) -> Result<()> {
    tracing::info!("update timestamp for {peer_id}");
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let mut storage_process = local_db.acquire().await?;
    match storage_process.update_node_timestamp(peer_id, current_time).await {
        Ok(_) => {}
        Err(err) => warn!("{err}"),
    };
    Ok(())
}

pub async fn detect_heart_beat(swarm: &mut Swarm<AllBehaviours>) -> Result<()> {
    tracing::info!("start detect_heart_beat");
    let message_content = GOATMessageContent::RequestNodeInfo(get_local_node_info());
    // send to actor
    let actors = get_rpc_support_actors();
    for actor in actors {
        match send_to_peer(swarm, GOATMessage::from_typed(actor, &message_content)?) {
            Ok(_) => {}
            Err(err) => warn!("{err}"),
        }
    }
    Ok(())
}

pub async fn validate_actor(peer_id: &[u8], role: Actor) -> Result<bool> {
    let rpc_url = get_goat_url_from_env();
    let provider = ProviderBuilder::new().connect_http(rpc_url);
    let goat_gateway_contract_address = get_goat_gateway_contract_from_env();
    match role {
        Actor::Committee => {
            Ok(validate_committee(&provider, goat_gateway_contract_address, peer_id).await?)
        }
        Actor::Operator => {
            Ok(validate_operator(&provider, goat_gateway_contract_address, peer_id).await?)
        }
        Actor::Relayer => {
            Ok(validate_relayer(&provider, goat_gateway_contract_address, peer_id).await?)
        }
        _ => Ok(true),
    }
}

pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..len).map(|_| rng.gen_range(0..255)).collect()
}

pub fn get_rand_btc_address_p2wpkh(network: Network) -> String {
    let secp = Secp256k1::new();
    Address::p2wpkh(
        &CompressedPublicKey::try_from(PrivateKey::generate(network).public_key(&secp))
            .expect("Could not compress public key"),
        Network::Testnet,
    )
    .to_string()
}

pub fn get_rand_btc_address_p2pkh(network: Network) -> String {
    let secp = Secp256k1::new();
    Address::p2pkh(
        CompressedPublicKey::try_from(PrivateKey::generate(network).public_key(&secp))
            .expect("Could not compress public key"),
        Network::Testnet,
    )
    .to_string()
}

pub fn get_rand_goat_address() -> String {
    EvmAddress::from_slice(&generate_random_bytes(20)).to_string()
}

pub fn strip_hex_prefix_owned(s: &str) -> String {
    if s.starts_with("0x") || s.starts_with("0X") { s[2..].to_string() } else { s.to_string() }
}

/// Retrieve the server's public IP via NAT protocol and combine it with
/// the configured RPC monitoring port`rpc_addr` to generate the external RPC service address.
pub async fn set_node_external_socket_addr_env(rpc_addr: &str) -> Result<()> {
    if get_proof_server_url().is_some() {
        // not provide proof server
        return Ok(());
    }
    let addr = SocketAddr::from_str(rpc_addr)?;
    let mut client = Client::new("0.0.0.0:0", None).await?;
    let message_res = client.binding_request("stun.l.google.com:19302", None).await;
    if message_res.is_err() {
        warn!("fail to get message from stun.l.google.com:19302, err :{:?}", message_res.err());
        return Ok(());
    }
    let message = message_res?;
    if message.get_class() != Class::SuccessResponse {
        warn!(
            "fail to get message from stun.l.google.com:19302, return class :{:?}",
            message.get_class()
        );
        return Ok(());
    }
    if let Some(socket_addr) = Attribute::get_xor_mapped_address(&message) {
        unsafe {
            std::env::set_var(
                ENV_EXTERNAL_SOCKET_ADDR,
                SocketAddr::new(socket_addr.ip(), addr.port()).to_string(),
            );
        }
    }
    Ok(())
}
// TODO
pub fn get_fixed_disprove_output() -> Result<TxOut> {
    Ok(TxOut {
        script_pubkey: generate_burn_script_address(get_network()).script_pubkey(),
        value: Amount::from_sat(DUST_AMOUNT),
    })
}

pub fn reflect_goat_address(addr_op: Option<String>) -> (bool, Option<String>) {
    if let Some(addr) = addr_op
        && let Ok(addr) = EvmAddress::from_str(&addr)
    {
        return (true, Some(addr.to_string()));
    }

    (false, None)
}

pub async fn pop_batch_local_unhandle_msg(
    local_db: &LocalDB,
    actor: Actor,
    lock_time_until: i64,
    offset: i64,
    limit: i64,
) -> Result<Vec<Message>> {
    // todo mv to single function
    if actor == Actor::Operator {
        operator_scan_ready_proof(
            local_db,
            get_proof_server_url(),
            routes::v1::PROOFS_GROTH16_BASE,
        )
        .await?;
    }
    let mut tx = local_db.start_transaction().await?;
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    tx.set_messages_expired(current_time - MESSAGE_EXPIRE_TIME).await?;
    tx.delete_old_messages(current_time - MESSAGE_EXPIRE_TIME).await?;
    let messages = tx
        .filter_messages(
            MessageState::Pending.to_string(),
            0,
            lock_time_until,
            current_time - MESSAGE_EXPIRE_TIME,
            limit,
            offset,
        )
        .await?;
    tx.commit().await?;
    Ok(messages)
}

pub async fn operator_scan_ready_proof(
    local_db: &LocalDB,
    remote_proof_server_socket: Option<String>,
    uri: &str,
) -> Result<()> {
    tracing::info!("start operator_scan_ready_proof");
    let client = reqwest::Client::new();
    let check_txs: Vec<GoatTxRecord> = {
        let mut storage_processor = local_db.acquire().await?;
        storage_processor
            .get_goat_tx_record_by_processing_status(
                &GoatTxType::ProceedWithdraw.to_string(),
                &GoatTxProcessingStatus::Pending.to_string(),
            )
            .await?
    };

    let parse_challenge_txid_fn = |extra_data: Option<String>| -> Result<Txid> {
        if extra_data.is_none() {
            return Err(anyhow!("extra data is none"));
        }
        let extra: GoatTxProceedWithdrawExtra = serde_json::from_str(&extra_data.unwrap())?;
        Ok(deserialize_hex(&extra.challenge_txid)?)
    };

    for tx in check_txs {
        if tx.height == 0 {
            tracing::info!("Graph id :{} proceed withdraw tx online just waiting", tx.graph_id);
            continue;
        }
        let challenge_txid_res = parse_challenge_txid_fn(tx.extra.clone());
        if let Ok(challenge_txid) = challenge_txid_res {
            let mut db_tx = local_db.start_transaction().await?;
            if let Some(socket) = remote_proof_server_socket.clone() {
                let resp = client.get(format!("http://{socket}{uri}/{}", tx.height)).send().await?;
                if resp.status().is_success()
                    && let Some(proof_value) = resp.json::<Option<Groth16ProofValue>>().await?
                {
                    if !proof_value.verify()? {
                        warn!(
                            "fail to get detail proof  from {socket} for height {}, verify failed",
                            tx.height
                        );
                        continue;
                    }
                    db_tx
                        .create_verifier_key(&proof_value.zkm_version, &proof_value.groth16_vk)
                        .await?;
                    db_tx
                        .add_groth16_proof(
                            tx.height,
                            tx.height,
                            &format!("{}", tx.height),
                            &proof_value.proof,
                            &proof_value.public_values,
                            &proof_value.verifier_id,
                            &proof_value.zkm_version,
                            &GoatTxProcessingStatus::Processed.to_string(),
                        )
                        .await?;
                } else {
                    warn!(
                        "fail to get detail proof  from {socket} for height {}, will try later",
                        tx.height
                    );
                    continue;
                }
            } else {
                let (proof, _, _, _) = db_tx.get_groth16_proof(tx.height).await?;
                if proof.is_empty() {
                    tracing::info!("Graph id :{} proof is empty just waiting", tx.graph_id);
                    continue;
                }
            }

            tracing::info!("Graph id :{} proof is ready", tx.graph_id);
            db_tx
                .update_goat_tx_record_processing_status(
                    &tx.graph_id,
                    &tx.instance_id,
                    &tx.tx_type,
                    &GoatTxProcessingStatus::Processed.to_string(),
                )
                .await?;

            create_message(
                &mut db_tx,
                tx.graph_id,
                None,
                "self".to_string(),
                Actor::Operator,
                GOATMessageContent::ChallengeSent(ChallengeSent {
                    instance_id: tx.instance_id,
                    graph_id: tx.graph_id,
                    challenge_txid,
                }),
                0,
                0,
            )
            .await?;
            db_tx.commit().await?;
        }
    }
    Ok(())
}

pub fn generate_local_key() -> libp2p::identity::Keypair {
    libp2p::identity::Keypair::generate_ed25519()
}

pub fn temp_file() -> String {
    let tmp_db = tempfile::NamedTempFile::new().unwrap();
    tmp_db.path().as_os_str().to_str().unwrap().to_string()
}

#[allow(dead_code)]
pub async fn generate_instance_from_event(
    btc_client: &BTCClient,
    event: &BridgeInRequestEvent,
) -> Result<Instance> {
    let user_xonly_pubkey_bytes = hex::decode(strip_hex_prefix_owned(&event.user_xonly_pubkey))?;
    let user_xonly_pubkey_array: [u8; 32] = user_xonly_pubkey_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("user_x_only_pubkey must be exactly 32 bytes"))?;

    let input_utxos: Vec<ClientUtxo> = event
        .user_inputs
        .iter()
        .map(|v| {
            let txid_bytes = hex::decode(&strip_hex_prefix_owned(&v.txid))
                .map_err(|_| anyhow::anyhow!("Invalid txid hex format"))?;
            let txid_array: [u8; 32] = txid_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("txid must be exactly 32 bytes"))?;
            Ok(ClientUtxo {
                txid: txid_array,
                vout: v.vout,
                amount_stats: v.amount_sats.parse::<u64>().unwrap_or_default(),
            })
        })
        .collect::<Result<Vec<ClientUtxo>>>()?;

    let from_addr = if !input_utxos.is_empty()
        && let Some(tx) = btc_client.get_tx(&Txid::from_slice(&input_utxos[0].txid)?).await?
    {
        let tx_scripts = tx.output[input_utxos[0].vout as usize].script_pubkey.clone();
        Address::from_script(&tx_scripts, env::get_network())
            .map(|addr| addr.to_string())
            .unwrap_or_default()
    } else {
        warn!(
            "failed to decode instance  from from pegin_request event, txid:{}, as input_utxos is empty or decode address failed",
            event.instance_id
        );
        "".to_string()
    };

    let instance = Instance {
        instance_id: Uuid::from_str(&strip_hex_prefix_owned(&event.instance_id))?,
        network: get_network().to_string(),
        from_addr,
        to_addr: EvmAddress::from_str(&event.depositor_address)?.to_string(),
        amount: event.pegin_amount_sats.parse()?,
        fees: UInt64Array3(event.txn_fees.clone().map(|v| v.parse::<u64>().unwrap_or_default())),
        input_utxos: serde_json::to_string(&input_utxos)?,
        status: InstanceStatus::UserInited.to_string(),
        pegin_request_tx_hash: event.transaction_hash.clone(),
        pegin_request_height: event.block_number.parse()?,
        user_xonly_pubkey: ByteArray32(user_xonly_pubkey_array),
        user_change_addr: event.user_change_address.clone(),
        user_refund_addr: event.user_refund_address.clone(),
        pegin_prepare_txid: None,
        pegin_confirm_txid: None,
        pegin_cancel_txid: None,
        unsign_pegin_confirm_tx: None,
        committees_answers: IndexMap::new(),
        pegin_data_tx_hash: "".to_string(),
        pegin_prepare_height: 0,
        created_at: current_time_secs(),
        updated_at: current_time_secs(),
    };
    Ok(instance)
}
