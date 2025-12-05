#![allow(clippy::collapsible_match)]
#![allow(clippy::single_match)]
#![allow(clippy::collapsible_else_if)]

use crate::env::{
    get_bitvm_key, get_local_node_info, get_network, get_node_goat_address, is_relayer,
};
use crate::error::SpecialError;
use crate::middleware::AllBehaviours;
use crate::rpc_service::current_time_secs;
use crate::utils::*;
use alloy::primitives::Address as EvmAddress;
use anyhow::{Result, anyhow, bail};
use bitcoin::{OutPoint, Txid};
use bitcoin::{PublicKey, XOnlyPublicKey};
use bitvm2_lib::actors::Actor;
use bitvm2_lib::challenger::*;
use bitvm2_lib::committee::*;
use bitvm2_lib::keys::*;
use bitvm2_lib::operator::*;
use bitvm2_lib::types::{Bitvm2Graph, SimplifiedBitvm2Graph};
use client::goat_chain::{DisproveTxType, PeginStatus, WithdrawStatus};
use client::{btc_chain::BTCClient, goat_chain::GOATClient};
use goat::connectors::connector_z::ConnectorZ;
use goat::transactions::base::{BaseTransaction, Input};
use goat::transactions::pre_signed::PreSignedTransaction;
use goat::transactions::pre_signed_musig2::verify_public_nonce;
use libp2p::gossipsub::MessageId;
use libp2p::{PeerId, Swarm, gossipsub};
use musig2::{PartialSignature, PubNonce};
use secp256k1::schnorr::Signature as SchnorrSignature;
use serde::{Deserialize, Serialize};
use store::ipfs::IPFS;
use store::localdb::LocalDB;
use store::{GraphStatus, MessageState};
use tracing::warn;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct GOATMessage {
    pub actor: Actor,
    pub content: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub enum GOATMessageContent {
    PeginRequest(PeginRequest),
    CreateGraph(CreateGraph),
    ConfirmInstance(ConfirmInstance),
    NonceGeneration(NonceGeneration),
    CommitteePresign(CommitteePresign),
    EndorseGraph(EndorseGraph),
    GraphFinalize(GraphFinalize),
    PeginConfirmNonce(PeginConfirmNonce),
    PeginConfirmPartialSig(PeginConfirmPartialSig),
    PostReady(PostReady),
    KickoffReady(KickoffReady),
    KickoffSent(KickoffSent),
    PreKickoffSent(PreKickoffSent),
    ChallengeSent(ChallengeSent),
    WatchtowerChallengeInitSent(WatchtowerChallengeInitSent),
    WatchtowerChallengeSent(WatchtowerChallengeSent),
    WatchtowerChallengeTimeout(WatchtowerChallengeTimeout),
    OperatorAckTimeout(OperatorAckTimeout),
    OperatorCommitBlockHashReady(OperatorCommitBlockHashReady),
    OperatorCommitBlockHashTimeout(OperatorCommitBlockHashTimeout),
    AssertInitReady(AssertInitReady),
    AssertCommitTimeout(AssertCommitTimeout),
    DisproveReady(DisproveReady),
    DisproveSent(DisproveSent),
    Take1Ready(Take1Ready),
    Take1Sent(Take1Sent),
    Take2Ready(Take2Ready),
    Take2Sent(Take2Sent),
    RequestNodeInfo(NodeInfo),
    ResponseNodeInfo(NodeInfo),
    SyncGraphRequest(SyncGraphRequest),
    SyncGraph(SyncGraph),
    InstanceDiscarded(InstanceDiscarded),
}

/// Pegin

#[derive(Serialize, Deserialize, Clone)]
pub struct PeginRequest {
    pub instance_id: Uuid,
    pub pegin_request_tx_hash: String, // goat tx hash
    pub pegin_request_height: i64,
    pub pegin_timestamp: i64,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct ConfirmInstance {
    pub instance_id: Uuid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct CreateGraph {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub graph_nonce: u64,
    pub graph: SimplifiedBitvm2Graph,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct NonceGeneration {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub committee_pubkey: PublicKey,
    pub watchtower_num: usize,
    pub assert_commit_num: usize,
    pub pub_nonces: CommitteePubNonces,
    pub nonce_sigs: CommitteeNonceSignatures,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct CommitteePresign {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub committee_pubkey: PublicKey,
    pub committee_partial_sigs: CommitteePartialSignatures,
    pub agg_nonces: CommitteeAggNonces,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct EndorseGraph {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub committee_pubkey: PublicKey,
    pub committee_evm_address: EvmAddress,
    pub committee_sig_for_graph: Vec<u8>, // ECDSA signature signed with committee evm keypair
}
#[derive(Serialize, Deserialize, Clone)]
pub struct GraphFinalize {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub graph_nonce: u64,
    pub graph: SimplifiedBitvm2Graph,
    pub endorse_sigs: Vec<(PublicKey, EvmAddress, Vec<u8>)>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct PeginConfirmNonce {
    pub instance_id: Uuid,
    pub committee_pubkey: PublicKey,
    pub pub_nonce: PubNonce,
    pub nonce_sig: SchnorrSignature,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct PeginConfirmPartialSig {
    pub instance_id: Uuid,
    pub committee_pubkey: PublicKey,
    pub partial_sig: PartialSignature,
    pub endorse_sig: Vec<u8>, // ECDSA signature signed with committee evm keypair
}
#[derive(Serialize, Deserialize, Clone)]
pub struct PostReady {
    pub instance_id: Uuid,
}

/// Pegout

#[derive(Serialize, Deserialize, Clone)]
pub struct KickoffReady {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct KickoffSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct PreKickoffSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct ChallengeSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub challenge_txid: Txid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct WatchtowerChallengeInitSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct WatchtowerChallengeSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub watchtower_challenge_txids: Vec<(usize, Txid)>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct WatchtowerChallengeTimeout {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub watchtower_indexes: Vec<usize>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct OperatorAckTimeout {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct OperatorCommitBlockHashReady {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct OperatorCommitBlockHashTimeout {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct AssertInitReady {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct AssertCommitTimeout {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct DisproveReady {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct DisproveSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub disprove_type: DisproveTxType,
    pub index: usize, // nack txns index or assert timeout txns index, ignored for other disprove types
    pub challenge_start_txid: Option<Txid>,
    pub challenge_finish_txid: Txid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct Take1Ready {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct Take1Sent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct Take2Ready {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct Take2Sent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}

/// Others

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct NodeInfo {
    pub peer_id: String,
    pub actor: String,
    pub goat_addr: String,
    pub btc_pub_key: String,
    pub socket_addr: String,
    pub node_name: String,
    pub service_fee_rate: f64,
    pub available_peg_btc: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SyncGraphRequest {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SyncGraph {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub graph: SimplifiedBitvm2Graph,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct InstanceDiscarded {
    // (graph_id, instance_id, OperatorPubkey)
    pub graph_infos: Vec<(Uuid, Uuid, String)>,
}

impl GOATMessage {
    pub fn from_typed<T: Serialize>(actor: Actor, value: &T) -> Result<Self, serde_json::Error> {
        let content = serde_json::to_vec(value)?;
        Ok(Self { actor, content })
    }

    pub fn to_typed<T: for<'de> Deserialize<'de>>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&self.content)
    }

    pub fn default_message_id() -> MessageId {
        MessageId(b"__inner_message_id__".to_vec())
    }
}
#[allow(clippy::too_many_arguments)]
pub async fn handle_self_p2p_msg(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    ipfs: &IPFS,
    actor: Actor,
    from_peer_id: PeerId,
    id: MessageId,
    message: &[u8],
) -> Result<()> {
    if id != GOATMessage::default_message_id() {
        tracing::warn!("handle_self_p2p_msg received unexpected message id: {:?}", id);
        return Ok(());
    }
    let message: GOATMessage = serde_json::from_slice(message)?;
    tracing::info!(
        "Got self p2p message: {}:{} with id: {} from peer: {:?}",
        &message.actor.to_string(),
        String::from_utf8_lossy(&message.content),
        id,
        from_peer_id
    );

    let messages =
        pop_batch_local_unhandle_msg(local_db, actor.clone(), current_time_secs(), 0, 50).await?;
    for message in messages {
        match recv_and_dispatch(
            swarm,
            local_db,
            btc_client,
            goat_client,
            ipfs,
            actor.clone(),
            from_peer_id,
            id.clone(),
            &message.content,
        )
        .await
        {
            Ok(_) => {
                let mut storage_processor = local_db.acquire().await?;
                storage_processor
                    .update_messages_state(
                        &message.message_id,
                        message.message_version,
                        MessageState::Processed.to_string(),
                    )
                    .await?;
            }
            Err(err) => {
                let lock_time = 600;
                warn!(
                    "fail to process message:{}: {} will lock seconds {lock_time}",
                    message.message_id, err
                );
                let mut storage_processor = local_db.acquire().await?;
                storage_processor
                    .update_messages_lock_time_until(
                        &message.message_id,
                        message.message_version,
                        current_time_secs() + lock_time,
                    )
                    .await?;
            }
        }
    }
    Ok(())
}

/// Filter the message and dispatch message to different handlers, like rpc handler, or other peers
///     * database: inner_rpc: Write or Read.
///     * peers: send
/// TODO: we should create a trait for all the actions of different roles to simplify this function.
#[allow(clippy::too_many_arguments)]
pub async fn recv_and_dispatch(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    _ipfs: &IPFS,
    actor: Actor,
    from_peer_id: PeerId,
    id: MessageId,
    message: &[u8],
) -> Result<()> {
    if id != GOATMessage::default_message_id() {
        update_node_timestamp(local_db, &from_peer_id.to_string()).await?;
    }

    // Determine whether the message comes from this node itself to optionally skip validations
    let is_self_peer = get_local_node_info().peer_id == from_peer_id.to_string();

    let message: GOATMessage = serde_json::from_slice(message)?;
    let content: GOATMessageContent = message.to_typed()?;
    match (content, actor) {
        (
            GOATMessageContent::PeginRequest(PeginRequest {
                instance_id,
                pegin_request_tx_hash,
                pegin_request_height,
                pegin_timestamp,
            }),
            Actor::Committee,
        ) => {
            // triggered by BridgeInRequest event
            tracing::info!("Handle PeginRequest for {instance_id}");
            // 1. read & check the pegin request data
            let (user_info, pegin_amount) =
                match read_pegin_request(btc_client, goat_client, instance_id).await {
                    Ok(v) => v,
                    Err(e) => {
                        if let Some(msg) = e.downcast_ref::<SpecialError>() {
                            match msg {
                                SpecialError::InvalidPeginRequest(err_msg) => {
                                    tracing::warn!(
                                        "Ignore PeginRequest for {instance_id}: {err_msg}"
                                    );
                                    return Ok(());
                                }
                                _ => {}
                            }
                        };
                        bail!(e)
                    }
                };
            // 2. save the pegin request data to local db
            store_pegin_request(
                btc_client,
                local_db,
                GenerateInstanceParams {
                    instance_id,
                    user_info,
                    pegin_amount,
                    pegin_request_tx_hash,
                    pegin_request_height,
                    pegin_timestamp,
                },
            )
            .await?;
            // 3. call Gateway.answerPeginRequest
            let pubkey_for_instance = CommitteeMasterKey::new(get_bitvm_key()?)
                .keypair_for_instance(instance_id)
                .public_key()
                .into();
            goat_client.gateway_answer_pegin_request(&instance_id, &pubkey_for_instance).await?;
        }
        (
            GOATMessageContent::PeginRequest(PeginRequest {
                instance_id,
                pegin_request_tx_hash,
                pegin_request_height,
                pegin_timestamp,
            }),
            _,
        ) => {
            // triggered by BridgeInRequest event
            tracing::info!("Handle PeginRequest for {instance_id}");
            // 1. read & check the pegin request data
            let (user_info, pegin_amount) =
                match read_pegin_request(btc_client, goat_client, instance_id).await {
                    Ok(v) => v,
                    Err(e) => {
                        if let Some(msg) = e.downcast_ref::<SpecialError>() {
                            match msg {
                                SpecialError::InvalidPeginRequest(err_msg) => {
                                    tracing::warn!(
                                        "Ignore PeginRequest for {instance_id}: {err_msg}"
                                    );
                                    return Ok(());
                                }
                                _ => {}
                            }
                        };
                        bail!(e)
                    }
                };
            // 2. save the pegin request data to local db
            store_pegin_request(
                btc_client,
                local_db,
                GenerateInstanceParams {
                    instance_id,
                    user_info,
                    pegin_amount,
                    pegin_request_tx_hash,
                    pegin_request_height,
                    pegin_timestamp,
                },
            )
            .await?;
        }
        (GOATMessageContent::ConfirmInstance(ConfirmInstance { instance_id }), Actor::Operator) => {
            // triggered by PeginDeposit tx
            tracing::info!("Handle ConfirmInstance for {instance_id}");
            // 1. read & check parameters
            let instance_params = match read_instance_info_from_goat(goat_client, instance_id).await
            {
                Ok(v) => v,
                Err(e) => {
                    if let Some(msg) = e.downcast_ref::<SpecialError>() {
                        match msg {
                            SpecialError::InvalidPeginData(err_msg) => {
                                tracing::warn!(
                                    "Ignore ConfirmInstance for {instance_id}: {err_msg}"
                                );
                                return Ok(());
                            }
                            _ => {}
                        }
                    };
                    bail!(e)
                }
            };
            let pegin_deposit_txid = instance_params.build_pegin_tx()?.0.tx().compute_txid();
            if !tx_on_chain(btc_client, &pegin_deposit_txid).await? {
                tracing::warn!(
                    "Ignore ConfirmInstance for {instance_id}: pegin deposit tx {pegin_deposit_txid} not found on chain"
                );
                bail!(
                    "Invalid ConfirmInstance: pegin deposit tx {pegin_deposit_txid} not found on chain"
                );
            }
            // 2. save the instance data to local db
            store_instance_parameters(local_db, &instance_params).await?;
            // 3. create & presign graph
            let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
            let local_operator_pubkey = operator_master_key.master_keypair().public_key().into();
            let (graph_nonce, cur_prekickoff_tx) =
                match get_current_prekickoff_tx(local_db, &local_operator_pubkey).await? {
                    Some(v) => v,
                    None => {
                        // create a genesis prekickoff tx
                        let genesis_prekickoff_tx =
                            build_genesis_prekickoff_tx(btc_client, goat_client).await?;
                        (0, genesis_prekickoff_tx)
                    }
                };
            let prekickoff_params =
                build_prekickoff_params(btc_client, graph_nonce, cur_prekickoff_tx).await?;
            let graph_params = build_graph_params(
                local_db,
                goat_client,
                instance_params,
                prekickoff_params,
                graph_nonce,
                Uuid::new_v4(),
            )
            .await?;
            let graph_id = graph_params.graph_id;
            let disprove_scripts = get_disprove_scripts(local_db, &graph_params).await?;
            let mut graph = generate_bitvm_graph(graph_params, disprove_scripts)?;
            operator_pre_sign(operator_master_key.master_keypair(), &mut graph)?;
            store_graph(local_db, &graph.to_simplified()?).await?;
            // 4. broadcast CreateGraph
            let message_content = GOATMessageContent::CreateGraph(CreateGraph {
                instance_id,
                graph_id,
                graph_nonce,
                graph: graph.to_simplified()?,
            });
            send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
        }
        (GOATMessageContent::ConfirmInstance(ConfirmInstance { instance_id }), _) => {
            // triggered by PeginDeposit tx
            tracing::info!("Handle ConfirmInstance for {instance_id}");
            // 1. read & check parameters
            let instance_params = match read_instance_info_from_goat(goat_client, instance_id).await
            {
                Ok(v) => v,
                Err(e) => {
                    if let Some(msg) = e.downcast_ref::<SpecialError>() {
                        match msg {
                            SpecialError::InvalidPeginData(err_msg) => {
                                tracing::warn!(
                                    "Ignore ConfirmInstance for {instance_id}: {err_msg}"
                                );
                                return Ok(());
                            }
                            _ => {}
                        }
                    };
                    bail!(e)
                }
            };
            let pegin_deposit_txid = instance_params.build_pegin_tx()?.0.tx().compute_txid();
            if !tx_on_chain(btc_client, &pegin_deposit_txid).await? {
                tracing::warn!(
                    "Ignore ConfirmInstance for {instance_id}: pegin deposit tx {pegin_deposit_txid} not found on chain"
                );
                return Ok(());
            }
            // 2. save the instance data to local db
            store_instance_parameters(local_db, &instance_params).await?;
        }
        (
            GOATMessageContent::CreateGraph(CreateGraph { instance_id, graph_id, graph, .. }),
            Actor::Committee,
        ) => {
            // received from Operator
            tracing::info!("Handle CreateGraph for {instance_id}:{graph_id}");
            // 1. check graph data & operator stake
            if let Err(e) =
                todo_funcs::validate_init_graph(local_db, btc_client, goat_client, &graph).await
            {
                if let Some(msg) = e.downcast_ref::<SpecialError>() {
                    match msg {
                        SpecialError::InvalidGraph(err_msg) => {
                            tracing::warn!(
                                "Ignore CreateGraph for {instance_id}:{graph_id}: {err_msg}"
                            );
                            return Ok(());
                        }
                        _ => {}
                    }
                };
                bail!(e)
            };
            // 2. save the graph data to local db
            store_graph(local_db, &graph).await?;
            // 3. generate Musig2 nonces & broadcast NonceGeneration
            let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
            let (pub_nonces, _, nonce_sigs) = committee_master_key.nonces_for_graph(
                instance_id,
                graph_id,
                graph.parameters.watchtower_pubkeys.len(),
                graph.assert_commit_num,
            );
            let local_committee_pubkey =
                committee_master_key.keypair_for_instance(instance_id).public_key().into();
            let message_content = GOATMessageContent::NonceGeneration(NonceGeneration {
                instance_id,
                graph_id,
                committee_pubkey: local_committee_pubkey,
                watchtower_num: graph.parameters.watchtower_pubkeys.len(),
                assert_commit_num: graph.assert_commit_num,
                pub_nonces: pub_nonces.clone(),
                nonce_sigs,
            });
            send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
            store_committee_pub_nonces_for_graph(
                local_db,
                instance_id,
                graph_id,
                local_committee_pubkey,
                pub_nonces,
            )
            .await?;
            // 4. if collected enough pub_nonces, generate partial signatures & broadcast CommitteePresign
            let committee_pubkeys = goat_client.gateway_get_committee_pubkeys(&instance_id).await?;
            let pub_nonces_unchecked =
                get_committee_pub_nonces_for_graph(local_db, instance_id, graph_id).await?;
            if pub_nonces_unchecked.len() == committee_pubkeys.len() {
                let mut graph = Bitvm2Graph::from_simplified(&graph)?;
                let watchtower_num = graph.parameters.watchtower_pubkeys.len();
                let assert_commit_num = graph.assert_commit_timeout_txns.len();
                let mut pub_nonces = Vec::with_capacity(pub_nonces_unchecked.len());
                for (pk, pn) in pub_nonces_unchecked.into_iter() {
                    if let Err(e) = pn.validate_length(watchtower_num, assert_commit_num) {
                        tracing::warn!("PubNonces from {} has invalid length: {e}", pk.to_string());
                        return Ok(());
                    }
                    pub_nonces.push(pn);
                }
                let agg_nonces = nonces_aggregation(&pub_nonces)?;
                let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
                let (_, sec_nonces, _) = committee_master_key.nonces_for_graph(
                    instance_id,
                    graph_id,
                    watchtower_num,
                    assert_commit_num,
                );
                let committee_partial_sigs = committee_pre_sign(
                    committee_master_key.keypair_for_instance(instance_id),
                    sec_nonces,
                    agg_nonces.clone(),
                    &mut graph,
                )?;
                let message_content = GOATMessageContent::CommitteePresign(CommitteePresign {
                    instance_id,
                    graph_id,
                    committee_pubkey: local_committee_pubkey,
                    committee_partial_sigs,
                    agg_nonces,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
            }
        }
        (
            GOATMessageContent::NonceGeneration(NonceGeneration {
                instance_id,
                graph_id,
                committee_pubkey: received_committee_pubkey,
                watchtower_num,
                assert_commit_num,
                pub_nonces,
                nonce_sigs,
            }),
            Actor::Committee,
        ) => {
            // received from Committee members
            tracing::info!(
                "Handle NonceGeneration for {instance_id}:{graph_id} from {}",
                received_committee_pubkey.to_string()
            );
            if !is_self_peer
                && let Err(e) = validate_committee(
                    goat_client,
                    &from_peer_id,
                    instance_id,
                    &received_committee_pubkey,
                )
                .await
            {
                if let Some(msg) = e.downcast_ref::<SpecialError>() {
                    match msg {
                        SpecialError::InvalidCommittee(err_msg) => {
                            tracing::warn!(
                                "Ignore NonceGeneration for {instance_id}:{graph_id} from {}: {err_msg}",
                                from_peer_id.to_string()
                            );
                            return Ok(());
                        }
                        SpecialError::EvmReverted(err_msg) => {
                            tracing::warn!(
                                "Ignore NonceGeneration for {instance_id}:{graph_id} from {}: fail to validate committee info on chain: {err_msg}",
                                from_peer_id.to_string()
                            );
                            return Ok(());
                        }
                        _ => {}
                    }
                };
                bail!(e);
            }
            // 1. check pub_nonces & nonce signatures
            let committee_xonly_pubkey = XOnlyPublicKey::from(received_committee_pubkey);
            if !verify_nonce_signatures(
                &committee_xonly_pubkey,
                &pub_nonces,
                &nonce_sigs,
                watchtower_num,
                assert_commit_num,
            )? {
                tracing::warn!(
                    "Ignore NonceGeneration for {instance_id}:{graph_id} from {}: invalid pub_nonces or nonce_sigs",
                    received_committee_pubkey.to_string()
                );
                return Ok(());
            }
            // TODO: deal with the case that one committee member sends different pub_nonces for the same graph
            // 2. save the pub_nonces to local db
            store_committee_pub_nonces_for_graph(
                local_db,
                instance_id,
                graph_id,
                received_committee_pubkey,
                pub_nonces,
            )
            .await?;
            // 3. if received enough pub_nonces, generate partial signatures & broadcast CommitteePresign
            let committee_pubkeys = goat_client.gateway_get_committee_pubkeys(&instance_id).await?;
            let pub_nonces_unchecked =
                get_committee_pub_nonces_for_graph(local_db, instance_id, graph_id).await?;
            if pub_nonces_unchecked.len() == committee_pubkeys.len() {
                let local_committee_pubkey = CommitteeMasterKey::new(get_bitvm_key()?)
                    .keypair_for_instance(instance_id)
                    .public_key()
                    .into();
                let graph = match get_graph_or_defer(
                    swarm,
                    local_db,
                    goat_client,
                    instance_id,
                    graph_id,
                    &message,
                )
                .await?
                {
                    Some(g) => g,
                    None => return Ok(()),
                };
                let mut graph = Bitvm2Graph::from_simplified(&graph)?;
                let watchtower_num = graph.parameters.watchtower_pubkeys.len();
                let assert_commit_num = graph.assert_commit_timeout_txns.len();
                let mut pub_nonces = Vec::with_capacity(pub_nonces_unchecked.len());
                for (pk, pn) in pub_nonces_unchecked.into_iter() {
                    if let Err(e) = pn.validate_length(watchtower_num, assert_commit_num) {
                        tracing::warn!("PubNonces from {} has invalid length: {e}", pk.to_string());
                        return Ok(());
                    }
                    pub_nonces.push(pn);
                }
                let agg_nonces = nonces_aggregation(&pub_nonces)?;
                let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
                let (_, sec_nonces, _) = committee_master_key.nonces_for_graph(
                    instance_id,
                    graph_id,
                    watchtower_num,
                    assert_commit_num,
                );
                let committee_partial_sigs = committee_pre_sign(
                    committee_master_key.keypair_for_instance(instance_id),
                    sec_nonces,
                    agg_nonces.clone(),
                    &mut graph,
                )?;
                let message_content = GOATMessageContent::CommitteePresign(CommitteePresign {
                    instance_id,
                    graph_id,
                    committee_pubkey: local_committee_pubkey,
                    committee_partial_sigs: committee_partial_sigs.clone(),
                    agg_nonces,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
                store_committee_partial_sigs_for_graph(
                    local_db,
                    instance_id,
                    graph_id,
                    local_committee_pubkey,
                    committee_partial_sigs,
                )
                .await?;
                // 4. if received enough valid committee partial sigs, endorse the graph
                let committee_partial_sigs =
                    get_committee_partial_sigs_for_graph(local_db, instance_id, graph_id)
                        .await?
                        .into_iter()
                        .map(|(_, ps)| ps)
                        .collect::<Vec<_>>();
                if committee_partial_sigs.len() == committee_pubkeys.len() {
                    let committee_sig_for_graph = endorse_graph(goat_client, &graph).await?;
                    let committee_evm_address = get_node_goat_address().ok_or_else(|| {
                        anyhow::anyhow!("failed to get node goat address".to_string())
                    })?;
                    let message_content = GOATMessageContent::EndorseGraph(EndorseGraph {
                        instance_id,
                        graph_id,
                        committee_pubkey: local_committee_pubkey,
                        committee_sig_for_graph: committee_sig_for_graph.as_bytes().to_vec(),
                        committee_evm_address,
                    });
                    send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
                }
            }
        }
        (
            GOATMessageContent::NonceGeneration(NonceGeneration {
                instance_id,
                graph_id,
                committee_pubkey: received_committee_pubkey,
                watchtower_num,
                assert_commit_num,
                pub_nonces,
                nonce_sigs,
            }),
            Actor::Operator,
        ) => {
            // received from Committee members
            tracing::info!(
                "Handle NonceGeneration for {instance_id}:{graph_id} from {}",
                received_committee_pubkey.to_string()
            );
            if !is_self_peer
                && let Err(e) = validate_committee(
                    goat_client,
                    &from_peer_id,
                    instance_id,
                    &received_committee_pubkey,
                )
                .await
            {
                if let Some(msg) = e.downcast_ref::<SpecialError>() {
                    match msg {
                        SpecialError::InvalidCommittee(err_msg) => {
                            tracing::warn!(
                                "Ignore NonceGeneration for {instance_id}:{graph_id} from {}: {err_msg}",
                                from_peer_id.to_string()
                            );
                            return Ok(());
                        }
                        SpecialError::EvmReverted(err_msg) => {
                            tracing::warn!(
                                "Ignore NonceGeneration for {instance_id}:{graph_id} from {}: fail to validate committee info on chain: {err_msg}",
                                from_peer_id.to_string()
                            );
                            return Ok(());
                        }
                        _ => {}
                    }
                };
                bail!(e);
            }
            // 1. check pub_nonces & nonce signatures
            let committee_xonly_pubkey = XOnlyPublicKey::from(received_committee_pubkey);
            if !verify_nonce_signatures(
                &committee_xonly_pubkey,
                &pub_nonces,
                &nonce_sigs,
                watchtower_num,
                assert_commit_num,
            )? {
                tracing::warn!(
                    "Ignore NonceGeneration for {instance_id}:{graph_id} from {}: invalid pub_nonces or nonce_sigs",
                    received_committee_pubkey.to_string()
                );
                return Ok(());
            }
            let graph = match get_graph(local_db, instance_id, graph_id).await? {
                Some(g) => g,
                None => {
                    tracing::warn!(
                        "Ignore NonceGeneration for {instance_id}:{graph_id} from {}: graph not found, maybe belongs to another Operator",
                        received_committee_pubkey.to_string()
                    );
                    return Ok(());
                }
            };
            let watchtower_num = graph.parameters.watchtower_pubkeys.len();
            let assert_commit_num = graph.assert_commit_num;
            if let Err(e) = pub_nonces.validate_length(watchtower_num, assert_commit_num) {
                tracing::warn!(
                    "Ignore NonceGeneration for {instance_id}:{graph_id} from {}: invalid pub_nonces length: {e}",
                    received_committee_pubkey.to_string()
                );
                return Ok(());
            }
            // TODO: deal with the case that one committee member sends different pub_nonces for the same graph
            // 2. save the pub_nonces to local db
            store_committee_pub_nonces_for_graph(
                local_db,
                instance_id,
                graph_id,
                received_committee_pubkey,
                pub_nonces,
            )
            .await?;
            // 3. if received enough endorsement signatures, mark the graph as endorsed, send the graph to IPFS, broadcast GraphFinalize
            // Operator may receive EndorseGraph, CommitteePresign or NonceGeneration messages in any order
            // So we need to check if we have collected enough endorsements, pub_nonces and partial_sigs every time we receive them
            try_finalize_graph(
                swarm,
                local_db,
                goat_client,
                instance_id,
                graph_id,
                Some(&graph),
                true,
            )
            .await?;
        }
        (
            GOATMessageContent::CommitteePresign(CommitteePresign {
                instance_id,
                graph_id,
                committee_pubkey: received_committee_pubkey,
                committee_partial_sigs,
                agg_nonces: _,
            }),
            Actor::Committee,
        ) => {
            // received from Committee members
            tracing::info!(
                "Handle CommitteePresign for {instance_id}:{graph_id} from {}",
                received_committee_pubkey.to_string()
            );
            if !is_self_peer
                && let Err(e) = validate_committee(
                    goat_client,
                    &from_peer_id,
                    instance_id,
                    &received_committee_pubkey,
                )
                .await
            {
                if let Some(msg) = e.downcast_ref::<SpecialError>() {
                    match msg {
                        SpecialError::InvalidCommittee(err_msg) => {
                            tracing::warn!(
                                "Ignore CommitteePresign for {instance_id}:{graph_id} from {}: {err_msg}",
                                from_peer_id.to_string()
                            );
                            return Ok(());
                        }
                        SpecialError::EvmReverted(err_msg) => {
                            tracing::warn!(
                                "Ignore CommitteePresign for {instance_id}:{graph_id} from {}: fail to validate committee info on chain: {err_msg}",
                                from_peer_id.to_string()
                            );
                            return Ok(());
                        }
                        _ => {}
                    }
                };
                bail!(e);
            }
            // 1. save the committee partial sigs to local db
            // TODO: validate the partial sigs
            store_committee_partial_sigs_for_graph(
                local_db,
                instance_id,
                graph_id,
                received_committee_pubkey,
                committee_partial_sigs,
            )
            .await?;
            // 2. if received enough valid committee partial sigs, endorse the graph
            let committee_pubkeys = goat_client.gateway_get_committee_pubkeys(&instance_id).await?;
            let committee_partial_sigs =
                get_committee_partial_sigs_for_graph(local_db, instance_id, graph_id)
                    .await?
                    .into_iter()
                    .map(|(_, ps)| ps)
                    .collect::<Vec<_>>();
            if committee_partial_sigs.len() == committee_pubkeys.len() {
                let graph = match get_graph_or_defer(
                    swarm,
                    local_db,
                    goat_client,
                    instance_id,
                    graph_id,
                    &message,
                )
                .await?
                {
                    Some(g) => g,
                    None => return Ok(()),
                };
                let graph = Bitvm2Graph::from_simplified(&graph)?;
                let committee_sig_for_graph = endorse_graph(goat_client, &graph).await?;
                let local_committee_pubkey = CommitteeMasterKey::new(get_bitvm_key()?)
                    .keypair_for_instance(instance_id)
                    .public_key()
                    .into();
                let committee_evm_address = get_node_goat_address().ok_or_else(|| {
                    anyhow::anyhow!("failed to get node goat address".to_string())
                })?;
                let message_content = GOATMessageContent::EndorseGraph(EndorseGraph {
                    instance_id,
                    graph_id,
                    committee_pubkey: local_committee_pubkey,
                    committee_sig_for_graph: committee_sig_for_graph.as_bytes().to_vec(),
                    committee_evm_address,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
            }
        }
        (
            GOATMessageContent::CommitteePresign(CommitteePresign {
                instance_id,
                graph_id,
                committee_pubkey: received_committee_pubkey,
                committee_partial_sigs,
                agg_nonces: _,
            }),
            Actor::Operator,
        ) => {
            // received from Committee members
            tracing::info!(
                "Handle CommitteePresign for {instance_id}:{graph_id} from {}",
                received_committee_pubkey.to_string()
            );
            if !is_self_peer
                && let Err(e) = validate_committee(
                    goat_client,
                    &from_peer_id,
                    instance_id,
                    &received_committee_pubkey,
                )
                .await
            {
                if let Some(msg) = e.downcast_ref::<SpecialError>() {
                    match msg {
                        SpecialError::InvalidCommittee(err_msg) => {
                            tracing::warn!(
                                "Ignore CommitteePresign for {instance_id}:{graph_id} from {}: {err_msg}",
                                from_peer_id.to_string()
                            );
                            return Ok(());
                        }
                        SpecialError::EvmReverted(err_msg) => {
                            tracing::warn!(
                                "Ignore CommitteePresign for {instance_id}:{graph_id} from {}: fail to validate committee info on chain: {err_msg}",
                                from_peer_id.to_string()
                            );
                            return Ok(());
                        }
                        _ => {}
                    }
                };
                bail!(e);
            }
            // 1. save the committee partial sigs to local db
            // TODO: validate the partial sigs
            store_committee_partial_sigs_for_graph(
                local_db,
                instance_id,
                graph_id,
                received_committee_pubkey,
                committee_partial_sigs,
            )
            .await?;
            // 3. if received enough endorsement signatures, mark the graph as endorsed, send the graph to IPFS, broadcast GraphFinalize
            // Operator may receive EndorseGraph, CommitteePresign or NonceGeneration messages in any order
            // So we need to check if we have collected enough endorsements, pub_nonces and partial_sigs every time we receive them
            try_finalize_graph(swarm, local_db, goat_client, instance_id, graph_id, None, true)
                .await?;
        }
        (
            GOATMessageContent::EndorseGraph(EndorseGraph {
                instance_id,
                graph_id,
                committee_pubkey: received_committee_pubkey,
                committee_sig_for_graph,
                committee_evm_address,
            }),
            Actor::Operator,
        ) => {
            // received from Committee members
            tracing::info!(
                "Handle EndorseGraph for {instance_id}:{graph_id} from {}",
                received_committee_pubkey.to_string()
            );
            if !is_self_peer
                && let Err(e) = validate_committee_with_evm_address(
                    goat_client,
                    &from_peer_id,
                    instance_id,
                    &received_committee_pubkey,
                    &committee_evm_address,
                )
                .await
            {
                if let Some(msg) = e.downcast_ref::<SpecialError>() {
                    match msg {
                        SpecialError::InvalidCommittee(err_msg) => {
                            tracing::warn!(
                                "Ignore EndorseGraph for {instance_id}:{graph_id} from {}: {err_msg}",
                                from_peer_id.to_string()
                            );
                            return Ok(());
                        }
                        SpecialError::EvmReverted(err_msg) => {
                            tracing::warn!(
                                "Ignore EndorseGraph for {instance_id}:{graph_id} from {}: fail to validate committee info on chain: {err_msg}",
                                from_peer_id.to_string()
                            );
                            return Ok(());
                        }
                        _ => {}
                    }
                };
                bail!(e);
            }
            // 1. check endorsement signature
            let graph = match get_graph(local_db, instance_id, graph_id).await? {
                Some(g) => g,
                None => {
                    tracing::warn!(
                        "Ignore EndorseGraph for {instance_id}:{graph_id} from {}: graph not found, maybe belongs to another Operator",
                        received_committee_pubkey.to_string()
                    );
                    return Ok(());
                }
            };
            let full_graph = Bitvm2Graph::from_simplified(&graph)?;
            if let Err(e) = verify_graph_endorsement(
                goat_client,
                &committee_evm_address,
                &full_graph,
                &committee_sig_for_graph,
            )
            .await
            {
                tracing::warn!(
                    "Ignore EndorseGraph for {instance_id}:{graph_id} from {}: invalid endorsement signature: {e}",
                    received_committee_pubkey.to_string()
                );
                return Ok(());
            }
            // 2. save the endorsement signature to local db
            store_committee_endorsement_for_graph(
                local_db,
                instance_id,
                graph_id,
                received_committee_pubkey,
                committee_evm_address,
                committee_sig_for_graph,
            )
            .await?;
            // 3. if received enough endorsement signatures, mark the graph as endorsed, send the graph to IPFS, broadcast GraphFinalize
            // Operator may receive EndorseGraph, CommitteePresign or NonceGeneration messages in any order
            // So we need to check if we have collected enough endorsements, pub_nonces and partial_sigs every time we receive them
            try_finalize_graph(
                swarm,
                local_db,
                goat_client,
                instance_id,
                graph_id,
                Some(&graph),
                true,
            )
            .await?;
        }
        (
            GOATMessageContent::GraphFinalize(GraphFinalize {
                instance_id,
                graph_id,
                graph,
                endorse_sigs,
                ..
            }),
            Actor::Committee,
        ) => {
            // received from Operator
            tracing::info!(
                "Handle GraphFinalize for {instance_id}:{graph_id} from {}",
                from_peer_id.to_string()
            );
            // 1. check graph data & ipfs cid
            if let Err(e) =
                todo_funcs::validate_finalized_graph(goat_client, &graph, &endorse_sigs).await
            {
                if let Some(msg) = e.downcast_ref::<SpecialError>() {
                    match msg {
                        SpecialError::InvalidGraph(err_msg) => {
                            tracing::warn!(
                                "Ignore GraphFinalize for {instance_id}:{graph_id} from {}: {err_msg}",
                                from_peer_id.to_string()
                            );
                            return Ok(());
                        }
                        _ => {}
                    }
                };
                bail!(e)
            }
            // 2. save the graph data to local db
            store_graph(local_db, &graph).await?;
            // TODO: check endorse_sigs
            store_committee_endorsements_for_graph(
                local_db,
                instance_id,
                graph_id,
                endorse_sigs.clone(),
            )
            .await?;
            // After storing, mark the graph as endorsed
            mark_graph_as_endorsed(local_db, instance_id, graph_id).await?;
            // 3. if endorsed graph count >= threshold, generate & broadcast PeginConfirmNonce
            if get_endorsed_graph_count(local_db, instance_id).await?
                >= todo_funcs::min_required_operator()
            {
                let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
                let local_committee_pubkey =
                    committee_master_key.keypair_for_instance(instance_id).public_key().into();
                let stored_pub_nonce = get_committee_pub_nonce_for_instance(
                    local_db,
                    instance_id,
                    &local_committee_pubkey,
                )
                .await?;
                if stored_pub_nonce.is_none() {
                    let (_, pub_nonce, nonce_sig) =
                        committee_master_key.nonce_for_instance(instance_id);
                    let message_content =
                        GOATMessageContent::PeginConfirmNonce(PeginConfirmNonce {
                            instance_id,
                            committee_pubkey: local_committee_pubkey,
                            pub_nonce: pub_nonce.clone(),
                            nonce_sig,
                        });
                    send_to_peer(
                        swarm,
                        GOATMessage::from_typed(Actor::Committee, &message_content)?,
                    )?;
                    store_committee_pub_nonce_for_instance(
                        local_db,
                        instance_id,
                        local_committee_pubkey,
                        pub_nonce,
                    )
                    .await?;
                }
            }
            // 4. (Relayer) try to call Gateway.postGraphData
            // GraphFinalize may come after PostReady, so we need to check it here
            if is_relayer() {
                let pegin_data = goat_client.gateway_get_pegin_data(&instance_id).await?;
                if pegin_data.status != PeginStatus::Withdrawable {
                    // pegin not posted yet
                    return Ok(());
                }
                let graph_data = goat_client.gateway_get_graph_data(&graph_id).await?;
                if graph_data.operator_pubkey != [0u8; 32] {
                    // already posted
                    return Ok(());
                }
                let graph = Bitvm2Graph::from_simplified(&graph)?;
                let graph_data = build_graph_data(&graph)?;
                let endorse_sigs =
                    endorse_sigs.into_iter().map(|(_, _, sig)| sig).collect::<Vec<_>>();
                goat_client
                    .gateway_post_graph_data(&instance_id, &graph_id, &graph_data, &endorse_sigs)
                    .await?;
            }
        }
        (
            GOATMessageContent::GraphFinalize(GraphFinalize {
                instance_id,
                graph_id,
                graph,
                endorse_sigs,
                ..
            }),
            _,
        ) => {
            // received from Operator
            tracing::info!(
                "Handle GraphFinalize for {instance_id}:{graph_id} from {}",
                from_peer_id.to_string()
            );
            // 1. check graph data & ipfs cid
            if let Err(e) =
                todo_funcs::validate_finalized_graph(goat_client, &graph, &endorse_sigs).await
            {
                if let Some(msg) = e.downcast_ref::<SpecialError>() {
                    match msg {
                        SpecialError::InvalidGraph(err_msg) => {
                            tracing::warn!(
                                "Ignore GraphFinalize for {instance_id}:{graph_id} from {}: {err_msg}",
                                from_peer_id.to_string()
                            );
                            return Ok(());
                        }
                        _ => {}
                    }
                };
                bail!(e)
            }
            // 2. save the graph data to local db
            store_graph(local_db, &graph).await?;
        }
        (
            GOATMessageContent::PeginConfirmNonce(PeginConfirmNonce {
                instance_id,
                committee_pubkey: received_committee_pubkey,
                pub_nonce,
                nonce_sig,
            }),
            Actor::Committee,
        ) => {
            // received from Committee members
            tracing::info!(
                "Handle PeginConfirmNonce for {instance_id} from {}",
                received_committee_pubkey.to_string()
            );
            if !is_self_peer
                && let Err(e) = validate_committee(
                    goat_client,
                    &from_peer_id,
                    instance_id,
                    &received_committee_pubkey,
                )
                .await
            {
                if let Some(msg) = e.downcast_ref::<SpecialError>() {
                    match msg {
                        SpecialError::InvalidCommittee(err_msg) => {
                            tracing::warn!(
                                "Ignore PeginConfirmNonce for {instance_id} from {}: {err_msg}",
                                from_peer_id.to_string()
                            );
                            return Ok(());
                        }
                        SpecialError::EvmReverted(err_msg) => {
                            tracing::warn!(
                                "Ignore PeginConfirmNonce for {instance_id} from {}: fail to validate committee info on chain: {err_msg}",
                                from_peer_id.to_string()
                            );
                            return Ok(());
                        }
                        _ => {}
                    }
                };
                bail!(e);
            }
            // 1. check pub_nonce
            if !verify_public_nonce(
                &nonce_sig,
                &pub_nonce,
                &XOnlyPublicKey::from(received_committee_pubkey),
            ) {
                tracing::warn!(
                    "Ignore PeginConfirmNonce for {instance_id} from {}: invalid pub_nonce or nonce_sig",
                    received_committee_pubkey.to_string()
                );
                return Ok(());
            }
            // 2. save the pub_nonce to local db
            store_committee_pub_nonce_for_instance(
                local_db,
                instance_id,
                received_committee_pubkey,
                pub_nonce,
            )
            .await?;
            // 3. if received enough pub_nonces, generate partial signature & broadcast PeginConfirmPartialSig
            let committee_pubkeys = goat_client.gateway_get_committee_pubkeys(&instance_id).await?;
            let pub_nonces = get_committee_pub_nonces_for_instance(local_db, instance_id).await?;
            if pub_nonces.len() == committee_pubkeys.len() {
                let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
                let local_committee_pubkey =
                    committee_master_key.keypair_for_instance(instance_id).public_key().into();
                let (sec_nonce, _, _) = committee_master_key.nonce_for_instance(instance_id);
                let agg_nonce = nonce_aggregation(
                    &pub_nonces.iter().map(|(_, pn)| pn.clone()).collect::<Vec<_>>(),
                );
                let instance_params = get_instance_parameters(local_db, instance_id)
                    .await?
                    .ok_or_else(|| anyhow!("Instance parameters not found for {instance_id}"))?;
                let mut pegin_confirm = instance_params.build_pegin_tx()?.1;
                let context = instance_params
                    .get_verifier_context(committee_master_key.keypair_for_instance(instance_id))?;
                let partial_sig = pegin_confirm
                    .sign_input_0_musig2(&context, &sec_nonce, &agg_nonce)
                    .map_err(|e| anyhow!("Failed to sign pegin confirm for {instance_id}: {e}"))?;
                let endorse_sig =
                    endorse_pegin(goat_client, instance_id, &pegin_confirm.tx().compute_txid())
                        .await?;
                let message_content =
                    GOATMessageContent::PeginConfirmPartialSig(PeginConfirmPartialSig {
                        instance_id,
                        committee_pubkey: local_committee_pubkey,
                        partial_sig,
                        endorse_sig: endorse_sig.as_bytes().to_vec(),
                    });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::Committee, &message_content)?)?;
                store_committee_partial_sig_for_instance(
                    local_db,
                    instance_id,
                    local_committee_pubkey,
                    partial_sig,
                )
                .await?;
                store_committee_endorse_sig_for_pegin(
                    local_db,
                    instance_id,
                    local_committee_pubkey,
                    endorse_sig.as_bytes().to_vec(),
                )
                .await?;
                // 4. (Relayer) if received enough partial signatures, aggregate the sigs
                if is_relayer() {
                    let partial_sigs =
                        get_committee_partial_sigs_for_instance(local_db, instance_id)
                            .await?
                            .into_iter()
                            .map(|(_, ps)| ps)
                            .collect::<Vec<_>>();
                    let context = instance_params.get_base_context();
                    if partial_sigs.len() == committee_pubkeys.len() {
                        let full_sig = pegin_confirm
                            .aggregate_input_0_musig2_signatures(&context, partial_sigs, &agg_nonce)
                            .map_err(|e| {
                                anyhow!(
                                    "Failed to aggregate pegin confirm sigs for {instance_id}: {e}"
                                )
                            })?;
                        let connector_z = ConnectorZ::new(
                            context.network,
                            &context.n_of_n_taproot_public_key,
                            &instance_params.user_info.user_xonly_pubkey,
                        );
                        pegin_confirm.push_input_0_signature(&connector_z, full_sig);
                        broadcast_tx(btc_client, pegin_confirm.tx()).await?;
                    }
                }
            }
        }
        (
            GOATMessageContent::PeginConfirmPartialSig(PeginConfirmPartialSig {
                instance_id,
                committee_pubkey: received_committee_pubkey,
                partial_sig,
                endorse_sig,
            }),
            Actor::Committee,
        ) => {
            // received from Committee members
            tracing::info!(
                "Handle PeginConfirmPartialSig for {instance_id} from {}",
                received_committee_pubkey.to_string()
            );
            if !is_self_peer
                && let Err(e) = validate_committee(
                    goat_client,
                    &from_peer_id,
                    instance_id,
                    &received_committee_pubkey,
                )
                .await
            {
                if let Some(msg) = e.downcast_ref::<SpecialError>() {
                    match msg {
                        SpecialError::InvalidCommittee(err_msg) => {
                            tracing::warn!(
                                "Ignore PeginConfirmPartialSig for {instance_id} from {}: {err_msg}",
                                from_peer_id.to_string()
                            );
                            return Ok(());
                        }
                        SpecialError::EvmReverted(err_msg) => {
                            tracing::warn!(
                                "Ignore PeginConfirmPartialSig for {instance_id} from {}: fail to validate committee info on chain: {err_msg}",
                                from_peer_id.to_string()
                            );
                            return Ok(());
                        }
                        _ => {}
                    }
                };
                bail!(e);
            }
            // 1. save the partial signature & endorsement signature to local db
            // partial sigs will be validated when aggregating
            store_committee_partial_sig_for_instance(
                local_db,
                instance_id,
                received_committee_pubkey,
                partial_sig,
            )
            .await?;
            store_committee_endorse_sig_for_pegin(
                local_db,
                instance_id,
                received_committee_pubkey,
                endorse_sig,
            )
            .await?;
            // 3. (Relayer) if received enough partial signatures, aggregate the sigs
            if is_relayer() {
                let partial_sigs = get_committee_partial_sigs_for_instance(local_db, instance_id)
                    .await?
                    .into_iter()
                    .map(|(_, ps)| ps)
                    .collect::<Vec<_>>();
                let pub_nonces =
                    get_committee_pub_nonces_for_instance(local_db, instance_id).await?;
                let committee_pubkeys =
                    goat_client.gateway_get_committee_pubkeys(&instance_id).await?;
                if partial_sigs.len() == committee_pubkeys.len()
                    && pub_nonces.len() == committee_pubkeys.len()
                {
                    let instance_params =
                        get_instance_parameters(local_db, instance_id).await?.ok_or_else(|| {
                            anyhow!("Instance parameters not found for {instance_id}")
                        })?;
                    let context = instance_params.get_base_context();
                    let mut pegin_confirm = instance_params.build_pegin_tx()?.1;
                    let agg_nonce = nonce_aggregation(
                        &pub_nonces.iter().map(|(_, pn)| pn.clone()).collect::<Vec<_>>(),
                    );
                    let full_sig = pegin_confirm
                        .aggregate_input_0_musig2_signatures(&context, partial_sigs, &agg_nonce)
                        .map_err(|e| {
                            anyhow!("Failed to aggregate pegin confirm sigs for {instance_id}: {e}")
                        })?;
                    let connector_z = ConnectorZ::new(
                        context.network,
                        &context.n_of_n_taproot_public_key,
                        &instance_params.user_info.user_xonly_pubkey,
                    );
                    pegin_confirm.push_input_0_signature(&connector_z, full_sig);
                    broadcast_tx(btc_client, pegin_confirm.tx()).await?;
                }
            }
        }
        (GOATMessageContent::PostReady(PostReady { instance_id }), Actor::Committee) => {
            // triggered by PeginConfirm tx
            if !is_relayer() {
                return Ok(());
            }
            tracing::info!("Handle PostReady for {instance_id}");
            // 1. (Relayer)call Gateway.postPeginData on GoatChain
            let committee_pubkeys = goat_client.gateway_get_committee_pubkeys(&instance_id).await?;
            let pegin_data = goat_client.gateway_get_pegin_data(&instance_id).await?;
            if pegin_data.status == PeginStatus::None {
                tracing::warn!("Ignore PostReady for {instance_id}: not a pending pegin request");
                return Ok(());
            } else if pegin_data.status == PeginStatus::Pending {
                let instance_params = get_instance_parameters(local_db, instance_id)
                    .await?
                    .ok_or_else(|| anyhow!("Instance parameters not found for {instance_id}"))?;
                let pegin_confirm = instance_params.build_pegin_tx()?.1;
                let pegin_txid = pegin_confirm.tx().compute_txid();
                let pegin_tx = match btc_client.get_tx(&pegin_txid).await? {
                    Some(tx) => tx,
                    None => {
                        tracing::warn!(
                            "Ignore PostReady for {instance_id}: pegin confirm tx not found on Bitcoin chain: {pegin_txid}"
                        );
                        return Ok(());
                    }
                };
                let endorse_sigs = get_committee_endorse_sigs_for_pegin(local_db, instance_id)
                    .await?
                    .into_iter()
                    .map(|(_, es)| es)
                    .collect::<Vec<_>>();
                if endorse_sigs.len() != committee_pubkeys.len() {
                    tracing::warn!(
                        "Ignore PostReady for {instance_id}: not enough endorse sigs for pegin confirm tx: {}",
                        endorse_sigs.len()
                    );
                    return Ok(());
                }
                let pegin_height = match btc_client.get_tx_status(&pegin_txid).await?.block_height {
                    Some(height) => height as u64,
                    None => {
                        let delay_secs = todo_funcs::avg_block_time_secs(btc_client.network()); // wait for 1 blocks
                        push_local_unhandled_messages(
                            local_db,
                            instance_id,
                            &message,
                            delay_secs as usize,
                        )
                        .await?;
                        tracing::info!(
                            "Retry postPeginData later for {instance_id}: pegin confirm tx not confirmed on btc yet"
                        );
                        return Ok(());
                    }
                };
                let goat_confirmed_height = goat_client.btc_spv_latest_height().await?;
                if goat_confirmed_height < pegin_height {
                    let delay_secs = todo_funcs::avg_block_time_secs(btc_client.network())
                        * (pegin_height - goat_confirmed_height);
                    push_local_unhandled_messages(
                        local_db,
                        instance_id,
                        &message,
                        delay_secs as usize,
                    )
                    .await?;
                    tracing::info!(
                        "Retry postPeginData later for {instance_id}: pegin confirm tx block not posted to goat spv contract yet"
                    );
                    return Ok(());
                }
                goat_client
                    .gateway_post_pegin_data(btc_client, &instance_id, &pegin_tx, &endorse_sigs)
                    .await?;
            } else {
                // already posted
            }
            // 2. (Relayer)call Gateway.postGraphData on GoatChain
            let graph_ids = get_graph_ids_for_instance(local_db, instance_id).await?;
            for graph_id in &graph_ids {
                let graph_data = goat_client.gateway_get_graph_data(graph_id).await?;
                if graph_data.operator_pubkey != [0u8; 32] {
                    // already posted
                    continue;
                }
                let endorsement_sigs =
                    get_committee_endorsements_for_graph(local_db, instance_id, *graph_id)
                        .await?
                        .into_iter()
                        .map(|(_, _, sig)| sig)
                        .collect::<Vec<_>>();
                if endorsement_sigs.len() != committee_pubkeys.len() {
                    tracing::warn!(
                        "Ignore postGraphData for {instance_id}:{graph_id}: not enough endorse sigs for graph: {}",
                        endorsement_sigs.len()
                    );
                    continue;
                }
                let graph = get_graph(local_db, instance_id, *graph_id)
                    .await?
                    .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
                let graph = Bitvm2Graph::from_simplified(&graph)?;
                let graph_data = build_graph_data(&graph)?;
                goat_client
                    .gateway_post_graph_data(&instance_id, graph_id, &graph_data, &endorsement_sigs)
                    .await?;
            }
        }
        (
            GOATMessageContent::KickoffReady(KickoffReady { instance_id, graph_id }),
            Actor::Operator,
        ) => {
            // triggered by InitWithdraw event from GoatChain
            tracing::info!("Handle KickoffReady for {instance_id}:{graph_id}");
            let graph = match get_graph_or_defer(
                swarm,
                local_db,
                goat_client,
                instance_id,
                graph_id,
                &message,
            )
            .await?
            {
                Some(g) => g,
                None => return Ok(()),
            };
            let mut graph = Bitvm2Graph::from_simplified(&graph)?;
            let operator_pubkey = graph.parameters.operator_pubkey;
            let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
            let node_pubkey: PublicKey = operator_master_key.master_keypair().public_key().into();
            if node_pubkey != operator_pubkey {
                tracing::warn!("Ignore KickoffReady for {instance_id}:{graph_id}: not my graph");
                return Ok(());
            }
            // 1. check the withdraw status on GoatChain
            let withdraw_status = goat_client.gateway_get_withdraw_data(&graph_id).await?.status;
            if withdraw_status != WithdrawStatus::Initialized {
                tracing::warn!(
                    "Ignore KickoffReady for {instance_id}:{graph_id}: invalid withdraw status: {withdraw_status:?}"
                );
                return Ok(());
            }
            // 2. check prekickoff nonce & broadcast previous pre-kickoff if needed
            let start_nonce =
                match get_latest_pegout_finalized_graph(local_db, &operator_pubkey).await? {
                    Some((n, _)) => n + 1,
                    None => 0,
                };
            for current_nonce in start_nonce..graph.parameters.graph_nonce {
                let (current_instance_id, current_graph_id) = match get_graph_id_by_nonce(
                    local_db,
                    current_nonce,
                    &operator_pubkey,
                )
                .await?
                {
                    Some(gid) => gid,
                    None => {
                        tracing::warn!(
                            "Ignore KickoffReady for {instance_id}:{graph_id}: missing graph for Operator {operator_pubkey}: nonce {current_nonce}"
                        );
                        continue;
                    }
                };
                let current_graph = match get_graph_or_defer(
                    swarm,
                    local_db,
                    goat_client,
                    current_instance_id,
                    current_graph_id,
                    &message,
                )
                .await?
                {
                    Some(g) => g,
                    None => return Ok(()),
                };
                let mut current_graph = Bitvm2Graph::from_simplified(&current_graph)?;
                let current_graph_start_status =
                    get_graph_status(local_db, current_instance_id, current_graph_id)
                        .await?
                        .ok_or_else(|| {
                            anyhow!("Graph status not found for {instance_id}:{graph_id}")
                        })?;
                let (current_graph_status, current_graph_sub_status) = refresh_graph(
                    local_db,
                    btc_client,
                    goat_client,
                    current_instance_id,
                    current_graph_id,
                    Some(&current_graph),
                    Some(current_graph_start_status),
                    None,
                )
                .await?;
                compensate_graph_events(
                    local_db,
                    btc_client,
                    current_instance_id,
                    current_graph_id,
                    Some(&current_graph),
                    Some(current_graph_start_status),
                    current_graph_start_status,
                    current_graph_status,
                    current_graph_sub_status,
                )
                .await?;
                if current_graph_status.is_closed() {
                    continue;
                } else if current_graph_status.is_pegout_started() {
                    tracing::warn!(
                        "Ignore KickoffReady for {instance_id}:{graph_id}: previous graph not finalized for Operator {operator_pubkey}: {current_instance_id}:{current_graph_id}"
                    );
                    return Ok(());
                } else if current_graph_status.is_obsoleted() {
                    operator_skip_graph(btc_client, &mut current_graph).await?;
                    tracing::info!(
                        "Operator {operator_pubkey} skipped obsoleted graph {current_instance_id}:{current_graph_id}"
                    );
                    let delay_secs = todo_funcs::avg_block_time_secs(btc_client.network()); // wait for 1 blocks
                    push_local_unhandled_messages(
                        local_db,
                        current_graph_id,
                        &message,
                        delay_secs as usize,
                    )
                    .await?;
                    return Ok(());
                } else {
                    let graph_data_on_goat =
                        goat_client.gateway_get_graph_data(&current_graph_id).await?;
                    if graph_data_on_goat.operator_pubkey != [0u8; 32] {
                        tracing::warn!(
                            "Ignore KickoffReady for {instance_id}:{graph_id}: previous available graph exists for Operator {operator_pubkey}: {current_instance_id}:{current_graph_id}, please withdraw it first"
                        );
                        return Ok(());
                    }
                    operator_skip_graph(btc_client, &mut current_graph).await?;
                    tracing::info!(
                        "Operator {operator_pubkey} skipped non-posted graph {current_instance_id}:{current_graph_id}"
                    );
                    let delay_secs = todo_funcs::avg_block_time_secs(btc_client.network()); // wait for 1 blocks
                    push_local_unhandled_messages(
                        local_db,
                        current_graph_id,
                        &message,
                        delay_secs as usize,
                    )
                    .await?;
                    return Ok(());
                }
            }
            // 3. sign & broadcast prekickoff & kickoff txns
            operator_kickoff(btc_client, &mut graph).await?;
        }
        (
            GOATMessageContent::KickoffSent(KickoffSent { instance_id, graph_id }),
            Actor::Committee,
        ) => {
            // triggered by Kickoff tx
            // 1. update status
            tracing::info!("Handle KickoffSent for {instance_id}:{graph_id}");
            let graph = get_graph(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
            let graph = Bitvm2Graph::from_simplified(&graph)?;
            let graph_start_status = get_graph_status(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph status not found for {instance_id}:{graph_id}"))?;
            let (graph_status, sub_status) = refresh_graph(
                local_db,
                btc_client,
                goat_client,
                instance_id,
                graph_id,
                Some(&graph),
                Some(graph_start_status),
                None,
            )
            .await?;
            tracing::info!("Graph {graph_id} latest status: {graph_status}");
            compensate_graph_events(
                local_db,
                btc_client,
                instance_id,
                graph_id,
                Some(&graph),
                Some(graph_start_status),
                GraphStatus::OperatorKickOff,
                graph_status,
                sub_status,
            )
            .await?;
            if !is_relayer() {
                return Ok(());
            }
            // 2. (Relayer) try to call Gateway.proceedWithdraw
            let withdraw_status = goat_client.gateway_get_withdraw_data(&graph_id).await?.status;
            if withdraw_status != WithdrawStatus::Initialized {
                tracing::warn!(
                    "Relayer Ignore proceedWithdraw for {instance_id}:{graph_id}: invalid withdraw status: {withdraw_status:?}"
                );
                return Ok(());
            }
            let kickoff_txid = graph.kickoff.tx().compute_txid();
            let kickoff_tx = match btc_client.get_tx(&kickoff_txid).await? {
                Some(tx) => tx,
                None => {
                    tracing::warn!(
                        "Relayer Ignore proceedWithdraw for {instance_id}:{graph_id}: kickoff tx not found on Bitcoin chain: {kickoff_txid}"
                    );
                    return Ok(());
                }
            };
            let kickoff_height = match btc_client.get_tx_status(&kickoff_txid).await?.block_height {
                Some(height) => height as u64,
                None => {
                    let delay_secs = todo_funcs::avg_block_time_secs(btc_client.network()); // wait for 1 blocks
                    push_local_unhandled_messages(
                        local_db,
                        graph_id,
                        &message,
                        delay_secs as usize,
                    )
                    .await?;
                    tracing::info!(
                        "Retry proceedWithdraw later for {instance_id}:{graph_id}: kickoff tx not confirmed on btc yet"
                    );
                    return Ok(());
                }
            };
            let goat_confirmed_btc_height = goat_client.btc_spv_latest_height().await?;
            if goat_confirmed_btc_height < kickoff_height {
                let delay_secs = todo_funcs::avg_block_time_secs(btc_client.network())
                    * (kickoff_height - goat_confirmed_btc_height);
                push_local_unhandled_messages(local_db, graph_id, &message, delay_secs as usize)
                    .await?;
                tracing::info!(
                    "Retry proceedWithdraw later for {instance_id}:{graph_id}: kickoff tx block not posted to goat spv contract yet"
                );
                return Ok(());
            }
            goat_client.gateway_process_withdraw(btc_client, &graph_id, &kickoff_tx).await?;
        }
        (
            GOATMessageContent::KickoffSent(KickoffSent { instance_id, graph_id }),
            Actor::Challenger,
        ) => {
            // triggered by Kickoff tx
            tracing::info!("Handle KickoffSent for {instance_id}:{graph_id}");
            let graph = match get_graph_or_defer(
                swarm,
                local_db,
                goat_client,
                instance_id,
                graph_id,
                &message,
            )
            .await?
            {
                Some(g) => g,
                None => return Ok(()),
            };
            let graph = Bitvm2Graph::from_simplified(&graph)?;
            let graph_start_status = get_graph_status(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph status not found for {instance_id}:{graph_id}"))?;
            let (graph_status, sub_status) = refresh_graph(
                local_db,
                btc_client,
                goat_client,
                instance_id,
                graph_id,
                Some(&graph),
                Some(graph_start_status),
                None,
            )
            .await?;
            tracing::info!("Graph {graph_id} latest status: {graph_status}");
            compensate_graph_events(
                local_db,
                btc_client,
                instance_id,
                graph_id,
                Some(&graph),
                Some(graph_start_status),
                GraphStatus::OperatorKickOff,
                graph_status,
                sub_status,
            )
            .await?;
            // 1. check kickoff tx status on Bitcoin chain
            let kickoff_txid = graph.kickoff.tx().compute_txid();
            let kickoff_height = match btc_client.get_tx_status(&kickoff_txid).await?.block_height {
                Some(height) => height,
                None => {
                    tracing::warn!(
                        "Ignore KickoffSent for {instance_id}:{graph_id}: kickoff tx not confirmed yet"
                    );
                    return Ok(());
                }
            };
            let take1_txid = graph.take1.tx().compute_txid();
            let (challenge_tx, _) = export_challenge_tx(&graph).unwrap();
            let kickoff_challenge_outpoint = challenge_tx.input[0].previous_output;
            if let Some(spent_txid) = outpoint_spent_txid(
                btc_client,
                &kickoff_challenge_outpoint.txid,
                kickoff_challenge_outpoint.vout as u64,
            )
            .await?
            {
                let spent_tx_name = if spent_txid == take1_txid { "Take1" } else { "Challenge" };
                tracing::warn!(
                    "Ignore KickoffSent for {instance_id}:{graph_id}: kickoff challenge connector already spent by {spent_tx_name}: {spent_txid}"
                );
                return Ok(());
            }
            // 2. check withdraw status, if it's invalid, sign & broadcast challenge txn
            let withdraw_status = goat_client.gateway_get_withdraw_data(&graph_id).await?.status;
            let goat_confirmed_btc_height = goat_client.btc_spv_latest_height().await? as u32;
            if [WithdrawStatus::None, WithdrawStatus::Canceled].contains(&withdraw_status) {
                if kickoff_height >= goat_confirmed_btc_height {
                    let delay_secs = (kickoff_height + 1 - goat_confirmed_btc_height)
                        * todo_funcs::avg_block_time_secs(btc_client.network()) as u32;
                    push_local_unhandled_messages(
                        local_db,
                        graph_id,
                        &message,
                        delay_secs as usize,
                    )
                    .await?;
                } else {
                    if let Err(e) = send_challenge_tx(btc_client, &graph).await {
                        if let Some(msg) = e.downcast_ref::<SpecialError>() {
                            match msg {
                                SpecialError::InsufficientBalance(err_msg) => {
                                    tracing::warn!(
                                        "Ignore KickoffSent for {instance_id}:{graph_id}: insufficient balance to send challenge tx: {err_msg}"
                                    );
                                    return Ok(());
                                }
                                _ => {}
                            }
                        };
                        bail!(e)
                    }
                }
            } else {
                tracing::info!(
                    "No action needed for KickoffSent for {instance_id}:{graph_id}: withdraw status is {withdraw_status:?}"
                );
            }
        }
        (GOATMessageContent::KickoffSent(KickoffSent { instance_id, graph_id }), _) => {
            // triggered by Kickoff tx
            tracing::info!("Handle KickoffSent for {instance_id}:{graph_id}");
            let graph = match get_graph_or_defer(
                swarm,
                local_db,
                goat_client,
                instance_id,
                graph_id,
                &message,
            )
            .await?
            {
                Some(g) => g,
                None => return Ok(()),
            };
            let graph = Bitvm2Graph::from_simplified(&graph)?;
            let graph_start_status = get_graph_status(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph status not found for {instance_id}:{graph_id}"))?;
            let (graph_status, sub_status) = refresh_graph(
                local_db,
                btc_client,
                goat_client,
                instance_id,
                graph_id,
                Some(&graph),
                Some(graph_start_status),
                None,
            )
            .await?;
            tracing::info!("Graph {graph_id} latest status: {graph_status}");
            compensate_graph_events(
                local_db,
                btc_client,
                instance_id,
                graph_id,
                Some(&graph),
                Some(graph_start_status),
                GraphStatus::OperatorKickOff,
                graph_status,
                sub_status,
            )
            .await?;
        }
        (
            GOATMessageContent::PreKickoffSent(PreKickoffSent { instance_id, graph_id }),
            Actor::Challenger,
        ) => {
            // triggered by PreKickoff tx
            tracing::info!("Handle PreKickoffSent for {instance_id}:{graph_id}");
            let graph = match get_graph_or_defer(
                swarm,
                local_db,
                goat_client,
                instance_id,
                graph_id,
                &message,
            )
            .await?
            {
                Some(g) => g,
                None => return Ok(()),
            };
            let graph = Bitvm2Graph::from_simplified(&graph)?;
            let graph_start_status = get_graph_status(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph status not found for {instance_id}:{graph_id}"))?;
            let (graph_status, sub_status) = refresh_graph(
                local_db,
                btc_client,
                goat_client,
                instance_id,
                graph_id,
                Some(&graph),
                Some(graph_start_status),
                None,
            )
            .await?;
            tracing::info!("Graph {graph_id} latest status: {graph_status}");
            compensate_graph_events(
                local_db,
                btc_client,
                instance_id,
                graph_id,
                Some(&graph),
                Some(graph_start_status),
                GraphStatus::PreKickoff,
                graph_status,
                sub_status,
            )
            .await?;
            // 1. check the previous graph status
            if !tx_on_chain(
                btc_client,
                &graph.parameters.prekickoff_parameters.cur_prekickoff_txn.tx().compute_txid(),
            )
            .await?
            {
                tracing::warn!(
                    "Ignore PreKickoffSent for {instance_id}:{graph_id}: prekickoff tx not found on chain"
                );
                return Ok(());
            }
            let graph_nonce = graph.parameters.graph_nonce;
            if graph_nonce == 0 {
                return Ok(());
            }
            let (prev_instance_id, prev_graph_id) =
                get_graph_id_by_nonce(local_db, graph_nonce - 1, &graph.parameters.operator_pubkey)
                    .await?
                    .ok_or_else(|| {
                        anyhow!(
                            "Previous graph not found for Operator {}: nonce {}",
                            graph.parameters.operator_pubkey,
                            graph_nonce - 1
                        )
                    })?;
            let prev_graph = match get_graph_or_defer(
                swarm,
                local_db,
                goat_client,
                prev_instance_id,
                prev_graph_id,
                &message,
            )
            .await?
            {
                Some(g) => g,
                None => return Ok(()),
            };
            let prev_graph = Bitvm2Graph::from_simplified(&prev_graph)?;
            let prev_graph_start_status =
                get_graph_status(local_db, prev_instance_id, prev_graph_id).await?.ok_or_else(
                    || {
                        anyhow!(
                            "Previous graph status not found for {prev_instance_id}:{prev_graph_id}"
                        )
                    },
                )?;
            let (prev_graph_status, prev_graph_sub_status) = refresh_graph(
                local_db,
                btc_client,
                goat_client,
                prev_instance_id,
                prev_graph_id,
                Some(&prev_graph),
                Some(prev_graph_start_status),
                None,
            )
            .await?;
            compensate_graph_events(
                local_db,
                btc_client,
                prev_instance_id,
                prev_graph_id,
                Some(&prev_graph),
                Some(prev_graph_start_status),
                prev_graph_start_status,
                prev_graph_status,
                prev_graph_sub_status,
            )
            .await?;
            if !tx_on_chain(btc_client, &prev_graph.kickoff.tx().compute_txid()).await? {
                // 2. if previous kickoff not started, broadcast force-skip-kickoff txn
                challenger_force_skip_kickoff(btc_client, &prev_graph).await?;
            } else if !prev_graph_status.is_closed() {
                // 3. if previous kickoff is not closed, broadcast quick-challenge/challenge-incomplete-kickoff txn
                challenger_quick_challenge(btc_client, &prev_graph).await?;
            }
        }
        (GOATMessageContent::PreKickoffSent(PreKickoffSent { instance_id, graph_id }), _) => {
            // triggered by PreKickoff tx
            tracing::info!("Handle PreKickoffSent for {instance_id}:{graph_id}");
            let graph = get_graph(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
            let graph = Bitvm2Graph::from_simplified(&graph)?;
            let graph_start_status = get_graph_status(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph status not found for {instance_id}:{graph_id}"))?;
            let (graph_status, sub_status) = refresh_graph(
                local_db,
                btc_client,
                goat_client,
                instance_id,
                graph_id,
                Some(&graph),
                Some(graph_start_status),
                None,
            )
            .await?;
            tracing::info!("Graph {graph_id} latest status: {graph_status}");
            compensate_graph_events(
                local_db,
                btc_client,
                instance_id,
                graph_id,
                Some(&graph),
                Some(graph_start_status),
                GraphStatus::PreKickoff,
                graph_status,
                sub_status,
            )
            .await?;
        }
        (
            GOATMessageContent::ChallengeSent(ChallengeSent {
                instance_id,
                graph_id,
                challenge_txid,
            }),
            Actor::Operator,
        ) => {
            // triggered by Challenge tx
            tracing::info!("Handle ChallengeSent for {instance_id}:{graph_id}");
            let graph = match get_graph_or_defer(
                swarm,
                local_db,
                goat_client,
                instance_id,
                graph_id,
                &message,
            )
            .await?
            {
                Some(g) => g,
                None => return Ok(()),
            };
            let mut graph = Bitvm2Graph::from_simplified(&graph)?;
            let graph_start_status = get_graph_status(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph status not found for {instance_id}:{graph_id}"))?;
            let (graph_status, sub_status) = refresh_graph(
                local_db,
                btc_client,
                goat_client,
                instance_id,
                graph_id,
                Some(&graph),
                Some(graph_start_status),
                None,
            )
            .await?;
            tracing::info!("Graph {graph_id} latest status: {graph_status}");
            compensate_graph_events(
                local_db,
                btc_client,
                instance_id,
                graph_id,
                Some(&graph),
                Some(graph_start_status),
                GraphStatus::Challenge,
                graph_status,
                sub_status,
            )
            .await?;
            // 1. check the challenge tx status on Bitcoin chain
            let watchtower_challenge_init_txid =
                graph.watchtower_challenge_init.tx().compute_txid();
            if tx_on_chain(btc_client, &watchtower_challenge_init_txid).await? {
                tracing::warn!(
                    "Ignore ChallengeSent for {instance_id}:{graph_id}: watchtower challenge init tx already sent"
                );
                return Ok(());
            }
            let kickoff_txid = graph.kickoff.tx().compute_txid();
            if let Some(challenge_tx) = btc_client.get_tx(&challenge_txid).await? {
                let challenge_outpoint = OutPoint { txid: kickoff_txid, vout: 0 };
                if challenge_tx.input[0].previous_output != challenge_outpoint {
                    tracing::warn!(
                        "Ignore ChallengeSent for {instance_id}:{graph_id}: invalid challenge tx: input[0] does not match kickoff connector_A"
                    );
                    return Ok(());
                }
            } else {
                tracing::warn!(
                    "Ignore ChallengeSent for {instance_id}:{graph_id}: challenge tx not found"
                );
                return Ok(());
            }
            // 2. if the challenge is confirmed, sign & broadcast watchtower-challenge-init txn
            let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
            let watchtower_challenge_init_tx = operator_sign_watchtower_challenge_init(
                operator_master_key.master_keypair(),
                &mut graph,
            )?;
            let anchor_vout = watchtower_challenge_init_tx.output.len() as u64 - 1;
            let watchtower_challenge_init_tx_total_input_amount =
                graph.watchtower_challenge_init.prev_outs().iter().map(|o| o.value).sum();
            let child_tx = build_cpfp_txns(
                btc_client,
                &watchtower_challenge_init_tx,
                anchor_vout,
                watchtower_challenge_init_tx_total_input_amount,
            )
            .await?;
            match child_tx {
                Some(tx) => {
                    broadcast_package(btc_client, &[watchtower_challenge_init_tx, tx], true).await?
                }
                None => broadcast_tx(btc_client, &watchtower_challenge_init_tx).await?,
            };
        }
        (GOATMessageContent::ChallengeSent(ChallengeSent { instance_id, graph_id, .. }), _) => {
            // triggered by Challenge tx
            tracing::info!("Handle ChallengeSent for {instance_id}:{graph_id}");
            let graph = get_graph(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
            let graph = Bitvm2Graph::from_simplified(&graph)?;
            let graph_start_status = get_graph_status(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph status not found for {instance_id}:{graph_id}"))?;
            let (graph_status, sub_status) = refresh_graph(
                local_db,
                btc_client,
                goat_client,
                instance_id,
                graph_id,
                Some(&graph),
                Some(graph_start_status),
                None,
            )
            .await?;
            tracing::info!("Graph {graph_id} latest status: {graph_status}");
            compensate_graph_events(
                local_db,
                btc_client,
                instance_id,
                graph_id,
                Some(&graph),
                Some(graph_start_status),
                GraphStatus::Challenge,
                graph_status,
                sub_status,
            )
            .await?;
        }
        (
            GOATMessageContent::WatchtowerChallengeInitSent(WatchtowerChallengeInitSent {
                instance_id,
                graph_id,
            }),
            Actor::Watchtower,
        ) => {
            // triggered by WatchtowerChallengeInit tx
            tracing::info!("Handle WatchtowerChallengeInitSent for {instance_id}:{graph_id}");
            let graph = match get_graph_or_defer(
                swarm,
                local_db,
                goat_client,
                instance_id,
                graph_id,
                &message,
            )
            .await?
            {
                Some(g) => g,
                None => return Ok(()),
            };
            let watchtower_keypair = WatchtowerMasterKey::new(get_bitvm_key()?).master_keypair();
            let node_index = match graph
                .parameters
                .watchtower_pubkeys
                .iter()
                .position(|pk| *pk == watchtower_keypair.public_key().x_only_public_key().0)
            {
                Some(index) => index,
                None => {
                    tracing::warn!(
                        "Ignore WatchtowerChallengeInitSent for {instance_id}:{graph_id}: not in the watchtower list"
                    );
                    return Ok(());
                }
            };
            let graph = Bitvm2Graph::from_simplified(&graph)?;
            let watchtower_challenge_init_txid =
                graph.watchtower_challenge_init.tx().compute_txid();
            if !tx_on_chain(btc_client, &watchtower_challenge_init_txid).await? {
                tracing::warn!(
                    "Ignore WatchtowerChallengeInitSent for {instance_id}:{graph_id}: watchtower challenge init tx not found on chain"
                );
                return Ok(());
            }
            // 1. check the withdraw status on GoatChain, if the withdraw is invalid, sign & broadcast watchtower-challenge txn
            let withdraw_status = goat_client.gateway_get_withdraw_data(&graph_id).await?.status;
            if [WithdrawStatus::None, WithdrawStatus::Canceled].contains(&withdraw_status) {
                let watchtower_proof =
                    todo_funcs::get_watchtower_proof(instance_id, graph_id).await?;
                if let Err(e) =
                    send_watchtower_challenge_tx(btc_client, &graph, node_index, watchtower_proof)
                        .await
                {
                    if let Some(msg) = e.downcast_ref::<SpecialError>() {
                        match msg {
                            SpecialError::InsufficientBalance(err_msg) => {
                                tracing::warn!(
                                    "Ignore WatchtowerChallengeInitSent for {instance_id}:{graph_id}: insufficient balance to send watchtower challenge tx: {err_msg}"
                                );
                                return Ok(());
                            }
                            _ => {}
                        }
                    };
                    bail!(e)
                }
            }
        }
        (
            GOATMessageContent::WatchtowerChallengeSent(WatchtowerChallengeSent {
                instance_id,
                graph_id,
                watchtower_challenge_txids,
            }),
            Actor::Operator,
        ) => {
            // triggered by WatchtowerChallenge tx
            tracing::info!(
                "Handle WatchtowerChallengeSent for {instance_id}:{graph_id}, included watchtower indexes: {:?}",
                watchtower_challenge_txids.iter().map(|(index, _)| index).collect::<Vec<_>>()
            );
            // 1. check the watchtower-challenge tx status on Bitcoin chain, if watchtower challenge tx is confirmed, sign & broadcast operator-ack txn
            let graph = match get_graph_or_defer(
                swarm,
                local_db,
                goat_client,
                instance_id,
                graph_id,
                &message,
            )
            .await?
            {
                Some(g) => g,
                None => return Ok(()),
            };
            let mut graph = Bitvm2Graph::from_simplified(&graph)?;
            let watchtower_challenge_init_txid =
                graph.watchtower_challenge_init.tx().compute_txid();
            let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
            let operator_graph_keypair = operator_master_key.master_keypair();
            let operator_master_keypair = operator_master_key.master_keypair();
            for (watchtower_index, watchtower_challenge_txid) in watchtower_challenge_txids {
                tracing::info!(
                    "Handle WatchtowerChallengeSent for {instance_id}:{graph_id}:{watchtower_index}"
                );
                let watchtower_challenge_tx = match btc_client
                    .get_tx(&watchtower_challenge_txid)
                    .await?
                {
                    Some(tx) => tx,
                    None => {
                        tracing::warn!(
                            "Ignore WatchtowerChallengeSent for {instance_id}:{graph_id}:{watchtower_index}: watchtower challenge tx {watchtower_challenge_txid} not found"
                        );
                        continue;
                    }
                };
                let watchtower_challenge_outpoint = OutPoint {
                    txid: watchtower_challenge_init_txid,
                    vout: 2 * watchtower_index as u32,
                };
                if watchtower_challenge_tx.input[0].previous_output != watchtower_challenge_outpoint
                {
                    tracing::warn!(
                        "Ignore WatchtowerChallengeSent for {instance_id}:{graph_id}: invalid watchtower challenge tx {watchtower_challenge_txid}: input[0] does not match watchtower challenge connector"
                    );
                    continue;
                }
                let preimage =
                    todo_funcs::get_preimage(local_db, instance_id, graph_id, watchtower_index)
                        .await?;
                let (ack_txin, ack_txin_amount) = operator_sign_ack(
                    operator_graph_keypair,
                    &mut graph,
                    watchtower_index,
                    &preimage,
                )?;
                build_sign_and_broadcast_tx(
                    btc_client,
                    operator_master_keypair,
                    vec![ack_txin],
                    ack_txin_amount,
                    vec![],
                )
                .await?;
            }
        }
        (
            GOATMessageContent::WatchtowerChallengeTimeout(WatchtowerChallengeTimeout {
                instance_id,
                graph_id,
                watchtower_indexes,
            }),
            Actor::Operator,
        ) => {
            // triggered by timeout task
            tracing::info!(
                "Handle WatchtowerChallengeTimeout for {instance_id}:{graph_id}, watchtower indexes: {:?}",
                watchtower_indexes
            );
            let graph = match get_graph_or_defer(
                swarm,
                local_db,
                goat_client,
                instance_id,
                graph_id,
                &message,
            )
            .await?
            {
                Some(g) => g,
                None => return Ok(()),
            };
            let mut graph = Bitvm2Graph::from_simplified(&graph)?;
            let watchtower_challenge_init_txid =
                graph.watchtower_challenge_init.tx().compute_txid();
            let watchtower_challenge_init_height = match btc_client
                .get_tx_status(&watchtower_challenge_init_txid)
                .await?
                .block_height
            {
                Some(height) => height,
                None => {
                    tracing::warn!(
                        "Ignore WatchtowerChallengeTimeout for {instance_id}:{graph_id}: watchtower challenge init tx not confirmed yet"
                    );
                    return Ok(());
                }
            };
            let current_height = btc_client.get_height().await?;
            if current_height
                < watchtower_challenge_init_height
                    + watchtower_challenge_timeout_timelock(get_network())
            {
                tracing::warn!(
                    "Ignore WatchtowerChallengeTimeout for {instance_id}:{graph_id}: watchtower challenge init tx timelock not expired yet"
                );
                return Ok(());
            }
            let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
            let operator_master_keypair = operator_master_key.master_keypair();
            // 1. sign & broadcast watchtower-challenge-timeout txn
            for watchtower_index in watchtower_indexes {
                tracing::info!(
                    "Handle WatchtowerChallengeTimeout for {instance_id}:{graph_id}:{watchtower_index}"
                );
                let watchtower_challenge_vout = 2 * watchtower_index as u64;
                if outpoint_spent_txid(
                    btc_client,
                    &watchtower_challenge_init_txid,
                    watchtower_challenge_vout,
                )
                .await?
                .is_some()
                {
                    continue;
                }
                let watchtower_challenge_timeout_tx = operator_sign_watchtower_challenge_timeout(
                    operator_master_keypair,
                    &mut graph,
                    watchtower_index,
                )?;
                let anchor_vout = watchtower_challenge_timeout_tx.output.len() as u64 - 1;
                let watchtower_challenge_timeout_tx_total_input_amount = graph
                    .watchtower_challenge_timeout_txns[watchtower_index]
                    .prev_outs()
                    .iter()
                    .map(|o| o.value)
                    .sum();
                let child_tx = build_cpfp_txns(
                    btc_client,
                    &watchtower_challenge_timeout_tx,
                    anchor_vout,
                    watchtower_challenge_timeout_tx_total_input_amount,
                )
                .await?;
                match child_tx {
                    Some(tx) => {
                        broadcast_package(btc_client, &[watchtower_challenge_timeout_tx, tx], true)
                            .await?
                    }
                    None => broadcast_tx(btc_client, &watchtower_challenge_timeout_tx).await?,
                };
            }
        }
        (
            GOATMessageContent::OperatorAckTimeout(OperatorAckTimeout { instance_id, graph_id }),
            Actor::Challenger,
        ) => {
            // triggered by timeout task
            tracing::info!("Handle OperatorAckTimeout for {instance_id}:{graph_id}");
            let graph = match get_graph_or_defer(
                swarm,
                local_db,
                goat_client,
                instance_id,
                graph_id,
                &message,
            )
            .await?
            {
                Some(g) => g,
                None => return Ok(()),
            };
            let graph = Bitvm2Graph::from_simplified(&graph)?;
            let watchtower_challenge_init_txid =
                graph.watchtower_challenge_init.tx().compute_txid();
            let connector_f_vout = 1 + 2 * graph.parameters.watchtower_pubkeys.len() as u64;
            if outpoint_spent_txid(btc_client, &watchtower_challenge_init_txid, connector_f_vout)
                .await?
                .is_some()
            {
                tracing::warn!(
                    "Ignore OperatorAckTimeout for {instance_id}:{graph_id}: connector_F already spent"
                );
                return Ok(());
            }
            let current_height = btc_client.get_height().await?;
            let watchtower_challenge_init_height = match btc_client
                .get_tx_status(&watchtower_challenge_init_txid)
                .await?
                .block_height
            {
                Some(height) => height,
                None => {
                    tracing::warn!(
                        "Ignore OperatorAckTimeout for {instance_id}:{graph_id}: watchtower challenge init tx not confirmed yet"
                    );
                    return Ok(());
                }
            };
            if current_height < watchtower_challenge_init_height + nack_timelock(get_network()) {
                tracing::warn!(
                    "Ignore OperatorAckTimeout for {instance_id}:{graph_id}: watchtower challenge init tx timelock not expired yet"
                );
                return Ok(());
            }
            let mut nack_index = None;
            for watchtower_index in 0..graph.parameters.watchtower_pubkeys.len() {
                let ack_vout = 1 + 2 * watchtower_index as u64;
                if outpoint_spent_txid(btc_client, &watchtower_challenge_init_txid, ack_vout)
                    .await?
                    .is_none()
                {
                    nack_index = Some(watchtower_index);
                    break;
                }
            }
            let nack_index = match nack_index {
                Some(index) => index,
                None => {
                    tracing::warn!(
                        "Ignore OperatorAckTimeout for {instance_id}:{graph_id}: all ack connectors already spent"
                    );
                    return Ok(());
                }
            };
            // 1. broadcast Nack txn
            let nack_tx = graph
                .nack_txns
                .get(nack_index)
                .ok_or_else(|| {
                    anyhow!("Nack txn not found for {instance_id}:{graph_id}:{nack_index}")
                })?
                .finalize();
            let anchor_vout = nack_tx.output.len() as u64 - 1;
            let nack_tx_total_input_amount =
                graph.nack_txns[nack_index].prev_outs().iter().map(|o| o.value).sum();
            let child_tx =
                build_cpfp_txns(btc_client, &nack_tx, anchor_vout, nack_tx_total_input_amount)
                    .await?;
            match child_tx {
                Some(tx) => broadcast_package(btc_client, &[nack_tx, tx], true).await?,
                None => broadcast_package(btc_client, &[nack_tx], true).await?,
            };
        }
        (
            GOATMessageContent::OperatorCommitBlockHashReady(OperatorCommitBlockHashReady {
                instance_id,
                graph_id,
            }),
            Actor::Operator,
        ) => {
            // triggered by timeout task
            tracing::info!("Handle OperatorCommitBlockHashReady for {instance_id}:{graph_id}");
            let graph = match get_graph_or_defer(
                swarm,
                local_db,
                goat_client,
                instance_id,
                graph_id,
                &message,
            )
            .await?
            {
                Some(g) => g,
                None => return Ok(()),
            };
            let mut graph = Bitvm2Graph::from_simplified(&graph)?;
            let watchtower_challenge_init_txid =
                graph.watchtower_challenge_init.tx().compute_txid();
            // 1. check that all WatchtowerChallenge Connectors are spent
            for watchtower_index in 0..graph.parameters.watchtower_pubkeys.len() {
                let watchtower_challenge_vout = 2 * watchtower_index as u32;
                if outpoint_spent_txid(
                    btc_client,
                    &watchtower_challenge_init_txid,
                    watchtower_challenge_vout as u64,
                )
                .await?
                .is_none()
                {
                    tracing::warn!(
                        "Ignore OperatorCommitBlockHashReady for {instance_id}:{graph_id}: watchtower challenge connector {watchtower_index} not spent yet"
                    );
                    return Ok(());
                }
            }
            // 2. sign & broadcast commit-blockhash txn
            let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
            let operator_graph_keypair = operator_master_key.master_keypair();
            let operator_master_keypair = operator_master_key.master_keypair();
            let wots_secret_keys =
                operator_master_key.wots_keypair_for_graph(graph.parameters.graph_id).0;
            let blockhash_wots_secret_key = &wots_secret_keys[0];
            let blockhash = todo_funcs::get_operator_proof_blockhash(instance_id, graph_id).await?;
            let (operator_commit_blockhash_txin, operator_commit_blockhash_txin_amount) =
                operator_sign_blockhash_commit(
                    operator_graph_keypair,
                    &mut graph,
                    &blockhash,
                    blockhash_wots_secret_key,
                )?;
            build_sign_and_broadcast_tx(
                btc_client,
                operator_master_keypair,
                vec![operator_commit_blockhash_txin],
                operator_commit_blockhash_txin_amount,
                vec![],
            )
            .await?;
        }
        (
            GOATMessageContent::OperatorCommitBlockHashTimeout(OperatorCommitBlockHashTimeout {
                instance_id,
                graph_id,
            }),
            Actor::Challenger,
        ) => {
            // triggered by timeout task
            tracing::info!("Handle OperatorCommitBlockHashTimeout for {instance_id}:{graph_id}");
            let graph = match get_graph_or_defer(
                swarm,
                local_db,
                goat_client,
                instance_id,
                graph_id,
                &message,
            )
            .await?
            {
                Some(g) => g,
                None => return Ok(()),
            };
            let graph = Bitvm2Graph::from_simplified(&graph)?;
            let watchtower_challenge_init_txid =
                graph.watchtower_challenge_init.tx().compute_txid();
            let connector_f_vout = 1 + 2 * graph.parameters.watchtower_pubkeys.len() as u64;
            if outpoint_spent_txid(btc_client, &watchtower_challenge_init_txid, connector_f_vout)
                .await?
                .is_some()
            {
                tracing::warn!(
                    "Ignore OperatorCommitBlockHashTimeout for {instance_id}:{graph_id}: connector_F already spent"
                );
                return Ok(());
            }
            let watchtower_challenge_init_height = match btc_client
                .get_tx_status(&watchtower_challenge_init_txid)
                .await?
                .block_height
            {
                Some(height) => height,
                None => {
                    tracing::warn!(
                        "Ignore OperatorCommitBlockHashTimeout for {instance_id}:{graph_id}: watchtower challenge init tx not confirmed yet"
                    );
                    return Ok(());
                }
            };
            let current_height = btc_client.get_height().await?;
            if current_height
                < watchtower_challenge_init_height
                    + commit_blockhash_timeout_timelock(get_network())
            {
                tracing::warn!(
                    "Ignore OperatorCommitBlockHashTimeout for {instance_id}:{graph_id}: watchtower challenge init tx timelock not expired yet"
                );
                return Ok(());
            }
            let connector_g_vout = 2 * graph.parameters.watchtower_pubkeys.len() as u64;
            if outpoint_spent_txid(btc_client, &watchtower_challenge_init_txid, connector_g_vout)
                .await?
                .is_some()
            {
                tracing::warn!(
                    "Ignore OperatorCommitBlockHashTimeout for {instance_id}:{graph_id}: connector_G already spent"
                );
                return Ok(());
            }
            // 1. broadcast OperatorCommitBlockHashTimeout txn
            let blockhash_commit_timeout_tx = graph.blockhash_commit_timeout.finalize();
            let anchor_vout = blockhash_commit_timeout_tx.output.len() as u64 - 1;
            let blockhash_commit_timeout_tx_total_input_amount =
                graph.blockhash_commit_timeout.prev_outs().iter().map(|o| o.value).sum();
            let child_tx = build_cpfp_txns(
                btc_client,
                &blockhash_commit_timeout_tx,
                anchor_vout,
                blockhash_commit_timeout_tx_total_input_amount,
            )
            .await?;
            match child_tx {
                Some(tx) => {
                    broadcast_package(btc_client, &[blockhash_commit_timeout_tx, tx], true).await?
                }
                None => broadcast_package(btc_client, &[blockhash_commit_timeout_tx], true).await?,
            };
        }
        (
            GOATMessageContent::AssertInitReady(AssertInitReady { instance_id, graph_id }),
            Actor::Operator,
        ) => {
            // triggered by timeout task
            tracing::info!("Handle AssertInitReady for {instance_id}:{graph_id}");
            let graph = match get_graph_or_defer(
                swarm,
                local_db,
                goat_client,
                instance_id,
                graph_id,
                &message,
            )
            .await?
            {
                Some(g) => g,
                None => return Ok(()),
            };
            let mut graph = Bitvm2Graph::from_simplified(&graph)?;
            let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
            let operator_graph_keypair = operator_master_key.master_keypair();
            let assert_init_txid = graph.assert_init.tx().compute_txid();
            // 1. sign & broadcast assert-init txn
            if !tx_on_chain(btc_client, &assert_init_txid).await? {
                let watchtower_challenge_init_txid =
                    graph.watchtower_challenge_init.tx().compute_txid();
                let watchtower_challenge_init_height = match btc_client
                    .get_tx_status(&watchtower_challenge_init_txid)
                    .await?
                    .block_height
                {
                    Some(height) => height,
                    None => {
                        tracing::warn!(
                            "Ignore AssertInitReady for {instance_id}:{graph_id}: watchtower challenge init tx not confirmed yet"
                        );
                        return Ok(());
                    }
                };
                let current_height = btc_client.get_height().await?;
                if current_height
                    < watchtower_challenge_init_height
                        + watchtower_challenge_timeout_timelock(get_network())
                {
                    tracing::warn!(
                        "Ignore AssertInitReady for {instance_id}:{graph_id}: watchtower challenge not finished yet"
                    );
                    return Ok(());
                }
                let assert_init_tx = operator_sign_assert_init(operator_graph_keypair, &mut graph)?;
                let anchor_vout = assert_init_tx.output.len() as u64 - 1;
                let assert_init_tx_total_input_amount =
                    graph.assert_init.prev_outs().iter().map(|o| o.value).sum();
                let child_tx = build_cpfp_txns(
                    btc_client,
                    &assert_init_tx,
                    anchor_vout,
                    assert_init_tx_total_input_amount,
                )
                .await?;
                match child_tx {
                    Some(tx) => broadcast_package(btc_client, &[assert_init_tx, tx], true).await?,
                    None => broadcast_tx(btc_client, &assert_init_tx).await?,
                };
                // assert-commit should be broadcasted after assert-init is confirmed (wait for 1 block)
                let delay_secs = todo_funcs::avg_block_time_secs(btc_client.network());
                push_local_unhandled_messages(local_db, graph_id, &message, delay_secs as usize)
                    .await?;
                return Ok(());
            }
            let connector_d_vout = graph.assert_commit_timeout_txns.len() as u64;
            if outpoint_spent_txid(btc_client, &assert_init_txid, connector_d_vout).await?.is_some()
            {
                tracing::warn!(
                    "Ignore AssertInitReady for {instance_id}:{graph_id}: connector_D already spent"
                );
                return Ok(());
            }
            // 2. sign & broadcast assert-commit txns
            if !tx_confirmed(btc_client, &assert_init_txid).await? {
                // assert-commit should be broadcasted after assert-init is confirmed (wait for 1 block)
                let delay_secs = todo_funcs::avg_block_time_secs(btc_client.network());
                push_local_unhandled_messages(local_db, graph_id, &message, delay_secs as usize)
                    .await?;
                return Ok(());
            } else {
                let (split_txid_opt, has_pending_fee_input) =
                    operator_send_assert_commit(btc_client, &mut graph).await?;
                if let Some(_split_txid) = split_txid_opt {
                    let delay_secs = todo_funcs::avg_block_time_secs(btc_client.network()) * 2;
                    push_local_unhandled_messages(
                        local_db,
                        graph_id,
                        &message,
                        delay_secs as usize,
                    )
                    .await?;
                } else if has_pending_fee_input {
                    let delay_secs = todo_funcs::avg_block_time_secs(btc_client.network()) * 2;
                    push_local_unhandled_messages(
                        local_db,
                        graph_id,
                        &message,
                        delay_secs as usize,
                    )
                    .await?;
                }
            }
        }
        (
            GOATMessageContent::AssertCommitTimeout(AssertCommitTimeout { instance_id, graph_id }),
            Actor::Challenger,
        ) => {
            // triggered by timeout task
            tracing::info!("Handle AssertCommitTimeout for {instance_id}:{graph_id}");
            let graph = match get_graph_or_defer(
                swarm,
                local_db,
                goat_client,
                instance_id,
                graph_id,
                &message,
            )
            .await?
            {
                Some(g) => g,
                None => return Ok(()),
            };
            let graph = Bitvm2Graph::from_simplified(&graph)?;
            let assert_init_txid = graph.assert_init.tx().compute_txid();
            let connector_d_vout = graph.assert_commit_timeout_txns.len() as u64;
            if outpoint_spent_txid(btc_client, &assert_init_txid, connector_d_vout).await?.is_some()
            {
                tracing::warn!(
                    "Ignore AssertCommitTimeout for {instance_id}:{graph_id}: connector_D already spent"
                );
                return Ok(());
            }
            let assert_init_height = match btc_client
                .get_tx_status(&assert_init_txid)
                .await?
                .block_height
            {
                Some(height) => height,
                None => {
                    tracing::warn!(
                        "Ignore AssertCommitTimeout for {instance_id}:{graph_id}: assert init tx not confirmed yet"
                    );
                    return Ok(());
                }
            };
            let current_height = btc_client.get_height().await?;
            if current_height < assert_init_height + assert_commit_timeout_timelock(get_network()) {
                tracing::warn!(
                    "Ignore AssertCommitTimeout for {instance_id}:{graph_id}: assert init tx timelock not expired yet"
                );
                return Ok(());
            }
            let mut commit_index = None;
            for i in 0..graph.assert_commit_timeout_txns.len() {
                let assert_commit_vout = i as u64;
                if outpoint_spent_txid(btc_client, &assert_init_txid, assert_commit_vout)
                    .await?
                    .is_none()
                {
                    commit_index = Some(i);
                    break;
                }
            }
            let commit_index = match commit_index {
                Some(index) => index,
                None => {
                    tracing::warn!(
                        "Ignore AssertCommitTimeout for {instance_id}:{graph_id}: all assert commit connectors already spent"
                    );
                    return Ok(());
                }
            };
            // 1. broadcast AssertCommitTimeout txn
            let assert_commit_timeout_tx = graph.assert_commit_timeout_txns.get(commit_index).ok_or_else(|| {
                anyhow!("AssertCommitTimeout txn not found for {instance_id}:{graph_id}:{commit_index}")
            })?.finalize();
            let anchor_vout = assert_commit_timeout_tx.output.len() as u64 - 1;
            let assert_commit_timeout_tx_total_input_amount = graph.assert_commit_timeout_txns
                [commit_index]
                .prev_outs()
                .iter()
                .map(|o| o.value)
                .sum();
            let child_tx = build_cpfp_txns(
                btc_client,
                &assert_commit_timeout_tx,
                anchor_vout,
                assert_commit_timeout_tx_total_input_amount,
            )
            .await?;
            match child_tx {
                Some(tx) => {
                    broadcast_package(btc_client, &[assert_commit_timeout_tx, tx], true).await?
                }
                None => broadcast_tx(btc_client, &assert_commit_timeout_tx).await?,
            };
        }
        (
            GOATMessageContent::DisproveReady(DisproveReady { instance_id, graph_id }),
            Actor::Challenger,
        ) => {
            // triggered by AssertCommit tx or OperatorCommitBlockHash tx
            tracing::info!("Handle DisproveReady for {instance_id}:{graph_id}");
            let graph = match get_graph_or_defer(
                swarm,
                local_db,
                goat_client,
                instance_id,
                graph_id,
                &message,
            )
            .await?
            {
                Some(g) => g,
                None => return Ok(()),
            };
            let graph = Bitvm2Graph::from_simplified(&graph)?;
            // 1. get assertions committed by Operator from Bitcoin chain
            let operator_commit_blockhash_txin = {
                let watchtower_challenge_init_txid =
                    graph.watchtower_challenge_init.tx().compute_txid();
                let connector_g_vout = 2 * graph.parameters.watchtower_pubkeys.len() as u64;
                let commit_blockhash_timeout_txid =
                    graph.blockhash_commit_timeout.tx().compute_txid();
                match outpoint_spent_txin(
                    btc_client,
                    &watchtower_challenge_init_txid,
                    connector_g_vout,
                )
                .await?
                {
                    Some((spent_txid, _, txin)) => {
                        if spent_txid == commit_blockhash_timeout_txid {
                            tracing::warn!(
                                "Ignore DisproveReady for {instance_id}:{graph_id}: graph already challenged by CommitBlockHashTimeout: {spent_txid}"
                            );
                            return Ok(());
                        }
                        txin
                    }
                    None => {
                        tracing::warn!(
                            "Ignore DisproveReady for {instance_id}:{graph_id}: operator-commit-blockhash not sent yet"
                        );
                        return Ok(());
                    }
                }
            };
            let operator_assert_commit_txins = {
                let assert_init_txid = graph.assert_init.tx().compute_txid();
                let mut txins = vec![];
                for i in 0..graph.assert_commit_timeout_txns.len() {
                    let assert_commit_vout = i as u64;
                    match outpoint_spent_txin(btc_client, &assert_init_txid, assert_commit_vout)
                        .await?
                    {
                        Some((spent_txid, _, txin)) => {
                            let assert_commit_timeout_txid =
                                graph.assert_commit_timeout_txns[i].tx().compute_txid();
                            if spent_txid == assert_commit_timeout_txid {
                                tracing::warn!(
                                    "Ignore DisproveReady for {instance_id}:{graph_id}: graph already challenged by AssertCommitTimeout[{i}]: {spent_txid}"
                                );
                                return Ok(());
                            }
                            txins.push(txin);
                        }
                        None => {
                            tracing::warn!(
                                "Ignore DisproveReady for {instance_id}:{graph_id}: assert-commit {i} not sent yet"
                            );
                            return Ok(());
                        }
                    }
                }
                txins
            };
            let operator_ack_txins = {
                let watchtower_challenge_init_txid =
                    graph.watchtower_challenge_init.tx().compute_txid();
                let mut txins = vec![];
                for watchtower_index in 0..graph.parameters.watchtower_pubkeys.len() {
                    let ack_vout = 1 + 2 * watchtower_index as u64;
                    if let Some((spent_txid, _, txin)) =
                        outpoint_spent_txin(btc_client, &watchtower_challenge_init_txid, ack_vout)
                            .await?
                    {
                        let nack_txid = graph.nack_txns[watchtower_index].tx().compute_txid();
                        if spent_txid != nack_txid {
                            txins.push(txin);
                        }
                    }
                }
                txins
            };
            // 2. check assertions committed by Operator, if any assertion is invalid, sign & broadcast disprove txn
            let vk = todo_funcs::get_operator_proof_vk(instance_id, graph_id).await?;
            let disprove_scripts = get_disprove_scripts(local_db, &graph.parameters).await?;
            let disprove_scripts = disprove_scripts
                .try_into()
                .map_err(|_| anyhow!("Mismatch disprove scripts num"))?;
            if let Some(disprove_witness) = verify_operator_commits(
                operator_commit_blockhash_txin,
                operator_assert_commit_txins,
                operator_ack_txins,
                graph.parameters.watchtower_pubkeys.len(),
                &vk,
                &disprove_scripts,
            )? {
                let disprover_evm_address = get_node_goat_address().ok_or_else(|| {
                    anyhow::anyhow!("failed to get node goat address".to_string())
                })?;
                let connector_e_input = Input {
                    outpoint: OutPoint { txid: graph.kickoff.tx().compute_txid(), vout: 3 },
                    amount: graph.kickoff.tx().output[3].value,
                };
                let disprove_tx = sign_disprove(
                    &graph,
                    &connector_e_input,
                    disprove_witness,
                    disprove_scripts.to_vec(),
                    Some(*disprover_evm_address.as_ref()),
                )?;
                todo_funcs::broadcast_nonstandard_tx(btc_client, &disprove_tx).await?;
            } else {
                tracing::info!(
                    "All assertions valid for {instance_id}:{graph_id}, no need to disprove"
                );
                return Ok(());
            }
        }
        (
            GOATMessageContent::DisproveSent(DisproveSent {
                instance_id,
                graph_id,
                disprove_type,
                index,
                challenge_finish_txid,
                ..
            }),
            Actor::Committee,
        ) => {
            // triggered by Disprove tx
            tracing::info!("Handle DisproveSent for {instance_id}:{graph_id}");
            // 1. update graph status
            let graph = get_graph(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
            let graph = Bitvm2Graph::from_simplified(&graph)?;
            let graph_start_status = get_graph_status(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph status not found for {instance_id}:{graph_id}"))?;
            let (graph_status, sub_status) = refresh_graph(
                local_db,
                btc_client,
                goat_client,
                instance_id,
                graph_id,
                Some(&graph),
                Some(graph_start_status),
                None,
            )
            .await?;
            tracing::info!("Graph {graph_id} latest status: {graph_status}");
            compensate_graph_events(
                local_db,
                btc_client,
                instance_id,
                graph_id,
                Some(&graph),
                Some(graph_start_status),
                GraphStatus::Disprove,
                graph_status,
                sub_status,
            )
            .await?;
            if !is_relayer() {
                return Ok(());
            }
            // 2. (Relayer) call finalizeWithdrawDisprove on GoatChain
            let withdraw_status = goat_client.gateway_get_withdraw_data(&graph_id).await?.status;
            if withdraw_status == WithdrawStatus::Disproved {
                tracing::warn!(
                    "Relayer Ignore finishWithdrawDisproved for {instance_id}:{graph_id}: already posted"
                );
                return Ok(());
            }
            let kickoff_txid = graph.kickoff.tx().compute_txid();
            let take1_txid = graph.take1.tx().compute_txid();
            let connector_a_vout = 0;
            let challenge_start_tx = if let Some(spent_txid) =
                outpoint_spent_txid(btc_client, &kickoff_txid, connector_a_vout).await?
            {
                if spent_txid == take1_txid {
                    tracing::warn!(
                        "Ignore DisproveSent for {instance_id}:{graph_id}: graph already finalized by Take1 tx: {spent_txid}"
                    );
                    return Ok(());
                }
                btc_client.get_tx(&spent_txid).await?
            } else {
                None
            };
            let challenge_finish_tx = match btc_client.get_tx(&challenge_finish_txid).await? {
                Some(tx) => tx,
                None => {
                    tracing::warn!(
                        "Ignore DisproveSent for {instance_id}:{graph_id}: challenge finish tx {challenge_finish_txid} not found on chain"
                    );
                    return Ok(());
                }
            };
            match disprove_type {
                DisproveTxType::AssertTimeout => {
                    if challenge_finish_txid != graph.assert_commit_timeout_txns.get(index)
                        .ok_or_else(|| anyhow!("AssertCommitTimeout txn not found for {instance_id}:{graph_id}:{index}"))?
                        .tx()
                        .compute_txid()
                    {
                        tracing::warn!(
                            "Ignore DisproveSent for {instance_id}:{graph_id}: challenge finish txid does not match assert commit timeout txn"
                        );
                        return Ok(());
                    }
                }
                DisproveTxType::OperatorCommitTimeout => {
                    if challenge_finish_txid != graph.blockhash_commit_timeout.tx().compute_txid() {
                        tracing::warn!(
                            "Ignore DisproveSent for {instance_id}:{graph_id}: challenge finish txid does not match operator commit timeout txn"
                        );
                        return Ok(());
                    }
                }
                DisproveTxType::OperatorNack => {
                    if challenge_finish_txid != graph.nack_txns.get(index)
                        .ok_or_else(|| anyhow!("Nack txn not found for {instance_id}:{graph_id}:{index}"))?
                        .tx()
                        .compute_txid()
                    {
                        tracing::warn!(
                            "Ignore DisproveSent for {instance_id}:{graph_id}: challenge finish txid does not match nack txn"
                        );
                        return Ok(());
                    }
                }
                DisproveTxType::Disprove => {
                    let connector_e_input = OutPoint {
                        txid: kickoff_txid,
                        vout: 3,
                    };
                    if challenge_finish_tx.input[0].previous_output != connector_e_input {
                        tracing::warn!(
                            "Ignore DisproveSent for {instance_id}:{graph_id}: challenge finish tx is not a disprove txn"
                        );
                        return Ok(());
                    }
                }
                DisproveTxType::QuickChallenge => {
                    let guardian_connector_input = OutPoint {
                        txid: kickoff_txid,
                        vout: 4,
                    };
                    if challenge_finish_tx.input[0].previous_output != guardian_connector_input {
                        tracing::warn!(
                            "Ignore DisproveSent for {instance_id}:{graph_id}: challenge finish tx is not a quick challenge txn"
                        );
                        return Ok(());
                    }
                }
                DisproveTxType::ChallengeIncompleteKickoff => {
                    let guardian_connector_input = OutPoint {
                        txid: kickoff_txid,
                        vout: 4,
                    };
                    if challenge_finish_tx.input[0].previous_output != guardian_connector_input {
                        tracing::warn!(
                            "Ignore DisproveSent for {instance_id}:{graph_id}: challenge finish tx is not a challenge incomplete kickoff txn"
                        );
                        return Ok(());
                    }
                }
            }
            let challenge_finish_height = match btc_client
                .get_tx_status(&challenge_finish_txid)
                .await?
                .block_height
            {
                Some(height) => height as u64,
                None => {
                    let delay_secs = todo_funcs::avg_block_time_secs(btc_client.network()); // wait for 1 block
                    push_local_unhandled_messages(
                        local_db,
                        graph_id,
                        &message,
                        delay_secs as usize,
                    )
                    .await?;
                    tracing::info!(
                        "Retry finishWithdrawDisproved later for {instance_id}:{graph_id}: challenge finish tx not confirmed on btc yet"
                    );
                    return Ok(());
                }
            };
            let goat_confirmed_height = goat_client.btc_spv_latest_height().await?;
            if goat_confirmed_height < challenge_finish_height {
                let delay_secs = todo_funcs::avg_block_time_secs(btc_client.network())
                    * (challenge_finish_height - goat_confirmed_height);
                push_local_unhandled_messages(local_db, graph_id, &message, delay_secs as usize)
                    .await?;
                tracing::info!(
                    "Retry finishWithdrawDisproved later for {instance_id}:{graph_id}: challenge finish tx block not posted to goat spv contract yet"
                );
                return Ok(());
            }
            goat_client
                .gateway_finish_withdraw_disproved(
                    btc_client,
                    &graph_id,
                    disprove_type,
                    index as u64,
                    challenge_start_tx.as_ref(),
                    &challenge_finish_tx,
                )
                .await?;
        }
        (GOATMessageContent::DisproveSent(DisproveSent { instance_id, graph_id, .. }), _) => {
            // triggered by Disprove tx
            tracing::info!("Handle DisproveSent for {instance_id}:{graph_id}");
            let graph = get_graph(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
            let graph = Bitvm2Graph::from_simplified(&graph)?;
            let graph_start_status = get_graph_status(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph status not found for {instance_id}:{graph_id}"))?;
            let (graph_status, sub_status) = refresh_graph(
                local_db,
                btc_client,
                goat_client,
                instance_id,
                graph_id,
                Some(&graph),
                Some(graph_start_status),
                None,
            )
            .await?;
            tracing::info!("Graph {graph_id} latest status: {graph_status}");
            compensate_graph_events(
                local_db,
                btc_client,
                instance_id,
                graph_id,
                Some(&graph),
                Some(graph_start_status),
                GraphStatus::Disprove,
                graph_status,
                sub_status,
            )
            .await?;
        }
        (GOATMessageContent::Take1Ready(Take1Ready { instance_id, graph_id }), Actor::Operator) => {
            // triggered by timeout task
            tracing::info!("Handle Take1Ready for {instance_id}:{graph_id}");
            let graph = match get_graph_or_defer(
                swarm,
                local_db,
                goat_client,
                instance_id,
                graph_id,
                &message,
            )
            .await?
            {
                Some(g) => g,
                None => return Ok(()),
            };
            let mut graph = Bitvm2Graph::from_simplified(&graph)?;
            let kickoff_txid = graph.kickoff.tx().compute_txid();
            let connector_a_vout = 0;
            let guardian_connector_vout = 4;
            if outpoint_spent_txid(btc_client, &kickoff_txid, connector_a_vout).await?.is_some()
                || outpoint_spent_txid(btc_client, &kickoff_txid, guardian_connector_vout)
                    .await?
                    .is_some()
            {
                tracing::warn!(
                    "Ignore Take1Ready for {instance_id}:{graph_id}: connectors already spent"
                );
                return Ok(());
            }
            let kickoff_height = match btc_client.get_tx_status(&kickoff_txid).await?.block_height {
                Some(height) => height,
                None => {
                    tracing::warn!(
                        "Ignore Take1Ready for {instance_id}:{graph_id}: kickoff tx not confirmed yet"
                    );
                    return Ok(());
                }
            };
            if !is_take1_timelock_expired(btc_client, kickoff_height).await? {
                tracing::warn!(
                    "Ignore Take1Ready for {instance_id}:{graph_id}: kickoff tx timelock not expired yet"
                );
                return Ok(());
            }
            // 1. sign & broadcast take1 txn
            let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
            let operator_graph_keypair = operator_master_key.master_keypair();
            let take1_tx = operator_sign_take1(operator_graph_keypair, &mut graph)?;
            let anchor_vout = take1_tx.output.len() as u64 - 1;
            let take1_tx_total_input_amount = graph.take1.prev_outs().iter().map(|o| o.value).sum();
            let child_tx =
                build_cpfp_txns(btc_client, &take1_tx, anchor_vout, take1_tx_total_input_amount)
                    .await?;
            match child_tx {
                Some(tx) => broadcast_package(btc_client, &[take1_tx, tx], true).await?,
                None => broadcast_tx(btc_client, &take1_tx).await?,
            };
        }
        (GOATMessageContent::Take1Sent(Take1Sent { instance_id, graph_id }), Actor::Committee) => {
            // triggered by Take1 tx
            tracing::info!("Handle Take1Sent for {instance_id}:{graph_id}");
            // 1. update graph status
            let graph = get_graph(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
            let graph = Bitvm2Graph::from_simplified(&graph)?;
            let graph_start_status = get_graph_status(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph status not found for {instance_id}:{graph_id}"))?;
            let (graph_status, sub_status) = refresh_graph(
                local_db,
                btc_client,
                goat_client,
                instance_id,
                graph_id,
                Some(&graph),
                Some(graph_start_status),
                None,
            )
            .await?;
            tracing::info!("Graph {graph_id} latest status: {graph_status}");
            compensate_graph_events(
                local_db,
                btc_client,
                instance_id,
                graph_id,
                Some(&graph),
                Some(graph_start_status),
                GraphStatus::OperatorTake1,
                graph_status,
                sub_status,
            )
            .await?;
            if !is_relayer() {
                return Ok(());
            }
            // 2. (Relayer) call finalizeWithdrawHappyPath on GoatChain
            let take1_txid = graph.take1.tx().compute_txid();
            let take1_tx = match btc_client.get_tx(&take1_txid).await? {
                Some(tx) => tx,
                None => {
                    tracing::warn!(
                        "Ignore Take1Sent for {instance_id}:{graph_id}: take1 tx not found on chain"
                    );
                    return Ok(());
                }
            };
            let withdraw_status = goat_client.gateway_get_withdraw_data(&graph_id).await?.status;
            if withdraw_status == WithdrawStatus::Initialized {
                // Kickoff not posted yet, wait for it
                let delay_secs = todo_funcs::avg_block_time_secs(btc_client.network()) * 6; // wait for 6 blocks
                push_local_unhandled_messages(local_db, graph_id, &message, delay_secs as usize)
                    .await?;
                tracing::info!(
                    "Retry finishWithdrawHappyPath later for {instance_id}:{graph_id} as kickoff not posted yet"
                );
                return Ok(());
            }
            if withdraw_status != WithdrawStatus::Processing {
                tracing::warn!(
                    "Relayer Ignore finishWithdrawHappyPath for {instance_id}:{graph_id}: invalid withdraw status: {withdraw_status}"
                );
                return Ok(());
            }
            let take1_height = match btc_client.get_tx_status(&take1_txid).await?.block_height {
                Some(height) => height as u64,
                None => {
                    let delay_secs = todo_funcs::avg_block_time_secs(btc_client.network()); // wait for 1 block
                    push_local_unhandled_messages(
                        local_db,
                        graph_id,
                        &message,
                        delay_secs as usize,
                    )
                    .await?;
                    tracing::info!(
                        "Retry finishWithdrawHappyPath later for {instance_id}:{graph_id} as take1 tx not confirmed on btc yet"
                    );
                    return Ok(());
                }
            };
            let goat_confirmed_height = goat_client.btc_spv_latest_height().await?;
            if goat_confirmed_height < take1_height {
                let delay_secs = todo_funcs::avg_block_time_secs(btc_client.network())
                    * (take1_height - goat_confirmed_height);
                push_local_unhandled_messages(local_db, graph_id, &message, delay_secs as usize)
                    .await?;
                tracing::info!(
                    "Retry finishWithdrawHappyPath later for {instance_id}:{graph_id} as take1 tx block not posted to goat spv contract yet"
                );
                return Ok(());
            }
            goat_client
                .gateway_finish_withdraw_happy_path(btc_client, &graph_id, &take1_tx)
                .await?;
        }
        (GOATMessageContent::Take1Sent(Take1Sent { instance_id, graph_id }), _) => {
            // triggered by Take1 tx
            tracing::info!("Handle Take1Sent for {instance_id}:{graph_id}");
            // 1. update graph status
            let graph = get_graph(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
            let graph = Bitvm2Graph::from_simplified(&graph)?;
            let graph_start_status = get_graph_status(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph status not found for {instance_id}:{graph_id}"))?;
            let (graph_status, sub_status) = refresh_graph(
                local_db,
                btc_client,
                goat_client,
                instance_id,
                graph_id,
                Some(&graph),
                Some(graph_start_status),
                None,
            )
            .await?;
            tracing::info!("Graph {graph_id} latest status: {graph_status}");
            compensate_graph_events(
                local_db,
                btc_client,
                instance_id,
                graph_id,
                Some(&graph),
                Some(graph_start_status),
                GraphStatus::OperatorTake1,
                graph_status,
                sub_status,
            )
            .await?;
        }
        (GOATMessageContent::Take2Ready(Take2Ready { instance_id, graph_id }), Actor::Operator) => {
            // triggered by timeout task
            tracing::info!("Handle Take2Ready for {instance_id}:{graph_id}");
            let graph = get_graph(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
            let mut graph = Bitvm2Graph::from_simplified(&graph)?;
            let kickoff_txid = graph.kickoff.tx().compute_txid();
            let watchtower_challenge_init_txid =
                graph.watchtower_challenge_init.tx().compute_txid();
            let assert_init_txid = graph.assert_init.tx().compute_txid();
            let connector_d_vout = graph.assert_commit_timeout_txns.len() as u64;
            let connector_e_vout = 3;
            let connector_f_vout = 1 + 2 * graph.parameters.watchtower_pubkeys.len() as u64;
            let guardian_connector_vout = 4;
            // check if connector_E, connector_F, connector_D, guardian_connector are all unspent
            if outpoint_spent_txid(btc_client, &kickoff_txid, connector_e_vout).await?.is_some()
                || outpoint_spent_txid(
                    btc_client,
                    &watchtower_challenge_init_txid,
                    connector_f_vout,
                )
                .await?
                .is_some()
                || outpoint_spent_txid(btc_client, &assert_init_txid, connector_d_vout)
                    .await?
                    .is_some()
                || outpoint_spent_txid(btc_client, &kickoff_txid, guardian_connector_vout)
                    .await?
                    .is_some()
            {
                tracing::warn!(
                    "Ignore Take2Ready for {instance_id}:{graph_id}: connectors already spent"
                );
                return Ok(());
            }
            // check if assert-init tx and watchtower-challenge-init tx are both confirmed and timelock expired
            let assert_init_height = match btc_client
                .get_tx_status(&assert_init_txid)
                .await?
                .block_height
            {
                Some(height) => height,
                None => {
                    tracing::warn!(
                        "Ignore Take2Ready for {instance_id}:{graph_id}: assert init tx not confirmed yet"
                    );
                    return Ok(());
                }
            };
            let watchtower_challenge_init_height = match btc_client
                .get_tx_status(&watchtower_challenge_init_txid)
                .await?
                .block_height
            {
                Some(height) => height,
                None => {
                    tracing::warn!(
                        "Ignore Take2Ready for {instance_id}:{graph_id}: watchtower challenge init tx not confirmed yet"
                    );
                    return Ok(());
                }
            };
            if !is_take2_timelock_expired(
                btc_client,
                watchtower_challenge_init_height,
                assert_init_height,
            )
            .await?
            {
                tracing::warn!(
                    "Ignore Take2Ready for {instance_id}:{graph_id}: take2 timelock not expired yet"
                );
                return Ok(());
            }
            // 1. sign & broadcast take2 txn
            let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
            let operator_graph_keypair = operator_master_key.master_keypair();
            let take2_tx = operator_sign_take2(operator_graph_keypair, &mut graph)?;
            let anchor_vout = take2_tx.output.len() as u64 - 1;
            let take2_tx_total_input_amount = graph.take2.prev_outs().iter().map(|o| o.value).sum();
            let child_tx =
                build_cpfp_txns(btc_client, &take2_tx, anchor_vout, take2_tx_total_input_amount)
                    .await?;
            match child_tx {
                Some(tx) => broadcast_package(btc_client, &[take2_tx, tx], true).await?,
                None => broadcast_tx(btc_client, &take2_tx).await?,
            };
        }
        (GOATMessageContent::Take2Sent(Take2Sent { instance_id, graph_id }), Actor::Committee) => {
            // triggered by Take2 tx
            tracing::info!("Handle Take2Sent for {instance_id}:{graph_id}");
            // 1. update graph status
            let graph = get_graph(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
            let graph = Bitvm2Graph::from_simplified(&graph)?;
            let graph_start_status = get_graph_status(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph status not found for {instance_id}:{graph_id}"))?;
            let (graph_status, sub_status) = refresh_graph(
                local_db,
                btc_client,
                goat_client,
                instance_id,
                graph_id,
                Some(&graph),
                Some(graph_start_status),
                None,
            )
            .await?;
            tracing::info!("Graph {graph_id} latest status: {graph_status}");
            compensate_graph_events(
                local_db,
                btc_client,
                instance_id,
                graph_id,
                Some(&graph),
                Some(graph_start_status),
                GraphStatus::OperatorTake2,
                graph_status,
                sub_status,
            )
            .await?;
            if !is_relayer() {
                return Ok(());
            }
            // 2. (Relayer) call finalizeWithdrawUnhappyPath on GoatChain
            let take2_txid = graph.take2.tx().compute_txid();
            let take2_tx = match btc_client.get_tx(&take2_txid).await? {
                Some(tx) => tx,
                None => {
                    tracing::warn!(
                        "Ignore Take2Sent for {instance_id}:{graph_id}: take2 tx not found on chain"
                    );
                    return Ok(());
                }
            };
            let withdraw_status = goat_client.gateway_get_withdraw_data(&graph_id).await?.status;
            if withdraw_status == WithdrawStatus::Initialized {
                // Kickoff not posted yet, wait for it
                let delay_secs = todo_funcs::avg_block_time_secs(btc_client.network()) * 6; // wait for 6 blocks
                push_local_unhandled_messages(local_db, graph_id, &message, delay_secs as usize)
                    .await?;
                tracing::info!(
                    "Retry finishWithdrawUnhappyPath later for {instance_id}:{graph_id} as kickoff not posted yet"
                );
                return Ok(());
            }
            if withdraw_status != WithdrawStatus::Processing {
                tracing::warn!(
                    "Relayer Ignore finishWithdrawUnhappyPath for {instance_id}:{graph_id}: invalid withdraw status: {withdraw_status}"
                );
                return Ok(());
            }
            let take2_height = match btc_client.get_tx_status(&take2_txid).await?.block_height {
                Some(height) => height as u64,
                None => {
                    let delay_secs = todo_funcs::avg_block_time_secs(btc_client.network()); // wait for 1 block
                    push_local_unhandled_messages(
                        local_db,
                        graph_id,
                        &message,
                        delay_secs as usize,
                    )
                    .await?;
                    tracing::info!(
                        "Retry finishWithdrawUnhappyPath later for {instance_id}:{graph_id} as take2 tx not confirmed on btc yet"
                    );
                    return Ok(());
                }
            };
            let goat_confirmed_height = goat_client.btc_spv_latest_height().await?;
            if goat_confirmed_height < take2_height {
                let delay_secs = todo_funcs::avg_block_time_secs(btc_client.network())
                    * (take2_height - goat_confirmed_height);
                push_local_unhandled_messages(local_db, graph_id, &message, delay_secs as usize)
                    .await?;
                tracing::info!(
                    "Retry finishWithdrawUnhappyPath later for {instance_id}:{graph_id} as take2 tx block not posted to goat spv contract yet"
                );
                return Ok(());
            }
            goat_client
                .gateway_finish_withdraw_unhappy_path(btc_client, &graph_id, &take2_tx)
                .await?;
        }
        (GOATMessageContent::Take2Sent(Take2Sent { instance_id, graph_id }), _) => {
            // triggered by Take2 tx
            tracing::info!("Handle Take2Sent for {instance_id}:{graph_id}");
            // 1. update graph status
            let graph = get_graph(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
            let graph = Bitvm2Graph::from_simplified(&graph)?;
            let graph_start_status = get_graph_status(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph status not found for {instance_id}:{graph_id}"))?;
            let (graph_status, sub_status) = refresh_graph(
                local_db,
                btc_client,
                goat_client,
                instance_id,
                graph_id,
                Some(&graph),
                Some(graph_start_status),
                None,
            )
            .await?;
            tracing::info!("Graph {graph_id} latest status: {graph_status}");
            compensate_graph_events(
                local_db,
                btc_client,
                instance_id,
                graph_id,
                Some(&graph),
                Some(graph_start_status),
                GraphStatus::OperatorTake2,
                graph_status,
                sub_status,
            )
            .await?;
        }
        (
            GOATMessageContent::SyncGraphRequest(SyncGraphRequest { instance_id, graph_id }),
            Actor::Committee,
        ) => {
            // sent by other nodes when they find a graph is missing locally
            // 1. (Relayer) send SyncGraph response if have the graph
            if !is_relayer() {
                tracing::warn!(
                    "Ignore SyncGraphRequest for {instance_id}:{graph_id}: not a relayer node"
                );
                return Ok(());
            }
            tracing::info!("Handle SyncGraphRequest for {instance_id}:{graph_id}");
            if let Some(graph) = get_graph(local_db, instance_id, graph_id).await? {
                let message_content =
                    GOATMessageContent::SyncGraph(SyncGraph { instance_id, graph_id, graph });
                let message = GOATMessage::from_typed(Actor::All, &message_content)?;
                send_to_peer(swarm, message)?;
            } else {
                // TODO: if no relayer has the graph, how to recover?
                tracing::warn!("Graph not found for SyncGraphRequest {instance_id}:{graph_id}");
            }
        }
        (GOATMessageContent::SyncGraph(SyncGraph { instance_id, graph_id, graph }), _) => {
            // sent by relayer nodes in response to SyncGraphRequest
            if graph_exists(local_db, instance_id, graph_id).await? {
                tracing::warn!(
                    "Ignore SyncGraph for {instance_id}:{graph_id}: graph already exists locally"
                );
                return Ok(());
            }
            validate_graph_id_on_goat(goat_client, instance_id, graph_id).await.map_err(|e| {
                anyhow!("Failed to validate graph_id on GoatChain for SyncGraph {instance_id}:{graph_id}: {e}")
            })?;
            tracing::info!("Handle SyncGraph for {instance_id}:{graph_id}");
            store_graph(local_db, &graph).await?;
            let graph = Bitvm2Graph::from_simplified(&graph)?;
            let (graph_status, sub_status) = refresh_graph(
                local_db,
                btc_client,
                goat_client,
                instance_id,
                graph_id,
                Some(&graph),
                None,
                None,
            )
            .await?;
            compensate_graph_events(
                local_db,
                btc_client,
                instance_id,
                graph_id,
                Some(&graph),
                None,
                GraphStatus::OperatorPresigned,
                graph_status,
                sub_status,
            )
            .await?;
        }
        (GOATMessageContent::RequestNodeInfo(node_info), _) => {
            save_node_info(local_db, &node_info).await?;
            let message_content = GOATMessageContent::ResponseNodeInfo(get_local_node_info());
            send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
        }

        (GOATMessageContent::ResponseNodeInfo(node_info), _) => {
            save_node_info(local_db, &node_info).await?;
        }
        _ => {}
    }
    Ok(())
}

pub async fn try_finalize_graph(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    goat_client: &GOATClient,
    instance_id: Uuid,
    graph_id: Uuid,
    graph: Option<&SimplifiedBitvm2Graph>,
    broadcast_graph_finalize: bool,
) -> Result<()> {
    let endorsements =
        get_committee_endorsements_for_graph(local_db, instance_id, graph_id).await?;
    let pub_nonoces = get_committee_pub_nonces_for_graph(local_db, instance_id, graph_id).await?;
    let partial_sigs =
        get_committee_partial_sigs_for_graph(local_db, instance_id, graph_id).await?;
    let committee_pubkeys = goat_client.gateway_get_committee_pubkeys(&instance_id).await?;
    if endorsements.len() == committee_pubkeys.len()
        && pub_nonoces.len() == committee_pubkeys.len()
        && partial_sigs.len() == committee_pubkeys.len()
    {
        let mut graph = match graph {
            Some(g) => Bitvm2Graph::from_simplified(g)?,
            None => {
                let g = get_graph(local_db, instance_id, graph_id)
                    .await?
                    .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
                Bitvm2Graph::from_simplified(&g)?
            }
        };
        let pub_nonces = pub_nonoces.into_iter().map(|(_, pn)| pn).collect::<Vec<_>>();
        let agg_nonces = nonces_aggregation(&pub_nonces)?;
        let partial_sigs = partial_sigs.into_iter().map(|(_, ps)| ps).collect::<Vec<_>>();
        let committee_sig_for_graph = signature_aggregation(&partial_sigs, &agg_nonces, &graph)?;
        push_committee_pre_signatures(&mut graph, &committee_sig_for_graph)?;
        let simplified_graph = graph.to_simplified()?;
        store_graph(local_db, &simplified_graph).await?;
        if broadcast_graph_finalize {
            let message_content = GOATMessageContent::GraphFinalize(GraphFinalize {
                instance_id,
                graph_id,
                graph_nonce: graph.parameters.graph_nonce,
                endorse_sigs: endorsements,
                graph: simplified_graph,
            });
            send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
        }
    }
    Ok(())
}

pub fn send_to_peer(swarm: &mut Swarm<AllBehaviours>, message: GOATMessage) -> Result<MessageId> {
    let actor = message.actor.to_string();
    let topic = crate::middleware::get_topic_name(&actor);
    let gossipsub_topic = gossipsub::IdentTopic::new(topic);
    Ok(swarm.behaviour_mut().gossipsub.publish(gossipsub_topic, serde_json::to_vec(&message)?)?)
}

pub async fn push_local_unhandled_messages(
    local_db: &LocalDB,
    business_id: Uuid,
    message: &GOATMessage,
    delay_secs: usize,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let actor = message.actor.clone();
    let content: GOATMessageContent = message.to_typed()?;
    upsert_message(
        &mut storage_processor,
        true,
        business_id,
        None,
        "Self".to_string(),
        actor,
        content,
        0,
        delay_secs as i64,
    )
    .await
}

/// Helper: try to get graph. If missing, send SyncGraphRequest and defer current handling.
async fn get_graph_or_defer(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    goat_client: &GOATClient,
    instance_id: Uuid,
    graph_id: Uuid,
    message: &GOATMessage,
) -> Result<Option<SimplifiedBitvm2Graph>> {
    match get_graph(local_db, instance_id, graph_id).await? {
        Some(g) => Ok(Some(g)),
        None => {
            // Ask for sync and push to local queue with a short retry delay
            if let Err(e) =
                try_send_sync_graph_request(swarm, goat_client, instance_id, graph_id).await
            {
                tracing::warn!("Failed to send SyncGraphRequest for {instance_id}:{graph_id}: {e}");
            }
            let delay_secs: usize = 60; // 1 min default retry
            if let Err(e) =
                push_local_unhandled_messages(local_db, graph_id, message, delay_secs).await
            {
                tracing::warn!(
                    "Failed to enqueue deferred message for {instance_id}:{graph_id}: {e}"
                );
            }
            tracing::info!(
                "Graph missing locally for {instance_id}:{graph_id}; requested sync and deferred"
            );
            Ok(None)
        }
    }
}

pub async fn try_send_sync_graph_request(
    swarm: &mut Swarm<AllBehaviours>,
    goat_client: &GOATClient,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<()> {
    validate_graph_id_on_goat(goat_client, instance_id, graph_id).await?;
    let message_content =
        GOATMessageContent::SyncGraphRequest(SyncGraphRequest { instance_id, graph_id });
    let message = GOATMessage::from_typed(Actor::All, &message_content)?;
    send_to_peer(swarm, message)?;
    Ok(())
}
