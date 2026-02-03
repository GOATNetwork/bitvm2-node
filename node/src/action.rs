#![allow(clippy::collapsible_match)]
#![allow(clippy::single_match)]
#![allow(clippy::collapsible_else_if)]

use crate::env::get_local_node_info;
use crate::handle::{HandlerContext, dispatch as handle_dispatch};
use crate::middleware::AllBehaviours;
use crate::rpc_service::current_time_secs;
use crate::utils::*;
use alloy::primitives::Address as EvmAddress;
use anyhow::{Result, anyhow};
use bitcoin::{PublicKey, Txid};
use bitvm2_lib::actors::Actor;
use bitvm2_lib::committee::*;
use bitvm2_lib::types::{Bitvm2Graph, SimplifiedBitvm2Graph};
use client::goat_chain::DisproveTxType;
use client::http_client::async_client::HttpAsyncClient;
use client::{btc_chain::BTCClient, goat_chain::GOATClient};
use libp2p::gossipsub::MessageId;
use libp2p::{PeerId, Swarm, gossipsub};
use musig2::{PartialSignature, PubNonce};
use secp256k1::schnorr::Signature as SchnorrSignature;
use serde::{Deserialize, Serialize};
use store::MessageState;
use store::localdb::LocalDB;
use tracing::warn;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone)]
pub struct GOATMessage {
    pub actor: Actor,
    pub content: GOATMessageContent,
}

#[derive(Serialize, Deserialize, Clone)]
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
    Tick,
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
    pub available_peg_btc: String,
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
    pub fn new(actor: Actor, content: GOATMessageContent) -> Self {
        Self { actor, content }
    }

    pub fn content(&self) -> &GOATMessageContent {
        &self.content
    }

    pub fn default_message_id() -> MessageId {
        MessageId(b"__inner_message_id__".to_vec())
    }

    pub async fn serialize_message(&self) -> Result<Vec<u8>> {
        let cloned = self.clone();
        Ok(tokio::task::spawn_blocking(move || serde_json::to_vec(&cloned)).await??)
    }

    pub async fn deserialize_message(message: &[u8]) -> Result<GOATMessage> {
        let cloned = message.to_vec();
        Ok(tokio::task::spawn_blocking(move || serde_json::from_slice(&cloned)).await??)
    }
}
#[allow(clippy::too_many_arguments)]
pub async fn handle_self_p2p_msg(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    http_client: &HttpAsyncClient,
    actor: Actor,
    from_peer_id: PeerId,
    id: MessageId,
    message: &[u8],
) -> Result<()> {
    if id != GOATMessage::default_message_id() {
        tracing::warn!("handle_self_p2p_msg received unexpected message id: {:?}", id);
        return Ok(());
    }
    let message = GOATMessage::deserialize_message(message).await?;
    tracing::info!(
        "Got self p2p message: {} with id: {} from peer: {:?}",
        &message.actor.to_string(),
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
            http_client,
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
    http_client: &HttpAsyncClient,
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
    let message = GOATMessage::deserialize_message(message).await?;
    let mut handler_ctx = HandlerContext {
        swarm,
        local_db,
        btc_client,
        goat_client,
        http_client,
        actor,
        from_peer_id,
        id,
        is_self_peer,
    };
    handle_dispatch(&mut handler_ctx, message.content()).await
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
            send_to_peer(swarm, GOATMessage::new(Actor::All, message_content)).await?;
        }
    }
    Ok(())
}

pub async fn send_to_peer(
    swarm: &mut Swarm<AllBehaviours>,
    message: GOATMessage,
) -> Result<MessageId> {
    let actor = message.actor.to_string();
    let topic = crate::middleware::get_topic_name(&actor);
    let gossipsub_topic = gossipsub::IdentTopic::new(topic);
    Ok(swarm
        .behaviour_mut()
        .gossipsub
        .publish(gossipsub_topic, message.serialize_message().await?)?)
}

pub async fn push_local_unhandled_messages(
    local_db: &LocalDB,
    business_id: Uuid,
    message: &GOATMessage,
    delay_secs: usize,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let actor = message.actor.clone();
    let content: GOATMessageContent = message.content().clone();
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
pub(crate) async fn get_graph_or_defer(
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
    let message = GOATMessage::new(Actor::All, message_content);
    send_to_peer(swarm, message).await?;
    Ok(())
}
