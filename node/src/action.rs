use crate::env::{get_bitvm_key, get_network};
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
use client::goat_chain::{DisproveTxType, WithdrawStatus};
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
    pub graph_status: GraphStatus,
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
    let message: GOATMessage = serde_json::from_slice(&message)?;
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
        recv_and_dispatch(
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
        .await?;
        let mut storage_processor = local_db.acquire().await?;
        storage_processor
            .update_messages_state(&[message.message_id], MessageState::Processed.to_string())
            .await?;
    }
    Ok(())
}

/// Filter the message and dispatch message to different handlers, like rpc handler, or other peers
///     * database: inner_rpc: Write or Read.
///     * peers: send
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

    let message: GOATMessage = serde_json::from_slice(&message)?;
    let content: GOATMessageContent = message.to_typed()?;
    match (content, actor) {
        (GOATMessageContent::PeginRequest(data), Actor::Committee) => {
            // triggered by BridgeInRequest event
            let PeginRequest { instance_id } = data;
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
            todo_funcs::store_pegin_request(local_db, instance_id, user_info, pegin_amount).await?;
            // 3. call Gateway.answerPeginRequest
            let pubkey_for_instance = CommitteeMasterKey::new(get_bitvm_key()?)
                .keypair_for_instance(instance_id)
                .public_key()
                .into();
            todo_funcs::answer_pegin_request(goat_client, instance_id, pubkey_for_instance).await?;
        }
        (GOATMessageContent::PeginRequest(data), _) => {
            // triggered by BridgeInRequest event
            let PeginRequest { instance_id } = data;
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
            todo_funcs::store_pegin_request(local_db, instance_id, user_info, pegin_amount).await?;
        }
        (GOATMessageContent::ConfirmInstance(data), Actor::Operator) => {
            // triggered by PeginDeposit tx
            let ConfirmInstance { instance_id } = data;
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
            todo_funcs::store_instance_parameters(local_db, &instance_params).await?;
            // 3. create & presign graph
            let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
            let local_operator_pubkey = operator_master_key.master_keypair().public_key().into();
            let (graph_nonce, cur_prekickoff_tx) =
                match todo_funcs::get_current_prekickoff_tx(local_db, &local_operator_pubkey)
                    .await?
                {
                    Some(v) => v,
                    None => {
                        // create a genesis prekickoff tx
                        let genesis_prekickoff_tx =
                            todo_funcs::build_genesis_prekickoff_tx(btc_client).await?;
                        (0, genesis_prekickoff_tx)
                    }
                };
            let prekickoff_params =
                todo_funcs::build_prekickoff_params(btc_client, graph_nonce, cur_prekickoff_tx)
                    .await?;
            let graph_params =
                todo_funcs::build_graph_params(&instance_params, &prekickoff_params).await?;
            let graph_id = graph_params.graph_id;
            let disprove_scripts =
                todo_funcs::generate_disprove_scripts(instance_id, graph_id, &graph_params).await?;
            let mut graph = generate_bitvm_graph(graph_params, disprove_scripts)?;
            operator_pre_sign(operator_master_key.keypair_for_graph(graph_id), &mut graph)?;
            // 4. broadcast CreateGraph
            let message_content = GOATMessageContent::CreateGraph(CreateGraph {
                instance_id,
                graph_id,
                graph_nonce,
                graph: graph.to_simplified()?,
            });
            send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
        }
        (GOATMessageContent::ConfirmInstance(data), _) => {
            // triggered by PeginDeposit tx
            let ConfirmInstance { instance_id } = data;
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
            todo_funcs::store_instance_parameters(local_db, &instance_params).await?;
        }
        (GOATMessageContent::CreateGraph(data), Actor::Committee) => {
            // received from Operator
            let CreateGraph { instance_id, graph_id, graph_nonce, graph } = data;
            tracing::info!("Handle CreateGraph for {instance_id}:{graph_id}");
            // 1. check graph data & operator stake
            if let Err(e) = todo_funcs::validate_init_graph(
                local_db,
                btc_client,
                goat_client,
                graph_nonce,
                &graph,
            )
            .await
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
            todo_funcs::store_graph(local_db, graph_nonce, &graph).await?;
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
            todo_funcs::store_committee_pub_nonces_for_graph(
                local_db,
                instance_id,
                graph_id,
                local_committee_pubkey,
                pub_nonces,
            )
            .await?;
            // 4. if collected enough pub_nonces, generate partial signatures & broadcast CommitteePresign
            let committee_pubkeys =
                todo_funcs::get_committee_pubkeys(goat_client, instance_id).await?;
            let pub_nonces_unchecked =
                todo_funcs::get_committee_pub_nonces_for_graph(local_db, instance_id, graph_id)
                    .await?;
            if pub_nonces_unchecked.len() == committee_pubkeys.len() {
                let (_, graph) = todo_funcs::get_graph(local_db, instance_id, graph_id)
                    .await?
                    .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
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
        (GOATMessageContent::NonceGeneration(data), Actor::Committee) => {
            // received from Committee members
            let NonceGeneration {
                instance_id,
                graph_id,
                committee_pubkey: received_committee_pubkey,
                watchtower_num,
                assert_commit_num,
                pub_nonces,
                nonce_sigs,
            } = data;
            if let Err(e) = todo_funcs::validate_committee(
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
                        _ => {}
                    }
                };
                bail!(e)
            }
            tracing::info!(
                "Handle NonceGeneration for {instance_id}:{graph_id} from {}",
                received_committee_pubkey.to_string()
            );
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
            todo_funcs::store_committee_pub_nonces_for_graph(
                local_db,
                instance_id,
                graph_id,
                received_committee_pubkey,
                pub_nonces,
            )
            .await?;
            // 3. if received enough pub_nonces, generate partial signatures & broadcast CommitteePresign
            let committee_pubkeys =
                todo_funcs::get_committee_pubkeys(goat_client, instance_id).await?;
            let pub_nonces_unchecked =
                todo_funcs::get_committee_pub_nonces_for_graph(local_db, instance_id, graph_id)
                    .await?;
            if pub_nonces_unchecked.len() == committee_pubkeys.len() {
                let local_committee_pubkey = CommitteeMasterKey::new(get_bitvm_key()?)
                    .keypair_for_instance(instance_id)
                    .public_key()
                    .into();
                let (_, graph) = todo_funcs::get_graph(local_db, instance_id, graph_id)
                    .await?
                    .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
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
                todo_funcs::store_committee_partial_sigs_for_graph(
                    local_db,
                    instance_id,
                    graph_id,
                    local_committee_pubkey,
                    committee_partial_sigs,
                )
                .await?;
                // 4. if received enough valid committee partial sigs, endorse the graph
                let committee_partial_sigs = todo_funcs::get_committee_partial_sigs_for_graph(
                    local_db,
                    instance_id,
                    graph_id,
                )
                .await?
                .into_iter()
                .map(|(_, ps)| ps)
                .collect::<Vec<_>>();
                if committee_partial_sigs.len() == committee_pubkeys.len() {
                    let committee_sig_for_graph = todo_funcs::endorse_graph(&graph)?;
                    let committee_evm_address = todo_funcs::get_node_evm_address()?;
                    let message_content = GOATMessageContent::EndorseGraph(EndorseGraph {
                        instance_id,
                        graph_id,
                        committee_pubkey: local_committee_pubkey,
                        committee_sig_for_graph,
                        committee_evm_address,
                    });
                    send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
                }
            }
        }
        (GOATMessageContent::NonceGeneration(data), Actor::Operator) => {
            // received from Committee members
            let NonceGeneration {
                instance_id,
                graph_id,
                committee_pubkey: received_committee_pubkey,
                watchtower_num,
                assert_commit_num,
                pub_nonces,
                nonce_sigs,
            } = data;
            if let Err(e) = todo_funcs::validate_committee(
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
                        _ => {}
                    }
                };
                bail!(e)
            }
            tracing::info!(
                "Handle NonceGeneration for {instance_id}:{graph_id} from {}",
                received_committee_pubkey.to_string()
            );
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
            let (graph_nonce, graph) = todo_funcs::get_graph(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
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
            todo_funcs::store_committee_pub_nonces_for_graph(
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
                Some((graph_nonce, &graph)),
                true,
            )
            .await?;
        }
        (GOATMessageContent::CommitteePresign(data), Actor::Committee) => {
            // received from Committee members
            let CommitteePresign {
                instance_id,
                graph_id,
                committee_pubkey: received_committee_pubkey,
                committee_partial_sigs,
                agg_nonces: _,
            } = data;
            if let Err(e) = todo_funcs::validate_committee(
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
                        _ => {}
                    }
                };
                bail!(e)
            }
            tracing::info!(
                "Handle CommitteePresign for {instance_id}:{graph_id} from {}",
                received_committee_pubkey.to_string()
            );
            // 1. save the committee partial sigs to local db
            // TODO: validate the partial sigs
            todo_funcs::store_committee_partial_sigs_for_graph(
                local_db,
                instance_id,
                graph_id,
                received_committee_pubkey,
                committee_partial_sigs,
            )
            .await?;
            // 2. if received enough valid committee partial sigs, endorse the graph
            let committee_pubkeys =
                todo_funcs::get_committee_pubkeys(goat_client, instance_id).await?;
            let committee_partial_sigs =
                todo_funcs::get_committee_partial_sigs_for_graph(local_db, instance_id, graph_id)
                    .await?
                    .into_iter()
                    .map(|(_, ps)| ps)
                    .collect::<Vec<_>>();
            if committee_partial_sigs.len() == committee_pubkeys.len() {
                let (_, graph) = todo_funcs::get_graph(local_db, instance_id, graph_id)
                    .await?
                    .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
                let graph = Bitvm2Graph::from_simplified(&graph)?;
                let committee_sig_for_graph = todo_funcs::endorse_graph(&graph)?;
                let local_committee_pubkey = CommitteeMasterKey::new(get_bitvm_key()?)
                    .keypair_for_instance(instance_id)
                    .public_key()
                    .into();
                let committee_evm_address = todo_funcs::get_node_evm_address()?;
                let message_content = GOATMessageContent::EndorseGraph(EndorseGraph {
                    instance_id,
                    graph_id,
                    committee_pubkey: local_committee_pubkey,
                    committee_sig_for_graph,
                    committee_evm_address,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
            }
        }
        (GOATMessageContent::CommitteePresign(data), Actor::Operator) => {
            // received from Committee members
            let CommitteePresign {
                instance_id,
                graph_id,
                committee_pubkey: received_committee_pubkey,
                committee_partial_sigs,
                agg_nonces: _,
            } = data;
            if let Err(e) = todo_funcs::validate_committee(
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
                        _ => {}
                    }
                };
                bail!(e)
            }
            tracing::info!(
                "Handle CommitteePresign for {instance_id}:{graph_id} from {}",
                received_committee_pubkey.to_string()
            );
            // 1. save the committee partial sigs to local db
            // TODO: validate the partial sigs
            todo_funcs::store_committee_partial_sigs_for_graph(
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
        (GOATMessageContent::EndorseGraph(data), Actor::Operator) => {
            // received from Committee members
            let EndorseGraph {
                instance_id,
                graph_id,
                committee_pubkey: received_committee_pubkey,
                committee_sig_for_graph,
                committee_evm_address,
            } = data;
            if let Err(e) = todo_funcs::validate_committee_with_evm_address(
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
                        _ => {}
                    }
                };
                bail!(e)
            }
            tracing::info!(
                "Handle EndorseGraph for {instance_id}:{graph_id} from {}",
                received_committee_pubkey.to_string()
            );
            // 1. check endorsement signature
            let (graph_nonce, graph) = todo_funcs::get_graph(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
            let full_graph = Bitvm2Graph::from_simplified(&graph)?;
            if let Err(e) = todo_funcs::verify_graph_endorsement(
                &committee_evm_address,
                &full_graph,
                &committee_sig_for_graph,
            ) {
                tracing::warn!(
                    "Ignore EndorseGraph for {instance_id}:{graph_id} from {}: invalid endorsement signature: {e}",
                    received_committee_pubkey.to_string()
                );
                return Ok(());
            }
            // 2. save the endorsement signature to local db
            todo_funcs::store_committee_endorsement_for_graph(
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
                Some((graph_nonce, &graph)),
                true,
            )
            .await?;
        }
        (GOATMessageContent::GraphFinalize(data), Actor::Committee) => {
            // received from Operator
            let GraphFinalize { instance_id, graph_id, graph_nonce, graph, endorse_sigs } = data;
            // 1. check graph data & ipfs cid
            if let Err(e) = todo_funcs::validate_finalized_graph(
                goat_client,
                graph_nonce,
                &graph,
                &endorse_sigs,
            ) {
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
            tracing::info!(
                "Handle GraphFinalize for {instance_id}:{graph_id} from {}",
                from_peer_id.to_string()
            );
            // 2. save the graph data to local db
            todo_funcs::store_graph(local_db, graph_nonce, &graph).await?;
            todo_funcs::store_committee_endorsements_for_graph(
                local_db,
                instance_id,
                graph_id,
                endorse_sigs,
            )
            .await?;
            // 3. if endorsed graph count >= threshold, generate & broadcast PeginConfirmNonce
            if todo_funcs::get_endorsed_graph_count(local_db, instance_id).await?
                >= todo_funcs::min_required_operator()
            {
                let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
                let local_committee_pubkey =
                    committee_master_key.keypair_for_instance(instance_id).public_key().into();
                let stored_pub_nonce = todo_funcs::get_committee_pub_nonce_for_instance(
                    local_db,
                    instance_id,
                    &local_committee_pubkey,
                )
                .await?;
                if let None = stored_pub_nonce {
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
                    todo_funcs::store_committee_pub_nonce_for_instance(
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
            todo!("");
        }
        (GOATMessageContent::GraphFinalize(data), _) => {
            // received from Operator
            let GraphFinalize { instance_id, graph_id, graph_nonce, graph, endorse_sigs } = data;
            // 1. check graph data & ipfs cid
            if let Err(e) = todo_funcs::validate_finalized_graph(
                goat_client,
                graph_nonce,
                &graph,
                &endorse_sigs,
            ) {
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
            tracing::info!(
                "Handle GraphFinalize for {instance_id}:{graph_id} from {}",
                from_peer_id.to_string()
            );
            // 2. save the graph data to local db
            todo_funcs::store_graph(local_db, graph_nonce, &graph).await?;
        }
        (GOATMessageContent::PeginConfirmNonce(data), Actor::Committee) => {
            // received from Committee members
            let PeginConfirmNonce {
                instance_id,
                committee_pubkey: received_committee_pubkey,
                pub_nonce,
                nonce_sig,
            } = data;
            if let Err(e) = todo_funcs::validate_committee(
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
                        _ => {}
                    }
                };
                bail!(e)
            }
            tracing::info!(
                "Handle PeginConfirmNonce for {instance_id} from {}",
                received_committee_pubkey.to_string()
            );
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
            todo_funcs::store_committee_pub_nonce_for_instance(
                local_db,
                instance_id,
                received_committee_pubkey,
                pub_nonce,
            )
            .await?;
            // 3. if received enough pub_nonces, generate partial signature & broadcast PeginConfirmPartialSig
            let committee_pubkeys =
                todo_funcs::get_committee_pubkeys(goat_client, instance_id).await?;
            let pub_nonces =
                todo_funcs::get_committee_pub_nonces_for_instance(local_db, instance_id).await?;
            if pub_nonces.len() == committee_pubkeys.len() {
                let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
                let local_committee_pubkey =
                    committee_master_key.keypair_for_instance(instance_id).public_key().into();
                let (sec_nonce, _, _) = committee_master_key.nonce_for_instance(instance_id);
                let agg_nonce = nonce_aggregation(
                    &pub_nonces.iter().map(|(_, pn)| pn.clone()).collect::<Vec<_>>(),
                );
                let instance_params = todo_funcs::get_instance_parameters(local_db, instance_id)
                    .await?
                    .ok_or_else(|| anyhow!("Instance parameters not found for {instance_id}"))?;
                let mut pegin_confirm = instance_params.build_pegin_tx()?.1;
                let context = instance_params
                    .get_verifier_context(committee_master_key.keypair_for_instance(instance_id))?;
                let partial_sig = pegin_confirm
                    .sign_input_0_musig2(&context, &sec_nonce, &agg_nonce)
                    .map_err(|e| anyhow!("Failed to sign pegin confirm for {instance_id}: {e}"))?;
                let message_content =
                    GOATMessageContent::PeginConfirmPartialSig(PeginConfirmPartialSig {
                        instance_id,
                        committee_pubkey: local_committee_pubkey,
                        partial_sig,
                    });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::Committee, &message_content)?)?;
                todo_funcs::store_committee_partial_sig_for_instance(
                    local_db,
                    instance_id,
                    local_committee_pubkey,
                    partial_sig,
                )
                .await?;
                // 4. (Relayer) if received enough partial signatures, aggregate the sigs
                if todo_funcs::is_relayer() {
                    let partial_sigs =
                        todo_funcs::get_committee_partial_sigs_for_instance(local_db, instance_id)
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
        (GOATMessageContent::PeginConfirmPartialSig(_data), Actor::Committee) => {
            // received from Committee members
            let PeginConfirmPartialSig {
                instance_id,
                committee_pubkey: received_committee_pubkey,
                partial_sig,
            } = _data;
            if let Err(e) = todo_funcs::validate_committee(
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
                        _ => {}
                    }
                };
                bail!(e)
            }
            tracing::info!(
                "Handle PeginConfirmPartialSig for {instance_id} from {}",
                received_committee_pubkey.to_string()
            );
            // 1. TODO: check partial signature
            // 2. save the partial signature to local db
            todo_funcs::store_committee_partial_sig_for_instance(
                local_db,
                instance_id,
                received_committee_pubkey,
                partial_sig,
            )
            .await?;
            // 3. (Relayer) if received enough partial signatures, aggregate the sigs
            if todo_funcs::is_relayer() {
                let partial_sigs =
                    todo_funcs::get_committee_partial_sigs_for_instance(local_db, instance_id)
                        .await?
                        .into_iter()
                        .map(|(_, ps)| ps)
                        .collect::<Vec<_>>();
                let pub_nonces =
                    todo_funcs::get_committee_pub_nonces_for_instance(local_db, instance_id)
                        .await?;
                let committee_pubkeys =
                    todo_funcs::get_committee_pubkeys(goat_client, instance_id).await?;
                if partial_sigs.len() == committee_pubkeys.len()
                    && pub_nonces.len() == committee_pubkeys.len()
                {
                    let instance_params =
                        todo_funcs::get_instance_parameters(local_db, instance_id)
                            .await?
                            .ok_or_else(|| {
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
        (GOATMessageContent::PostReady(_data), Actor::Committee) => {
            // triggered by PeginConfirm tx
            // 1. (Relayer)check if postPeginData requirements are met
            // 2. (Relayer)call Gateway.postPeginData on GoatChain
            // 3. (Relayer)call Gateway.postGraphData on GoatChain
            todo!("Handle PostReady");
        }
        (GOATMessageContent::KickoffReady(data), Actor::Operator) => {
            // triggered by InitWithdraw event from GoatChain
            let KickoffReady { instance_id, graph_id } = data;
            // 1. check the withdraw status on GoatChain
            let withdraw_status =
                todo_funcs::get_withdraw_data(goat_client, &graph_id).await?.status;
            if withdraw_status != WithdrawStatus::Initialized {
                tracing::warn!(
                    "Ignore KickoffReady for {instance_id}:{graph_id}: invalid withdraw status: {withdraw_status:?}"
                );
                return Ok(());
            }
            tracing::info!("Handle KickoffReady for {instance_id}:{graph_id}");
            // 2. check prekickoff nonce
            // 3. sign & broadcast prekickoff & kickoff txns
            todo!("Handle KickoffReady");
        }
        (GOATMessageContent::KickoffSent(data), Actor::Challenger) => {
            // triggered by Kickoff tx
            let KickoffSent { instance_id, graph_id } = data;
            tracing::info!("Handle KickoffSent for {instance_id}:{graph_id}");
            // 1. check kickoff tx status on Bitcoin chain
            let (_, graph) = todo_funcs::get_graph(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
            let graph = Bitvm2Graph::from_simplified(&graph)?;
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
            let withdraw_status =
                todo_funcs::get_withdraw_data(goat_client, &graph_id).await?.status;
            let goat_confirmed_btc_height =
                todo_funcs::get_goat_confirmed_btc_height(goat_client).await?;
            if [WithdrawStatus::None, WithdrawStatus::Canceled].contains(&withdraw_status) {
                if kickoff_height >= goat_confirmed_btc_height {
                    let delay_ms = (kickoff_height + 1 - goat_confirmed_btc_height) * 600_000;
                    push_local_unhandled_messages(local_db, message, delay_ms as usize).await?;
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
            }
        }
        (GOATMessageContent::PreKickoffSent(_data), Actor::Challenger) => {
            // triggered by PreKickoff tx
            // 1. check the previous graph status
            // 2. if previous kickoff is not closed, broadcast quick-challenge/challenge-incomplete-kickoff txn
            // 3. if previous kickoff not started, broadcast force-skip-kickoff txn
            todo!("Handle PreKickoffSent");
        }
        (GOATMessageContent::ChallengeSent(data), Actor::Operator) => {
            // triggered by Challenge tx
            let ChallengeSent { instance_id, graph_id, challenge_txid } = data;
            tracing::info!("Handle ChallengeSent for {instance_id}:{graph_id}");
            // 1. check the challenge tx status on Bitcoin chain
            let (_, graph) = todo_funcs::get_graph(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
            let mut graph = Bitvm2Graph::from_simplified(&graph)?;
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
                operator_master_key.keypair_for_graph(graph_id),
                &mut graph,
            )?;
            let anchor_vout = watchtower_challenge_init_tx.input.len() as u64 - 1;
            todo_funcs::build_and_broadcast_cpfp_txns(
                btc_client,
                watchtower_challenge_init_tx,
                anchor_vout,
            )
            .await?;
        }
        (GOATMessageContent::WatchtowerChallengeInitSent(data), Actor::Watchtower) => {
            // triggered by WatchtowerChallengeInit tx
            let WatchtowerChallengeInitSent { instance_id, graph_id } = data;
            tracing::info!("Handle WatchtowerChallengeInitSent for {instance_id}:{graph_id}");
            let (_, graph) = todo_funcs::get_graph(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
            let watchtower_keypair = WatchtowerMasterKey::new(get_bitvm_key()?).master_keypair();
            let node_index = match graph
                .parameters
                .watchtower_pubkeys
                .iter()
                .position(|pk| *pk == watchtower_keypair.public_key().into())
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
            let withdraw_status =
                todo_funcs::get_withdraw_data(goat_client, &graph_id).await?.status;
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
        (GOATMessageContent::WatchtowerChallengeSent(data), Actor::Operator) => {
            // triggered by WatchtowerChallenge tx
            let WatchtowerChallengeSent { instance_id, graph_id, watchtower_challenge_txids } =
                data;
            // 1. check the watchtower-challenge tx status on Bitcoin chain, if watchtower challenge tx is confirmed, sign & broadcast operator-ack txn
            let (_, graph) = todo_funcs::get_graph(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
            let mut graph = Bitvm2Graph::from_simplified(&graph)?;
            let watchtower_challenge_init_txid =
                graph.watchtower_challenge_init.tx().compute_txid();
            let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
            let operator_graph_keypair = operator_master_key.keypair_for_graph(graph_id);
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
        (GOATMessageContent::WatchtowerChallengeTimeout(data), Actor::Operator) => {
            // triggered by timeout task
            let WatchtowerChallengeTimeout { instance_id, graph_id, watchtower_indexes } = data;
            let (_, graph) = todo_funcs::get_graph(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
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
                let watchtower_challenge_vout = 2 * watchtower_index as u64;
                if outpoint_spent_txid(
                    btc_client,
                    &watchtower_challenge_init_txid,
                    watchtower_challenge_vout,
                )
                .await?
                .is_some()
                {
                    tracing::warn!(
                        "Ignore WatchtowerChallengeTimeout for {instance_id}:{graph_id}:{watchtower_index}: watchtower challenge connector already spent"
                    );
                    continue;
                }
                let watchtower_challenge_timeout_tx = operator_sign_watchtower_challenge_timeout(
                    operator_master_keypair,
                    &mut graph,
                    watchtower_index,
                )?;
                let anchor_vout = watchtower_challenge_timeout_tx.input.len() as u64 - 1;
                todo_funcs::build_and_broadcast_cpfp_txns(
                    btc_client,
                    watchtower_challenge_timeout_tx,
                    anchor_vout,
                )
                .await?;
            }
        }
        (GOATMessageContent::OperatorAckTimeout(data), Actor::Challenger) => {
            // triggered by timeout task
            let OperatorAckTimeout { instance_id, graph_id } = data;
            let (_, graph) = todo_funcs::get_graph(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
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
            tracing::info!("Handle OperatorAckTimeout for {instance_id}:{graph_id}");
            let nack_tx = graph
                .nack_txns
                .get(nack_index)
                .ok_or_else(|| {
                    anyhow!("Nack txn not found for {instance_id}:{graph_id}:{nack_index}")
                })?
                .finalize();
            let anchor_vout = nack_tx.input.len() as u64 - 1;
            todo_funcs::build_and_broadcast_cpfp_txns(btc_client, nack_tx, anchor_vout).await?;
        }
        (GOATMessageContent::OperatorCommitBlockHashReady(data), Actor::Operator) => {
            // triggered by timeout task
            let OperatorCommitBlockHashReady { instance_id, graph_id } = data;
            let (_, graph) = todo_funcs::get_graph(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
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
            tracing::info!("Handle OperatorCommitBlockHashReady for {instance_id}:{graph_id}");
            let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
            let operator_graph_keypair = operator_master_key.keypair_for_graph(graph_id);
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
        (GOATMessageContent::OperatorCommitBlockHashTimeout(data), Actor::Challenger) => {
            // triggered by timeout task
            let OperatorCommitBlockHashTimeout { instance_id, graph_id } = data;
            let (_, graph) = todo_funcs::get_graph(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
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
            tracing::info!("Handle OperatorCommitBlockHashTimeout for {instance_id}:{graph_id}");
            let blockhash_commit_timeout_tx = graph.blockhash_commit_timeout.finalize();
            let anchor_vout = blockhash_commit_timeout_tx.input.len() as u64 - 1;
            todo_funcs::build_and_broadcast_cpfp_txns(
                btc_client,
                blockhash_commit_timeout_tx,
                anchor_vout,
            )
            .await?;
        }
        (GOATMessageContent::AssertInitReady(data), Actor::Operator) => {
            // triggered by timeout task
            let AssertInitReady { instance_id, graph_id } = data;
            let (_, graph) = todo_funcs::get_graph(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
            let mut graph = Bitvm2Graph::from_simplified(&graph)?;
            let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
            let operator_graph_keypair = operator_master_key.keypair_for_graph(graph_id);
            let operator_master_keypair = operator_master_key.master_keypair();
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
                let anchor_vout = assert_init_tx.input.len() as u64 - 1;
                todo_funcs::build_and_broadcast_cpfp_txns(btc_client, assert_init_tx, anchor_vout)
                    .await?;
                // assert-commit should be broadcasted after assert-init is confirmed (wait 20 minutes here)
                let delay_ms = 20 * 60 * 1000; // 20 minutes
                push_local_unhandled_messages(local_db, message, delay_ms).await?;
                return Ok(());
            }
            // 2. sign & broadcast assert-commit txns
            if !tx_confirmed(btc_client, &assert_init_txid).await? {
                // assert-commit should be broadcasted after assert-init is confirmed (wait 20 minutes here)
                let delay_ms = 20 * 60 * 1000; // 20 minutes
                push_local_unhandled_messages(local_db, message, delay_ms).await?;
                return Ok(());
            } else {
                let wots_secret_keys =
                    operator_master_key.wots_keypair_for_graph(graph.parameters.graph_id).0;
                let (guest_inputs, proof, groth16_pubin, vk) =
                    todo_funcs::get_operator_proof(instance_id, graph_id).await?;
                let assert_commit_inputs = operator_sign_assert_commit(
                    operator_graph_keypair,
                    &mut graph,
                    &wots_secret_keys,
                    guest_inputs,
                    proof,
                    groth16_pubin,
                    &vk,
                )?;
                for (i, (txin, txin_amount)) in assert_commit_inputs.into_iter().enumerate() {
                    if outpoint_spent_txid(btc_client, &assert_init_txid, i as u64).await?.is_none()
                    {
                        build_sign_and_broadcast_tx(
                            btc_client,
                            operator_master_keypair,
                            vec![txin],
                            txin_amount,
                            vec![],
                        )
                        .await?;
                    }
                }
            }
        }
        (GOATMessageContent::AssertCommitTimeout(data), Actor::Challenger) => {
            // triggered by timeout task
            let AssertCommitTimeout { instance_id, graph_id } = data;
            let (_, graph) = todo_funcs::get_graph(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
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
            tracing::info!("Handle AssertCommitTimeout for {instance_id}:{graph_id}");
            let assert_commit_timeout_tx = graph.assert_commit_timeout_txns.get(commit_index).ok_or_else(|| {
                anyhow!("AssertCommitTimeout txn not found for {instance_id}:{graph_id}:{commit_index}")
            })?.finalize();
            let anchor_vout = assert_commit_timeout_tx.input.len() as u64 - 1;
            todo_funcs::build_and_broadcast_cpfp_txns(
                btc_client,
                assert_commit_timeout_tx,
                anchor_vout,
            )
            .await?;
        }
        (GOATMessageContent::DisproveReady(data), Actor::Challenger) => {
            // triggered by AssertCommit tx or OperatorCommitBlockHash tx
            let DisproveReady { instance_id, graph_id } = data;
            let (_, graph) = todo_funcs::get_graph(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
            let graph = Bitvm2Graph::from_simplified(&graph)?;
            tracing::info!("Handle DisproveReady for {instance_id}:{graph_id}");
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
            let disprove_scripts =
                todo_funcs::generate_disprove_scripts(instance_id, graph_id, &graph.parameters)
                    .await?;
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
                let disprover_evm_address = todo_funcs::get_node_evm_address()?;
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
        (GOATMessageContent::DisproveSent(_data), Actor::Committee) => {
            // triggered by Disprove tx
            // 1. (Relayer) call finalizeWithdrawDisprove on GoatChain
            todo!("Handle DisproveSent");
        }
        (GOATMessageContent::Take1Ready(data), Actor::Operator) => {
            // triggered by timeout task
            let Take1Ready { instance_id, graph_id } = data;
            let (_, graph) = todo_funcs::get_graph(local_db, instance_id, graph_id)
                .await?
                .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
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
            let current_height = btc_client.get_height().await?;
            if current_height < kickoff_height + take1_timelock(get_network()) {
                tracing::warn!(
                    "Ignore Take1Ready for {instance_id}:{graph_id}: kickoff tx timelock not expired yet"
                );
                return Ok(());
            }
            // 1. sign & broadcast take1 txn
            tracing::info!("Handle Take1Ready for {instance_id}:{graph_id}");
            let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
            let operator_graph_keypair = operator_master_key.keypair_for_graph(graph_id);
            let take1_tx = operator_sign_take1(operator_graph_keypair, &mut graph)?;
            let anchor_vout = take1_tx.input.len() as u64 - 1;
            todo_funcs::build_and_broadcast_cpfp_txns(btc_client, take1_tx, anchor_vout).await?;
        }
        (GOATMessageContent::Take1Sent(_data), Actor::Committee) => {
            // triggered by Take1 tx
            // 1. (Relayer) call finalizeWithdrawHappyPath on GoatChain
            todo!("Handle Take1Sent");
        }
        (GOATMessageContent::Take2Ready(data), Actor::Operator) => {
            // triggered by timeout task
            let Take2Ready { instance_id, graph_id } = data;
            let (_, graph) = todo_funcs::get_graph(local_db, instance_id, graph_id)
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
            let current_height = btc_client.get_height().await?;
            let (connector_f_timelock, connector_d_timelock) = take2_timelocks(get_network());
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
            if current_height < assert_init_height + connector_d_timelock {
                tracing::warn!(
                    "Ignore Take2Ready for {instance_id}:{graph_id}: assert init tx timelock not expired yet"
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
                        "Ignore Take2Ready for {instance_id}:{graph_id}: watchtower challenge init tx not confirmed yet"
                    );
                    return Ok(());
                }
            };
            if current_height < watchtower_challenge_init_height + connector_f_timelock {
                tracing::warn!(
                    "Ignore Take2Ready for {instance_id}:{graph_id}: watchtower challenge not finished yet"
                );
                return Ok(());
            }
            // 1. sign & broadcast take2 txn
            tracing::info!("Handle Take2Ready for {instance_id}:{graph_id}");
            let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
            let operator_graph_keypair = operator_master_key.keypair_for_graph(graph_id);
            let take2_tx = operator_sign_take2(operator_graph_keypair, &mut graph)?;
            let anchor_vout = take2_tx.input.len() as u64 - 1;
            todo_funcs::build_and_broadcast_cpfp_txns(btc_client, take2_tx, anchor_vout).await?;
        }
        (GOATMessageContent::Take2Sent(_data), Actor::Committee) => {
            // triggered by Take2 tx
            // 1. (Relayer) call finalizeWithdrawHappyPath on GoatChain
            todo!("Handle Take2Sent");
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
    graph: Option<(u64, &SimplifiedBitvm2Graph)>,
    broadcast_graph_finalize: bool,
) -> Result<()> {
    let endorsements =
        todo_funcs::get_committee_endorsements_for_graph(local_db, instance_id, graph_id).await?;
    let pub_nonoces =
        todo_funcs::get_committee_pub_nonces_for_graph(local_db, instance_id, graph_id).await?;
    let partial_sigs =
        todo_funcs::get_committee_partial_sigs_for_graph(local_db, instance_id, graph_id).await?;
    let committee_pubkeys = todo_funcs::get_committee_pubkeys(goat_client, instance_id).await?;
    if endorsements.len() == committee_pubkeys.len()
        && pub_nonoces.len() == committee_pubkeys.len()
        && partial_sigs.len() == committee_pubkeys.len()
    {
        let (graph_nonce, mut graph) = match graph {
            Some((gn, g)) => (gn, Bitvm2Graph::from_simplified(g)?),
            None => {
                let (gn, g) = todo_funcs::get_graph(local_db, instance_id, graph_id)
                    .await?
                    .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
                (gn, Bitvm2Graph::from_simplified(&g)?)
            }
        };
        let pub_nonces = pub_nonoces.into_iter().map(|(_, pn)| pn).collect::<Vec<_>>();
        let agg_nonces = nonces_aggregation(&pub_nonces)?;
        let partial_sigs = partial_sigs.into_iter().map(|(_, ps)| ps).collect::<Vec<_>>();
        let committee_sig_for_graph = signature_aggregation(&partial_sigs, &agg_nonces, &graph)?;
        let simplified_graph = graph.to_simplified()?;
        todo_funcs::store_graph(local_db, graph_nonce, &simplified_graph).await?;
        push_committee_pre_signatures(&mut graph, &committee_sig_for_graph)?;
        if broadcast_graph_finalize {
            let message_content = GOATMessageContent::GraphFinalize(GraphFinalize {
                instance_id,
                graph_id,
                graph_nonce,
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
    _local_db: &LocalDB,
    _message: GOATMessage,
    _delay_ms: usize,
) -> Result<()> {
    todo!("Push local unhandled messages");
}
