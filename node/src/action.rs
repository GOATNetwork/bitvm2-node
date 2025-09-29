use crate::env::get_bitvm_key;
use crate::error::SpecialError;
use crate::middleware::AllBehaviours;
use crate::scheduled_tasks::{committee_scheduled_tasks, relayer_scheduled_tasks};
use crate::utils::*;
use alloy::primitives::Address as EvmAddress;
use anyhow::{Result, anyhow, bail};
use bitcoin::Txid;
use bitcoin::{PublicKey, XOnlyPublicKey};
use bitvm2_lib::actors::Actor;
use bitvm2_lib::committee::*;
use bitvm2_lib::keys::{CommitteeMasterKey, OperatorMasterKey};
use bitvm2_lib::operator::{generate_bitvm_graph, operator_pre_sign};
use bitvm2_lib::types::{Bitvm2Graph, SimplifiedBitvm2Graph};
use client::goat_chain::DisproveTxType;
use client::{btc_chain::BTCClient, goat_chain::GOATClient};
use goat::connectors::connector_z::ConnectorZ;
use goat::transactions::pre_signed::PreSignedTransaction;
use goat::transactions::pre_signed_musig2::verify_public_nonce;
use libp2p::gossipsub::MessageId;
use libp2p::{PeerId, Swarm, gossipsub};
use musig2::{PartialSignature, PubNonce};
use secp256k1::schnorr::Signature as SchnorrSignature;
use serde::{Deserialize, Serialize};
use store::GraphStatus;
use store::ipfs::IPFS;
use store::localdb::LocalDB;
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
    OperatorCommitBlockHashSent(OperatorCommitBlockHashSent),
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
    pub watchtower_indexes: Vec<usize>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct OperatorCommitBlockHashReady {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct OperatorCommitBlockHashSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub operator_commit_blockhash_txid: Txid,
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
    pub assert_commit_indexes: Vec<usize>,
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
) -> anyhow::Result<()> {
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

    tracing::debug!("Get the running task, and broadcast the task status or result");
    if actor == Actor::Relayer {
        relayer_scheduled_tasks(swarm, local_db, btc_client, goat_client).await?;
    }
    if actor == Actor::Committee {
        committee_scheduled_tasks(swarm, local_db, btc_client, goat_client).await?;
    }

    if let Some(message) = pop_local_unhandle_msg(local_db, actor.clone()).await?
        && !message.is_empty()
    {
        recv_and_dispatch(
            swarm,
            local_db,
            btc_client,
            goat_client,
            ipfs,
            actor,
            from_peer_id,
            id,
            &message,
        )
        .await
    } else {
        Ok(())
    }
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
        (GOATMessageContent::KickoffReady(_data), Actor::Operator) => {
            // triggered by InitWithdraw event from GoatChain
            // 1. check the withdraw status on GoatChain
            // 2. sign & broadcast prekickoff & kickoff txns
            todo!("Handle KickoffReady");
        }
        (GOATMessageContent::KickoffSent(_data), Actor::Challenger) => {
            // triggered by Kickoff tx
            // 1. check the withdraw status on GoatChain
            // 2. if it's invalid, sign & broadcast challenge txn
            todo!("Handle KickoffSent");
        }
        (GOATMessageContent::PreKickoffSent(_data), Actor::Challenger) => {
            // triggered by PreKickoff tx
            // 1. check the previous graph status
            // 2. if previous kickoff is not closed, broadcast quick-challenge/challenge-incomplete-kickoff txn
            // 3. if previous kickoff not started, broadcast force-skip-kickoff txn
            todo!("Handle PreKickoffSent");
        }
        (GOATMessageContent::ChallengeSent(_data), Actor::Operator) => {
            // triggered by Challenge tx
            // 1. check the challenge tx status on Bitcoin chain
            // 2. if the challenge is confirmed, sign & broadcast watchtower-challenge-init txn
            todo!("Handle ChallengeSent");
        }
        (GOATMessageContent::WatchtowerChallengeInitSent(_data), Actor::Watchtower) => {
            // triggered by WatchtowerChallengeInit tx
            // 1. check the withdraw status on GoatChain
            // 2. if the withdraw is invalid, sign & broadcast watchtower-challenge txn
            todo!("Handle WatchtowerChallengeInitSent");
        }
        (GOATMessageContent::WatchtowerChallengeSent(_data), Actor::Operator) => {
            // triggered by WatchtowerChallenge tx
            // 1. check the watchtower-challenge tx status on Bitcoin chain
            // 2. if the challenge is confirmed, sign & broadcast operator-ack txn
            todo!("Handle WatchtowerChallengeSent");
        }
        (GOATMessageContent::WatchtowerChallengeTimeout(_data), Actor::Operator) => {
            // triggered by timeout task
            // 1. sign & broadcast operator-ack txn
            todo!("Handle WatchtowerChallengeTimeout");
        }
        (GOATMessageContent::OperatorAckTimeout(_data), Actor::Challenger) => {
            // triggered by timeout task
            // 1. broadcast Nack txn
            todo!("Handle OperatorAckTimeout");
        }
        (GOATMessageContent::OperatorCommitBlockHashReady(_data), Actor::Operator) => {
            // triggered by timeout task
            // 1. check that all WatchtowerChallenge Connectors are spent
            // 2. sign & broadcast commit-blockhash txn
            todo!("Handle OperatorCommitBlockHashReady");
        }
        (GOATMessageContent::OperatorCommitBlockHashSent(_data), Actor::Challenger) => {
            // triggered by CommitBlockHash tx
            // 1. get CommitBlockHash tx, save it to local db
            // 2. if CommitBlockHash tx and all AssertCommit txns are sent, start disprove process
            todo!("Handle OperatorCommitBlockHashSent");
        }
        (GOATMessageContent::OperatorCommitBlockHashTimeout(_data), Actor::Challenger) => {
            // triggered by timeout task
            // 1. broadcast OperatorCommitBlockHashTimeout txn
            todo!("Handle OperatorCommitBlockHashTimeout");
        }
        (GOATMessageContent::AssertInitReady(_data), Actor::Operator) => {
            // triggered by timeout task
            // 1. sign & broadcast assert-init txn
            // 2. sign & broadcast assert-commit txns
            todo!("Handle AssertInitReady");
        }
        (GOATMessageContent::AssertCommitTimeout(_data), Actor::Challenger) => {
            // triggered by timeout task
            // 1. broadcast AssertCommitTimeout txn
            todo!("Handle AssertCommitTimeout");
        }
        (GOATMessageContent::DisproveReady(_data), Actor::Challenger) => {
            // triggered by AssertCommitSent/OperatorCommitBlockHashSent
            // 1. check assertions committed by Operator
            // 2. if any assertion is invalid, sign & broadcast disprove txn
            todo!("Handle DisproveReady");
        }
        (GOATMessageContent::DisproveSent(_data), Actor::Committee) => {
            // triggered by Disprove tx
            // 1. (Relayer) call finalizeWithdrawDisprove on GoatChain
            todo!("Handle DisproveSent");
        }
        (GOATMessageContent::Take1Ready(_data), Actor::Operator) => {
            // triggered by timeout task
            // 1. sign & broadcast take1 txn
            todo!("Handle Take1Ready");
        }
        (GOATMessageContent::Take1Sent(_data), Actor::Committee) => {
            // triggered by Take1 tx
            // 1. (Relayer) call finalizeWithdrawHappyPath on GoatChain
            todo!("Handle Take1Sent");
        }
        (GOATMessageContent::Take2Ready(_data), Actor::Operator) => {
            // triggered by timeout task
            // 1. sign & broadcast take2 txn
            todo!("Handle Take2Ready");
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
