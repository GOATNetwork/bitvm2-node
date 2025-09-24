use crate::middleware::AllBehaviours;
use crate::scheduled_tasks::{committee_scheduled_tasks, relayer_scheduled_tasks};
use crate::utils::*;
use anyhow::Result;
use bitcoin::PublicKey;
use bitcoin::{Amount, Network, Txid};
use bitvm2_lib::actors::Actor;
use bitvm2_lib::committee::*;
use bitvm2_lib::types::{Bitvm2InstanceParameters, SimplifiedBitvm2Graph, UserInfo};
use client::goat_chain::DisproveTxType;
use client::{btc_chain::BTCClient, goat_chain::GOATClient};
use libp2p::gossipsub::MessageId;
use libp2p::{PeerId, Swarm, gossipsub};
use musig2::{PartialSignature, PubNonce};
use serde::{Deserialize, Serialize};
use store::GraphStatus;
use store::ipfs::IPFS;
use store::localdb::LocalDB;
use tracing::log::warn;
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
    GraphFinalize(GraphFinalize),
    EndorseGraph(EndorseGraph),
    PeginConfirmNonce(PeginConfirmNonce),
    PeginConfirmPartialSig(PeginConfirmPartialSig),
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
    pub network: Network,
    pub pegin_amount: Amount,
    pub user_info: UserInfo,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct ConfirmInstance {
    pub instance_id: Uuid,
    pub network: Network,
    pub parameters: Bitvm2InstanceParameters,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct CreateGraph {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub graph: SimplifiedBitvm2Graph,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct NonceGeneration {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub committee_pubkey: PublicKey,
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
pub struct GraphFinalize {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub graph: SimplifiedBitvm2Graph,
    pub graph_ipfs_cid: String,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct EndorseGraph {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub committee_pubkey: PublicKey,
    pub committee_sig_for_graph: Vec<u8>, // ECDSA signature signed with committee evm keypair
}
#[derive(Serialize, Deserialize, Clone)]
pub struct PeginConfirmNonce {
    pub instance_id: Uuid,
    pub committee_pubkey: PublicKey,
    pub pub_nonces: PubNonce,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct PeginConfirmPartialSig {
    pub instance_id: Uuid,
    pub committee_pubkey: PublicKey,
    pub partial_sig: PartialSignature,
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
    pub watchtower_indexs: Vec<usize>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct OperatorAckTimeout {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub watchtower_indexs: Vec<usize>,
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
    pub assert_commit_indexs: Vec<usize>,
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
    pub challenge_start_txid: Txid,
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
        warn!("handle_self_p2p_msg received unexpected message id: {:?}", id);
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
    _swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    _btc_client: &BTCClient,
    _goat_client: &GOATClient,
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
        (GOATMessageContent::PeginRequest(_data), Actor::Committee) => {
            // triggered by BridgeInRequest event
            // 1. check the pegin request data
            // 2. call Gateway.answerPeginRequest
            // 3. save the pegin request data to local db
            todo!("Handle PeginRequest");
        }
        (GOATMessageContent::PeginRequest(_data), _) => {
            // triggered by BridgeInRequest event
            // 1. check the pegin request data
            // 2. save the pegin request data to local db
            todo!("Handle PeginRequest");
        }
        (GOATMessageContent::ConfirmInstance(_data), Actor::Operator) => {
            // triggered by PeginDeposit tx
            // 1. check parameters
            // 2. create & presign graph
            // 3. broadcast CreateGraph
            // 4. save the instance data to local db
            todo!("Handle ConfirmInstance");
        }
        (GOATMessageContent::ConfirmInstance(_data), _) => {
            // triggered by PeginDeposit tx
            // 1. check parameters
            // 2. save the instance data to local db
            todo!("Handle ConfirmInstance");
        }
        (GOATMessageContent::CreateGraph(_data), Actor::Committee) => {
            // received from Operator
            // 1. check graph data & operator stake
            // 2. generate Musig2 nonces & broadcast NonceGeneration
            // 3. save the graph data to local db
            todo!("Handle CreateGraph");
        }
        (GOATMessageContent::NonceGeneration(_data), Actor::Committee) => {
            // received from Committee members
            // 1. check pub_nonces & nonce signatures
            // 2. save the pub_nonces to local db
            // 3. if received enough pub_nonces, generate partial signatures & broadcast CommitteePresign
            todo!("Handle NonceGeneration");
        }
        (GOATMessageContent::CommitteePresign(_data), Actor::Operator) => {
            // received from Committee members
            // 1. check committee partial sigs
            // 2. save the committee partial sigs to local db
            // 3. if received enough committee partial sigs, aggregate the sigs, finalize the graph, push data to ipfs & broadcast GraphFinalize
            todo!("Handle CommitteePresign");
        }
        (GOATMessageContent::GraphFinalize(_data), Actor::Committee) => {
            // received from Operator
            // 1. check graph data & ipfs cid
            // 2. save the graph data to local db
            // 3. generate endorsement signature & broadcast EndorseGraph
            todo!("Handle GraphFinalize");
        }
        (GOATMessageContent::GraphFinalize(_data), _) => {
            // received from Operator
            // 1. check graph data & ipfs cid
            // 2. save the graph data to local db
            todo!("Handle GraphFinalize");
        }
        (GOATMessageContent::EndorseGraph(_data), Actor::Committee) => {
            // received from Committee members
            // 1. check endorsement signature
            // 2. save the endorsement signature to local db
            // 3. if received enough endorsement signatures, mark the graph as endorsed
            // 4. if endorsed graph count >= threshold, generate & broadcast PeginConfirmNonce
            todo!("Handle EndorseGraph");
        }
        (GOATMessageContent::PeginConfirmNonce(_data), Actor::Committee) => {
            // received from Committee members
            // 1. check pub_nonce
            // 2. save the pub_nonce to local db
            // 3. if received enough pub_nonces, generate partial signature & broadcast PeginConfirmPartialSig
            todo!("Handle PeginConfirmNonce");
        }
        (GOATMessageContent::PeginConfirmPartialSig(_data), Actor::Committee) => {
            // received from Committee members
            // 1. check partial signature
            // 2. save the partial signature to local db
            // 3. (Relayer) if received enough partial signatures, aggregate the sigs, call postPeginData & postGraphData
            todo!("Handle PeginConfirmPartialSig");
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
            // 2. if the its invalid, sign & broadcast challenge txn
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
            // 1. check that all WatchtowerChallenge Connector are spent
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

pub fn send_to_peer(
    swarm: &mut Swarm<AllBehaviours>,
    message: GOATMessage,
) -> anyhow::Result<MessageId> {
    let actor = message.actor.to_string();
    let topic = crate::middleware::get_topic_name(&actor);
    let gossipsub_topic = gossipsub::IdentTopic::new(topic);
    Ok(swarm.behaviour_mut().gossipsub.publish(gossipsub_topic, serde_json::to_vec(&message)?)?)
}
