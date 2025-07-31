use crate::client::{BTCClient, GOATClient};
use crate::env::{self, get_local_node_info, get_node_goat_address, get_node_pubkey};
use crate::middleware::AllBehaviours;
use crate::relayer_action::do_tick_action;
use crate::rpc_service::current_time_secs;
use crate::utils::{statics::*, *};
use crate::{defer, dismiss_defer};
use anyhow::Result;
use bitcoin::PublicKey;
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::{Amount, Network, Txid};
use bitvm2_lib::actors::Actor;
use bitvm2_lib::keys::*;
use bitvm2_lib::types::{Bitvm2Graph, Bitvm2Parameters, CustomInputs, SimplifiedBitvm2Graph};
use bitvm2_lib::verifier::export_challenge_tx;
use bitvm2_lib::{committee::*, operator::*, verifier::*};
use goat::transactions::{assert::utils::COMMIT_TX_NUM, pre_signed::PreSignedTransaction};
use libp2p::gossipsub::MessageId;
use libp2p::{PeerId, Swarm, gossipsub};
use musig2::{AggNonce, PartialSignature, PubNonce, SecNonce};
use serde::{Deserialize, Serialize};
use store::ipfs::IPFS;
use store::localdb::LocalDB;
use store::{GoatTxProveStatus, GoatTxType, GraphStatus, MessageType};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct GOATMessage {
    pub actor: Actor,
    pub content: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub enum GOATMessageContent {
    CreateInstance(CreateInstance),
    CreateGraphPrepare(CreateGraphPrepare),
    CreateGraph(CreateGraph),
    NonceGeneration(NonceGeneration),
    CommitteePresign(CommitteePresign),
    GraphFinalize(GraphFinalize),
    KickoffReady(KickoffReady),
    KickoffSent(KickoffSent),
    Take1Ready(Take1Ready),
    Take1Sent(Take1Sent),
    ChallengeSent(ChallengeSent),
    AssertSent(AssertSent),
    Take2Ready(Take2Ready),
    Take2Sent(Take2Sent),
    DisproveSent(DisproveSent),
    RequestNodeInfo(NodeInfo),
    ResponseNodeInfo(NodeInfo),
    SyncGraphRequest(SyncGraphRequest),
    SyncGraph(SyncGraph),
    InstanceDiscarded(InstanceDiscarded),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CreateInstance {
    pub instance_id: Uuid,
    pub network: Network,
    pub depositor_evm_address: [u8; 20],
    pub pegin_amount: Amount,
    pub user_inputs: CustomInputs,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CreateGraphPrepare {
    pub instance_id: Uuid,
    pub network: Network,
    pub depositor_evm_address: [u8; 20],
    pub pegin_amount: Amount,
    pub user_inputs: CustomInputs,
    pub committee_member_pubkey: PublicKey,
    pub committee_members_num: usize,
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
    pub pub_nonces: [PubNonce; COMMITTEE_PRE_SIGN_NUM],
    pub committee_members_num: usize,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CommitteePresign {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub committee_pubkey: PublicKey,
    pub committee_partial_sigs: [PartialSignature; COMMITTEE_PRE_SIGN_NUM],
    pub agg_nonces: [AggNonce; COMMITTEE_PRE_SIGN_NUM],
    pub committee_members_num: usize,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GraphFinalize {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub graph: SimplifiedBitvm2Graph,
    pub graph_ipfs_cid: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct KickoffReady {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct KickoffSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub kickoff_txid: Txid,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ChallengeSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub challenge_txid: Txid,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AssertSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub assert_init_txid: Txid,
    pub assert_commit_txids: [Txid; COMMIT_TX_NUM],
    pub assert_final_txid: Txid,
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
    pub take1_txid: Txid,
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
    pub take2_txid: Txid,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DisproveSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub disprove_txid: Txid,
}

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

/// Filter the message and dispatch message to different handlers, like rpc handler, or other peers
///     * database: inner_rpc: Write or Read.
///     * peers: send
#[allow(clippy::too_many_arguments)]
pub async fn recv_and_dispatch(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    ipfs: &IPFS,
    actor: Actor,
    from_peer_id: PeerId,
    id: MessageId,
    message: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut local_message: Vec<u8> = vec![];
    // Tick
    if id == GOATMessage::default_message_id() {
        tracing::debug!("Get the running task, and broadcast the task status or result");
        if actor == Actor::Relayer {
            do_tick_action(swarm, local_db, btc_client, goat_client).await?;
        }
        if let Some(message) = pop_local_unhandle_msg(local_db, actor.clone()).await? {
            local_message = message.clone();
        } else {
            return Ok(());
        }
    }

    if local_message.is_empty() {
        update_node_timestamp(local_db, &from_peer_id.to_string()).await?;
    }

    let message: GOATMessage = if local_message.is_empty() {
        serde_json::from_slice(message)?
    } else {
        tracing::info!("use local message");
        serde_json::from_slice(&local_message)?
    };
    // let message: GOATMessage = serde_json::from_slice(message)?;
    let content: GOATMessageContent = message.to_typed()?;
    match &content {
        // Make logs more readable
        GOATMessageContent::CreateGraph(data) => tracing::info!(
            "Got message: {}:CreateGraph {} with id: {} from peer: {:?}",
            &message.actor.to_string(),
            data.graph_id,
            id,
            from_peer_id
        ),
        GOATMessageContent::GraphFinalize(data) => tracing::info!(
            "Got message: {}:GraphFinalize {}  with id: {} from peer: {:?}",
            &message.actor.to_string(),
            data.graph_id,
            id,
            from_peer_id
        ),
        GOATMessageContent::RequestNodeInfo(_) | GOATMessageContent::ResponseNodeInfo(_) => {
            tracing::debug!(
                "Got message: {}:{} with id: {} from peer: {:?}",
                &message.actor.to_string(),
                String::from_utf8_lossy(&message.content),
                id,
                from_peer_id
            )
        }
        _ => tracing::info!(
            "Got message: {}:{} with id: {} from peer: {:?}",
            &message.actor.to_string(),
            String::from_utf8_lossy(&message.content),
            id,
            from_peer_id
        ),
    }
    // TODO: validate message
    match (content, actor) {
        // pegin
        // CreateInstance sent by bootnode
        (GOATMessageContent::CreateInstance(receive_data), Actor::Committee) => {
            tracing::info!("Handle CreateInstance");
            // TODO: check: user inputs must be segwit addresses
            // TODO: Is it necessary to restrict only relayers to broadcasting CreateInstance?
            // if !validate_actor(&from_peer_id.to_bytes(), Actor::Relayer).await? {
            //     tracing::warn!("receive CreateInstance message but not from Relayer, ignored");
            //     return Ok(());
            // }
            let instance_id = receive_data.instance_id;
            let master_key = CommitteeMasterKey::new(env::get_bitvm_key()?);
            let keypair = master_key.keypair_for_instance(instance_id);
            let message_content = GOATMessageContent::CreateGraphPrepare(CreateGraphPrepare {
                instance_id,
                network: receive_data.network,
                pegin_amount: receive_data.pegin_amount,
                depositor_evm_address: receive_data.depositor_evm_address,
                user_inputs: receive_data.user_inputs,
                committee_member_pubkey: keypair.public_key().into(),
                committee_members_num: env::get_committee_member_num(),
            });
            store_committee_pubkeys(
                local_db,
                receive_data.instance_id,
                keypair.public_key().into(),
            )
            .await?;
            send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
        }
        (GOATMessageContent::CreateGraphPrepare(receive_data), Actor::Operator) => {
            tracing::info!("Handle CreateGraphPrepare");
            if !validate_actor(&from_peer_id.to_bytes(), Actor::Committee).await? {
                tracing::warn!(
                    "receive CreateGraphPrepare message but not from Committee, ignored"
                );
                return Ok(());
            }
            store_committee_pubkeys(
                local_db,
                receive_data.instance_id,
                receive_data.committee_member_pubkey,
            )
            .await?;
            let collected_keys = get_committee_pubkeys(local_db, receive_data.instance_id).await?;
            tracing::info!(
                "instance {}, {}/{} committee-public-key collected",
                receive_data.instance_id,
                collected_keys.len(),
                receive_data.committee_members_num
            );
            if collected_keys.len() == receive_data.committee_members_num
                && should_generate_graph(btc_client, &receive_data).await?
            {
                let graph_id = Uuid::new_v4();
                if try_start_new_graph(receive_data.instance_id, graph_id) {
                    defer!(on_err, {
                        force_stop_current_graph();
                    });
                    tracing::info!("generating new graph: {graph_id}");
                    let master_key = OperatorMasterKey::new(env::get_bitvm_key()?);
                    let keypair = master_key.keypair_for_graph(graph_id);
                    let (_, operator_wots_pubkeys) = master_key.wots_keypair_for_graph(graph_id);
                    let committee_agg_pubkey = key_aggregation(&collected_keys);
                    let disprove_scripts = generate_disprove_scripts(
                        &get_partial_scripts(local_db).await?,
                        &operator_wots_pubkeys,
                    );
                    let operator_inputs = select_operator_inputs(
                        btc_client,
                        get_stake_amount(receive_data.pegin_amount.to_sat()),
                    )
                    .await?
                    .ok_or("operator doesn't have enough fund")?;
                    let params = Bitvm2Parameters {
                        network: receive_data.network,
                        depositor_evm_address: receive_data.depositor_evm_address,
                        pegin_amount: receive_data.pegin_amount,
                        user_inputs: receive_data.user_inputs,
                        stake_amount: get_stake_amount(receive_data.pegin_amount.to_sat()),
                        challenge_amount: get_challenge_amount(receive_data.pegin_amount.to_sat()),
                        committee_pubkeys: collected_keys,
                        committee_agg_pubkey,
                        operator_pubkey: keypair.public_key().into(),
                        operator_wots_pubkeys,
                        operator_inputs,
                    };
                    let mut graph = generate_bitvm_graph(
                        params,
                        disprove_scripts,
                        get_fixed_disprove_output()?,
                    )?;
                    operator_pre_sign(keypair, &mut graph)?;
                    store_graph(
                        local_db,
                        receive_data.instance_id,
                        graph_id,
                        &graph,
                        Some(GraphStatus::OperatorPresigned.to_string()),
                    )
                    .await?;
                    let message_content = GOATMessageContent::CreateGraph(CreateGraph {
                        instance_id: receive_data.instance_id,
                        graph_id,
                        graph: graph.to_simplified(),
                    });
                    // TODO: compress huge message
                    send_to_peer(
                        swarm,
                        GOATMessage::from_typed(Actor::Committee, &message_content)?,
                    )?;
                    dismiss_defer!(on_err);
                };
            };
        }
        (GOATMessageContent::CreateGraph(receive_data), Actor::Committee) => {
            tracing::info!("Handle CreateGraph");
            if !validate_actor(&from_peer_id.to_bytes(), Actor::Operator).await? {
                tracing::warn!(
                    "receive CreateGraph message but not from whitelisted Operator, ignored"
                );
                return Ok(());
            }
            let graph = Bitvm2Graph::from_simplified(receive_data.graph)?;
            store_graph(
                local_db,
                receive_data.instance_id,
                receive_data.graph_id,
                &graph,
                Some(GraphStatus::OperatorPresigned.to_string()),
            )
            .await?;
            let master_key = CommitteeMasterKey::new(env::get_bitvm_key()?);
            let nonces =
                master_key.nonces_for_graph(receive_data.instance_id, receive_data.graph_id);
            let keypair = master_key.keypair_for_instance(receive_data.instance_id);
            let pub_nonces: [PubNonce; COMMITTEE_PRE_SIGN_NUM] =
                std::array::from_fn(|i| nonces[i].1.clone());
            store_committee_pub_nonces(
                local_db,
                receive_data.instance_id,
                receive_data.graph_id,
                keypair.public_key().into(),
                pub_nonces.clone(),
            )
            .await?;
            let committee_members_num = graph.parameters.committee_pubkeys.len();
            let message_content = GOATMessageContent::NonceGeneration(NonceGeneration {
                instance_id: receive_data.instance_id,
                graph_id: receive_data.graph_id,
                committee_pubkey: keypair.public_key().into(),
                pub_nonces,
                committee_members_num,
            });
            send_to_peer(swarm, GOATMessage::from_typed(Actor::Committee, &message_content)?)?;
            let collected_pub_nonces =
                get_committee_pub_nonces(local_db, receive_data.instance_id, receive_data.graph_id)
                    .await?;
            tracing::info!(
                "graph {}, {}/{} committee-pub-nonces-pack collected",
                receive_data.graph_id,
                collected_pub_nonces.len(),
                committee_members_num
            );
            if collected_pub_nonces.len() == committee_members_num {
                let graph = get_bitvm2_graph_from_db(
                    local_db,
                    receive_data.instance_id,
                    receive_data.graph_id,
                )
                .await?;
                let master_key = CommitteeMasterKey::new(env::get_bitvm_key()?);
                let keypair = master_key.keypair_for_instance(receive_data.instance_id);
                let nonces =
                    master_key.nonces_for_graph(receive_data.instance_id, receive_data.graph_id);
                let sec_nonces: [SecNonce; COMMITTEE_PRE_SIGN_NUM] =
                    std::array::from_fn(|i| nonces[i].0.clone());
                let agg_nonces = nonces_aggregation(collected_pub_nonces);
                let committee_partial_sigs =
                    committee_pre_sign(keypair, sec_nonces, agg_nonces.clone(), &graph)?;
                let message_content = GOATMessageContent::CommitteePresign(CommitteePresign {
                    instance_id: receive_data.instance_id,
                    graph_id: receive_data.graph_id,
                    committee_pubkey: keypair.public_key().into(),
                    committee_partial_sigs,
                    agg_nonces,
                    committee_members_num,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::Committee, &message_content)?)?;
            };
        }
        (GOATMessageContent::NonceGeneration(receive_data), Actor::Committee) => {
            tracing::info!("Handle NonceGeneration");
            if !validate_actor(&from_peer_id.to_bytes(), Actor::Committee).await? {
                tracing::warn!("receive NonceGeneration message but not from Committee, ignored");
                return Ok(());
            }
            store_committee_pub_nonces(
                local_db,
                receive_data.instance_id,
                receive_data.graph_id,
                receive_data.committee_pubkey,
                receive_data.pub_nonces,
            )
            .await?;
            let collected_pub_nonces =
                get_committee_pub_nonces(local_db, receive_data.instance_id, receive_data.graph_id)
                    .await?;
            tracing::info!(
                "graph {}, {}/{} committee-pub-nonces-pack collected",
                receive_data.graph_id,
                collected_pub_nonces.len(),
                receive_data.committee_members_num
            );
            if collected_pub_nonces.len() == receive_data.committee_members_num {
                let graph = get_bitvm2_graph_from_db(
                    local_db,
                    receive_data.instance_id,
                    receive_data.graph_id,
                )
                .await?;
                let master_key = CommitteeMasterKey::new(env::get_bitvm_key()?);
                let keypair = master_key.keypair_for_instance(receive_data.instance_id);
                let nonces =
                    master_key.nonces_for_graph(receive_data.instance_id, receive_data.graph_id);
                let sec_nonces: [SecNonce; COMMITTEE_PRE_SIGN_NUM] =
                    std::array::from_fn(|i| nonces[i].0.clone());
                let agg_nonces = nonces_aggregation(collected_pub_nonces);
                let committee_partial_sigs =
                    committee_pre_sign(keypair, sec_nonces, agg_nonces.clone(), &graph)?;
                let message_content = GOATMessageContent::CommitteePresign(CommitteePresign {
                    instance_id: receive_data.instance_id,
                    graph_id: receive_data.graph_id,
                    committee_pubkey: keypair.public_key().into(),
                    committee_partial_sigs,
                    agg_nonces,
                    committee_members_num: receive_data.committee_members_num,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::Operator, &message_content)?)?;
            };
        }
        (GOATMessageContent::CommitteePresign(receive_data), Actor::Operator) => {
            tracing::info!("Handle CommitteePresign");
            if !validate_actor(&from_peer_id.to_bytes(), Actor::Committee).await? {
                tracing::warn!("receive CommitteePresign message but not from Committee, ignored");
                return Ok(());
            }
            if Some((receive_data.instance_id, receive_data.graph_id))
                == statics::current_processing_graph()
            {
                defer!(on_err, {
                    force_stop_current_graph();
                });
                store_committee_partial_sigs(
                    local_db,
                    receive_data.instance_id,
                    receive_data.graph_id,
                    receive_data.committee_pubkey,
                    receive_data.committee_partial_sigs,
                )
                .await?;
                let collected_partial_sigs = get_committee_partial_sigs(
                    local_db,
                    receive_data.instance_id,
                    receive_data.graph_id,
                )
                .await?;
                tracing::info!(
                    "graph {}, {}/{} committee-partial-sigs-pack collected",
                    receive_data.graph_id,
                    collected_partial_sigs.len(),
                    receive_data.committee_members_num
                );
                if collected_partial_sigs.len() == receive_data.committee_members_num {
                    let mut grouped_partial_sigs: [Vec<PartialSignature>; COMMITTEE_PRE_SIGN_NUM] =
                        Default::default();
                    for partial_sigs in collected_partial_sigs {
                        for (i, sig) in partial_sigs.into_iter().enumerate() {
                            grouped_partial_sigs[i].push(sig);
                        }
                    }
                    let mut graph = get_bitvm2_graph_from_db(
                        local_db,
                        receive_data.instance_id,
                        receive_data.graph_id,
                    )
                    .await?;
                    signature_aggregation_and_push(
                        &grouped_partial_sigs,
                        &receive_data.agg_nonces,
                        &mut graph,
                    )?;
                    let prekickoff_tx = graph.pre_kickoff.tx().clone();
                    let prekickoff_txid = prekickoff_tx.compute_txid();
                    let node_keypair =
                        OperatorMasterKey::new(env::get_bitvm_key()?).master_keypair();
                    sign_and_broadcast_prekickoff_tx(btc_client, node_keypair, prekickoff_tx)
                        .await?;
                    tracing::info!("prekickoff sent, txid: {prekickoff_txid}");
                    let graph_ipfs_cid =
                        publish_graph_to_ipfs(ipfs, receive_data.graph_id, &graph).await?;
                    tracing::info!(
                        "graph: {} ipfs-base-url: {graph_ipfs_cid}",
                        receive_data.graph_id
                    );
                    store_graph(
                        local_db,
                        receive_data.instance_id,
                        receive_data.graph_id,
                        &graph,
                        Some(GraphStatus::CommitteePresigned.to_string()),
                    )
                    .await?;
                    update_graph_fields(
                        local_db,
                        receive_data.graph_id,
                        None,
                        Some(graph_ipfs_cid.clone()),
                        None,
                        None,
                        None,
                    )
                    .await?;
                    let message_content = GOATMessageContent::GraphFinalize(GraphFinalize {
                        instance_id: receive_data.instance_id,
                        graph_id: receive_data.graph_id,
                        graph: graph.to_simplified(),
                        graph_ipfs_cid,
                    });
                    send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
                    force_stop_current_graph();
                };
                dismiss_defer!(on_err);
            };
        }
        (GOATMessageContent::GraphFinalize(receive_data), _) => {
            tracing::info!("Handle GraphFinalize");
            if !validate_actor(&from_peer_id.to_bytes(), Actor::Operator).await? {
                tracing::warn!(
                    "receive GraphFinalize message but not from whitelisted Operator, ignored"
                );
                return Ok(());
            }
            // TODO: validate graph & ipfs
            let graph = Bitvm2Graph::from_simplified(receive_data.graph)?;
            store_graph(
                local_db,
                receive_data.instance_id,
                receive_data.graph_id,
                &graph,
                Some(GraphStatus::CommitteePresigned.to_string()),
            )
            .await?;
            update_graph_fields(
                local_db,
                receive_data.graph_id,
                None,
                Some(receive_data.graph_ipfs_cid.clone()),
                None,
                None,
                None,
            )
            .await?;
        }

        // peg-out
        // KickoffReady sent by relayer
        (GOATMessageContent::KickoffReady(receive_data), Actor::Operator) => {
            tracing::info!("Handle KickoffReady");
            let status_op = sync_graph_without_waiting(
                swarm,
                local_db,
                receive_data.instance_id,
                receive_data.graph_id,
            )
            .await?;
            if status_op.is_none() {
                tracing::info!(
                    "save unhandle KickoffReady: graph_id: {} into db, will be hanlded later",
                    receive_data.graph_id,
                );
                let message_content = GOATMessageContent::KickoffReady(receive_data.clone());
                let message = GOATMessage::from_typed(Actor::Operator, &message_content)?;
                save_unhandle_message(
                    local_db,
                    &from_peer_id.to_string(),
                    &Actor::Operator.to_string(),
                    &MessageType::KickoffReady.to_string(),
                    serde_json::to_vec(&message)?,
                )
                .await?;
                return Ok(());
            }
            if let Some(graph_status) = status_op
                && ![GraphStatus::CommitteePresigned, GraphStatus::OperatorDataPushed]
                    .contains(&graph_status)
            {
                tracing::warn!(
                    "receive KickoffReady but currently in {graph_status} Status, ignored"
                );
                return Ok(());
            }
            let mut graph =
                get_bitvm2_graph_from_db(local_db, receive_data.instance_id, receive_data.graph_id)
                    .await?;
            let master_key = OperatorMasterKey::new(env::get_bitvm_key()?);
            let keypair = master_key.keypair_for_graph(receive_data.graph_id);
            let operator_graph_pubkey: PublicKey = keypair.public_key().into();
            if graph.parameters.operator_pubkey == operator_graph_pubkey {
                tracing::info!("Handle KickoffReady");
                if is_withdraw_initialized_on_l2(
                    goat_client,
                    receive_data.instance_id,
                    receive_data.graph_id,
                )
                .await?
                {
                    tracing::info!("sending Kickoff ...");
                    let master_key = OperatorMasterKey::new(env::get_bitvm_key()?);
                    let keypair = master_key.keypair_for_graph(receive_data.graph_id);
                    let (operator_wots_seckeys, operator_wots_pubkeys) =
                        master_key.wots_keypair_for_graph(receive_data.graph_id);
                    let mut kickoff_commit_data = [0u8; 32];
                    kickoff_commit_data[..16].copy_from_slice(receive_data.instance_id.as_bytes());
                    kickoff_commit_data[16..].copy_from_slice(receive_data.graph_id.as_bytes());
                    let kickoff_tx = operator_sign_kickoff(
                        keypair,
                        &mut graph,
                        &operator_wots_seckeys,
                        &operator_wots_pubkeys,
                        kickoff_commit_data,
                    )?;
                    broadcast_tx(btc_client, &kickoff_tx).await?;
                    tracing::info!("kickoff sent, txid: {}", kickoff_tx.compute_txid().to_string());
                    // malicious Operator may not broadcast kickoff to the p2p network
                    // Relayer will monitor all graphs & broadcast KickoffSent
                }
            }
        }
        // KickoffSent sent by relayer
        (GOATMessageContent::KickoffSent(receive_data), Actor::Challenger) => {
            tracing::info!("Handle KickoffSent");
            let status_op = sync_graph_without_waiting(
                swarm,
                local_db,
                receive_data.instance_id,
                receive_data.graph_id,
            )
            .await?;
            if status_op.is_none() {
                tracing::info!(
                    "save unhandle KickoffSent: graph_id: {} into db, will be hanlded later",
                    receive_data.graph_id,
                );
                let message_content = GOATMessageContent::KickoffSent(receive_data.clone());
                let message = GOATMessage::from_typed(Actor::Challenger, &message_content)?;
                save_unhandle_message(
                    local_db,
                    &from_peer_id.to_string(),
                    &Actor::Challenger.to_string(),
                    &MessageType::KickoffSent.to_string(),
                    serde_json::to_vec(&message)?,
                )
                .await?;
                return Ok(());
            }
            if let Some(graph_status) = status_op
                && ![
                    GraphStatus::CommitteePresigned,
                    GraphStatus::OperatorDataPushed,
                    GraphStatus::KickOff,
                ]
                .contains(&graph_status)
            {
                tracing::warn!(
                    "receive KickoffSent for graph {} but currently in {graph_status} Status, ignored",
                    receive_data.graph_id
                );
                return Ok(());
            }
            let mut graph =
                get_bitvm2_graph_from_db(local_db, receive_data.instance_id, receive_data.graph_id)
                    .await?;
            if should_challenge(
                btc_client,
                goat_client,
                Amount::from_sat(graph.challenge.min_crowdfunding_amount()),
                receive_data.instance_id,
                receive_data.graph_id,
                &graph.kickoff.tx().compute_txid(),
            )
            .await?
            {
                tracing::info!("sending Challenge ...");
                let (challenge_tx, _challenge_amount) = export_challenge_tx(&mut graph)?;
                let node_keypair = ChallengerMasterKey::new(env::get_bitvm_key()?).master_keypair();
                let challenge_txid = complete_and_broadcast_challenge_tx(
                    btc_client,
                    node_keypair,
                    challenge_tx,
                    // challenge_amount,
                )
                .await?;
                tracing::info!("challenge sent, txid: {}", challenge_txid.to_string());
                let _ = wait_tx_confirmation(btc_client, &challenge_txid, 2, 300).await;
                let message_content = GOATMessageContent::ChallengeSent(ChallengeSent {
                    instance_id: receive_data.instance_id,
                    graph_id: receive_data.graph_id,
                    challenge_txid,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
                update_graph_fields(
                    local_db,
                    receive_data.graph_id,
                    Some(GraphStatus::Challenge.to_string()),
                    None,
                    None,
                    None,
                    None,
                )
                .await?;
            } else {
                update_graph_fields(
                    local_db,
                    receive_data.graph_id,
                    Some(GraphStatus::KickOff.to_string()),
                    None,
                    None,
                    None,
                    Some(current_time_secs()),
                )
                .await?;
            }
        }
        // Take1Ready sent by relayer
        (GOATMessageContent::Take1Ready(receive_data), Actor::Operator) => {
            tracing::info!("Handle Take1Ready");
            let status_op = sync_graph_without_waiting(
                swarm,
                local_db,
                receive_data.instance_id,
                receive_data.graph_id,
            )
            .await?;
            if status_op.is_none() {
                tracing::info!(
                    "save unhandle Take1Ready: graph_id: {} into db, will be hanlded later",
                    receive_data.graph_id,
                );
                let message_content = GOATMessageContent::Take1Ready(receive_data.clone());
                let message = GOATMessage::from_typed(Actor::Operator, &message_content)?;
                save_unhandle_message(
                    local_db,
                    &from_peer_id.to_string(),
                    &Actor::Operator.to_string(),
                    &MessageType::Take1Ready.to_string(),
                    serde_json::to_vec(&message)?,
                )
                .await?;
                return Ok(());
            }
            if let Some(graph_status) = status_op
                && ![
                    GraphStatus::CommitteePresigned,
                    GraphStatus::OperatorDataPushed,
                    GraphStatus::KickOff,
                ]
                .contains(&graph_status)
            {
                tracing::warn!(
                    "receive Take1Ready for graph {}, but currently in {graph_status} Status, ignored",
                    receive_data.graph_id
                );
                return Ok(());
            }
            let mut graph =
                get_bitvm2_graph_from_db(local_db, receive_data.instance_id, receive_data.graph_id)
                    .await?;
            let master_key = OperatorMasterKey::new(env::get_bitvm_key()?);
            let keypair = master_key.keypair_for_graph(receive_data.graph_id);
            let operator_graph_pubkey: PublicKey = keypair.public_key().into();
            if graph.parameters.operator_pubkey == operator_graph_pubkey {
                tracing::info!("Handle Take1Ready");
                if !is_valid_withdraw(goat_client, receive_data.instance_id, receive_data.graph_id)
                    .await?
                {
                    tracing::warn!(
                        "receive Take1Ready for graph {}, but kickoff is invalid, ignored",
                        receive_data.graph_id
                    );
                    return Ok(());
                }
                if is_take1_timelock_expired(btc_client, graph.kickoff.tx().compute_txid()).await? {
                    tracing::info!("sending Take1 ...");
                    let master_key = OperatorMasterKey::new(env::get_bitvm_key()?);
                    let keypair = master_key.keypair_for_graph(receive_data.graph_id);
                    let take1_tx = operator_sign_take1(keypair, &mut graph)?;
                    let take1_txid = take1_tx.compute_txid();
                    broadcast_tx(btc_client, &take1_tx).await?;
                    tracing::info!("take1 sent, txid: {}", take1_txid.to_string());
                    let _ = wait_tx_confirmation(btc_client, &take1_txid, 2, 300).await;
                    let message_content = GOATMessageContent::Take1Sent(Take1Sent {
                        instance_id: receive_data.instance_id,
                        graph_id: receive_data.graph_id,
                        take1_txid,
                    });
                    send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
                    update_graph_fields(
                        local_db,
                        receive_data.graph_id,
                        Some(GraphStatus::Take1.to_string()),
                        None,
                        None,
                        None,
                        None,
                    )
                    .await?;
                    obsolete_sibling_graphs(
                        local_db,
                        receive_data.instance_id,
                        receive_data.graph_id,
                    )
                    .await?;
                }
            }
        }
        // ChallengeSent sent by challenger
        // if challenger
        (GOATMessageContent::ChallengeSent(receive_data), Actor::Operator) => {
            tracing::info!("Handle ChallengeSent");
            let status_op = sync_graph_without_waiting(
                swarm,
                local_db,
                receive_data.instance_id,
                receive_data.graph_id,
            )
            .await?;
            if status_op.is_none() {
                tracing::info!(
                    "save unhandle ChallengeSent: graph_id: {} into db, will be hanlded later",
                    receive_data.graph_id,
                );
                let message_content = GOATMessageContent::ChallengeSent(receive_data.clone());
                let message = GOATMessage::from_typed(Actor::Operator, &message_content)?;
                save_unhandle_message(
                    local_db,
                    &from_peer_id.to_string(),
                    &Actor::Operator.to_string(),
                    &MessageType::ChallengeSent.to_string(),
                    serde_json::to_vec(&message)?,
                )
                .await?;
                return Ok(());
            }
            if let Some(graph_status) = status_op
                && ![
                    GraphStatus::CommitteePresigned,
                    GraphStatus::OperatorDataPushed,
                    GraphStatus::KickOff,
                    GraphStatus::Challenge,
                ]
                .contains(&graph_status)
            {
                tracing::warn!(
                    "receive ChallengeSent for graph {} but currently in {graph_status} Status, ignored",
                    receive_data.graph_id
                );
                return Ok(());
            }
            let mut graph =
                get_bitvm2_graph_from_db(local_db, receive_data.instance_id, receive_data.graph_id)
                    .await?;
            if graph.parameters.operator_pubkey == env::get_node_pubkey()?
                && validate_challenge(
                    btc_client,
                    &graph.kickoff.tx().compute_txid(),
                    &receive_data.challenge_txid,
                )
                .await?
            {
                tracing::info!("Handle ChallengeSent");
                tracing::info!("sending Assert ...");
                let master_key = OperatorMasterKey::new(env::get_bitvm_key()?);
                let keypair = master_key.keypair_for_graph(receive_data.graph_id);
                let (operator_wots_seckeys, operator_wots_pubkeys) =
                    master_key.wots_keypair_for_graph(receive_data.graph_id);
                let (proof, pubin, vk) = get_groth16_proof(
                    local_db,
                    &receive_data.instance_id,
                    &receive_data.graph_id,
                    serialize_hex(&receive_data.challenge_txid),
                )
                .await?;
                let mut proof_sigs = sign_proof(&vk, proof, pubin, &operator_wots_seckeys);
                if !is_valid_withdraw(goat_client, receive_data.instance_id, receive_data.graph_id)
                    .await?
                {
                    // if kickoff is invalid, operator should not be able to generate a valid groth proof
                    // TODO: replace mock proof with proof from ProofNetwork so that corrupt is not needed
                    tracing::warn!(
                        "graph {}, kickoff is invalid, generating fake proof...",
                        receive_data.graph_id
                    );
                    corrupt_proof(&mut proof_sigs, &operator_wots_seckeys.1, 8);
                }
                let (assert_init_tx, assert_commit_txns, assert_final_tx) =
                    operator_sign_assert(keypair, &mut graph, &operator_wots_pubkeys, proof_sigs)?;
                if !tx_on_chain(btc_client, &assert_init_tx.compute_txid()).await? {
                    tracing::info!("sending Assert-Init {} ...", assert_init_tx.compute_txid());
                    broadcast_tx(btc_client, &assert_init_tx).await?;
                }
                wait_tx_confirmation(btc_client, &assert_init_tx.compute_txid(), 5, 1800).await?;
                for tx in &assert_commit_txns {
                    let txid = tx.compute_txid();
                    if !tx_on_chain(btc_client, &txid).await? {
                        tracing::info!("sending Assert-Commit {txid} ...");
                        broadcast_tx(btc_client, tx).await?;
                    }
                }
                wait_tx_confirmation(btc_client, &assert_commit_txns[0].compute_txid(), 5, 900)
                    .await?;
                wait_tx_confirmation(btc_client, &assert_commit_txns[1].compute_txid(), 5, 900)
                    .await?;
                wait_tx_confirmation(btc_client, &assert_commit_txns[2].compute_txid(), 5, 900)
                    .await?;
                wait_tx_confirmation(btc_client, &assert_commit_txns[3].compute_txid(), 5, 900)
                    .await?;
                if !tx_on_chain(btc_client, &assert_final_tx.compute_txid()).await? {
                    tracing::info!("sending Assert-Final {} ...", assert_init_tx.compute_txid());
                    broadcast_tx(btc_client, &assert_final_tx).await?;
                }
                update_graph_fields(
                    local_db,
                    receive_data.graph_id,
                    Some(GraphStatus::Assert.to_string()),
                    None,
                    Some(serialize_hex(&receive_data.challenge_txid)),
                    None,
                    None,
                )
                .await?;
                // malicious Operator may not broadcast assert to the p2p network
                // Relayer will monitor all graphs & broadcast AssertSent
            }
        }
        // Take2Ready sent by relayer
        (GOATMessageContent::Take2Ready(receive_data), Actor::Operator) => {
            tracing::info!("Handle Take2Ready");
            let status_op = sync_graph_without_waiting(
                swarm,
                local_db,
                receive_data.instance_id,
                receive_data.graph_id,
            )
            .await?;
            if status_op.is_none() {
                tracing::info!(
                    "save unhandle Take2Ready: graph_id: {} into db, will be hanlded later",
                    receive_data.graph_id,
                );
                let message_content = GOATMessageContent::Take2Ready(receive_data.clone());
                let message = GOATMessage::from_typed(Actor::Operator, &message_content)?;
                save_unhandle_message(
                    local_db,
                    &from_peer_id.to_string(),
                    &Actor::Operator.to_string(),
                    &MessageType::Take2Ready.to_string(),
                    serde_json::to_vec(&message)?,
                )
                .await?;
                return Ok(());
            }
            let mut graph =
                get_bitvm2_graph_from_db(local_db, receive_data.instance_id, receive_data.graph_id)
                    .await?;
            let master_key = OperatorMasterKey::new(env::get_bitvm_key()?);
            let keypair = master_key.keypair_for_graph(receive_data.graph_id);
            let operator_graph_pubkey: PublicKey = keypair.public_key().into();
            if graph.parameters.operator_pubkey == operator_graph_pubkey {
                tracing::info!("Handle Take2Ready");
                if !is_valid_withdraw(goat_client, receive_data.instance_id, receive_data.graph_id)
                    .await?
                {
                    tracing::warn!(
                        "receive Take2Ready for graph {}, but kickoff is invalid, ignored",
                        receive_data.graph_id
                    );
                    return Ok(());
                }
                if is_take2_timelock_expired(btc_client, graph.assert_final.tx().compute_txid())
                    .await?
                {
                    let master_key = OperatorMasterKey::new(env::get_bitvm_key()?);
                    let keypair = master_key.keypair_for_graph(receive_data.graph_id);
                    let take2_tx = operator_sign_take2(keypair, &mut graph)?;
                    let take2_txid = take2_tx.compute_txid();
                    broadcast_tx(btc_client, &take2_tx).await?;
                    tracing::info!("take2 sent, txid: {}", take2_txid.to_string());
                    let _ = wait_tx_confirmation(btc_client, &take2_txid, 2, 300).await;
                    let message_content = GOATMessageContent::Take2Sent(Take2Sent {
                        instance_id: receive_data.instance_id,
                        graph_id: receive_data.graph_id,
                        take2_txid,
                    });
                    send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
                    update_graph_fields(
                        local_db,
                        receive_data.graph_id,
                        Some(GraphStatus::Take2.to_string()),
                        None,
                        None,
                        None,
                        None,
                    )
                    .await?;
                    obsolete_sibling_graphs(
                        local_db,
                        receive_data.instance_id,
                        receive_data.graph_id,
                    )
                    .await?;
                }
            }
        }
        // AssertSent sent by relayer
        (GOATMessageContent::AssertSent(receive_data), Actor::Challenger) => {
            tracing::info!("Handle AssertSent");
            let status_op = sync_graph_without_waiting(
                swarm,
                local_db,
                receive_data.instance_id,
                receive_data.graph_id,
            )
            .await?;
            if status_op.is_none() {
                tracing::info!(
                    "save unhandle AssertSent: graph_id: {} into db, will be hanlded later",
                    receive_data.graph_id,
                );
                let message_content = GOATMessageContent::AssertSent(receive_data.clone());
                let message = GOATMessage::from_typed(Actor::Challenger, &message_content)?;
                save_unhandle_message(
                    local_db,
                    &from_peer_id.to_string(),
                    &Actor::Challenger.to_string(),
                    &MessageType::AssertSent.to_string(),
                    serde_json::to_vec(&message)?,
                )
                .await?;
                return Ok(());
            }
            if let Some(graph_status) = status_op
                && [GraphStatus::Take2, GraphStatus::Disprove].contains(&graph_status)
            {
                tracing::warn!(
                    "receive AssertSent for graph {} but currently in {graph_status} Status, ignored",
                    receive_data.graph_id
                );
                return Ok(());
            }
            let mut graph =
                get_bitvm2_graph_from_db(local_db, receive_data.instance_id, receive_data.graph_id)
                    .await?;
            if let Some(disprove_witness) = validate_assert(
                local_db,
                btc_client,
                &receive_data.assert_commit_txids,
                graph.parameters.operator_wots_pubkeys.clone(),
            )
            .await?
            {
                tracing::info!("sending Disprove ...");
                let disprove_scripts = generate_disprove_scripts(
                    &get_partial_scripts(local_db).await?,
                    &graph.parameters.operator_wots_pubkeys,
                );
                let assert_wots_pubkeys = graph.parameters.operator_wots_pubkeys.1.clone();
                let fee_rate = get_fee_rate(btc_client).await?;
                let disprove_tx = sign_disprove(
                    &mut graph,
                    disprove_witness,
                    disprove_scripts,
                    &assert_wots_pubkeys,
                    get_node_goat_address().map(|a| a.0.0),
                    Some(disprove_reward_address()?),
                    fee_rate,
                )?;
                let disprove_txid = disprove_tx.compute_txid();
                let _ = wait_tx_confirmation(
                    btc_client,
                    &graph.assert_final.tx().compute_txid(),
                    5,
                    600,
                )
                .await;
                broadcast_tx(btc_client, &disprove_tx).await?;
                let _ = wait_tx_confirmation(btc_client, &disprove_txid, 2, 300).await;
                let message_content = GOATMessageContent::DisproveSent(DisproveSent {
                    instance_id: receive_data.instance_id,
                    graph_id: receive_data.graph_id,
                    disprove_txid,
                });
                tracing::info!("disprove sent, txid: {}", disprove_txid.to_string());
                send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
                update_graph_fields(
                    local_db,
                    receive_data.graph_id,
                    Some(GraphStatus::Disprove.to_string()),
                    None,
                    None,
                    None,
                    None,
                )
                .await?;
            } else {
                tracing::info!("nothing to Disprove.");
            }
        }

        // Relayer handles
        (GOATMessageContent::Take1Sent(receive_data), Actor::Relayer) => {
            tracing::info!("Handle Take1Sent");
            let graph =
                get_bitvm2_graph_from_db(local_db, receive_data.instance_id, receive_data.graph_id)
                    .await?;
            let take1_txid = graph.take1.tx().compute_txid();
            if tx_on_chain(btc_client, &take1_txid).await? {
                let tx_hash = finish_withdraw_happy_path(
                    btc_client,
                    goat_client,
                    &receive_data.graph_id,
                    graph.take1.tx(),
                )
                .await?;
                create_goat_tx_record(
                    local_db,
                    goat_client,
                    receive_data.graph_id,
                    receive_data.instance_id,
                    &tx_hash,
                    GoatTxType::WithdrawHappyPath,
                    GoatTxProveStatus::NoNeed.to_string(),
                )
                .await?;
                update_graph_fields(
                    local_db,
                    receive_data.graph_id,
                    Some(GraphStatus::Take1.to_string()),
                    None,
                    None,
                    None,
                    None,
                )
                .await?;
                obsolete_sibling_graphs(local_db, receive_data.instance_id, receive_data.graph_id)
                    .await?;
            }
        }
        (GOATMessageContent::Take2Sent(receive_data), Actor::Relayer) => {
            tracing::info!("Handle Take2Sent");
            let graph =
                get_bitvm2_graph_from_db(local_db, receive_data.instance_id, receive_data.graph_id)
                    .await?;
            if tx_on_chain(btc_client, &graph.take2.tx().compute_txid()).await? {
                let tx_hash = finish_withdraw_unhappy_path(
                    btc_client,
                    goat_client,
                    &receive_data.graph_id,
                    graph.take2.tx(),
                )
                .await?;
                create_goat_tx_record(
                    local_db,
                    goat_client,
                    receive_data.graph_id,
                    receive_data.instance_id,
                    &tx_hash,
                    GoatTxType::WithdrawUnhappyPath,
                    GoatTxProveStatus::NoNeed.to_string(),
                )
                .await?;
                update_graph_fields(
                    local_db,
                    receive_data.graph_id,
                    Some(GraphStatus::Take2.to_string()),
                    None,
                    None,
                    None,
                    None,
                )
                .await?;
                obsolete_sibling_graphs(local_db, receive_data.instance_id, receive_data.graph_id)
                    .await?;
            }
        }
        (GOATMessageContent::DisproveSent(receive_data), Actor::Relayer) => {
            tracing::info!("Handle DisproveSent");
            let graph =
                get_graph(local_db, Some(receive_data.instance_id), receive_data.graph_id).await?;

            if graph.challenge_txid.is_none() || graph.assert_final_txid.is_none() {
                tracing::warn!(
                    "graph_id:{} challenge tx is none or assert final txid is none",
                    receive_data.graph_id
                );
                return Err(format!(
                    "graph_id:{} challenge tx is none or assert final txid is none",
                    receive_data.graph_id
                )
                .into());
            }

            if validate_disprove(
                btc_client,
                &deserialize_hex(&graph.assert_final_txid.expect("finial assert txid is none"))?,
                &receive_data.disprove_txid,
            )
            .await?
            {
                update_graph_fields(
                    local_db,
                    receive_data.graph_id,
                    None,
                    None,
                    None,
                    Some(serialize_hex(&receive_data.disprove_txid)),
                    None,
                )
                .await?;
                let tx_hash = finish_withdraw_disproved(
                    btc_client,
                    goat_client,
                    &receive_data.graph_id,
                    &btc_client.fetch_btc_tx(&receive_data.disprove_txid).await?,
                    &btc_client
                        .fetch_btc_tx(&deserialize_hex(
                            &graph.challenge_txid.expect("challenge txid is none"),
                        )?)
                        .await?,
                )
                .await?;
                create_goat_tx_record(
                    local_db,
                    goat_client,
                    receive_data.graph_id,
                    receive_data.instance_id,
                    &tx_hash,
                    GoatTxType::WithdrawDisproved,
                    GoatTxProveStatus::NoNeed.to_string(),
                )
                .await?;
                update_graph_fields(
                    local_db,
                    receive_data.graph_id,
                    Some(GraphStatus::Disprove.to_string()),
                    None,
                    None,
                    None,
                    None,
                )
                .await?;

                // NOTE: clean up other graphs?
            }
        }

        // Operator recycle prekickoff utxo
        (GOATMessageContent::Take1Sent(receive_data), Actor::Operator) => {
            tracing::info!("Handle Take1Sent");
            let status_op = sync_graph_without_waiting(
                swarm,
                local_db,
                receive_data.instance_id,
                receive_data.graph_id,
            )
            .await?;
            if status_op.is_none() {
                tracing::info!(
                    "save unhandle Take1Sent: graph_id: {} into db, will be hanlded later",
                    receive_data.graph_id,
                );
                let message_content = GOATMessageContent::Take1Sent(receive_data.clone());
                let message = GOATMessage::from_typed(Actor::Operator, &message_content)?;
                save_unhandle_message(
                    local_db,
                    &from_peer_id.to_string(),
                    &Actor::Operator.to_string(),
                    &MessageType::Take1Sent.to_string(),
                    serde_json::to_vec(&message)?,
                )
                .await?;
                return Ok(());
            }
            let graph =
                get_bitvm2_graph_from_db(local_db, receive_data.instance_id, receive_data.graph_id)
                    .await?;
            if tx_on_chain(btc_client, &graph.take1.tx().compute_txid()).await? {
                if let Some(graph_status) = status_op
                    && graph_status != GraphStatus::Take1
                {
                    update_graph_fields(
                        local_db,
                        receive_data.graph_id,
                        Some(GraphStatus::Take1.to_string()),
                        None,
                        None,
                        None,
                        None,
                    )
                    .await?;
                }
                if let Some(graph_id) = get_my_graph_for_instance(
                    goat_client,
                    receive_data.instance_id,
                    get_node_pubkey()?,
                )
                .await?
                {
                    let status_op = sync_graph_without_waiting(
                        swarm,
                        local_db,
                        receive_data.instance_id,
                        graph_id,
                    )
                    .await?;
                    if status_op.is_none() {
                        tracing::info!(
                            "save unhandle Take1Sent: graph_id: {} into db, will be hanlded later",
                            receive_data.graph_id,
                        );
                        let message_content = GOATMessageContent::Take1Sent(receive_data.clone());
                        let message = GOATMessage::from_typed(Actor::Operator, &message_content)?;
                        save_unhandle_message(
                            local_db,
                            &from_peer_id.to_string(),
                            &Actor::Operator.to_string(),
                            &MessageType::Take1Sent.to_string(),
                            serde_json::to_vec(&message)?,
                        )
                        .await?;
                        return Ok(());
                    }
                    let graph =
                        get_bitvm2_graph_from_db(local_db, receive_data.instance_id, graph_id)
                            .await?;
                    let prekickoff_txid = graph.pre_kickoff.tx().compute_txid();
                    if outpoint_available(btc_client, &prekickoff_txid, 0).await? {
                        tracing::info!(
                            "recycle btc, instance_id: {}, graph: {graph_id} , pre_kickoff: {prekickoff_txid}",
                            receive_data.instance_id
                        );
                        recycle_prekickoff_tx(
                            btc_client,
                            graph_id,
                            OperatorMasterKey::new(env::get_bitvm_key()?),
                            prekickoff_txid,
                        )
                        .await?;
                    }
                }
                obsolete_sibling_graphs(local_db, receive_data.instance_id, receive_data.graph_id)
                    .await?;
            }
        }
        (GOATMessageContent::Take2Sent(receive_data), Actor::Operator) => {
            tracing::info!("Handle Take2Sent");
            let status_op = sync_graph_without_waiting(
                swarm,
                local_db,
                receive_data.instance_id,
                receive_data.graph_id,
            )
            .await?;
            if status_op.is_none() {
                tracing::info!(
                    "save unhandle Take2Sent: graph_id: {} into db, will be hanlded later",
                    receive_data.graph_id,
                );
                let message_content = GOATMessageContent::Take2Sent(receive_data.clone());
                let message = GOATMessage::from_typed(Actor::Operator, &message_content)?;
                save_unhandle_message(
                    local_db,
                    &from_peer_id.to_string(),
                    &Actor::Operator.to_string(),
                    &MessageType::Take2Sent.to_string(),
                    serde_json::to_vec(&message)?,
                )
                .await?;
                return Ok(());
            }
            let graph =
                get_bitvm2_graph_from_db(local_db, receive_data.instance_id, receive_data.graph_id)
                    .await?;
            if tx_on_chain(btc_client, &graph.take2.tx().compute_txid()).await? {
                if let Some(graph_status) = status_op
                    && graph_status != GraphStatus::Take2
                {
                    update_graph_fields(
                        local_db,
                        receive_data.graph_id,
                        Some(GraphStatus::Take2.to_string()),
                        None,
                        None,
                        None,
                        None,
                    )
                    .await?;
                }
                if let Some(graph_id) = get_my_graph_for_instance(
                    goat_client,
                    receive_data.instance_id,
                    get_node_pubkey()?,
                )
                .await?
                {
                    let status_op = sync_graph_without_waiting(
                        swarm,
                        local_db,
                        receive_data.instance_id,
                        graph_id,
                    )
                    .await?;
                    if status_op.is_none() {
                        tracing::info!(
                            "save unhandle Take2Sent: graph_id: {} into db, will be hanlded later",
                            receive_data.graph_id,
                        );
                        let message_content = GOATMessageContent::Take2Sent(receive_data.clone());
                        let message = GOATMessage::from_typed(Actor::Operator, &message_content)?;
                        save_unhandle_message(
                            local_db,
                            &from_peer_id.to_string(),
                            &Actor::Operator.to_string(),
                            &MessageType::Take2Sent.to_string(),
                            serde_json::to_vec(&message)?,
                        )
                        .await?;
                        return Ok(());
                    }
                    let graph =
                        get_bitvm2_graph_from_db(local_db, receive_data.instance_id, graph_id)
                            .await?;
                    let prekickoff_txid = graph.pre_kickoff.tx().compute_txid();
                    if outpoint_available(btc_client, &prekickoff_txid, 0).await? {
                        tracing::info!(
                            "recycle btc, instance_id: {}, graph: {graph_id} , pre_kickoff: {prekickoff_txid}",
                            receive_data.instance_id
                        );
                        recycle_prekickoff_tx(
                            btc_client,
                            graph_id,
                            OperatorMasterKey::new(env::get_bitvm_key()?),
                            prekickoff_txid,
                        )
                        .await?;
                    }
                }
                obsolete_sibling_graphs(local_db, receive_data.instance_id, receive_data.graph_id)
                    .await?;
            }
        }

        (GOATMessageContent::InstanceDiscarded(receive_data), Actor::Operator) => {
            tracing::info!("Handle InstanceDiscarded:{:?}", receive_data.graph_infos);
            // recycle btc
            let master_key = OperatorMasterKey::new(env::get_bitvm_key()?);
            let mut handle_graph_ids: Vec<Uuid> = vec![];
            let mut unhandle_graph_info: Vec<(Uuid, Uuid, String)> = vec![];
            for (graph_id, instance_id, operator) in receive_data.graph_infos {
                let operator_graph_pubkey: PublicKey =
                    master_key.keypair_for_graph(graph_id).public_key().into();
                if operator != operator_graph_pubkey.to_string() {
                    tracing::info!("graph :{graph_id} not local graph, no need to recycle",);
                    handle_graph_ids.push(graph_id);
                    continue;
                }

                let status_op =
                    sync_graph_without_waiting(swarm, local_db, instance_id, graph_id).await?;
                if status_op.is_none() {
                    tracing::info!(
                        "start sync graph at graph_id:{graph_id}, instance_id:{instance_id}"
                    );
                    unhandle_graph_info.push((graph_id, instance_id, operator));
                    continue;
                }
                if let Some(status) = status_op
                    && status != GraphStatus::CommitteePresigned
                {
                    tracing::info!(
                        "start sync graph at graph_id:{graph_id}, instance_id:{instance_id}, status is {status}, neq CommitteePresigned"
                    );
                    handle_graph_ids.push(graph_id);
                    continue;
                }
                let graph = get_bitvm2_graph_from_db(local_db, instance_id, graph_id).await?;
                let prekickoff_txid = graph.pre_kickoff.tx().compute_txid();
                if outpoint_available(btc_client, &prekickoff_txid, 0).await? {
                    tracing::info!(
                        "recycle btc,  graph: {graph_id} , pre_kickoff: {prekickoff_txid}",
                    );
                    recycle_prekickoff_tx(
                        btc_client,
                        graph_id,
                        OperatorMasterKey::new(env::get_bitvm_key()?),
                        prekickoff_txid,
                    )
                    .await?;
                    handle_graph_ids.push(graph_id);
                }
            }

            for graph_id in handle_graph_ids {
                update_graph_fields(
                    local_db,
                    graph_id,
                    Some(GraphStatus::Discarded.to_string()),
                    None,
                    None,
                    None,
                    None,
                )
                .await?;
            }

            if !unhandle_graph_info.is_empty() {
                tracing::info!(
                    "save unhandle graph info {unhandle_graph_info:?} into db, will be hanlded later"
                );
                let message_content = GOATMessageContent::InstanceDiscarded(InstanceDiscarded {
                    graph_infos: unhandle_graph_info,
                });
                let message = GOATMessage::from_typed(Actor::Operator, &message_content)?;
                save_unhandle_message(
                    local_db,
                    &from_peer_id.to_string(),
                    &Actor::Operator.to_string(),
                    &MessageType::InstanceDiscarded.to_string(),
                    serde_json::to_vec(&message)?,
                )
                .await?;
            }
        }

        // Other participants update graph status
        (GOATMessageContent::KickoffSent(receive_data), _) => {
            tracing::info!("Handle KickoffSent");
            let status_op = sync_graph_without_waiting(
                swarm,
                local_db,
                receive_data.instance_id,
                receive_data.graph_id,
            )
            .await?;
            if status_op.is_none() {
                tracing::info!(
                    "KickoffSent: graph {} not found in local database. Skipping update and waiting for sync from other nodes.",
                    receive_data.graph_id,
                );
                return Ok(());
            }
            if let Some(graph_status) = status_op
                && ![GraphStatus::CommitteePresigned, GraphStatus::OperatorDataPushed]
                    .contains(&graph_status)
            {
                tracing::warn!(
                    "receive KickoffSent for graph {} but currently in {graph_status} Status, ignored",
                    receive_data.graph_id
                );
                return Ok(());
            }
            let graph =
                get_bitvm2_graph_from_db(local_db, receive_data.instance_id, receive_data.graph_id)
                    .await?;
            if tx_on_chain(btc_client, &graph.kickoff.tx().compute_txid()).await? {
                update_graph_fields(
                    local_db,
                    receive_data.graph_id,
                    Some(GraphStatus::KickOff.to_string()),
                    None,
                    None,
                    None,
                    None,
                )
                .await?;
            }
        }
        (GOATMessageContent::ChallengeSent(receive_data), _) => {
            tracing::info!("Handle ChallengeSent");
            let status_op = sync_graph_without_waiting(
                swarm,
                local_db,
                receive_data.instance_id,
                receive_data.graph_id,
            )
            .await?;
            if status_op.is_none() {
                tracing::info!(
                    "ChallengeSent: graph {} not found in local database. Skipping update and waiting for sync from other nodes.",
                    receive_data.graph_id,
                );
                return Ok(());
            }
            if let Some(graph_status) = status_op
                && ![
                    GraphStatus::CommitteePresigned,
                    GraphStatus::OperatorDataPushed,
                    GraphStatus::KickOff,
                ]
                .contains(&graph_status)
            {
                tracing::warn!(
                    "receive ChallengeSent for graph {} but currently in {graph_status} Status, ignored",
                    receive_data.graph_id
                );
                return Ok(());
            }
            let graph =
                get_bitvm2_graph_from_db(local_db, receive_data.instance_id, receive_data.graph_id)
                    .await?;
            if validate_challenge(
                btc_client,
                &graph.kickoff.tx().compute_txid(),
                &receive_data.challenge_txid,
            )
            .await?
            {
                update_graph_fields(
                    local_db,
                    receive_data.graph_id,
                    Some(GraphStatus::Challenge.to_string()),
                    None,
                    Some(serialize_hex(&receive_data.challenge_txid)),
                    None,
                    None,
                )
                .await?;
            }
        }
        (GOATMessageContent::Take1Sent(receive_data), _) => {
            tracing::info!("Handle Take1Sent");
            let status_op = sync_graph_without_waiting(
                swarm,
                local_db,
                receive_data.instance_id,
                receive_data.graph_id,
            )
            .await?;
            if status_op.is_none() {
                tracing::info!(
                    "Take1Sent: graph {} not found in local database. Skipping update and waiting for sync from other nodes.",
                    receive_data.graph_id,
                );
                return Ok(());
            }
            let graph =
                get_bitvm2_graph_from_db(local_db, receive_data.instance_id, receive_data.graph_id)
                    .await?;
            if tx_on_chain(btc_client, &graph.take1.tx().compute_txid()).await? {
                update_graph_fields(
                    local_db,
                    receive_data.graph_id,
                    Some(GraphStatus::Take1.to_string()),
                    None,
                    None,
                    None,
                    None,
                )
                .await?;
                obsolete_sibling_graphs(local_db, receive_data.instance_id, receive_data.graph_id)
                    .await?;
            }
        }
        (GOATMessageContent::Take2Sent(receive_data), _) => {
            tracing::info!("Handle Take2Sent");
            let status_op = sync_graph_without_waiting(
                swarm,
                local_db,
                receive_data.instance_id,
                receive_data.graph_id,
            )
            .await?;
            if status_op.is_none() {
                tracing::info!(
                    "Take2Sent: graph {} not found in local database. Skipping update and waiting for sync from other nodes.",
                    receive_data.graph_id,
                );
                return Ok(());
            }
            let graph =
                get_bitvm2_graph_from_db(local_db, receive_data.instance_id, receive_data.graph_id)
                    .await?;
            if tx_on_chain(btc_client, &graph.take2.tx().compute_txid()).await? {
                update_graph_fields(
                    local_db,
                    receive_data.graph_id,
                    Some(GraphStatus::Take2.to_string()),
                    None,
                    None,
                    None,
                    None,
                )
                .await?;
                obsolete_sibling_graphs(local_db, receive_data.instance_id, receive_data.graph_id)
                    .await?;
            }
        }
        (GOATMessageContent::DisproveSent(receive_data), _) => {
            tracing::info!("Handle DisproveSent");
            let status_op = sync_graph_without_waiting(
                swarm,
                local_db,
                receive_data.instance_id,
                receive_data.graph_id,
            )
            .await?;
            if status_op.is_none() {
                tracing::info!(
                    "DisproveSent: graph {} not found in local database. Skipping update and waiting for sync from other nodes.",
                    receive_data.graph_id,
                );
                return Ok(());
            }
            let graph =
                get_bitvm2_graph_from_db(local_db, receive_data.instance_id, receive_data.graph_id)
                    .await?;
            if validate_disprove(
                btc_client,
                &graph.assert_final.tx().compute_txid(),
                &receive_data.disprove_txid,
            )
            .await?
            {
                update_graph_fields(
                    local_db,
                    receive_data.graph_id,
                    Some(GraphStatus::Disprove.to_string()),
                    None,
                    None,
                    Some(serialize_hex(&receive_data.disprove_txid)),
                    None,
                )
                .await?;
                // NOTE: clean up other graphs?
            }
        }

        (GOATMessageContent::RequestNodeInfo(node_info), _) => {
            save_node_info(local_db, &node_info).await?;
            let message_content = GOATMessageContent::ResponseNodeInfo(get_local_node_info());
            send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
        }

        (GOATMessageContent::ResponseNodeInfo(node_info), _) => {
            save_node_info(local_db, &node_info).await?;
        }

        (GOATMessageContent::SyncGraphRequest(receive_data), Actor::Relayer) => {
            tracing::info!("Handle SyncGraphRequest...  ");
            let graph =
                get_bitvm2_graph_from_db(local_db, receive_data.instance_id, receive_data.graph_id)
                    .await?;
            let graph_status =
                get_graph_status(local_db, receive_data.instance_id, receive_data.graph_id)
                    .await?
                    .ok_or("empty graph status")?;
            let message_content = GOATMessageContent::SyncGraph(SyncGraph {
                instance_id: receive_data.instance_id,
                graph_id: receive_data.graph_id,
                graph: graph.to_simplified(),
                graph_status,
            });
            send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
        }
        (GOATMessageContent::SyncGraph(receive_data), _) => {
            tracing::info!("Handle SyncGraph...  ");
            if !validate_actor(&from_peer_id.to_bytes(), Actor::Relayer).await? {
                tracing::warn!("receive SyncGraph message but not from Relayer, ignored");
                return Ok(());
            }
            let graph_status = if receive_data.graph_status == GraphStatus::Discarded {
                // only get discarded for pre-kickoff recycle, need status to been CommitteePresigned
                Some(GraphStatus::CommitteePresigned.to_string())
            } else {
                Some(receive_data.graph_status.to_string())
            };

            store_graph(
                local_db,
                receive_data.instance_id,
                receive_data.graph_id,
                &Bitvm2Graph::from_simplified(receive_data.graph)?,
                graph_status,
            )
            .await?;
        }

        _ => {}
    }
    Ok(())
}

async fn sync_graph_without_waiting(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<Option<GraphStatus>, Box<dyn std::error::Error>> {
    if let Ok(status_op) = get_graph_status(local_db, instance_id, graph_id).await
        && status_op.is_some()
    {
        Ok(status_op)
    } else {
        let message_content =
            GOATMessageContent::SyncGraphRequest(SyncGraphRequest { instance_id, graph_id });
        send_to_peer(swarm, GOATMessage::from_typed(Actor::Relayer, &message_content)?)?;
        Ok(None)
    }
}

pub fn send_to_peer(
    swarm: &mut Swarm<AllBehaviours>,
    message: GOATMessage,
) -> Result<MessageId, Box<dyn std::error::Error>> {
    let actor = message.actor.to_string();
    let topic = crate::middleware::get_topic_name(&actor);
    let gossipsub_topic = gossipsub::IdentTopic::new(topic);
    Ok(swarm.behaviour_mut().gossipsub.publish(gossipsub_topic, serde_json::to_vec(&message)?)?)
}
