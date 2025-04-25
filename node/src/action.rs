use crate::env;
use crate::middleware::AllBehaviours;
use crate::relayer_action::do_tick_action;
use crate::utils::{statics::*, *};
use anyhow::Result;
use bitcoin::PublicKey;
use bitcoin::{Amount, Network, Txid};
use bitvm2_lib::actors::Actor;
use bitvm2_lib::keys::*;
use bitvm2_lib::types::{Bitvm2Graph, Bitvm2Parameters, CustomInputs};
use bitvm2_lib::verifier::export_challenge_tx;
use bitvm2_lib::{committee::*, operator::*, verifier::*};
use client::client::BitVM2Client;
use goat::transactions::{assert::utils::COMMIT_TX_NUM, pre_signed::PreSignedTransaction};
use libp2p::gossipsub::MessageId;
use libp2p::{PeerId, Swarm, gossipsub};
use musig2::{AggNonce, PartialSignature, PubNonce, SecNonce};
use reqwest::Request;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use store::GraphStatus;
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
}

#[derive(Serialize, Deserialize)]
pub struct CreateInstance {
    pub instance_id: Uuid,
    pub network: Network,
    pub depositor_evm_address: [u8; 20],
    pub pegin_amount: Amount,
    pub user_inputs: CustomInputs,
}

#[derive(Serialize, Deserialize)]
pub struct CreateGraphPrepare {
    pub instance_id: Uuid,
    pub network: Network,
    pub depositor_evm_address: [u8; 20],
    pub pegin_amount: Amount,
    pub user_inputs: CustomInputs,
    pub committee_member_pubkey: PublicKey,
    pub committee_members_num: usize,
}

#[derive(Serialize, Deserialize)]
pub struct CreateGraph {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub graph: Bitvm2Graph,
}

#[derive(Serialize, Deserialize)]
pub struct NonceGeneration {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub committee_pubkey: PublicKey,
    pub pub_nonces: [PubNonce; COMMITTEE_PRE_SIGN_NUM],
    pub committee_members_num: usize,
}

#[derive(Serialize, Deserialize)]
pub struct CommitteePresign {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub committee_pubkey: PublicKey,
    pub committee_partial_sigs: [PartialSignature; COMMITTEE_PRE_SIGN_NUM],
    pub agg_nonces: [AggNonce; COMMITTEE_PRE_SIGN_NUM],
    pub committee_members_num: usize,
}

#[derive(Serialize, Deserialize)]
pub struct GraphFinalize {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub graph: Bitvm2Graph,
    pub graph_ipfs_cid: String,
}

#[derive(Serialize, Deserialize)]
pub struct KickoffReady {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}

#[derive(Serialize, Deserialize)]
pub struct KickoffSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub kickoff_txid: Txid,
}

#[derive(Serialize, Deserialize)]
pub struct ChallengeSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub challenge_txid: Txid,
}

#[derive(Serialize, Deserialize)]
pub struct AssertSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub assert_init_txid: Txid,
    pub assert_commit_txids: [Txid; COMMIT_TX_NUM],
    pub assert_final_txid: Txid,
}

#[derive(Serialize, Deserialize)]
pub struct Take1Ready {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}

#[derive(Serialize, Deserialize)]
pub struct Take1Sent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub take1_txid: Txid,
}

#[derive(Serialize, Deserialize)]
pub struct Take2Ready {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}

#[derive(Serialize, Deserialize)]
pub struct Take2Sent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub take2_txid: Txid,
}

#[derive(Serialize, Deserialize)]
pub struct DisproveSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub disprove_txid: Txid,
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
pub async fn recv_and_dispatch(
    swarm: &mut Swarm<AllBehaviours>,
    client: &BitVM2Client,
    actor: Actor,
    peer_id: PeerId,
    id: MessageId,
    message: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let message: GOATMessage = serde_json::from_slice(message)?;
    tracing::info!(
        "Got message: {}:{} with id: {} from peer: {:?}",
        &message.actor.to_string(),
        String::from_utf8_lossy(&message.content),
        id,
        peer_id
    );
    let default_message_id = GOATMessage::default_message_id();
    if id == default_message_id {
        tracing::debug!("Get the running task, and broadcast the task status or result");
        if actor == Actor::Relayer {
            do_tick_action(swarm, client).await?;
        }

        return Ok(());
    }
    // // no need to check actor here, it's matched in the subsequent match block.
    // if message.actor != actor && message.actor != Actor::All && actor != Actor::Relayer {
    //     return Ok(());
    // }
    let content: GOATMessageContent = message.to_typed()?;
    // TODO: validate message
    match (content, actor) {
        // pegin
        // CreateInstance sent by bootnode
        (GOATMessageContent::CreateInstance(receive_data), Actor::Committee) => {
            tracing::info!("Handle CreateInstance");
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
            store_committee_pubkeys(client, receive_data.instance_id, keypair.public_key().into())
                .await?;
            send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
        }
        (GOATMessageContent::CreateGraphPrepare(receive_data), Actor::Operator) => {
            tracing::info!("Handle CreateGraphPrepare");
            store_committee_pubkeys(
                client,
                receive_data.instance_id,
                receive_data.committee_member_pubkey,
            )
            .await?;
            let collected_keys = get_committee_pubkeys(client, receive_data.instance_id).await?;
            tracing::info!(
                "instance {}, {}/{} committee-public-key collected",
                receive_data.instance_id,
                collected_keys.len(),
                receive_data.committee_members_num
            );
            if collected_keys.len() == receive_data.committee_members_num
                && should_generate_graph(client, &receive_data).await?
            {
                let graph_id = Uuid::new_v4();
                if try_start_new_graph(receive_data.instance_id, graph_id) {
                    let master_key = OperatorMasterKey::new(env::get_bitvm_key()?);
                    let keypair = master_key.keypair_for_graph(graph_id);
                    let (_, operator_wots_pubkeys) = master_key.wots_keypair_for_graph(graph_id);
                    let committee_agg_pubkey = key_aggregation(&collected_keys);
                    let disprove_scripts =
                        generate_disprove_scripts(&get_partial_scripts()?, &operator_wots_pubkeys);
                    let operator_inputs = select_operator_inputs(
                        client,
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
                    let disprove_scripts_bytes =
                        disprove_scripts.iter().map(|x| x.clone().compile().into_bytes()).collect();
                    let mut graph = generate_bitvm_graph(params, disprove_scripts_bytes)?;
                    operator_pre_sign(keypair, &mut graph)?;
                    store_graph(
                        client,
                        receive_data.instance_id,
                        graph_id,
                        &graph,
                        Some(GraphStatus::OperatorPresigned.to_string()),
                    )
                    .await?;
                    let message_content = GOATMessageContent::CreateGraph(CreateGraph {
                        instance_id: receive_data.instance_id,
                        graph_id,
                        graph,
                    });
                    send_to_peer(
                        swarm,
                        GOATMessage::from_typed(Actor::Committee, &message_content)?,
                    )?;
                };
            };
        }
        (GOATMessageContent::CreateGraph(receive_data), Actor::Committee) => {
            tracing::info!("Handle CreateGraph");
            store_graph(
                client,
                receive_data.instance_id,
                receive_data.graph_id,
                &receive_data.graph,
                Some(GraphStatus::OperatorPresigned.to_string()),
            )
            .await?;
            let master_key = CommitteeMasterKey::new(env::get_bitvm_key()?);
            let nonces =
                master_key.nonces_for_graph(receive_data.instance_id, receive_data.graph_id);
            let keypair = master_key.keypair_for_instance(receive_data.instance_id);
            let pub_nonces: [PubNonce; COMMITTEE_PRE_SIGN_NUM] =
                std::array::from_fn(|i| nonces[i].1.clone());
            let message_content = GOATMessageContent::NonceGeneration(NonceGeneration {
                instance_id: receive_data.instance_id,
                graph_id: receive_data.graph_id,
                committee_pubkey: keypair.public_key().into(),
                pub_nonces,
                committee_members_num: receive_data.graph.parameters.committee_pubkeys.len(),
            });
            send_to_peer(swarm, GOATMessage::from_typed(Actor::Committee, &message_content)?)?;
        }
        (GOATMessageContent::NonceGeneration(receive_data), Actor::Committee) => {
            tracing::info!("Handle NonceGeneration");
            store_committee_pub_nonces(
                client,
                receive_data.instance_id,
                receive_data.graph_id,
                receive_data.committee_pubkey,
                receive_data.pub_nonces,
            )
            .await?;
            let collected_pub_nonces =
                get_committee_pub_nonces(client, receive_data.instance_id, receive_data.graph_id)
                    .await?;
            tracing::info!(
                "graph {}, {}/{} committee-pub-nonces-pack collected",
                receive_data.graph_id,
                collected_pub_nonces.len(),
                receive_data.committee_members_num
            );
            if collected_pub_nonces.len() == receive_data.committee_members_num {
                let graph =
                    get_graph(client, receive_data.instance_id, receive_data.graph_id).await?;
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
                    committee_pubkey: receive_data.committee_pubkey,
                    committee_partial_sigs,
                    agg_nonces,
                    committee_members_num: receive_data.committee_members_num,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::Committee, &message_content)?)?;
            };
        }
        (GOATMessageContent::CommitteePresign(receive_data), Actor::Operator) => {
            tracing::info!("Handle CommitteePresign");
            if Some((receive_data.instance_id, receive_data.graph_id))
                == statics::current_processing_graph()
            {
                store_committee_partial_sigs(
                    client,
                    receive_data.instance_id,
                    receive_data.graph_id,
                    receive_data.committee_pubkey,
                    receive_data.committee_partial_sigs,
                )
                .await?;
                let collected_partial_sigs = get_committee_partial_sigs(
                    client,
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
                    let mut graph =
                        get_graph(client, receive_data.instance_id, receive_data.graph_id).await?;
                    signature_aggregation_and_push(
                        &grouped_partial_sigs,
                        &receive_data.agg_nonces,
                        &mut graph,
                    )?;
                    let prekickoff_tx = graph.pre_kickoff.tx().clone();
                    let node_keypair =
                        OperatorMasterKey::new(env::get_bitvm_key()?).master_keypair();
                    sign_and_broadcast_prekickoff_tx(client, node_keypair, prekickoff_tx).await?;
                    let graph_ipfs_cid =
                        publish_graph_to_ipfs(client, receive_data.graph_id, &graph).await?;
                    store_graph(
                        client,
                        receive_data.instance_id,
                        receive_data.graph_id,
                        &graph,
                        Some(GraphStatus::CommitteePresigned.to_string()),
                    )
                    .await?;
                    update_graph_fields(
                        client,
                        receive_data.graph_id,
                        None,
                        Some(graph_ipfs_cid.clone()),
                        None,
                        None,
                    )
                    .await?;
                    let message_content = GOATMessageContent::GraphFinalize(GraphFinalize {
                        instance_id: receive_data.instance_id,
                        graph_id: receive_data.graph_id,
                        graph,
                        graph_ipfs_cid,
                    });
                    send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
                    force_stop_current_graph();
                }
            };
        }
        (GOATMessageContent::GraphFinalize(receive_data), _) => {
            tracing::info!("Handle GraphFinalize");
            // TODO: validate graph & ipfs
            store_graph(
                client,
                receive_data.instance_id,
                receive_data.graph_id,
                &receive_data.graph,
                Some(GraphStatus::CommitteePresigned.to_string()),
            )
            .await?;
            update_graph_fields(
                client,
                receive_data.graph_id,
                None,
                Some(receive_data.graph_ipfs_cid.clone()),
                None,
                None,
            )
            .await?;
        }

        // peg-out
        // KickoffReady sent by relayer
        (GOATMessageContent::KickoffReady(receive_data), Actor::Operator) => {
            tracing::info!("Handle KickoffReady");
            let mut graph =
                get_graph(client, receive_data.instance_id, receive_data.graph_id).await?;
            if graph.parameters.operator_pubkey == env::get_node_pubkey()?
                && is_withdraw_initialized_on_l2(
                    client,
                    receive_data.instance_id,
                    receive_data.graph_id,
                )
                .await?
            {
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
                broadcast_tx(client, &kickoff_tx).await?;
                // malicious Operator may not broadcast kickoff to the p2p network
                // Relayer will monitor all graphs & broadcast KickoffSent
            }
        }
        // KickoffSent sent by relayer
        (GOATMessageContent::KickoffSent(receive_data), Actor::Challenger) => {
            tracing::info!("Handle KickoffSent");
            let mut graph =
                get_graph(client, receive_data.instance_id, receive_data.graph_id).await?;
            if should_challenge(
                client,
                Amount::from_sat(graph.challenge.min_crowdfunding_amount()),
                receive_data.instance_id,
                receive_data.graph_id,
                &graph.kickoff.tx().compute_txid(),
            )
            .await?
            {
                let (challenge_tx, challenge_amount) = export_challenge_tx(&mut graph)?;
                let node_keypair = ChallengerMasterKey::new(env::get_bitvm_key()?).master_keypair();
                let challenge_txid = complete_and_broadcast_challenge_tx(
                    client,
                    node_keypair,
                    challenge_tx,
                    challenge_amount,
                )
                .await?;
                let message_content = GOATMessageContent::ChallengeSent(ChallengeSent {
                    instance_id: receive_data.instance_id,
                    graph_id: receive_data.graph_id,
                    challenge_txid,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
                update_graph_fields(
                    client,
                    receive_data.graph_id,
                    Some(GraphStatus::KickOff.to_string()),
                    None,
                    None,
                    None,
                )
                .await?;
            }
        }
        // Take1Ready sent by relayer
        (GOATMessageContent::Take1Ready(receive_data), Actor::Operator) => {
            tracing::info!("Handle Take1Ready");
            let mut graph =
                get_graph(client, receive_data.instance_id, receive_data.graph_id).await?;
            if graph.parameters.operator_pubkey == env::get_node_pubkey()?
                && is_take1_timelock_expired(client, graph.take1.tx().compute_txid()).await?
            {
                let master_key = OperatorMasterKey::new(env::get_bitvm_key()?);
                let keypair = master_key.keypair_for_graph(receive_data.graph_id);
                let take1_tx = operator_sign_take1(keypair, &mut graph)?;
                let take1_txid = take1_tx.compute_txid();
                broadcast_tx(client, &take1_tx).await?;
                let message_content = GOATMessageContent::Take1Sent(Take1Sent {
                    instance_id: receive_data.instance_id,
                    graph_id: receive_data.graph_id,
                    take1_txid,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
                update_graph_fields(
                    client,
                    receive_data.graph_id,
                    Some(GraphStatus::Take1.to_string()),
                    None,
                    None,
                    None,
                )
                .await?;
                // NOTE: clean up other graphs?
            }
        }
        // ChallengeSent sent by challenger
        // if challenger
        (GOATMessageContent::ChallengeSent(receive_data), Actor::Operator) => {
            tracing::info!("Handle ChallengeSent");
            let mut graph =
                get_graph(client, receive_data.instance_id, receive_data.graph_id).await?;
            if graph.parameters.operator_pubkey == env::get_node_pubkey()?
                && validate_challenge(
                    client,
                    &graph.kickoff.tx().compute_txid(),
                    &receive_data.challenge_txid,
                )
                .await?
            {
                let master_key = OperatorMasterKey::new(env::get_bitvm_key()?);
                let keypair = master_key.keypair_for_graph(receive_data.graph_id);
                let (operator_wots_seckeys, operator_wots_pubkeys) =
                    master_key.wots_keypair_for_graph(receive_data.graph_id);
                let (proof, pubin, vk) =
                    get_groth16_proof(receive_data.instance_id, receive_data.graph_id)?;
                let proof_sigs = sign_proof(&vk, proof, pubin, &operator_wots_seckeys);
                let (assert_init_tx, assert_commit_txns, assert_final_tx) =
                    operator_sign_assert(keypair, &mut graph, &operator_wots_pubkeys, proof_sigs)?;
                broadcast_tx(client, &assert_init_tx).await?;
                for tx in assert_commit_txns {
                    broadcast_tx(client, &tx).await?;
                }
                broadcast_tx(client, &assert_final_tx).await?;
                update_graph_fields(
                    client,
                    receive_data.graph_id,
                    Some(GraphStatus::Assert.to_string()),
                    None,
                    Some(receive_data.challenge_txid.to_string()),
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
            let mut graph =
                get_graph(client, receive_data.instance_id, receive_data.graph_id).await?;
            if graph.parameters.operator_pubkey == env::get_node_pubkey()?
                && is_take2_timelock_expired(client, graph.assert_final.tx().compute_txid()).await?
            {
                let master_key = OperatorMasterKey::new(env::get_bitvm_key()?);
                let keypair = master_key.keypair_for_graph(receive_data.graph_id);
                let take2_tx = operator_sign_take2(keypair, &mut graph)?;
                let take2_txid = take2_tx.compute_txid();
                broadcast_tx(client, &take2_tx).await?;
                let message_content = GOATMessageContent::Take2Sent(Take2Sent {
                    instance_id: receive_data.instance_id,
                    graph_id: receive_data.graph_id,
                    take2_txid,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
                update_graph_fields(
                    client,
                    receive_data.graph_id,
                    Some(GraphStatus::Take2.to_string()),
                    None,
                    None,
                    None,
                )
                .await?;
                // NOTE: clean up other graphs?
            }
        }
        // AssertSent sent by relayer
        (GOATMessageContent::AssertSent(receive_data), Actor::Challenger) => {
            tracing::info!("Handle AssertSent");
            let mut graph =
                get_graph(client, receive_data.instance_id, receive_data.graph_id).await?;
            if let Some(disprove_witness) = validate_assert(
                client,
                &receive_data.assert_commit_txids,
                graph.parameters.operator_wots_pubkeys.clone(),
            )
            .await?
            {
                let disprove_scripts = generate_disprove_scripts(
                    &get_partial_scripts()?,
                    &graph.parameters.operator_wots_pubkeys,
                );
                let disprove_scripts_bytes =
                    disprove_scripts.iter().map(|x| x.clone().compile().into_bytes()).collect();
                let assert_wots_pubkeys = graph.parameters.operator_wots_pubkeys.1.clone();
                let disprove_tx = sign_disprove(
                    &mut graph,
                    disprove_witness,
                    disprove_scripts_bytes,
                    &assert_wots_pubkeys,
                    disprove_reward_address()?,
                )?;
                let disprove_txid = disprove_tx.compute_txid();
                broadcast_tx(client, &disprove_tx).await?;
                let message_content = GOATMessageContent::DisproveSent(DisproveSent {
                    instance_id: receive_data.instance_id,
                    graph_id: receive_data.graph_id,
                    disprove_txid,
                });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
                update_graph_fields(
                    client,
                    receive_data.graph_id,
                    Some(GraphStatus::Disprove.to_string()),
                    None,
                    None,
                    None,
                )
                .await?;
            }
        }

        // Relayer handles
        (GOATMessageContent::Take1Sent(receive_data), Actor::Relayer) => {
            tracing::info!("Handle Take1Sent");
            let graph = get_graph(client, receive_data.instance_id, receive_data.graph_id).await?;
            let take1_txid = graph.take1.tx().compute_txid();
            if tx_on_chain(client, &take1_txid).await? {
                finish_withdraw_happy_path(client, &receive_data.graph_id, &graph.take1).await?;
                update_graph_fields(
                    client,
                    receive_data.graph_id,
                    Some(GraphStatus::Take1.to_string()),
                    None,
                    None,
                    None,
                )
                .await?;
                // NOTE: clean up other graphs?
            }
        }
        (GOATMessageContent::Take2Sent(receive_data), Actor::Relayer) => {
            tracing::info!("Handle Take2Sent");
            let graph = get_graph(client, receive_data.instance_id, receive_data.graph_id).await?;
            if tx_on_chain(client, &graph.take2.tx().compute_txid()).await? {
                finish_withdraw_unhappy_path(client, &receive_data.graph_id, &graph.take2).await?;
                update_graph_fields(
                    client,
                    receive_data.graph_id,
                    Some(GraphStatus::Take2.to_string()),
                    None,
                    None,
                    None,
                )
                .await?;
                // NOTE: clean up other graphs?
            }
        }
        (GOATMessageContent::DisproveSent(receive_data), Actor::Relayer) => {
            tracing::info!("Handle DisproveSent");
            let graph = get_graph(client, receive_data.instance_id, receive_data.graph_id).await?;
            if validate_disprove(
                client,
                &graph.assert_final.tx().compute_txid(),
                &receive_data.disprove_txid,
            )
            .await?
            {
                finish_withdraw_disproved(client, &receive_data.graph_id, &graph.disprove).await?;
                update_graph_fields(
                    client,
                    receive_data.graph_id,
                    Some(GraphStatus::Disprove.to_string()),
                    None,
                    None,
                    Some(receive_data.disprove_txid.to_string()),
                )
                .await?;

                // NOTE: clean up other graphs?
            }
        }

        // Other participants update graph status
        (GOATMessageContent::KickoffSent(receive_data), _) => {
            tracing::info!("Handle KickoffSent");
            let graph = get_graph(client, receive_data.instance_id, receive_data.graph_id).await?;
            if tx_on_chain(client, &graph.kickoff.tx().compute_txid()).await? {
                update_graph_fields(
                    client,
                    receive_data.graph_id,
                    Some(GraphStatus::KickOff.to_string()),
                    None,
                    None,
                    None,
                )
                .await?;
            }
        }
        (GOATMessageContent::ChallengeSent(receive_data), _) => {
            tracing::info!("Handle ChallengeSent");
            let graph = get_graph(client, receive_data.instance_id, receive_data.graph_id).await?;
            if validate_challenge(
                client,
                &graph.kickoff.tx().compute_txid(),
                &receive_data.challenge_txid,
            )
            .await?
            {
                update_graph_fields(
                    client,
                    receive_data.graph_id,
                    Some(GraphStatus::Challenge.to_string()),
                    None,
                    Some(receive_data.challenge_txid.to_string()),
                    None,
                )
                .await?;
            }
        }
        (GOATMessageContent::Take1Sent(receive_data), _) => {
            tracing::info!("Handle Take1Sent");
            let graph = get_graph(client, receive_data.instance_id, receive_data.graph_id).await?;
            if tx_on_chain(client, &graph.take1.tx().compute_txid()).await? {
                update_graph_fields(
                    client,
                    receive_data.graph_id,
                    Some(GraphStatus::Take1.to_string()),
                    None,
                    None,
                    None,
                )
                .await?;
                // NOTE: clean up other graphs?
            }
        }
        (GOATMessageContent::Take2Sent(receive_data), _) => {
            tracing::info!("Handle Take2Sent");
            let graph = get_graph(client, receive_data.instance_id, receive_data.graph_id).await?;
            if tx_on_chain(client, &graph.take2.tx().compute_txid()).await? {
                update_graph_fields(
                    client,
                    receive_data.graph_id,
                    Some(GraphStatus::Take2.to_string()),
                    None,
                    None,
                    None,
                )
                .await?;
                // NOTE: clean up other graphs?
            }
        }
        (GOATMessageContent::DisproveSent(receive_data), _) => {
            tracing::info!("Handle DisproveSent");
            let graph = get_graph(client, receive_data.instance_id, receive_data.graph_id).await?;
            if validate_disprove(
                client,
                &graph.assert_final.tx().compute_txid(),
                &receive_data.disprove_txid,
            )
            .await?
            {
                update_graph_fields(
                    client,
                    receive_data.graph_id,
                    Some(GraphStatus::Disprove.to_string()),
                    None,
                    None,
                    Some(receive_data.disprove_txid.to_string()),
                )
                .await?;
                // NOTE: clean up other graphs?
            }
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn send_to_peer(
    swarm: &mut Swarm<AllBehaviours>,
    message: GOATMessage,
) -> Result<MessageId, Box<dyn std::error::Error>> {
    let actor = message.actor.to_string();
    let gossipsub_topic = gossipsub::IdentTopic::new(actor);
    Ok(swarm.behaviour_mut().gossipsub.publish(gossipsub_topic, serde_json::to_vec(&message)?)?)
}

///  call the rpc service
///     Method::GET/POST/PUT
#[allow(dead_code)]
pub(crate) async fn inner_rpc<S, R>(
    addr: &str,
    method: reqwest::Method,
    uri: &str,
    params: S,
) -> Result<R, Box<dyn std::error::Error>>
where
    S: Serialize,
    R: DeserializeOwned,
{
    let client = reqwest::Client::new();
    let url = reqwest::Url::parse(&format!("{addr}/{uri}"))?;

    let req = Request::new(method, url);
    let req_builder = reqwest::RequestBuilder::from_parts(client, req);
    let resp = req_builder.json(&params).send().await?;
    let txt = resp.text().await?;
    Ok(serde_json::from_str(txt.as_str())?)
}
