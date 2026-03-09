use crate::action::*;
use crate::env::{get_bitvm_key, get_network, get_node_goat_address, is_relayer};
use crate::error::SpecialError;
use crate::middleware::AllBehaviours;
use crate::scheduled_tasks::graph_maintenance_tasks::ChallengeSubStatus;
use crate::utils::*;
use anyhow::{Result, anyhow, bail};
use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, Txid};
use bitcoin::{PublicKey, XOnlyPublicKey};
use bitvm2_lib::actors::Actor;
use bitvm2_lib::challenger::*;
use bitvm2_lib::committee::*;
use bitvm2_lib::keys::*;
use bitvm2_lib::operator::*;
use bitvm2_lib::types::{Bitvm2Graph, SimplifiedBitvm2Graph};
use client::goat_chain::{DisproveTxType, PeginStatus, WithdrawStatus};
use client::http_client::async_client::HttpAsyncClient;
use client::{btc_chain::BTCClient, goat_chain::GOATClient};
use goat::connectors::connector_z::ConnectorZ;
use goat::transactions::base::{BaseTransaction, Input};
use goat::transactions::pre_signed::PreSignedTransaction;
use goat::transactions::pre_signed_musig2::verify_public_nonce;
use libp2p::gossipsub::MessageId;
use libp2p::{PeerId, Swarm};
use store::GraphStatus;
use store::localdb::LocalDB;
use uuid::Uuid;

pub struct HandlerContext<'a> {
    pub swarm: &'a mut Swarm<AllBehaviours>,
    pub local_db: &'a LocalDB,
    pub btc_client: &'a BTCClient,
    pub goat_client: &'a GOATClient,
    pub http_client: &'a HttpAsyncClient,
    pub actor: Actor,
    pub from_peer_id: PeerId,
    pub id: MessageId,
    pub is_self_peer: bool,
}

pub async fn dispatch(ctx: &mut HandlerContext<'_>, content: &GOATMessageContent) -> Result<()> {
    match (content, &ctx.actor) {
        (
            GOATMessageContent::PeginRequest(PeginRequest {
                instance_id,
                pegin_request_tx_hash,
                pegin_request_height,
                pegin_timestamp,
            }),
            Actor::Committee,
        ) => {
            handle_pegin_request_committee(
                ctx,
                *instance_id,
                pegin_request_tx_hash,
                *pegin_request_height,
                *pegin_timestamp,
            )
            .await
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
            handle_pegin_request_default(
                ctx,
                *instance_id,
                pegin_request_tx_hash,
                *pegin_request_height,
                *pegin_timestamp,
            )
            .await
        }
        (GOATMessageContent::ConfirmInstance(ConfirmInstance { instance_id }), Actor::Operator) => {
            handle_confirm_instance_operator(ctx, *instance_id).await
        }
        (GOATMessageContent::ConfirmInstance(ConfirmInstance { instance_id }), _) => {
            handle_confirm_instance_default(ctx, *instance_id).await
        }
        (
            GOATMessageContent::CreateGraph(CreateGraph { instance_id, graph_id, graph, .. }),
            Actor::Committee,
        ) => handle_create_graph_committee(ctx, *instance_id, *graph_id, graph).await,
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
            handle_nonce_generation_committee(
                ctx,
                *instance_id,
                *graph_id,
                received_committee_pubkey,
                *watchtower_num,
                *assert_commit_num,
                pub_nonces,
                nonce_sigs,
                content,
            )
            .await
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
            handle_nonce_generation_operator(
                ctx,
                *instance_id,
                *graph_id,
                received_committee_pubkey,
                *watchtower_num,
                *assert_commit_num,
                pub_nonces,
                nonce_sigs,
            )
            .await
        }
        (
            GOATMessageContent::CommitteePresign(CommitteePresign {
                instance_id,
                graph_id,
                committee_pubkey: received_committee_pubkey,
                committee_partial_sigs,
                agg_nonces,
            }),
            Actor::Committee,
        ) => {
            handle_committee_presign_committee(
                ctx,
                *instance_id,
                *graph_id,
                received_committee_pubkey,
                committee_partial_sigs,
                agg_nonces,
                content,
            )
            .await
        }
        (
            GOATMessageContent::CommitteePresign(CommitteePresign {
                instance_id,
                graph_id,
                committee_pubkey: received_committee_pubkey,
                committee_partial_sigs,
                agg_nonces,
            }),
            Actor::Operator,
        ) => {
            handle_committee_presign_operator(
                ctx,
                *instance_id,
                *graph_id,
                received_committee_pubkey,
                committee_partial_sigs,
                agg_nonces,
            )
            .await
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
            handle_endorse_graph_operator(
                ctx,
                *instance_id,
                *graph_id,
                received_committee_pubkey,
                committee_sig_for_graph,
                committee_evm_address,
            )
            .await
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
            handle_graph_finalize_committee(ctx, *instance_id, *graph_id, graph, endorse_sigs).await
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
        ) => handle_graph_finalize_default(ctx, *instance_id, *graph_id, graph, endorse_sigs).await,
        (
            GOATMessageContent::PeginConfirmNonce(PeginConfirmNonce {
                instance_id,
                committee_pubkey: received_committee_pubkey,
                pub_nonce,
                nonce_sig,
            }),
            Actor::Committee,
        ) => {
            handle_pegin_confirm_nonce_committee(
                ctx,
                *instance_id,
                received_committee_pubkey,
                pub_nonce,
                nonce_sig,
            )
            .await
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
            handle_pegin_confirm_partial_sig_committee(
                ctx,
                *instance_id,
                received_committee_pubkey,
                partial_sig,
                endorse_sig,
            )
            .await
        }
        (GOATMessageContent::PostReady(PostReady { instance_id }), Actor::Committee) => {
            handle_post_ready(ctx, *instance_id).await
        }
        (
            GOATMessageContent::KickoffReady(KickoffReady { instance_id, graph_id }),
            Actor::Operator,
        ) => handle_kickoff_ready_operator(ctx, *instance_id, *graph_id, content).await,
        (
            GOATMessageContent::KickoffSent(KickoffSent { instance_id, graph_id }),
            Actor::Committee,
        ) => handle_kickoff_sent_committee(ctx, *instance_id, *graph_id, content).await,
        (
            GOATMessageContent::KickoffSent(KickoffSent { instance_id, graph_id }),
            Actor::Challenger,
        ) => handle_kickoff_sent_challenger(ctx, *instance_id, *graph_id, content).await,
        (GOATMessageContent::KickoffSent(KickoffSent { instance_id, graph_id }), _) => {
            handle_kickoff_sent_default(ctx, *instance_id, *graph_id, content).await
        }
        (
            GOATMessageContent::PreKickoffSent(PreKickoffSent { instance_id, graph_id }),
            Actor::Challenger,
        ) => handle_prekickoff_sent_challenger(ctx, *instance_id, *graph_id, content).await,
        (GOATMessageContent::PreKickoffSent(PreKickoffSent { instance_id, graph_id }), _) => {
            handle_prekickoff_sent_default(ctx, *instance_id, *graph_id).await
        }
        (
            GOATMessageContent::ChallengeSent(ChallengeSent {
                instance_id,
                graph_id,
                challenge_txid,
            }),
            Actor::Operator,
        ) => {
            handle_challenge_sent_operator(ctx, *instance_id, *graph_id, *challenge_txid, content)
                .await
        }
        (GOATMessageContent::ChallengeSent(ChallengeSent { instance_id, graph_id, .. }), _) => {
            handle_challenge_sent_default(ctx, *instance_id, *graph_id).await
        }
        (
            GOATMessageContent::WatchtowerChallengeInitSent(WatchtowerChallengeInitSent {
                instance_id,
                graph_id,
            }),
            Actor::Watchtower,
        ) => {
            handle_watchtower_challenge_init_sent_watchtower(ctx, *instance_id, *graph_id, content)
                .await
        }
        (
            GOATMessageContent::WatchtowerChallengeSent(WatchtowerChallengeSent {
                instance_id,
                graph_id,
                watchtower_challenge_txids,
            }),
            Actor::Operator,
        ) => {
            handle_watchtower_challenge_sent_operator(
                ctx,
                *instance_id,
                *graph_id,
                watchtower_challenge_txids,
                content,
            )
            .await
        }
        (
            GOATMessageContent::WatchtowerChallengeTimeout(WatchtowerChallengeTimeout {
                instance_id,
                graph_id,
                watchtower_indexes,
            }),
            Actor::Operator,
        ) => {
            handle_watchtower_challenge_timeout_operator(
                ctx,
                *instance_id,
                *graph_id,
                watchtower_indexes,
                content,
            )
            .await
        }
        (
            GOATMessageContent::OperatorAckTimeout(OperatorAckTimeout { instance_id, graph_id }),
            Actor::Challenger,
        ) => handle_operator_ack_timeout_challenger(ctx, *instance_id, *graph_id, content).await,
        (
            GOATMessageContent::OperatorCommitBlockHashReady(OperatorCommitBlockHashReady {
                instance_id,
                graph_id,
            }),
            Actor::Operator,
        ) => {
            handle_operator_commit_blockhash_ready_operator(ctx, *instance_id, *graph_id, content)
                .await
        }
        (
            GOATMessageContent::OperatorCommitBlockHashTimeout(OperatorCommitBlockHashTimeout {
                instance_id,
                graph_id,
            }),
            Actor::Challenger,
        ) => {
            handle_operator_commit_blockhash_timeout_challenger(
                ctx,
                *instance_id,
                *graph_id,
                content,
            )
            .await
        }
        (
            GOATMessageContent::AssertInitReady(AssertInitReady { instance_id, graph_id }),
            Actor::Operator,
        ) => handle_assert_init_ready_operator(ctx, *instance_id, *graph_id, content).await,
        (
            GOATMessageContent::AssertCommitTimeout(AssertCommitTimeout { instance_id, graph_id }),
            Actor::Challenger,
        ) => handle_assert_commit_timeout_challenger(ctx, *instance_id, *graph_id, content).await,
        (
            GOATMessageContent::DisproveReady(DisproveReady { instance_id, graph_id }),
            Actor::Challenger,
        ) => handle_disprove_ready_challenger(ctx, *instance_id, *graph_id, content).await,
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
            handle_disprove_sent_committee(
                ctx,
                *instance_id,
                *graph_id,
                *disprove_type,
                *index,
                *challenge_finish_txid,
                content,
            )
            .await
        }
        (GOATMessageContent::DisproveSent(DisproveSent { instance_id, graph_id, .. }), _) => {
            handle_disprove_sent_default(ctx, *instance_id, *graph_id).await
        }
        (GOATMessageContent::Take1Ready(Take1Ready { instance_id, graph_id }), Actor::Operator) => {
            handle_take1_ready_operator(ctx, *instance_id, *graph_id, content).await
        }
        (GOATMessageContent::Take1Sent(Take1Sent { instance_id, graph_id }), Actor::Committee) => {
            handle_take1_sent_committee(ctx, *instance_id, *graph_id, content).await
        }
        (GOATMessageContent::Take1Sent(Take1Sent { instance_id, graph_id }), _) => {
            handle_take1_sent_default(ctx, *instance_id, *graph_id).await
        }
        (GOATMessageContent::Take2Ready(Take2Ready { instance_id, graph_id }), Actor::Operator) => {
            handle_take2_ready_operator(ctx, *instance_id, *graph_id, content).await
        }
        (GOATMessageContent::Take2Sent(Take2Sent { instance_id, graph_id }), Actor::Committee) => {
            handle_take2_sent_committee(ctx, *instance_id, *graph_id, content).await
        }
        (GOATMessageContent::Take2Sent(Take2Sent { instance_id, graph_id }), _) => {
            handle_take2_sent_default(ctx, *instance_id, *graph_id).await
        }
        (
            GOATMessageContent::SyncGraphRequest(SyncGraphRequest { instance_id, graph_id }),
            Actor::Committee,
        ) => handle_sync_graph_request(ctx, *instance_id, *graph_id).await,
        (GOATMessageContent::SyncGraph(SyncGraph { instance_id, graph_id, graph }), _) => {
            handle_sync_graph(ctx, *instance_id, *graph_id, graph).await
        }
        (GOATMessageContent::RequestNodeInfo(node_info), _) => {
            handle_request_node_info(ctx, node_info).await
        }
        (GOATMessageContent::ResponseNodeInfo(node_info), _) => {
            handle_response_node_info(ctx, node_info).await
        }
        _ => Ok(()),
    }
}

fn make_message(ctx: &HandlerContext<'_>, content: &GOATMessageContent) -> GOATMessage {
    GOATMessage::new(ctx.actor.clone(), content.clone())
}

fn should_ignore_invalid_pegin_request(e: &anyhow::Error, instance_id: Uuid) -> bool {
    if let Some(SpecialError::InvalidPeginRequest(err_msg)) = e.downcast_ref::<SpecialError>() {
        tracing::warn!("Ignore PeginRequest for {instance_id}: {err_msg}");
        return true;
    }
    false
}

fn should_ignore_invalid_pegin_data(e: &anyhow::Error, instance_id: Uuid) -> bool {
    if let Some(SpecialError::InvalidPeginData(err_msg)) = e.downcast_ref::<SpecialError>() {
        tracing::warn!("Ignore ConfirmInstance for {instance_id}: {err_msg}");
        return true;
    }
    false
}

fn should_ignore_invalid_graph(
    e: &anyhow::Error,
    instance_id: Uuid,
    graph_id: Uuid,
    context: &str,
    from_peer: Option<&PeerId>,
) -> bool {
    if let Some(SpecialError::InvalidGraph(err_msg)) = e.downcast_ref::<SpecialError>() {
        if let Some(peer_id) = from_peer {
            tracing::warn!(
                "Ignore {context} for {instance_id}:{graph_id} from {}: {err_msg}",
                peer_id.to_string()
            );
        } else {
            tracing::warn!("Ignore {context} for {instance_id}:{graph_id}: {err_msg}");
        }
        return true;
    }
    false
}

fn should_ignore_committee_error(
    e: &anyhow::Error,
    instance_id: Uuid,
    graph_id: Option<Uuid>,
    ctx: &HandlerContext<'_>,
    context: &str,
) -> bool {
    let peer = ctx.from_peer_id.to_string();
    match e.downcast_ref::<SpecialError>() {
        Some(SpecialError::InvalidCommittee(err_msg)) => {
            if let Some(graph_id) = graph_id {
                tracing::warn!(
                    "Ignore {context} for {instance_id}:{graph_id} from {peer}: {err_msg}"
                );
            } else {
                tracing::warn!("Ignore {context} for {instance_id} from {peer}: {err_msg}");
            }
            true
        }
        Some(SpecialError::EvmReverted(err_msg)) => {
            if let Some(graph_id) = graph_id {
                tracing::warn!(
                    "Ignore {context} for {instance_id}:{graph_id} from {peer}: fail to validate committee info on chain: {err_msg}"
                );
            } else {
                tracing::warn!(
                    "Ignore {context} for {instance_id} from {peer}: fail to validate committee info on chain: {err_msg}"
                );
            }
            true
        }
        _ => false,
    }
}

async fn ensure_self_or_valid_committee(
    ctx: &HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Option<Uuid>,
    received_committee_pubkey: &PublicKey,
    context: &str,
) -> Result<bool> {
    if ctx.is_self_peer {
        return Ok(true);
    }
    if let Err(e) = validate_committee(
        ctx.goat_client,
        &ctx.from_peer_id,
        instance_id,
        received_committee_pubkey,
    )
    .await
    {
        if should_ignore_committee_error(&e, instance_id, graph_id, ctx, context) {
            return Ok(false);
        }
        bail!(e);
    }
    Ok(true)
}

async fn ensure_self_or_valid_committee_with_evm(
    ctx: &HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Option<Uuid>,
    received_committee_pubkey: &PublicKey,
    committee_evm_address: &alloy::primitives::Address,
    context: &str,
) -> Result<bool> {
    if ctx.is_self_peer {
        return Ok(true);
    }
    if let Err(e) = validate_committee_with_evm_address(
        ctx.goat_client,
        &ctx.from_peer_id,
        instance_id,
        received_committee_pubkey,
        committee_evm_address,
    )
    .await
    {
        if should_ignore_committee_error(&e, instance_id, graph_id, ctx, context) {
            return Ok(false);
        }
        bail!(e);
    }
    Ok(true)
}

async fn refresh_and_compensate(
    ctx: &HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    graph: Option<&Bitvm2Graph>,
    scan_from_status: Option<GraphStatus>,
    compensate_from_status: GraphStatus,
) -> Result<(GraphStatus, Option<ChallengeSubStatus>)> {
    let (graph_status, sub_status) = refresh_graph(
        ctx.local_db,
        ctx.btc_client,
        ctx.goat_client,
        instance_id,
        graph_id,
        graph,
        scan_from_status,
        None,
    )
    .await?;
    tracing::info!("Graph {graph_id} latest status: {graph_status}");
    compensate_graph_events(
        ctx.local_db,
        ctx.btc_client,
        instance_id,
        graph_id,
        graph,
        scan_from_status,
        compensate_from_status,
        graph_status,
        sub_status,
    )
    .await?;
    Ok((graph_status, sub_status))
}

async fn get_graph_and_status(
    ctx: &HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<(Bitvm2Graph, GraphStatus)> {
    let graph = get_graph(ctx.local_db, instance_id, graph_id)
        .await?
        .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
    let graph = Bitvm2Graph::from_simplified(&graph)?;
    let graph_start_status = get_graph_status(ctx.local_db, instance_id, graph_id)
        .await?
        .ok_or_else(|| anyhow!("Graph status not found for {instance_id}:{graph_id}"))?;
    Ok((graph, graph_start_status))
}

async fn get_graph_and_status_or_defer(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    message: &GOATMessage,
) -> Result<Option<(Bitvm2Graph, GraphStatus)>> {
    let graph = match get_graph_or_defer(
        ctx.swarm,
        ctx.local_db,
        ctx.goat_client,
        instance_id,
        graph_id,
        message,
    )
    .await?
    {
        Some(g) => g,
        None => return Ok(None),
    };
    let graph = Bitvm2Graph::from_simplified(&graph)?;
    let graph_start_status = get_graph_status(ctx.local_db, instance_id, graph_id)
        .await?
        .ok_or_else(|| anyhow!("Graph status not found for {instance_id}:{graph_id}"))?;
    Ok(Some((graph, graph_start_status)))
}

async fn refresh_graph_status(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    message: Option<&GOATMessage>,
    compensate_from_status: GraphStatus,
) -> Result<Option<(Bitvm2Graph, GraphStatus, Option<ChallengeSubStatus>)>> {
    let (graph, graph_start_status) = match message {
        Some(message) => {
            match get_graph_and_status_or_defer(ctx, instance_id, graph_id, message).await? {
                Some(v) => v,
                None => return Ok(None),
            }
        }
        None => get_graph_and_status(ctx, instance_id, graph_id).await?,
    };
    let (graph_status, sub_status) = refresh_and_compensate(
        ctx,
        instance_id,
        graph_id,
        Some(&graph),
        Some(graph_start_status),
        compensate_from_status,
    )
    .await?;
    Ok(Some((graph, graph_status, sub_status)))
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id))]
async fn handle_pegin_request_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    pegin_request_tx_hash: &str,
    pegin_request_height: i64,
    pegin_timestamp: i64,
) -> Result<()> {
    // triggered by BridgeInRequest event
    // 1. read & check the pegin request data
    let (user_info, pegin_amount) =
        match read_pegin_request(ctx.btc_client, ctx.goat_client, instance_id).await {
            Ok(v) => v,
            Err(e) => {
                if should_ignore_invalid_pegin_request(&e, instance_id) {
                    return Ok(());
                }
                bail!(e)
            }
        };

    // 2. save the pegin request data to local db
    store_pegin_request(
        ctx.btc_client,
        ctx.local_db,
        GenerateInstanceParams {
            instance_id,
            user_info,
            pegin_amount,
            pegin_request_tx_hash: pegin_request_tx_hash.to_string(),
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
    ctx.goat_client.gateway_answer_pegin_request(&instance_id, &pubkey_for_instance).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id))]
async fn handle_pegin_request_default(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    pegin_request_tx_hash: &str,
    pegin_request_height: i64,
    pegin_timestamp: i64,
) -> Result<()> {
    // triggered by BridgeInRequest event
    // 1. read & check the pegin request data
    let (user_info, pegin_amount) =
        match read_pegin_request(ctx.btc_client, ctx.goat_client, instance_id).await {
            Ok(v) => v,
            Err(e) => {
                if should_ignore_invalid_pegin_request(&e, instance_id) {
                    return Ok(());
                }
                bail!(e)
            }
        };
    // 2. save the pegin request data to local db
    store_pegin_request(
        ctx.btc_client,
        ctx.local_db,
        GenerateInstanceParams {
            instance_id,
            user_info,
            pegin_amount,
            pegin_request_tx_hash: pegin_request_tx_hash.to_string(),
            pegin_request_height,
            pegin_timestamp,
        },
    )
    .await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id))]
async fn handle_confirm_instance_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
) -> Result<()> {
    // triggered by PeginDeposit tx
    // 0. check if graph already created
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let local_operator_pubkey = operator_master_key.master_keypair().public_key().into();
    if let Some(graph) = get_graph_by_instance_id_and_operator_pubkey(
        ctx.local_db,
        instance_id,
        &local_operator_pubkey,
    )
    .await?
    {
        let graph_id = graph.parameters.graph_id;
        tracing::info!("Graph already created for {instance_id}, graph_id: {}", graph_id);
        let message_content = GOATMessageContent::CreateGraph(CreateGraph {
            instance_id,
            graph_id,
            graph_nonce: graph.parameters.graph_nonce,
            graph,
        });
        let msg = GOATMessage::new(Actor::All, message_content);
        send_to_peer(ctx.swarm, msg).await?;
        return Ok(());
    }
    // 1. read & check parameters
    let instance_params = match read_instance_info_from_goat(ctx.goat_client, instance_id).await {
        Ok(v) => v,
        Err(e) => {
            if should_ignore_invalid_pegin_data(&e, instance_id) {
                return Ok(());
            }
            bail!(e)
        }
    };
    let pegin_deposit_txid = instance_params.build_pegin_tx()?.0.tx().compute_txid();
    if !tx_on_chain(ctx.btc_client, &pegin_deposit_txid).await? {
        tracing::warn!(
            "Ignore ConfirmInstance for {instance_id}: pegin deposit tx {pegin_deposit_txid} not found on chain"
        );
        bail!("Invalid ConfirmInstance: pegin deposit tx {pegin_deposit_txid} not found on chain");
    }
    // 2. save the instance data to local db
    store_instance_parameters(ctx.local_db, &instance_params).await?;
    // 3. create & presign graph
    let (graph_nonce, cur_prekickoff_tx) =
        match get_current_prekickoff_tx(ctx.local_db, &local_operator_pubkey).await? {
            Some(v) => v,
            None => {
                let genesis_prekickoff_tx =
                    build_genesis_prekickoff_tx(ctx.btc_client, ctx.goat_client).await?;
                (0, genesis_prekickoff_tx)
            }
        };
    let prekickoff_params =
        build_prekickoff_params(ctx.btc_client, graph_nonce, cur_prekickoff_tx).await?;
    let graph_params = build_graph_params(
        ctx.local_db,
        ctx.goat_client,
        instance_params,
        prekickoff_params,
        graph_nonce,
        Uuid::new_v4(),
    )
    .await?;
    let graph_id = graph_params.graph_id;
    let disprove_scripts = get_disprove_scripts(&graph_params).await?;
    let mut graph = generate_bitvm_graph(graph_params, disprove_scripts)?;
    operator_pre_sign(operator_master_key.master_keypair(), &mut graph)?;
    store_graph(ctx.local_db, &graph.to_simplified()?).await?;
    // 4. broadcast CreateGraph
    let message_content = GOATMessageContent::CreateGraph(CreateGraph {
        instance_id,
        graph_id,
        graph_nonce,
        graph: graph.to_simplified()?,
    });
    send_to_peer(ctx.swarm, GOATMessage::new(Actor::All, message_content)).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id))]
async fn handle_confirm_instance_default(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
) -> Result<()> {
    // triggered by PeginDeposit tx
    // 1. read & check parameters
    let instance_params = match read_instance_info_from_goat(ctx.goat_client, instance_id).await {
        Ok(v) => v,
        Err(e) => {
            if should_ignore_invalid_pegin_data(&e, instance_id) {
                return Ok(());
            }
            bail!(e)
        }
    };
    let pegin_deposit_txid = instance_params.build_pegin_tx()?.0.tx().compute_txid();
    if !tx_on_chain(ctx.btc_client, &pegin_deposit_txid).await? {
        tracing::warn!(
            "Ignore ConfirmInstance for {instance_id}: pegin deposit tx {pegin_deposit_txid} not found on chain"
        );
        return Ok(());
    }
    // 2. save the instance data to local db
    store_instance_parameters(ctx.local_db, &instance_params).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_create_graph_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    graph: &SimplifiedBitvm2Graph,
) -> Result<()> {
    // received from Operator
    // 1. check graph data & operator stake
    if let Err(e) =
        todo_funcs::validate_init_graph(ctx.local_db, ctx.btc_client, ctx.goat_client, graph).await
    {
        if should_ignore_invalid_graph(&e, instance_id, graph_id, "CreateGraph", None) {
            return Ok(());
        }
        bail!(e)
    };
    // 2. save the graph data to local db
    store_graph(ctx.local_db, graph).await?;
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
    send_to_peer(ctx.swarm, GOATMessage::new(Actor::All, message_content)).await?;
    store_committee_pub_nonces_for_graph(
        ctx.local_db,
        instance_id,
        graph_id,
        local_committee_pubkey,
        pub_nonces,
    )
    .await?;
    // 4. if collected enough pub_nonces, generate partial signatures & broadcast CommitteePresign
    let committee_pubkeys = ctx.goat_client.gateway_get_committee_pubkeys(&instance_id).await?;
    let pub_nonces_unchecked =
        get_committee_pub_nonces_for_graph(ctx.local_db, instance_id, graph_id).await?;
    if pub_nonces_unchecked.len() == committee_pubkeys.len() {
        let mut graph = Bitvm2Graph::from_simplified(graph)?;
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
        send_to_peer(ctx.swarm, GOATMessage::new(Actor::All, message_content)).await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_nonce_generation_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    received_committee_pubkey: &PublicKey,
    watchtower_num: usize,
    assert_commit_num: usize,
    pub_nonces: &CommitteePubNonces,
    nonce_sigs: &CommitteeNonceSignatures,
    content: &GOATMessageContent,
) -> Result<()> {
    // received from Committee members
    if !ensure_self_or_valid_committee(
        ctx,
        instance_id,
        Some(graph_id),
        received_committee_pubkey,
        "NonceGeneration",
    )
    .await?
    {
        return Ok(());
    }
    // 1. check pub_nonces & nonce signatures
    let committee_xonly_pubkey = XOnlyPublicKey::from(*received_committee_pubkey);
    if !verify_nonce_signatures(
        &committee_xonly_pubkey,
        pub_nonces,
        nonce_sigs,
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
        ctx.local_db,
        instance_id,
        graph_id,
        *received_committee_pubkey,
        pub_nonces.clone(),
    )
    .await?;
    // 3. if received enough pub_nonces, generate partial signatures & broadcast CommitteePresign
    let committee_pubkeys = ctx.goat_client.gateway_get_committee_pubkeys(&instance_id).await?;
    let pub_nonces_unchecked =
        get_committee_pub_nonces_for_graph(ctx.local_db, instance_id, graph_id).await?;
    if pub_nonces_unchecked.len() == committee_pubkeys.len() {
        let local_committee_pubkey = CommitteeMasterKey::new(get_bitvm_key()?)
            .keypair_for_instance(instance_id)
            .public_key()
            .into();
        let message = make_message(ctx, content);
        let graph = match get_graph_or_defer(
            ctx.swarm,
            ctx.local_db,
            ctx.goat_client,
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
        // 4. if received enough valid committee partial sigs, endorse the graph
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
        send_to_peer(ctx.swarm, GOATMessage::new(Actor::All, message_content)).await?;
        store_committee_partial_sigs_for_graph(
            ctx.local_db,
            instance_id,
            graph_id,
            local_committee_pubkey,
            committee_partial_sigs,
        )
        .await?;
        let committee_partial_sigs =
            get_committee_partial_sigs_for_graph(ctx.local_db, instance_id, graph_id)
                .await?
                .into_iter()
                .map(|(_, ps)| ps)
                .collect::<Vec<_>>();
        if committee_partial_sigs.len() == committee_pubkeys.len() {
            let committee_sig_for_graph = endorse_graph(ctx.goat_client, &graph).await?;
            let committee_evm_address = get_node_goat_address()
                .ok_or_else(|| anyhow::anyhow!("failed to get node goat address".to_string()))?;
            let message_content = GOATMessageContent::EndorseGraph(EndorseGraph {
                instance_id,
                graph_id,
                committee_pubkey: local_committee_pubkey,
                committee_sig_for_graph: committee_sig_for_graph.as_bytes().to_vec(),
                committee_evm_address,
            });
            send_to_peer(ctx.swarm, GOATMessage::new(Actor::All, message_content)).await?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_nonce_generation_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    received_committee_pubkey: &PublicKey,
    watchtower_num: usize,
    assert_commit_num: usize,
    pub_nonces: &CommitteePubNonces,
    nonce_sigs: &CommitteeNonceSignatures,
) -> Result<()> {
    // received from Committee members
    if !ensure_self_or_valid_committee(
        ctx,
        instance_id,
        Some(graph_id),
        received_committee_pubkey,
        "NonceGeneration",
    )
    .await?
    {
        return Ok(());
    }
    // 1. check pub_nonces & nonce signatures
    let committee_xonly_pubkey = XOnlyPublicKey::from(*received_committee_pubkey);
    if !verify_nonce_signatures(
        &committee_xonly_pubkey,
        pub_nonces,
        nonce_sigs,
        watchtower_num,
        assert_commit_num,
    )? {
        tracing::warn!(
            "Ignore NonceGeneration for {instance_id}:{graph_id} from {}: invalid pub_nonces or nonce_sigs",
            received_committee_pubkey.to_string()
        );
        return Ok(());
    }
    let graph = match get_graph(ctx.local_db, instance_id, graph_id).await? {
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
        ctx.local_db,
        instance_id,
        graph_id,
        *received_committee_pubkey,
        pub_nonces.clone(),
    )
    .await?;
    // 3. if received enough endorsement signatures, mark the graph as endorsed, send the graph to local db, broadcast GraphFinalize
    // Operator may receive EndorseGraph, CommitteePresign or NonceGeneration messages in any order
    // So we need to check if we have collected enough endorsements, pub_nonces and partial_sigs every time we receive them
    try_finalize_graph(
        ctx.swarm,
        ctx.local_db,
        ctx.goat_client,
        instance_id,
        graph_id,
        Some(&graph),
        true,
    )
    .await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_committee_presign_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    received_committee_pubkey: &PublicKey,
    committee_partial_sigs: &CommitteePartialSignatures,
    _agg_nonces: &CommitteeAggNonces,
    content: &GOATMessageContent,
) -> Result<()> {
    // received from Committee members
    if !ensure_self_or_valid_committee(
        ctx,
        instance_id,
        Some(graph_id),
        received_committee_pubkey,
        "CommitteePresign",
    )
    .await?
    {
        return Ok(());
    }
    // 1. save the committee partial sigs to local db
    // TODO: validate the partial sigs
    store_committee_partial_sigs_for_graph(
        ctx.local_db,
        instance_id,
        graph_id,
        *received_committee_pubkey,
        committee_partial_sigs.clone(),
    )
    .await?;
    // 2. if received enough valid committee partial sigs, endorse the graph
    let committee_pubkeys = ctx.goat_client.gateway_get_committee_pubkeys(&instance_id).await?;
    let committee_partial_sigs =
        get_committee_partial_sigs_for_graph(ctx.local_db, instance_id, graph_id)
            .await?
            .into_iter()
            .map(|(_, ps)| ps)
            .collect::<Vec<_>>();
    if committee_partial_sigs.len() == committee_pubkeys.len() {
        let message = make_message(ctx, content);
        let graph = match get_graph_or_defer(
            ctx.swarm,
            ctx.local_db,
            ctx.goat_client,
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
        let committee_sig_for_graph = endorse_graph(ctx.goat_client, &graph).await?;
        let local_committee_pubkey = CommitteeMasterKey::new(get_bitvm_key()?)
            .keypair_for_instance(instance_id)
            .public_key()
            .into();
        let committee_evm_address = get_node_goat_address()
            .ok_or_else(|| anyhow::anyhow!("failed to get node goat address".to_string()))?;
        let message_content = GOATMessageContent::EndorseGraph(EndorseGraph {
            instance_id,
            graph_id,
            committee_pubkey: local_committee_pubkey,
            committee_sig_for_graph: committee_sig_for_graph.as_bytes().to_vec(),
            committee_evm_address,
        });
        send_to_peer(ctx.swarm, GOATMessage::new(Actor::All, message_content)).await?;
    }
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_committee_presign_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    received_committee_pubkey: &PublicKey,
    committee_partial_sigs: &CommitteePartialSignatures,
    _agg_nonces: &CommitteeAggNonces,
) -> Result<()> {
    // received from Committee members
    if !ensure_self_or_valid_committee(
        ctx,
        instance_id,
        Some(graph_id),
        received_committee_pubkey,
        "CommitteePresign",
    )
    .await?
    {
        return Ok(());
    }
    // 1. save the committee partial sigs to local db
    // TODO: validate the partial sigs
    store_committee_partial_sigs_for_graph(
        ctx.local_db,
        instance_id,
        graph_id,
        *received_committee_pubkey,
        committee_partial_sigs.clone(),
    )
    .await?;
    // 3. if received enough endorsement signatures, mark the graph as endorsed, send the graph to local database, broadcast GraphFinalize
    // Operator may receive EndorseGraph, CommitteePresign or NonceGeneration messages in any order
    // So we need to check if we have collected enough endorsements, pub_nonces and partial_sigs every time we receive them
    try_finalize_graph(ctx.swarm, ctx.local_db, ctx.goat_client, instance_id, graph_id, None, true)
        .await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_endorse_graph_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    received_committee_pubkey: &PublicKey,
    committee_sig_for_graph: &[u8],
    committee_evm_address: &alloy::primitives::Address,
) -> Result<()> {
    // received from Committee members
    if !ensure_self_or_valid_committee_with_evm(
        ctx,
        instance_id,
        Some(graph_id),
        received_committee_pubkey,
        committee_evm_address,
        "EndorseGraph",
    )
    .await?
    {
        return Ok(());
    }
    // 1. check endorsement signature
    let graph = match get_graph(ctx.local_db, instance_id, graph_id).await? {
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
        ctx.goat_client,
        committee_evm_address,
        &full_graph,
        committee_sig_for_graph,
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
        ctx.local_db,
        instance_id,
        graph_id,
        *received_committee_pubkey,
        *committee_evm_address,
        committee_sig_for_graph.to_owned(),
    )
    .await?;
    // 3. if received enough endorsement signatures, mark the graph as endorsed, send the graph to local database, broadcast GraphFinalize
    // Operator may receive EndorseGraph, CommitteePresign or NonceGeneration messages in any order
    // So we need to check if we have collected enough endorsements, pub_nonces and partial_sigs every time we receive them
    try_finalize_graph(
        ctx.swarm,
        ctx.local_db,
        ctx.goat_client,
        instance_id,
        graph_id,
        Some(&graph),
        true,
    )
    .await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_graph_finalize_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    graph: &SimplifiedBitvm2Graph,
    endorse_sigs: &[(PublicKey, alloy::primitives::Address, Vec<u8>)],
) -> Result<()> {
    // received from Operator
    // 1. check graph data
    if let Err(e) = todo_funcs::validate_finalized_graph(ctx.goat_client, graph, endorse_sigs).await
    {
        if should_ignore_invalid_graph(
            &e,
            instance_id,
            graph_id,
            "GraphFinalize",
            Some(&ctx.from_peer_id),
        ) {
            return Ok(());
        }
        bail!(e)
    }
    // 2. save the graph data to local db
    store_graph(ctx.local_db, graph).await?;
    store_committee_endorsements_for_graph(
        ctx.local_db,
        instance_id,
        graph_id,
        endorse_sigs.to_owned(),
    )
    .await?;
    // After storing, mark the graph as endorsed
    mark_graph_as_endorsed(ctx.local_db, instance_id, graph_id).await?;
    // 3. if endorsed graph count >= threshold, generate & broadcast PeginConfirmNonce
    if get_endorsed_graph_count(ctx.local_db, instance_id).await?
        >= todo_funcs::min_required_operator()
    {
        let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
        let local_committee_pubkey =
            committee_master_key.keypair_for_instance(instance_id).public_key().into();
        let stored_pub_nonce = get_committee_pub_nonce_for_instance(
            ctx.local_db,
            instance_id,
            &local_committee_pubkey,
        )
        .await?;
        if stored_pub_nonce.is_none() {
            let (_, pub_nonce, nonce_sig) = committee_master_key.nonce_for_instance(instance_id);
            let message_content = GOATMessageContent::PeginConfirmNonce(PeginConfirmNonce {
                instance_id,
                committee_pubkey: local_committee_pubkey,
                pub_nonce: pub_nonce.clone(),
                nonce_sig,
            });
            send_to_peer(ctx.swarm, GOATMessage::new(Actor::Committee, message_content)).await?;
            store_committee_pub_nonce_for_instance(
                ctx.local_db,
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
        let pegin_data = ctx.goat_client.gateway_get_pegin_data(&instance_id).await?;
        if pegin_data.status != PeginStatus::Withdrawable {
            // pegin not posted yet
            return Ok(());
        }
        let graph_data = ctx.goat_client.gateway_get_graph_data(&graph_id).await?;
        if graph_data.operator_pubkey != [0u8; 32] {
            // already posted
            return Ok(());
        }
        let graph = Bitvm2Graph::from_simplified(graph)?;
        let graph_data = build_graph_data(&graph)?;
        let endorse_sigs = endorse_sigs.iter().map(|(_, _, sig)| sig.clone()).collect::<Vec<_>>();
        ctx.goat_client
            .gateway_post_graph_data(&instance_id, &graph_id, &graph_data, &endorse_sigs)
            .await?;
    }
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_graph_finalize_default(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    graph: &SimplifiedBitvm2Graph,
    endorse_sigs: &[(PublicKey, alloy::primitives::Address, Vec<u8>)],
) -> Result<()> {
    // received from Operator
    // 1. check graph data
    if let Err(e) = todo_funcs::validate_finalized_graph(ctx.goat_client, graph, endorse_sigs).await
    {
        if should_ignore_invalid_graph(
            &e,
            instance_id,
            graph_id,
            "GraphFinalize",
            Some(&ctx.from_peer_id),
        ) {
            return Ok(());
        }
        bail!(e)
    }
    // 2. save the graph data to local db
    store_graph(ctx.local_db, graph).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id))]
async fn handle_pegin_confirm_nonce_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    received_committee_pubkey: &PublicKey,
    pub_nonce: &musig2::PubNonce,
    nonce_sig: &secp256k1::schnorr::Signature,
) -> Result<()> {
    // received from Committee members
    if !ensure_self_or_valid_committee(
        ctx,
        instance_id,
        None,
        received_committee_pubkey,
        "PeginConfirmNonce",
    )
    .await?
    {
        return Ok(());
    }
    // 1. check pub_nonce
    if !verify_public_nonce(nonce_sig, pub_nonce, &XOnlyPublicKey::from(*received_committee_pubkey))
    {
        tracing::warn!(
            "Ignore PeginConfirmNonce for {instance_id} from {}: invalid pub_nonce or nonce_sig",
            received_committee_pubkey.to_string()
        );
        return Ok(());
    }
    // 2. save the pub_nonce to local db
    store_committee_pub_nonce_for_instance(
        ctx.local_db,
        instance_id,
        *received_committee_pubkey,
        pub_nonce.clone(),
    )
    .await?;
    // 3. if received enough pub_nonces, generate partial signature & broadcast PeginConfirmPartialSig
    let committee_pubkeys = ctx.goat_client.gateway_get_committee_pubkeys(&instance_id).await?;
    let pub_nonces = get_committee_pub_nonces_for_instance(ctx.local_db, instance_id).await?;
    if pub_nonces.len() == committee_pubkeys.len() {
        let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
        let local_committee_pubkey =
            committee_master_key.keypair_for_instance(instance_id).public_key().into();
        let (sec_nonce, _, _) = committee_master_key.nonce_for_instance(instance_id);
        let agg_nonce =
            nonce_aggregation(&pub_nonces.iter().map(|(_, pn)| pn.clone()).collect::<Vec<_>>());
        let instance_params = get_instance_parameters(ctx.local_db, instance_id)
            .await?
            .ok_or_else(|| anyhow!("Instance parameters not found for {instance_id}"))?;
        let mut pegin_confirm = instance_params.build_pegin_tx()?.1;
        let context = instance_params
            .get_verifier_context(committee_master_key.keypair_for_instance(instance_id))?;
        let partial_sig = pegin_confirm
            .sign_input_0_musig2(&context, &sec_nonce, &agg_nonce)
            .map_err(|e| anyhow!("Failed to sign pegin confirm for {instance_id}: {e}"))?;
        let endorse_sig =
            endorse_pegin(ctx.goat_client, instance_id, &pegin_confirm.tx().compute_txid()).await?;
        let message_content = GOATMessageContent::PeginConfirmPartialSig(PeginConfirmPartialSig {
            instance_id,
            committee_pubkey: local_committee_pubkey,
            partial_sig,
            endorse_sig: endorse_sig.as_bytes().to_vec(),
        });
        send_to_peer(ctx.swarm, GOATMessage::new(Actor::Committee, message_content)).await?;
        store_committee_partial_sig_for_instance(
            ctx.local_db,
            instance_id,
            local_committee_pubkey,
            partial_sig,
        )
        .await?;
        store_committee_endorse_sig_for_pegin(
            ctx.local_db,
            instance_id,
            local_committee_pubkey,
            endorse_sig.as_bytes().to_vec(),
        )
        .await?;
        // 4. (Relayer) if received enough partial signatures, aggregate the sigs
        if is_relayer() {
            let partial_sigs = get_committee_partial_sigs_for_instance(ctx.local_db, instance_id)
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
                            "Failed to aggregate Pegin-Confirm's signatures for {instance_id}: {e}"
                        )
                    })?;
                let connector_z = ConnectorZ::new(
                    context.network,
                    &context.n_of_n_taproot_public_key,
                    &instance_params.user_info.user_xonly_pubkey,
                );
                pegin_confirm.push_input_0_signature(&connector_z, full_sig);
                broadcast_tx(ctx.btc_client, pegin_confirm.tx()).await?;
            }
        }
    }
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id))]
async fn handle_pegin_confirm_partial_sig_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    received_committee_pubkey: &PublicKey,
    partial_sig: &musig2::PartialSignature,
    endorse_sig: &[u8],
) -> Result<()> {
    // received from Committee members
    if !ensure_self_or_valid_committee(
        ctx,
        instance_id,
        None,
        received_committee_pubkey,
        "PeginConfirmPartialSig",
    )
    .await?
    {
        return Ok(());
    }
    // 1. save the partial signature & endorsement signature to local db
    // partial sigs will be validated when aggregating
    store_committee_partial_sig_for_instance(
        ctx.local_db,
        instance_id,
        *received_committee_pubkey,
        *partial_sig,
    )
    .await?;
    store_committee_endorse_sig_for_pegin(
        ctx.local_db,
        instance_id,
        *received_committee_pubkey,
        endorse_sig.to_owned(),
    )
    .await?;
    // 3. (Relayer) if received enough partial signatures, aggregate the sigs
    if is_relayer() {
        let committee_pubkeys = ctx.goat_client.gateway_get_committee_pubkeys(&instance_id).await?;
        let pub_nonces = get_committee_pub_nonces_for_instance(ctx.local_db, instance_id).await?;
        let partial_sigs = get_committee_partial_sigs_for_instance(ctx.local_db, instance_id)
            .await?
            .into_iter()
            .map(|(_, ps)| ps)
            .collect::<Vec<_>>();
        if pub_nonces.len() == committee_pubkeys.len()
            && partial_sigs.len() == committee_pubkeys.len()
        {
            let instance_params = get_instance_parameters(ctx.local_db, instance_id)
                .await?
                .ok_or_else(|| anyhow!("Instance parameters not found for {instance_id}"))?;
            let mut pegin_confirm = instance_params.build_pegin_tx()?.1;
            let agg_nonce =
                nonce_aggregation(&pub_nonces.iter().map(|(_, pn)| pn.clone()).collect::<Vec<_>>());
            let context = instance_params.get_base_context();
            let full_sig = pegin_confirm
                .aggregate_input_0_musig2_signatures(&context, partial_sigs, &agg_nonce)
                .map_err(|e| {
                    anyhow!("Failed to aggregate Pegin-Confirm's signatures for {instance_id}: {e}")
                })?;
            let connector_z = ConnectorZ::new(
                context.network,
                &context.n_of_n_taproot_public_key,
                &instance_params.user_info.user_xonly_pubkey,
            );
            pegin_confirm.push_input_0_signature(&connector_z, full_sig);
            broadcast_tx(ctx.btc_client, pegin_confirm.tx()).await?;
        }
    }
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id))]
async fn handle_post_ready(ctx: &mut HandlerContext<'_>, instance_id: Uuid) -> Result<()> {
    // triggered by PeginConfirm tx
    if !is_relayer() {
        return Ok(());
    }
    // 1. (Relayer)call Gateway.postPeginData on GoatChain
    let committee_pubkeys = ctx.goat_client.gateway_get_committee_pubkeys(&instance_id).await?;
    let pegin_data = ctx.goat_client.gateway_get_pegin_data(&instance_id).await?;
    if pegin_data.status == PeginStatus::None {
        tracing::warn!("Ignore PostReady for {instance_id}: not a pending pegin request");
        return Ok(());
    } else if pegin_data.status == PeginStatus::Pending {
        let instance_params = get_instance_parameters(ctx.local_db, instance_id)
            .await?
            .ok_or_else(|| anyhow!("Instance parameters not found for {instance_id}"))?;
        let pegin_confirm = instance_params.build_pegin_tx()?.1;
        let pegin_txid = pegin_confirm.tx().compute_txid();
        let pegin_tx = match ctx.btc_client.get_tx(&pegin_txid).await? {
            Some(tx) => tx,
            None => {
                tracing::warn!(
                    "Ignore PostReady for {instance_id}: Pegin-Confirm transaction not found on Bitcoin: {pegin_txid}"
                );
                return Ok(());
            }
        };
        let endorse_sigs = get_committee_endorse_sigs_for_pegin(ctx.local_db, instance_id)
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
        let pegin_height = match ctx.btc_client.get_tx_status(&pegin_txid).await?.block_height {
            Some(height) => height as u64,
            None => {
                let delay_secs = todo_funcs::avg_block_time_secs(ctx.btc_client.network());
                let message = GOATMessage::new(
                    ctx.actor.clone(),
                    GOATMessageContent::PostReady(PostReady { instance_id }),
                );
                push_local_unhandled_messages(
                    ctx.local_db,
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
        let goat_confirmed_height = ctx.goat_client.btc_spv_latest_height().await?;
        if goat_confirmed_height < pegin_height {
            let delay_secs = todo_funcs::avg_block_time_secs(ctx.btc_client.network())
                * (pegin_height - goat_confirmed_height);
            let message = GOATMessage::new(
                ctx.actor.clone(),
                GOATMessageContent::PostReady(PostReady { instance_id }),
            );
            push_local_unhandled_messages(ctx.local_db, instance_id, &message, delay_secs as usize)
                .await?;
            tracing::info!(
                "Retry postPeginData later for {instance_id}: pegin confirm tx block not posted to goat spv contract yet"
            );
            return Ok(());
        }
        ctx.goat_client
            .gateway_post_pegin_data(ctx.btc_client, &instance_id, &pegin_tx, &endorse_sigs)
            .await?;
    } else {
        // already posted
    }
    // 2. (Relayer)call Gateway.postGraphData on GoatChain
    let graph_ids = get_graph_ids_for_instance(ctx.local_db, instance_id).await?;
    for graph_id in &graph_ids {
        let graph_data = ctx.goat_client.gateway_get_graph_data(graph_id).await?;
        if graph_data.operator_pubkey != [0u8; 32] {
            // already posted
            continue;
        }
        let endorsement_sigs =
            get_committee_endorsements_for_graph(ctx.local_db, instance_id, *graph_id)
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
        let graph = get_graph(ctx.local_db, instance_id, *graph_id)
            .await?
            .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
        let graph = Bitvm2Graph::from_simplified(&graph)?;
        let graph_data = build_graph_data(&graph)?;
        ctx.goat_client
            .gateway_post_graph_data(&instance_id, graph_id, &graph_data, &endorsement_sigs)
            .await?;
    }
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_kickoff_ready_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by InitWithdraw event from GoatChain
    let message = make_message(ctx, content);
    let graph = match get_graph_or_defer(
        ctx.swarm,
        ctx.local_db,
        ctx.goat_client,
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
    let withdraw_status = ctx.goat_client.gateway_get_withdraw_data(&graph_id).await?.status;
    if withdraw_status != WithdrawStatus::Initialized {
        tracing::warn!(
            "Ignore KickoffReady for {instance_id}:{graph_id}: invalid withdraw status: {withdraw_status:?}"
        );
        return Ok(());
    }
    // 2. check prekickoff nonce & broadcast previous pre-kickoff if needed
    let start_nonce =
        match get_latest_pegout_finalized_graph(ctx.local_db, &operator_pubkey).await? {
            Some((n, _)) => n + 1,
            None => 0,
        };
    for current_nonce in start_nonce..graph.parameters.graph_nonce {
        let (current_instance_id, current_graph_id) = match get_graph_id_by_nonce(
            ctx.local_db,
            current_nonce,
            &operator_pubkey,
        )
        .await?
        {
            Some(v) => v,
            None => {
                tracing::warn!(
                    "Ignore KickoffReady for {instance_id}:{graph_id}: missing previous graph {current_nonce}"
                );
                return Ok(());
            }
        };
        let current_graph = match get_graph_or_defer(
            ctx.swarm,
            ctx.local_db,
            ctx.goat_client,
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
            get_graph_status(ctx.local_db, current_instance_id, current_graph_id)
                .await?
                .ok_or_else(|| {
                    anyhow!("Graph status not found for {current_instance_id}:{current_graph_id}")
                })?;
        let (current_graph_status, current_graph_sub_status) = refresh_graph(
            ctx.local_db,
            ctx.btc_client,
            ctx.goat_client,
            current_instance_id,
            current_graph_id,
            Some(&current_graph),
            Some(current_graph_start_status),
            None,
        )
        .await?;
        compensate_graph_events(
            ctx.local_db,
            ctx.btc_client,
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
                "Ignore KickoffReady for {instance_id}:{graph_id}: previous graph {current_graph_id} already started pegout"
            );
            let nonce_interval =
                graph.parameters.graph_nonce - current_graph.parameters.graph_nonce;
            let min_pegout_time_secs = take1_timelock(ctx.btc_client.network()) as u64
                * todo_funcs::avg_block_time_secs(ctx.btc_client.network());
            let delay_secs = min_pegout_time_secs * nonce_interval;
            push_local_unhandled_messages(
                ctx.local_db,
                current_graph_id,
                &message,
                delay_secs as usize,
            )
            .await?;
            return Ok(());
        } else if current_graph_status.is_obsoleted() {
            operator_skip_graph(ctx.btc_client, &mut current_graph).await?;
            tracing::info!(
                "Operator {operator_pubkey} skipped obsoleted graph {current_instance_id}:{current_graph_id}"
            );
            let delay_secs = todo_funcs::avg_block_time_secs(ctx.btc_client.network()); // wait for 1 blocks
            push_local_unhandled_messages(
                ctx.local_db,
                current_graph_id,
                &message,
                delay_secs as usize,
            )
            .await?;
            return Ok(());
        } else {
            let graph_data_on_goat =
                ctx.goat_client.gateway_get_graph_data(&current_graph_id).await?;
            if graph_data_on_goat.operator_pubkey != [0u8; 32] {
                tracing::warn!(
                    "Ignore KickoffReady for {instance_id}:{graph_id}: previous available graph exists for Operator {operator_pubkey}: {current_instance_id}:{current_graph_id}, please withdraw it first"
                );
                let nonce_interval =
                    graph.parameters.graph_nonce - current_graph.parameters.graph_nonce;
                let min_pegout_time_secs = take1_timelock(ctx.btc_client.network()) as u64
                    * todo_funcs::avg_block_time_secs(ctx.btc_client.network());
                let delay_secs = min_pegout_time_secs * nonce_interval;
                push_local_unhandled_messages(
                    ctx.local_db,
                    current_graph_id,
                    &message,
                    delay_secs as usize,
                )
                .await?;
                return Ok(());
            } else {
                operator_skip_graph(ctx.btc_client, &mut current_graph).await?;
                tracing::info!(
                    "Operator {operator_pubkey} skipped non-posted graph {current_instance_id}:{current_graph_id}"
                );
                let delay_secs = todo_funcs::avg_block_time_secs(ctx.btc_client.network()); // wait for 1 blocks
                push_local_unhandled_messages(
                    ctx.local_db,
                    current_graph_id,
                    &message,
                    delay_secs as usize,
                )
                .await?;
                return Ok(());
            }
        }
    }
    // 3. sign & broadcast prekickoff & kickoff txns
    operator_kickoff(ctx.btc_client, &mut graph).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_kickoff_sent_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by Kickoff tx
    // 1. update status
    let (graph, _graph_status, _graph_sub_status) =
        match refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::OperatorKickOff)
            .await?
        {
            Some(v) => v,
            None => return Ok(()),
        };
    if !is_relayer() {
        return Ok(());
    }
    // 2. (Relayer) try to call Gateway.proceedWithdraw
    let withdraw_status = ctx.goat_client.gateway_get_withdraw_data(&graph_id).await?.status;
    if withdraw_status != WithdrawStatus::Initialized {
        tracing::warn!(
            "Ignore KickoffSent for {instance_id}:{graph_id}: invalid withdraw status: {withdraw_status:?}"
        );
        return Ok(());
    }
    let kickoff_txid = graph.kickoff.tx().compute_txid();
    let kickoff_tx = match ctx.btc_client.get_tx(&kickoff_txid).await? {
        Some(tx) => tx,
        None => {
            tracing::warn!(
                "Ignore KickoffSent for {instance_id}:{graph_id}: kickoff tx not found on chain: {kickoff_txid}"
            );
            return Ok(());
        }
    };
    let kickoff_height = match ctx.btc_client.get_tx_status(&kickoff_txid).await?.block_height {
        Some(height) => height as u64,
        None => {
            let delay_secs = todo_funcs::avg_block_time_secs(ctx.btc_client.network());
            let message = make_message(ctx, content);
            push_local_unhandled_messages(ctx.local_db, graph_id, &message, delay_secs as usize)
                .await?;
            tracing::info!(
                "Retry proceedWithdraw later for {instance_id}:{graph_id}: kickoff tx not confirmed on btc yet"
            );
            return Ok(());
        }
    };
    let goat_confirmed_btc_height = ctx.goat_client.btc_spv_latest_height().await?;
    if goat_confirmed_btc_height < kickoff_height {
        let delay_secs = todo_funcs::avg_block_time_secs(ctx.btc_client.network())
            * (kickoff_height - goat_confirmed_btc_height);
        let message = make_message(ctx, content);
        push_local_unhandled_messages(ctx.local_db, graph_id, &message, delay_secs as usize)
            .await?;
        tracing::info!(
            "Retry proceedWithdraw later for {instance_id}:{graph_id}: kickoff tx block not posted to goat spv contract yet"
        );
        return Ok(());
    }
    ctx.goat_client.gateway_process_withdraw(ctx.btc_client, &graph_id, &kickoff_tx).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_kickoff_sent_challenger(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by Kickoff tx
    let message = make_message(ctx, content);
    let (graph, _graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::OperatorKickOff,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    // 1. check kickoff tx status on Bitcoin chain
    let kickoff_txid = graph.kickoff.tx().compute_txid();
    let kickoff_height = match ctx.btc_client.get_tx_status(&kickoff_txid).await?.block_height {
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
        ctx.btc_client,
        &kickoff_challenge_outpoint.txid,
        kickoff_challenge_outpoint.vout as u64,
    )
    .await?
    {
        let spent_tx_name = if spent_txid == take1_txid { "Take1" } else { "Challenge" };
        tracing::warn!(
            "Ignore KickoffSent for {instance_id}:{graph_id}: challenge connector already spent by {spent_tx_name} tx: {spent_txid}"
        );
        return Ok(());
    }
    // 2. check withdraw status, if it's invalid, sign & broadcast challenge txn
    let withdraw_status = ctx.goat_client.gateway_get_withdraw_data(&graph_id).await?.status;
    let goat_confirmed_btc_height = ctx.goat_client.btc_spv_latest_height().await? as u32;
    if [WithdrawStatus::None, WithdrawStatus::Canceled].contains(&withdraw_status) {
        if kickoff_height >= goat_confirmed_btc_height {
            tracing::warn!(
                "Ignore KickoffSent for {instance_id}:{graph_id}: kickoff tx not confirmed by goat spv yet"
            );
            return Ok(());
        } else {
            let (challenge_tx, _) = export_challenge_tx(&graph).unwrap();
            let challenge_txid = challenge_tx.compute_txid();
            if ctx.btc_client.get_tx(&challenge_txid).await?.is_none() {
                let challenge_txid = send_challenge_tx(ctx.btc_client, &graph).await?;
                let message_content = GOATMessageContent::ChallengeSent(ChallengeSent {
                    instance_id,
                    graph_id,
                    challenge_txid,
                });
                send_to_peer(ctx.swarm, GOATMessage::new(Actor::All, message_content)).await?;
            }
        }
    } else {
        tracing::info!(
            "Ignore KickoffSent for {instance_id}:{graph_id}: withdraw already initiated, status: {withdraw_status:?}"
        );
    }
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_kickoff_sent_default(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by Kickoff tx
    let message = make_message(ctx, content);
    let _graph = refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::OperatorKickOff,
    )
    .await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_prekickoff_sent_challenger(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by PreKickoff tx
    let message = make_message(ctx, content);
    let (graph, _graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::PreKickoff,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    // 1. check the previous graph status
    if !tx_on_chain(
        ctx.btc_client,
        &graph.parameters.prekickoff_parameters.cur_prekickoff_txn.tx().compute_txid(),
    )
    .await?
    {
        tracing::warn!(
            "Ignore PreKickoffSent for {instance_id}:{graph_id}: prekickoff tx not on chain"
        );
        return Ok(());
    }
    let graph_nonce = graph.parameters.graph_nonce;
    if graph_nonce == 0 {
        return Ok(());
    }
    let (prev_instance_id, prev_graph_id) =
        get_graph_id_by_nonce(ctx.local_db, graph_nonce - 1, &graph.parameters.operator_pubkey)
            .await?
            .ok_or_else(|| anyhow!("Prev graph not found for {instance_id}:{graph_id}"))?;
    let prev_graph = match get_graph_or_defer(
        ctx.swarm,
        ctx.local_db,
        ctx.goat_client,
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
    let prev_graph_start_status = get_graph_status(ctx.local_db, prev_instance_id, prev_graph_id)
        .await?
        .ok_or_else(|| anyhow!("Graph status not found for {prev_instance_id}:{prev_graph_id}"))?;
    let (prev_graph_status, _prev_graph_sub_status) = refresh_and_compensate(
        ctx,
        prev_instance_id,
        prev_graph_id,
        Some(&prev_graph),
        Some(prev_graph_start_status),
        prev_graph_start_status,
    )
    .await?;
    if !tx_on_chain(ctx.btc_client, &prev_graph.kickoff.tx().compute_txid()).await? {
        // 2. if previous kickoff not started, broadcast force-skip-kickoff txn
        challenger_force_skip_kickoff(ctx.btc_client, &prev_graph).await?;
    } else if !prev_graph_status.is_closed() {
        // 3. if previous kickoff is not closed, broadcast quick-challenge/challenge-incomplete-kickoff txn
        challenger_quick_challenge(ctx.btc_client, &prev_graph).await?;
    }
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_prekickoff_sent_default(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<()> {
    // triggered by PreKickoff tx
    let _graph =
        refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::PreKickoff).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_challenge_sent_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    challenge_txid: Txid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by Challenge tx
    let message = make_message(ctx, content);
    let (mut graph, _graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::Challenge,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    // 1. check the challenge tx status on Bitcoin chain
    let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
    if tx_on_chain(ctx.btc_client, &watchtower_challenge_init_txid).await? {
        tracing::warn!(
            "Ignore ChallengeSent for {instance_id}:{graph_id}: watchtower challenge init already sent"
        );
        return Ok(());
    }
    let kickoff_txid = graph.kickoff.tx().compute_txid();
    if let Some(challenge_tx) = ctx.btc_client.get_tx(&challenge_txid).await? {
        let challenge_outpoint = OutPoint { txid: kickoff_txid, vout: 0 };
        if challenge_tx.input[0].previous_output != challenge_outpoint {
            tracing::warn!(
                "Ignore ChallengeSent for {instance_id}:{graph_id}: invalid challenge tx input"
            );
            return Ok(());
        }
    } else {
        tracing::warn!(
            "Ignore ChallengeSent for {instance_id}:{graph_id}: challenge tx not found on chain"
        );
        return Ok(());
    }
    // 2. if the challenge is confirmed, sign & broadcast watchtower-challenge-init txn
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let watchtower_challenge_init_tx =
        operator_sign_watchtower_challenge_init(operator_master_key.master_keypair(), &mut graph)?;
    let anchor_vout = watchtower_challenge_init_tx.output.len() as u64 - 1;
    let watchtower_challenge_init_tx_total_input_amount =
        graph.watchtower_challenge_init.prev_outs().iter().map(|o| o.value).sum();
    let child_tx = build_cpfp_txns(
        ctx.btc_client,
        &watchtower_challenge_init_tx,
        anchor_vout,
        watchtower_challenge_init_tx_total_input_amount,
    )
    .await?;
    match child_tx {
        Some(tx) => {
            broadcast_package(ctx.btc_client, &[watchtower_challenge_init_tx, tx], true).await?
        }
        None => broadcast_tx(ctx.btc_client, &watchtower_challenge_init_tx).await?,
    };
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_challenge_sent_default(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<()> {
    // triggered by Challenge tx
    let _graph =
        refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::Challenge).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_watchtower_challenge_init_sent_watchtower(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by WatchtowerChallengeInit tx
    let message = make_message(ctx, content);
    let (graph, graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::Challenge,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    if graph_status != GraphStatus::Challenge {
        tracing::warn!(
            "Ignore WatchtowerChallengeInitSent for {instance_id}:{graph_id}: graph status is {graph_status:?}"
        );
        return Ok(());
    }
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
                "Ignore WatchtowerChallengeInitSent for {instance_id}:{graph_id}: node not a watchtower"
            );
            return Ok(());
        }
    };
    let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
    if !tx_on_chain(ctx.btc_client, &watchtower_challenge_init_txid).await? {
        tracing::warn!(
            "Ignore WatchtowerChallengeInitSent for {instance_id}:{graph_id}: watchtower challenge init not on chain"
        );
        return Ok(());
    }
    if outpoint_spent_txid(ctx.btc_client, &watchtower_challenge_init_txid, 2 * node_index as u64)
        .await?
        .is_some()
    {
        tracing::warn!(
            "Ignore WatchtowerChallengeInitSent for {instance_id}:{graph_id}: watchtower challenge already spent"
        );
        return Ok(());
    }
    // 1. check the withdraw status on GoatChain, if the withdraw is invalid, sign & broadcast watchtower-challenge txn
    let withdraw_status = ctx.goat_client.gateway_get_withdraw_data(&graph_id).await?.status;
    if crate::env::should_always_challenge()
        || [WithdrawStatus::None, WithdrawStatus::Canceled].contains(&withdraw_status)
    {
        let watchtower_proof = match get_watchtower_commitment(
            ctx.local_db,
            ctx.btc_client,
            ctx.http_client,
            instance_id,
            graph_id,
        )
        .await?
        {
            (Some(p), _) => p,
            (None, wait_secs) => {
                tracing::warn!(
                    "Retry WatchtowerChallengeInitSent for {instance_id}:{graph_id} later: watchtower proof not ready, retry after {wait_secs} seconds"
                );
                push_local_unhandled_messages(ctx.local_db, graph_id, &message, wait_secs).await?;
                return Ok(());
            }
        };
        let watchtower_challenge_txid = match send_watchtower_challenge_tx(
            ctx.btc_client,
            &graph,
            node_index,
            watchtower_proof,
        )
        .await
        {
            Ok(txid) => txid,
            Err(e) => {
                tracing::warn!(
                    "Ignore WatchtowerChallengeInitSent for {instance_id}:{graph_id}: failed to send watchtower challenge tx: {e}"
                );
                return Ok(());
            }
        };
        let message_content =
            GOATMessageContent::WatchtowerChallengeSent(WatchtowerChallengeSent {
                instance_id,
                graph_id,
                watchtower_challenge_txids: vec![(node_index, watchtower_challenge_txid)],
            });
        send_to_peer(ctx.swarm, GOATMessage::new(Actor::All, message_content)).await?;
    }
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_watchtower_challenge_sent_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    watchtower_challenge_txids: &Vec<(usize, Txid)>,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by WatchtowerChallenge tx
    let message = make_message(ctx, content);
    // 1. check the watchtower-challenge tx status on Bitcoin chain, if watchtower challenge tx is confirmed, sign & broadcast operator-ack txn
    let (mut graph, graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::Challenge,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    if graph_status != GraphStatus::Challenge {
        tracing::warn!(
            "Ignore WatchtowerChallengeSent for {instance_id}:{graph_id}: graph status is {graph_status:?}"
        );
        return Ok(());
    }
    let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let operator_graph_keypair = operator_master_key.master_keypair();
    let operator_master_keypair = operator_master_key.master_keypair();
    for (watchtower_index, watchtower_challenge_txid) in watchtower_challenge_txids {
        tracing::info!(
            "Handle WatchtowerChallengeSent for {instance_id}:{graph_id}, watchtower index: {watchtower_index}, watchtower challenge txid: {watchtower_challenge_txid}"
        );
        let watchtower_challenge_tx = match ctx.btc_client.get_tx(watchtower_challenge_txid).await?
        {
            Some(tx) => tx,
            None => {
                tracing::warn!(
                    "Ignore WatchtowerChallengeSent for {instance_id}:{graph_id}: watchtower challenge tx not found on chain: {watchtower_challenge_txid}"
                );
                continue;
            }
        };
        let watchtower_challenge_outpoint =
            OutPoint { txid: watchtower_challenge_init_txid, vout: 2 * *watchtower_index as u32 };
        if watchtower_challenge_tx.input[0].previous_output != watchtower_challenge_outpoint {
            tracing::warn!(
                "Ignore WatchtowerChallengeSent for {instance_id}:{graph_id}: invalid watchtower challenge tx input"
            );
            continue;
        }
        let preimage =
            todo_funcs::get_preimage(ctx.local_db, instance_id, graph_id, *watchtower_index)
                .await?;
        let (ack_txin, ack_txin_amount) =
            operator_sign_ack(operator_graph_keypair, &mut graph, *watchtower_index, &preimage)?;
        build_sign_and_broadcast_tx(
            ctx.btc_client,
            operator_master_keypair,
            vec![ack_txin],
            ack_txin_amount,
            vec![],
        )
        .await?;
    }
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_watchtower_challenge_timeout_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    watchtower_indexes: &Vec<usize>,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by timeout task
    let message = make_message(ctx, content);
    let (mut graph, graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::Challenge,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    if graph_status != GraphStatus::Challenge {
        tracing::warn!(
            "Ignore WatchtowerChallengeTimeout for {instance_id}:{graph_id}: graph status is {graph_status:?}"
        );
        return Ok(());
    }
    let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
    let watchtower_challenge_init_height = match ctx
        .btc_client
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
    let current_height = ctx.btc_client.get_height().await?;
    if current_height
        < watchtower_challenge_init_height + watchtower_challenge_timeout_timelock(get_network())
    {
        tracing::warn!(
            "Ignore WatchtowerChallengeTimeout for {instance_id}:{graph_id}: watchtower challenge timelock not expired yet"
        );
        return Ok(());
    }
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let operator_master_keypair = operator_master_key.master_keypair();
    // 1. sign & broadcast watchtower-challenge-timeout txn
    for watchtower_index in watchtower_indexes {
        tracing::info!(
            "Handle WatchtowerChallengeTimeout for {instance_id}:{graph_id}, watchtower index: {watchtower_index}"
        );
        let watchtower_challenge_vout = 2 * *watchtower_index as u64;
        if outpoint_spent_txid(
            ctx.btc_client,
            &watchtower_challenge_init_txid,
            watchtower_challenge_vout,
        )
        .await?
        .is_some()
        {
            tracing::warn!(
                "Ignore WatchtowerChallengeTimeout for {instance_id}:{graph_id}: watchtower challenge already spent"
            );
            continue;
        }
        let watchtower_challenge_timeout_tx = operator_sign_watchtower_challenge_timeout(
            operator_master_keypair,
            &mut graph,
            *watchtower_index,
        )?;
        let anchor_vout = watchtower_challenge_timeout_tx.output.len() as u64 - 1;
        let watchtower_challenge_timeout_tx_total_input_amount = graph
            .watchtower_challenge_timeout_txns
            .get(*watchtower_index)
            .ok_or_else(|| anyhow!("WatchtowerChallengeTimeout txn not found for {instance_id}:{graph_id}:{watchtower_index}"))?
            .prev_outs()
            .iter()
            .map(|o| o.value)
            .sum();
        let child_tx = build_cpfp_txns(
            ctx.btc_client,
            &watchtower_challenge_timeout_tx,
            anchor_vout,
            watchtower_challenge_timeout_tx_total_input_amount,
        )
        .await?;
        match child_tx {
            Some(tx) => {
                broadcast_package(ctx.btc_client, &[watchtower_challenge_timeout_tx, tx], true)
                    .await?
            }
            None => broadcast_tx(ctx.btc_client, &watchtower_challenge_timeout_tx).await?,
        };
    }
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_operator_ack_timeout_challenger(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by timeout task
    let message = make_message(ctx, content);
    let (graph, graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::Challenge,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    if graph_status != GraphStatus::Challenge {
        tracing::warn!(
            "Ignore AckTimeout for {instance_id}:{graph_id}: graph status is {graph_status:?}"
        );
        return Ok(());
    }
    let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
    let connector_f_vout = 1 + 2 * graph.parameters.watchtower_pubkeys.len() as u64;
    if outpoint_spent_txid(ctx.btc_client, &watchtower_challenge_init_txid, connector_f_vout)
        .await?
        .is_some()
    {
        tracing::warn!(
            "Ignore OperatorAckTimeout for {instance_id}:{graph_id}: connector_F already spent"
        );
        return Ok(());
    }
    let current_height = ctx.btc_client.get_height().await?;
    let watchtower_challenge_init_height = match ctx
        .btc_client
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
            "Ignore OperatorAckTimeout for {instance_id}:{graph_id}: nack timelock not expired yet"
        );
        return Ok(());
    }
    let mut nack_index = None;
    for watchtower_index in 0..graph.parameters.watchtower_pubkeys.len() {
        let ack_vout = 1 + 2 * watchtower_index as u64;
        if outpoint_spent_txid(ctx.btc_client, &watchtower_challenge_init_txid, ack_vout)
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
        .ok_or_else(|| anyhow!("Nack txn not found for {instance_id}:{graph_id}:{nack_index}"))?
        .finalize();
    let anchor_vout = nack_tx.output.len() as u64 - 1;
    let nack_tx_total_input_amount =
        graph.nack_txns[nack_index].prev_outs().iter().map(|o| o.value).sum();
    let child_tx =
        build_cpfp_txns(ctx.btc_client, &nack_tx, anchor_vout, nack_tx_total_input_amount).await?;
    match child_tx {
        Some(tx) => broadcast_package(ctx.btc_client, &[nack_tx, tx], true).await?,
        None => broadcast_package(ctx.btc_client, &[nack_tx], true).await?,
    };
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_operator_commit_blockhash_ready_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by timeout task
    let message = make_message(ctx, content);
    let (mut graph, graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::Challenge,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    if graph_status != GraphStatus::Challenge {
        tracing::warn!(
            "Ignore CommitBlockHashReady for {instance_id}:{graph_id}: graph status is {graph_status:?}"
        );
        return Ok(());
    }
    // 1. check that all WatchtowerChallenge Connectors are spent
    let largest_watchtower_challenge_block_hash = match get_largest_watchtower_challenge_block(
        &graph,
        ctx.btc_client,
    )
    .await
    {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(
                "Retry OperatorCommitBlockHashReady later for {instance_id}:{graph_id}: failed to get
                            largest watchtower challenge block, error: {e:?}"
            );
            push_local_unhandled_messages(
                ctx.local_db,
                graph_id,
                &message,
                todo_funcs::avg_block_time_secs(ctx.btc_client.network()) as usize,
            )
            .await?;
            return Ok(());
        }
    };
    // 2. sign & broadcast commit-blockhash txn
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let operator_graph_keypair = operator_master_key.master_keypair();
    let operator_master_keypair = operator_master_key.master_keypair();
    let wots_secret_keys = operator_master_key.wots_keypair_for_graph(graph.parameters.graph_id).0;
    let blockhash_wots_secret_key = &wots_secret_keys[0];
    let (operator_commit_blockhash_txin, operator_commit_blockhash_txin_amount) =
        operator_sign_blockhash_commit(
            operator_graph_keypair,
            &mut graph,
            &largest_watchtower_challenge_block_hash.to_byte_array(),
            blockhash_wots_secret_key,
        )?;
    build_sign_and_broadcast_tx(
        ctx.btc_client,
        operator_master_keypair,
        vec![operator_commit_blockhash_txin],
        operator_commit_blockhash_txin_amount,
        vec![],
    )
    .await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_operator_commit_blockhash_timeout_challenger(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by timeout task
    let message = make_message(ctx, content);
    let (graph, graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::Challenge,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    if graph_status != GraphStatus::Challenge {
        tracing::warn!(
            "Ignore CommitBlockHashTimeout for {instance_id}:{graph_id}: graph status is {graph_status:?}"
        );
        return Ok(());
    }
    let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
    let connector_f_vout = 1 + 2 * graph.parameters.watchtower_pubkeys.len() as u64;
    if outpoint_spent_txid(ctx.btc_client, &watchtower_challenge_init_txid, connector_f_vout)
        .await?
        .is_some()
    {
        tracing::warn!(
            "Ignore OperatorCommitBlockHashTimeout for {instance_id}:{graph_id}: connector_F already spent"
        );
        return Ok(());
    }
    let watchtower_challenge_init_height = match ctx
        .btc_client
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
    let current_height = ctx.btc_client.get_height().await?;
    if current_height
        < watchtower_challenge_init_height + commit_blockhash_timeout_timelock(get_network())
    {
        tracing::warn!(
            "Ignore OperatorCommitBlockHashTimeout for {instance_id}:{graph_id}: commit-blockhash timelock not expired yet"
        );
        return Ok(());
    }
    let connector_g_vout = 2 * graph.parameters.watchtower_pubkeys.len() as u64;
    if outpoint_spent_txid(ctx.btc_client, &watchtower_challenge_init_txid, connector_g_vout)
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
        ctx.btc_client,
        &blockhash_commit_timeout_tx,
        anchor_vout,
        blockhash_commit_timeout_tx_total_input_amount,
    )
    .await?;
    match child_tx {
        Some(tx) => {
            broadcast_package(ctx.btc_client, &[blockhash_commit_timeout_tx, tx], true).await?
        }
        None => broadcast_tx(ctx.btc_client, &blockhash_commit_timeout_tx).await?,
    };
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_assert_init_ready_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by timeout task
    let message = make_message(ctx, content);
    let (mut graph, graph_status, graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::Challenge,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    if graph_status != GraphStatus::Challenge {
        tracing::warn!(
            "Ignore AssertInitReady for {instance_id}:{graph_id}: graph status is {graph_status:?}"
        );
        return Ok(());
    }
    match graph_sub_status {
        Some(sub_status) => {
            if !sub_status.is_watchtower_challenge_success() {
                tracing::warn!(
                    "Ignore AssertInitReady for {instance_id}:{graph_id}: watchtower challenge not finished yet, sub-status {sub_status:?}"
                );
                return Ok(());
            }
        }
        None => {
            tracing::warn!(
                "Ignore AssertInitReady for {instance_id}:{graph_id}: graph sub-status is None"
            );
            return Ok(());
        }
    }
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let operator_graph_keypair = operator_master_key.master_keypair();
    let assert_init_txid = graph.assert_init.tx().compute_txid();
    // uncomment the following lines to check operator proof before sending assert-init txn
    // let (proof_opt, wait_secs) =
    //     get_operator_proof(local_db, http_client, instance_id, graph_id).await?;
    // if proof_opt.is_none() {
    //     tracing::warn!(
    //         "Retry AssertInitReady for {instance_id}:{graph_id} later: operator proof not ready, retry after {wait_secs} seconds"
    //     );
    //     push_local_unhandled_messages(local_db, graph_id, &message, wait_secs).await?;
    //     return Ok(());
    // }
    // 1. sign & broadcast assert-init txn
    if !tx_on_chain(ctx.btc_client, &assert_init_txid).await? {
        let assert_init_tx = operator_sign_assert_init(operator_graph_keypair, &mut graph)?;
        let anchor_vout = assert_init_tx.output.len() as u64 - 1;
        let assert_init_tx_total_input_amount =
            graph.assert_init.prev_outs().iter().map(|o| o.value).sum();
        let child_tx = build_cpfp_txns(
            ctx.btc_client,
            &assert_init_tx,
            anchor_vout,
            assert_init_tx_total_input_amount,
        )
        .await?;
        match child_tx {
            Some(tx) => broadcast_package(ctx.btc_client, &[assert_init_tx, tx], true).await?,
            None => broadcast_tx(ctx.btc_client, &assert_init_tx).await?,
        };
        // assert-commit should be broadcasted after assert-init is confirmed (wait for 1 block)
        let delay_secs = todo_funcs::avg_block_time_secs(ctx.btc_client.network());
        push_local_unhandled_messages(ctx.local_db, graph_id, &message, delay_secs as usize)
            .await?;
        return Ok(());
    }
    let connector_d_vout = graph.assert_commit_timeout_txns.len() as u64;
    if outpoint_spent_txid(ctx.btc_client, &assert_init_txid, connector_d_vout).await?.is_some() {
        tracing::warn!(
            "Ignore AssertInitReady for {instance_id}:{graph_id}: connector_D already spent"
        );
        return Ok(());
    }
    // 2. sign & broadcast assert-commit txns
    if !tx_confirmed(ctx.btc_client, &assert_init_txid).await? {
        // assert-commit should be broadcasted after assert-init is confirmed (wait for 1 block)
        let delay_secs = todo_funcs::avg_block_time_secs(ctx.btc_client.network());
        push_local_unhandled_messages(ctx.local_db, graph_id, &message, delay_secs as usize)
            .await?;
        return Ok(());
    } else {
        let (split_txid_opt, has_pending_fee_input, proof_wait_secs_opt) =
            operator_send_assert_commit(ctx.local_db, ctx.btc_client, ctx.http_client, &mut graph)
                .await?;
        if let Some(wait_secs) = proof_wait_secs_opt {
            tracing::warn!(
                "Retry AssertInitReady for {instance_id}:{graph_id} later: operator proof not ready, retry after {wait_secs} seconds"
            );
            push_local_unhandled_messages(ctx.local_db, graph_id, &message, wait_secs).await?;
            return Ok(());
        } else if let Some(split_txid) = split_txid_opt {
            let delay_secs = todo_funcs::avg_block_time_secs(ctx.btc_client.network()) * 2;
            tracing::warn!(
                "Retry AssertInitReady for {instance_id}:{graph_id} later: fee_inputs_split_tx {split_txid} broadcasted, retry after {delay_secs} seconds"
            );
            push_local_unhandled_messages(ctx.local_db, graph_id, &message, delay_secs as usize)
                .await?;
        } else if has_pending_fee_input {
            let delay_secs = todo_funcs::avg_block_time_secs(ctx.btc_client.network()) * 2;
            tracing::warn!(
                "Retry AssertInitReady for {instance_id}:{graph_id} later: some fee inputs are pending, retry after {delay_secs} seconds",
            );
            push_local_unhandled_messages(ctx.local_db, graph_id, &message, delay_secs as usize)
                .await?;
        }
    }
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_assert_commit_timeout_challenger(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by timeout task
    let message = make_message(ctx, content);
    let (graph, graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::Challenge,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    if graph_status != GraphStatus::Challenge {
        tracing::warn!(
            "Ignore AssertCommitTimeout for {instance_id}:{graph_id}: graph status is {graph_status:?}"
        );
        return Ok(());
    }
    let assert_init_txid = graph.assert_init.tx().compute_txid();
    let connector_d_vout = graph.assert_commit_timeout_txns.len() as u64;
    if outpoint_spent_txid(ctx.btc_client, &assert_init_txid, connector_d_vout).await?.is_some() {
        tracing::warn!(
            "Ignore AssertCommitTimeout for {instance_id}:{graph_id}: connector_D already spent"
        );
        return Ok(());
    }
    let assert_init_height = match ctx
        .btc_client
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
    let current_height = ctx.btc_client.get_height().await?;
    if current_height < assert_init_height + assert_commit_timeout_timelock(get_network()) {
        tracing::warn!(
            "Ignore AssertCommitTimeout for {instance_id}:{graph_id}: assert init tx timelock not expired yet"
        );
        return Ok(());
    }
    let mut commit_index = None;
    for i in 0..graph.assert_commit_timeout_txns.len() {
        let assert_commit_vout = i as u64;
        if outpoint_spent_txid(ctx.btc_client, &assert_init_txid, assert_commit_vout)
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
    let assert_commit_timeout_tx = graph
        .assert_commit_timeout_txns
        .get(commit_index)
        .ok_or_else(|| {
            anyhow!("AssertCommitTimeout txn not found for {instance_id}:{graph_id}:{commit_index}")
        })?
        .finalize();
    let anchor_vout = assert_commit_timeout_tx.output.len() as u64 - 1;
    let assert_commit_timeout_tx_total_input_amount =
        graph.assert_commit_timeout_txns[commit_index].prev_outs().iter().map(|o| o.value).sum();
    let child_tx = build_cpfp_txns(
        ctx.btc_client,
        &assert_commit_timeout_tx,
        anchor_vout,
        assert_commit_timeout_tx_total_input_amount,
    )
    .await?;
    match child_tx {
        Some(tx) => {
            broadcast_package(ctx.btc_client, &[assert_commit_timeout_tx, tx], true).await?
        }
        None => broadcast_tx(ctx.btc_client, &assert_commit_timeout_tx).await?,
    };
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_disprove_ready_challenger(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by AssertCommit tx or OperatorCommitBlockHash tx
    let message = make_message(ctx, content);
    let (graph, graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::Challenge,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    if graph_status != GraphStatus::Challenge {
        tracing::warn!(
            "Ignore DisproveReady for {instance_id}:{graph_id}: graph status is {graph_status:?}"
        );
        return Ok(());
    }
    // 1. get assertions committed by Operator from Bitcoin chain
    let operator_commit_blockhash_txin = {
        let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
        let connector_g_vout = 2 * graph.parameters.watchtower_pubkeys.len() as u64;
        let commit_blockhash_timeout_txid = graph.blockhash_commit_timeout.tx().compute_txid();
        match outpoint_spent_txin(ctx.btc_client, &watchtower_challenge_init_txid, connector_g_vout)
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
            match outpoint_spent_txin(ctx.btc_client, &assert_init_txid, assert_commit_vout).await?
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
        let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
        let mut txins = vec![];
        for watchtower_index in 0..graph.parameters.watchtower_pubkeys.len() {
            let ack_vout = 1 + 2 * watchtower_index as u64;
            if let Some((spent_txid, _, txin)) =
                outpoint_spent_txin(ctx.btc_client, &watchtower_challenge_init_txid, ack_vout)
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
    let vk = crate::vk::get_vk(&graph.parameters.zkm_version).await?;
    let disprove_scripts = get_disprove_scripts(&graph.parameters).await?;
    let disprove_scripts =
        disprove_scripts.try_into().map_err(|_| anyhow!("Mismatch disprove scripts num"))?;
    if let Some(disprove_witness) = verify_operator_commits(
        operator_commit_blockhash_txin,
        operator_assert_commit_txins,
        operator_ack_txins,
        graph.parameters.watchtower_pubkeys.len(),
        &vk,
        &disprove_scripts,
    )? {
        let disprover_evm_address = get_node_goat_address()
            .ok_or_else(|| anyhow::anyhow!("failed to get node goat address".to_string()))?;
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
        let challenger_master_key = ChallengerMasterKey::new(get_bitvm_key()?);
        let challenger_master_keypair = challenger_master_key.master_keypair();
        build_sign_and_broadcast_non_standard_tx(
            ctx.btc_client,
            challenger_master_keypair,
            disprove_tx,
            connector_e_input.amount,
        )
        .await?;
    } else {
        tracing::info!("All assertions valid for {instance_id}:{graph_id}, no need to disprove");
        return Ok(());
    }
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_disprove_sent_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    disprove_type: DisproveTxType,
    index: usize,
    challenge_finish_txid: Txid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by Disprove tx
    // 1. update graph status
    let message = make_message(ctx, content);
    let (graph, _graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        None,
        GraphStatus::Disprove,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    if !is_relayer() {
        return Ok(());
    }
    // 2. (Relayer) call finalizeWithdrawDisprove on GoatChain
    let withdraw_status = ctx.goat_client.gateway_get_withdraw_data(&graph_id).await?.status;
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
        outpoint_spent_txid(ctx.btc_client, &kickoff_txid, connector_a_vout).await?
    {
        if spent_txid == take1_txid {
            tracing::warn!(
                "Ignore DisproveSent for {instance_id}:{graph_id}: graph already finalized by Take1 tx: {spent_txid}"
            );
            return Ok(());
        }
        ctx.btc_client.get_tx(&spent_txid).await?
    } else {
        None
    };
    let challenge_finish_tx = match ctx.btc_client.get_tx(&challenge_finish_txid).await? {
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
            if challenge_finish_txid
                != graph
                    .assert_commit_timeout_txns
                    .get(index)
                    .ok_or_else(|| {
                        anyhow!(
                            "AssertCommitTimeout txn not found for {instance_id}:{graph_id}:{index}"
                        )
                    })?
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
            if challenge_finish_txid
                != graph
                    .nack_txns
                    .get(index)
                    .ok_or_else(|| {
                        anyhow!("Nack txn not found for {instance_id}:{graph_id}:{index}")
                    })?
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
            let connector_e_input = OutPoint { txid: kickoff_txid, vout: 3 };
            if challenge_finish_tx.input[0].previous_output != connector_e_input {
                tracing::warn!(
                    "Ignore DisproveSent for {instance_id}:{graph_id}: challenge finish tx is not a disprove txn"
                );
                return Ok(());
            }
        }
        DisproveTxType::QuickChallenge => {
            let guardian_connector_input = OutPoint { txid: kickoff_txid, vout: 4 };
            if challenge_finish_tx.input[0].previous_output != guardian_connector_input {
                tracing::warn!(
                    "Ignore DisproveSent for {instance_id}:{graph_id}: challenge finish tx is not a quick challenge txn"
                );
                return Ok(());
            }
        }
        DisproveTxType::ChallengeIncompleteKickoff => {
            let guardian_connector_input = OutPoint { txid: kickoff_txid, vout: 4 };
            if challenge_finish_tx.input[0].previous_output != guardian_connector_input {
                tracing::warn!(
                    "Ignore DisproveSent for {instance_id}:{graph_id}: challenge finish tx is not a challenge incomplete kickoff txn"
                );
                return Ok(());
            }
        }
    }
    let challenge_finish_height = match ctx
        .btc_client
        .get_tx_status(&challenge_finish_txid)
        .await?
        .block_height
    {
        Some(height) => height as u64,
        None => {
            let delay_secs = todo_funcs::avg_block_time_secs(ctx.btc_client.network());
            push_local_unhandled_messages(ctx.local_db, graph_id, &message, delay_secs as usize)
                .await?;
            tracing::info!(
                "Retry finishWithdrawDisproved later for {instance_id}:{graph_id}: challenge finish tx not confirmed on btc yet"
            );
            return Ok(());
        }
    };
    let goat_confirmed_height = ctx.goat_client.btc_spv_latest_height().await?;
    if goat_confirmed_height < challenge_finish_height {
        let delay_secs = todo_funcs::avg_block_time_secs(ctx.btc_client.network())
            * (challenge_finish_height - goat_confirmed_height);
        push_local_unhandled_messages(ctx.local_db, graph_id, &message, delay_secs as usize)
            .await?;
        tracing::info!(
            "Retry finishWithdrawDisproved later for {instance_id}:{graph_id}: challenge finish tx block not posted to goat spv contract yet"
        );
        return Ok(());
    }
    ctx.goat_client
        .gateway_finish_withdraw_disproved(
            ctx.btc_client,
            &graph_id,
            disprove_type,
            index as u64,
            challenge_start_tx.as_ref(),
            &challenge_finish_tx,
        )
        .await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_disprove_sent_default(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<()> {
    // triggered by Disprove tx
    let _graph =
        refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::Disprove).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_take1_ready_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by timeout task
    let message = make_message(ctx, content);
    let (mut graph, graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::OperatorKickOff,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    if graph_status != GraphStatus::OperatorKickOff {
        tracing::warn!(
            "Ignore Take1Ready for {instance_id}:{graph_id}: graph status is {graph_status:?}"
        );
        return Ok(());
    }
    let kickoff_txid = graph.kickoff.tx().compute_txid();
    let connector_a_vout = 0;
    let guardian_connector_vout = 4;
    if outpoint_spent_txid(ctx.btc_client, &kickoff_txid, connector_a_vout).await?.is_some()
        || outpoint_spent_txid(ctx.btc_client, &kickoff_txid, guardian_connector_vout)
            .await?
            .is_some()
    {
        tracing::warn!("Ignore Take1Ready for {instance_id}:{graph_id}: connectors already spent");
        return Ok(());
    }
    let kickoff_height = match ctx.btc_client.get_tx_status(&kickoff_txid).await?.block_height {
        Some(height) => height,
        None => {
            tracing::warn!(
                "Ignore Take1Ready for {instance_id}:{graph_id}: kickoff tx not confirmed yet"
            );
            return Ok(());
        }
    };
    if !is_take1_timelock_expired(ctx.btc_client, kickoff_height).await? {
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
        build_cpfp_txns(ctx.btc_client, &take1_tx, anchor_vout, take1_tx_total_input_amount)
            .await?;
    match child_tx {
        Some(tx) => broadcast_package(ctx.btc_client, &[take1_tx, tx], true).await?,
        None => broadcast_tx(ctx.btc_client, &take1_tx).await?,
    };
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_take1_sent_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by Take1 tx
    // 1. update graph status
    let message = make_message(ctx, content);
    let (graph, _graph_status, _graph_sub_status) =
        match refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::OperatorTake1)
            .await?
        {
            Some(v) => v,
            None => return Ok(()),
        };
    if !is_relayer() {
        return Ok(());
    }
    // 2. (Relayer) call finalizeWithdrawHappyPath on GoatChain
    let take1_txid = graph.take1.tx().compute_txid();
    let take1_tx = match ctx.btc_client.get_tx(&take1_txid).await? {
        Some(tx) => tx,
        None => {
            tracing::warn!(
                "Ignore Take1Sent for {instance_id}:{graph_id}: take1 tx not found on chain"
            );
            return Ok(());
        }
    };
    let withdraw_status = ctx.goat_client.gateway_get_withdraw_data(&graph_id).await?.status;
    if withdraw_status == WithdrawStatus::Initialized {
        // Kickoff not posted yet, wait for it
        let delay_secs = todo_funcs::avg_block_time_secs(ctx.btc_client.network()) * 6; // wait for 6 blocks
        push_local_unhandled_messages(ctx.local_db, graph_id, &message, delay_secs as usize)
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
    let take1_height = match ctx.btc_client.get_tx_status(&take1_txid).await?.block_height {
        Some(height) => height as u64,
        None => {
            let delay_secs = todo_funcs::avg_block_time_secs(ctx.btc_client.network()); // wait for 1 block
            push_local_unhandled_messages(ctx.local_db, graph_id, &message, delay_secs as usize)
                .await?;
            tracing::info!(
                "Retry finishWithdrawHappyPath later for {instance_id}:{graph_id} as take1 tx not confirmed on btc yet"
            );
            return Ok(());
        }
    };
    let goat_confirmed_height = ctx.goat_client.btc_spv_latest_height().await?;
    if goat_confirmed_height < take1_height {
        let delay_secs = todo_funcs::avg_block_time_secs(ctx.btc_client.network())
            * (take1_height - goat_confirmed_height);
        push_local_unhandled_messages(ctx.local_db, graph_id, &message, delay_secs as usize)
            .await?;
        tracing::info!(
            "Retry finishWithdrawHappyPath later for {instance_id}:{graph_id} as take1 tx block not posted to goat spv contract yet"
        );
        return Ok(());
    }
    ctx.goat_client
        .gateway_finish_withdraw_happy_path(ctx.btc_client, &graph_id, &take1_tx)
        .await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_take1_sent_default(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<()> {
    // triggered by Take1 tx
    // 1. update graph status
    let _graph =
        refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::OperatorTake1).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_take2_ready_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by timeout task
    let message = make_message(ctx, content);
    let (mut graph, graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::Challenge,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    if graph_status != GraphStatus::Challenge {
        tracing::warn!(
            "Ignore Take2Ready for {instance_id}:{graph_id}: graph status is {graph_status:?}"
        );
        return Ok(());
    }
    let kickoff_txid = graph.kickoff.tx().compute_txid();
    let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
    let assert_init_txid = graph.assert_init.tx().compute_txid();
    let connector_d_vout = graph.assert_commit_timeout_txns.len() as u64;
    let connector_e_vout = 3;
    let connector_f_vout = 1 + 2 * graph.parameters.watchtower_pubkeys.len() as u64;
    let guardian_connector_vout = 4;
    // check if connector_E, connector_F, connector_D, guardian_connector are all unspent
    if outpoint_spent_txid(ctx.btc_client, &kickoff_txid, connector_e_vout).await?.is_some()
        || outpoint_spent_txid(ctx.btc_client, &watchtower_challenge_init_txid, connector_f_vout)
            .await?
            .is_some()
        || outpoint_spent_txid(ctx.btc_client, &assert_init_txid, connector_d_vout).await?.is_some()
        || outpoint_spent_txid(ctx.btc_client, &kickoff_txid, guardian_connector_vout)
            .await?
            .is_some()
    {
        tracing::warn!("Ignore Take2Ready for {instance_id}:{graph_id}: connectors already spent");
        return Ok(());
    }
    // check if assert-init tx and watchtower-challenge-init tx are both confirmed and timelock expired
    let assert_init_height = match ctx
        .btc_client
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
    let watchtower_challenge_init_height = match ctx
        .btc_client
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
        ctx.btc_client,
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
        build_cpfp_txns(ctx.btc_client, &take2_tx, anchor_vout, take2_tx_total_input_amount)
            .await?;
    match child_tx {
        Some(tx) => broadcast_package(ctx.btc_client, &[take2_tx, tx], true).await?,
        None => broadcast_tx(ctx.btc_client, &take2_tx).await?,
    };
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_take2_sent_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by Take2 tx
    // 1. update graph status
    let message = make_message(ctx, content);
    let (graph, _graph_status, _graph_sub_status) =
        match refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::OperatorTake2)
            .await?
        {
            Some(v) => v,
            None => return Ok(()),
        };
    if !is_relayer() {
        return Ok(());
    }
    // 2. (Relayer) call finalizeWithdrawUnhappyPath on GoatChain
    let take2_txid = graph.take2.tx().compute_txid();
    let take2_tx = match ctx.btc_client.get_tx(&take2_txid).await? {
        Some(tx) => tx,
        None => {
            tracing::warn!(
                "Ignore Take2Sent for {instance_id}:{graph_id}: take2 tx not found on chain"
            );
            return Ok(());
        }
    };
    let withdraw_status = ctx.goat_client.gateway_get_withdraw_data(&graph_id).await?.status;
    if withdraw_status == WithdrawStatus::Initialized {
        // Kickoff not posted yet, wait for it
        let delay_secs = todo_funcs::avg_block_time_secs(ctx.btc_client.network()) * 6; // wait for 6 blocks
        push_local_unhandled_messages(ctx.local_db, graph_id, &message, delay_secs as usize)
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
    let take2_height = match ctx.btc_client.get_tx_status(&take2_txid).await?.block_height {
        Some(height) => height as u64,
        None => {
            let delay_secs = todo_funcs::avg_block_time_secs(ctx.btc_client.network()); // wait for 1 block
            push_local_unhandled_messages(ctx.local_db, graph_id, &message, delay_secs as usize)
                .await?;
            tracing::info!(
                "Retry finishWithdrawUnhappyPath later for {instance_id}:{graph_id} as take2 tx not confirmed on btc yet"
            );
            return Ok(());
        }
    };
    let goat_confirmed_height = ctx.goat_client.btc_spv_latest_height().await?;
    if goat_confirmed_height < take2_height {
        let delay_secs = todo_funcs::avg_block_time_secs(ctx.btc_client.network())
            * (take2_height - goat_confirmed_height);
        push_local_unhandled_messages(ctx.local_db, graph_id, &message, delay_secs as usize)
            .await?;
        tracing::info!(
            "Retry finishWithdrawUnhappyPath later for {instance_id}:{graph_id} as take2 tx block not posted to goat spv contract yet"
        );
        return Ok(());
    }
    ctx.goat_client
        .gateway_finish_withdraw_unhappy_path(ctx.btc_client, &graph_id, &take2_tx)
        .await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_take2_sent_default(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<()> {
    // triggered by Take2 tx
    // 1. update graph status
    let _graph =
        refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::OperatorTake2).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_sync_graph_request(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<()> {
    // sent by other nodes when they find a graph is missing locally
    // 1. (Relayer) send SyncGraph response if have the graph
    if !is_relayer() {
        tracing::warn!("Ignore SyncGraphRequest for {instance_id}:{graph_id}: not a relayer node");
        return Ok(());
    }
    if let Some(graph) = get_graph(ctx.local_db, instance_id, graph_id).await? {
        let message_content =
            GOATMessageContent::SyncGraph(SyncGraph { instance_id, graph_id, graph });
        let message = GOATMessage::new(Actor::All, message_content);
        send_to_peer(ctx.swarm, message).await?;
    } else {
        // TODO: if no relayer has the graph, how to recover?
        tracing::warn!("Graph not found for SyncGraphRequest {instance_id}:{graph_id}");
    }
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_sync_graph(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    graph: &SimplifiedBitvm2Graph,
) -> Result<()> {
    // sent by relayer nodes in response to SyncGraphRequest
    if graph_exists(ctx.local_db, instance_id, graph_id).await? {
        tracing::warn!(
            "Ignore SyncGraph for {instance_id}:{graph_id}: graph already exists locally"
        );
        return Ok(());
    }
    validate_graph_id_on_goat(ctx.goat_client, instance_id, graph_id).await.map_err(|e| {
        anyhow!(
            "Failed to validate graph_id on GoatChain for SyncGraph {instance_id}:{graph_id}: {e}"
        )
    })?;
    store_graph(ctx.local_db, graph).await?;
    let graph = Bitvm2Graph::from_simplified(graph)?;
    refresh_and_compensate(
        ctx,
        instance_id,
        graph_id,
        Some(&graph),
        None,
        GraphStatus::OperatorPresigned,
    )
    .await?;
    Ok(())
}

async fn handle_request_node_info(
    ctx: &mut HandlerContext<'_>,
    node_info: &NodeInfo,
) -> Result<()> {
    save_node_info(ctx.local_db, node_info).await?;
    let message_content = GOATMessageContent::ResponseNodeInfo(crate::env::get_local_node_info());
    send_to_peer(ctx.swarm, GOATMessage::new(Actor::All, message_content)).await?;
    Ok(())
}

async fn handle_response_node_info(
    ctx: &mut HandlerContext<'_>,
    node_info: &NodeInfo,
) -> Result<()> {
    save_node_info(ctx.local_db, node_info).await?;
    Ok(())
}
