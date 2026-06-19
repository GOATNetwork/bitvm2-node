use crate::action::*;
use crate::env::{
    COMMITTEE_INSTANCE_KEYS_DIR, get_babe_gc_asset_paths, get_bitvm_key, get_node_goat_address,
    get_soldering_proof_payload_store_path, is_relayer,
};
use crate::error::SpecialError;
use crate::middleware::AllBehaviours;
use crate::scheduled_tasks::graph_maintenance_tasks::ChallengeSubStatus;
use crate::soldering_payload_store::{
    read_soldering_proof_store_payload, soldering_proof_payload_store_path,
};
use crate::utils::*;
use anyhow::{Context, Result, anyhow, bail};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bitcoin::{Amount, OutPoint, Txid};
use bitcoin::{PublicKey, XOnlyPublicKey};
use bitvm_lib::actors::Actor;
use bitvm_lib::babe_adapter::{BABE_M_CC, BABE_N_CC, BabeBundleBuilder, BabeChallengeAssertWitness, BabeProverState, CompactSolderingProofPayload, TxAssertWitness, assert_wots_message, build_assert_witness, build_real_challenge_assert_witness, build_real_setup_package, derive_finalized_indices, expand_compact_soldering_proof_payload, extract_gc_circuit_data, open_real_setup_and_solder, recover_real_wrongly_challenged_witness, verify_real_setup, CACSetupPackage};
use bitvm_lib::committee::*;
use bitvm_lib::keys::*;
use bitvm_lib::operator::*;
use bitvm_lib::types::{BitvmGcCircuitData, BitvmGcGraph, SimplifiedBitvmGcGraph};
use bitvm_lib::verifier::*;
use client::goat_chain::{DisproveTxType, PeginStatus, WithdrawStatus};
use client::http_client::async_client::HttpAsyncClient;
use client::{btc_chain::BTCClient, goat_chain::GOATClient};
use goat::connectors::connector_z::ConnectorZ;
use goat::transactions::base::output_topology;
use goat::transactions::pre_signed::PreSignedTransaction;
use goat::transactions::pre_signed_musig2::verify_public_nonce;
use libp2p::gossipsub::MessageId;
use libp2p::{PeerId, Swarm};
use std::sync::Arc;
use store::{GraphStatus, SerializableTxid};
use store::localdb::LocalDB;
use uuid::Uuid;

pub struct HandlerContext<'a> {
    pub swarm: &'a mut Swarm<AllBehaviours>,
    pub local_db: &'a LocalDB,
    pub btc_client: &'a BTCClient,
    pub goat_client: &'a GOATClient,
    pub http_client: &'a HttpAsyncClient,
    pub soldering_builder: &'a Option<Arc<BabeBundleBuilder>>,
    pub actor: Actor,
    pub from_peer_id: PeerId,
    pub id: MessageId,
    pub is_self_peer: bool,
}

fn committee_instance_keys_envelope_path(instance_id: Uuid) -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from(COMMITTEE_INSTANCE_KEYS_DIR);
    path.push(format!("{instance_id}.json"));
    path
}

fn is_io_not_found_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io_err| io_err.kind() == std::io::ErrorKind::NotFound)
    })
}

fn load_committee_instance_keypair(
    committee_master_key: &CommitteeMasterKey,
    instance_id: Uuid,
) -> Result<bitcoin::key::Keypair> {
    let envelope_path = committee_instance_keys_envelope_path(instance_id);
    committee_master_key.load_instance_keypair(instance_id, &envelope_path).with_context(|| {
        format!(
            "load committee instance keypair failed for {} at {}",
            instance_id,
            envelope_path.display()
        )
    })
}

fn load_or_create_committee_instance_keypair(
    committee_master_key: &CommitteeMasterKey,
    instance_id: Uuid,
) -> Result<bitcoin::key::Keypair> {
    let envelope_path = committee_instance_keys_envelope_path(instance_id);
    match committee_master_key.load_instance_keypair(instance_id, &envelope_path) {
        Ok(keypair) => Ok(keypair),
        Err(load_err) => {
            if !is_io_not_found_error(&load_err) {
                return Err(load_err).with_context(|| {
                    format!(
                        "load committee instance keypair failed for {} at {} (refuse auto-overwrite for non-missing envelope)",
                        instance_id,
                        envelope_path.display()
                    )
                });
            }
            tracing::info!(
                "committee instance key not found for {} at {}: {}, creating new envelope",
                instance_id,
                envelope_path.display(),
                load_err
            );
            committee_master_key
                .create_instance_keypair_envelope(instance_id, &envelope_path)
                .with_context(|| {
                    format!(
                        "create committee instance key envelope failed for {} at {}",
                        instance_id,
                        envelope_path.display()
                    )
                })?;
            committee_master_key.load_instance_keypair(instance_id, &envelope_path).with_context(
                || {
                    format!(
                        "reload committee instance key envelope failed for {} at {}",
                        instance_id,
                        envelope_path.display()
                    )
                },
            )
        }
    }
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
        (GOATMessageContent::InitGraph(InitGraph { instance_id, graph_id }), Actor::Verifier) => {
            handle_init_graph_verifier(ctx, *instance_id, *graph_id).await
        }
        (
            GOATMessageContent::GenCircuits(GenCircuits {
                instance_id,
                graph_id,
                verifier_pubkey,
                setup_package,
            }),
            Actor::Operator,
        ) => {
            handle_gen_circuits_operator(
                ctx,
                *instance_id,
                *graph_id,
                verifier_pubkey,
                setup_package,
            )
            .await
        }
        (
            GOATMessageContent::CutCircuits(CutCircuits {
                instance_id,
                graph_id,
                verifier_pubkey,
                verifier_index,
                selected_circuit_indexes,
            }),
            Actor::Verifier,
        ) => {
            handle_cut_circuits_verifier(
                ctx,
                *instance_id,
                *graph_id,
                verifier_pubkey,
                *verifier_index,
                selected_circuit_indexes,
            )
            .await
        }
        (
            GOATMessageContent::SolderingProofReady(SolderingProofReady {
                instance_id,
                graph_id,
                verifier_index,
                payload_hash,
                total_len,
            }),
            Actor::Operator,
        ) => {
            handle_soldering_proof_ready_operator(
                ctx,
                *instance_id,
                *graph_id,
                *verifier_index,
                *payload_hash,
                *total_len,
            )
            .await
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
            Actor::Verifier,
        ) => handle_kickoff_sent_verifier(ctx, *instance_id, *graph_id, content).await,
        (GOATMessageContent::KickoffSent(KickoffSent { instance_id, graph_id }), _) => {
            handle_kickoff_sent_default(ctx, *instance_id, *graph_id, content).await
        }
        (
            GOATMessageContent::PreKickoffSent(PreKickoffSent { instance_id, graph_id }),
            Actor::Verifier,
        ) => handle_prekickoff_sent_verifier(ctx, *instance_id, *graph_id, content).await,
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
                watchtower_index,
            }),
            Actor::Operator,
        ) => {
            handle_watchtower_challenge_sent_operator(
                ctx,
                *instance_id,
                *graph_id,
                *watchtower_index,
                content,
            )
            .await
        }
        (
            GOATMessageContent::WatchtowerChallengeTimeout(WatchtowerChallengeTimeout {
                instance_id,
                graph_id,
            }),
            Actor::Operator,
        ) => {
            handle_watchtower_challenge_timeout_operator(ctx, *instance_id, *graph_id, content)
                .await
        }
        (GOATMessageContent::NackReady(NackReady { instance_id, graph_id }), Actor::Verifier) => {
            handle_nack_ready_verifier(ctx, *instance_id, *graph_id, content).await
        }
        (
            GOATMessageContent::OperatorCommitPubinReady(OperatorCommitPubinReady {
                instance_id,
                graph_id,
            }),
            Actor::Operator,
        ) => {
            handle_operator_commit_pubin_ready_operator(ctx, *instance_id, *graph_id, content).await
        }
        (
            GOATMessageContent::OperatorCommitPubinTimeout(OperatorCommitPubinTimeout {
                instance_id,
                graph_id,
            }),
            Actor::Verifier,
        ) => {
            handle_operator_commit_pubin_timeout_verifier(ctx, *instance_id, *graph_id, content)
                .await
        }
        (
            GOATMessageContent::AssertReady(AssertReady { instance_id, graph_id }),
            Actor::Operator,
        ) => handle_assert_ready_operator(ctx, *instance_id, *graph_id).await,
        (
            GOATMessageContent::AssertSent(AssertSent {
                instance_id,
                graph_id,
                assert_txid,
                assert_witness,
            }),
            Actor::Verifier,
        ) => {
            handle_assert_sent_verifier(ctx, *instance_id, *graph_id, *assert_txid, assert_witness)
                .await
        }
        (
            GOATMessageContent::ChallengeAssertSent(ChallengeAssertSent {
                instance_id,
                graph_id,
                challenge_assert_txid,
                verifier_index,
                challenge_witness,
                ..
            }),
            Actor::Operator,
        ) => {
            handle_challenge_assert_sent_operator(
                ctx,
                *instance_id,
                *graph_id,
                *challenge_assert_txid,
                *verifier_index,
                challenge_witness,
                content,
            )
            .await
        }
        (
            GOATMessageContent::WronglyChallengeTimeout(WronglyChallengeTimeout {
                instance_id,
                graph_id,
                challenge_assert_txid,
                verifier_index,
                ..
            }),
            Actor::Verifier,
        ) => {
            handle_wrongly_challenge_timeout_verifier(
                ctx,
                *instance_id,
                *graph_id,
                *challenge_assert_txid,
                *verifier_index,
                content,
            )
            .await
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

/// Freezes the first accepted Verifiers and assigns deterministic graph slots.
fn freeze_operator_candidates(state: &mut OperatorBabeSetupState) -> Result<()> {
    if state.frozen_verifier_pubkeys.is_some() {
        return Ok(());
    }
    if state.candidates.len() < todo_funcs::min_required_verifier() {
        bail!(
            "cannot freeze {} verifier candidates before reaching target {}",
            state.candidates.len(),
            todo_funcs::min_required_verifier()
        );
    }
    state.candidates.truncate(todo_funcs::min_required_verifier());
    state.candidates.sort_by_key(|candidate| candidate.verifier_pubkey.to_bytes());
    for (verifier_index, candidate) in state.candidates.iter_mut().enumerate() {
        candidate.verifier_index = Some(verifier_index);
        candidate.selected_circuit_indexes =
            derive_finalized_indices(&candidate.setup_package, BABE_M_CC)?;
    }
    state.frozen_verifier_pubkeys =
        Some(state.candidates.iter().map(|candidate| candidate.verifier_pubkey).collect());
    Ok(())
}

/// Stores one selected Verifier slot and emits ordered graph data when complete.
fn record_candidate_gc_data(
    state: &mut OperatorBabeSetupState,
    verifier_pubkey: PublicKey,
    verifier_index: usize,
    setup_package: &CACSetupPackage,
    gc_data: BitvmGcCircuitData,
    prover_state: BabeProverState,
) -> Result<Option<Vec<BitvmGcCircuitData>>> {
    let frozen = state
        .frozen_verifier_pubkeys
        .as_ref()
        .ok_or_else(|| anyhow!("operator verifier membership is not frozen"))?;
    let expected_pubkey = frozen
        .get(verifier_index)
        .ok_or_else(|| anyhow!("verifier index {verifier_index} out of frozen slot range"))?;
    if expected_pubkey != &verifier_pubkey {
        bail!("verifier public key does not own slot {verifier_index}");
    }
    if gc_data.verifier_pubkey != verifier_pubkey {
        bail!("GC slot owner does not match soldering proof verifier");
    }
    let candidate = state
        .candidates
        .iter_mut()
        .find(|candidate| candidate.verifier_pubkey == verifier_pubkey)
        .ok_or_else(|| anyhow!("selected verifier candidate is missing"))?;
    if candidate.verifier_index != Some(verifier_index) {
        bail!("candidate verifier index does not match soldering proof slot");
    }
    if candidate.setup_package != *setup_package {
        bail!("soldering proof setup package does not match selected verifier candidate");
    }
    if prover_state.package != *setup_package {
        bail!("BABE prover state setup package does not match selected verifier candidate");
    }
    if candidate.selected_circuit_indexes != prover_state.soldering.finalized_indices {
        bail!("BABE prover state finalized indices do not match selected verifier cut");
    }
    if prover_state.finalized.len() != BABE_M_CC || prover_state.h_msgs.len() != BABE_M_CC {
        bail!("BABE prover state must contain exactly {BABE_M_CC} finalized instances and hashes");
    }
    if prover_state.h_msgs != gc_data.final_msg_hashlocks {
        bail!("BABE prover state hashes do not match GC slot hashes");
    }
    if let Some(existing) = &candidate.gc_data
        && existing != &gc_data
    {
        bail!("conflicting GC slot received for selected verifier");
    }
    if let Some(existing) = &candidate.prover_state
        && existing != &prover_state
    {
        bail!("conflicting BABE prover state received for selected verifier");
    }
    if candidate.gc_data.is_none() {
        candidate.gc_data = Some(gc_data);
    }
    if candidate.prover_state.is_none() {
        candidate.prover_state = Some(prover_state);
    }
    if state.candidates.iter().any(|candidate| candidate.gc_data.is_none()) {
        return Ok(None);
    }
    Ok(Some(state.candidates.iter().map(|candidate| candidate.gc_data.clone().unwrap()).collect()))
}

fn validate_verifier_slot_lengths(
    verifier_index: usize,
    gc_data_len: usize,
    verifier_asserts_len: usize,
    disproves_len: usize,
) -> Result<()> {
    if gc_data_len == 0 {
        bail!("graph has no verifier GC slots");
    }
    if gc_data_len != verifier_asserts_len || gc_data_len != disproves_len {
        bail!(
            "graph verifier branch lengths differ: gc_data={gc_data_len}, verifier_asserts={verifier_asserts_len}, disproves={disproves_len}"
        );
    }
    if verifier_index >= gc_data_len {
        bail!("verifier index {verifier_index} out of range for {gc_data_len} slots");
    }
    Ok(())
}

fn validate_verifier_slot(graph: &BitvmGcGraph, verifier_index: usize) -> Result<()> {
    validate_verifier_slot_lengths(
        verifier_index,
        graph.parameters.gc_data.len(),
        graph.verifier_asserts.len(),
        graph.disproves.len(),
    )
}

fn validate_watchtower_branches(graph: &BitvmGcGraph) -> Result<usize> {
    let watchtower_num = graph.parameters.watchtower_pubkeys.len();
    if watchtower_num == 0 {
        bail!("graph has no watchtower slots");
    }
    if graph.parameters.watchtower_ack_hashlocks.len() != watchtower_num
        || graph.watchtower_challenge_timeouts.len() != watchtower_num
        || graph.operator_challenge_nacks.len() != watchtower_num
    {
        bail!(
            "graph watchtower branch lengths differ: watchtowers={}, ack_hashlocks={}, timeouts={}, nacks={}",
            watchtower_num,
            graph.parameters.watchtower_ack_hashlocks.len(),
            graph.watchtower_challenge_timeouts.len(),
            graph.operator_challenge_nacks.len()
        );
    }
    Ok(watchtower_num)
}

fn find_verifier_index_by_pubkey(
    gc_data: &[BitvmGcCircuitData],
    verifier_pubkey: &PublicKey,
) -> Result<Option<usize>> {
    let matches = gc_data
        .iter()
        .enumerate()
        .filter_map(|(index, data)| (data.verifier_pubkey == *verifier_pubkey).then_some(index))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => Ok(None),
        [index] => Ok(Some(*index)),
        _ => bail!("graph contains duplicate slots for verifier {verifier_pubkey}"),
    }
}

fn validate_challenge_witness_index(
    verifier_index: usize,
    challenge_witness: &BabeChallengeAssertWitness,
) -> Result<()> {
    if challenge_witness.verifier_index != verifier_index {
        bail!(
            "challenge witness verifier index {} does not match message verifier index {verifier_index}",
            challenge_witness.verifier_index
        );
    }
    Ok(())
}

fn validate_expected_challenge_assert_txid(
    graph: &BitvmGcGraph,
    verifier_index: usize,
    challenge_assert_txid: Txid,
) -> Result<()> {
    validate_verifier_slot(graph, verifier_index)?;
    let expected_txid = graph.verifier_asserts[verifier_index].tx().compute_txid();
    if challenge_assert_txid != expected_txid {
        bail!(
            "challenge assert txid {challenge_assert_txid} does not match graph verifier assert txid {expected_txid}"
        );
    }
    Ok(())
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
    graph: Option<&BitvmGcGraph>,
    scan_from_status: Option<GraphStatus>,
    compensate_from_status: GraphStatus,
) -> Result<(GraphStatus, Option<ChallengeSubStatus>)> {
    let (graph_status, sub_status, scan) = refresh_graph(
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
        scan.as_ref(),
        scan_from_status,
        compensate_from_status,
        graph_status,
    )
    .await?;
    Ok((graph_status, sub_status))
}

async fn get_graph_and_status(
    ctx: &HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<(BitvmGcGraph, GraphStatus)> {
    let graph = get_graph(ctx.local_db, instance_id, graph_id)
        .await?
        .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
    let graph = BitvmGcGraph::from_simplified(&graph)?;
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
) -> Result<Option<(BitvmGcGraph, GraphStatus)>> {
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
    let graph = BitvmGcGraph::from_simplified(&graph)?;
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
) -> Result<Option<(BitvmGcGraph, GraphStatus, Option<ChallengeSubStatus>)>> {
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
    let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
    let instance_keypair =
        load_or_create_committee_instance_keypair(&committee_master_key, instance_id)?;
    let pubkey_for_instance = instance_keypair.public_key().into();
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

    let pending_graph_id = {
        let mut storage = ctx.local_db.acquire().await?;
        storage
            .find_pending_graph_init_by_instance_and_operator_pubkey(
                &instance_id,
                &local_operator_pubkey.to_string(),
            )
            .await?
            .map(|pending| pending.graph_id)
    };
    if let Some(graph_id) = pending_graph_id {
        tracing::info!("Resume pending graph setup for {instance_id}, graph_id: {graph_id}");
        let message_content = GOATMessageContent::InitGraph(InitGraph { instance_id, graph_id });
        send_to_peer(ctx.swarm, GOATMessage::new(Actor::Verifier, message_content)).await?;

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
    // after PeginPrepare is confirmed, broadcast InitGraph and let Verifiers generate GC.

    // 2. save the instance data to local db
    store_instance_parameters(ctx.local_db, &instance_params).await?;
    let graph_id = Uuid::new_v4();
    let mut storage = ctx.local_db.acquire().await?;
    storage
        .upsert_pending_graph_init(&instance_id, &local_operator_pubkey.to_string(), &graph_id)
        .await?;
    let message_content = GOATMessageContent::InitGraph(InitGraph { instance_id, graph_id });
    send_to_peer(ctx.swarm, GOATMessage::new(Actor::Verifier, message_content)).await?;

    Ok(())
}

// generate garbled circuits and broadcast GenCircuits.
#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_init_graph_verifier(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<()> {
    let verifier_master_key = VerifierMasterKey::new(get_bitvm_key()?);
    let verifier_pubkey = verifier_master_key.master_keypair().public_key().into();

    let saved_verifier_state = load_babe_setup_state(ctx.local_db, instance_id, graph_id)?
        .and_then(|state| state.verifier)
        .filter(|state| state.verifier_pubkey == verifier_pubkey);
    let verifier_state = if let Some(saved) = saved_verifier_state {
        saved
    } else {
        get_babe_gc_asset_paths()?;
        let vk = crate::vk::get_vk().await.context("load Groth16 verifying key for BABE setup")?;
        let static_input = derive_operator_statement(graph_id)?.static_input;
        let (setup_package, private_state) = tokio::task::spawn_blocking(move || {
            build_real_setup_package(BABE_N_CC, &vk, static_input)
        })
        .await
        .context("real BABE setup task failed")??;
        tracing::info!("Verifier setup done.");
        VerifierBabeSetupState {
            verifier_pubkey,
            setup_package,
            private_state,
            verifier_index: None,
            finalized_indices: vec![],
            opened: vec![],
            finalized: vec![],
            soldering: None,
        }
    };

    let setup_package = verifier_state.setup_package.clone();
    update_babe_setup_state(ctx.local_db, instance_id, graph_id, |state| {
        state.verifier = Some(verifier_state);
    })?;

    let message_content = GOATMessageContent::GenCircuits(GenCircuits {
        instance_id,
        graph_id,
        verifier_pubkey,
        setup_package,
    });
    send_to_peer(ctx.swarm, GOATMessage::new(Actor::Operator, message_content)).await?;

    Ok(())
}

//  select a subset of GC and broadcast CutCircuits.
#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_gen_circuits_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    verifier_pubkey: &PublicKey,
    setup_package: &CACSetupPackage,
) -> Result<()> {
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let local_operator_pubkey = operator_master_key.master_keypair().public_key().into();
    if !pending_graph_belongs_to_operator(
        ctx.local_db,
        instance_id,
        graph_id,
        &local_operator_pubkey,
    )
    .await?
    {
        tracing::debug!(
            "Ignore GenCircuits for {instance_id}:{graph_id}: no local pending graph session"
        );
        return Ok(());
    }

    if setup_package.commits.is_empty() {
        bail!("GenCircuits setup package has no commitments");
    }

    let mut state = load_babe_setup_state(ctx.local_db, instance_id, graph_id)?.unwrap_or_default();
    let operator_state = state.operator.get_or_insert_with(|| OperatorBabeSetupState {
        frozen_verifier_pubkeys: None,
        candidates: vec![],
        asserted_wrapper_proof: None,
    });

    let was_frozen = operator_state.frozen_verifier_pubkeys.is_some();
    if let Some(existing) = operator_state
        .candidates
        .iter()
        .find(|candidate| candidate.verifier_pubkey == *verifier_pubkey)
    {
        if existing.setup_package != *setup_package {
            bail!("conflicting GenCircuits setup package for verifier {verifier_pubkey}");
        }
    } else if was_frozen {
        tracing::debug!(
            "Ignore GenCircuits for {instance_id}:{graph_id}: verifier membership is frozen"
        );

        return Ok(());
    } else {
        operator_state.candidates.push(OperatorVerifierCandidate {
            verifier_pubkey: *verifier_pubkey,
            setup_package: setup_package.clone(),
            verifier_index: None,
            selected_circuit_indexes: vec![],
            gc_data: None,
            prover_state: None,
        });
    }

    if operator_state.frozen_verifier_pubkeys.is_none()
        && operator_state.candidates.len() < todo_funcs::min_required_verifier()
    {
        save_babe_setup_state(ctx.local_db, instance_id, graph_id, &state)?;

        return Ok(());
    }

    freeze_operator_candidates(operator_state)?;
    let cut_candidates = if was_frozen {
        operator_state
            .candidates
            .iter()
            .filter(|candidate| candidate.verifier_pubkey == *verifier_pubkey)
            .cloned()
            .collect::<Vec<_>>()
    } else {
        operator_state.candidates.clone()
    };

    save_babe_setup_state(ctx.local_db, instance_id, graph_id, &state)?;
    for candidate in cut_candidates {
        let message_content = GOATMessageContent::CutCircuits(CutCircuits {
            instance_id,
            graph_id,
            verifier_pubkey: candidate.verifier_pubkey,
            verifier_index: candidate.verifier_index.unwrap(),
            selected_circuit_indexes: candidate.selected_circuit_indexes,
        });
        send_to_peer(ctx.swarm, GOATMessage::new(Actor::Verifier, message_content)).await?;
    }

    Ok(())
}

// generate proofs for the chosen GC and broadcast SolderingProof.
#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_cut_circuits_verifier(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    verifier_pubkey: &PublicKey,
    verifier_index: usize,
    selected_circuit_indexes: &Vec<usize>,
) -> Result<()> {
    let verifier_master_key = VerifierMasterKey::new(get_bitvm_key()?);
    let local_verifier_pubkey: PublicKey = verifier_master_key.master_keypair().public_key().into();
    if &local_verifier_pubkey != verifier_pubkey {
        tracing::debug!(
            "Ignore CutCircuits for {instance_id}:{graph_id}: target verifier pubkey does not match local verifier"
        );

        return Ok(());
    }

    let Some(mut verifier_state) = load_babe_setup_state(ctx.local_db, instance_id, graph_id)?
        .and_then(|state| state.verifier)
    else {
        tracing::warn!(
            "Ignore CutCircuits for {instance_id}:{graph_id}: missing BABE verifier setup state"
        );
        return Ok(());
    };

    if verifier_state.verifier_pubkey != *verifier_pubkey {
        tracing::warn!(
            "Ignore CutCircuits for {instance_id}:{graph_id}: verifier pubkey does not match saved BABE setup state"
        );

        return Ok(());
    }

    if let Some(saved_index) = verifier_state.verifier_index {
        if saved_index != verifier_index {
            bail!(
                "CutCircuits verifier index {verifier_index} conflicts with persisted slot {saved_index}"
            );
        }
        if verifier_state.finalized_indices != *selected_circuit_indexes {
            bail!("CutCircuits finalized indices conflict with persisted selection");
        }
        if let Some(soldering) = verifier_state.soldering.clone() {
            let setup_state = verifier_state;
            send_soldering_proof_to_operator(
                ctx.swarm,
                instance_id,
                graph_id,
                verifier_index,
                &setup_state.opened,
                &setup_state.finalized,
                &soldering,
            )
            .await?;

            return Ok(());
        }
    }

    let setup_package = verifier_state.setup_package.clone();
    get_babe_gc_asset_paths()?;

    let vk = crate::vk::get_vk().await.context("load Groth16 verifying key for BABE opening")?;
    let static_input = derive_operator_statement(graph_id)?.static_input;
    let private_state = verifier_state.private_state.clone();
    let selected_indices = selected_circuit_indexes.clone();
    let package_for_opening = setup_package.clone();
    let soldering_builder = Arc::clone(
        ctx.soldering_builder
            .as_ref()
            .context("BABE soldering builder is not initialized for Verifier")?,
    );
    let (opened, finalized, soldering) = tokio::task::spawn_blocking(move || {
        open_real_setup_and_solder(
            &soldering_builder,
            &private_state,
            &package_for_opening,
            &selected_indices,
            &vk,
            static_input,
        )
    })
    .await
    .context("real BABE opening task failed")??;

    verifier_state.verifier_index = Some(verifier_index);
    verifier_state.finalized_indices = selected_circuit_indexes.clone();
    verifier_state.opened = opened.clone();
    verifier_state.finalized = finalized.clone();
    verifier_state.soldering = Some(soldering.clone());

    update_babe_setup_state(ctx.local_db, instance_id, graph_id, |state| {
        state.verifier = Some(verifier_state);
    })?;

    send_soldering_proof_to_operator(
        ctx.swarm,
        instance_id,
        graph_id,
        verifier_index,
        &opened,
        &finalized,
        &soldering,
    )
    .await?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_soldering_proof_ready_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    verifier_index: usize,
    payload_hash: [u8; 32],
    total_len: usize,
) -> Result<()> {
    if total_len == 0 {
        bail!("SolderingProofReady total_len must be greater than zero");
    }
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let local_operator_pubkey = operator_master_key.master_keypair().public_key().into();
    if !pending_graph_belongs_to_operator(
        ctx.local_db,
        instance_id,
        graph_id,
        &local_operator_pubkey,
    )
    .await?
    {
        tracing::debug!(
            "Ignore SolderingProofReady for {instance_id}:{graph_id}: no local pending graph session"
        );

        return Ok(());
    }

    let state = load_babe_setup_state(ctx.local_db, instance_id, graph_id)?
        .ok_or_else(|| anyhow!("missing BABE setup state for pending graph {graph_id}"))?;
    let operator_state = state
        .operator
        .as_ref()
        .ok_or_else(|| anyhow!("missing operator BABE setup state for pending graph {graph_id}"))?;
    let frozen = operator_state
        .frozen_verifier_pubkeys
        .as_ref()
        .ok_or_else(|| anyhow!("operator verifier membership is not frozen"))?;
    let verifier_pubkey = frozen.get(verifier_index).ok_or_else(|| {
        anyhow!("SolderingProofReady verifier index {verifier_index} out of range")
    })?;
    let candidate = operator_state
        .candidates
        .iter()
        .find(|candidate| candidate.verifier_pubkey == *verifier_pubkey)
        .ok_or_else(|| anyhow!("selected verifier candidate is missing"))?;
    if candidate.verifier_index != Some(verifier_index) {
        bail!("selected verifier candidate index does not match SolderingProofReady slot");
    }

    let store_base_path = get_soldering_proof_payload_store_path()?;
    let payload_path = soldering_proof_payload_store_path(
        &store_base_path,
        instance_id,
        graph_id,
        verifier_index,
        &payload_hash,
    )?;
    tracing::info!(
        from_peer_id = %ctx.from_peer_id,
        instance_id = %instance_id,
        graph_id = %graph_id,
        verifier_index,
        total_len,
        payload_hash = %soldering_payload_hash_hex(&payload_hash),
        payload_path = %payload_path,
        "received SolderingProofReady; reading payload from store"
    );
    let payload = match read_soldering_proof_store_payload(&payload_path).await {
        Ok(payload) => payload,
        Err(err) => {
            tracing::error!(
                instance_id = %instance_id,
                graph_id = %graph_id,
                verifier_index,
                payload_path = %payload_path,
                error = %err,
                "failed to read soldering proof payload from store"
            );
            return Err(err).context("read soldering proof payload from store");
        }
    };
    tracing::info!(
        instance_id = %instance_id,
        graph_id = %graph_id,
        verifier_index,
        bytes = payload.len(),
        total_len,
        payload_hash = %soldering_payload_hash_hex(&payload_hash),
        payload_path = %payload_path,
        "read soldering proof payload from store"
    );
    tracing::info!(
        instance_id = %instance_id,
        graph_id = %graph_id,
        verifier_index,
        total_len,
        payload_hash = %soldering_payload_hash_hex(&payload_hash),
        "start processing soldering proof payload"
    );
    handle_soldering_proof_payload_operator(
        ctx,
        instance_id,
        graph_id,
        verifier_index,
        payload_hash,
        total_len,
        &payload,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_soldering_proof_payload_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    verifier_index: usize,
    payload_hash: [u8; 32],
    total_len: usize,
    payload: &[u8],
) -> Result<()> {
    if payload.len() != total_len {
        tracing::warn!(
            instance_id = %instance_id,
            graph_id = %graph_id,
            verifier_index,
            actual_len = payload.len(),
            total_len,
            payload_hash = %soldering_payload_hash_hex(&payload_hash),
            "SolderingProof payload length mismatch"
        );
        bail!(
            "SolderingProof payload length {} does not match total_len {total_len}",
            payload.len()
        );
    }
    let actual_hash = soldering_payload_hash(payload);
    if actual_hash != payload_hash {
        tracing::warn!(
            instance_id = %instance_id,
            graph_id = %graph_id,
            verifier_index,
            expected_hash = %soldering_payload_hash_hex(&payload_hash),
            actual_hash = %soldering_payload_hash_hex(&actual_hash),
            "SolderingProof payload hash mismatch"
        );
        bail!("SolderingProof payload hash mismatch");
    }
    let payload: CompactSolderingProofPayload =
        bincode::deserialize(payload).context("deserialize compact soldering proof payload")?;
    handle_compact_soldering_proof_operator(ctx, instance_id, graph_id, verifier_index, payload)
        .await
}

// verify Verifier SolderingProof, build Graph and broadcast CreateGraph.
#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_compact_soldering_proof_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    verifier_index: usize,
    payload: CompactSolderingProofPayload,
) -> Result<()> {
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let local_operator_pubkey = operator_master_key.master_keypair().public_key().into();
    if !pending_graph_belongs_to_operator(
        ctx.local_db,
        instance_id,
        graph_id,
        &local_operator_pubkey,
    )
    .await?
    {
        tracing::debug!(
            "Ignore SolderingProof for {instance_id}:{graph_id}: no local pending graph session"
        );

        return Ok(());
    }

    let mut state = load_babe_setup_state(ctx.local_db, instance_id, graph_id)?
        .ok_or_else(|| anyhow!("missing BABE setup state for pending graph {graph_id}"))?;
    let operator_state = state
        .operator
        .as_mut()
        .ok_or_else(|| anyhow!("missing operator BABE setup state for pending graph {graph_id}"))?;
    let frozen = operator_state
        .frozen_verifier_pubkeys
        .as_ref()
        .ok_or_else(|| anyhow!("operator verifier membership is not frozen"))?;
    let verifier_pubkey = *frozen
        .get(verifier_index)
        .ok_or_else(|| anyhow!("SolderingProof verifier index {verifier_index} out of range"))?;

    let candidate = operator_state
        .candidates
        .iter()
        .find(|candidate| candidate.verifier_pubkey == verifier_pubkey)
        .ok_or_else(|| anyhow!("selected verifier candidate is missing"))?;
    if candidate.verifier_index != Some(verifier_index) {
        bail!("selected verifier candidate index does not match SolderingProof slot");
    }
    let setup_package = candidate.setup_package.clone();
    let (opened, finalized, soldering) =
        expand_compact_soldering_proof_payload(payload)
            .context("expand compact soldering proof payload")?;

    let vk = crate::vk::get_vk().await.context("load Groth16 verifying key for BABE validation")?;
    let static_input = derive_operator_statement(graph_id)?.static_input;
    let package_for_validation = setup_package.clone();
    let opened_for_validation = opened.clone();
    let finalized_for_validation = finalized.clone();
    let soldering_for_validation = soldering.clone();
    let soldering_builder = Arc::clone(
        ctx.soldering_builder
            .as_ref()
            .context("BABE soldering builder is not initialized for Operator")?,
    );

    tokio::task::spawn_blocking(move || {
        verify_real_setup(
            &soldering_builder,
            &package_for_validation,
            &opened_for_validation,
            &finalized_for_validation,
            &soldering_for_validation,
            &vk,
            static_input,
        )
    })
    .await
    .context("real BABE setup verification task failed")??;

    if finalized.len() != BABE_M_CC {
        bail!("each verifier must contribute exactly {BABE_M_CC} finalized BABE instances");
    }
    let epk = &setup_package.commits[finalized[0].index].epk;
    let h_msgs: Vec<[u8; 20]> = finalized.iter().map(|f| setup_package.commits[f.index].h_msg).collect();
    let gc_data = extract_gc_circuit_data(verifier_pubkey, epk, &h_msgs)?;
    let prover_state = BabeProverState {
        package: setup_package.clone(),
        finalized,
        soldering,
        h_msgs: gc_data.final_msg_hashlocks.clone(),
    };
    let Some(bitvm_gc_circuit_datas) = record_candidate_gc_data(
        operator_state,
        verifier_pubkey,
        verifier_index,
        &setup_package,
        gc_data,
        prover_state,
    )?
    else {
        save_babe_setup_state(ctx.local_db, instance_id, graph_id, &state)?;
        return Ok(());
    };
    save_babe_setup_state(ctx.local_db, instance_id, graph_id, &state)?;

    let instance_params = get_instance_parameters(ctx.local_db, instance_id)
        .await?
        .ok_or_else(|| anyhow!("Instance parameters not found for {instance_id}"))?;

    let (graph_nonce, cur_prekickoff_txn) =
        match get_current_prekickoff_tx(ctx.local_db, &local_operator_pubkey).await? {
            Some((graph_nonce, prekickoff_tx)) => (graph_nonce, prekickoff_tx),
            None => (0, build_genesis_prekickoff_tx(ctx.btc_client, ctx.goat_client).await?),
        };
    let prekickoff_params =
        build_prekickoff_params(ctx.btc_client, graph_nonce, cur_prekickoff_txn).await?;

    let graph_params = build_graph_params(
        ctx.local_db,
        ctx.goat_client,
        instance_params,
        prekickoff_params,
        bitvm_gc_circuit_datas,
        graph_nonce,
        graph_id,
    )
    .await?;

    let mut graph = generate_bitvm_graph(graph_params)?;
    operator_pre_sign(operator_master_key.master_keypair(), &mut graph)?;

    let graph = graph.to_simplified()?;
    store_graph(ctx.local_db, &graph).await?;

    let mut storage = ctx.local_db.acquire().await?;
    storage.delete_pending_graph_init(&instance_id, &local_operator_pubkey.to_string()).await?;

    let message_content =
        GOATMessageContent::CreateGraph(CreateGraph { instance_id, graph_id, graph_nonce, graph });
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
    graph: &SimplifiedBitvmGcGraph,
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
    let instance_keypair = load_committee_instance_keypair(&committee_master_key, instance_id)?;
    let verifier_num = graph.parameters.gc_data.len();
    let watchtower_num = graph.parameters.watchtower_pubkeys.len();
    let (pub_nonces, _, nonce_sigs) = committee_master_key.nonces_for_graph_with_keypair(
        instance_id,
        graph_id,
        watchtower_num,
        verifier_num,
        instance_keypair,
    );
    let local_committee_pubkey = instance_keypair.public_key().into();
    let message_content = GOATMessageContent::NonceGeneration(NonceGeneration {
        instance_id,
        graph_id,
        committee_pubkey: local_committee_pubkey,
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
        let mut graph = BitvmGcGraph::from_simplified(graph)?;
        let verifier_num = graph.verifier_asserts.len();
        let watchtower_num = graph.parameters.watchtower_pubkeys.len();
        let mut pub_nonces = Vec::with_capacity(pub_nonces_unchecked.len());
        for (pk, pn) in pub_nonces_unchecked.into_iter() {
            if let Err(e) = pn.validate_length(watchtower_num, verifier_num) {
                tracing::warn!("PubNonces from {} has invalid length: {e}", pk.to_string());
                return Ok(());
            }
            pub_nonces.push(pn);
        }
        let agg_nonces = nonces_aggregation(&pub_nonces)?;
        let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
        let instance_keypair = load_committee_instance_keypair(&committee_master_key, instance_id)?;
        let (_, sec_nonces, _) = committee_master_key.nonces_for_graph_with_keypair(
            instance_id,
            graph_id,
            watchtower_num,
            verifier_num,
            instance_keypair,
        );
        let committee_partial_sigs =
            committee_pre_sign(instance_keypair, sec_nonces, agg_nonces.clone(), &mut graph)?;
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

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_nonce_generation_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    received_committee_pubkey: &PublicKey,
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
    let watchtower_num = graph.parameters.watchtower_pubkeys.len();
    let verifier_num = graph.parameters.gc_data.len();
    let committee_xonly_pubkey = XOnlyPublicKey::from(*received_committee_pubkey);
    if !verify_nonce_signatures(
        &committee_xonly_pubkey,
        pub_nonces,
        nonce_sigs,
        watchtower_num,
        verifier_num,
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
        let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
        let instance_keypair = load_committee_instance_keypair(&committee_master_key, instance_id)?;
        let local_committee_pubkey = instance_keypair.public_key().into();
        let mut graph = BitvmGcGraph::from_simplified(&graph)?;
        let verifier_num = graph.verifier_asserts.len();
        let watchtower_num = graph.parameters.watchtower_pubkeys.len();
        let mut pub_nonces = Vec::with_capacity(pub_nonces_unchecked.len());
        for (pk, pn) in pub_nonces_unchecked.into_iter() {
            if let Err(e) = pn.validate_length(watchtower_num, verifier_num) {
                tracing::warn!("PubNonces from {} has invalid length: {e}", pk.to_string());
                return Ok(());
            }
            pub_nonces.push(pn);
        }
        let agg_nonces = nonces_aggregation(&pub_nonces)?;
        let (_, sec_nonces, _) = committee_master_key.nonces_for_graph_with_keypair(
            instance_id,
            graph_id,
            watchtower_num,
            verifier_num,
            instance_keypair,
        );
        // 4. if received enough valid committee partial sigs, endorse the graph
        let committee_partial_sigs =
            committee_pre_sign(instance_keypair, sec_nonces, agg_nonces.clone(), &mut graph)?;
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

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_nonce_generation_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    received_committee_pubkey: &PublicKey,
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
    let verifier_num = graph.parameters.gc_data.len();
    let watchtower_num = graph.parameters.watchtower_pubkeys.len();
    // 1. check pub_nonces & nonce signatures
    let committee_xonly_pubkey = XOnlyPublicKey::from(*received_committee_pubkey);
    if !verify_nonce_signatures(
        &committee_xonly_pubkey,
        pub_nonces,
        nonce_sigs,
        watchtower_num,
        verifier_num,
    )? {
        tracing::warn!(
            "Ignore NonceGeneration for {instance_id}:{graph_id} from {}: invalid pub_nonces or nonce_sigs",
            received_committee_pubkey.to_string()
        );
        return Ok(());
    }
    if let Err(e) = pub_nonces.validate_length(watchtower_num, verifier_num) {
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
        let graph = BitvmGcGraph::from_simplified(&graph)?;
        let committee_sig_for_graph = endorse_graph(ctx.goat_client, &graph).await?;
        let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
        let instance_keypair = load_committee_instance_keypair(&committee_master_key, instance_id)?;
        let local_committee_pubkey = instance_keypair.public_key().into();
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
    let full_graph = BitvmGcGraph::from_simplified(&graph)?;
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
    graph: &SimplifiedBitvmGcGraph,
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
        let instance_keypair = load_committee_instance_keypair(&committee_master_key, instance_id)?;
        let local_committee_pubkey = instance_keypair.public_key().into();
        let stored_pub_nonce = get_committee_pub_nonce_for_instance(
            ctx.local_db,
            instance_id,
            &local_committee_pubkey,
        )
        .await?;
        if stored_pub_nonce.is_none() {
            let (_, pub_nonce, nonce_sig) =
                committee_master_key.nonce_for_instance_with_keypair(instance_id, instance_keypair);
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
        let graph = BitvmGcGraph::from_simplified(graph)?;
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
    graph: &SimplifiedBitvmGcGraph,
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
        let instance_keypair = load_committee_instance_keypair(&committee_master_key, instance_id)?;
        let local_committee_pubkey = instance_keypair.public_key().into();
        let (sec_nonce, _, _) =
            committee_master_key.nonce_for_instance_with_keypair(instance_id, instance_keypair);
        let agg_nonce =
            nonce_aggregation(&pub_nonces.iter().map(|(_, pn)| pn.clone()).collect::<Vec<_>>());
        let instance_params = get_instance_parameters(ctx.local_db, instance_id)
            .await?
            .ok_or_else(|| anyhow!("Instance parameters not found for {instance_id}"))?;
        let mut pegin_confirm = instance_params.build_pegin_tx()?.1;
        let context = instance_params.get_committee_context(instance_keypair)?;
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
        let graph = BitvmGcGraph::from_simplified(&graph)?;
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
    let mut graph = BitvmGcGraph::from_simplified(&graph)?;
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
        let mut current_graph = BitvmGcGraph::from_simplified(&current_graph)?;
        let current_graph_start_status =
            get_graph_status(ctx.local_db, current_instance_id, current_graph_id)
                .await?
                .ok_or_else(|| {
                    anyhow!("Graph status not found for {current_instance_id}:{current_graph_id}")
                })?;
        let (current_graph_status, _current_graph_sub_status, current_graph_scan) = refresh_graph(
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
            current_graph_scan.as_ref(),
            Some(current_graph_start_status),
            current_graph_start_status,
            current_graph_status,
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
async fn handle_kickoff_sent_verifier(
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
async fn handle_prekickoff_sent_verifier(
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
    let prev_graph = BitvmGcGraph::from_simplified(&prev_graph)?;
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
        verifier_force_skip_kickoff(ctx.btc_client, &prev_graph).await?;
    } else if !prev_graph_status.is_closed() {
        // 3. if previous kickoff is not closed, broadcast quick-challenge/challenge-incomplete-kickoff txn
        verifier_quick_challenge(ctx.btc_client, &prev_graph).await?;
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
    if let Some(challenge_tx) = ctx.btc_client.get_tx(&challenge_txid).await? {
        let challenge_outpoint = graph
            .kickoff
            .connector_a_input()
            .map_err(|e| anyhow!("failed to get connector-a input: {e}"))?
            .outpoint;
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
    let message_content =
        GOATMessageContent::WatchtowerChallengeInitSent(WatchtowerChallengeInitSent {
            instance_id,
            graph_id,
        });
    send_to_peer(ctx.swarm, GOATMessage::new(Actor::Watchtower, message_content)).await?;
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
    let watchtower_challenge_vout =
        output_topology::watchtower_challenge_init::watchtower_connector(node_index) as u64;
    if outpoint_spent_txid(
        ctx.btc_client,
        &watchtower_challenge_init_txid,
        watchtower_challenge_vout,
    )
    .await?
    .is_some()
    {
        tracing::warn!(
            "Ignore WatchtowerChallengeInitSent for {instance_id}:{graph_id}: watchtower challenge already spent"
        );
        return Ok(());
    }
    // watchtower should always challenge
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
    tracing::info!(
        "WatchtowerChallengeSent for {instance_id}:{graph_id}: watchtower_index={node_index}, txid={watchtower_challenge_txid}"
    );
    let message_content = GOATMessageContent::WatchtowerChallengeSent(WatchtowerChallengeSent {
        instance_id,
        graph_id,
        watchtower_index: node_index,
    });
    send_to_peer(ctx.swarm, GOATMessage::new(Actor::Operator, message_content)).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id, watchtower_index = watchtower_index))]
async fn handle_watchtower_challenge_sent_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    watchtower_index: usize,
    content: &GOATMessageContent,
) -> Result<()> {
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
            "Ignore WatchtowerChallengeSent for {instance_id}:{graph_id}: graph status is {graph_status:?}"
        );
        return Ok(());
    }
    let watchtower_num = validate_watchtower_branches(&graph)?;
    if watchtower_index >= watchtower_num {
        bail!("watchtower index {watchtower_index} out of range for {watchtower_num} slots");
    }

    let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
    let watchtower_vout =
        output_topology::watchtower_challenge_init::watchtower_connector(watchtower_index) as u64;
    let Some((watchtower_spent_txid, watchtower_vin, _txin)) =
        outpoint_spent_txin(ctx.btc_client, &watchtower_challenge_init_txid, watchtower_vout)
            .await?
    else {
        tracing::warn!(
            "Ignore WatchtowerChallengeSent for {instance_id}:{graph_id}: watchtower connector {watchtower_index} is not spent yet"
        );
        return Ok(());
    };
    if watchtower_vin != 0 {
        tracing::warn!(
            "Ignore WatchtowerChallengeSent for {instance_id}:{graph_id}: watchtower connector {watchtower_index} was spent by tx {watchtower_spent_txid} at unexpected input index {watchtower_vin}"
        );
        return Ok(());
    }
    let timeout_txid = graph.watchtower_challenge_timeouts[watchtower_index].tx().compute_txid();
    if watchtower_spent_txid == timeout_txid {
        tracing::warn!(
            "Ignore WatchtowerChallengeSent for {instance_id}:{graph_id}: watchtower connector {watchtower_index} was spent by timeout tx {timeout_txid}"
        );
        return Ok(());
    }

    let ack_vout =
        output_topology::watchtower_challenge_init::ack_connector(watchtower_index) as u64;
    if let Some(spent_txid) =
        outpoint_spent_txid(ctx.btc_client, &watchtower_challenge_init_txid, ack_vout).await?
    {
        tracing::warn!(
            "Ignore WatchtowerChallengeSent for {instance_id}:{graph_id}: ack connector {watchtower_index} already spent by {spent_txid}"
        );
        return Ok(());
    }

    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let preimage = operator_master_key.preimage_for_graph(graph_id, watchtower_index);
    let ack_connector_input = graph
        .watchtower_challenge_init
        .ack_connector_input(watchtower_index)
        .map_err(|e| anyhow!("failed to get ack connector input: {e}"))?;
    let ack_input = operator_sign_challenge_ack(&graph, watchtower_index, &preimage)?;
    let ack_txid = build_sign_and_broadcast_tx(
        ctx.btc_client,
        operator_master_key.master_keypair(),
        vec![ack_input],
        ack_connector_input.amount,
        vec![goat::scripts::p2a_output()],
    )
    .await?;
    tracing::info!(
        "Operator challenge ACK sent for {instance_id}:{graph_id}: watchtower_index={watchtower_index}, txid={ack_txid}"
    );
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_watchtower_challenge_timeout_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
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

    let watchtower_num = validate_watchtower_branches(&graph)?;
    let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    for watchtower_index in 0..watchtower_num {
        let watchtower_vout =
            output_topology::watchtower_challenge_init::watchtower_connector(watchtower_index)
                as u64;
        let ack_vout =
            output_topology::watchtower_challenge_init::ack_connector(watchtower_index) as u64;
        if outpoint_spent_txid(ctx.btc_client, &watchtower_challenge_init_txid, watchtower_vout)
            .await?
            .is_some()
            || outpoint_spent_txid(ctx.btc_client, &watchtower_challenge_init_txid, ack_vout)
                .await?
                .is_some()
        {
            continue;
        }

        let timeout_tx = operator_sign_watchtower_challenge_timeout(
            operator_master_key.master_keypair(),
            &mut graph,
            watchtower_index,
        )?;
        if tx_on_chain(ctx.btc_client, &timeout_tx.compute_txid()).await? {
            continue;
        }
        let timeout_txid = timeout_tx.compute_txid();
        let timeout_tx_total_input_amount = graph.watchtower_challenge_timeouts[watchtower_index]
            .prev_outs()
            .iter()
            .map(|o| o.value)
            .sum::<Amount>();
        broadcast_tx_with_cpfp(ctx.btc_client, timeout_tx, timeout_tx_total_input_amount).await?;
        tracing::info!(
            "Watchtower challenge timeout sent for {instance_id}:{graph_id}: watchtower_index={watchtower_index}, txid={timeout_txid}"
        );
    }
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_nack_ready_verifier(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
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
            "Ignore NackReady for {instance_id}:{graph_id}: graph status is {graph_status:?}"
        );
        return Ok(());
    }
    let watchtower_num = validate_watchtower_branches(&graph)?;

    let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
    let connector_f_vout =
        output_topology::watchtower_challenge_init::connector_f(watchtower_num) as u64;
    if outpoint_spent_txid(ctx.btc_client, &watchtower_challenge_init_txid, connector_f_vout)
        .await?
        .is_some()
    {
        tracing::warn!("Ignore NackReady for {instance_id}:{graph_id}: connector-F already spent");
        return Ok(());
    }

    for watchtower_index in 0..watchtower_num {
        let watchtower_vout =
            output_topology::watchtower_challenge_init::watchtower_connector(watchtower_index)
                as u64;
        let Some(watchtower_spent_txid) =
            outpoint_spent_txid(ctx.btc_client, &watchtower_challenge_init_txid, watchtower_vout)
                .await?
        else {
            continue;
        };

        let timeout_txid =
            graph.watchtower_challenge_timeouts[watchtower_index].tx().compute_txid();
        if watchtower_spent_txid == timeout_txid {
            continue;
        }

        let ack_vout =
            output_topology::watchtower_challenge_init::ack_connector(watchtower_index) as u64;
        if outpoint_spent_txid(ctx.btc_client, &watchtower_challenge_init_txid, ack_vout)
            .await?
            .is_some()
        {
            continue;
        }

        let nack = graph
            .operator_challenge_nacks
            .get(watchtower_index)
            .ok_or_else(|| anyhow!("invalid watchtower index {watchtower_index}"))?;
        let nack_tx = nack.tx().clone();
        let nack_txid = nack_tx.compute_txid();
        if tx_on_chain(ctx.btc_client, &nack_txid).await? {
            return Ok(());
        }
        let nack_tx_total_input_amount = nack.prev_outs().iter().map(|o| o.value).sum::<Amount>();
        broadcast_tx_with_cpfp(ctx.btc_client, nack_tx, nack_tx_total_input_amount).await?;
        tracing::info!(
            "Operator challenge NACK sent for {instance_id}:{graph_id}: watchtower_index={watchtower_index}, txid={nack_txid}"
        );
        return Ok(());
    }

    tracing::warn!(
        "Ignore NackReady for {instance_id}:{graph_id}: no watchtower branch is ready for NACK"
    );
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_operator_commit_pubin_ready_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    let message = make_message(ctx, content);
    let Some((graph, _graph_status, _graph_sub_status)) =
        refresh_graph_status(ctx, instance_id, graph_id, Some(&message), GraphStatus::Challenge)
            .await?
    else {
        return Ok(());
    };

    // compute the 96-byte guest pubin
    let watchtower_challenge_init_txid =
        SerializableTxid::from(graph.watchtower_challenge_init.tx().compute_txid());
    let num_watchtowers = graph.parameters.watchtower_pubkeys.len();
    let (challenge_txids, included_watchtowers_bits) =
        get_watchtower_challenge_info(ctx.btc_client, &watchtower_challenge_init_txid, num_watchtowers)
            .await?;
    let (btc_best_block_hash, included_watchtowers_bitmap) =
        compute_operator_pubin_blockhash_and_bitmap(
            ctx.btc_client,
            &challenge_txids,
            &included_watchtowers_bits,
        )
            .await?;
    let guest_pubin = build_operator_guest_pubin(
        &btc_best_block_hash,
        &graph.parameters.pubin_disprove_constant,
        &included_watchtowers_bitmap,
    );

    // sign and broadcast
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let commit_pubin_wots_sk = operator_master_key.commit_pubin_wots_keypair_for_graph(graph_id).0;
    let signed_input = operator_sign_commit_pubin(&graph, &commit_pubin_wots_sk, &guest_pubin)?;
    let connector_e_amount = graph
        .watchtower_challenge_init
        .connector_e_input()
        .map_err(|e| anyhow!("failed to get connector-e input: {e}"))?
        .amount;
    let operator_keypair = operator_master_key.master_keypair();
    build_sign_and_broadcast_tx(
        ctx.btc_client,
        operator_keypair,
        vec![signed_input],
        connector_e_amount,
        vec![],
    )
        .await?;

    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_operator_commit_pubin_timeout_verifier(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
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
            "Ignore OperatorCommitPubinTimeout for {instance_id}:{graph_id}: graph status is {graph_status:?}"
        );
        return Ok(());
    }

    let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
    let watchtower_num = graph.parameters.watchtower_pubkeys.len();
    let connector_e_vout =
        output_topology::watchtower_challenge_init::connector_e(watchtower_num) as u64;
    let connector_f_vout =
        output_topology::watchtower_challenge_init::connector_f(watchtower_num) as u64;
    if outpoint_spent_txid(ctx.btc_client, &watchtower_challenge_init_txid, connector_e_vout)
        .await?
        .is_some()
        || outpoint_spent_txid(ctx.btc_client, &watchtower_challenge_init_txid, connector_f_vout)
            .await?
            .is_some()
    {
        tracing::warn!(
            "Ignore OperatorCommitPubinTimeout for {instance_id}:{graph_id}: timeout input already spent"
        );
        return Ok(());
    }

    let timeout_tx = graph.operator_commit_timeout.tx().clone();
    let timeout_txid = timeout_tx.compute_txid();
    if tx_on_chain(ctx.btc_client, &timeout_txid).await? {
        return Ok(());
    }
    let timeout_tx_total_input_amount =
        graph.operator_commit_timeout.prev_outs().iter().map(|o| o.value).sum::<Amount>();
    broadcast_tx_with_cpfp(ctx.btc_client, timeout_tx, timeout_tx_total_input_amount).await?;
    tracing::info!(
        "Operator commit pubin timeout sent for {instance_id}:{graph_id}: txid={timeout_txid}"
    );
    Ok(())
}


// after the watchtower challenge flow is complete, build proof and broadcast Assert transaction.
#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_assert_ready_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<()> {
    let message = GOATMessage::new(
        Actor::Operator,
        GOATMessageContent::AssertReady(AssertReady { instance_id, graph_id }),
    );
    let (mut graph, _graph_status, _graph_sub_status) =
        match refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::Challenge).await?
        {
            Some(v) => v,
            None => return Ok(()),
        };
    let (operator_proof, wait_secs) = get_operator_proof(
        ctx.local_db,
        ctx.http_client,
        &graph,
        ctx.btc_client,
        instance_id,
        graph_id,
    )
    .await?;

    if wait_secs > 0 {
        tracing::info!(
            "Retry AssertReady later for {instance_id}:{graph_id}: operator proof is not ready"
        );
        push_local_unhandled_messages(ctx.local_db, graph_id, &message, wait_secs).await?;
        return Ok(());
    }

    let Some(operator_proof) = operator_proof else {
        return Ok(());
    };
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let assert_secret_key = operator_master_key.assert_wots_keypair_for_graph(graph_id).0;

    if operator_proof.public_inputs.len() != 2 {
        bail!(
            "operator proof has {} public inputs; expected 2",
            operator_proof.public_inputs.len()
        );
    }
    let dynamic_input = operator_proof.public_inputs[1];
    let assert_witness = build_assert_witness(&operator_proof.proof, &assert_secret_key, dynamic_input)?;
    let assert_message = assert_wots_message(&assert_witness)?;
    let mut asserted_wrapper_proof = Vec::new();
    operator_proof.proof.serialize_compressed(&mut asserted_wrapper_proof)?;
    let mut setup_state = load_babe_setup_state(ctx.local_db, instance_id, graph_id)?
        .ok_or_else(|| anyhow!("missing operator BABE setup state for graph {graph_id}"))?;
    let operator_state = setup_state
        .operator
        .as_mut()
        .ok_or_else(|| anyhow!("missing operator BABE setup state for graph {graph_id}"))?;
    if let Some(existing) = &operator_state.asserted_wrapper_proof
        && existing != &asserted_wrapper_proof
    {
        bail!("operator assertion wrapper proof conflicts with persisted proof");
    }
    operator_state.asserted_wrapper_proof = Some(asserted_wrapper_proof);
    save_babe_setup_state(ctx.local_db, instance_id, graph_id, &setup_state)?;

    let assert_tx = operator_sign_assert(&mut graph, &assert_secret_key, &assert_message)?;
    broadcast_nonstandard_tx(ctx.btc_client, &assert_tx).await?;

    let message_content = GOATMessageContent::AssertSent(AssertSent {
        instance_id,
        graph_id,
        assert_txid: assert_tx.compute_txid(),
        assert_witness: Some(assert_witness),
    });
    send_to_peer(ctx.swarm, GOATMessage::new(Actor::Verifier, message_content)).await?;

    Ok(())
}

// verify Operator DynamicPublicInput and Proof; broadcast PubinDisprove or ChallengeAssert as needed.
#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_assert_sent_verifier(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    assert_txid: Txid,
    assert_witness: &Option<TxAssertWitness>,
) -> Result<()> {
    // TODO: check pubin first, if invalid, directly send PubinDisprove without building ChallengeAssert transaction
    let (graph, _graph_status, _graph_sub_status) =
        match refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::Challenge).await?
        {
            Some(v) => v,
            None => return Ok(()),
        };

    let Some(assert_tx) = ctx.btc_client.get_tx(&assert_txid).await? else {
        tracing::warn!(
            "Ignore AssertSent for {instance_id}:{graph_id}: assert tx {assert_txid} not found on chain"
        );
        return Ok(());
    };
    let Some(assert_witness) = assert_witness else {
        // TODO(gc-v2): recover BabeAssertWitness from the assert tx witness and graph.
        tracing::warn!(
            "Ignore AssertSent for {instance_id}:{graph_id}: assert witness is not available in message"
        );
        return Ok(());
    };

    let verifier_master_key = VerifierMasterKey::new(get_bitvm_key()?);
    let verifier_pubkey = verifier_master_key.master_keypair().public_key().into();
    let Some(verifier_index) =
        find_verifier_index_by_pubkey(&graph.parameters.gc_data, &verifier_pubkey)?
    else {
        tracing::debug!(
            "Ignore AssertSent for {instance_id}:{graph_id}: local verifier has no graph slot"
        );
        return Ok(());
    };
    validate_verifier_slot(&graph, verifier_index)?;

    let Some(saved_verifier_state) = load_babe_setup_state(ctx.local_db, instance_id, graph_id)?
        .and_then(|state| state.verifier)
    else {
        tracing::warn!(
            "Ignore AssertSent for {instance_id}:{graph_id}: missing BABE verifier setup state"
        );
        return Ok(());
    };
    if saved_verifier_state.verifier_index != Some(verifier_index) {
        tracing::warn!(
            "Ignore AssertSent for {instance_id}:{graph_id}: local setup slot does not match graph owner slot"
        );
        return Ok(());
    }
    let vk = crate::vk::get_vk().await.context("load Groth16 verifying key for BABE challenge")?;
    let static_input = derive_operator_statement(graph_id)?.static_input;
    let challenge_witness = build_real_challenge_assert_witness(
        &saved_verifier_state.private_state,
        &saved_verifier_state.setup_package,
        &saved_verifier_state.finalized_indices,
        &vk,
        static_input,
        &graph.parameters.operator_assert_wots_pubkey,
        assert_witness,
        verifier_index,
    )?;
    let labels: [Vec<u8>; goat::assert_scripts::INPUT_WIRE_NUM] = challenge_witness
        .witness
        .input_labels
        .iter()
        .map(|label| label.to_vec())
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|labels: Vec<Vec<u8>>| {
            anyhow!(
                "BABE challenge witness exposes {} labels; expected {}",
                labels.len(),
                goat::assert_scripts::INPUT_WIRE_NUM
            )
        })?;
    let operator_assert_txin = assert_tx
        .input
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("operator assert transaction has no input"))?;
    let challenge_assert_tx =
        build_verifier_assert_tx(&graph, operator_assert_txin, verifier_index, labels)?;
    broadcast_nonstandard_tx(ctx.btc_client, &challenge_assert_tx).await?;
    let message_content = GOATMessageContent::ChallengeAssertSent(ChallengeAssertSent {
        instance_id,
        graph_id,
        challenge_assert_txid: challenge_assert_tx.compute_txid(),
        verifier_index,
        challenge_witness: Some(challenge_witness),
    });
    send_to_peer(ctx.swarm, GOATMessage::new(Actor::Operator, message_content)).await?;

    Ok(())
}

// compute msg after ChallengeAssert is broadcast and broadcast WronglyChallenge transaction.
#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_challenge_assert_sent_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    challenge_assert_txid: Txid,
    verifier_index: usize,
    challenge_witness: &Option<BabeChallengeAssertWitness>,
    content: &GOATMessageContent,
) -> Result<()> {
    let (graph, _graph_status, _graph_sub_status) =
        match refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::Challenge).await?
        {
            Some(v) => v,
            None => return Ok(()),
        };
    let Some(challenge_witness) = challenge_witness else {
        // TODO(gc-v2): recover BabeChallengeAssertWitness from the challenge tx witness and graph.
        tracing::warn!(
            "Ignore ChallengeAssertSent for {instance_id}:{graph_id}: challenge witness is not available in message"
        );
        return Ok(());
    };

    validate_verifier_slot(&graph, verifier_index)?;
    validate_challenge_witness_index(verifier_index, challenge_witness)?;
    validate_expected_challenge_assert_txid(&graph, verifier_index, challenge_assert_txid)?;

    let Some(challenge_assert_tx) = ctx.btc_client.get_tx(&challenge_assert_txid).await? else {
        let delay_secs = todo_funcs::avg_block_time_secs(ctx.btc_client.network());
        let message = make_message(ctx, content);
        push_local_unhandled_messages(ctx.local_db, graph_id, &message, delay_secs as usize)
            .await?;
        tracing::info!(
            "Retry ChallengeAssertSent later for {instance_id}:{graph_id}: challenge assert tx {challenge_assert_txid} not found on chain"
        );
        return Ok(());
    };

    let labels: [Vec<u8>; goat::assert_scripts::INPUT_WIRE_NUM] = challenge_witness
        .witness
        .input_labels
        .iter()
        .map(|label| label.to_vec())
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|labels: Vec<Vec<u8>>| {
            anyhow!(
                "BABE challenge witness exposes {} labels; expected {}",
                labels.len(),
                goat::assert_scripts::INPUT_WIRE_NUM
            )
        })?;
    let operator_assert_txid = challenge_assert_tx
        .input
        .first()
        .ok_or_else(|| anyhow!("published verifier assert transaction has no input"))?
        .previous_output
        .txid;
    let operator_assert_tx =
        ctx.btc_client.get_tx(&operator_assert_txid).await?.ok_or_else(|| {
            anyhow!("published operator assert transaction {operator_assert_txid} is unavailable")
        })?;
    let operator_assert_txin = operator_assert_tx
        .input
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("published operator assert transaction has no input"))?;
    let expected_challenge_assert =
        build_verifier_assert_tx(&graph, operator_assert_txin, verifier_index, labels)?;
    if expected_challenge_assert.input.first().map(|input| &input.witness)
        != challenge_assert_tx.input.first().map(|input| &input.witness)
    {
        bail!("published verifier assert witness does not match BABE challenge labels");
    }

    let setup_state = load_babe_setup_state(ctx.local_db, instance_id, graph_id)?
        .ok_or_else(|| anyhow!("missing operator BABE setup state for graph {graph_id}"))?;
    let operator_state = setup_state
        .operator
        .ok_or_else(|| anyhow!("missing operator BABE setup state for graph {graph_id}"))?;
    let candidate = operator_state
        .candidates
        .iter()
        .find(|candidate| candidate.verifier_index == Some(verifier_index))
        .ok_or_else(|| anyhow!("missing BABE prover state for verifier slot {verifier_index}"))?;
    let prover_state = candidate
        .prover_state
        .as_ref()
        .ok_or_else(|| anyhow!("missing BABE prover state for verifier slot {verifier_index}"))?;
    let proof_bytes = operator_state
        .asserted_wrapper_proof
        .as_ref()
        .ok_or_else(|| anyhow!("missing asserted wrapper proof for graph {graph_id}"))?;
    let proof = Groth16Proof::deserialize_compressed(proof_bytes.as_slice())
        .context("deserialize asserted wrapper proof")?;
    let vk = crate::vk::get_vk().await.context("load Groth16 verifying key for BABE wrongly challenged")?;
    let (_, dyn_pubin) = TxAssertWitness { wots_sig: challenge_witness.witness.wots_sig.clone() }
        .recover_pi1_xd_without_verify()
        .ok_or_else(|| anyhow!("cannot recover dynamic input from challenge witness WOTS signature"))?;
    let wrongly_challenged_witness =
        recover_real_wrongly_challenged_witness(prover_state, challenge_witness, &proof, vk, dyn_pubin)?;
    let (wrongly_challenged_input, _amount) = operator_sign_wrongly_challenged(
        &graph,
        verifier_index,
        &wrongly_challenged_witness.final_msg,
    )?;

    let wrongly_challenged_tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![wrongly_challenged_input],
        output: vec![goat::scripts::p2a_output()],
    };
    broadcast_nonstandard_tx(ctx.btc_client, &wrongly_challenged_tx).await?;

    Ok(())
}

// broadcast NoWithdraw after the ChallengeAssert timelock expires.
#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_wrongly_challenge_timeout_verifier(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    challenge_assert_txid: Txid,
    verifier_index: usize,
    content: &GOATMessageContent,
) -> Result<()> {
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
    validate_verifier_slot(&graph, verifier_index)?;
    validate_expected_challenge_assert_txid(&graph, verifier_index, challenge_assert_txid)?;
    let verifier_master_key = VerifierMasterKey::new(get_bitvm_key()?);
    let local_verifier_pubkey: PublicKey = verifier_master_key.master_keypair().public_key().into();
    if graph.parameters.gc_data[verifier_index].verifier_pubkey != local_verifier_pubkey {
        tracing::debug!(
            "Ignore WronglyChallengeTimeout for {instance_id}:{graph_id}: local verifier does not own slot {verifier_index}"
        );
        return Ok(());
    }

    let delay_secs = todo_funcs::avg_block_time_secs(ctx.btc_client.network());
    let message = make_message(ctx, content);
    if ctx.btc_client.get_tx(&challenge_assert_txid).await?.is_none() {
        push_local_unhandled_messages(ctx.local_db, graph_id, &message, delay_secs as usize)
            .await?;
        tracing::info!(
            "Retry WronglyChallengeTimeout later for {instance_id}:{graph_id}: challenge assert tx {challenge_assert_txid} not found on chain"
        );
        return Ok(());
    }

    let challenge_assert_height = match ctx
        .btc_client
        .get_tx_status(&challenge_assert_txid)
        .await?
        .block_height
    {
        Some(height) => height as u64,
        None => {
            push_local_unhandled_messages(ctx.local_db, graph_id, &message, delay_secs as usize)
                .await?;
            tracing::info!(
                "Retry WronglyChallengeTimeout later for {instance_id}:{graph_id}: challenge assert tx {challenge_assert_txid} is not confirmed"
            );
            return Ok(());
        }
    };

    let disprove_height = challenge_assert_height
        + disprove_timelock(graph.parameters.instance_parameters.network) as u64;
    let goat_confirmed_height = ctx.goat_client.btc_spv_latest_height().await?;
    if goat_confirmed_height < disprove_height {
        let retry_secs = todo_funcs::avg_block_time_secs(ctx.btc_client.network())
            * (disprove_height - goat_confirmed_height);
        push_local_unhandled_messages(ctx.local_db, graph_id, &message, retry_secs as usize)
            .await?;
        tracing::info!(
            "Retry WronglyChallengeTimeout later for {instance_id}:{graph_id}: disprove timelock has not expired"
        );
        return Ok(());
    }
    if let Some(spent_txid) = outpoint_spent_txid(ctx.btc_client, &challenge_assert_txid, 0).await?
    {
        tracing::info!(
            "Skip Disprove for {instance_id}:{graph_id} slot {verifier_index}: verifier assertion output already spent by {spent_txid}"
        );
        return Ok(());
    }

    let disprove_tx = build_disprove_tx(&graph, verifier_index, None)?;
    broadcast_nonstandard_tx(ctx.btc_client, &disprove_tx).await?;

    let message_content = GOATMessageContent::DisproveSent(DisproveSent {
        instance_id,
        graph_id,
        disprove_type: DisproveTxType::Disprove,
        index: verifier_index,
        challenge_start_txid: Some(challenge_assert_txid),
        challenge_finish_txid: disprove_tx.compute_txid(),
    });
    send_to_peer(ctx.swarm, GOATMessage::new(Actor::Committee, message_content)).await?;

    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id
))]
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
    let connector_a_vout = output_topology::kickoff::connector_a() as u64;
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
    let connector_a_vout = output_topology::kickoff::connector_a() as u64;
    let guardian_connector_vout = output_topology::kickoff::guardian_connector() as u64;
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
    let operator_assert_txid = graph.operator_assert.tx().compute_txid();
    // Take2 spends Connector-0, Connector-D, and Guardian Connector. Recheck every input before
    // signing so a stale Take2Ready cannot race an already-spent connector.
    let take2_inputs =
        graph.take2.tx().input.iter().map(|txin| txin.previous_output).collect::<Vec<OutPoint>>();
    for previous_output in take2_inputs {
        if let Some(spent_txid) =
            outpoint_spent_txid(ctx.btc_client, &previous_output.txid, previous_output.vout as u64)
                .await?
        {
            tracing::warn!(
                "Ignore Take2Ready for {instance_id}:{graph_id}: take2 input {}:{} already spent by {}",
                previous_output.txid,
                previous_output.vout,
                spent_txid
            );
            return Ok(());
        }
    }
    let operator_assert_height = match ctx
        .btc_client
        .get_tx_status(&operator_assert_txid)
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
    if !is_take2_timelock_expired(ctx.btc_client, operator_assert_height).await? {
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
    graph: &SimplifiedBitvmGcGraph,
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
    let graph = BitvmGcGraph::from_simplified(graph)?;
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitvm_lib::babe_adapter::{
        BABE_M_CC, BabeProverState, build_setup_package, open_and_solder,
    };

    use super::*;

    fn verifier_pubkey() -> PublicKey {
        PublicKey::from_str("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap()
    }

    fn gc_submission() -> (CACSetupPackage, BitvmGcCircuitData, BabeProverState) {
        let package = build_setup_package(BABE_M_CC + 1).unwrap();
        let selected = (0..BABE_M_CC).collect::<Vec<_>>();
        let (_, finalized, soldering) = open_and_solder(&package, &selected).unwrap();
        let epk = &package.commits[finalized[0].index].epk;
        let h_msgs: Vec<[u8; 20]> = finalized.iter().map(|f| package.commits[f.index].h_msg).collect();
        let gc_data = extract_gc_circuit_data(verifier_pubkey(), epk, &h_msgs).unwrap();
        let prover_state = BabeProverState {
            package: package.clone(),
            finalized,
            soldering,
            h_msgs: gc_data.final_msg_hashlocks.clone(),
        };
        (package, gc_data, prover_state)
    }

    fn operator_state(package: CACSetupPackage) -> OperatorBabeSetupState {
        OperatorBabeSetupState {
            frozen_verifier_pubkeys: Some(vec![verifier_pubkey()]),
            candidates: vec![OperatorVerifierCandidate {
                verifier_pubkey: verifier_pubkey(),
                setup_package: package,
                verifier_index: Some(0),
                selected_circuit_indexes: (0..BABE_M_CC).collect(),
                gc_data: None,
                prover_state: None,
            }],
            asserted_wrapper_proof: None,
        }
    }

    #[test]
    fn freeze_operator_candidate_selects_protocol_finalized_count() {
        let package = build_setup_package(BABE_M_CC + 1).unwrap();
        let mut state = OperatorBabeSetupState {
            frozen_verifier_pubkeys: None,
            candidates: vec![OperatorVerifierCandidate {
                verifier_pubkey: verifier_pubkey(),
                setup_package: package,
                verifier_index: None,
                selected_circuit_indexes: vec![],
                gc_data: None,
                prover_state: None,
            }],
            asserted_wrapper_proof: None,
        };

        freeze_operator_candidates(&mut state).unwrap();

        assert_eq!(state.candidates[0].selected_circuit_indexes.len(), BABE_M_CC);
    }

    #[test]
    fn candidate_records_one_slot_and_full_prover_state_idempotently() {
        let (package, gc_data, prover_state) = gc_submission();
        let mut state = operator_state(package.clone());

        let graph_data = record_candidate_gc_data(
            &mut state,
            verifier_pubkey(),
            0,
            &package,
            gc_data.clone(),
            prover_state.clone(),
        )
        .unwrap()
        .unwrap();

        assert_eq!(graph_data.len(), 1);
        assert_eq!(graph_data[0].final_msg_hashlocks.len(), BABE_M_CC);
        assert_eq!(state.candidates[0].prover_state.as_ref().unwrap().finalized.len(), BABE_M_CC);

        let duplicate = record_candidate_gc_data(
            &mut state,
            verifier_pubkey(),
            0,
            &package,
            gc_data.clone(),
            prover_state.clone(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(duplicate.len(), 1);

        let mut conflict = prover_state;
        conflict.h_msgs[0][0] ^= 1;
        assert!(
            record_candidate_gc_data(
                &mut state,
                verifier_pubkey(),
                0,
                &package,
                gc_data,
                conflict,
            )
            .is_err()
        );
    }

    #[test]
    fn legacy_operator_candidate_without_prover_state_deserializes() {
        let (package, _, _) = gc_submission();
        let mut value = serde_json::to_value(operator_state(package)).unwrap();
        value["candidates"][0].as_object_mut().unwrap().remove("prover_state");

        let restored: OperatorBabeSetupState = serde_json::from_value(value).unwrap();

        assert!(restored.candidates[0].prover_state.is_none());
    }
}
