use crate::action::{
    GOATMessage, GOATMessageContent, push_local_unhandled_messages,
};
use crate::utils::{get_graph, outpoint_spent_txid};
use anyhow::{Result, anyhow, bail};
use bitvm2_lib::actors::Actor;
use bitvm2_lib::types::Bitvm2Graph;
use client::btc_chain::BTCClient;
use goat::transactions::pre_signed::PreSignedTransaction;
use store::localdb::LocalDB;
use store::GraphStatus;

use crate::scheduled_tasks::graph_maintenance_tasks::ChallengeSubStatus;
use client::goat_chain::DisproveTxType;
use uuid::Uuid;

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy)]
enum GraphCompensateEventKind {
    PreKickoffSent, // OperatorDataPushed -> PreKickoff
    KickoffSent,    // PreKickoff -> OperatorKickOff
    Take1Sent,      // OperatorKickOff -> OperatorTake1
    ChallengeSent,  // OperatorKickOff -> Challenge
    DisproveSent,   // Challenge -> Disprove
    Take2Sent,      // Challenge -> OperatorTake2
}

fn map_transition_to_event(from: GraphStatus, to: GraphStatus) -> Option<GraphCompensateEventKind> {
    use GraphStatus::*;
    match (from, to) {
        (OperatorDataPushed, PreKickoff) => Some(GraphCompensateEventKind::PreKickoffSent),
        (PreKickoff, OperatorKickOff) => Some(GraphCompensateEventKind::KickoffSent),
        (OperatorKickOff, OperatorTake1) => Some(GraphCompensateEventKind::Take1Sent),
        (OperatorKickOff, Challenge) => Some(GraphCompensateEventKind::ChallengeSent),
        (Challenge, Disprove) => Some(GraphCompensateEventKind::DisproveSent),
        (Challenge, OperatorTake2) => Some(GraphCompensateEventKind::Take2Sent),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn compensate_graph_events(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    instance_id: Uuid,
    graph_id: Uuid,
    graph: Option<&Bitvm2Graph>,
    scan_from_status: Option<GraphStatus>,
    compensate_from_status: GraphStatus,
    final_status: GraphStatus,
    final_sub_status: Option<ChallengeSubStatus>,
) -> Result<()> {
    use GOATMessageContent::*;

    let scan_start = scan_from_status.unwrap_or(compensate_from_status);

    let effective_from = if scan_start.is_after(&compensate_from_status) {
        scan_start
    } else {
        compensate_from_status
    };

    if !effective_from.is_before(&final_status) {
        tracing::debug!(
            "Skip compensating graph events: effective_from {effective_from:?} is not before final_status {final_status:?}",
        );
        return Ok(());
    }

    let mut rev_path = Vec::new();
    let mut cur = final_status;
    loop {
        rev_path.push(cur);
        if cur == effective_from {
            break;
        }
        cur = match cur.get_previous_status() {
            Some(prev) => prev,
            None => {
                tracing::debug!(
                    "Stop compensating graph events early: no previous status for {cur:?} while targeting {effective_from:?}",
                );
                return Ok(());
            }
        };
    }
    rev_path.reverse();

    for window in rev_path.windows(2) {
        let s_from = window[0];
        let s_to = window[1];

        if let Some(kind) = map_transition_to_event(s_from, s_to) {
            match kind {
                GraphCompensateEventKind::PreKickoffSent => {
                    let prekickoff_sent =
                        PreKickoffSent(crate::action::PreKickoffSent { instance_id, graph_id });
                    let message = GOATMessage::from_typed(Actor::All, &prekickoff_sent)?;
                    push_local_unhandled_messages(local_db, graph_id, &message, 0).await?;
                }
                GraphCompensateEventKind::KickoffSent => {
                    let kickoff_sent =
                        KickoffSent(crate::action::KickoffSent { instance_id, graph_id });
                    let message = GOATMessage::from_typed(Actor::All, &kickoff_sent)?;
                    push_local_unhandled_messages(local_db, graph_id, &message, 0).await?;
                }
                GraphCompensateEventKind::Take1Sent => {
                    let take1_sent = Take1Sent(crate::action::Take1Sent { instance_id, graph_id });
                    let message = GOATMessage::from_typed(Actor::All, &take1_sent)?;
                    push_local_unhandled_messages(local_db, graph_id, &message, 0).await?;
                }
                GraphCompensateEventKind::ChallengeSent => {
                    let graph = match graph {
                        Some(g) => g,
                        None => {
                            let g = get_graph(local_db, instance_id, graph_id).await?;
                            match g {
                                Some(g) => &Bitvm2Graph::from_simplified(&g)?,
                                None => bail!("Graph {graph_id} not found in local db"),
                            }
                        }
                    };
                    let kickoff_txid = graph.kickoff.tx().compute_txid();
                    let take1_txid = graph.take1.tx().compute_txid();
                    let connector_a_vout = 0;
                    if let Some(challenge_txid) =
                        outpoint_spent_txid(btc_client, &kickoff_txid, connector_a_vout).await?
                        && challenge_txid != take1_txid
                    {
                        let challenge_sent = ChallengeSent(crate::action::ChallengeSent {
                            instance_id,
                            graph_id,
                            challenge_txid,
                        });
                        let message = GOATMessage::from_typed(Actor::All, &challenge_sent)?;
                        push_local_unhandled_messages(local_db, graph_id, &message, 0).await?;
                    }
                }
                GraphCompensateEventKind::DisproveSent => {
                    let sub_status = match final_sub_status {
                        Some(ref s) => s,
                        None => {
                            tracing::error!(
                                "No final_sub_status provided for DisproveSent compensation!"
                            );
                            continue;
                        }
                    };
                    let disprove_type = match sub_status.disprove_type {
                        Some(t) => t,
                        None => {
                            tracing::error!(
                                "No disprove_type in final_sub_status for DisproveSent compensation!"
                            );
                            continue;
                        }
                    };
                    let graph = match graph {
                        Some(g) => g,
                        None => {
                            let g = get_graph(local_db, instance_id, graph_id).await?;
                            match g {
                                Some(g) => &Bitvm2Graph::from_simplified(&g)?,
                                None => bail!("Graph {graph_id} not found in local db"),
                            }
                        }
                    };
                    let kickoff_txid = graph.kickoff.tx().compute_txid();
                    let take1_txid = graph.take1.tx().compute_txid();
                    let connector_a_vout = 0;
                    let challenge_start_txid = if let Some(challenge_txid) =
                        outpoint_spent_txid(btc_client, &kickoff_txid, connector_a_vout).await?
                    {
                        if challenge_txid == take1_txid {
                            tracing::error!("Take1 found for DisproveSent compensation!");
                            continue;
                        }
                        Some(challenge_txid)
                    } else {
                        None
                    };
                    let challenge_finish_txid = match disprove_type {
                        DisproveTxType::Disprove => {
                            let connector_e_vout = 3;
                            outpoint_spent_txid(btc_client, &kickoff_txid, connector_e_vout)
                                .await?
                                .ok_or(anyhow!(
                                    "No Disprove txn found for DisproveSent compensation!"
                                ))?
                        }
                        DisproveTxType::OperatorCommitTimeout => {
                            let watchtower_num = graph.parameters.watchtower_pubkeys.len();
                            let connector_f_vout = watchtower_num * 2 + 1;
                            let watchtower_challenge_init_txid =
                                graph.watchtower_challenge_init.tx().compute_txid();
                            outpoint_spent_txid(
                                btc_client,
                                &watchtower_challenge_init_txid,
                                connector_f_vout as u64,
                            )
                            .await?
                            .ok_or(anyhow!(
                                "No OperatorCommitTimeout txn found for DisproveSent compensation!"
                            ))?
                        }
                        DisproveTxType::OperatorNack => {
                            let watchtower_num = graph.parameters.watchtower_pubkeys.len();
                            let connector_f_vout = watchtower_num * 2 + 1;
                            let watchtower_challenge_init_txid =
                                graph.watchtower_challenge_init.tx().compute_txid();
                            outpoint_spent_txid(
                                btc_client,
                                &watchtower_challenge_init_txid,
                                connector_f_vout as u64,
                            )
                            .await?
                            .ok_or(anyhow!(
                                "No OperatorNack txn found for DisproveSent compensation!"
                            ))?
                        }
                        DisproveTxType::AssertTimeout => {
                            let assert_commit_num = graph.assert_commit_timeout_txns.len();
                            let connector_d_vout = assert_commit_num;
                            let assert_init_txid = graph.assert_init.tx().compute_txid();
                            outpoint_spent_txid(
                                btc_client,
                                &assert_init_txid,
                                connector_d_vout as u64,
                            )
                            .await?
                            .ok_or(anyhow!(
                                "No AssertTimeout txn found for DisproveSent compensation!"
                            ))?
                        }
                        DisproveTxType::QuickChallenge => {
                            let guardian_connector_vout = 4;
                            outpoint_spent_txid(btc_client, &kickoff_txid, guardian_connector_vout)
                                .await?
                                .ok_or(anyhow!(
                                    "No QuickChallenge txn found for DisproveSent compensation!"
                                ))?
                        }
                        DisproveTxType::ChallengeIncompleteKickoff => {
                            let guardian_connector_vout = 4;
                            outpoint_spent_txid(btc_client, &kickoff_txid, guardian_connector_vout)
                                .await?
                                .ok_or(
                                    anyhow!("No ChallengeIncompleteKickoff txn found for DisproveSent compensation!")
                                )?
                        }
                    };
                    let disprove_sent = DisproveSent(crate::action::DisproveSent {
                        instance_id,
                        graph_id,
                        disprove_type,
                        index: sub_status.disprove_index as usize,
                        challenge_start_txid,
                        challenge_finish_txid,
                    });
                    let message = GOATMessage::from_typed(Actor::All, &disprove_sent)?;
                    push_local_unhandled_messages(local_db, graph_id, &message, 0).await?;
                }
                GraphCompensateEventKind::Take2Sent => {
                    let take2_sent = Take2Sent(crate::action::Take2Sent { instance_id, graph_id });
                    let message = GOATMessage::from_typed(Actor::All, &take2_sent)?;
                    push_local_unhandled_messages(local_db, graph_id, &message, 0).await?;
                }
            }
        }
    }

    Ok(())
}