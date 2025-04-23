use bitvm2_lib::actors::Actor;
use client::client::BitVM2Client;
use goat::{
    constants::{CONNECTOR_3_TIMELOCK, CONNECTOR_4_TIMELOCK},
    utils::num_blocks_per_network,
};
use libp2p::Swarm;
use store::GraphStatus;
use uuid::Uuid;

use crate::{
    action::{
        send_to_peer, todo_funcs::tx_on_chain, AssertSent, GOATMessage, GOATMessageContent,
        KickoffReady, KickoffSent, Take1Ready, Take2Ready,
    },
    env::get_network,
    middleware::AllBehaviours,
};

mod todo_funcs {
    use bitcoin::Txid;
    use goat::transactions::assert::utils::COMMIT_TX_NUM;
    use store::GraphStatus;

    use super::*;

    pub async fn get_initialized_graphs(
        client: &BitVM2Client,
    ) -> Result<Vec<(Uuid, Uuid)>, Box<dyn std::error::Error>> {
        // call L2 contract : getInitializedInstanceIds
        // returns Vec<(instance_id, graph_id)>
        Err("TODO".into())
    }

    pub async fn get_avaiable_graphs_by_status(
        client: &BitVM2Client,
        status: GraphStatus,
    ) -> Result<Vec<(Uuid, Uuid)>, Box<dyn std::error::Error>> {
        // If instance corresponding to the graph has already been consumed, the graph is excluded.
        // When a graph enters the take1/take2 status, mark its corresponding instance as consumed.
        Err("TODO".into())
    }

    pub async fn get_graph_kickoff_txid(
        client: &BitVM2Client,
        graph_id: Uuid,
    ) -> Result<Txid, Box<dyn std::error::Error>> {
        Err("TODO".into())
    }

    pub type AssertTxids = (Txid, [Txid; COMMIT_TX_NUM], Txid);
    pub async fn get_graph_assert_txids(
        client: &BitVM2Client,
        graph_id: Uuid,
    ) -> Result<AssertTxids, Box<dyn std::error::Error>> {
        Err("TODO".into())
    }
}

pub async fn scan_bridge_in_prepare(
    swarm: &mut Swarm<AllBehaviours>,
    client: &BitVM2Client,
) -> Result<(), Box<dyn std::error::Error>> {
    // scan bridge-in-prepare message & send CreateInstance message
    Err("TODO".into())
}

pub async fn scan_bridge_in(
    swarm: &mut Swarm<AllBehaviours>,
    client: &BitVM2Client,
) -> Result<(), Box<dyn std::error::Error>> {
    // scan bridge-in tx & relay to L2 contract: postPeginData & postOperatorData
    Err("TODO".into())
}

pub async fn scan_withdraw(
    swarm: &mut Swarm<AllBehaviours>,
    client: &BitVM2Client,
) -> Result<(), Box<dyn std::error::Error>> {
    let graphs = todo_funcs::get_initialized_graphs(client).await?;
    for (instance_id, graph_id) in graphs {
        let message_content =
            GOATMessageContent::KickoffReady(KickoffReady { instance_id, graph_id });
        send_to_peer(swarm, GOATMessage::from_typed(Actor::Operator, &message_content)?)?;
        // TODO: Avoid sending duplicate messages frequently
    }
    Err("TODO".into())
}

pub async fn scan_kickoff(
    swarm: &mut Swarm<AllBehaviours>,
    client: &BitVM2Client,
) -> Result<(), Box<dyn std::error::Error>> {
    let graphs =
        todo_funcs::get_avaiable_graphs_by_status(client, GraphStatus::CommitteePresigned).await?;
    for (instance_id, graph_id) in graphs {
        let kickoff_txid = todo_funcs::get_graph_kickoff_txid(&client, graph_id).await?;
        if tx_on_chain(client, &kickoff_txid).await? {
            let message_content = GOATMessageContent::KickoffSent(KickoffSent {
                instance_id,
                graph_id,
                kickoff_txid,
            });
            send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
            // TODO: Avoid sending duplicate messages frequently
        }
    }
    Err("TODO".into())
}

pub async fn scan_assert(
    swarm: &mut Swarm<AllBehaviours>,
    client: &BitVM2Client,
) -> Result<(), Box<dyn std::error::Error>> {
    let graphs_a =
        todo_funcs::get_avaiable_graphs_by_status(client, GraphStatus::Challenge).await?;
    let graphs_b = todo_funcs::get_avaiable_graphs_by_status(client, GraphStatus::KickOff).await?; // in case challenger never broadcast ChallengeSent
    let graphs = vec![graphs_a, graphs_b].concat();
    for (instance_id, graph_id) in graphs {
        let (assert_init_txid, assert_commit_txids, assert_final_txid) =
            todo_funcs::get_graph_assert_txids(client, graph_id).await?;
        if tx_on_chain(client, &assert_final_txid).await? {
            let message_content = GOATMessageContent::AssertSent(AssertSent {
                instance_id,
                graph_id,
                assert_init_txid,
                assert_commit_txids,
                assert_final_txid,
            });
            send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?)?;
            // TODO: Avoid sending duplicate messages frequently
        }
    }
    Err("TODO".into())
}

pub async fn scan_take1(
    swarm: &mut Swarm<AllBehaviours>,
    client: &BitVM2Client,
) -> Result<(), Box<dyn std::error::Error>> {
    let graphs = todo_funcs::get_avaiable_graphs_by_status(client, GraphStatus::KickOff).await?;
    let current_height = client.esplora.get_height().await?;
    let lock_blocks = num_blocks_per_network(get_network(), CONNECTOR_3_TIMELOCK);
    for (instance_id, graph_id) in graphs {
        let kickoff_txid = todo_funcs::get_graph_kickoff_txid(&client, graph_id).await?;
        if let Some(kickoff_height) =
            client.esplora.get_tx_status(&kickoff_txid).await?.block_height
        {
            if kickoff_height + lock_blocks > current_height {
                let message_content =
                    GOATMessageContent::Take1Ready(Take1Ready { instance_id, graph_id });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::Operator, &message_content)?)?;
                // TODO: Avoid sending duplicate messages frequently
            }
        }
    }
    Err("TODO".into())
}

pub async fn scan_take2(
    swarm: &mut Swarm<AllBehaviours>,
    client: &BitVM2Client,
) -> Result<(), Box<dyn std::error::Error>> {
    let graphs = todo_funcs::get_avaiable_graphs_by_status(client, GraphStatus::Assert).await?;
    let current_height = client.esplora.get_height().await?;
    let lock_blocks = num_blocks_per_network(get_network(), CONNECTOR_4_TIMELOCK);
    for (instance_id, graph_id) in graphs {
        let (_, _, assert_final_txid) =
            todo_funcs::get_graph_assert_txids(&client, graph_id).await?;
        if let Some(assert_height) =
            client.esplora.get_tx_status(&assert_final_txid).await?.block_height
        {
            if assert_height + lock_blocks > current_height {
                let message_content =
                    GOATMessageContent::Take2Ready(Take2Ready { instance_id, graph_id });
                send_to_peer(swarm, GOATMessage::from_typed(Actor::Operator, &message_content)?)?;
                // TODO: Avoid sending duplicate messages frequently
            }
        }
    }
    Err("TODO".into())
}
