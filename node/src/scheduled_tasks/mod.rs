mod event_watche_task;
pub mod graph_maintenance_tasks;
pub mod instance_maintenance_tasks;

use crate::client::btc_chain::BTCClient;
use crate::client::goat_chain::GOATClient;
use crate::middleware::AllBehaviours;
use crate::scheduled_tasks::graph_maintenance_tasks::{
    scan_assert, scan_kickoff, scan_take1, scan_take2, scan_withdraw,
};
use crate::scheduled_tasks::instance_maintenance_tasks::{
    instance_answers_monitor, instance_btc_tx_monitor, instance_expiration_monitor,
    instance_window_expiration_monitor, scan_post_graph_data, scan_post_pegin_data,
};
pub use event_watche_task::{is_processing_history_events, run_watch_event_task};
use libp2p::Swarm;
use store::localdb::LocalDB;
use tracing::warn;

pub async fn relayer_scheduled_tasks(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
) -> Result<(), Box<dyn std::error::Error>> {
    if is_processing_history_events(local_db, goat_client).await? {
        warn!("Still in history events processing");
        return Ok(());
    }

    if let Err(err) = instance_window_expiration_monitor(local_db, goat_client).await {
        warn!("instance_window_expiration_monitor, err {:?}", err)
    }

    if let Err(err) = instance_expiration_monitor(local_db).await {
        warn!("instance_expiration_monitor, err {:?}", err)
    }

    if let Err(err) = instance_btc_tx_monitor(swarm, local_db, btc_client).await {
        warn!("instance_btc_tx_monitor, err {:?}", err)
    }

    if let Err(err) = scan_post_pegin_data(swarm, local_db, btc_client, goat_client).await {
        warn!("scan_post_operator_data, err {:?}", err)
    }

    if let Err(err) = scan_post_graph_data(swarm, local_db, goat_client).await {
        warn!("scan_post_operator_data, err {:?}", err)
    }

    if let Err(err) = scan_withdraw(swarm, local_db, goat_client, btc_client).await {
        warn!("scan_withdraw, err {:?}", err)
    }

    if let Err(err) = scan_kickoff(swarm, local_db, btc_client, goat_client).await {
        warn!("scan_kickoff, err {:?}", err)
    }

    if let Err(err) = scan_assert(swarm, local_db, btc_client).await {
        warn!("scan_assert, err {:?}", err)
    }

    if let Err(err) = scan_take1(swarm, local_db, btc_client, goat_client).await {
        warn!("scan_take1, err {:?}", err)
    }

    if let Err(err) = scan_take2(swarm, local_db, btc_client, goat_client).await {
        warn!("scan_take2, err {:?}", err)
    }
    Ok(())
}

pub async fn committee_scheduled_tasks(
    _swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    _btc_client: &BTCClient,
    goat_client: &GOATClient,
) -> Result<(), Box<dyn std::error::Error>> {
    if is_processing_history_events(local_db, goat_client).await? {
        warn!("Still in history events processing");
        return Ok(());
    }

    if let Err(err) = instance_answers_monitor(local_db, goat_client).await {
        warn!("instance_window_expiration_monitor, err {:?}", err)
    }

    // if let Err(err) = instance_window_expiration_monitor(local_db,  goat_client).await {
    //     warn!("instance_window_expiration_monitor, err {:?}", err)
    // }
    //
    // if let Err(err) = instance_expiration_monitor( local_db).await {
    //     warn!("instance_expiration_monitor, err {:?}", err)
    // }
    // if let Err(err) = instance_btc_tx_monitor(swarm, local_db, btc_client).await {
    //     warn!("instance_btc_tx_monitor, err {:?}", err)
    // }
    Ok(())
}
