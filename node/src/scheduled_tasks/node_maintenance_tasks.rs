use alloy::primitives::Address;
use bitvm2_lib::actors::Actor;
use client::goat_chain::GOATClient;
use std::str::FromStr;
use store::localdb::{LocalDB, NodeQuery};
use tracing::info;

pub async fn node_available_pbtc_update_monitor(
    local_db: &LocalDB,
    goat_client: &GOATClient,
) -> anyhow::Result<()> {
    let (nodes, size) = {
        let mut storage_processor = local_db.acquire().await?;
        storage_processor
            .find_nodes(&NodeQuery::default().with_actor(Actor::Operator.to_string()))
            .await?
    };
    info!("node_available_pbtc_update_monitor update {size} operator available peg btc");
    for mut node in nodes {
        if let Ok(addr) = Address::from_str(&node.actor) {
            let peg_btc = goat_client.peg_btc_balance(&addr.0).await?;
            node.available_peg_btc = peg_btc as i64;
            let mut storage_processor = local_db.acquire().await?;
            storage_processor.upsert_node(node).await?;
        }
    }
    Ok(())
}
