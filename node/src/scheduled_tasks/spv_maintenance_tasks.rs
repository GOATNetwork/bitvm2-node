use crate::env::get_btc_block_confirms;
use bitcoin::hashes::Hash;
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
use tracing::info;

pub(crate) async fn spv_header_hash_update(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
) -> anyhow::Result<()> {
    let block_confirms = get_btc_block_confirms();
    let last_height = goat_client.btc_spv_latest_height().await?;
    let btc_height = btc_client.get_height().await? as u64;
    if btc_height < last_height + block_confirms {
        return Ok(());
    }
    let update_height = last_height + 1;
    let block_hash = btc_client.get_block_hash(update_height as u32).await?;
    let tx_hash =
        goat_client.btc_spv_post_block_hash(update_height, &block_hash.to_byte_array()).await?;
    info!(
        "update spv contract at height: {update_height}, block_hash: {block_hash}, tx_hash: {tx_hash}"
    );
    Ok(())
}
