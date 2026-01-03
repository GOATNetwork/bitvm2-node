use crate::env::get_btc_block_confirms;
use bitcoin::hashes::Hash;
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
use tracing::info;

const MAX_BATCH_SIZE: u64 = 500; //Adjust the value upward as needed, as long as the Ethereum transaction size does not exceed 128KB.

pub(crate) async fn spv_header_hash_update(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
) -> anyhow::Result<()> {
    let block_confirms = get_btc_block_confirms();
    loop {
        let last_height = goat_client.btc_spv_latest_height().await?;
        let btc_height = btc_client.get_height().await? as u64;
        if btc_height <= last_height + block_confirms {
            break;
        }
        let target_height = (btc_height - block_confirms).min(last_height + MAX_BATCH_SIZE);
        let len = (target_height - last_height) as usize;
        let mut heights = Vec::with_capacity(len);
        let mut header_hashes = Vec::with_capacity(len);
        for height in last_height + 1..=target_height {
            heights.push(height);
            let mut header_hash = btc_client.get_block_hash(height as u32).await?.to_byte_array();
            header_hash.reverse();
            header_hashes.push(header_hash);
        }

        let tx_hash = goat_client.btc_spv_post_block_hash_batch(&heights, &header_hashes).await?;
        info!(
            "update spv contract: btc block in range [{}, {}], tx_hash: {tx_hash}",
            last_height + 1,
            btc_height - block_confirms
        );
    }
    Ok(())
}
