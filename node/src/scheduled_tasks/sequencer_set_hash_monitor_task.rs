use anyhow::Context;
use cbft_rpc::{CosmosRpcProvider, DefaultCosmosRpcProvider};
use std::sync::Arc;
use std::time::Duration;
use store::localdb::LocalDB;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

pub(crate) async fn load_or_init_scan_state(
    local_db: &LocalDB,
    rpc: &impl CosmosRpcProvider,
    start_cosmos_block: u64,
) -> anyhow::Result<store::SequencerSetScanState> {
    let mut storage = local_db.acquire().await?;
    if let Some(state) = storage.get_sequencer_set_scan_state().await? {
        return Ok(state);
    }

    if let Some(last_change) = storage.find_latest_sequencer_set_hash_change().await? {
        let next_cosmos_block_height = last_change.cosmos_block_height.saturating_add(1);
        storage
            .upsert_sequencer_set_scan_state(
                next_cosmos_block_height,
                last_change.goat_block_height,
                &last_change.validators_hash,
            )
            .await?;
        return Ok(store::SequencerSetScanState {
            id: 1,
            next_cosmos_block_height,
            latest_goat_block_height: last_change.goat_block_height,
            latest_validators_hash: last_change.validators_hash,
            created_at: 0,
            updated_at: 0,
        });
    }

    // Drop the DB connection before making the async RPC call to avoid holding it across await.
    drop(storage);
    let (validators_hash, goat_block_height) =
        rpc.get_validators_hash_and_goat_block(start_cosmos_block).await?;
    let goat_block_height = goat_block_height.ok_or_else(|| {
        anyhow::anyhow!(
            "Cosmos block {} has no CBFT tx data, cannot initialize scan state from this block",
            start_cosmos_block
        )
    })?;
    let validators_hash_hex = hex::encode(validators_hash);
    let start_cosmos_block =
        i64::try_from(start_cosmos_block).context("start cosmos block exceeds i64")?;
    let goat_block_height =
        i64::try_from(goat_block_height).context("goat block height exceeds i64")?;
    let next_cosmos_block_height = start_cosmos_block.saturating_add(1);

    let mut storage = local_db.acquire().await?;
    storage
        .upsert_sequencer_set_hash_change(
            start_cosmos_block,
            goat_block_height,
            &validators_hash_hex,
        )
        .await?;
    storage
        .upsert_sequencer_set_scan_state(
            next_cosmos_block_height,
            goat_block_height,
            &validators_hash_hex,
        )
        .await?;
    info!(
        "Initialized sequencer_set_hash monitor at cosmos block {}, validators_hash {}",
        start_cosmos_block, validators_hash_hex
    );

    Ok(store::SequencerSetScanState {
        id: 1,
        next_cosmos_block_height,
        latest_goat_block_height: goat_block_height,
        latest_validators_hash: validators_hash_hex,
        created_at: 0,
        updated_at: 0,
    })
}

pub(crate) async fn sync_sequencer_set_hash_changes(
    local_db: &LocalDB,
    rpc: &impl CosmosRpcProvider,
    start_cosmos_block: u64,
) -> anyhow::Result<()> {
    let mut state = load_or_init_scan_state(local_db, rpc, start_cosmos_block).await?;
    let latest_cosmos_block = rpc.get_latest_block_height().await?;
    let latest_cosmos_block =
        i64::try_from(latest_cosmos_block).context("latest cosmos block exceeds i64")?;

    if state.next_cosmos_block_height > latest_cosmos_block {
        return Ok(());
    }

    let finish_info = format!(
        "finish monitor seq_set_hash from: {}, to: {})",
        state.next_cosmos_block_height, latest_cosmos_block
    );

    const SCAN_STATE_FLUSH_INTERVAL: i64 = 10;
    let mut blocks_since_last_flush: i64 = 0;

    while state.next_cosmos_block_height <= latest_cosmos_block {
        info!(
            "Syncing sequencer_set_hash changes at cosmos block {}",
            state.next_cosmos_block_height
        );

        // Define a closure or block to handle the per-block logic so we can catch errors
        let result: anyhow::Result<()> = async {
            let cosmos_block_height = u64::try_from(state.next_cosmos_block_height)
                .context("cosmos block height is negative")?;
            let (validators_hash, goat_block_height) =
                rpc.get_validators_hash_and_goat_block(cosmos_block_height).await?;

            // Skip cosmos blocks without CBFT tx data (empty blocks or unparsable payload).
            let goat_block_height = match goat_block_height {
                Some(h) => h,
                None => {
                    return Ok(());
                }
            };

            let validators_hash_hex = hex::encode(validators_hash);
            let goat_block_height =
                i64::try_from(goat_block_height).context("goat block height exceeds i64")?;

            if state.latest_validators_hash != validators_hash_hex {
                let mut storage = local_db.acquire().await?;
                storage
                    .upsert_sequencer_set_hash_change(
                        state.next_cosmos_block_height,
                        goat_block_height,
                        &validators_hash_hex,
                    )
                    .await?;
                info!(
                    "Detected validators_hash change at cosmos block {} (goat block {}): {}",
                    state.next_cosmos_block_height, goat_block_height, validators_hash_hex
                );
                state.latest_validators_hash = validators_hash_hex;
            }

            state.latest_goat_block_height = goat_block_height;

            Ok(())
        }
        .await;

        if let Err(e) = result {
            // Attempt to save state before returning the error
            let mut storage = local_db.acquire().await?;
            storage
                .upsert_sequencer_set_scan_state(
                    state.next_cosmos_block_height,
                    state.latest_goat_block_height,
                    &state.latest_validators_hash,
                )
                .await?;
            return Err(e);
        }

        // Advance state on success (or empty block)
        state.next_cosmos_block_height = state.next_cosmos_block_height.saturating_add(1);
        blocks_since_last_flush += 1;

        // Flush scan state periodically to reduce DB writes during catch-up.
        if blocks_since_last_flush >= SCAN_STATE_FLUSH_INTERVAL
            || state.next_cosmos_block_height > latest_cosmos_block
        {
            let mut storage = local_db.acquire().await?;
            storage
                .upsert_sequencer_set_scan_state(
                    state.next_cosmos_block_height,
                    state.latest_goat_block_height,
                    &state.latest_validators_hash,
                )
                .await?;
            blocks_since_last_flush = 0;
            info!(
                "Scan progress: cosmos block {}/{}",
                state.next_cosmos_block_height, latest_cosmos_block
            );
        }
    }
    info!(finish_info);

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn run_sequencer_set_hash_monitor_task(
    local_db: LocalDB,
    _goat_client: Arc<client::goat_chain::GOATClient>,
    cosmos_rpc_url: String,
    start_cosmos_block: u64,
    interval_secs: u64,
    cancellation_token: CancellationToken,
) -> anyhow::Result<String> {
    let rpc = DefaultCosmosRpcProvider { cosmos_rpc_url };
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(interval_secs)) => {
                if let Err(err) = sync_sequencer_set_hash_changes(
                    &local_db,
                    &rpc,
                    start_cosmos_block,
                ).await {
                    warn!("sequencer_set_hash monitor sync failed: {err:?}");
                }
            }
            _ = cancellation_token.cancelled() => {
                info!("Sequencer set hash monitor task received shutdown signal");
                return Ok("sequencer_set_hash_monitor_shutdown".to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use cbft_rpc::CosmosRpcProvider;
    use std::collections::HashMap;
    use store::localdb::create_local_db;

    /// Mock Cosmos RPC provider for testing.
    /// `blocks` maps cosmos_block_height -> (validators_hash, Option<goat_block_number>).
    struct MockCosmosRpc {
        blocks: HashMap<u64, ([u8; 32], Option<u64>)>,
        latest_height: u64,
    }

    #[async_trait::async_trait]
    impl CosmosRpcProvider for MockCosmosRpc {
        async fn get_latest_block_height(&self) -> Result<u64> {
            Ok(self.latest_height)
        }
        async fn get_validators_hash_and_goat_block(
            &self,
            cosmos_block_height: u64,
        ) -> Result<([u8; 32], Option<u64>)> {
            self.blocks
                .get(&cosmos_block_height)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("block {} not found in mock", cosmos_block_height))
        }
    }

    fn make_hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[tokio::test]
    async fn test_sync_init_from_empty() {
        let db = create_local_db("sqlite::memory:").await;
        let mut blocks = HashMap::new();
        // Blocks 10..=12, all with same validators_hash
        for i in 10..=12 {
            blocks.insert(i, (make_hash(0xAA), Some(1000 + i)));
        }
        let rpc = MockCosmosRpc { blocks, latest_height: 12 };

        sync_sequencer_set_hash_changes(&db, &rpc, 10).await.unwrap();

        let mut s = db.acquire().await.unwrap();
        // Initial block should be recorded as a hash change
        let latest = s.find_latest_sequencer_set_hash_change().await.unwrap().unwrap();
        assert_eq!(latest.cosmos_block_height, 10);
        assert_eq!(latest.validators_hash, hex::encode(make_hash(0xAA)));

        // Scan state should be at block 13 (past latest)
        let state = s.get_sequencer_set_scan_state().await.unwrap().unwrap();
        assert_eq!(state.next_cosmos_block_height, 13);
    }

    #[tokio::test]
    async fn test_sync_detects_hash_change() {
        let db = create_local_db("sqlite::memory:").await;
        let mut blocks = HashMap::new();
        // Blocks 10..=12 with hash AA, blocks 13..=15 with hash BB
        for i in 10..=12 {
            blocks.insert(i, (make_hash(0xAA), Some(1000 + i)));
        }
        for i in 13..=15 {
            blocks.insert(i, (make_hash(0xBB), Some(1000 + i)));
        }
        let rpc = MockCosmosRpc { blocks, latest_height: 15 };

        sync_sequencer_set_hash_changes(&db, &rpc, 10).await.unwrap();

        let mut s = db.acquire().await.unwrap();
        // Should have 2 hash change records: one at block 10 (init), one at block 13 (change)
        let first = s
            .find_first_sequencer_set_hash_change_by_cosmos_block_at_or_after(10)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.cosmos_block_height, 10);
        assert_eq!(first.validators_hash, hex::encode(make_hash(0xAA)));

        let second = s
            .find_first_sequencer_set_hash_change_by_cosmos_block_at_or_after(11)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.cosmos_block_height, 13);
        assert_eq!(second.validators_hash, hex::encode(make_hash(0xBB)));
    }

    #[tokio::test]
    async fn test_sync_skips_empty_blocks() {
        let db = create_local_db("sqlite::memory:").await;
        let mut blocks = HashMap::new();
        blocks.insert(10, (make_hash(0xAA), Some(1000)));
        blocks.insert(11, (make_hash(0xAA), None)); // empty block
        blocks.insert(12, (make_hash(0xAA), None)); // empty block
        blocks.insert(13, (make_hash(0xAA), Some(1003)));
        let rpc = MockCosmosRpc { blocks, latest_height: 13 };

        sync_sequencer_set_hash_changes(&db, &rpc, 10).await.unwrap();

        // Scan state should advance past all blocks including empty ones
        let mut s = db.acquire().await.unwrap();
        let state = s.get_sequencer_set_scan_state().await.unwrap().unwrap();
        assert_eq!(state.next_cosmos_block_height, 14);
        assert_eq!(state.latest_goat_block_height, 1003);
    }

    #[tokio::test]
    async fn test_sync_resumes_from_scan_state() {
        let db = create_local_db("sqlite::memory:").await;

        // Pre-seed scan state at block 13
        {
            let mut s = db.acquire().await.unwrap();
            s.upsert_sequencer_set_hash_change(10, 1000, &hex::encode(make_hash(0xAA)))
                .await
                .unwrap();
            s.upsert_sequencer_set_scan_state(13, 1002, &hex::encode(make_hash(0xAA)))
                .await
                .unwrap();
        }

        let mut blocks = HashMap::new();
        // Only provide blocks 13..=15, earlier blocks should NOT be needed
        for i in 13..=15 {
            blocks.insert(i, (make_hash(0xAA), Some(1000 + i)));
        }
        let rpc = MockCosmosRpc { blocks, latest_height: 15 };

        sync_sequencer_set_hash_changes(&db, &rpc, 10).await.unwrap();

        let mut s = db.acquire().await.unwrap();
        let state = s.get_sequencer_set_scan_state().await.unwrap().unwrap();
        assert_eq!(state.next_cosmos_block_height, 16);
    }

    #[tokio::test]
    async fn test_sync_already_caught_up() {
        let db = create_local_db("sqlite::memory:").await;

        // Pre-seed scan state already past latest
        {
            let mut s = db.acquire().await.unwrap();
            s.upsert_sequencer_set_scan_state(20, 1019, &hex::encode(make_hash(0xAA)))
                .await
                .unwrap();
        }

        let blocks = HashMap::new();
        let rpc = MockCosmosRpc { blocks, latest_height: 15 };

        // Should return Ok(()) immediately without querying any blocks
        sync_sequencer_set_hash_changes(&db, &rpc, 10).await.unwrap();

        // Scan state should be unchanged
        let mut s = db.acquire().await.unwrap();
        let state = s.get_sequencer_set_scan_state().await.unwrap().unwrap();
        assert_eq!(state.next_cosmos_block_height, 20);
    }
}
