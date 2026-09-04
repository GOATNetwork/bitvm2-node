use crate::env::get_soldering_proof_payload_store_path;
use crate::utils::cleanup_babe_setup_states;
use store::localdb::LocalDB;
use tracing::info;

pub async fn babe_setup_state_cleanup_monitor(local_db: &LocalDB) -> anyhow::Result<()> {
    let payload_store = get_soldering_proof_payload_store_path()?;
    let deleted = cleanup_babe_setup_states(local_db, &payload_store).await?;
    if deleted > 0 {
        info!(deleted, "BABE setup state cleanup monitor finished");
    }
    Ok(())
}
