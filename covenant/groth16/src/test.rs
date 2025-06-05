use store::localdb::LocalDB;
use tracing::Level;

use crate::*;

#[tokio::test]
async fn test_groth16_proof() {
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    const DB_URL: &str = "/tmp/bitvm2-node.db";
    let db: LocalDB = LocalDB::new(&format!("sqlite:{}", DB_URL), true).await;

    let (proof, vk) = generate_groth16_proof(&db, 2).await.unwrap();

    let client = ProverClient::new();
    client.verify(&proof, &vk).unwrap();
}
