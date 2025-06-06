use ark_bn254::Bn254;
use ark_groth16::{r1cs_to_qap::LibsnarkReduction, Groth16};
use store::localdb::LocalDB;
use tracing::Level;

use crate::*;

#[tokio::test]
async fn test_ark_groth16_proof() {
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    const DB_URL: &str = "/tmp/bitvm2-node.db";
    let db: LocalDB = LocalDB::new(&format!("sqlite:{}", DB_URL), true).await;

    let (proof, public_inputs, groth16_vk) = get_groth16_proof(&db, 2).await.unwrap();

    assert_eq!(groth16_vk, get_groth16_vk().unwrap());

    // Verify the arkworks proof.
    let ok = Groth16::<Bn254, LibsnarkReduction>::verify_proof(
        &groth16_vk.into(),
        &proof,
        &public_inputs,
    )
    .unwrap();
    assert!(ok);
}

#[tokio::test]
async fn test_gnark_groth16_proof() {
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    const DB_URL: &str = "/tmp/bitvm2-node.db";
    let db: LocalDB = LocalDB::new(&format!("sqlite:{}", DB_URL), true).await;

    let (proof, vk) = generate_groth16_proof(&db, 2).await.unwrap();

    let client = ProverClient::new();
    client.verify(&proof, &vk).unwrap();
}
