pub mod chain;
pub mod client;
pub mod esplora;

#[cfg(test)]
mod tests {
    use crate::chain::chain_adaptor::GoatNetwork;
    use crate::chain::goat_adaptor::GoatInitConfig;
    use crate::client::BitVM2Client;
    use bitcoin::hashes::Hash;
    use bitcoin::{Network, Txid};
    use std::str::FromStr;

    #[tokio::test]
    async fn test_spv_check() {
        let global_init_config = GoatInitConfig::from_env_for_test();
        //  let local_db = LocalDB::new(&format!("sqlite:{db_path}"), true).await;
        let tmp_db = tempfile::NamedTempFile::new().unwrap();
        let client = BitVM2Client::new(
            tmp_db.path().as_os_str().to_str().unwrap(),
            None,
            Network::Testnet,
            GoatNetwork::Test,
            global_init_config,
            "http://localhost:5001",
        )
        .await;
        let tx_id =
            Txid::from_str("cd557f6656051531ab53d08a43524330b39344bb98b710461450feda4ff4b231")
                .expect("decode txid");

        let (root, proof_info, _) =
            client.get_bitc_merkle_proof(&tx_id).await.expect("call merkle proof");
        let root = root.to_byte_array().map(|v| v);
        let proof: Vec<[u8; 32]> =
            proof_info.merkle.iter().map(|v| v.to_byte_array().map(|v| v)).collect();
        let res = client
            .verify_merkle_proof(&root, &proof, &tx_id.to_byte_array(), proof_info.pos as u64)
            .await
            .expect("get result");
        assert!(res);
    }
}
