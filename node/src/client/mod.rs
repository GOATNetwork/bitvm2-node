pub mod btc_chain;
pub mod goat_chain;
pub mod graphs;
mod local_db;

pub use goat_chain::Utxo;
pub use local_db::create_local_db;

#[cfg(test)]
mod tests {
    use crate::client::btc_chain::BTCClient;
    use crate::client::goat_chain::{GOATClient, GoatInitConfig, GoatNetwork};
    use bitcoin::hashes::Hash;
    use bitcoin::{Network, Txid};
    use std::str::FromStr;

    #[tokio::test]
    async fn test_spv_check() {
        let global_init_config = GoatInitConfig::from_env_for_test();
        //  let local_db = LocalDB::new(&format!("sqlite:{db_path}"), true).await;
        let btc_client = BTCClient::new(None, Network::Testnet);
        let goat_client = GOATClient::new(global_init_config, GoatNetwork::Test);
        let tx_id =
            Txid::from_str("cd557f6656051531ab53d08a43524330b39344bb98b710461450feda4ff4b231")
                .expect("decode txid");

        let (root, proof_info, _) =
            btc_client.get_bitc_merkle_proof(&tx_id).await.expect("call merkle proof");
        let root = root.to_byte_array().map(|v| v);
        let proof: Vec<[u8; 32]> =
            proof_info.merkle.iter().map(|v| v.to_byte_array().map(|v| v)).collect();
        let res = goat_client
            .verify_merkle_proof(&root, &proof, &tx_id.to_byte_array(), proof_info.pos as u64)
            .await
            .expect("get result");
        assert!(res);
    }
}
