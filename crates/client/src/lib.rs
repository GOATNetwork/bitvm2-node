pub mod chain;
pub mod client;
pub mod esplora;

#[cfg(test)]
mod tests {
    use crate::chain::chain_adaptor::GoatNetwork;
    use crate::chain::goat_adaptor::GoatInitConfig;
    use crate::client::BitVM2Client;
    use alloy::transports::http::reqwest::Url;
    use bitcoin::{Network, Txid};
    use std::str::FromStr;

    #[tokio::test]
    async fn test_spv_check() {
        let global_init_config = GoatInitConfig {
            rpc_url: "https://rpc.testnet3.goat.network".parse::<Url>().expect("decode url"),
            gateway_address: "0xeD8AeeD334fA446FA03Aa00B28aFf02FA8aC02df"
                .parse()
                .expect("parse contract address"),
            gateway_creation_block: 0,
            to_block: None,
            private_key: None,
            chain_id: 48816_u32,
        };
        //  let local_db = LocalDB::new(&format!("sqlite:{db_path}"), true).await;
        let client = BitVM2Client::new(
            "/tmp/.bitvm2-node.db".to_string(),
            None,
            Network::Testnet,
            GoatNetwork::Test,
            global_init_config,
        )
        .await;
        let tx_id =
            Txid::from_str("a95cb0da04e4b64d7633c34621e31030611ddf2b852ebbc0a293661bad914e2e")
                .expect("decode txid");

        let (root, proof_info) =
            client.get_bitc_merkle_proof(&tx_id).await.expect("call merkle proof");
        let res = client.verify_merkle_proof(&tx_id, &root, &proof_info).await.expect("get result");
        assert!(res);
    }
}
