mod client;
mod chain;
mod esplora;

#[cfg(test)]
mod tests {
    use bitcoin::Network;
    use crate::chain::chain_adaptor::GoatNetwork;
    use crate::client::BitVM2Client;

    #[tokio::test]
    async fn test_btc_call() {
        let client = BitVM2Client::new(None, Network::Testnet, GoatNetwork::Local, None);
        let block = client.await.fetch_btc_block(10).await;
        println!("{:?}", block);
    }
}
