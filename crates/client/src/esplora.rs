use bitcoin::Network;


const TEST_URL: &str = "https://mempool.space/testnet/api";
const MAIN_URL: &str = "https://mempool.space/api";


pub fn get_esplora_url(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => MAIN_URL,
        _ => TEST_URL,
    }
}
