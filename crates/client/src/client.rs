use crate::chain::chain::Chain;
use crate::chain::chain_adaptor::{ChainAdaptor, GoatNetwork, get_chain_adaptor};
use crate::chain::goat_adaptor::GoatInitConfig;
use crate::esplora::get_esplora_url;
use bitcoin::Address as BtcAddress;
use bitcoin::{Block, Network};
use esplora_client::{AsyncClient, Builder, TxStatus, Utxo};

pub struct BitVM2Client {
    pub esplora: AsyncClient,
    pub btc_network: Network,
    pub chain_service: Chain,
}

impl BitVM2Client {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        esplora_url: Option<&str>,
        btc_network: Network,
        goat_network: GoatNetwork,
        goat_config: Option<GoatInitConfig>,
    ) -> Self {
        Self {
            esplora: Builder::new(esplora_url.unwrap_or(get_esplora_url(btc_network)))
                .build_async()
                .expect("Could not build esplora client"),
            btc_network,
            chain_service: Chain::new(get_chain_adaptor(goat_network, goat_config, None)),
        }
    }

    pub async fn fetch_btc_block(&self, block_height: u32) -> anyhow::Result<Block> {
        let block_hash = self.esplora.get_block_hash(block_height).await?;
        Ok(self.esplora.get_block_by_hash(&block_hash).await?.ok_or(anyhow::format_err!(
            "failed to fetch block at :{} hash:{}",
            block_height,
            block_hash.to_string()
        ))?)
    }

    pub async fn fetch_btc_address_utxos(&self, address: BtcAddress) -> anyhow::Result<Vec<Utxo>> {
        Ok(self.esplora.get_address_utxo(address).await?)
    }
}
