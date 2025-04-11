use esplora_client::{AsyncClient};

use bitcoin::{Block, Network};

use anyhow::{Result, bail};

/// Fetch block at specific height
pub async fn fetch_block(cli: &AsyncClient, block_hei: u32) -> Result<Block> {
    let dummy_block = match cli.get_blocks(Some(block_hei)).await {
        Ok(dummy_blocks) => {
            assert!(dummy_blocks.len() == 1);
            dummy_blocks[0].clone()
        },
        Err(err) => bail!("Fetching blocks: {}", err)
    };

    Ok(cli.get_block_by_hash(&dummy_block.id).await?.expect("111"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use esplora_client::Builder;
    use tokio::task;
    use futures::future::join_all;
    use futures::StreamExt;

    #[tokio::test]
    async fn test_fetch_block() {
        // Define Esplora API URL (Use Blockstream or your own Esplora instance)
        let esplora_url = "https://blockstream.info/api"; // Mainnet
        let cli = Builder::new(esplora_url).build_async().unwrap();
        // let esplora_url = "https://mempool.space/testnet/api"; // Testnet

        let total_num = 10;

        let blocks: Vec<_> = futures::stream::iter((0..total_num).into_iter())
            .map(|x| {
                let value = cli.clone();
                async move {
                    fetch_block(&value, x).await.unwrap()
                }
            })
            .collect()
        .await;

        assert_eq!(blocks.len(), total_num);
        println!("{:?}", blocks);
    }
}