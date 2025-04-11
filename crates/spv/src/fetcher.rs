use esplora_client::AsyncClient;

use bitcoin::Block;

use anyhow::{Result, bail};

/// Fetch block at specific height
pub async fn fetch_block(cli: &AsyncClient, block_hei: u32) -> Result<Block> {
    let dummy_block = match cli.get_block_hash(block_hei).await {
        Ok(bh) => bh,
        Err(err) => bail!("Fetching blocks: {}", err),
    };

    let block = cli.get_block_by_hash(&dummy_block).await?;
    match block {
        Some(b) => {
            let block_status =
                cli.get_block_status(&b.block_hash()).await.expect("Failed to get block status");
            if block_status.in_best_chain {
                Ok(b)
            } else {
                bail!("Block {block_hei} is not confirmed yet")
            }
        }
        None => {
            bail!("Fetch block {block_hei} does not exist");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlockInclusionProof, CircuitBlockHeader, CircuitTransaction};
    use bitcoin::hashes::Hash;
    use esplora_client::Builder;

    #[tokio::test]
    async fn test_fetch_block_and_spv_verify() {
        // Define Esplora API URL (Use Blockstream or your own Esplora instance)
        let esplora_url = "https://blockstream.info/api"; // Mainnet
        let cli = Builder::new(esplora_url).build_async().unwrap();
        // let esplora_url = "https://mempool.space/testnet/api"; // Testnet

        let block_hei = 10;

        let block = fetch_block(&cli, block_hei).await.unwrap();
        println!("block hash {:?}", block.block_hash());

        let circuit_blocks = CircuitBlockHeader::from(block.header.clone());

        let tx_0_0 = &block.txdata[0];
        let merkle_proof = cli.get_merkle_proof(&tx_0_0.compute_txid()).await.unwrap().unwrap();
        let merkle_proof = merkle_proof.merkle.iter().map(|x| x.to_byte_array()).collect();

        let tx_idx = block.txdata.len() as u32 - 1;
        let block_inclusion_proof = BlockInclusionProof::new(tx_idx, merkle_proof);
        let txn = &block.txdata[0];
        let transaction = CircuitTransaction::from(txn.clone());

        let spv = crate::SPV { transaction, block_header: circuit_blocks, block_inclusion_proof };

        println!("{:?}", spv.verify());
    }
}
