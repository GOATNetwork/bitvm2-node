use anyhow::{Result, bail};
use bitcoin::blockdata::script::Script;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, Block, Transaction};
use esplora_client::{AsyncClient, Builder};
use futures::{StreamExt, stream};
use spv::verify_merkle_proof;
use spv::{
    BitcoinMerkleTree, BlockInclusionProof, CircuitBlockHeader, CircuitTransaction, MMRGuest,
    MMRNative, SPV,
};

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
/// Check pegin_tx is of one the tx in the blocks
pub async fn check_pegin_tx(
    cli: &AsyncClient,
    blocks: &Vec<Block>,
    pegin_txid: &str,
) -> Result<bool> {
    let txid = pegin_txid.parse().unwrap();
    if let Some(tx) = cli.get_tx(&txid).await.unwrap() {
        // 1. do tx content check

        // output: deposit,message,[change]
        assert!(tx.output.len() >= 2);
        assert!(tx.output[0].value > Amount::from_sat(0)); // should one of the constant deposit amounts

        assert_eq!(tx.output[1].value, Amount::from_sat(0));
        assert!(tx.output[1].script_pubkey.is_op_return());

        // check evm address
        if !bitvm2_lib::pegin::check_pegin_opreturn(&tx.output[1].script_pubkey) {
            return Ok(false);
        }

        // 2. do spv check

        return Ok(true);
    }
    Ok(false)
}
