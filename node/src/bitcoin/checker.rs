use anyhow::{Result, bail};
use bitcoin::hashes::Hash;
use bitcoin::{Amount, Block, Network, Transaction, Txid};
use esplora_client::AsyncClient;
use spv::verify_merkle_proof;
use spv::{BitcoinMerkleTree, CircuitBlockHeader, CircuitTransaction, MMRGuest, MMRHost, SPV};

/// Fetch block at specific height
#[allow(dead_code)]
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
#[allow(dead_code)]
pub async fn check_pegin_tx(
    cli: &AsyncClient,
    network: &Network,
    blocks: &Vec<Block>,
    pegin_txid: &str,
) -> Result<bool> {
    let txid = pegin_txid.parse()?;
    if let Some(tx) = cli.get_tx(&txid).await? {
        // 1. do tx content check
        // output: deposit,message,[change]
        if tx.output.len() < 2 {
            bail!("Peg-in tx should contain at least 2 outputs");
        }
        if tx.output[0].value == Amount::from_sat(0) {
            bail!("Deposit amount should be greater than zero");
        }

        if !tx.output[1].script_pubkey.is_op_return() {
            bail!("Output 1 should be OP_RETURN");
        }

        if tx.output[1].value != Amount::from_sat(0) {
            bail!("OP_RETURN output should hold no value");
        }

        // check evm address
        if !bitvm2_lib::pegin::check_pegin_opreturn(network, &tx.output[1].script_pubkey) {
            return Ok(false);
        }

        // 2. do spv check

        let mut mmr_native = MMRHost::new();
        let mut mmr_guest = MMRGuest::new();
        let block_headers = blocks
            .iter()
            .map(|b| CircuitBlockHeader::from(b.header))
            .collect::<Vec<CircuitBlockHeader>>();

        let target_txid: Txid = pegin_txid.parse()?;
        let pegin_tx: Transaction = cli.get_tx(&target_txid).await?.unwrap();
        let _circuit_transaction = CircuitTransaction::from(pegin_tx);

        // find the target block
        let block_pos = blocks.iter().position(|b| {
            let tx_pos = b.txdata.iter().position(|x| x.compute_txid() == target_txid);
            tx_pos.is_some()
        });
        if block_pos.is_none() {
            return Ok(false);
        }
        let target_block = &blocks[block_pos.unwrap()];
        let target_block_header = &block_headers[block_pos.unwrap()];

        // find the index of target tx
        let tx_pos = target_block.txdata.iter().position(|x| x.compute_txid() == target_txid);
        let txid_list =
            target_block.txdata.iter().map(|x| x.compute_txid().to_byte_array()).collect();

        let bitcoin_merkle_tree = BitcoinMerkleTree::new(txid_list);
        let bitcoin_merkle_proof = bitcoin_merkle_tree.generate_proof(tx_pos.unwrap() as u32);

        if !(verify_merkle_proof(
            target_txid.to_byte_array(),
            &bitcoin_merkle_proof,
            bitcoin_merkle_tree.root(),
        )) {
            bail!("Can not verify tx merkle proof");
        }

        let bitcoin_merkle_proofs = [bitcoin_merkle_proof];

        mmr_native.append(target_block_header.compute_block_hash());
        mmr_guest.append(target_block_header.compute_block_hash());

        let txs = target_block
            .txdata
            .iter()
            .map(|tx| CircuitTransaction::from(tx.clone()))
            .collect::<Vec<CircuitTransaction>>();

        for j in 0..block_pos.unwrap() {
            let (mmr_leaf, mmr_proof) = mmr_native.generate_proof(j as u32);
            if !mmr_native.verify_proof(mmr_leaf, &mmr_proof) {
                bail!("Can not verify MMR proof on host side");
            }
            if mmr_leaf != block_headers[j].compute_block_hash() {
                bail!("Can not verify MMR leaf");
            }
            let spv = SPV::new(
                txs[j].clone(),
                bitcoin_merkle_proofs[j].clone(),
                block_headers[j].clone(),
                mmr_proof,
            );
            if !spv.verify(&mmr_guest) {
                bail!("Can not verify MMR proof on guest side")
            }
        }

        return Ok(true);
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use esplora_client::Builder;
    use futures::{StreamExt, stream};
    #[tokio::test]
    async fn test_check_pegin_tx() {
        // tx: https://mempool.space/testnet/tx/e413208c6644d51f4f3adf3a5aad425da817ac825e56352e7164de1e2a4d9394
        //let esplora_url = "https://blockstream.info/api"; // Mainnet
        let esplora_url = "https://mempool.space/testnet/api"; // Testnet
        let client = Builder::new(esplora_url).build_async().unwrap();

        let block_height_start = 4296464;
        let block_height = block_height_start + 1;

        let blocks = stream::iter(block_height_start..block_height)
            .then(|x| {
                let value = client.clone();
                async move { fetch_block(&value, x).await.unwrap() }
            })
            .collect::<Vec<_>>()
            .await;

        let txid = "f3945b0793caaac369378996e693040a629f0bd19a1c32177b999a3ea8f0b109";
        let network = Network::Testnet;

        assert!(check_pegin_tx(&client, &network, &blocks, txid).await.unwrap());
    }
}
