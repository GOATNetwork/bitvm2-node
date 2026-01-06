use anyhow::{Result, anyhow};
use state_chain::parse_cbft_tx_payload;
use tendermint::block::Height;
use tendermint::validator::Info;
use tendermint_light_client_verifier::types::{LightBlock, PeerId, ValidatorSet};
use tendermint_rpc::{Client, HttpClient};

#[tracing::instrument(level = "info")]
pub async fn fetch_validators(cosmos_rpc_url: &str, block_height: u64) -> Result<Vec<Info>> {
    let rpc = HttpClient::new(cosmos_rpc_url).unwrap();
    let validators_response = rpc
        .validators(Height::try_from(block_height).unwrap(), tendermint_rpc::Paging::All)
        .await
        .map_err(|e| {
            anyhow!("Error fetching validators for block height {}: {:?}", block_height, e)
        })?;
    Ok(validators_response.validators)
}

// get cosmos block height from block hash: curl https://rpc.testnet3.goat.network/goat-rpc/block_by_hash?hash=0xd2e236b8f89278a527a042727cd4eebb59a566006a844f294da54ed727b95470
pub async fn get_cosmos_block_height_at(
    cosmos_rpc_url: &str,
    cosmos_block_hash: [u8; 32],
) -> Result<Option<u64>> {
    let rpc = HttpClient::new(cosmos_rpc_url).unwrap();
    match rpc.block_by_hash(tendermint::Hash::Sha256(cosmos_block_hash)).await {
        Ok(resp) => match resp.block {
            Some(b) => Ok(Some(b.header.height.into())),
            None => Ok(None),
        },
        Err(e) => anyhow::bail!("Error fetching block by hash: {:?}", e),
    }
}

#[tracing::instrument(level = "info")]
pub async fn fetch_cbft_validator_info(
    cosmos_rpc_url: &str,
    goat_block_height: u64,
    cosmos_block_height_at: Option<u64>,
) -> Result<([u8; 32], u64, [u8; 32])> {
    // find cosmos height by goat block height, goat_block_height should be always less than or equal to cosmos_block_height
    // 1. fetch the latest cosmos block height
    // 2. binary search cosmos block height between goat block height and latest cosmos block height
    // > 2.1. fetch the block info and parse the first transction: // curl "https://rpc.testnet3.goat.network/goat-rpcblock?height=5756784" | jq .result.block.data
    let mut block_height = match cosmos_block_height_at {
        Some(height) => height,
        None => goat_block_height,
    };
    let mut sequencer_hash = [0u8; 32];
    let mut goat_block_hash = [0u8; 32];

    let mut max_retries = 100;
    let rpc = HttpClient::new(cosmos_rpc_url).unwrap();
    while max_retries > 0 {
        let block_data = rpc.block(Height::from(block_height as u32)).await.map_err(|e| {
            anyhow!("Error fetching block data for height {}: {:?}", block_height, e)
        })?;
        let header = &block_data.block.header;
        let tx_data = &block_data.block.data;
        let validators_hash = header.validators_hash.as_bytes();

        if let Some(payload) = parse_cbft_tx_payload(&tx_data[0]) {
            if payload.block_number == goat_block_height {
                sequencer_hash = validators_hash.try_into().unwrap();
                goat_block_hash = payload.block_hash.try_into().unwrap();
                break;
            }
            if payload.block_number < block_height {
                block_height += block_height - payload.block_number;
            } else {
                block_height -= 1;
            }
        }
        max_retries -= 1;
    }
    if max_retries == 0 {
        anyhow::bail!("Can not find the cosmos block for goat block height {goat_block_height}");
    }

    Ok((sequencer_hash, block_height, goat_block_hash))
}

pub async fn fetch_cbft_tx_data(cosmos_rpc_url: &str, height: u64) -> Result<Vec<Vec<u8>>> {
    let rpc = HttpClient::new(cosmos_rpc_url).unwrap();
    let block_data = rpc
        .block(Height::from(height as u32))
        .await
        .map_err(|e| anyhow!("Error fetching block data for height {}: {:?}", height, e))?;

    let tx_data = block_data.block.data;
    Ok(tx_data)
}

pub async fn fetch_cosmos_block(cosmos_rpc_url: &str, height: u64) -> Result<LightBlock> {
    let rpc = HttpClient::new(cosmos_rpc_url).unwrap();
    // 1. header + commit
    let commit_resp = rpc
        .commit(Height::try_from(height).unwrap())
        .await
        .map_err(|e| anyhow!("Error fetching commit data for height {}: {:?}", height, e))?;
    let signed_header = commit_resp.signed_header;
    let validators_response = rpc
        .validators(Height::try_from(height).unwrap(), tendermint_rpc::Paging::All)
        .await
        .map_err(|e| anyhow!("Error fetching validators for block height {}: {:?}", height, e))?;
    let validators = validators_response.validators;
    let next_validators_response = rpc
        .validators(Height::try_from(height + 1).unwrap(), tendermint_rpc::Paging::All)
        .await
        .map_err(|e| {
            anyhow!("Error fetching validators for block height {}: {:?}", height + 1, e)
        })?;
    let next_validators = next_validators_response.validators;
    let status_resp = rpc.status().await.map_err(|e| anyhow!("Error fetching status: {:?}", e))?;
    let peer_id: PeerId = status_resp.node_info.id;

    let light_block = LightBlock::new(
        signed_header,
        ValidatorSet::without_proposer(validators),
        ValidatorSet::without_proposer(next_validators),
        peer_id,
    );

    Ok(light_block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::info;
    #[tokio::test]
    async fn test_create_cosmos_light_client() {
        let block_number = 10000;
        let cosmos_rpc_url = std::env::var("COSMOS_RPC_URL")
            .unwrap_or("https://rpc.testnet3.goat.network/goat-rpc".to_string());
        let result = fetch_cbft_tx_data(&cosmos_rpc_url, block_number).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_fetch_validators() {
        let cosmos_rpc_url = std::env::var("COSMOS_RPC_URL")
            .unwrap_or("https://rpc.testnet3.goat.network/goat-rpc".to_string());
        let evm_block_number = 9511050;
        let (sequencer_hash, block_number, _) =
            fetch_cbft_validator_info(&cosmos_rpc_url, evm_block_number, None).await.unwrap();

        info!("hex sequencer_hash: {}", hex::encode(sequencer_hash));
        info!("cosmos block number: {}", block_number);

        let validators = fetch_validators(&cosmos_rpc_url, block_number).await.unwrap();
        let validators_info: Vec<commit_chain::SequencerInfo> =
            validators.iter().cloned().map(|v| v.into()).collect();

        if let tendermint::Hash::Sha256(expected_hash) =
            commit_chain::sequencer_hash(&validators_info)
        {
            assert_eq!(expected_hash, sequencer_hash);
        } else {
            panic!("Invalid sequencer set hash");
        }

        let light_block = fetch_cosmos_block(&cosmos_rpc_url, block_number).await.unwrap();
        assert_eq!(light_block.signed_header.header.validators_hash.as_bytes(), &sequencer_hash);
    }
}
