use bitcoin_light_client_circuit::{Header, parse_cosmos_payload};
use serde_json::Value;

fn parse_block_data(block_data: &str) -> Result<(Header, Vec<String>), Box<dyn std::error::Error>> {
    let block_data_json: Value = serde_json::from_str(&block_data)?;
    let block = block_data_json.get("result").and_then(|result| result.get("block"));

    let header = block.and_then(|block| block.get("header")).ok_or("Unable to extract header")?;
    let header: Header = serde_json::from_value(header.clone())?;

    // Access the "txs" field as an array of strings
    let txs = block
        .and_then(|block| block.get("data"))
        .and_then(|data| data.get("txs"))
        .and_then(|txs| txs.as_array())
        .ok_or("Unable to extract txs array")?;

    // Decode each base64-encoded transaction
    let decoded_txs: Vec<String> =
        txs.iter().map(|tx| serde_json::from_value(tx.clone()).unwrap()).collect::<Vec<_>>();
    Ok((header, decoded_txs))
}

pub fn get_cosmos_rpc_url() -> String {
    std::env::var("COSMOS_RPC_URL").unwrap_or("https://cosmos.testnet3.goat.network/".to_string())
}

pub async fn fetch_cosmos_validator_info(
    goat_block_height: u64,
) -> Result<(Option<[u8; 32]>, Option<[u8; 32]>), Box<dyn std::error::Error>> {
    let cosmos_rpc_url = get_cosmos_rpc_url();
    // find cosmos height by goat block height, goat_block_height should be always less than or equal to cosmos_block_height
    // 1. fetch the latest cosmos block height
    // 2. binary search cosmos block height between goat block height and latest cosmos block height
    // > 2.1. fetch the block info and parse the first transction: // curl "http://127.0.0.1:26657/block?height=5756784" | jq .result.block.data

    let mut block_height = goat_block_height;
    let mut sequencer_hash = None;
    let mut next_sequencer_hash = None;

    let mut max_retries = 100;
    while max_retries > 0 {
        let block_data = reqwest::get(format!("{}/block?height={}", cosmos_rpc_url, block_height))
            .await?
            .text()
            .await?;

        let (header, tx_data) = parse_block_data(&block_data)?;
        let validators_hash = header.validators_hash.as_bytes();
        let next_validators_hash = header.next_validators_hash.as_bytes();

        if let Some(payload) = parse_cosmos_payload(&tx_data[0]) {
            if payload.block_number == goat_block_height {
                sequencer_hash = Some(validators_hash.try_into().unwrap());
                next_sequencer_hash = Some(next_validators_hash.try_into().unwrap());
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
        return Err(
            "Can not find the cosmos block for goat block height {goat_block_height}".into()
        );
    }
    println!("cosmos block height: {block_height}");

    Ok((sequencer_hash, next_sequencer_hash))
}

pub async fn fetch_commit_chain_proof_input(
    block_number: u64,
) -> Result<([u8; 32], [u8; 32], Vec<String>), Box<dyn std::error::Error>> {
    let cosmos_rpc_url = get_cosmos_rpc_url();
    let block_data = reqwest::get(format!("{}/block?height={}", cosmos_rpc_url, block_number))
        .await?
        .text()
        .await?;
    let (header, tx_data) = parse_block_data(&block_data)?;

    let sequencer_set_hash = header.validators_hash.as_bytes();
    let data_hash = header.data_hash.as_ref().unwrap().as_bytes();

    Ok((sequencer_set_hash.try_into().unwrap(), data_hash.try_into().unwrap(), tx_data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_cosmos_light_client() {
        let block_number = 10000;
        let result = fetch_commit_chain_proof_input(block_number).await;
        assert!(result.is_ok());
    }
}
