use base64::Engine;
use base64::engine::general_purpose::STANDARD as b64;
use bitcoin_light_client_circuit::{Header, ValidatorSet};
use serde_json::Value;
use state_chain::parse_cbft_tx_payload;
use tendermint::PublicKey;
use tendermint::vote::Power;
use tendermint_light_client_verifier::types::Validator;

fn parse_block_data(block_data: &str) -> Result<(Header, Vec<String>), Box<dyn std::error::Error>> {
    let block_data_json: Value = serde_json::from_str(block_data)?;
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

pub async fn fetch_validators(
    block_height: u64,
) -> Result<ValidatorSet, Box<dyn std::error::Error>> {
    let cosmos_rpc_url = get_cbft_rpc_url();
    // fetch validator set
    let validators_data =
        reqwest::get(format!("{cosmos_rpc_url}/validators?height={block_height}"))
            .await?
            .text()
            .await?;
    let validator_data_json: Value = serde_json::from_str(&validators_data)?;
    let validators = validator_data_json
        .get("result")
        .and_then(|result| result.get("validators"))
        .and_then(|validators| validators.as_array())
        .ok_or("Unable to extract validators array")?;

    let mut validator_set = vec![];
    for validator in validators {
        let pub_key = validator
            .get("pub_key")
            .and_then(|pk| pk.get("value"))
            .and_then(|value| value.as_str())
            .ok_or("Unable to extract pub_key value")?;
        let pub_key_bytes = b64.decode(pub_key)?;
        let voting_power = validator
            .get("voting_power")
            .and_then(|vp| vp.as_str())
            .and_then(|vp_str| vp_str.parse::<u64>().ok())
            .ok_or("Unable to extract voting_power")?;
        validator_set.push(Validator::new(
            PublicKey::from_raw_secp256k1(&pub_key_bytes).unwrap(),
            Power::try_from(voting_power).unwrap(),
        ));
    }
    Ok(ValidatorSet::without_proposer(validator_set))
}

pub fn get_cbft_rpc_url() -> String {
    std::env::var("COSMOS_RPC_URL").unwrap_or("https://cosmos.testnet3.goat.network/".to_string())
}

pub async fn fetch_cbft_validator_info(
    goat_block_height: u64,
) -> Result<([u8; 32], u64), Box<dyn std::error::Error>> {
    let cosmos_rpc_url = get_cbft_rpc_url();
    // find cosmos height by goat block height, goat_block_height should be always less than or equal to cosmos_block_height
    // 1. fetch the latest cosmos block height
    // 2. binary search cosmos block height between goat block height and latest cosmos block height
    // > 2.1. fetch the block info and parse the first transction: // curl "https://cosmos.testnet3.goat.network/block?height=5756784" | jq .result.block.data
    let mut block_height = goat_block_height;
    let mut sequencer_hash = [0u8; 32];

    let mut max_retries = 100;
    while max_retries > 0 {
        println!("block_height: {block_height}");
        let block_data = reqwest::get(format!("{cosmos_rpc_url}/block?height={block_height}"))
            .await?
            .text()
            .await?;

        let (header, tx_data) = parse_block_data(&block_data)?;
        let validators_hash = header.validators_hash.as_bytes();

        if let Some(payload) = parse_cbft_tx_payload(&tx_data[0]) {
            if payload.block_number == goat_block_height {
                sequencer_hash = validators_hash.try_into().unwrap();
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

    Ok((sequencer_hash, block_height))
}

pub async fn fetch_cbft_tx_data(
    block_number: u64,
) -> Result<([u8; 32], [u8; 32], Vec<String>), Box<dyn std::error::Error>> {
    let cosmos_rpc_url = get_cbft_rpc_url();
    let block_data =
        reqwest::get(format!("{cosmos_rpc_url}/block?height={block_number}")).await?.text().await?;
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
        let result = fetch_cbft_tx_data(block_number).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_fetch_validators() {
        let evm_block_number = 2000002;
        let (sequencer_hash, block_number) =
            fetch_cbft_validator_info(evm_block_number).await.unwrap();

        println!("hex sequencer_hash: {}", hex::encode(sequencer_hash));
        println!("cosmos block number: {}", block_number);

        let validators = fetch_validators(block_number).await.unwrap();

        if let tendermint::Hash::Sha256(expected_hash) = validators.hash() {
            assert_eq!(expected_hash, sequencer_hash);
        } else {
            panic!("Invalid sequencer set hash");
        }
    }
}
