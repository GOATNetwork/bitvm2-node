use base64::Engine;
use base64::engine::general_purpose::STANDARD as b64;
use k256::ecdsa::Signature;
use k256::ecdsa::signature::Verifier;
use k256::elliptic_curve::generic_array::GenericArray;
use k256::elliptic_curve::generic_array::typenum::U64;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::sha2::{Digest, Sha256};

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Commit {
    height: String,
    round: i64,
    block_id: BlockId,
    signatures: Vec<CommitSig>,
}
#[derive(Debug, Serialize, Deserialize)]
struct BlockId {
    hash: String, // often base64 encoded
    parts: Parts,
}

#[derive(Debug, Serialize, Deserialize)]
struct Parts {
    total: i64,
    hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CommitSig {
    block_id_flag: i32,
    validator_address: Option<String>, // consensus address hex
    timestamp: Option<String>,
    signature: String, // base64
}

#[derive(Debug, Serialize, Deserialize)]
struct ValidatorInfo {
    pub_address: Option<String>, // sometimes present
    pub_key: PubKey,
    voting_power: String,
    address: String, // consensus address (hex)
}

#[derive(Debug, Serialize, Deserialize)]
struct PubKey {
    r#type: String,
    value: String, // base64-encoded pubkey body
}

/// Try to verify the base64 signature with the pubkey (PubKey.value is base64)
/// Supports:
/// - secp256k1 (type names: "tendermint/PubKeySecp256k1" or "secp256k1")
///
/// message is raw bytes (in our simplified example: block_id.hash bytes).
fn verify_signature(pubkey: &PubKey, signature_b64: &str, message: &[u8]) -> Option<bool> {
    let sig_bytes = b64.decode(signature_b64).ok()?;
    let pk_bytes = b64.decode(&pubkey.value).ok()?;
    let ep = k256::EncodedPoint::from_bytes(&pk_bytes).ok()?;
    let pk = k256::PublicKey::from_encoded_point(&ep).unwrap();
    let vk = k256::ecdsa::VerifyingKey::from(pk);
    let digest = Sha256::digest(message);

    let verified = if sig_bytes.len() == 64 {
        let sig_arr: &GenericArray<u8, U64> = GenericArray::from_slice(&sig_bytes);
        match Signature::from_bytes(sig_arr) {
            Ok(sig) => vk.verify(digest.as_slice(), &sig).is_ok(),
            Err(_) => panic!("invalid signature length = 64"),
        }
    } else {
        match Signature::from_der(&sig_bytes) {
            Ok(sig) => vk.verify(digest.as_slice(), &sig).is_ok(),
            Err(_) => panic!("invalid signature length != 64"),
        }
    };
    Some(verified)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_cometbft_sig() {
        // curl "http://127.0.0.1:26657/validators?height=5756784"
        let validators: Vec<ValidatorInfo> = serde_json::from_str(
            r#"[
      {
        "address": "762E41E7DD3E0708B6A39F1DEC870CD89932ECDC",
        "pub_key": {
          "type": "tendermint/PubKeySecp256k1",
          "value": "ApAw3FDpmYkCasdiEx/J77A8SsOrZc2CAasCWk87bIKw"
        },
        "voting_power": "8286030",
        "proposer_priority": "2071468"
      },
      {
        "address": "A075E25AD183E70ABD35639D8A9DF57889A9D733",
        "pub_key": {
          "type": "tendermint/PubKeySecp256k1",
          "value": "A9jvL81us8nBr9uq3Th0F/lFBHE5QQtevvLGnS+az927"
        },
        "voting_power": "8142753",
        "proposer_priority": "-3211466"
      },
      {
        "address": "3A80B97491EF7CEDB4CBA67D0F8DE18D23200B79",
        "pub_key": {
          "type": "tendermint/PubKeySecp256k1",
          "value": "A1de8RhxYmFBQhzpjk3I9jKqDZhfXAZ8pY4tQYJMLKvJ"
        },
        "voting_power": "7998934",
        "proposer_priority": "-11369921"
      },
      {
        "address": "DE864C2A398543EF059026C3BF401F505E98D747",
        "pub_key": {
          "type": "tendermint/PubKeySecp256k1",
          "value": "Akz/2W6tdsYEanZw+uQEipuCscRt68m0IFpRnrIdc8km"
        },
        "voting_power": "1949866",
        "proposer_priority": "10427059"
      },
      {
        "address": "57E4AA9111E3899547D51D8F1510878F4A1FE2D6",
        "pub_key": {
          "type": "tendermint/PubKeySecp256k1",
          "value": "A3iE47FwKrLG6qAU0Z3wig+ikNbu+hRTTDxSoXpfBAQO"
        },
        "voting_power": "327600",
        "proposer_priority": "2082863"
      }
    ]"#,
        )
        .unwrap();

        println!("{:?}", validators);

        // curl "http://127.0.0.1:26657/commit?height=5756784"
        let commit: Commit = serde_json::from_str(
            r#"{
        "height": "5756784",
        "round": 0,
        "block_id": {
          "hash": "886575C444D229B77160B3513EA860A0D49D3B2891BA86AA995A77C45A113EC8",
          "parts": {
            "total": 1,
            "hash": "5BC90CEBDAB9356F4B9E7262BF27BAAB04229A50D1DE1300D58EEC9219C3CCFA"
          }
        },
        "signatures": [
          {
            "block_id_flag": 2,
            "validator_address": "762E41E7DD3E0708B6A39F1DEC870CD89932ECDC",
            "timestamp": "2025-08-15T11:50:11.224608171Z",
            "signature": "BwCZwWV8T7hXwYch4aabIZr9D4ea1IYCS5dUg6Yi6N8NTB1hivnsbqlyD5zIARYBX3LaSBqK0KxMFlr2MTz7jQ=="
          },
          {
            "block_id_flag": 2,
            "validator_address": "A075E25AD183E70ABD35639D8A9DF57889A9D733",
            "timestamp": "2025-08-15T11:50:11.325396406Z",
            "signature": "Rbgfztf+vuEaRmGE2/uQy6IVgBXx64Vf0fn9+U9KJDB5pun6oanuxGaVhCiRnvlc+0LzfGK5BX7CIDoVqgBcvw=="
          },
          {
            "block_id_flag": 2,
            "validator_address": "3A80B97491EF7CEDB4CBA67D0F8DE18D23200B79",
            "timestamp": "2025-08-15T11:50:11.224650549Z",
            "signature": "usI+3XqwcH3GAjaZQxK9/xC/q6T+WiNaZDqkvbUWKx4rLRl1ByQ0YdX5Iju/vd9/EbVoQXEPArYagTnYCQFA7A=="
          },
          {
            "block_id_flag": 2,
            "validator_address": "DE864C2A398543EF059026C3BF401F505E98D747",
            "timestamp": "2025-08-15T11:50:11.263064889Z",
            "signature": "tpK6uwJR6izDFtYDfUNbFU+t5F6kAyOHIxz0plSoRONXUqQYjbEZGvox/aThUMIyJxM/+YoPaodSlitmxg9UQg=="
          },
          {
            "block_id_flag": 2,
            "validator_address": "57E4AA9111E3899547D51D8F1510878F4A1FE2D6",
            "timestamp": "2025-08-15T11:50:11.225315076Z",
            "signature": "rm3mQL5uz45OkJ71gr7xKnlsOXS0dEQfD9WvKQq1YoIBAQwZw/B60VjyKuj3m4CIdweNIziU9b76gs4B4XIN4A=="
          }
        ]
      }"#
        ).unwrap();

        // 3. build map: address -> validator info
        let mut val_map: std::collections::HashMap<String, ValidatorInfo> = std::collections::HashMap::new();
        for v in validators {
            val_map.insert(v.address.clone(), v);
        }

        // 4. iterate signatures and verify
        for sig in commit.signatures {
            let addr = sig.validator_address.clone().unwrap_or_default();
            if addr.is_empty() {
                println!("absent signature (validator didn't sign) or nil_vote");
                continue;
            }

            match val_map.get(&addr) {
                Some(v) => {
                    // message we verify against - simplified: block_id.hash
                    let message = hex::decode(commit.block_id.hash.trim_start_matches("0x")).unwrap();
                    let ok = verify_signature(&v.pub_key, &sig.signature, &message);
                    println!(
                        "validator {} (pubkey type: {}) -> signature present: {} -> verified: {}",
                        addr,
                        v.pub_key.r#type,
                        !sig.signature.is_empty(),
                        ok.unwrap_or(false)
                    );
                }
                None => {
                    println!("signature from unknown validator address: {}", addr);
                }
            }
        }
    }
}
