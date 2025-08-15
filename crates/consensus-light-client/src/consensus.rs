use k256::ecdsa::signature::Verifier;
use k256::ecdsa::Signature;
use k256::sha2::{Digest, Sha256};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as b64;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::elliptic_curve::generic_array::GenericArray;
use k256::elliptic_curve::generic_array::typenum::U64;

use serde::{Serialize, Deserialize};
struct Commit {
    height: String,
    round: i64,
    block_id: BlockId,
    signatures: Vec<CommitSig>,
}
struct BlockId {
    hash: String, // often base64 encoded
    // parts omitted
}
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
/// - ed25519 (tendermint type names: "tendermint/PubKeyEd25519" or "ed25519")
/// - secp256k1 (type names: "tendermint/PubKeySecp256k1" or "secp256k1")
///
/// message is raw bytes (in our simplified example: block_id.hash bytes).
fn verify_signature(pubkey: &PubKey, signature_b64: &str, message: &[u8]) -> Option<bool> {
    if signature_b64.is_empty() {
        return Some(false);
    }
    let sig_bytes = match b64.decode(signature_b64.as_bytes()) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("bad sig base64: {}", e);
            return None;
        }
    };

    let pk_bytes = match b64.decode(pubkey.value.as_bytes()) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("bad pubkey base64: {}", e);
            return None;
        }
    };

    let t = pubkey.r#type.to_lowercase();
    assert!(t.contains("secp256k1"));
    // secp256k1: Tendermint historically encodes compressed pubkey 33 bytes (but sometimes raw 33/65)
    // signature might be 64-bytes compact (r||s) or DER.
    // We'll try compact first, then DER.
    // Use k256 ECDSA verify with SHA256 digest over message (common practice),
    // but note: Tendermint ECDSA signature scheme details may vary across chains.

    let digest = Sha256::digest(message);
    // try parse pubkey as SEC1 (compressed or uncompressed)
    let vk = match k256::EncodedPoint::from_bytes(&pk_bytes) {
        Ok(ep) => {
            let pk = k256::PublicKey::from_encoded_point(&ep).unwrap();
            k256::ecdsa::VerifyingKey::from(pk)
        },
        Err(_) => {
            eprintln!("secp256k1 pubkey parse error");
            return None;
        }
    };

    // try compact (64) -> K256::Signature::from_bytes expects DER or fixed?
    if sig_bytes.len() == 64 {
        // k256::ecdsa::Signature::from_bytes expects ASN.1 DER OR compact? K256 provides from_bytes expecting DER
        // But k256::ecdsa::Signature::from_slice accepts 64-bytes r||s via Signature::from_bytes (new)

        let sig_arr: &GenericArray<u8, U64> = GenericArray::from_slice(&sig_bytes);
        match Signature::from_bytes(&sig_arr) {
            Ok(k256_sig) => match vk.verify(digest.as_slice(), &k256_sig) {
                Ok(_) => return Some(true),
                Err(_) => return Some(false),
            },
            Err(e) => {
                eprintln!("k256 signature parse err: {}", e);
                // fallthrough to try DER below
            }
        }
    }
    // try DER
    match Signature::from_der(&sig_bytes) {
        Ok(der_sig) => match vk.verify(digest.as_slice(), &der_sig) {
            Ok(_) => Some(true),
            Err(_) => Some(false),
        },
        Err(e) => {
            eprintln!("k256 sig der parse err: {}", e);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn test_basic_cometbft_sig() {
        // curl "http://127.0.0.1:26657/validators?height=100"
        let validators: Vec<ValidatorInfo> = serde_json::from_str(r#"
    [
      {
        "address": "57E4AA9111E3899547D51D8F1510878F4A1FE2D6",
        "pub_key": {
          "type": "tendermint/PubKeySecp256k1",
          "value": "A3iE47FwKrLG6qAU0Z3wig+ikNbu+hRTTDxSoXpfBAQO"
        },
        "voting_power": "250000",
        "proposer_priority": "-500000"
      },
      {
        "address": "762E41E7DD3E0708B6A39F1DEC870CD89932ECDC",
        "pub_key": {
          "type": "tendermint/PubKeySecp256k1",
          "value": "ApAw3FDpmYkCasdiEx/J77A8SsOrZc2CAasCWk87bIKw"
        },
        "voting_power": "250000",
        "proposer_priority": "250000"
      },
      {
        "address": "A075E25AD183E70ABD35639D8A9DF57889A9D733",
        "pub_key": {
          "type": "tendermint/PubKeySecp256k1",
          "value": "A9jvL81us8nBr9uq3Th0F/lFBHE5QQtevvLGnS+az927"
        },
        "voting_power": "250000",
        "proposer_priority": "250000"
      }
    ]"#).unwrap();

        println!("{:?}", validators);

    }
}