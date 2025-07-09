use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use serde::{Deserialize, Serialize};
use zkm_sdk::{ZKMProofWithPublicValues, ZKMStdin};
use zkm_verifier::convert_ark;

#[derive(Debug, Deserialize, Serialize)]
pub struct ProofsQueryParams {
    pub block_number: Option<i64>,
    #[serde(default = "default_block_range")]
    pub block_range: i64,
    pub graph_id: Option<String>,
}

fn default_block_range() -> i64 {
    6
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BlockProofs {
    pub block_number: i64,
    pub block_proof: Option<ProofItem>,
    pub aggregation_proof: Option<ProofItem>,
    pub groth16_proof: Option<ProofItem>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProofItem {
    pub state: String,
    pub proving_time: i64,
    pub total_time_to_proof: i64,
    pub proof_size: f64,
    pub zkm_version: String,
    pub started_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Proofs {
    pub block_proofs: Vec<BlockProofs>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProofsOverview {
    pub total_blocks: i64,
    pub avg_block_proof: f64,
    pub avg_aggregation_proof: f64,
    pub avg_groth16_proof: f64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Groth16ProofValue {
    pub proof: Vec<u8>,
    pub public_values: Vec<u8>,
    pub verifier_id: String,
    pub zkm_version: String,
    pub groth16_vk: Vec<u8>,
}

impl Groth16ProofValue {
    pub fn verify(&self) -> anyhow::Result<bool> {
        let proof = ZKMProofWithPublicValues {
            proof: bincode::deserialize(&self.proof)?,
            public_values: bincode::deserialize(&self.public_values)?,
            zkm_version: self.zkm_version.clone(),
            stdin: ZKMStdin::default(),
        };
        let ark_proof = convert_ark(&proof, &self.verifier_id, &self.groth16_vk)?;
        Ok(Groth16::<Bn254, LibsnarkReduction>::verify_proof(
            &ark_proof.groth16_vk.vk.into(),
            &ark_proof.proof,
            ark_proof.public_inputs.as_ref(),
        )
        .unwrap_or(false))
    }
}
