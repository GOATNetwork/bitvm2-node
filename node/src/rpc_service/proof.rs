use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use serde::{Deserialize, Serialize};
use store::ProofInfo;
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
    pub contain_blocks: String,
    pub total_time_to_proof: i64,
    pub proof_size: f64,
    pub proving_cycles: i64,
    pub zkm_version: String,
    pub started_at: i64,
    pub updated_at: i64,
}

impl From<ProofInfo> for ProofItem {
    fn from(proof_info: ProofInfo) -> Self {
        let total_time_to_proof = if proof_info.updated_at >= proof_info.created_at {
            proof_info.updated_at - proof_info.created_at
        } else {
            0
        };
        let contain_blocks = if proof_info.real_numbers.is_empty() {
            format!("{}", proof_info.block_number)
        } else {
            proof_info.real_numbers
        };

        Self {
            state: proof_info.state,
            proving_time: proof_info.proving_time,
            contain_blocks,
            total_time_to_proof,
            proof_size: proof_info.proof_size,
            proving_cycles: proof_info.proving_cycles,
            zkm_version: proof_info.zkm_version,
            started_at: proof_info.created_at,
            updated_at: proof_info.updated_at,
        }
    }
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
