use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use serde::{Deserialize, Serialize};
use store::ProofInfo;
use zkm_sdk::{ZKMProofWithPublicValues, ZKMStdin};
use zkm_verifier::convert_ark;

#[derive(Debug, Deserialize, Serialize)]
pub struct ProofsOverviewQueryParams {
    #[serde(default = "default_block_proof_count")]
    pub block_proof_count: i64,
    #[serde(default = "default_agg_proof_count")]
    pub agg_proof_count: i64,
    #[serde(default = "default_groth16_proof_count")]
    pub groth16_proof_count: i64,
}
fn default_block_proof_count() -> i64 {
    6
}
fn default_agg_proof_count() -> i64 {
    6
}
fn default_groth16_proof_count() -> i64 {
    1
}

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
    pub block_proof_count: i64,
    pub aggregation_proof_count: i64,
    pub groth16_proof_count: i64,
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

#[cfg(test)]
mod tests {
    use crate::rpc_service::proof::{
        Groth16ProofValue, ProofsOverviewQueryParams, ProofsQueryParams,
    };

    #[test]
    fn test_groth16_proof_value_verify() {
        let proof_value = Groth16ProofValue{
        proof: hex::decode("030000004b000000000000003337333631313332313233383636313834363637393\
        83131323436373933363033363236303038343235363233353734373932363839393636353230353533353739323\
        3333130373833384c000000000000003533313436363436303137323737363332373532373338343437313036393\
        53039363430343531333532343436393235333333343032393839333832393634393535393938333430343237340\
        00200000000000032316235336430326562643736613465353364653737383965313439633738613030633137333\
        56338613535396139383561393934373137623439663538386132363239393233636631666637323161623039363\
        03136396162313934363835313363613938333039623534643735323764643433643363663634303430666132663\
        16536663238353733636539306537346233613932623564623437303038616538633733633664623566666438346\
        53238326339326639376130643339643230343761633565383630663036613032376336386339613132333931353\
        63661666464376431373430646161653839663438623966316438366634656465373237393930343933343533646\
        23832623361613132356336313937633435613462626137383436613262376166643234363032353339646538363\
        53666326430316137346161353030653861653936653236336337386664323231353838313339613165623230393\
        06665653234333365653065376163356362346132303331323434346631636439343035313734313331633861333\
        16466396666666537353430323934613238653365626533366636383966663163353565323735303864326264393\
        06231393533336132643362356233383234663738356161383233386662333866336532626266383666643363633\
        83130303238383833373363323188020000000000003231623533643032656264373661346535336465373738396\
        53134396337386130306331373335633861353539613938356139393437313762343966353838613236323939323\
        36366316666373231616230393630313639616231393436383531336361393833303962353464373532376464343\
        36433636636343034306661326631653666323835373363653930653734623361393262356462343730303861653\
        86337336336646235666664383465323832633932663937613064333964323034376163356538363066303661303\
        23763363863396131323339313536366166646437643137343064616165383966343862396631643836663465646\
        53732373939303439333435336462383262336161313235633631393763343561346262613738343661326237616\
        66432343630323533396465383635366632643031613734616135303065386165393665323633633738666432323\
        13538383133396131656232303930666565323433336565306537616335636234613230333132343434663163643\
        93430353137343133316338613331646639666666653735343032393461323865336562653336663638396666316\
        33535653237353038643262643930623139353333613264336235623338323466373835616138323338666233386\
        63365326262663836666433636338313030323838383337336332313030303030303030303030303030303030303\
        03030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303\
        03030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303\
        03030303030303030303030303030303030303030303030303000cd9fafafdece62f661a1ba3f047449c6f92d5bf\
        ba4baa9a0c8494c35b7f3ac").unwrap_or_default(),
        public_values: hex::decode("50000000000000002000000000000000b4dfdcff9e92e6081614c1c98e4\
        e31967f1676b8946fc50e7a998a62bdad32202000000000000000902c2c2af05f7fd2d859912830fd07b2348ab83\
        eb587a9920d0264f4affd6f50").unwrap_or_default(),
        verifier_id: "0x00d374de1b678ff3dcf918225aa9f632a98e2fc4e74d4e3af8a64e14c0b75f7e".to_string(),
        zkm_version: "v1.1.0".to_string(),
        groth16_vk: hex::decode("ad4d9aa7e302d9df41749d5507949d05dbea33fbb16c643b22f599a2be6df2\
        e2e1a1575c2e494d3613e95e43b622318d9225c820e46acd08e8c987b44051195bc967032fcbf776d1afc985f8887\
        7f182d38480a653f2decaa9794cbc3bf3060c0e187847ad4c798374d0d6732bf501847dd68bc0e071241e0213bc7f\
        c13db7ab998e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a0\
        0665e5c4479674322d4f75edadd46debd5cd992f6ed9550ddcfdba7f33a375ffb9696be78ebaf16395c38e2df43f0\
        977f055b903163cc2a9b33a3a9200e263d064cd7b0cad8362981643d74b163ff3eca36fe8d8fe02c2ff9578b51240\
        7900520f22c7097a395a6337c18773467082b7e9fcf10dbff00000003dcb81592ab70d9493a1d173975eb88579edc\
        4e79dce8bd04ef5ed151fc1e7ed19e0147b786f6f8a189ea78b897f1c55ad1a13293f23e392719a89c11abc5b69ad\
        e814b78c6ddd6dc74bd2ea6c0d1bd6f18217dd6dd55d174d6df2cb5dc36d6aa0000000000000000").unwrap(),
    };
        assert!(proof_value.verify().unwrap_or_default());
    }
    #[test]
    fn deserialize_with_only_required() {
        let json = r#"{}"#;
        let params: ProofsQueryParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.block_number, None);
        assert_eq!(params.block_range, 6);
        assert_eq!(params.graph_id, None);
    }

    #[test]
    fn deserialize_with_only_required_proof_overview() {
        let json = r#"{}"#;
        let params: ProofsOverviewQueryParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.block_proof_count, 6);
        assert_eq!(params.agg_proof_count, 6);
        assert_eq!(params.groth16_proof_count, 1);
    }
}
