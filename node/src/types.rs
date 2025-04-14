use crate::rpc_service::BridgeInTransactionPreparerRequest;
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Amount, Network, OutPoint, Txid};
use bitvm2_lib::types::CustomInputs;
use goat::transactions::base::Input;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

const STACK_AMOUNT: Amount = Amount::from_sat(20_000_000);
const FEE_AMOUNT: Amount = Amount::from_sat(2000);
#[derive(Clone, Serialize, Deserialize)]
pub struct P2pUserData {
    pub instance_id: String,
    pub network: Network,
    pub depositor_evm_address: [u8; 20],
    pub pegin_amount: Amount,
    pub stake_amount: Amount, // TODO get stake amount
    pub user_inputs: CustomInputs,
}

impl From<&BridgeInTransactionPreparerRequest> for P2pUserData {
    fn from(value: &BridgeInTransactionPreparerRequest) -> Self {
        let network = Network::from_str(&value.network).expect("decode network success");
        let change_address: Address<NetworkUnchecked> =
            value.from.parse().expect("decode btc address");
        let change_address = change_address.require_network(network).expect("set network");

        let inputs: Vec<Input> = value
            .utxo
            .iter()
            .map(|v| Input {
                outpoint: OutPoint { txid: Txid::from_str(&v.txid).unwrap(), vout: v.vout },
                amount: Amount::from_sat(v.value),
            })
            .collect();

        let input_amount: u64 = value.utxo.iter().map(|v| v.value).sum();
        let user_inputs = CustomInputs {
            inputs,
            input_amount: Amount::from_sat(input_amount),
            fee_amount: FEE_AMOUNT, // TODO get fee amount
            change_address,
        };
        let env_address: web3::types::Address = value.to.parse().expect("decode eth address");
        Self {
            instance_id: value.instance_id.clone(),
            network,
            depositor_evm_address: env_address.0,
            pegin_amount: Amount::from_sat(value.amount as u64),
            stake_amount: STACK_AMOUNT,
            user_inputs,
        }
    }
}
