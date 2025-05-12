use alloy::primitives::{Address, Bytes};
use alloy::{
    providers::RootProvider,
    sol,
    transports::http::{Client, Http},
};
sol!(
#[derive(Debug)]
#[allow(missing_docs)]
#[sol(rpc)]
interface IGateway {
        function isCommittee(bytes calldata id) external view returns (bool);
        function isOperator(bytes calldata id) external view returns (bool);
});

pub async fn validate_committee(
    provider: &RootProvider<Http<Client>>,
    address: Address,
    peer_id: &[u8],
) -> anyhow::Result<bool> {
    let gate_way = IGateway::new(address, provider);
    Ok(gate_way.isCommittee(Bytes::copy_from_slice(peer_id)).call().await?._0)
}

pub async fn validate_operator(
    provider: &RootProvider<Http<Client>>,
    address: Address,
    peer_id: &[u8],
) -> anyhow::Result<bool> {
    let gate_way = IGateway::new(address, provider);
    Ok(gate_way.isOperator(Bytes::copy_from_slice(peer_id)).call().await?._0)
}
