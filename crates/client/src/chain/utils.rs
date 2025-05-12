use alloy::primitives::Address;
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
        function  isCommittee(bytes calldata peer_id)  external view returns(bool);
        function  isOperator(bytes  calldata peer_id)  external view returns(bool);
});

pub async fn validate_committee(
    _provider: &RootProvider<Http<Client>>,
    _address: Address,
    _peer_id: &[u8],
) -> anyhow::Result<bool> {
    // TODO
    // let gate_way = IGateway::new(address, provider);
    // Ok(gate_way.isCommittee(Bytes::copy_from_slice(peer_id)).call().await?._0)
    Ok(true)
}
