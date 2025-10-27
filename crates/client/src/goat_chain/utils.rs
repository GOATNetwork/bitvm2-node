use alloy::network::Ethereum;
use alloy::primitives::{Address, Bytes, FixedBytes};
use alloy::providers::Identity;
use alloy::providers::fillers::{FillProvider, JoinFill, RecommendedFillers};
use alloy::{providers::RootProvider, sol};
use uuid::Uuid;
sol!(
#[derive(Debug)]
#[allow(missing_docs)]
#[sol(rpc)]
interface IGateway {
        address public  committeeManagement;
        address public  stakeManagement;
        address public  bitcoinSPV;
        //function isOperator(bytes calldata id) external view returns (bool);
        function getGraphIdsByInstanceId(bytes16 instanceId) external view returns (bytes16[]);
}
);

sol!(
    #[derive(Debug)]
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface ICommitteeManagement {
        function isValidPeerId(bytes peerId) external view returns (bool);
    }
);

pub async fn is_validate_committee(
    provider: &FillProvider<
        JoinFill<Identity, <Ethereum as RecommendedFillers>::RecommendedFillers>,
        RootProvider,
    >,
    address: Address,
    peer_id: &[u8],
) -> anyhow::Result<bool> {
    let committee_management = ICommitteeManagement::new(address, provider);
    Ok(committee_management.isValidPeerId(Bytes::copy_from_slice(peer_id)).call().await?)
}

pub async fn get_graph_ids_by_instance_id(
    provider: &FillProvider<
        JoinFill<Identity, <Ethereum as RecommendedFillers>::RecommendedFillers>,
        RootProvider,
    >,
    address: Address,
    instance_id: Uuid,
) -> anyhow::Result<Vec<Uuid>> {
    let gateway = IGateway::new(address, provider);
    let graph_ids = gateway
        .getGraphIdsByInstanceId(FixedBytes::<16>::from_slice(instance_id.as_bytes()))
        .call()
        .await?;
    Ok(graph_ids.into_iter().map(|v| Uuid::from_bytes(v.0)).collect())
}

pub async fn get_committee_management_contract(
    provider: &FillProvider<
        JoinFill<Identity, <Ethereum as RecommendedFillers>::RecommendedFillers>,
        RootProvider,
    >,
    gateway_address: Address,
) -> anyhow::Result<Address> {
    let gateway = IGateway::new(gateway_address, provider);
    Ok(gateway.committeeManagement().call().await?)
}

pub async fn get_stake_management_contract(
    provider: &FillProvider<
        JoinFill<Identity, <Ethereum as RecommendedFillers>::RecommendedFillers>,
        RootProvider,
    >,
    gateway_address: Address,
) -> anyhow::Result<Address> {
    let gateway = IGateway::new(gateway_address, provider);
    Ok(gateway.stakeManagement().call().await?)
}

pub async fn get_btc_spv_contract(
    provider: &FillProvider<
        JoinFill<Identity, <Ethereum as RecommendedFillers>::RecommendedFillers>,
        RootProvider,
    >,
    gateway_address: Address,
) -> anyhow::Result<Address> {
    let gateway = IGateway::new(gateway_address, provider);
    Ok(gateway.bitcoinSPV().call().await?)
}

pub async fn get_gateway_relay_contracts(
    provider: &FillProvider<
        JoinFill<Identity, <Ethereum as RecommendedFillers>::RecommendedFillers>,
        RootProvider,
    >,
    gateway_address: Address,
) -> anyhow::Result<(Address, Address, Address)> {
    Ok((
        get_committee_management_contract(provider, gateway_address).await?,
        get_stake_management_contract(provider, gateway_address).await?,
        get_btc_spv_contract(provider, gateway_address).await?,
    ))
}
