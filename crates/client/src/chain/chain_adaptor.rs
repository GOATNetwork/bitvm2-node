use async_trait::async_trait;
use crate::chain::goat_adaptor::{GoatAdaptor, GoatInitConfig};
use crate::chain::mock_addaptor::{MockAdaptor, MockAdaptorConfig};

#[async_trait]
pub trait ChainAdaptor {

}
#[derive(Eq, PartialEq, Clone, Copy)]
pub enum GoatNetwork {
    Main,
    Test,
    /// Locally hosted network.
    Local,
}




pub fn get_chain_adaptor(
    network: GoatNetwork,
    goat_config: Option<GoatInitConfig>,
    mock_adaptor_config: Option<MockAdaptorConfig>,
) -> Box<dyn ChainAdaptor> {
    match network {
        //GoatAdaptor
        GoatNetwork::Main => Box::new(GoatAdaptor::new(goat_config)),
        GoatNetwork::Test => Box::new(GoatAdaptor::new(goat_config)),
        GoatNetwork::Local => Box::new(MockAdaptor::new(mock_adaptor_config)),
    }
}