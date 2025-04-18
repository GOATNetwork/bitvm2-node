use async_trait::async_trait;
use crate::chain::chain_adaptor::ChainAdaptor;

pub struct MockAdaptorConfig {
}

pub struct MockAdaptor {
    config: Option<MockAdaptorConfig>,
}

#[async_trait]
impl ChainAdaptor for MockAdaptor {

}

impl MockAdaptor {
    pub fn new(config: Option<MockAdaptorConfig>) -> Self {
        Self { config }
    }
}