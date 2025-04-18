use crate::chain::chain_adaptor::ChainAdaptor;
use crate::chain::mock_addaptor::MockAdaptor;

pub struct Chain {
    adaptor: Box<dyn ChainAdaptor>,
}
impl Default for Chain {
    fn default() -> Self {
        Self::new(Box::new(MockAdaptor::new(None)))
    }
}
impl Chain {
    pub fn new(adaptor: Box<dyn ChainAdaptor>) -> Self {
        Self { adaptor }
    }
}
