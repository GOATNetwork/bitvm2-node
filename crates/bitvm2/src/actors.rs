use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

#[derive(Debug, Serialize, Deserialize, Clone, Hash, Eq, PartialEq, Display, EnumString)]
pub enum Actor {
    Committee,
    Operator,
    Challenger,
    Relayer,
    All,
}
