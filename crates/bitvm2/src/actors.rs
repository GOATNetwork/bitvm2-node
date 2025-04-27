use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum Actor {
    Committee,
    Operator,
    Challenger,
    Relayer,
    All,
}

impl FromStr for Actor {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Committee" => Ok(Actor::Committee),
            "Operator" => Ok(Actor::Operator),
            "Challenger" => Ok(Actor::Challenger),
            "Relayer" => Ok(Actor::Relayer),
            "All" => Ok(Actor::All),
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for Actor {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
