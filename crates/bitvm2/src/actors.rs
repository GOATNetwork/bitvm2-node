use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Actor {
    COMMITTEE,
    OPERATOR,
    CHALLENGER,
}

impl FromStr for Actor {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Committee" => Ok(Actor::COMMITTEE),
            "Operator" => Ok(Actor::OPERATOR),
            "Challenger" => Ok(Actor::CHALLENGER),
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for Actor {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
