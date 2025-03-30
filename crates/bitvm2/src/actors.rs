use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::str::FromStr;

#[derive(Debug, Serialize, Deserialize)]
pub enum Actor {
    FEDERATION,
    OPERATOR,
    CHALLENGER,
}

impl FromStr for Actor {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Federation" => Ok(Actor::FEDERATION),
            "Operator" => Ok(Actor::OPERATOR),
            "Challenger" => Ok(Actor::CHALLENGER),
            _ => Err(()),
        }
    }
}

impl TryFrom<&str> for Actor {
    type Error = ();

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "Federation" => Ok(Actor::FEDERATION),
            "Operator" => Ok(Actor::OPERATOR),
            "Challenger" => Ok(Actor::CHALLENGER),
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for Actor {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
        // or, alternatively:
        // fmt::Debug::fmt(self, f)
    }
}
