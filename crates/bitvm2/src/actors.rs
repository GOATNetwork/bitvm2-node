use std::convert::TryFrom;
use std::str::FromStr;
#[derive(Debug)]
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
