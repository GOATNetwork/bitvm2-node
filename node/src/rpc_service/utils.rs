use alloy::primitives::U256;
use serde::{Deserialize, Deserializer};
use std::str::FromStr;

fn parse_value_to_u256(value: &serde_json::Value) -> Result<U256, String> {
    let s = match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                if i < 0 {
                    return Err(format!("U256 cannot be negative, got: {i}"));
                }
                i.to_string()
            } else if let Some(f) = n.as_f64() {
                if f < 0.0 {
                    return Err(format!("U256 cannot be negative, got: {f}"));
                }
                if f.fract() != 0.0 {
                    return Err(format!("U256 must be an integer, got: {f}"));
                }
                format!("{f:.0}")
            } else {
                n.to_string()
            }
        }
        _ => return Err(format!("Expected number or string, got: {value}")),
    };
    U256::from_str(&s).map_err(|e| format!("Failed to parse U256 from '{s}': {e}"))
}

pub(super) fn serialize_u256<S>(value: &U256, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if let Ok(num) = u64::try_from(*value) {
        serializer.serialize_u64(num)
    } else if let Ok(num) = u128::try_from(*value) {
        serializer.serialize_u128(num)
    } else {
        serializer.serialize_str(&value.to_string())
    }
}

pub(super) fn deserialize_u256<'de, D>(deserializer: D) -> Result<U256, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    parse_value_to_u256(&value).map_err(serde::de::Error::custom)
}
