pub const ZKM_VERSION_BYTES_LEN: usize = 16;
pub type ZkmVersionBytes = [u8; ZKM_VERSION_BYTES_LEN];

pub fn encode_zkm_version_fixed(version: &str) -> Result<ZkmVersionBytes, String> {
    let raw = version.as_bytes();
    if raw.is_empty() {
        return Err("zkm_version is empty".to_string());
    }
    if raw.len() > ZKM_VERSION_BYTES_LEN {
        return Err(format!(
            "zkm_version '{}' too long: {} > {}",
            version,
            raw.len(),
            ZKM_VERSION_BYTES_LEN
        ));
    }

    let mut encoded = [0u8; ZKM_VERSION_BYTES_LEN];
    encoded[..raw.len()].copy_from_slice(raw);
    Ok(encoded)
}

pub fn decode_zkm_version_fixed(version: &ZkmVersionBytes) -> Result<String, String> {
    let end = version.iter().position(|b| *b == 0).unwrap_or(version.len());
    if end == 0 {
        return Err("zkm_version is empty".to_string());
    }
    String::from_utf8(version[..end].to_vec()).map_err(|e| format!("invalid zkm_version: {e}"))
}

pub fn read_zkm_version_from_file(input_proof: &str) -> Result<ZkmVersionBytes, String> {
    let version_path = format!("{input_proof}.zkm_version.bin");
    let raw = std::fs::read(&version_path)
        .map_err(|e| format!("failed to read zkm_version file '{}': {e}", version_path))?;
    let version = String::from_utf8(raw)
        .map_err(|e| format!("invalid UTF-8 in zkm_version file '{}': {e}", version_path))?;
    encode_zkm_version_fixed(version.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_rejects_empty_version() {
        let result = encode_zkm_version_fixed("");
        assert!(result.is_err());
    }

    #[test]
    fn encode_accepts_16_bytes_version() {
        let version = "v123456789012345";
        assert_eq!(version.len(), ZKM_VERSION_BYTES_LEN);
        let encoded = encode_zkm_version_fixed(version).unwrap();
        assert_eq!(decode_zkm_version_fixed(&encoded).unwrap(), version);
    }

    #[test]
    fn encode_rejects_17_bytes_version() {
        let version = "v1234567890123456";
        assert_eq!(version.len(), ZKM_VERSION_BYTES_LEN + 1);
        let result = encode_zkm_version_fixed(version);
        assert!(result.is_err());
    }
}
