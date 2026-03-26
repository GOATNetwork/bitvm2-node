use anyhow::{Context, Result};

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

pub fn parse_zkm_version(version: &str) -> Result<String, String> {
    let trimmed = version.trim();
    if trimmed.is_empty() {
        return Err("zkm_version is empty".to_string());
    }
    Ok(trimmed.to_string())
}

pub fn read_zkm_version_from_file(input_proof: &str) -> Result<String> {
    let version_path = format!("{input_proof}.zkm_version.bin");
    let raw = std::fs::read(&version_path)
        .with_context(|| format!("failed to read zkm_version file '{version_path}'"))?;
    let version = String::from_utf8(raw)
        .with_context(|| format!("invalid UTF-8 in zkm_version file '{version_path}'"))?;
    parse_zkm_version(&version).map_err(anyhow::Error::msg)
}

pub fn read_zkm_version_fixed_from_file(input_proof: &str) -> Result<ZkmVersionBytes> {
    let version = read_zkm_version_from_file(input_proof)?;
    encode_zkm_version_fixed(&version).map_err(anyhow::Error::msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn write_temp_version_file(version: &str) -> String {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let base: PathBuf = std::env::temp_dir().join(format!("zkm-version-test-{nanos}"));
        let base_str = base.to_string_lossy().to_string();
        fs::write(format!("{base_str}.zkm_version.bin"), version).unwrap();
        base_str
    }

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

    #[test]
    fn read_version_file_accepts_non_fixed_length_version() {
        let version = "v1.12.15-rc1+build.20260319";
        let input_proof = write_temp_version_file(version);
        let read = read_zkm_version_from_file(&input_proof).unwrap();
        assert_eq!(read, version);
        let _ = fs::remove_file(format!("{input_proof}.zkm_version.bin"));
    }

    #[test]
    fn read_version_file_rejects_empty() {
        let input_proof = write_temp_version_file("   ");
        let result = read_zkm_version_from_file(&input_proof);
        assert!(result.is_err());
        let _ = fs::remove_file(format!("{input_proof}.zkm_version.bin"));
    }
}
