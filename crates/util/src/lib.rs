use hex::FromHex;

pub fn hex_parse<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let mut s = s;
    if s.starts_with("0x") {
        s = &s[2..];
    }
    let b = Vec::from_hex(s).map_err(|e| e.to_string())?;
    b.try_into().map_err(|_| "len must be {N}".to_string())
}
