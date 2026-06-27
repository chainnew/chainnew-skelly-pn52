#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IvrsHeader {
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
}

pub fn looks_like_ivrs(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && &bytes[0..4] == b"IVRS"
}
