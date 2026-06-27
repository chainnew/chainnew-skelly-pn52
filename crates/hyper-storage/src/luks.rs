#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Luks2Profile {
    pub cipher: &'static str,
    pub key_size_bits: u16,
    pub pbkdf: &'static str,
}

pub const AES_256_XTS_ARGON2ID: Luks2Profile = Luks2Profile {
    cipher: "aes-xts-plain64",
    key_size_bits: 512,
    pbkdf: "argon2id",
};
