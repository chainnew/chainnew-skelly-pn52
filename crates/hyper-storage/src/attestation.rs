#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationPolicy {
    pub required_pcrs: &'static [u8],
    pub minimum_boot_policy_version: u64,
    pub require_secure_boot: bool,
}

pub const LAB_POLICY: AttestationPolicy = AttestationPolicy {
    required_pcrs: &[0, 7, 11],
    minimum_boot_policy_version: 1,
    require_secure_boot: false,
};
