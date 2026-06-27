#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyClass {
    DataEncryptionKey,
    VolumeMasterKey,
    KeyEncryptionKey,
    DeviceKey,
    UserKey,
    RecoveryKey,
    HardwareSealedKey,
    RemoteKmsKey,
    HybridPqcWrappedKey,
    ThresholdShare,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyVersion {
    pub key_id: &'static str,
    pub version: u64,
}
