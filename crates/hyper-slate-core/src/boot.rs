#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootEpoch {
    UefiBootServices,
    AfterExitBootServices,
    HypervisorHost,
    Guest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeasurementRef {
    pub pcr: u8,
    pub digest_len: usize,
}
