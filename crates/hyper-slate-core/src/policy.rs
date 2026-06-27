#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockMode {
    PassphraseOnly,
    Tpm2PcrPolicy,
    Tpm2Pin,
    Fido2HmacSecret,
    SmartcardPkcs11,
    RemoteAttestedKms,
    ThresholdRecovery,
    HybridClassicalPqc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny,
    RequireRecovery,
    RequireHumanApproval,
}
