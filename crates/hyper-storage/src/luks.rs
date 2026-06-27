//! LUKS2 data-plane profile and its mapping into the `qrsd-v1` control plane.
//!
//! The data plane stays "boring" (AES-256-XTS); the control plane is what
//! becomes quantum-ready. This module maps a [`Luks2Profile`] into the
//! [`hyper_qrse::manifest::DataPlane`] section and an Argon2id passphrase
//! [`hyper_qrse::keyslot::Keyslot`] descriptor.

use thiserror::Error;

use hyper_qrse::keyslot::{Argon2idKdf, Keyslot, KeyslotKind, KeyslotStatus, WrapSpec};
use hyper_qrse::manifest::{DataPlane, Integrity};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Luks2Profile {
    pub cipher: &'static str,
    pub key_size_bits: u16,
    pub pbkdf: &'static str,
}

/// The standard AES-256-XTS + Argon2id LUKS2 profile.
pub const AES_256_XTS_ARGON2ID: Luks2Profile = Luks2Profile {
    cipher: "aes-xts-plain64",
    key_size_bits: 512,
    pbkdf: "argon2id",
};

/// Default LUKS2 sector size (bytes).
pub const DEFAULT_SECTOR_SIZE: u32 = 4096;

/// Argon2id cost parameters for a passphrase keyslot (PAD §9.5 `kdf`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2idParams {
    pub memory_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

/// A sensible default Argon2id parameter set (1 GiB, t=3, p=4).
pub const DEFAULT_ARGON2ID_PARAMS: Argon2idParams = Argon2idParams {
    memory_kib: 1_048_576,
    time_cost: 3,
    parallelism: 4,
};

/// Errors mapping a [`Luks2Profile`] into the control plane (fail-closed).
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum LuksError {
    #[error("profile pbkdf is `{pbkdf}`, expected `argon2id`")]
    NotArgon2id { pbkdf: String },
}

impl Luks2Profile {
    /// Map this profile into the `qrsd-v1` data-plane section.
    ///
    /// Uses [`DEFAULT_SECTOR_SIZE`]; integrity defaults to `none` with
    /// `dm-integrity` listed as an upgrade alternative.
    pub fn data_plane(&self) -> DataPlane {
        self.data_plane_with_sector(DEFAULT_SECTOR_SIZE)
    }

    /// Map this profile into the data-plane section with an explicit sector size.
    pub fn data_plane_with_sector(&self, sector_size: u32) -> DataPlane {
        DataPlane {
            cipher: "AES-256-XTS".to_string(),
            xts_raw_key_bits: self.key_size_bits as u32,
            sector_size,
            integrity: Integrity {
                mode: "none".to_string(),
                alternatives: vec!["dm-integrity".to_string()],
            },
        }
    }

    /// Build an Argon2id passphrase keyslot descriptor for this profile.
    ///
    /// Fails closed with [`LuksError::NotArgon2id`] if the profile does not use
    /// Argon2id, so a weaker PBKDF can never silently produce a passphrase slot.
    pub fn argon2id_keyslot(
        &self,
        slot: u32,
        params: &Argon2idParams,
        wrapped_key_ref: impl Into<String>,
    ) -> Result<Keyslot, LuksError> {
        if !self.pbkdf.eq_ignore_ascii_case("argon2id") {
            return Err(LuksError::NotArgon2id {
                pbkdf: self.pbkdf.to_string(),
            });
        }
        Ok(Keyslot::new(
            slot,
            KeyslotStatus::Active,
            KeyslotKind::Argon2idPassphrase {
                kdf: Argon2idKdf {
                    algorithm: "argon2id".to_string(),
                    memory_kib: params.memory_kib,
                    time_cost: params.time_cost,
                    parallelism: params.parallelism,
                },
                wrap: WrapSpec {
                    algorithm: "aes-256-gcm".to_string(),
                    wrapped_key_ref: wrapped_key_ref.into(),
                },
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_plane_maps_aes_256_xts() {
        let dp = AES_256_XTS_ARGON2ID.data_plane();
        assert_eq!(dp.cipher, "AES-256-XTS");
        assert_eq!(dp.xts_raw_key_bits, 512);
        assert_eq!(dp.sector_size, DEFAULT_SECTOR_SIZE);
        assert_eq!(dp.integrity.mode, "none");
        assert!(dp.integrity.alternatives.contains(&"dm-integrity".to_string()));
    }

    #[test]
    fn data_plane_custom_sector() {
        let dp = AES_256_XTS_ARGON2ID.data_plane_with_sector(512);
        assert_eq!(dp.sector_size, 512);
    }

    #[test]
    fn argon2id_keyslot_happy_path() {
        let slot = AES_256_XTS_ARGON2ID
            .argon2id_keyslot(0, &DEFAULT_ARGON2ID_PARAMS, "blob:slot0")
            .unwrap();
        assert_eq!(slot.slot, 0);
        assert!(slot.is_active());
        assert!(slot.classical_only());
        match slot.kind {
            KeyslotKind::Argon2idPassphrase { kdf, wrap } => {
                assert_eq!(kdf.algorithm, "argon2id");
                assert_eq!(kdf.memory_kib, 1_048_576);
                assert_eq!(wrap.wrapped_key_ref, "blob:slot0");
            }
            _ => panic!("wrong kind"),
        }
    }

    #[test]
    fn argon2id_keyslot_fails_closed_on_wrong_pbkdf() {
        let weak = Luks2Profile {
            cipher: "aes-xts-plain64",
            key_size_bits: 512,
            pbkdf: "pbkdf2",
        };
        let err = weak
            .argon2id_keyslot(0, &DEFAULT_ARGON2ID_PARAMS, "ref")
            .unwrap_err();
        assert_eq!(
            err,
            LuksError::NotArgon2id {
                pbkdf: "pbkdf2".to_string()
            }
        );
    }
}
