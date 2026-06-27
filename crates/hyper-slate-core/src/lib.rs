#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod boot;
pub mod keys;
pub mod manifest;
pub mod policy;

pub const SCHEMA_VERSION: u32 = 1;
