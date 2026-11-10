//! Compliance artefact modules for IronVise.
//!
//! This crate bundles the self-contained compliance primitives:
//! - **ots** - OpenTimestamps integration (submit SHA-256 digests to calendar pools)
//! - **verifiable_credential** - W3C VC-JWT issuance and verification (EdDSA / ECDSA)
//!
//! The host crate re-exports these modules so existing `crate::ots::*` and
//! `crate::verifiable_credential::*` paths
//! continue to resolve.

pub mod ots;
pub mod verifiable_credential;
