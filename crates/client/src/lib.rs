//! Client library that ties bettersign and webauthn together to create passkey logs.

/// Common configuration options for all platform targets
mod config;

mod error;
pub use error::{Error, Result};

/// CBOR parsing utilities for WebAuthn attestation objects
mod cbor_utils;

/// Passkey wallet for browser-based P256 signing
#[cfg(feature = "web")]
pub mod web;

/// Native wallet for non-browser P256 signing
#[cfg(all(not(feature = "web"), not(target_arch = "wasm32")))]
pub mod native;
