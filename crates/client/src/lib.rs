//! Client library that ties bettersign and webauthn together to create passkey logs.
mod config;

mod error;
pub use error::{Error, Result};

mod key_manager;

/// Some references to webauthn functionality
mod webauthn;

/// CBOR parsing utilities for WebAuthn attestation objects
mod cbor_utils;

/// Passkey wallet for browser-based P256 signing
/// Note: Currently has compilation issues with WebAuthn API usage
/// Use the main Wallet in key_manager for general purpose key management
#[cfg(all(feature = "web", target_arch = "wasm32"))]
pub mod passkey_wallet;

#[cfg(all(feature = "web", target_arch = "wasm32"))]
pub use passkey_wallet::PasskeyWallet;

use bs::open_plog;

/// Keystr Client
pub struct Keystr {}

impl Keystr {
    /// Create a new Keystr client
    pub async fn new() -> Result<Self> {
        let config = config::GenerationConfig::default();
        let key_manager = key_manager::Wallet::default();
        let _plog = open_plog(&config, &key_manager, &key_manager).await?;
        Ok(Keystr {})
    }
}
