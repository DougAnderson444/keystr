//! Client library that ties bettersign and webauthn together to create passkey logs.
mod config;

mod error;
pub use error::{Error, Result};

pub mod key_manager;
pub use key_manager::{KeyManager, P256Signer, Wallet};

/// Some references to webauthn functionality
mod webauthn;

/// CBOR parsing utilities for WebAuthn attestation objects
mod cbor_utils;

/// Passkey wallet for browser-based P256 signing
#[cfg(feature = "web")]
pub mod passkey_wallet;

#[cfg(feature = "web")]
pub use passkey_wallet::{PasskeyKeyManager, PasskeyP256Signer, PasskeyStore};

use bs::open_plog;

/// Keystr Client
pub struct Keystr {}

impl Keystr {
    /// Create a new Keystr client
    pub async fn new() -> Result<Self> {
        let config = config::GenerationConfig::default();
        let wallet = key_manager::Wallet::default();
        let mut key_manager = KeyManager::new(wallet.clone());
        let signer = P256Signer::new(wallet);
        let _plog = open_plog(&config, &mut key_manager, &signer).await?;
        Ok(Keystr {})
    }
}
