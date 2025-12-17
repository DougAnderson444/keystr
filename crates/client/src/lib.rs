//! Client library that ties bettersign and webauthn together to create passkey logs.
mod config;

mod error;
pub use error::{Error, Result};

mod key_manager;

/// Some references to webauthn functionality
mod webauthn;

use bs::open_plog;

/// Keystr Client
pub struct Keystr {}

impl Keystr {
    /// Create a new Keystr client
    pub fn new() -> Result<Self> {
        let config = config::GenerationConfig::default();
        let key_manager = key_manager::Wallet::default();
        let _plog = open_plog(&config, &key_manager, &key_manager)?;
        Ok(Keystr {})
    }
}
