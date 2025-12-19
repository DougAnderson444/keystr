//! Module for web-related key management, including Passkey support.
pub mod passkey_wallet;
use bs::{
    BetterSign,
    config::asynchronous::{KeyManager, MultiSigner},
    open::{self, config::ValidatedKeyParams as _},
    params::{
        anykey::PubkeyParams,
        vlad::{FirstEntryKeyParams, VladParams},
    },
};
use multicodec::Codec;
pub use passkey_wallet::{PasskeyKeyManager, PasskeyP256Signer, PasskeyStore};
use provenance_log::{Key, Script};

use crate::{
    Result,
    config::{self, GenerationConfig},
};

/// Keystr Client
///
/// Takes dynamically dispatched KeyManager and MultiSigner implementations
/// to allow for different key management strategies (e.g., Passkeys in web,
/// standard Wallet in native).
pub struct Keystr {
    pub bs: BetterSign<PasskeyKeyManager<bs::Error>, PasskeyP256Signer<bs::Error>>,
}

impl Keystr {
    /// Create a new Keystr client
    pub async fn new() -> Result<Self> {
        let user_id = {
            let mut buf = [0u8; 16];
            getrandom::fill(&mut buf)?;
            buf.to_vec()
        };
        tracing::debug!("Generated initial user_id: {} bytes", user_id.len());

        let store = PasskeyStore::<bs::Error>::new(
            web_sys::window()
                .and_then(|w| w.location().hostname().ok())
                .unwrap_or_else(|| "localhost".to_string()),
            "Keystr Provenance Log".to_string(),
            "keystr-user".to_string(), // Will be overwritten by vlad
            user_id,
        );
        tracing::info!("PasskeyStore created with rp_id: {}", store.rp_id());

        let key_manager = PasskeyKeyManager::new(store.clone());
        let signer = PasskeyP256Signer::new(store);

        let pubkey_codec = Codec::P256Pub;

        tracing::info!("Building plog configuration...");
        tracing::debug!("Using pubkey_codec: {:?}", pubkey_codec);
        let config = GenerationConfig::default();
        tracing::debug!("Configuration built successfully");

        tracing::info!("Creating BetterSign instance...");
        let bs = BetterSign::new(&config, key_manager, signer).await?;
        Ok(Keystr { bs })
    }
}
