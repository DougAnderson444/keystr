//! Module for web-related key management, including Passkey support.
pub mod passkey_wallet;
use bs::BetterSign;
pub use passkey_wallet::{PasskeyKeyManager, PasskeyP256Signer, PasskeyStore};

use crate::{config::GenerationConfig, Result};

/// Keystr Client
///
/// Takes dynamically dispatched KeyManager and MultiSigner implementations
/// to allow for different key management strategies (e.g., Passkeys in web,
/// standard Wallet in native).
pub struct Keystr {
    pub bs: BetterSign<PasskeyKeyManager<bs::Error>, PasskeyP256Signer<bs::Error>>,
}

impl Keystr {
    /// Create a new Keystr client with a fresh identity.
    pub async fn new() -> Result<Self> {
        let bs = Self::create_bs(None).await?;
        Ok(Keystr { bs })
    }

    /// Create a new Keystr client from an existing vlad.
    pub async fn from_vlad(vlad: &str) -> Result<Self> {
        use sha2::{Digest, Sha256};
        let user_id = Sha256::digest(vlad.as_bytes()).to_vec();
        tracing::debug!(
            "Creating Keystr from vlad, derived user_id: {} bytes",
            user_id.len()
        );
        let bs = Self::create_bs(Some(user_id)).await?;
        Ok(Keystr { bs })
    }

    /// Create a BetterSign instance with an optional user_id.
    async fn create_bs(
        user_id: Option<Vec<u8>>,
    ) -> Result<BetterSign<PasskeyKeyManager<bs::Error>, PasskeyP256Signer<bs::Error>>> {
        let final_user_id = user_id.unwrap_or_else(|| {
            let mut buf = [0u8; 16];
            getrandom::fill(&mut buf).expect("Should fill random bytes");
            buf.to_vec()
        });

        let store = PasskeyStore::<bs::Error>::new(
            web_sys::window()
                .and_then(|w| w.location().hostname().ok())
                .unwrap_or_else(|| "localhost".to_string()),
            "Keystr Provenance Log".to_string(),
            "keystr-user".to_string(), // Will be overwritten by vlad
            final_user_id, // Might be overwritten by preprocess_vlad if not 32 bytes
        );
        tracing::info!("PasskeyStore created with rp_id: {}", store.rp_id());

        let key_manager = PasskeyKeyManager::new(store.clone());
        let signer = PasskeyP256Signer::new(store);

        let config = GenerationConfig::default();

        tracing::info!("Creating BetterSign instance...");
        Ok(BetterSign::new(&config, key_manager, signer).await?)
    }

    /// Sign a piece of data using a passkey associated with the given vlad.
    /// This will trigger the browser to prompt for a passkey.
    pub async fn sign(vlad: &str, data: &[u8]) -> Result<String> {
        use sha2::{Digest, Sha256};
        let user_id = Sha256::digest(vlad.as_bytes()).to_vec();

        let store = PasskeyStore::<bs::Error>::new(
            web_sys::window()
                .and_then(|w| w.location().hostname().ok())
                .unwrap_or_else(|| "localhost".to_string()),
            "Keystr Provenance Log".to_string(),
            vlad.to_string(),
            user_id,
        );

        // We pass `None` for the key_path to trigger discoverable credential selection
        let signature = store.sign_with_passkey(None, data).await?;

        // Format signature for display
        Ok(format!("Signature (ES256MSig): {:?}", signature))
    }
}
