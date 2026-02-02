//! Module for web-related key management, including Passkey support.
pub mod passkey_wallet;
use bs::BetterSign;
pub use passkey_wallet::{PasskeyKeyManager, PasskeyP256Signer, PasskeyStore};

use crate::{Result, config::GenerationConfig};
use base64::prelude::*;
use gloo_storage::{LocalStorage, Storage};
use multikey::Multikey;
use provenance_log::{Key, Log, Value};
use sha2::{Digest, Sha256};

const VLAD_STORAGE_KEY: &str = "keystr_vlad";

/// Keystr Client
///
/// Takes dynamically dispatched KeyManager and MultiSigner implementations
/// to allow for different key management strategies (e.g., Passkeys in web,
/// standard Wallet in native).
pub struct Keystr {
    pub bs: BetterSign<PasskeyKeyManager<bs::Error>, PasskeyP256Signer<bs::Error>>,
}

impl Keystr {
    /// Create a new Keystr client. If a VLAD is found in local storage,
    /// it loads the existing identity. Otherwise, it creates a new one.
    pub async fn new() -> Result<Self> {
        if let Ok(vlad_str) = LocalStorage::get::<String>(VLAD_STORAGE_KEY) {
            // Explicit String type
            Self::from_vlad(&vlad_str).await
        } else {
            let bs = Self::create_bs(None).await?;
            Ok(Keystr { bs })
        }
    }

    /// Create a new Keystr client from an existing vlad.
    pub async fn from_vlad(vlad: &str) -> Result<Self> {
        let bs = Self::create_bs_from_vlad(vlad).await?;
        Ok(Keystr { bs })
    }

    /// Creates a BetterSign instance by loading state from a VLAD.
    async fn create_bs_from_vlad(
        vlad_str: &str,
    ) -> Result<BetterSign<PasskeyKeyManager<bs::Error>, PasskeyP256Signer<bs::Error>>> {
        let user_id = Sha256::digest(vlad_str.as_bytes()).to_vec();
        tracing::debug!(
            "Creating Keystr from vlad, derived user_id: {} bytes",
            user_id.len()
        );

        let store = PasskeyStore::<bs::Error>::new(
            web_sys::window()
                .and_then(|w| w.location().hostname().ok())
                .map(|h| {
                    if h == "127.0.0.1" {
                        "localhost".to_string()
                    } else {
                        h
                    }
                })
                .unwrap_or_else(|| "localhost".to_string()),
            "Keystr Provenance Log".to_string(),
            vlad_str.to_string(),
            user_id,
        );

        // TODO: Pre-populate the store with credential_id from plog if available
        // This would require fetching the plog from storage/network first.
        // For now, we rely on discoverable credentials (user selects passkey).
        // When plog storage is implemented, add logic here to:
        // 1. Load plog bytes from storage
        // 2. Parse and verify the plog
        // 3. Extract /pubkey multikey from final Kvp state
        // 4. Get credential_id from multikey.comment
        // 5. store.insert_credential() to pre-populate

        let key_manager = PasskeyKeyManager::new(store.clone());
        let signer = PasskeyP256Signer::new(store);
        let config = GenerationConfig::default();

        tracing::info!("Creating BetterSign instance from VLAD...");
        Ok(BetterSign::new(&config, key_manager, signer).await?)
    }

    /// Create a BetterSign instance for a new identity.
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
                .map(|h| {
                    if h == "127.0.0.1" {
                        "localhost".to_string()
                    } else {
                        h
                    }
                })
                .unwrap_or_else(|| "localhost".to_string()),
            "Keystr Provenance Log".to_string(),
            "keystr-user".to_string(), // Will be overwritten by preprocess_vlad if not 32 bytes
            final_user_id,
        );
        tracing::info!("PasskeyStore created with rp_id: {}", store.rp_id());

        let key_manager = PasskeyKeyManager::new(store.clone());
        let signer = PasskeyP256Signer::new(store);
        let config = GenerationConfig::default();

        tracing::info!("Creating new BetterSign instance...");
        Ok(BetterSign::new(&config, key_manager, signer).await?)
    }

    /// Sign a piece of data using a passkey associated with the given vlad.
    pub async fn sign(vlad: &str, data: &[u8]) -> Result<String> {
        let user_id = Sha256::digest(vlad.as_bytes()).to_vec(); // Fixed typo Sha265 -> Sha256

        let store = PasskeyStore::<bs::Error>::new(
            web_sys::window()
                .and_then(|w| w.location().hostname().ok())
                .map(|h| {
                    if h == "127.0.0.1" {
                        "localhost".to_string()
                    } else {
                        h
                    }
                })
                .unwrap_or_else(|| "localhost".to_string()),
            "Keystr Provenance Log".to_string(),
            vlad.to_string(),
            user_id,
        );

        // TODO: Look up the specific credential_id from plog if available
        // This would require fetching the plog from storage/network first.
        // For now, we rely on discoverable credentials (user selects passkey).
        // When plog storage is implemented, extract credential_id and pre-populate store.

        let signature = store.sign_with_passkey(None, data).await?;

        // Format signature for display
        Ok(format!("Signature (ES256MSig): {:?}", signature))
    }

    /// Export the plog as a base64-encoded string for transfer to another device.
    /// This includes all entries and is the full machine-readable format.
    pub fn export_plog(&self) -> String {
        let plog_bytes: Vec<u8> = self.bs.plog().clone().into();
        BASE64_STANDARD.encode(&plog_bytes)
    }

    /// Import a plog from a base64-encoded string and create a Keystr instance.
    /// This will:
    /// 1. Decode and parse the plog
    /// 2. Extract the credential_id from the /pubkey multikey comment
    /// 3. Pre-populate the passkey store so the browser can find the right credential
    pub async fn import_plog(plog_base64: &str) -> Result<Self> {
        // Decode the base64 plog
        let plog_bytes = BASE64_STANDARD
            .decode(plog_base64)
            .map_err(|e| crate::Error::Message(format!("Base64 decode error: {}", e)))?;

        // Parse the plog
        let plog: Log = Log::try_from(plog_bytes.as_slice())
            .map_err(|e| crate::Error::Message(format!("Plog parse error: {}", e)))?;

        let vlad_str = plog.vlad.to_string();
        let user_id = Sha256::digest(vlad_str.as_bytes()).to_vec();

        tracing::info!("Importing plog with vlad: {}", vlad_str);

        let store = PasskeyStore::<bs::Error>::new(
            web_sys::window()
                .and_then(|w| w.location().hostname().ok())
                .map(|h| {
                    if h == "127.0.0.1" {
                        "localhost".to_string()
                    } else {
                        h
                    }
                })
                .unwrap_or_else(|| "localhost".to_string()),
            "Keystr Provenance Log".to_string(),
            vlad_str.clone(),
            user_id,
        );

        // Extract the credential_id from the plog by verifying and getting final Kvp state
        let pubkey_path = Key::try_from("/pubkey").expect("Static path is valid");
        let mut final_kvp = None;

        for result in plog.verify() {
            match result {
                Ok((_count, _entry, kvp)) => {
                    final_kvp = Some(kvp);
                }
                Err(e) => {
                    return Err(crate::Error::Message(format!(
                        "Plog verification failed: {}",
                        e
                    )));
                }
            }
        }

        // Extract the pubkey from the final Kvp state
        if let Some(kvp) = final_kvp {
            if let Some((_, value)) = kvp.iter().find(|(k, _)| *k == &pubkey_path) {
                if let Value::Data(data) = value {
                    // Decode the multikey from the data
                    if let Ok(multikey) = Multikey::try_from(data.as_slice()) {
                        let comment = &multikey.comment;
                        if !comment.is_empty() {
                            tracing::info!(
                                "Found credential_id in multikey comment, pre-populating store"
                            );
                            let credential_id = BASE64_STANDARD.decode(comment).map_err(|e| {
                                crate::Error::Message(format!("Credential ID decode error: {}", e))
                            })?;
                            store.insert_credential(
                                pubkey_path.clone(),
                                multikey.clone(),
                                credential_id,
                            );
                        } else {
                            tracing::warn!(
                                "No credential_id found in multikey comment, will use discoverable credentials"
                            );
                        }
                    }
                }
            }
        }

        let key_manager = PasskeyKeyManager::new(store.clone());
        let signer = PasskeyP256Signer::new(store);

        // Create BetterSign from the imported plog
        let bs = BetterSign::from_parts(plog, key_manager, signer);

        // Cache the vlad for next time
        LocalStorage::set(VLAD_STORAGE_KEY, &vlad_str)
            .map_err(|e| crate::Error::Message(format!("Failed to cache vlad: {:?}", e)))?;

        Ok(Keystr { bs })
    }
}
