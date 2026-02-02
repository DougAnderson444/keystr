//! Browser-based passkey wallet for P256 signing in provenance logs.
//!
//! This module provides a WebAuthn-based wallet that uses browser passkeys for
//! signing provenance log entries with P256 keys, while using ephemeral Ed25519
//! keys for the first entry.

use crate::cbor_utils::{
    extract_p256_public_key_from_attestation, extract_p256_signature_from_der,
};
use base64::prelude::*;
use bs_traits::asyncro::{AsyncKeyManager, AsyncMultiSigner, AsyncSigner, BoxFuture};
use bs_traits::sync::EphemeralSigningTuple;
#[cfg(feature = "web")]
use bs_traits::{CondSend, CondSync};
use bs_traits::{EphemeralKey, GetKey, Signer};
use multicodec::Codec;
use multikey::Multikey;
use multisig::Multisig;
use provenance_log::Key;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

#[cfg(feature = "web")]
use wasm_bindgen::JsCast;
#[cfg(feature = "web")]
use web_sys::{
    AuthenticatorAssertionResponse, AuthenticatorAttestationResponse, CredentialCreationOptions,
    CredentialRequestOptions, PublicKeyCredential, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
};

/// The ES256 signature algorithm identifier for WebAuthn
pub const WEBAUTHN_ES256_ALG: i32 = -7;

/// The EdDSA signature algorithm identifier for WebAuthn
pub const WEBAUTHN_EDDSA_ALG: i32 = -8;

/// The RS256 signature algorithm identifier for WebAuthn
pub const WEBAUTHN_RS256_ALG: i32 = -257;

/// Errors that can occur in the passkey wallet
#[derive(Debug, thiserror::Error)]
pub enum PasskeyError {
    #[error("WebAuthn not supported")]
    NotSupported,
    #[error("User cancelled operation")]
    UserCancelled,
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Invalid codec: {0:?}")]
    InvalidCodec(Codec),
    #[error("WebAuthn error: {0}")]
    WebAuthn(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Invalid signature format: {0}")]
    InvalidSignature(String),
    #[error("CBOR parsing error: {0}")]
    CborParsing(String),
    #[error("Multikey error: {0}")]
    Multikey(#[from] multikey::Error),
    #[error("Multihash error: {0}")]
    Multihash(#[from] multihash::Error),
    #[error("Multicid error: {0}")]
    Multicid(#[from] multicid::Error),
    #[error("Base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),
}

// Implement conversion to bs::Error for use with BetterSign
impl From<PasskeyError> for bs::Error {
    fn from(err: PasskeyError) -> Self {
        match err {
            PasskeyError::Multikey(e) => bs::Error::Multikey(e),
            PasskeyError::Multihash(e) => bs::Error::Multihash(e),
            PasskeyError::Multicid(e) => bs::Error::Multicid(e),
            // For all other passkey-specific errors, treat as key error
            _ => bs::Error::Traits(bs_traits::Error::KeyError),
        }
    }
}

/// Stored credential information
#[derive(Clone, Debug)]
pub struct CredentialInfo {
    /// The credential ID used to identify the passkey
    pub credential_id: Vec<u8>,
    /// The public key associated with this credential
    pub public_key: Multikey,
}

/// Browser-based wallet using WebAuthn/Passkeys for P256 signing in provenance logs
#[derive(Debug)]
pub struct PasskeyStore<E = PasskeyError> {
    /// Maps key paths to credential information
    credentials: Arc<Mutex<HashMap<Key, CredentialInfo>>>,
    /// Relying party ID (typically the domain, e.g., "example.com")
    rp_id: String,
    /// Relying party name (display name, e.g., "Example App")
    rp_name: String,
    /// User display name
    user_name: String,
    /// User ID (persisted identifier)
    user_id: Vec<u8>,
    /// Phantom data for error type
    _phantom: std::marker::PhantomData<E>,
}

// Manually implement Clone to avoid requiring E: Clone
impl<E> Clone for PasskeyStore<E> {
    fn clone(&self) -> Self {
        Self {
            credentials: self.credentials.clone(),
            rp_id: self.rp_id.clone(),
            rp_name: self.rp_name.clone(),
            user_name: self.user_name.clone(),
            user_id: self.user_id.clone(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<E> PasskeyStore<E> {
    /// Create a new passkey wallet
    ///
    /// # Arguments
    /// * `rp_id` - Relying party ID (domain name, e.g., "example.com")
    /// * `rp_name` - Relying party display name (e.g., "Example App")
    /// * `user_name` - User display name
    /// * `user_id` - Persistent user identifier (should be random bytes)
    pub fn new(rp_id: String, rp_name: String, user_name: String, user_id: Vec<u8>) -> Self {
        Self {
            credentials: Arc::new(Mutex::new(HashMap::new())),
            rp_id,
            rp_name,
            user_name,
            user_id,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Get the relying party ID
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    /// Get the user name
    pub fn user_name(&self) -> &str {
        &self.user_name
    }

    /// Set the user name
    pub fn set_user_name(&mut self, user_name: String) {
        self.user_name = user_name;
    }

    /// Set the user ID
    pub fn set_user_id(&mut self, user_id: Vec<u8>) {
        self.user_id = user_id;
    }

    /// Check if a key exists at the given path
    pub fn has_key(&self, key_path: &Key) -> bool {
        self.credentials.lock().unwrap().contains_key(key_path)
    }

    /// List all stored credential paths
    pub fn list_credentials(&self) -> Vec<Key> {
        self.credentials.lock().unwrap().keys().cloned().collect()
    }

    /// Manually insert a credential into the store.
    pub fn insert_credential(&self, key_path: Key, public_key: Multikey, credential_id: Vec<u8>) {
        let cred_info = CredentialInfo {
            credential_id,
            public_key,
        };
        self.credentials.lock().unwrap().insert(key_path, cred_info);
    }
}

#[cfg(feature = "web")]
impl<E> PasskeyStore<E>
where
    E: From<PasskeyError> + CondSend,
{
    /// Create a new passkey and store its credential ID and public key
    ///
    /// This initiates the WebAuthn credential creation flow in the browser,
    /// prompting the user to create a new passkey.
    pub async fn create_passkey(&self, key_path: &Key) -> Result<Multikey, E> {
        use js_sys::{Object, Reflect, Uint8Array};
        use wasm_bindgen::JsValue;
        use wasm_bindgen_futures::JsFuture;

        tracing::info!(
            "create_passkey: Starting passkey creation for path: {}",
            key_path
        );

        let window = web_sys::window().ok_or(PasskeyError::NotSupported)?;
        tracing::debug!("create_passkey: Got window object");

        let navigator = window.navigator();
        let credentials_container = navigator.credentials();
        tracing::debug!("create_passkey: Got credentials container");

        // Generate a random challenge
        let challenge = {
            let mut buf = [0u8; 32];
            getrandom::fill(&mut buf)
                .map_err(|e| PasskeyError::WebAuthn(format!("Random generation failed: {}", e)))?;
            buf
        };
        tracing::debug!("create_passkey: Generated challenge");

        // Build public key credential parameters for P256
        let pub_key_cred_params = js_sys::Array::new();
        let param = Object::new();
        Reflect::set(&param, &"type".into(), &"public-key".into())
            .map_err(|_| PasskeyError::WebAuthn("Failed to set type".to_string()))?;
        Reflect::set(&param, &"alg".into(), &JsValue::from(WEBAUTHN_ES256_ALG)) // ES256 (P-256)
            .map_err(|_| PasskeyError::WebAuthn("Failed to set alg".to_string()))?;
        pub_key_cred_params.push(&param);

        // Build relying party object using proper web_sys type
        let rp = web_sys::PublicKeyCredentialRpEntity::new(&self.rp_name);
        rp.set_id(&self.rp_id);

        // Build user object using proper web_sys type
        let user = web_sys::PublicKeyCredentialUserEntity::new(
            &self.user_name,
            &self.user_name,
            &Uint8Array::from(&self.user_id[..]),
        );

        // Create PublicKeyCredentialCreationOptions with proper constructor
        let options = PublicKeyCredentialCreationOptions::new(
            &Uint8Array::from(&challenge[..]).into(),
            &pub_key_cred_params,
            &rp,
            &user,
        );
        options.set_timeout(60_000); // 60 seconds
        options.set_attestation(web_sys::AttestationConveyancePreference::None);

        // Set authenticator selection criteria
        let auth_selection = web_sys::AuthenticatorSelectionCriteria::new();
        auth_selection.set_user_verification(web_sys::UserVerificationRequirement::Preferred);
        auth_selection.set_resident_key("required"); // Discoverable credential
        options.set_authenticator_selection(&auth_selection);

        let cred_options = CredentialCreationOptions::new();
        cred_options.set_public_key(&options);
        tracing::debug!("create_passkey: Built credential creation options");

        // Create the credential
        tracing::info!("create_passkey: Requesting credential creation from browser...");
        let promise = credentials_container
            .create_with_options(&cred_options)
            .map_err(|e| {
                PasskeyError::WebAuthn(format!("Failed to initiate credential creation: {:?}", e))
            })?;

        tracing::info!("create_passkey: Waiting for user to complete passkey creation...");
        let result = JsFuture::from(promise).await.map_err(|e| {
            tracing::error!("create_passkey: Credential creation failed: {:?}", e);
            PasskeyError::WebAuthn(format!("Credential creation failed: {:?}", e))
        })?;
        tracing::info!("create_passkey: User completed passkey creation");

        let credential: PublicKeyCredential = result.dyn_into().map_err(|_| {
            tracing::error!("create_passkey: Invalid credential type returned");
            PasskeyError::WebAuthn("Invalid credential type".to_string())
        })?;
        tracing::debug!("create_passkey: Got PublicKeyCredential");

        let response: AuthenticatorAttestationResponse =
            credential.response().dyn_into().map_err(|_| {
                tracing::error!("create_passkey: Invalid response type");
                PasskeyError::WebAuthn("Invalid response type".to_string())
            })?;
        tracing::debug!("create_passkey: Got AuthenticatorAttestationResponse");

        // Extract credential ID
        let raw_id = credential.raw_id();
        let cred_id = js_sys::Uint8Array::new(&raw_id).to_vec();
        tracing::debug!(
            "create_passkey: Extracted credential ID, length: {}",
            cred_id.len()
        );

        // Extract public key from attestation object
        let attestation_obj = response.attestation_object();
        let attestation_bytes = js_sys::Uint8Array::new(&attestation_obj).to_vec();
        tracing::debug!(
            "create_passkey: Extracted attestation object, length: {}",
            attestation_bytes.len()
        );

        tracing::debug!("create_passkey: Parsing attestation object to extract public key...");
        let public_key_bytes = extract_p256_public_key_from_attestation(&attestation_bytes)
            .map_err(|e| {
                tracing::error!("create_passkey: Failed to parse attestation: {}", e);
                PasskeyError::CborParsing(e)
            })?;
        tracing::debug!(
            "create_passkey: Extracted public key, length: {}",
            public_key_bytes.len()
        );

        // Convert to Multikey (P256 public key)
        // The public key is in uncompressed format (0x04 || x || y), 65 bytes
        tracing::debug!("create_passkey: Building Multikey from public key bytes...");
        use multikey::mk::Builder;
        let multikey = Builder::new(Codec::P256Pub)
            .with_key_bytes(&public_key_bytes)
            // let's put the credential_id as a comment so that another device
            // can lookup the same credential as needed
            .with_comment(&BASE64_STANDARD.encode(&cred_id))
            .try_build()
            .map_err(|e| {
                tracing::error!("create_passkey: Failed to build Multikey: {}", e);
                PasskeyError::Serialization(e.to_string())
            })?;
        tracing::debug!("create_passkey: Successfully built Multikey");

        // Store credential info
        let cred_info = CredentialInfo {
            credential_id: cred_id,
            public_key: multikey.clone(),
        };

        self.credentials
            .lock()
            .unwrap()
            .insert(key_path.clone(), cred_info.clone());

        tracing::info!(
            "create_passkey: Successfully created and stored passkey for path {} with credential ID length {}",
            key_path,
            cred_info.credential_id.len()
        );

        Ok(multikey)
    }

    /// This initiates the WebAuthn authentication flow, prompting the user to
    /// authenticate with their passkey and sign the provided data.
    ///
    /// If `key_path` is `None`, the browser will be prompted to select from
    /// any discoverable credentials (passkeys) available for this relying party.
    pub async fn sign_with_passkey(
        &self,
        key_path: Option<&Key>,
        data: &[u8],
    ) -> Result<Multisig, E> {
        use js_sys::{Object, Reflect, Uint8Array};
        use wasm_bindgen_futures::JsFuture;

        // Get credential info if key_path is provided and exists in the store
        let credential_id: Option<Vec<u8>> = key_path.and_then(|kp| {
            self.credentials
                .lock()
                .unwrap()
                .get(kp)
                .map(|cred_info| cred_info.credential_id.clone())
        });

        let window = web_sys::window().ok_or(PasskeyError::NotSupported)?;
        let navigator = window.navigator();
        let credentials_container = navigator.credentials();

        // Build credential request options
        // Use the data to sign as the challenge
        let options = PublicKeyCredentialRequestOptions::new(&Uint8Array::from(data));

        options.set_timeout(60_000);
        options.set_rp_id(&self.rp_id);
        options.set_user_verification(web_sys::UserVerificationRequirement::Preferred);

        // If a credential_id is available, specify it to the browser.
        // Otherwise, let the browser prompt the user to choose a passkey.
        if let Some(cred_id) = credential_id {
            tracing::debug!("Requesting signature for specific credential ID");
            let allowed_credentials = js_sys::Array::new();
            let cred_descriptor = Object::new();
            Reflect::set(&cred_descriptor, &"type".into(), &"public-key".into())
                .map_err(|_| PasskeyError::WebAuthn("Failed to set type".to_string()))?;
            Reflect::set(
                &cred_descriptor,
                &"id".into(),
                &Uint8Array::from(&cred_id[..]).into(),
            )
            .map_err(|_| PasskeyError::WebAuthn("Failed to set id".to_string()))?;
            allowed_credentials.push(&cred_descriptor);
            options.set_allow_credentials(&allowed_credentials);
        } else {
            tracing::debug!("No credential ID specified, letting browser select a passkey.");
        }

        let cred_options = CredentialRequestOptions::new();
        cred_options.set_public_key(&options);

        // Get the assertion (signature)
        let promise = credentials_container
            .get_with_options(&cred_options)
            .map_err(|e| PasskeyError::WebAuthn(format!("{:?}", e)))?;

        let result = JsFuture::from(promise)
            .await
            .map_err(|e| PasskeyError::WebAuthn(format!("Credential get failed: {:?}", e)))?;

        let credential: PublicKeyCredential = result
            .dyn_into()
            .map_err(|_| PasskeyError::WebAuthn("Invalid credential type".to_string()))?;

        let response: AuthenticatorAssertionResponse = credential
            .response()
            .dyn_into()
            .map_err(|_| PasskeyError::WebAuthn("Invalid response type".to_string()))?;

        // Extract signature (DER format)
        let signature_data = response.signature();
        let der_signature = js_sys::Uint8Array::new(&signature_data).to_vec();

        // Convert DER signature to raw format (r || s)
        let raw_signature = extract_p256_signature_from_der(&der_signature)
            .map_err(|e| PasskeyError::InvalidSignature(e))?;

        // Convert to Multisig (P256 signature)
        use multisig::ms::Builder as MsBuilder;
        let multisig = MsBuilder::new(multicodec::Codec::Es256Msig)
            .with_signature_bytes(&raw_signature)
            .try_build()
            .map_err(|e| PasskeyError::Serialization(e.to_string()))?;

        tracing::debug!(
            "Signed data with passkey, signature length: {}",
            raw_signature.len()
        );

        Ok(multisig)
    }
}
pub struct PasskeyKeyManager<E = PasskeyError> {
    store: PasskeyStore<E>,
}

impl<E> PasskeyKeyManager<E> {
    pub fn new(store: PasskeyStore<E>) -> Self {
        Self { store }
    }
}

pub struct PasskeyP256Signer<E = PasskeyError> {
    store: PasskeyStore<E>,
}

impl<E> PasskeyP256Signer<E> {
    pub fn new(store: PasskeyStore<E>) -> Self {
        Self { store }
    }
}

// Implement the required traits for PasskeyKeyManager
impl<E> GetKey for PasskeyKeyManager<E> {
    type Key = Multikey;
    type KeyPath = Key;
    type Codec = Codec;
    type Error = E;
}

#[cfg(feature = "web")]
impl<E> AsyncKeyManager<E> for PasskeyKeyManager<E>
where
    E: From<PasskeyError>
        + From<multikey::Error>
        + From<multihash::Error>
        + std::fmt::Debug
        + CondSync
        + 'static,
{
    fn get_key<'a>(
        &'a self,
        key_path: &'a Self::KeyPath,
        codec: &'a Self::Codec,
        _threshold: NonZeroUsize,
        _limit: NonZeroUsize,
    ) -> BoxFuture<'a, Result<Self::Key, E>> {
        let store = self.store.clone();
        let key_path = key_path.clone();
        let codec = *codec;

        Box::pin(async move {
            tracing::info!(
                "PasskeyKeyManager::get_key called for path: {}, codec: {:?}",
                key_path,
                codec
            );
            match codec {
                Codec::P256Pub => {
                    // Check if we already have this key
                    let existing_key = {
                        let creds = store.credentials.lock().unwrap();
                        creds
                            .get(&key_path)
                            .map(|cred_info| cred_info.public_key.clone())
                    }; // MutexGuard dropped here

                    if let Some(public_key) = existing_key {
                        tracing::info!("Found existing key for path: {}", key_path);
                        Ok(public_key)
                    } else {
                        tracing::info!(
                            "No existing key found, creating new passkey for path: {}",
                            key_path
                        );
                        // Create a new passkey
                        match store.create_passkey(&key_path).await {
                            Ok(key) => {
                                tracing::info!(
                                    "Successfully created passkey for path: {}",
                                    key_path
                                );
                                Ok(key)
                            }
                            Err(e) => {
                                tracing::error!(
                                    "Failed to create passkey for path {}: {:?}",
                                    key_path,
                                    e
                                );
                                Err(e)
                            }
                        }
                    }
                }
                _ => {
                    tracing::error!("Invalid codec requested: {:?}", codec);
                    Err(PasskeyError::InvalidCodec(codec).into())
                }
            }
        })
    }

    fn preprocess_vlad<'a>(&'a mut self, vlad: &'a multicid::Vlad) -> BoxFuture<'a, Result<(), E>> {
        use sha2::{Digest, Sha256};

        let vlad_str = vlad.to_string();
        tracing::info!("Preprocessing Vlad, setting user_id from vlad hash");
        let user_id = Sha256::digest(vlad_str.as_bytes()).to_vec();
        self.store.set_user_id(user_id);
        self.store.set_user_name(vlad_str);

        Box::pin(async move { Ok(()) })
    }
}

// Implement the required traits for PasskeyP256Signer
impl<E> GetKey for PasskeyP256Signer<E> {
    type Key = Multikey;
    type KeyPath = Key;
    type Codec = Codec;
    type Error = E;
}

impl<E> Signer for PasskeyP256Signer<E>
where
    E: std::fmt::Debug,
{
    type KeyPath = Key;
    type Signature = Multisig;
    type Error = E;
}

impl<E> EphemeralKey for PasskeyP256Signer<E> {
    type PubKey = Multikey;
}

#[cfg(feature = "web")]
impl<E> AsyncSigner for PasskeyP256Signer<E>
where
    E: From<PasskeyError>
        + From<multikey::Error>
        + From<multihash::Error>
        + std::fmt::Debug
        + CondSync
        + 'static,
{
    fn try_sign<'a>(
        &'a self,
        key: &'a Self::KeyPath,
        data: &'a [u8],
    ) -> BoxFuture<'a, Result<Self::Signature, Self::Error>> {
        let store = self.store.clone();
        let key = key.clone();
        let data = data.to_vec();

        Box::pin(async move { store.sign_with_passkey(Some(&key), &data).await })
    }
}

#[cfg(feature = "web")]
impl<E> AsyncMultiSigner<Multisig, E> for PasskeyP256Signer<E>
where
    E: From<PasskeyError>
        + From<multikey::Error>
        + From<multihash::Error>
        + From<multicid::Error>
        + std::fmt::Debug
        + CondSync
        + Send // Required by AsyncMultiSigner trait even on wasm32
        + 'static,
{
    fn prepare_ephemeral_signing<'a>(
        &'a self,
        codec: &'a Codec,
        _threshold: NonZeroUsize,
        _limit: NonZeroUsize,
    ) -> BoxFuture<'a, EphemeralSigningTuple<Self::PubKey, Multisig, E>> {
        Box::pin(async move {
            // For first entry, use Ed25519 ephemeral key
            if *codec != Codec::Ed25519Priv {
                return Err(PasskeyError::InvalidCodec(*codec).into());
            }

            // Generate ephemeral Ed25519 key using ed25519-dalek
            let mut csprng = rand::rngs::OsRng;
            let keypair = ed25519_dalek::SigningKey::generate(&mut csprng);
            let public_key_bytes = keypair.verifying_key();

            use multikey::mk::Builder;
            let public_multikey = Builder::new(Codec::Ed25519Pub)
                .with_key_bytes(&public_key_bytes.as_bytes())
                .try_build()
                .map_err(|e| PasskeyError::Serialization(e.to_string()))?;

            // Create a signing closure that owns the keypair
            let signer: Box<dyn FnOnce(&[u8]) -> Result<Multisig, E> + Send> =
                Box::new(move |data: &[u8]| -> Result<Multisig, E> {
                    use ed25519_dalek::Signer as DalekSigner;
                    use multisig::ms::Builder as MsBuilder;
                    let sig = keypair.sign(data);
                    MsBuilder::new(multicodec::Codec::EddsaMsig)
                        .with_signature_bytes(&sig.to_bytes())
                        .try_build()
                        .map_err(|e| PasskeyError::Serialization(e.to_string()).into())
                });

            Ok((public_multikey, signer))
        })
    }
}

#[cfg(test)]
#[cfg(feature = "web")]
mod tests {
    use super::*;

    #[test]
    fn test_passkey_store_creation() {
        let store = PasskeyStore::<PasskeyError>::new(
            "example.com".to_string(),
            "Example App".to_string(),
            "user@example.com".to_string(),
            vec![1, 2, 3, 4, 5, 6, 7, 8],
        );

        assert_eq!(store.rp_id(), "example.com");
        assert_eq!(store.user_name(), "user@example.com");
        assert_eq!(store.list_credentials().len(), 0);
    }

    #[test]
    fn test_credential_storage() {
        let store = PasskeyStore::<PasskeyError>::new(
            "example.com".to_string(),
            "Example App".to_string(),
            "user@example.com".to_string(),
            vec![1, 2, 3, 4, 5, 6, 7, 8],
        );

        let key_path = Key::try_from("/test/key").unwrap();
        assert!(!store.has_key(&key_path));
    }
}
