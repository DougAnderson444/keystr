//! Browser-based passkey wallet for P256 signing in provenance logs
//!
//! This module provides a WebAuthn-based wallet that uses browser passkeys for
//! signing provenance log entries with P256 keys, while using ephemeral Ed25519
//! keys for the first entry.

use crate::cbor_utils::{
    extract_p256_public_key_from_attestation, extract_p256_signature_from_der,
};
use bs_traits::asyncro::{AsyncKeyManager, AsyncMultiSigner, AsyncSigner, BoxFuture};
use bs_traits::sync::EphemeralSigningTuple;
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
}

/// Stored credential information
#[derive(Clone, Debug)]
struct CredentialInfo {
    /// The credential ID used to identify the passkey
    credential_id: Vec<u8>,
    /// The public key associated with this credential
    public_key: Multikey,
}

/// Browser-based wallet using WebAuthn/Passkeys for P256 signing
///
/// This wallet manages P256 keys via browser passkeys for signing provenance log
/// entries. The first entry uses an ephemeral Ed25519 key (as per provenance log
/// design), while subsequent entries are signed with the user's passkey.
#[derive(Clone, Debug)]
pub struct PasskeyWallet<E = PasskeyError> {
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

impl<E> PasskeyWallet<E> {
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

    /// Check if a key exists at the given path
    pub fn has_key(&self, key_path: &Key) -> bool {
        self.credentials.lock().unwrap().contains_key(key_path)
    }

    /// List all stored credential paths
    pub fn list_credentials(&self) -> Vec<Key> {
        self.credentials.lock().unwrap().keys().cloned().collect()
    }
}

#[cfg(feature = "web")]
impl<E> PasskeyWallet<E>
where
    E: From<PasskeyError> + Send,
{
    /// Create a new passkey and store its credential ID and public key
    ///
    /// This initiates the WebAuthn credential creation flow in the browser,
    /// prompting the user to create a new passkey.
    pub async fn create_passkey(&self, key_path: &Key) -> Result<Multikey, E> {
        use js_sys::{Object, Reflect, Uint8Array};
        use wasm_bindgen::JsValue;
        use wasm_bindgen_futures::JsFuture;

        let window = web_sys::window().ok_or(PasskeyError::NotSupported)?;
        let navigator = window.navigator();
        let credentials_container = navigator.credentials();

        // Generate a random challenge
        let challenge = {
            let mut buf = [0u8; 32];
            getrandom::fill(&mut buf)
                .map_err(|e| PasskeyError::WebAuthn(format!("Random generation failed: {}", e)))?;
            buf
        };

        // Build public key credential parameters for P256
        let pub_key_cred_params = js_sys::Array::new();
        let param = Object::new();
        Reflect::set(&param, &"type".into(), &"public-key".into())
            .map_err(|_| PasskeyError::WebAuthn("Failed to set type".to_string()))?;
        Reflect::set(&param, &"alg".into(), &JsValue::from(-7)) // ES256 (P-256)
            .map_err(|_| PasskeyError::WebAuthn("Failed to set alg".to_string()))?;
        pub_key_cred_params.push(&param);

        // Build relying party object
        let rp = Object::new();
        Reflect::set(&rp, &"id".into(), &self.rp_id.clone().into())
            .map_err(|_| PasskeyError::WebAuthn("Failed to set rp.id".to_string()))?;
        Reflect::set(&rp, &"name".into(), &self.rp_name.clone().into())
            .map_err(|_| PasskeyError::WebAuthn("Failed to set rp.name".to_string()))?;

        // Build user object
        let user = Object::new();
        Reflect::set(
            &user,
            &"id".into(),
            &Uint8Array::from(&self.user_id[..]).into(),
        )
        .map_err(|_| PasskeyError::WebAuthn("Failed to set user.id".to_string()))?;
        Reflect::set(&user, &"name".into(), &self.user_name.clone().into())
            .map_err(|_| PasskeyError::WebAuthn("Failed to set user.name".to_string()))?;
        Reflect::set(&user, &"displayName".into(), &self.user_name.clone().into())
            .map_err(|_| PasskeyError::WebAuthn("Failed to set user.displayName".to_string()))?;

        // Create PublicKeyCredentialCreationOptions
        let options = PublicKeyCredentialCreationOptions::new(
            &Uint8Array::from(&challenge[..]),
            &rp,
            &user,
            &pub_key_cred_params,
        );

        options.set_timeout(60_000); // 60 seconds
        options.set_attestation(web_sys::AttestationConveyancePreference::None);

        // Set authenticator selection criteria
        let auth_selection = web_sys::AuthenticatorSelectionCriteria::new();
        auth_selection.set_user_verification(web_sys::UserVerificationRequirement::Preferred);
        auth_selection.set_resident_key(web_sys::ResidentKeyRequirement::Required); // Discoverable credential
        options.set_authenticator_selection(&auth_selection);

        let cred_options = CredentialCreationOptions::new();
        cred_options.set_public_key(&options);

        // Create the credential
        let promise = credentials_container
            .create_with_options(&cred_options)
            .map_err(|e| PasskeyError::WebAuthn(format!("{:?}", e)))?;

        let result = JsFuture::from(promise)
            .await
            .map_err(|e| PasskeyError::WebAuthn(format!("Credential creation failed: {:?}", e)))?;

        let credential: PublicKeyCredential = result
            .dyn_into()
            .map_err(|_| PasskeyError::WebAuthn("Invalid credential type".to_string()))?;

        let response: AuthenticatorAttestationResponse = credential
            .response()
            .dyn_into()
            .map_err(|_| PasskeyError::WebAuthn("Invalid response type".to_string()))?;

        // Extract credential ID
        let raw_id = credential.raw_id();
        let cred_id = js_sys::Uint8Array::new(&raw_id).to_vec();

        // Extract public key from attestation object
        let attestation_obj = response.attestation_object();
        let attestation_bytes = js_sys::Uint8Array::new(&attestation_obj).to_vec();

        let public_key_bytes = extract_p256_public_key_from_attestation(&attestation_bytes)
            .map_err(|e| PasskeyError::CborParsing(e))?;

        // Convert to Multikey (P256 public key)
        // The public key is in uncompressed format (0x04 || x || y), 65 bytes
        let multikey = Multikey::try_from_key_bytes(Codec::P256Pub, &public_key_bytes)
            .map_err(|e| PasskeyError::Serialization(e.to_string()))?;

        // Store credential info
        let cred_info = CredentialInfo {
            credential_id: cred_id,
            public_key: multikey.clone(),
        };

        self.credentials
            .lock()
            .unwrap()
            .insert(key_path.clone(), cred_info);

        tracing::info!(
            "Created passkey for path {} with credential ID length {}",
            key_path,
            multikey
                .fingerprint_view()?
                .fingerprint(Codec::Sha2256)?
                .len()
        );

        Ok(multikey)
    }

    /// Sign data using an existing passkey
    ///
    /// This initiates the WebAuthn authentication flow, prompting the user to
    /// authenticate with their passkey and sign the provided data.
    pub async fn sign_with_passkey(&self, key_path: &Key, data: &[u8]) -> Result<Multisig, E> {
        use js_sys::{Object, Reflect, Uint8Array};
        use wasm_bindgen_futures::JsFuture;

        // Get credential info
        let cred_info = {
            let creds = self.credentials.lock().unwrap();
            creds
                .get(key_path)
                .ok_or_else(|| PasskeyError::KeyNotFound(key_path.to_string()))?
                .clone()
        };

        let window = web_sys::window().ok_or(PasskeyError::NotSupported)?;
        let navigator = window.navigator();
        let credentials_container = navigator.credentials();

        // Build credential request options
        // Use the data to sign as the challenge
        let options = PublicKeyCredentialRequestOptions::new(&Uint8Array::from(data));

        options.set_timeout(60_000);
        options.set_rp_id(&self.rp_id);
        options.set_user_verification(web_sys::UserVerificationRequirement::Preferred);

        // Set allowed credentials (specify the exact credential to use)
        let allowed_credentials = js_sys::Array::new();
        let cred_descriptor = Object::new();
        Reflect::set(&cred_descriptor, &"type".into(), &"public-key".into())
            .map_err(|_| PasskeyError::WebAuthn("Failed to set type".to_string()))?;
        Reflect::set(
            &cred_descriptor,
            &"id".into(),
            &Uint8Array::from(&cred_info.credential_id[..]).into(),
        )
        .map_err(|_| PasskeyError::WebAuthn("Failed to set id".to_string()))?;
        allowed_credentials.push(&cred_descriptor);
        options.set_allow_credentials(&allowed_credentials);

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
        let multisig = Multisig::try_from_sig_bytes(Codec::P256Sig, &raw_signature)
            .map_err(|e| PasskeyError::Serialization(e.to_string()))?;

        tracing::debug!(
            "Signed data with passkey at path {}, signature length: {}",
            key_path,
            raw_signature.len()
        );

        Ok(multisig)
    }
}

// Implement the required traits
impl<E> GetKey for PasskeyWallet<E> {
    type Key = Multikey;
    type KeyPath = Key;
    type Codec = Codec;
    type Error = E;
}

impl<E> Signer for PasskeyWallet<E>
where
    E: std::fmt::Debug,
{
    type KeyPath = Key;
    type Signature = Multisig;
    type Error = E;
}

impl<E> EphemeralKey for PasskeyWallet<E> {
    type PubKey = Multikey;
}

#[cfg(feature = "web")]
impl<E> AsyncKeyManager<E> for PasskeyWallet<E>
where
    E: From<PasskeyError> + From<multikey::Error> + From<multihash::Error> + Send + Sync + 'static,
{
    fn get_key<'a>(
        &'a self,
        key_path: &'a Self::KeyPath,
        codec: &'a Self::Codec,
        _threshold: NonZeroUsize,
        _limit: NonZeroUsize,
    ) -> BoxFuture<'a, Result<Self::Key, E>> {
        Box::pin(async move {
            match codec {
                Codec::P256Pub => {
                    // Check if we already have this key
                    let creds = self.credentials.lock().unwrap();
                    if let Some(cred_info) = creds.get(key_path) {
                        Ok(cred_info.public_key.clone())
                    } else {
                        drop(creds); // Release lock before async operation
                        // Create a new passkey
                        self.create_passkey(key_path).await
                    }
                }
                _ => Err(PasskeyError::InvalidCodec(*codec).into()),
            }
        })
    }
}

#[cfg(feature = "web")]
impl<E> AsyncSigner for PasskeyWallet<E>
where
    E: From<PasskeyError>
        + From<multikey::Error>
        + From<multihash::Error>
        + std::fmt::Debug
        + Send
        + Sync
        + 'static,
{
    fn try_sign<'a>(
        &'a self,
        key: &'a Self::KeyPath,
        data: &'a [u8],
    ) -> BoxFuture<'a, Result<Self::Signature, Self::Error>> {
        Box::pin(async move { self.sign_with_passkey(key, data).await })
    }
}

#[cfg(feature = "web")]
impl<E> AsyncMultiSigner<Multisig, E> for PasskeyWallet<E>
where
    E: From<PasskeyError>
        + From<multikey::Error>
        + From<multihash::Error>
        + From<multicid::Error>
        + std::fmt::Debug
        + Send
        + Sync
        + 'static,
{
    fn prepare_ephemeral_signing<'a>(
        &'a self,
        codec: &'a Codec,
        threshold: NonZeroUsize,
        limit: NonZeroUsize,
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

            let public_multikey =
                Multikey::try_from_key_bytes(Codec::Ed25519Pub, public_key_bytes.as_bytes())
                    .map_err(|e| PasskeyError::Serialization(e.to_string()))?;

            // Create a signing closure that owns the keypair
            let signer = Box::new(move |data: &[u8]| -> Result<Multisig, E> {
                use ed25519_dalek::Signer as DalekSigner;
                let sig = keypair.sign(data);
                Multisig::try_from_sig_bytes(Codec::Ed25519Sig, &sig.to_bytes())
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
    fn test_wallet_creation() {
        let wallet = PasskeyWallet::<PasskeyError>::new(
            "example.com".to_string(),
            "Example App".to_string(),
            "user@example.com".to_string(),
            vec![1, 2, 3, 4, 5, 6, 7, 8],
        );

        assert_eq!(wallet.rp_id(), "example.com");
        assert_eq!(wallet.user_name(), "user@example.com");
        assert_eq!(wallet.list_credentials().len(), 0);
    }

    #[test]
    fn test_credential_storage() {
        let wallet = PasskeyWallet::<PasskeyError>::new(
            "example.com".to_string(),
            "Example App".to_string(),
            "user@example.com".to_string(),
            vec![1, 2, 3, 4, 5, 6, 7, 8],
        );

        let key_path = Key::try_from("/test/key").unwrap();
        assert!(!wallet.has_key(&key_path));
    }
}
