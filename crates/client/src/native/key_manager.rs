//! Implements the [bs_traits] for managing keys in the Keystr client.
use bs::prelude::{Signature, multihash, multikey};
use bs_traits::asyncro::{AsyncKeyManager, AsyncMultiSigner, AsyncSigner, BoxFuture};
use bs_traits::sync::EphemeralSigningTuple;
use bs_traits::{EphemeralKey, GetKey, Signer};
use multicodec::Codec;
use multikey::Multikey;
use provenance_log::Key;
use std::collections::HashMap;
use std::fmt::Debug;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

/// The Key Store for Keystr client.
pub struct Wallet<E = crate::Error> {
    /// Storage for secret keys
    keys: Arc<Mutex<HashMap<Vec<u8>, Multikey>>>,
    /// Maps key paths to key fingerprints
    paths: Arc<Mutex<HashMap<Key, Vec<u8>>>>,
    _phantom: std::marker::PhantomData<E>,
}

impl<E> Clone for Wallet<E> {
    fn clone(&self) -> Self {
        Self {
            keys: self.keys.clone(),
            paths: self.paths.clone(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl Default for Wallet {
    fn default() -> Self {
        Self::new()
    }
}

impl Wallet {
    /// Creates a new KeyManager instance.
    pub fn new() -> Self {
        Wallet {
            keys: Arc::new(Mutex::new(HashMap::new())),
            paths: Arc::new(Mutex::new(HashMap::new())),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<E> Wallet<E> {
    /// Get secret key by path
    pub fn get_secret_key(&self, path: &Key) -> Result<Option<Multikey>, E>
    where
        E: From<multikey::Error> + From<multihash::Error>,
    {
        let paths = self.paths.lock().unwrap();
        if let Some(fingerprint) = paths.get(path) {
            let keys = self.keys.lock().unwrap();
            return Ok(keys.get(fingerprint).cloned());
        }
        Ok(None)
    }

    /// Store secret key by path
    pub fn store_secret_key(&self, path: Key, secret_key: Multikey) -> Result<(), E>
    where
        E: From<multikey::Error> + From<multihash::Error>,
    {
        use multikey::Views as _;
        let fingerprint = secret_key.fingerprint_view()?.fingerprint(Codec::Sha2256)?;
        let mut keys = self.keys.lock().unwrap();
        keys.insert(fingerprint.clone().into(), secret_key);
        let mut paths = self.paths.lock().unwrap();
        paths.insert(path, fingerprint.into());
        Ok(())
    }
}

pub struct KeyManager<E = crate::Error> {
    wallet: Wallet<E>,
}

impl<E> KeyManager<E> {
    pub fn new(wallet: Wallet<E>) -> Self {
        Self { wallet }
    }
}

pub struct P256Signer<E = crate::Error> {
    wallet: Wallet<E>,
}

impl<E> P256Signer<E> {
    pub fn new(wallet: Wallet<E>) -> Self {
        Self { wallet }
    }
}

impl<E> GetKey for KeyManager<E>
where
    E: From<multikey::Error> + From<multihash::Error> + Debug,
{
    type Key = Multikey;
    type KeyPath = Key;
    type Codec = Codec;
    type Error = E;
}

impl<E> AsyncKeyManager<E> for KeyManager<E>
where
    E: From<multikey::Error>
        + From<multihash::Error>
        + From<crate::Error>
        + Debug
        + Send
        + Sync
        + 'static,
{
    fn get_key<'a>(
        &'a self,
        key_path: &'a Self::KeyPath,
        codec: &'a Self::Codec,
        threshold: NonZeroUsize,
        limit: NonZeroUsize,
    ) -> BoxFuture<'a, Result<Self::Key, E>> {
        Box::pin(async move {
            use multikey::Views as _;
            // Check if key already exists
            if let Some(secret_key) = self.wallet.get_secret_key(key_path)? {
                return Ok(secret_key.conv_view()?.to_public_key()?);
            }

            // Generate new key
            let mut rng = rand_core_6::OsRng;
            let secret_key = multikey::Builder::new_from_random_bytes(*codec, &mut rng)?
                .with_threshold(threshold)
                .with_limit(limit)
                .try_build()?;

            let public_key = secret_key.conv_view()?.to_public_key()?;

            // Store the secret key
            self.wallet.store_secret_key(key_path.clone(), secret_key)?;

            Ok(public_key)
        })
    }

    fn preprocess_vlad<'a>(&'a mut self, vlad: &'a multicid::Vlad) -> BoxFuture<'a, Result<(), E>> {
        // assigns user_id to the Vlad
        Box::pin(async move { Ok(()) })
    }
}

impl<E> GetKey for P256Signer<E>
where
    E: From<multikey::Error> + From<multihash::Error> + Debug,
{
    type Key = Multikey;
    type KeyPath = Key;
    type Codec = Codec;
    type Error = E;
}

impl<E> Signer for P256Signer<E>
where
    E: From<multikey::Error> + From<multihash::Error> + Debug,
{
    type KeyPath = Key;
    type Signature = Signature;
    type Error = E;
}

impl<E> EphemeralKey for P256Signer<E>
where
    E: From<multikey::Error> + From<multihash::Error> + Debug,
{
    type PubKey = Multikey;
}

impl<E> AsyncMultiSigner<Signature, E> for P256Signer<E>
where
    E: From<multikey::Error>
        + From<multihash::Error>
        + From<crate::Error>
        + Debug
        + Send
        + Sync
        + 'static,
{
    fn prepare_ephemeral_signing<'a>(
        &'a self,
        codec: &'a Self::Codec,
        threshold: NonZeroUsize,
        limit: NonZeroUsize,
    ) -> BoxFuture<'a, EphemeralSigningTuple<Self::PubKey, Signature, E>> {
        Box::pin(async move {
            // Generate ephemeral key using multikey
            let mut rng = rand_core_6::OsRng;
            let secret_key = multikey::Builder::new_from_random_bytes(*codec, &mut rng)?
                .with_threshold(threshold)
                .with_limit(limit)
                .try_build()?;

            use multikey::Views as _;
            let public_key = secret_key.conv_view()?.to_public_key()?;

            let sign_once: Box<dyn FnOnce(&[u8]) -> Result<Signature, E> + Send> =
                Box::new(move |data: &[u8]| -> Result<Signature, E> {
                    let signature = secret_key.sign_view()?.sign(data, false, None)?;
                    Ok(signature)
                });

            Ok((public_key, sign_once))
        })
    }
}

impl<E> AsyncSigner for P256Signer<E>
where
    E: From<multikey::Error>
        + From<multihash::Error>
        + From<crate::Error>
        + Debug
        + Send
        + Sync
        + 'static,
{
    fn try_sign<'a>(
        &'a self,
        key_path: &'a Self::KeyPath,
        data: &'a [u8],
    ) -> BoxFuture<'a, Result<Self::Signature, Self::Error>> {
        Box::pin(async move {
            use multikey::Views as _;
            // Get the secret key corresponding to the provided path
            let secret_key = self
                .wallet
                .get_secret_key(key_path)?
                .ok_or(crate::Error::NoKeyPresent(key_path.clone()))?;

            let msg = data;
            let combined = false;
            let scheme = None;

            let signmk = secret_key.sign_view()?;
            let signature = signmk.sign(msg, combined, scheme)?;

            let sig_bytes_raw: Vec<u8> = signature.clone().into();
            tracing::debug!(
                "try_sign Signature created with {} bytes, first 4 bytes: {:02x?} ({:?} dec)",
                sig_bytes_raw.len(),
                &sig_bytes_raw[..4],
                &sig_bytes_raw[..4]
            );

            Ok(signature)
        })
    }
}

